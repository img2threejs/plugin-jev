import hashlib
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from _harness import linked_harness

with linked_harness():
    import jev_checkpoint as cp
    from jev_contracts import canonical, ContractError
    from jev_consent import ConsentError
    from jev_client import ProviderError
    from jev_checkpoint_client import validate_response as validate_checkpoint_response


def answer(choice, options):
    return {"type":"choice", "choice":choice, "probabilities":{x:float(x==choice) for x in options}, "confidence":1.0}


def response():
    return {"model":"jev-1.13.0", "answers":{
      "evidence":answer("sufficient", ["sufficient","insufficient-evidence","uncertain"]),
      "risk":answer("human-review", ["human-review","request-input","defer","stop"]),
      "artifact":answer("retain", ["revise","retain","uncertain"]),
      "scope":answer("human-review", ["human-review","request-input","defer","stop"]),
    }, "usage":{"input_tokens":11,"output_tokens":7}}


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ws=Path(self.tmp.name)
        self.calls=[]
        self.ctx=self.make_context()
        self.input=self.ws/"context.json"
        self.save_context()
        self.consent=mock.patch.object(cp,"require_consent",return_value={"user":"u","workspace":"w","policyVersion":"jev-disclosure-v3","generation":"g"})
        self.consent.start(); self.addCleanup(self.consent.stop)
        self.key=mock.patch.object(cp,"resolve_api_key",return_value="fake-key")
        self.key.start(); self.addCleanup(self.key.stop)
        self.transport=mock.patch.object(cp,"evaluate_checkpoint_bounded",side_effect=self.dispatch)
        self.transport.start(); self.addCleanup(self.transport.stop)

    def make_context(self, stage="inventory-review"):
        p=self.ws/"proposal.bin"; p.write_bytes(b"proposal")
        base={"kind":cp.KIND,"version":1,"checkpoint":stage,"status":"ready-for-review","proposalSha256":"a"*64,"sceneAnalysisSha256":None,"briefSha256":None,"metrics":{"sourceViewCount":2,"subjectCount":3,"groupCount":1,"coverageRegionCount":4,"visibilityCounts":{"visible":2,"partial":1,"occluded":0,"unknown":0},"representationCounts":{"model":2,"non-3d":0,"effect":0,"unresolved":1},"regionDispositionCounts":{"subject":2,"background":1,"shadow":0,"reflection":0,"text":0,"non-3d":0,"effect":0,"unresolved":1}},"signals":[],"bindings":[{"path":"proposal.bin","role":"scene-intake","size":8,"sha256":hashlib.sha256(b"proposal").hexdigest()}]}
        if stage=="scene-analysis-review":
            base.update(sceneAnalysisSha256="b"*64, metrics={"observationCounts":{"observed":3,"unknown":1},"unknownTopics":["camera"],"hypothesisCounts":{"proposed":2,"not-inferable":1},"unapprovedHypothesisCount":1})
        elif stage=="production-brief-review":
            base.update(sceneAnalysisSha256="b"*64,briefSha256="c"*64,metrics={"storyBeatCount":3,"storyBeatBasisCounts":{"observed":1,"inferred":1,"creative":1},"requirementCountsByCategory":{"animation":1,"vfx":0,"sfx":2},"requirementCountsByBasis":{"observed":1,"inferred":1,"creative":1},"standardReferenceCount":1,"profileBoundRequirementCount":2,"creativeStoryBeatCount":1,"creativeRequirementCount":1})
        base["contextSha256"]=hashlib.sha256(canonical(base)).hexdigest()
        return base

    def save_context(self): self.input.write_bytes(canonical(self.ctx))
    def dispatch(self, projection, key, timeout=15.0):
        self.calls.append((projection,key,timeout))
        return response()
    def invoke(self): return cp.consult(self.ws,"context.json")

    def test_all_stages_validate_and_projection_is_aggregate_only(self):
        for stage in ("inventory-review","scene-analysis-review","production-brief-review"):
            ctx=self.make_context(stage); cp.validate_context(self.ws,ctx)
            projected=cp.projection(ctx)
            self.assertEqual(set(projected),{"checkpoint","metrics","signals"})
            encoded=json.dumps(projected)
            self.assertNotIn("proposal.bin",encoded); self.assertNotIn(ctx["bindings"][0]["sha256"],encoded); self.assertNotIn("proposal",encoded)
            if stage=="scene-analysis-review": self.assertNotIn("camera",encoded); self.assertEqual(projected["metrics"]["unknownTopicCount"],1)

    def test_worker_projection_is_closed_at_parent_and_worker_boundaries(self):
        projected=cp.projection(self.ctx)
        cp.validate_checkpoint_projection(projected)
        malformed=json.loads(json.dumps(projected)); malformed["workspaceId"]="private"
        with self.assertRaises(ContractError): cp.validate_checkpoint_projection(malformed)
        malformed=json.loads(json.dumps(projected)); malformed["metrics"]["subjectCount"]=True
        with self.assertRaises(ContractError): cp.validate_checkpoint_projection(malformed)
        malformed=json.loads(json.dumps(projected)); malformed["signals"]=["free text"]
        with self.assertRaises(ContractError): cp.validate_checkpoint_projection(malformed)
        import io, jev_transport
        with mock.patch.object(jev_transport,"_run_worker") as spawn:
            with self.assertRaises(ContractError): jev_transport.evaluate_checkpoint_bounded(malformed,"fake-key")
            spawn.assert_not_called()
        invalid=canonical(malformed)
        with mock.patch.object(jev_transport.sys,"argv",["jev_transport","--checkpoint-worker","5"]), mock.patch.object(jev_transport.sys,"stdin",type("Input",(),{"buffer":io.BytesIO(invalid)})()), mock.patch.object(jev_transport.sys,"stdout",type("Output",(),{"buffer":io.BytesIO()})()), mock.patch.object(jev_transport,"evaluate_checkpoint",side_effect=AssertionError("must not call provider")):
            self.assertEqual(jev_transport.worker(),2)

    def test_checkpoint_response_is_strict_and_closed(self):
        valid=response(); self.assertEqual(validate_checkpoint_response(valid),valid)
        malformed=json.loads(json.dumps(valid)); malformed["extra"]="free text"
        with self.assertRaises(ProviderError): validate_checkpoint_response(malformed)
        malformed=json.loads(json.dumps(valid)); malformed["answers"]["evidence"]["choice"]="pass"
        with self.assertRaises(ProviderError): validate_checkpoint_response(malformed)

    def test_cli_consult_smoke_uses_separate_result_envelope(self):
        import contextlib, io
        with linked_harness():
            import jev
        output=io.StringIO()
        with mock.patch.object(jev,"resolve_workspace",return_value=self.ws), contextlib.redirect_stdout(output):
            self.assertEqual(jev.main(["consult","--workspace",str(self.ws),"--input","context.json"]),0)
        envelope=json.loads(output.getvalue())
        self.assertEqual(envelope["status"],"consulted")
        self.assertEqual(envelope["authority"],"advisory-only")
        self.assertEqual(envelope["contextSha256"],self.ctx["contextSha256"])
        self.assertNotIn("proposal",envelope)

    def test_binding_count_and_aggregate_byte_boundaries(self):
        ctx=json.loads(json.dumps(self.ctx))
        bindings=[]
        for i in range(64):
            rel=f"bound-{i:02d}.bin"; (self.ws/rel).write_bytes(b"x")
            bindings.append({"path":rel,"role":"source-view","size":1,"sha256":hashlib.sha256(b"x").hexdigest()})
        ctx["bindings"]=bindings[:33]
        ctx["contextSha256"]=hashlib.sha256(canonical({k:v for k,v in ctx.items() if k!="contextSha256"})).hexdigest()
        cp.validate_context(self.ws,ctx)
        ctx["bindings"]=bindings
        ctx["contextSha256"]=hashlib.sha256(canonical({k:v for k,v in ctx.items() if k!="contextSha256"})).hexdigest()
        cp.validate_context(self.ws,ctx)
        too_many=json.loads(json.dumps(ctx)); too_many["bindings"].append({"path":"bound-64.bin","role":"source-view","size":1,"sha256":hashlib.sha256(b"x").hexdigest()})
        (self.ws/"bound-64.bin").write_bytes(b"x")
        too_many["contextSha256"]=hashlib.sha256(canonical({k:v for k,v in too_many.items() if k!="contextSha256"})).hexdigest()
        with self.assertRaises(ContractError): cp.validate_context(self.ws,too_many)
        with mock.patch.object(cp,"MAX_BINDING_TOTAL_BYTES",63):
            with self.assertRaises(ContractError): cp.validate_context(self.ws,ctx)

    def test_uncertain_low_confidence_and_inconsistent_decisions_defer(self):
        uncertain=response(); a=uncertain["answers"]["evidence"]; a["choice"]="uncertain"; a["probabilities"]={"sufficient":0.0,"insufficient-evidence":0.0,"uncertain":1.0}
        self.assertEqual(cp.suggested_action(uncertain,self.ctx),"defer")
        low=response(); a=low["answers"]["evidence"]; a["probabilities"]={"sufficient":0.79,"insufficient-evidence":0.21,"uncertain":0.0}
        self.assertEqual(cp.suggested_action(low,self.ctx),"defer")
        low=response(); low["answers"]["evidence"]["confidence"]=0.49
        self.assertEqual(cp.suggested_action(low,self.ctx),"defer")
        conflict=response(); conflict["answers"]["risk"]["choice"]="stop"; conflict["answers"]["risk"]["probabilities"]={"human-review":0.0,"request-input":0.0,"defer":0.0,"stop":1.0}
        self.assertEqual(cp.suggested_action(conflict,self.ctx),"defer")

    def test_unknown_fields_boolean_counts_and_bad_digest_rejected(self):
        for change in (lambda x:x.update(extra=1),lambda x:x["metrics"].update(subjectCount=True),lambda x:x.update(contextSha256="f"*64)):
            bad=json.loads(json.dumps(self.ctx)); change(bad)
            if "contextSha256" not in bad or bad["contextSha256"]!="f"*64: bad["contextSha256"]=hashlib.sha256(canonical({k:v for k,v in bad.items() if k!="contextSha256"})).hexdigest()
            with self.assertRaises(ContractError): cp.validate_context(self.ws,bad)

    def test_stale_binding_and_request_input_do_not_dispatch(self):
        (self.ws/"proposal.bin").write_bytes(b"changed")
        with self.assertRaises(ContractError): self.invoke()
        self.assertEqual(self.calls,[])
        (self.ws/"proposal.bin").write_bytes(b"proposal")
        self.ctx["signals"]=["request-input"]; self.ctx["contextSha256"]=hashlib.sha256(canonical({k:v for k,v in self.ctx.items() if k!="contextSha256"})).hexdigest(); self.save_context()
        self.assertEqual(self.invoke()["status"],"not-consulted"); self.assertEqual(self.calls,[])

    def test_cached_and_concurrent_duplicate_dispatch_once(self):
        first=self.invoke()
        self.assertEqual(first["status"],"consulted")
        self.assertEqual(self.invoke()["status"],"cached")
        with mock.patch.object(cp,"resolve_api_key",side_effect=ConsentError()):
            self.assertEqual(self.invoke()["status"],"cached")
        artifact=Path(self.ws/first["artifact"])
        self.assertEqual(artifact.stem,hashlib.sha256(canonical(json.loads(artifact.read_text()))).hexdigest())
        self.assertEqual(len(self.calls),1)
        (self.ws/".img2/artifacts/jev/checkpoints/cache").glob("*")
        import shutil
        shutil.rmtree(self.ws/".img2/artifacts/jev/checkpoints")
        self.calls.clear()
        barrier=threading.Barrier(3); results=[]
        def run():
            barrier.wait(); results.append(self.invoke())
        workers=[threading.Thread(target=run) for _ in range(2)]
        for worker in workers: worker.start()
        barrier.wait()
        for worker in workers: worker.join(5)
        self.assertEqual(len(results),2)
        self.assertEqual({r["status"] for r in results},{"consulted","cached"})
        self.assertEqual(len(self.calls),1)

    def test_missing_consent_or_key_does_not_dispatch(self):
        with mock.patch.object(cp,"require_consent",side_effect=ConsentError()): self.assertEqual(self.invoke()["reasonCode"],"consent-required")
        with mock.patch.object(cp,"require_consent",return_value={"user":"u","workspace":"w","policyVersion":"jev-disclosure-v2","generation":"old"}):
            self.assertNotEqual(self.invoke()["status"],"consulted")
        with mock.patch.object(cp,"resolve_api_key",return_value=None): self.assertEqual(self.invoke()["reasonCode"],"credential-required")
        self.assertEqual(self.calls,[])

    def test_changed_consent_during_dispatch_discards_advice(self):
        values=iter([{"user":"u","workspace":"w","policyVersion":"jev-disclosure-v3","generation":"g"},{"user":"u","workspace":"w","policyVersion":"jev-disclosure-v3","generation":"g"},{"user":"u","workspace":"w","policyVersion":"jev-disclosure-v3","generation":"g"},{"user":"u","workspace":"w","policyVersion":"jev-disclosure-v3","generation":"changed"}])
        with mock.patch.object(cp,"require_consent",side_effect=lambda _: next(values)):
            with self.assertRaises(ContractError): self.invoke()
        self.assertEqual(len(self.calls),1)
        self.assertFalse(list((self.ws/".img2/artifacts/jev/checkpoints/records").glob("*.json")))

    def test_binding_changed_during_dispatch_discards_advice(self):
        def mutate(projection, key, timeout=15.0):
            (self.ws/"proposal.bin").write_bytes(b"changed")
            return response()
        with mock.patch.object(cp,"evaluate_checkpoint_bounded",side_effect=mutate):
            with self.assertRaises(ContractError): self.invoke()
        self.assertFalse(list((self.ws/".img2/artifacts/jev/checkpoints/records").glob("*.json")))

    def test_provider_error_no_advice_or_repair_mutation(self):
        repair=self.ws/".img2/artifacts/jev/recommendation.json"; repair.parent.mkdir(parents=True); repair.write_text("repair-marker")
        gate=self.ws/".img2/artifacts/environment/gate-results/gate.json"; gate.parent.mkdir(parents=True); gate.write_text("gate-marker")
        with mock.patch.object(cp,"evaluate_checkpoint_bounded",side_effect=ProviderError("provider failed")) as provider:
            with self.assertRaises(ProviderError): self.invoke()
            self.assertEqual(self.invoke()["reasonCode"],"already-attempted")
            self.assertEqual(provider.call_count,1)
        self.assertEqual(repair.read_text(),"repair-marker")
        self.assertEqual(gate.read_text(),"gate-marker")
        self.assertFalse(list((self.ws/".img2/artifacts/jev/checkpoints").glob("*.json")))

if __name__ == "__main__": unittest.main()
