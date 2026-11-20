---
name: img2-jev
description: Routes ambiguous img2 repair decisions from structured evaluation evidence through Jev TypeSafe. Use after an admitted render review to compare shadow advice or request an assisted repair proposal.
---

# Jev repair router

`$SKILL_DIR` is the absolute directory containing this SKILL.md. Run commands from the user's
workspace. Python 3.10+ and img2 harness 0.2.5+ are required; no pip packages.

## Install and discover

```bash
img2 add --link /absolute/path/to/plugin-jev
img2-jev login
img2 doctor
img2 sync --check
img2 capabilities --from-kind repair-state --to-kind repair-recommendation --json
```

This is an ordinary cross-cutting capability, not an emission target or subject domain.
`steps.json` describes contributed steps; installing it does NOT create an automatic after-render hook.
The host invokes it explicitly after evaluation and before recording the canonical repair action.
Do not use a domain profile to replace the current asset domain. Do not import base/plugin code.

## Authority and modes

- Run the existing img2threejs state gate first. Respect pass ordering, hard gates and correction ceilings.
- Run deterministic validation before any vision review; never invoke vision where the base forbids it.
- Jev receives structured text, never images. Vision observes; validators measure; Jev recommends.
- Default `shadow`: record advice, then follow the unchanged baseline workflow.
- A router or integrity-gate error in shadow mode discards the advice, not the baseline workflow.
- Explicit `assist`: show the proposal and require approval before any repair. No action executes here.
- `auto-safe` and `auto` are deliberately unsupported. No calibration data is bundled.
- Never treat a high provider confidence as a repair-success probability. Assist floors are not calibration.
- Never interpret the plugin gate as scene acceptance. It checks artifact integrity only.
- Never write another plugin's state, advance a pass, grant `continue`, or modify scene/spec/source files.

## Prepare the handoff

Read `examples/observation.json` for the full input shape. It is synthetic format documentation,
not visual evidence or historical benchmark data. Author an observation from current evaluator outputs;
do not copy its claims into a real asset. Write the input under the workspace artifacts directory.

Required artifact: `kind: img2.repair-observation`, `version: 1`, `state`, `control`, `bindings`.
Use stable component/feature/evidence IDs. Every referenced evidence ID must exist in the state facts.
Include one focus issue, at most five focus components, relevant shared-resource users and protected
properties, current requirements, direct implementation facts, and at most three recent attempts.
Separate `observation` from `inference`; include conflicting and missing evidence explicitly.
Evidence facts may use `validator`, `vision`, `spec`, or `measurement`; `specification.implementationFacts` must use `implementation`. Bind each source file and evaluator/context dependency in the same fresh snapshot.
Only the room adapter is currently fixture-qualified for live routing and outcome reports; street, vegetation-cluster, and building-exterior remain fail-closed pending per-kind fixture qualification. Four-kind source mappings do not advertise support or release qualification.
Do not put repair instructions, model names, budgets, credentials or desired classifications in facts.
Keep `control` outside `state`; counters and budgets come from the current controller, not Jev.
Defaults cap repairs at three per pass and six total; a stricter existing controller always wins.

Bind all relevant files, including dependencies whose changes invalidate the assessment, using
workspace-relative paths and roles: `reference`, `spec`, `source`, `render-profile`, `evaluation`,
`pipeline-state`. Multiple source/evaluation files are allowed. Include the actual base checklist
file as `pipeline-state`, not `.img2/state.json` (cross-plugin mutable state is not a handoff).
Copy references into the workspace if needed. Symlinks and parent-directory traversal are refused.
Hashes prove file identity/freshness, NOT that the observation accurately describes those files.
The caller remains responsible for complete source coverage and honest measurements.

```bash
python3 "$SKILL_DIR/tools/jev.py" prepare --workspace "$PWD" --input .img2/artifacts/jev/observation.json
```

This validates input, computes file hashes, and writes `.img2/artifacts/jev/repair-state.json`.
Do not re-prepare an old observation against changed files; re-evaluate first.
Limits: state 24KiB, JSON artifact 128KiB, each bound file 64MiB, 64 bound files.

## Credential enrollment

After installing Jev, each installer must enroll their own TypeSafe API key by running this command
from any directory. It does not resolve a workspace or contact TypeSafe:

```bash
img2-jev login
```

On macOS, Keychain prompts securely for the installer's own console-issued TypeSafe API key. The key
is stored in that user's Keychain and is never printed, logged, placed in command arguments, artifacts,
or plaintext files. Credentials belong to each individual user and must never be shared. Login only
stores the key; the first live route verifies it. For automation, provide `TYPESAFE_API_KEY` through
the host secret manager; it takes precedence over the Keychain entry. No .env files are automatically
sourced.

Inspect local enrollment with `img2-jev auth-status`: exit 0 means a key is present, exit 3 means it
is missing, and exit 1 means secure storage is inaccessible. The command never contacts TypeSafe or
prints the key; a present key may still be rejected on the first provider call. Missing or rejected
credentials require a user login prompt, not an automatic model fallback.

Credential enrollment does not grant workspace disclosure consent; authorize each canonical workspace
separately as described below.

## Workspace disclosure consent

Authorize disclosure separately for each canonical workspace before any repair route or checkpoint consultation:

```bash
python3 "$SKILL_DIR/tools/jev.py" consent authorize --workspace "$PWD"
```

Consent is stored in the per-user `IMG2_HOME/config/jev-consent.json` file, outside shareable workspace artifacts. The `jev-disclosure-v3` grant is bound to the current user and canonical workspace identity; copying or moving a workspace does not transfer consent. Re-authorize after this disclosure-policy version change; v1 and v2 grants do not authorize current routing; authorize again after the disclosure-purpose change.

Revoke authorization for this workspace with `python3 "$SKILL_DIR/tools/jev.py" consent revoke --workspace "$PWD"`. Revocation blocks dispatch and invalidates current advice before it can be consumed.

## Route

The enrolled macOS Keychain key is used by default; `TYPESAFE_API_KEY` provided through the host secret manager takes precedence. Never include credentials in commands, artifacts, or committed files.

Only a fresh, canonical Environment gate result with all 12 ordered rows evaluated pass/fail, current dependencies and an overall `fail` is eligible for live routing. The bound repair-state-v2 rows must be blocking and complete; an IP/provenance failure is eligible. Pass, unknown, partial, unevaluated, stale, mismatched or missing gate evidence is a no-call stop. Controller, budget, deadline and correction ceilings, missing consent and unsafe/oversized projection content also stop before dispatch.
The Environment exporter emits repair-state-v2 only when its required current source, evaluator, and context facts are present. Jev validates exact gate and dependency bindings and rejects missing, stale, contradictory, non-comparable, or unqualified facts; do not synthesize missing fields. Synthetic handoffs prove contract integrity only. Street, vegetation-cluster, and building-exterior remain unqualified until T5 supplies rights-cleared fixtures and qualification.

The disclosure projection is locally redacted and allowlisted: registered scene kind, pseudonymous component/evidence/feature IDs, canonical Environment gate IDs with status, coverage and normalized reason codes, registered evidence enums and bounded summaries. State and projection are each limited to 24 KiB; the serialized provider request is limited to 48 KiB. Images/source bytes, credentials, paths, filenames, provenance documents and unsafe free text are never disclosed; unsafe fields reject instead of being silently truncated.

The model is pinned to `jev-1.13.0`. Transport refuses redirects and environment proxies; a subprocess deadline contains stalled DNS, headers and body reads. Response size is bounded and requests are not retried. A route makes exactly one live request. Only a fresh, schema-validated response can publish `providerStatus=evaluated`; missing keys, provider errors, malformed responses, changed requests or changed consent fail the route, clear the current recommendation and never expose prior advice. No degraded/rules fallback is available.
No `.env` files are automatically sourced.

```bash
python3 "$SKILL_DIR/tools/jev.py" route --workspace "$PWD"
python3 "$SKILL_DIR/tools/jev.py" route --workspace "$PWD" --mode assist
```

Hard stops and noneligible Environment snapshots make no provider call. Ambiguous eligible failures ask four independent Choice questions: evidence readiness, technical domain, spec relation and repair scope. Inspect `proposal`, `providerStatus`, `authority` and the artifact path from stdout. Route errors exit 2 and publish no current advice. A `stop` proposal is not successful repair completion.

Record the approved canonical action through the existing base controller, never through this plugin. Re-evaluate after repair before calling this plugin again. Offline replay and `report-outcomes` remain diagnostics; neither can replace the current recommendation.

Artifacts: `.img2/artifacts/jev/recommendation.json` is the current view; `records/` contains immutable-named recommendations and their input snapshots. A route attempt clears the current view before validation/dispatch. Jev state updates use only `plugins.jev` through img2_core. Do not reuse old advice when files change. Check through the real gate runner before consuming advice:

```bash
python3 -m img2_core.gate_runner --plugin-dir "$SKILL_DIR" --workspace "$PWD"
```

Run with the installed harness on `PYTHONPATH` if the host does not already expose img2_core. V1 repair-state/request records are historical only and cannot validate as current advice.

## Proactive checkpoint consultation

The Environment workflow automatically invokes Jev after successful `ready-for-review` preflights at the inventory, scene-analysis, and production-brief review checkpoints. A provider request is made only when Jev is installed, current v3 workspace consent is granted, and credentials are available.

Environment invokes this command at a content-addressed receipt path under `.img2/artifacts/environment/jev-checkpoints/`; for manual use, pass the exact receipt path emitted by the Environment checkpoint step.

The input is the exact `img2.jev-checkpoint-context` v1 object. Jev validates the stage-specific closed schema, canonical context digest, and each workspace-relative binding locally before and after dispatch. The provider projection contains only the checkpoint enum, numeric aggregate metrics, and stable signal codes; it excludes binding paths, hashes, workspace identity, OCR, images, and free text. A `request-input` signal is a no-call status. Missing v3 workspace consent or TypeSafe credentials also returns `not-consulted` without dispatch.

Checkpoint consultations use a separate question-set and advisory artifact schema, are single-dispatch with exact-result cache reuse, and never validate as repair recommendations or mutate the existing repair route, Environment gate, or workflow state. Their `suggestedAction` is one of `human-review`, `request-input`, `revise-artifact`, `defer`, or `stop`; this is advisory only, never a pass, approval, or repair authorization. No fallback or retry is available.

## Record measured outcomes

### Persist outcome-v2 records

Create an `img2.repair-outcome` version-2 JSON input with the complete closed schema: `recommendationId`,
`attemptId`, `outcome` (`improved`, `unchanged`, `regressed`, `inconclusive`, or `build_failed`),
`recommendationHash`, `approvedAction`, `actualAction`, `recommendationFollowed`, and `assetAdapter`;
`beforeSnapshot` and `afterSnapshot` (each with snapshot `id`, `evaluator` identity/version,
`measurementContextHash`, and typed `metrics` of feature id/value/unit/direction); typed `measurements.rows`;
`adjudication` (`status`, `adjudicatorId`, `method`, `recordedAt`); `evidencePaths`;
`buildFailureEvidencePaths`; and `evidenceClass`. Actions are `{ "action": ..., "tactic": ... }`;
the follow flag must match whether the actual action equals the approved recommendation. Measurements must
match the before/after metric identities and values. Use real evaluator evidence in production; test fixtures
marked `synthetic` are never release evidence.

The input record flag `recommendationFollowed` is validated against `approvedAction` (`actualAction` equals
`approvedAction`). Reports independently recompute routing agreement and the `recommendationFollowed` stratum
against the immutable archived recommendation proposal (`actualAction` equals that proposal). An override may
remain an eligible measured outcome, but it is not a followed Jev recommendation.

`beforeSnapshot.evaluator` and `afterSnapshot.evaluator` each contain `id`, `version`, `adapter`, and
`checksDigest`. Each quality metric uses exactly `{featureId, value, unit, direction}`; `direction` is
`higher-is-better` or `lower-is-better`. Each measurement row uses exactly
`{featureId, beforeValue, afterValue, unit, direction}`. `measurementContextHash` is SHA-256 over canonical
UTF-8 JSON (object keys sorted, compact separators) of a projection containing `adapter`, ordered
`scene-intake.sourceViews` entries `{id, sha256}`, ordered `scene-spec.reviewViewpoints`, and `scene-review`
fields `camera`, `renderer`, `resolution`, `exposure`, `toneMapping`, `background`, `environment`,
`iblContribution`, and `qualityMeasurementMethod`. `qualityMeasurements` values are excluded from this hash;
`qualityMeasurementMethod` must be nonempty.

The before gate must be recommendation-bound to the archived request evaluation and agree with the before
snapshot. Its result bytes must be in `evidencePaths`, along with hash/size-matching historical copies of
canonical `.img2/artifacts/environment/scene-intake.json`, `scene-spec.json`, and `scene-review.json`; after
repair those copies may be stored under archived workspace-relative paths. Each non-`build_failed` quality
outcome must also include the current after-gate result and current canonical context files. The after snapshot
must bind the current Environment gate for the same evaluator/context; all 12 canonical gate rows must be
`pass` or `fail` and carry their required reasons/evidence.

`record-outcome` archives at most 12 evidence files / 64 MiB total, and the persisted record is capped at
128 KiB. For `build_failed`, set `afterSnapshot` to `null`, leave `measurements.rows` empty, and provide a
nonempty `buildFailureEvidencePaths` list (including the failure log); every listed path must also appear in
`evidencePaths`.

`adjudication.status=independent` is caller-declared. Jev records that declaration but does not
authenticate reviewer identity or independence; it is not proof that review was independent.

```bash
python3 "$SKILL_DIR/tools/jev.py" record-outcome --workspace "$PWD" --input .img2/artifacts/jev/outcome-v2-input.json --recommendation .img2/artifacts/jev/records/RECOMMENDATION_ID.json
```

The version-1 `record-outcome` path remains unchanged for archival compatibility. Version-1 records are
legacy-only and are excluded from version-2 reports.

### Build and report an explicit corpus

Construct a JSONL corpus by appending the complete persisted v2 record artifact for each record you
intend to analyze (one JSON object per line); for example, select record artifacts explicitly:

```bash
: > outcomes-v2.jsonl
cat .img2/artifacts/jev/outcomes/archive/records/RECORD_HASH.json >> outcomes-v2.jsonl
python3 "$SKILL_DIR/tools/jev.py" report-outcomes --workspace "$PWD" --input outcomes-v2.jsonl
```

The reporter reads exactly the selected corpus; it does not discover or merge other corpus files. For
integrity verification it also reads the archive blobs, recommendation, and request linked by each
selected persisted record. It makes no provider calls even when credentials exist. Reports are immutable,
content-addressed JSON under `.img2/artifacts/jev/reports/`; the machine-readable command result references
the artifact. Reporting does not change routes, recommendations, Jev state, or Environment snapshots.
Each report is subject to the existing 128 KiB JSON artifact limit. If a corpus would produce a report
over that bound, generation fails closed before writing any report artifact: exclusions are not truncated
and reports are not sharded.

Only records with `evidenceClass=observed`, `adjudication.status=independent`, and comparable before/after
evaluator and measurement contexts enter totals. `evidenceClass=observed` is caller-declared: use it only for
real evaluator-collected attempts, never synthetic fixtures. Archive hashes attest byte integrity, not truthful
measurements or genuine observation; Jev cannot independently authenticate that claim. Synthetic, unadjudicated,
incomparable, invalid, and legacy-v1 records are excluded with reasons. Invalid-record entries expose stable
category and corpus line/record identifiers, not low-level validator text. Quality denominator = improved + unchanged + regressed. Attempt
denominator adds build_failed. Inconclusive is reported separately, outside both denominators. Rates include
Wilson 95% intervals. Routing agreement is a separate descriptive measure, not part of outcome denominators.
Every report is observational, has zero live calls, and remains `calibrationStatus: uncalibrated`: no
calibration or causal-success claim follows from these summaries. There is no auto/auto-safe mode and no
Environment acceptance authority. Synthetic test fixtures are never presented as release evidence.
## Offline replay

JSONL rows have `caseId`, `state`, `control`, `response` (a recorded TypeSafe response or null), and
`acceptable` (one or more objects with `action` and `tactic`). Replay runs rules and recorded-response
policies over identical states; it makes no network calls and does not validate archived file freshness.

```bash
python3 "$SKILL_DIR/tools/jev.py" replay --workspace "$PWD" --input evaluation/cases.jsonl
```

Report acceptable routing, actionable coverage and conditional precision together. Replay cannot prove
saved repairs, live quota savings or unchanged final quality. Keep asset families together in data splits.
Requalify on any question, policy, normalizer or model upgrade. No historical accuracy claims are bundled.

## Development verification

Set `IMG2_HARNESS_DIR` to a local img2 checkout, then run `python3 -m unittest discover -s tests -v`
from this plugin repo. Tests use temporary workspaces and no paid provider requests. Verify installation,
capability resolution, `doctor`, `sync --check`, and the real gate runner against an isolated IMG2_HOME.
