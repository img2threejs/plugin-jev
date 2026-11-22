# Four-purpose Jev decision commands

Use these commands only at a trusted controller's admitted decision boundary. Jev returns advice,
never acceptance, executable code, a successful repair claim, or permission to change a scene.
Do not invoke a visual request where deterministic pipeline checks forbid vision.
Legacy `route` / `consult` retain their Environment-only v3 contracts and text-only projection.

## Obtain the user's separate authorization

Ask the user to run `img2-jev login` when credentials are missing or rejected. Never handle the key.
`img2-jev auth-status` is local-only: exit 0 present / 3 missing / 1 storage error. Presence is not
remote validation. Credentials come from Keychain or the host-secret-manager `TYPESAFE_API_KEY`;
there is no key argument, input field or credential output.

Before any image/reference/render bytes are read by a decision command, the user must separately
approve their disclosure to TypeSafe **and paid calls for all four purposes**: routing, build-strategy,
quality-review and repair. Show the exact run id and token budget; never authorize on the user's behalf.
V3 grants are not upgraded and v4 does not grant legacy Environment consent.

```bash
python3 "$SKILL_DIR/tools/jev.py" consent authorize-decisions --workspace "$PWD" \
  --run-id run-1 --token-budget 256000 --accept-image-disclosure --accept-paid-calls
python3 "$SKILL_DIR/tools/jev.py" consent decision-status --workspace "$PWD" --run-id run-1
python3 "$SKILL_DIR/tools/jev.py" consent revoke-decisions --workspace "$PWD" --run-id run-1
```

Both acknowledgements and a positive integer budget are required. The command's success JSON includes
`granted`, `purposes`, `sha256` and `tokenBudget`, matching the controller's live consent-probe shape.
`decision-status` reads local consent only; it does not contact TypeSafe or inspect credentials.
`revoke-decisions` without `--run-id` revokes every v4 grant for this workspace. Legacy `consent revoke`
revokes v3 plus all v4 grants. Reauthorization changes the consent digest but never resets run spend.
Extend a budget only by repeating the authorization command with explicit user approval and a larger
budget for the same run; a smaller budget is refused.

V4 grants live in private user-owned `IMG2_HOME/config/jev-decision-consent.json`, not in shareable
workspace artifacts. User, canonical workspace path and run id are bound locally. Copies/moves do
not inherit grants. Per-run private ledgers survive command restarts and consent renewal.

## Prepare the trusted handoff

Use the current `jev_decision_questions` context contract: exact kind/version/group,
subject `{runId,objectId,revision,passId}`, bindings, candidates, observations, requirements,
policyVersion, questionSetVersion and requestedModel `jev-1.14.0`. Every binding must include a
workspace-relative `path` and current `sha256`. The CLI verifies real bound bytes before and after
consultation; the caller still owns evidence completeness, provenance, eligibility and stage admission.
Do not pass a model-authored replacement for a trusted controller snapshot.

`observations.images` contains only `{role,asset}` opaque placeholders. Prepare the admitted images
using `jev_decision_images.prepare_image` **only after user consent**. Write an assets JSON map whose
keys equal the placeholders and whose values are the exact preparation records:
`{format,data_base64,sha256,width,height,transform}`. Current preparation emits metadata-free RGB PNG;
raw paths, original raster files, wire-only records, extra fields and unprepared JPEGs are not accepted
as assets. The CLI verifies actual image format/dimensions, stripped metadata, SHA-256 and transform
shape; preparation provenance remains the trusted caller's responsibility. It does not invent images
or evidence. Image-free numeric decisions use `{}` or omit `--assets`.

Only safe workspace-relative regular files are opened: no absolute paths, parent traversal, symlinks,
FIFOs or device files. Context JSON is bounded to 256 KiB; prepared assets JSON to 48 MiB; decoded
images to 16 MiB each / 32 MiB total. The transport bounds transmitted wire bytes to 32 MiB; this is
not proof of the server's separate postprocessed/expanded 32 MiB limits, where every image-reference
use counts again. Server HTTP 413 remains an explicit `request-too-large` failure.
Images are 280–1568 pixels per side. Pillow is an optional dependency in `requirements-decisions.txt`;
missing image support blocks dispatch, never triggers installation.
Deterministic question batching/splitting remains unresolved in this bounded reference-safety fix.
No questions are dropped or silently retried to fit; an oversized request fails closed.

## Invoke exactly one typed edge

| Command | Context kind → declared advisory edge | Question set |
|---|---|---|
| `decision-routing` | `img2.route-context` → `img2.route-advisory` | `route-questions-v3` |
| `decision-build-strategy` | `img2.build-strategy-context` → `img2.build-strategy-advisory` | `strategy-questions-v1` |
| `decision-quality-review` | `img2.quality-review-context` → `img2.quality-review-advisory` | `quality-review-questions-v1` |
| `decision-repair` | `img2.repair-context` → `img2.repair-advisory` | `repair-decision-questions-v1` |

```bash
python3 "$SKILL_DIR/tools/jev.py" decision-routing --workspace "$PWD" \
  --input .img2/artifacts/jev/contexts/routing.json \
  --assets .img2/artifacts/jev/contexts/routing-assets.json --timeout 15
```

Use the analogous group-specific paths for the other three declared steps. No installation-time or
automatic workflow hook is added. The trusted host explicitly invokes the appropriate step after
creating its fresh context and asset map. The timeout is a total transport deadline in `(0,30]` seconds.

Success JSON has `status=answered`, `reasonCode=answered`, `advisory`, `artifact`, `cached` and
`consentSha256`. The Wave 1 envelope is `img2.decision-advisory` v1 with group, subject, contextDigest,
served model, answers and usage. It is the payload of each declared typed edge, not a canonical verdict.
Low probabilities, confidence or positive `anyFits` Noul remain unchanged for the controller to arbitrate.
The allowlisted provider projection drops local paths, filenames, arbitrary prose and executable data.
The advisory digest covers the controller-safe context: bindings contain only `{role,sha256}`.
The CLI keeps a detached original with binding paths for local pre/post freshness checks and cache
identity; those paths are neither provider input nor part of the returned advisory digest.
TypeSafe replaces asset-reference substrings throughout string values. The adapter therefore maps
caller asset ids to deterministic `imgref-<sha256>` wire references and requires exactly one whole
placeholder occurrence per image, with none in other state text, instructions or criteria.
Collisions block dispatch; local asset ids, controller digests and path-based questions stay unchanged.
Routing Choice descriptions are fixed program text for `base-generic`, `interior`, `character`, `cs2`
and `pixi2d`, never copied from candidate display/labels. Unknown routes and other groups retain the
generic option description; these descriptions do not establish provider readiness or acceptance.
Routing `crop-choice` instead compares `model-crop`/`jev-crop` for complete intended-object coverage
and minimal unrelated content; unique matching images/bindings and the separate sufficiency Noul are required.
Routing requires `route-questions-v3`; earlier routing contexts and cached advice are not reusable.
Routing request disclosure preserves only expectedOutput `2d`/`3d`, intent `rig`, and an explicitRoute
equal to one of those approved route ids. It is not full intent fidelity. Room/instance disclosure
allows controlled roles, normalized boxes, opaque ids, numeric roomCount, enclosure `enclosed-room`
or `unknown`, and stylization only `unknown`; unrecognized values and arbitrary prose are omitted.

Routing contexts with `requirements.decomposition` are visual localization, not route selection.
They require `candidates=[]` and exactly this decomposition shape:
`{image,objects:[{id,label,approxBox}],inventory:[{id,label,role,approxBox}]}`.
The full current-round inventory includes every proposed object, not only the current targets.
Round 2 retains first-round proposals unchanged and adds only new proposal IDs; its localization
targets are the additions, while its inventory is the accumulated first-round-plus-additions list.
IDs are unique within each list; labels are bounded opaque identifiers, roles are `scene-container`,
`subject`, `prop` or `set-dressing`, and boxes are normalized `[left,top,right,bottom]` with positive
area. Each target's id, label and approximate box must match an inventory entry. Targets retain
the 12-item bound; inventory uses the existing bounded-JSON list limit of 256, not a 12-placement cap.
Only `missingObjects:Noul` and each target's `object:<id>:visible:Noul` / `object:<id>:box:Box`
are asked. No Selection or `anyFits` is generated or accepted. The provider sees the complete
validated inventory and target labels/roles/boxes as data, with no unused `candidates` state.
Owner/expert/ground-truth fields are not disclosed; they are invalid inside decomposition entries.
Typed valid absence remains answered evidence, not provider unavailability or route acceptance:
the controller alone drops invisible targets and applies unchanged Box/crop uncertainty rules.
`missingObjects` concerns an omitted independently reconstructable foreground subject needed for
the declared request, assessed against the full inventory. Background scenery, contained details
and parts already covered by an inventoried subject or scene-container do not separately require
routes. This is not a whole-scene completeness waiver or a required false answer. Genuine route,
crop, placement, strategy and repair choices still require nonempty closed candidates and `anyFits`.

Strategy projection preserves known/approved interior operation enums, opaque `components`/
`componentIds`, exactly allowlisted native/base `fieldPaths`, and boolean `rigHandoff`.
`materialSourcesPresent` reports only a nonempty list of valid SHA-256 values, not provenance
authorization; source hashes are not disclosed. Unknown operations, arbitrary field-path text,
`specFields` and `expectedMeasurements` remain omitted.

Failure JSON exits 2 with `status=request-input` and a reason code. Missing/rejected credentials are
`credential-missing` / `credential-rejected`, distinct from `credential-storage-error`, and name
`img2-jev login`. Missing/refused consent, exhausted budget, stale evidence, malformed answers and
provider failures never become fabricated success or implicit model fallback.

## One shared durable budget and bounded attempts

All four commands serialize on one user-owned consent lock and reserve **64,000 tokens per send**
in the same per-run ledger, atomically persisted and fsynced before transport. The 64k assumption is
the approved conservative model request bound, not a tighter provider-side `max_tokens` setting.
Do not claim stronger remote enforcement: the adapter exposes no output-token control. Validated
input+output usage replaces the reservation; unaccounted/failed sends retain all 64k. An observed
over-64k result is recorded at its actual usage and blocked as `provider-token-bound-exceeded`.
A budget below one full reservation cannot dispatch, even for a likely small request. Group changes,
new processes, retries and reauthorization never reset spend. The base controller's own ceiling also
continues to apply; the two guards count the same calls, not two separate spending allowances.

Consent is rechecked before asset reads and immediately before dispatch, and after the response.
The grant lock spans the request: revocation waits for an already-authorized request to finish;
once revocation completes, later requests cannot race it. Bindings are rechecked before publication.
Completed exact context/assets/consent replays reuse a hash-verified local artifact without a paid
call. In-flight or unpublishable attempts are `ambiguous-paid-attempt`; this CLI does not silently
retry them. Any explicitly approved new attempt still needs budget and a new consent generation.
No success cache is consumed after revocation. Receipts prove byte identity, not visual quality.

## Proposed offline checks (run after integration)

From the plugin repository, with `IMG2_HARNESS_DIR` set to the existing local harness checkout:

```bash
python3 -m unittest discover -s tests -p 'test_decision_enrollment.py' -v
python3 -m unittest discover -s tests -p 'test_consent.py' -v
python3 -m unittest discover -s tests -p 'test_decision_provider.py' -v
python3 -m unittest discover -s tests -p 'test_decision_questions.py' -v
python3 -m unittest discover -s tests -p 'test_manifest.py' -v
```

These fixture checks are not paid-service, held-out quality or installation qualification.
