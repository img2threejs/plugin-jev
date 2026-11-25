# Changelog

## Unreleased

### Added in 0.5.0

- Add strict Character material-only policy/questions and an exact path-free, hash-bound evidence
  lane. Refuse normal-only, incomplete inventory, missing physical pose coverage or inconsistent
  renderer/pixel/camera/ROI facts before cache reuse or paid reservation.
- Verify decoded source PNG/raw RGBA parity, including fractional alpha, before independently
  matching full-frame prepared RGB pixels and transforms. Preserve existing image/envelope caps.
- Keep generic quality behavior and historical cache/accounting liability unchanged; native
  producer attestation, replay, installation and paired host-ledger qualification remain core-owned.
- Advance manifest, repair CLI and checkpoint artifact version together to 0.5.0; no core/img2 pin
  updates or implicit compatibility aliases.
- Reject collapsed/dependent material camera world bases before compiling questions or
  provider preflight; normalize the basis-volume check to preserve nonsingular camera scaling.
- Make the cardinal boundary platform-independent with an exact-ratio comparison; retain
  rounded-outside sine/cosine vectors as negative cases rather than widening the tolerance.

### Fixed in 0.4.0

- Validate and freeze full wire framing before durable reservation. Release only a definite
  matching 401/403 rejection; retain ambiguous sends and account valid usage before answer validation.
- Bind decision send/charge evidence to context, consent, logical request and a host invocation nonce.
  Replay intact completed results without credential lookup; reject revoked or stale evidence.
- Migrate v4 grants atomically to private per-workspace/run storage with old-version fencing,
  independent run locks, bounded contention, atomic workspace revocation and explicit retirement.
  Preserve all grant generations, historical spend and budget floors; remove the global 128-run ceiling.
- Preserve bounded named/numeric views consistently and require hash-bound typed placement facts.
- Convert embedded ICC color to sRGB before stripping metadata, preserve alpha, and sanitize corrupt PNGs.
- Restore test import scopes without deleting shared core modules; add full one-process Python CI.

### Added

- Add a separate `jev consult` checkpoint-review route for aggregate-only inventory, scene-analysis, and production-brief receipts. It validates context digests and local bindings before and after one bounded TypeSafe dispatch, uses fixed checkpoint Choice questions, persists advisory-only content-addressed results, and never mutates the existing repair recommendation or gate state.
- Require `jev-disclosure-v3` consent for the new pre-model checkpoint disclosure purpose; existing v2 grants require reauthorization.
- Add local `auth-status` (0 present / 3 missing / 1 storage error), without exposing a credential or
  contacting TypeSafe. Presence does not establish that TypeSafe accepts the key.
- Add internal four-group decision question/response adapters and isolated image transport:
  controlled disclosure, explicit unevaluated review evidence, EXIF-upright image preparation and
  reversible Box coordinates, bounded HTTPS requests and separate credential-rejected outcomes.
  Optional image support uses `requirements-decisions.txt`; the base core stays dependency-free.
- Expose the four typed decision edges through `decision-routing`, `decision-build-strategy`,
  `decision-quality-review` and `decision-repair`. Require separately acknowledged v4 disclosure/paid
  consent for the exact workspace/run, with a durable shared token budget and conservative 64k
  reservation before every send. Record actual validated usage; retain unknown reservations.
- Keep v3 grants and Environment-only repair/checkpoint contracts separate. Never auto-widen older
  consent. Recheck consent/evidence around dispatch; refuse unsafe paths, unprepared images, revoked
  grants and ambiguous attempts. Completed exact-result replay makes no additional provider call.
- Declare only those callable typed edges and contributed commands; no automatic production hooks,
  live qualification or acceptance authority is implied.
- Add explicit `consent decline-decisions` enrollment with a run-bound budget but no Jev image,
  paid-call or purpose authorization. Provider callers still require a live grant; the host must
  independently approve any fallback.
- Support bounded dot/colon opaque decision identifiers needed by critical-feature bindings and
  typed placement choices. Omit free-form candidate labels from the outbound field allowlist;
  route descriptions remain fixed approved semantics, never caller-authored filenames or instructions.

### Changed

- Advance routing to `route-questions-v3` with no earlier-version alias. Separate visual localization
  from closed route selection: empty candidates, only missing-object and per-target Noul/Box evidence,
  and complete validated current-round inventory disclosed as data. Omit unused localization
  candidates from provider state; preserve typed absence and all existing controller gates.
  Scope missing-object judgment to omitted independently reconstructable foreground subjects, not
  background scenery or already-covered contained details. Other three decision-group versions remain unchanged.
- Bump Jev to 0.4.0; old repair/checkpoint recommendation records are stale under the current plugin version. Repair-state-v2 question and policy semantics remain unchanged.


### Added

- Require img2 harness 0.2.5+ and document per-installer `img2-jev login` enrollment of each user's own TypeSafe API key in their macOS Keychain; credentials are never shared, and workspace disclosure consent remains a separate per-workspace step.

- Add static Jev source/dependency mappings for room, street, vegetation-cluster, and building-exterior while keeping room as the only fixture-qualified route/outcome/report adapter.
- Allow measurement-backed repair-state-v2 evidence and require implementation facts to identify implementation as their source.
- Add workspace-independent jev login enrollment through a hidden macOS Keychain prompt; login stores credentials without contacting TypeSafe. The first live route verifies the key, and TYPESAFE_API_KEY remains the automation override.
- Add per-user, canonical-workspace-bound structured-disclosure consent with revocation, plus a bounded locally redacted outbound projection whose hash and policy version are bound to recommendation archives and revalidated before use.
- Parse every international-number candidate fail-closed: redact only complete supported phones and numeric extensions, or refuse malformed compact/grouped/parenthesized values and invalid suffix tails before provider dispatch; do not expose a matched numeric prefix.
- Rotate a private local consent generation on every authorize/revoke transition so stale advice and in-flight responses cannot survive a revoke/reauthorize cycle; keep the generation out of provider requests.
- Version archived outbound requests as v2 and bind each archive to the exact local grant hash, so earlier advice cannot be paired with a later consent generation; v1 archives remain historical only.
- Serialize consent updates and preserve decision-relevant evidence summaries after local path, credential, and PII redaction; historical component and feature references remain pseudonymous.
- Redact Authorization and Proxy-Authorization values including LF-folded continuation lines, plus standalone Bearer credentials. Pseudonymize exact known dotted IDs before screening any remaining compound filename, including ID-prefixed private filenames.
- Preserve adjacent signed decimal/fraction measurements with distinct hashes while redacting supported international and domestic phone formats, including one-digit national groups, common 4+6 UK mobile groups, and x/ext/# extensions as complete tokens. Refuse unconsumed numeric groups and punctuated phone tails (with or without an extension), incomplete whole-number candidates, repeated extensions, Unicode combining-mark boundaries, Unicode-letter tails after numeric domestic extensions, and non-delimiter international extension tails before serialization or provider dispatch. Keep complete unit-bearing measurements separate from phone matches. Consume repeated-space/tab-separated domestic groups; refuse genuine overlong international numbers. Redact Unicode filenames and preserve terminal punctuation.
- Reject malformed phone-extension and numeric suffix tails across punctuation, Unicode symbols, and whitespace—including repeated/mixed comma-semicolon chains—before credential resolution or provider dispatch; preserve complete decimal/fraction measurements after explicit separators and while pseudonymizing numeric identifiers.

### Changed

- Require a fresh, canonical, complete 12-row failed Environment gate and repair-state-v2 snapshot for live routing; stale, passing, incomplete/unknown, unsafe, consent, controller, budget, deadline and correction-limit stops make no provider call.
- Remove the rules provider and degraded fallback. A route makes one TypeSafe request and publishes only a fresh validated response; failures clear current advice instead of exposing the previous recommendation.
- Bound state and projection to 24 KiB and serialized requests to 48 KiB. Bump disclosure consent to `jev-disclosure-v2`; v1 grants require reauthorization and v1 requests/reports remain historical only.
- Keep historical repair-state-v1 observations ineligible for live routing; accept repair-state-v2 measurement facts only within current source-bound snapshots.
- Document the live projection cap of 12 contextual components and five focused components for one issue; omitted subjects remain Environment-gated but are not Jev-reviewed.

## 0.2.0 — 2026-09-28

### Added

- Add outcome-v2 collection through the existing `record-outcome` CLI, binding outcome records to recommendation and evaluator evidence; bound archives to 12 files / 64 MiB and persisted records to 128 KiB. Version-1 outcomes remain archival-only and are excluded from reports.
- Add the offline `report-outcomes` CLI over exactly one explicitly selected workspace-relative JSONL corpus, writing deterministic content-addressed reports under `.img2/artifacts/jev/reports/`; bound input to 64 MiB and 100,000 records.
- Report observational quality and attempt denominators, Wilson 95% intervals, strata, exclusions, and routing agreement only when the actual action/tactic matches the archived recommendation proposal. Provenance is caller-declared and is not independently authenticated.
- Reports are uncalibrated, make no live provider calls, and offer no causal claims. Jev remains advisory-only: reports do not grant Environment acceptance authority or mutate routes, recommendations, Jev state, or Environment snapshots.
