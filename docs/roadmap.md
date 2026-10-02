# Public roadmap

## Bounded preserved replacement prefix

Optional `replace.preserve_prefix_pattern` preserves the first regex match only when it starts at byte zero, then applies replacement to the remaining suffix with suffix-relative anchors/captures. The complete prefix counts toward the unchanged output bound and remains visible to later stages and the predicate. Full-input skip conditions run first; eager bounded compilation, UTF-8/value/NUL guards, complete core inspection and original HTTP bytes remain unchanged.

All 96 Rust semantic cases and 34 correlated neutral HTTP groups pass, with clippy/formatting, foundation/scorer and both statistics checks. Cursor independently reviewed the change and ran the two prefix unit tests with no blocker. An old pipeline-close fixture initially raised ConnectionResetError; after review it accepts reset as closure while requiring one valid HTTP response and exactly one backend execution. Full suite then passes. These are generic neutral proofs, not application equivalence, artifact resources or deployment acceptance.

## Conditional bounded replacement

The optional `replace.skip_pattern` matches the complete current stage input once and skips only that replacement. Omitted/null conditions retain unconditional replacement. Conditions use the existing bounded regex compiler; replacement patterns and capture templates are validated even when always skipped. Later stages, the predicate, value/NUL limits, full core inspection, original bytes and ban-confidence rules remain active.

All 94 Rust semantic cases and 33 correlated neutral HTTP groups pass, with clippy/formatting, foundation/scorer and both statistics checks. Tests cover current-input matching, later-stage execution, eager startup validation, input/output bounds, exact HTTP body/hash/ID forwarding, predicate denial and sibling-core denial without backend execution or bans. Cursor independently reviewed the change and ran both replacement unit tests with no merge blocker. Its documentation consistency suggestion was applied afterward. This generic capability does not establish application equivalence, resource qualification, deployment or site protection.

## Equal decoded scalar bounds across encoded and literal media

Selected form/query values now have an independently bounded 24,576-byte wire representation before decoding and the existing 8192-byte decoded UTF-8 scalar cap afterward. Literal MIME/header/target and projection bounds stay at 8192 bytes. This permits fully percent-encoded values at the scalar limit without lifting the decoded budget. Invalid encoding, NUL, oversized wire/decoded values and existing GP/ambiguity behavior still fail closed.

All 92 Rust semantic cases and 32 correlated neutral HTTP groups pass with clippy/formatting, foundation/scorer and both statistics checks. ASCII and multibyte UTF-8 witnesses preserve original bytes/backend hashes at the bound; wire/decoded oversized controls have no backend attempt or ban. Cursor reviewed the change and ran both binding-size unit cases with no merge blocker. Application parser/workflow and exact-artifact resources/deployment remain separate gates; this does not establish site protection or full acceptance.

## Conditional sequence removal

The optional `remove_sequences.skip_pattern` is compiled with the existing bounded regex limits and matches the current complete stage input once. A match skips only deletion; later projections, the selected-input predicate, full core inspection, original HTTP forwarding and value/privacy limits remain active. Omitted/null settings preserve unconditional deletion. Invalid patterns and ambiguous sequence sets fail startup.

All 90 Rust semantic cases and 31 correlated neutral HTTP groups pass with clippy/formatting, foundation/scorer and both statistics checks. Cursor independently reviewed the delta and ran the five sequence unit cases with no merge blocker. After review, HTTP reason/sibling-core assertions were added and two pre-existing early-ban fixtures were changed to empty bodies to avoid racing the deliberate connection close; the transport suite then passed. Actual application equivalence, artifact resources, deployment and full acceptance remain pending. This generic option enables declared conditional transforms, not an implicit sanitizer or bypass.

## Recursive literal sequence removal

The optional `remove_sequences` projection reaches the full deletion fixed point using a bounded streaming UTF-8 stack. Startup restricts the literal set to equal-width, nonoverlapping words; empty, duplicate, oversized and ambiguous sets are rejected. Nested inputs through the full 8 KiB value bound are supported without a recursion-depth cutoff. Values and original HTTP bytes remain private/unchanged; no ban confidence is inferred. All 88 Rust semantic cases and 30 correlated neutral HTTP groups pass, with clippy/formatting, foundation/scorer and both statistics checks. Cursor independently reviewed the mechanism and ran the sequence tests with no blocker identified. Actual application equivalence, private policy, artifact resources, deployment and final acceptance remain pending.

## Bounded selected-input projections

Opt-in per-source and common projection stages now support bounded regex replacement/captures, trimming, query removal, conditional segment form encoding and empty-result fallback. Original truthiness selects a source before projection; no transformed-empty fallback restart occurs. A sixteen-stage total budget, 8 KiB intermediate limit and 64 KiB regex program/cache bounds apply. Forwarded bytes, full core inspection, body-free provenance and no implicit ban confidence remain unchanged. All 85 Rust semantic cases and 29 correlated neutral HTTP groups pass, with clippy/formatting, foundation/scorer and both statistics checks. Cursor independently reviewed the capability with no blocker identified; a defensive per-stage result guard was added and locally verified. Actual plugin equivalence, site policy, artifact resources, deployment and full acceptance are pending. See [the stage contract](../crates/waf-wordpress/README.md).

## Step 01 — Contracts and composition

Profile composition is implemented with nine passing integration tests; schema-v1 body-free decision records are implemented with the proxy. Define profile/event formats, inheritance, versions, explicit exceptions, and invariants. Acceptance: deterministic composition, meaningful tests, rejection of cyclic/ambiguous configuration, and traceable exceptions that cannot silently weaken core invariants.

## Step 02 — Rust proxy and neutral test backend

Unix HTTP transport, complete-body inspection and neutral-backend protocol evidence are implemented. Nginx parser consistency and additional adversarial cases remain pending. Implement transport, normalization, complete-body limits/inspection, and a neutral backend. Acceptance: encoding/multipart/ambiguity tests, consistent parsing across Nginx/Rust, correlation, fail-closed behavior, and backend non-execution after a denial.

## Step 03 — Common rules and labeled corpus

Seven initial common patterns, observe/enforce decisions, a 30-case fictional development corpus and correlated neutral-backend checks are implemented. Independent acceptance coverage is pending. Implement decisions and common rules with observe/enforce modes. Acceptance: independent labels, actual decision records, TP/FP/TN/FN scoring, separate exception cases, and backend proof independent of HTTP status.

## Step 04 — Generic WordPress specialization

Scoped scalar input constraints now support explicit GP/header/target selection, falsey fallback, strict media and pre-backend denial with neutral protocol evidence. Site-derived virtual patches still require actual consumer/helper/filter analysis, legitimate PHP workflows and mandatory no-execution boundaries. These policies do not automatically establish reliable ban confidence.

Canonical nested URL-encoded leaf paths are implemented in the shared origin API with collision and fingerprint tests. The WordPress adapter now supports explicit opt-in canonical AJAX form consumer contracts with stable guards and FPM assumptions; actual plugin consumers remain unqualified. Qualify PHP normalization/tree collisions, dispatch, schema and permission boundaries with actual positive and negative workflows before enabling site exceptions. Conservative multipart text origins and explicit AJAX media opt-in are implemented; actual FPM/schema/workflow and artifact resource qualification remain required. Unsupported array shapes and JSON origins require separate implementation where justified.

The shared engine now exposes a form-origin-aware exception API with explicit application confirmation and all-match hull checks. WordPress now confirms fields on explicitly declared login and AJAX consumers; base profiles confirm nothing. Qualify actual WordPress consumer/action and PHP scalar/alias/array/collision behavior, then prove actual password/rich-content compatibility and negative sibling/dispatch/permission boundaries. Multi-field aggregation is implemented in the core with independent per-field scopes/confirmations and all accepting span checks; actual additional plugin consumers, JSON origins, multipart workflow qualification and deployed unapplied-candidate observability remain required where real workflows justify them. This prerequisite does not complete the application step.

Dispatch, effective methods, administration trust and evidence-bearing site method policies are implemented with eight semantic tests and correlated HTTP tests. Browser workflows, field-scoped exceptions, role/nonce integration and optional plugin modules remain pending. Qualify REST, AJAX, login, uploads, roles, methods, and optional plugin modules. Acceptance: legitimate workflows preserved; positive/negative permission and body tests; route alternatives and method overrides covered; no assumptions about a particular deployed site.

## Step 05 — Integration and reusable evidence

The bounded local ban table and early proxy check are implemented and tested. Reusable dynamic proxy/FastCGI bridge/service/correlation examples and body-free read-only event aggregation are implemented. The optional private read-only early-ban socket and Nginx access-phase templates are implemented with shared-table protocol tests; actual installed behavior, independent performance and per-installation acceptance remain required. Integrate the isolated Nginx FastCGI backend, read-only statistics, ingress adapters, and bounded temporary bans. Acceptance: no bypass, correct stop behavior, friend-IP cases, comparable baseline/protected load tests, latency/throughput/error/resource measurements, and correlated non-execution proof. No per-attack Cloudflare API calls.

Site qualification and private profiles are owned by their deployers and maintained separately. An analysis agent builds each site layer from actual installed plugins/themes, custom code, core differences and observed behavior, then tests the resulting policy. Changes to those components require targeted requalification. Public steps are not completed by this initial documentation alone.

Use short-lived branches when each step starts: `step-01/profile-contracts`, `step-02/http-proxy`, `step-03/common-rules`, `step-04/wordpress-profile`, `step-05/integration-proof`. Do not create empty permanent layer branches.

The current publication credential does not allow GitHub Issues access. This versioned roadmap remains the source of task tracking until Issues permission is available. No Issues were created.
