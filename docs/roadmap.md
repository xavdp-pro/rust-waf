# Public roadmap

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
