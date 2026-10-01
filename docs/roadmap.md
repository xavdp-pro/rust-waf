# Public roadmap

## Step 01 — Contracts and composition

Define profile/event formats, inheritance, versions, explicit exceptions, and invariants. Acceptance: deterministic composition, meaningful tests, rejection of cyclic/ambiguous configuration, and traceable exceptions that cannot silently weaken core invariants.

## Step 02 — Rust proxy and neutral test backend

Implement transport, normalization, complete-body limits/inspection, and a neutral backend. Acceptance: encoding/multipart/ambiguity tests, consistent parsing across Nginx/Rust, correlation, fail-closed behavior, and backend non-execution after a denial.

## Step 03 — Common rules and labeled corpus

Implement decisions and common rules with observe/enforce modes. Acceptance: independent labels, actual decision records, TP/FP/TN/FN scoring, separate exception cases, and backend proof independent of HTTP status.

## Step 04 — Generic WordPress specialization

Qualify REST, AJAX, login, uploads, roles, methods, and optional plugin modules. Acceptance: legitimate workflows preserved; positive/negative permission and body tests; route alternatives and method overrides covered; no assumptions about a particular deployed site.

## Step 05 — Integration and reusable evidence

Integrate the isolated Nginx FastCGI backend, read-only statistics, ingress adapters, and bounded temporary bans. Acceptance: no bypass, correct stop behavior, friend-IP cases, comparable baseline/protected load tests, latency/throughput/error/resource measurements, and correlated non-execution proof. No per-attack Cloudflare API calls.

Site qualification and private profiles are owned by their deployers and maintained separately. Public steps are not completed by this initial documentation alone.

Use short-lived branches when each step starts: `step-01/profile-contracts`, `step-02/http-proxy`, `step-03/common-rules`, `step-04/wordpress-profile`, `step-05/integration-proof`. Do not create empty permanent layer branches.

The current publication credential does not allow GitHub Issues access. This versioned roadmap remains the source of task tracking until Issues permission is available. No Issues were created.
