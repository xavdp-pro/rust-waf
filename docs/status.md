# Actual status — 2026-10-01

## Bounded origin measurement window

Origin aggregation now reads a snapshot of at most the final 64 MiB, retains at most 25,000 validated projected records and discards oversized 64 KiB lines and partial prefix fragments. Appending during collection cannot extend the snapshot budget. Invalid record shapes, duration/counter types and nonfinite durations are rejected rather than crashing aggregation. Unknown input fields are discarded. JSON and the English read-only page expose window size, retention losses and rejected records; counts explicitly describe this recent window, not lifetime totals.

Six focused origin tests cover sparse large files, exact/partial boundaries, retention, growth during parsing, oversized-line fragments and malformed/sensitive extra fields. Existing WAF aggregation, foundation and scorer checks pass. This changes measurement robustness only; independent effectiveness, matched performance and deployment proof remain separate requirements. Reproduce with `python3 observability/test_origin_metrics.py`.

## Explicit WordPress login binding

Sites can now declare evidence-bearing login_consumers with a canonical path and verified GP request order. The adapter confirms pwd only for the qualified scalar POST/login consumer, withholds confirmation for GET key/checkemail overrides, action conflicts/other actions, empty values, alternate dispatch, methods and formats, and rejects PHP array/alias collisions. The gateway supplies these confirmations after application checks; the site still needs a scoped form_field exception. No login consumer or password exception is enabled in the public base profiles. No password is retained in application context or decisions.

Four new WordPress semantic tests and a twenty-first HTTP group cover three original-byte positive cases and twelve correlated negative boundaries, including denied-before-backend arrays, sibling/query matches and REST/action alternatives. Forty-six Rust cases and twenty-one neutral HTTP groups pass with clippy, formatting, foundation and scorer checks. This enables site qualification but does not prove actual password authentication, browser workflows or deployed concurrent resources. See [the WordPress consumer contract](../crates/waf-wordpress/README.md).

## Form field origin checkpoint

The shared scanner now tracks selected scalar form-value origins through complete raw/decoded body views. An optional evidence-bearing form_field exception needs explicit application confirmation; at this source checkpoint the default proxy and WordPress adapter confirmed nothing. A bounded all-match Thompson automaton checks the match hull, including longer same-start alternatives and overlapping/later occurrences without repeated suffix searches. Non-body matches, duplicate bindings, other content types and syntax errors cannot borrow the exception. Existing profiles without selectors retain their canonical fingerprints.

Forty-two Rust cases and twenty neutral HTTP groups pass with clippy, formatting, foundation and scorer checks. Nine added core tests cover decoding equivalence/bounds and field boundaries; one added contract test covers explicit selectors/fingerprint/lookup behavior. The new protocol group proves configuration and a forged confirmation header cannot permit forwarding. [Scope and reproduction](form-field-origins.md) record the actual API and pending WordPress confirmation, multi-field aggregation, JSON/multipart origins, partial-exception observability and deployed resource/application proof. This is not a password false-positive fix or completed workflow qualification.

## Response representation metadata

The gateway preserves validated backend Content-Length when forwarding unchanged bytes, including HEAD and 304 representation metadata. A metadata-only body adapter prevents Hyper from dropping the nonzero length on GET/304; wire checks confirm no payload is sent on HEAD, 204 or 304. Missing HEAD length stays absent, and representation length above the response-body budget is accepted without allocating or receiving that content. Invalid/duplicate backend lengths and truncated ordinary responses return 502. A denied HEAD still has no neutral-backend receipt. This fixes transport compatibility only; field exceptions and site/browser acceptance remain pending.

The added nineteenth protocol group first reproduced four metadata failures on the previous binary and now passes eight raw-wire response cases, three backend-framing failures and a correlated pre-backend HEAD denial. Thirty-two Rust semantic/contract/inspection/ban cases, all nineteen HTTP groups, clippy, formatting, foundation and scorer checks pass. Reproduce with the commands below. The expected HEAD/304 distinction follows [RFC 9110 section 8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6).

## PHP parameter-name NUL consistency

WordPress dispatch now applies PHP's decoded-name NUL truncation before leading-space/dot normalization. Encoded aliases of action, rest_route and _method therefore cannot evade explicit method policies, and colliding aliases remain duplicate/array ambiguities. One added semantic test covers query/form route selection and AJAX identity; expanded existing semantic/protocol cases cover overrides, colliding names and correlated denial before a neutral backend. The workspace passes 32 Rust cases and eighteen protocol scenarios. This fixes dispatch identity only; it introduces no field exceptions and does not establish site/browser/independent acceptance.

## Streaming body inspection

The proxy now consumes normalized body views immediately into a bounded set of matching rule IDs rather than retaining body strings. All raw/decoded values remain inspected; rule provenance, effective-method exceptions, observation/enforcement and ban confidence are resolved after complete parsing. JSON uses a recursive visitor with per-object decoded-key equality checks and serde's depth bound, without building an AST or retaining array/scalar nodes. Original allowed bytes still forward unchanged. A detection cannot bypass validation of a later malformed suffix or duplicate key. Profile JSON retains its existing strict document parser.

Three added Rust tests cover streamed/collected match equivalence, method/exception provenance, malformed JSON tails/escaped duplicates, large node arrays and encoded binary tails without retained body views. The workspace passes 31 Rust semantic/contract/inspection/ban cases and eighteen neutral-backend HTTP scenarios, including a new invalid-tail/valid-many-objects protocol case. Clippy, formatting, repository checks and scorer self-test pass. The single-request probe now defaults to this production scan path and adds repeated/unique string arrays and many-key objects. Per-object key sets, decoding buffers and multipart parsing still need actual concurrent resource evidence; no full acceptance claim follows from these tests.

## Normalization allocation checkpoint

Owned normalization now avoids duplicate raw text/form views and repeated JSON-string clones, skips unnecessary decoding buffers and releases inspection views before backend I/O. Two added complete-body tests pass alongside the existing semantic/contract/ban suite and seventeen neutral-backend HTTP scenarios. Local six-case baseline/optimized single-process RSS observations and reproduction are in [normalization resources](normalization-resources.md). They establish allocation reductions only; JSON node amplification and concurrent gateway resource acceptance remain unresolved. No inspection scope, profile limit or acceptance threshold was reduced.

## Implemented

`waf-core` parses versioned JSON profiles, rejects unknown and duplicate top-level fields, composes a selected core → application → site chain, fingerprints its canonical representation, preserves rule provenance and declares scoped site exceptions. Limits may tighten only. Core parsing, ingress, forwarding and authentication invariants cannot be excepted. WordPress is an application profile; its routes do not belong in engine code.

Nine contract integration tests cover module provenance, nested duplicate-key rejection, ordering, fingerprints, missing parents, selected-chain cycles, duplicate identities, invariant/product constraints, bounds, explicit exception scope, invalid regular expressions and silent rule overrides.

Reproduce with `cargo test --workspace --locked`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `python3 tools/check_repository.py` and `python3 observability/evaluate_waf.py --self-test`. All passed locally. Run `cargo run --locked -p waf-core --example compose -- example-site profiles/core/base.json profiles/wordpress/base.json profiles/sites/example.json` to inspect the fictional composition fingerprint.

## Proxy implementation

The Unix-socket HTTP proxy inspects complete buffered request bodies before sending any backend bytes. Inspection targets include path, query, body and headers. Normalization handles bounded percent decoding, form bodies, JSON escapes and nested values, plus multipart fields/files. Duplicate JSON keys, invalid encodings, ambiguous paths, unsupported compressed bodies, missing trusted ingress metadata and unsafe connection tokens are denied. Rule patterns and exception patterns compile at startup. Original allowed bytes, URI and methods are forwarded unchanged to a fixed Unix backend socket. Public request IDs are replaced by generated correlation IDs.

The runtime has bounded concurrency, body/backend timeouts and response size, observe/enforce modes and body-free decision events. Backend failures return 502. No alternative backend destination can be supplied by the client. Socket permissions and public Nginx header replacement require deployment verification.

Evidence: nine contract tests, five normalization tests, four ban-table tests, eight WordPress semantic tests and seventeen Python HTTP integration scenarios invoked by `cargo test --workspace --locked` pass. The independent neutral server records correlation IDs and body hashes; sentinel/body/parse denials are checked against absence of backend receipt. The protocol suite also verifies original bytes/methods/cookies, spoofed-ID replacement, unsafe hop-header rejection, partial-body timeout and backend outage. Clippy passes with warnings denied. These are synthetic transport tests, not an independently labeled effectiveness corpus or PHP non-execution proof.

## Initial common rules and local bans

The core profile now supplies seven original, limited detection patterns for SQL union/time functions, active script elements/schemes, executable PHP tags, traversal and sensitive file references. They remain unqualified and all have `high_confidence: false`; no common pattern can start a ban before a trustworthy detection is established. A 30-case fictional development corpus produces 18 TP, 12 TN, zero FP/FN and correlated neutral-backend absence for all 18 denials. These labels were authored by the implementation agent; this is not the independent acceptance corpus and establishes no WordPress effectiveness rate.

The local HTTP ban table requires repeated high-confidence, unexcepted enforce-mode detections. Defaults: three requests in 60 seconds, 300-second bans and 4,096 entries. Configuration is bounded, bans do not extend on denied traffic, trusted/infrastructure identities are excluded, IPv4-mapped addresses are canonicalized and capacity exhaustion cannot become a global denial. The proxy checks bans after trusted identity parsing and before body buffering/inspection. Observe matches, generic uncertain detections, method errors and exceptions do not start bans. Synthetic high-confidence tests exercise expiry and trust boundaries. No upstream API exists in this implementation.

Original HTTP/1 headers are checked before Hyper can discard framing ambiguities. CL+TE and duplicate singleton fields are denied, incomplete headers time out, and each Unix connection serves one request to make this validation complete. Connection tasks are bounded; excess connections close without forwarding. Socket permissions still need deployment proof. The new raw framing tests caught and fixed a gap in the earlier post-parser checks.

## WordPress dispatch specialization

`waf-wordpress` is enabled through a versioned application module. Site settings are separate, strict modules with provenance and no silent overrides. Dispatch resolution covers REST prefix/index.php/query/POST form/multipart alternatives, PHP-normalized parameter names, query precedence for method overrides, duplicate/array dispatch rejection and conflicting POST/query route rejection. REST HEAD/OPTIONS are preserved. Common-rule exceptions use the effective method; a wire POST translated to DELETE cannot borrow a POST exception.

Administration requires trusted metadata; login and AJAX/admin-post remain available for backend authorization. Anchored evidence-bearing site policies can restrict resolved REST routes, canonical paths or AJAX actions. Unknown routes stay unqualified. Method policies intersect when overlapping and their denials retain the site profile identity. Decision events expose family/effective method/source without logging route values, actions or payloads. Parsing, administration and explicit method policies apply in both modes; observe/enforce controls regex detections.

Eight semantic tests plus two added protocol scenarios cover these behaviors, with correlated backend absence for denials and unchanged forwarding for legitimate fixture methods. This is dispatch/transport evidence, not complete WordPress user-workflow or role/nonce qualification. See the specialization README for configuration and limitations.

## Not implemented or proven

Independent common-rule effectiveness, full WordPress workflow/role/nonce/plugin qualification, reliable deployment-specific ban qualification and independent deployment acceptance remain pending. Composition tests and the synthetic scorer are not effectiveness evidence. No independent application detection rate, false-positive rate or proxy overhead has been measured. Core and WordPress profiles are marked implemented-unqualified; the fictional site example remains design-only. The proxy uses a new backend connection per request and bounded response buffering; streaming/pooling behavior and performance acceptance remain to be assessed. XML and content decompression are not semantic parsers in this implementation. Browser workflows, field-scoped exceptions, application role/nonce integration and Nginx/Rust/PHP path interpretation need additional verification. The origin-only collector reports the pre-engine state; the integrated collector accepts actual decisions plus deployment-verified runtime activity.

## Reusable Nginx and statistics integration

Fictional proxy, internal FastCGI bridge, correlation, service and PHP receipt examples are available under integrations/. No public dynamic location should call PHP directly or fall back around an unavailable gateway. Public static assets require an explicit file scope. An explicit rollback is distinct from forbidden automatic fail-open behavior. Socket-directory permissions, ingress replacement, internal rewrites, PHP receipts and outages require actual installation proof maintained by deployers.

The integrated statistics collector reports decisions, rule/profile provenance, fingerprints, scoped exceptions, bounded local bans and total gateway duration. Configured profile versions remain distinct from event fingerprints. Effectiveness and added-overhead metrics remain unavailable until independent labels and paired baseline/protected results exist. Its synthetic aggregation check passes. Bodyless requests with a JSON content type are preserved; nonempty malformed/duplicate JSON remains denied. Existing normalization and proxy tests pass after this compatibility correction.

## Optional early ban lookup

The gateway can bind a second private Unix socket through ban_lookup_socket. It provides read-only GET / identity checks against the same in-memory expiring table and never forwards to the backend. A separate bounded connection budget and 8 KiB/16-header/two-second header limits keep the lookup independent of buffered dynamic tasks. Wrong routes/methods, missing/ambiguous identity and bodies are rejected. Socket startup conflicts fail rather than unlinking an existing listener; termination of the lookup listener terminates the gateway for supervisor recovery.

Fictional Nginx auth_request examples perform this check before dynamic body buffering, with no original body, credentials, cookies or client-selected identity. An active ban returns 403; lookup errors deny dynamic requests with 502. Approved lookups produce no visitor event, and correlated early denials cannot reach the backend. Early and ordinary ban denials appear in read-only statistics. No control endpoint, Nginx reload churn or upstream API is introduced.

Seventeen protocol scenarios, the existing Rust semantic/contract/inspection/ban suite, clippy and statistics aggregation checks pass. These are synthetic high-confidence fixtures, not qualified common attack patterns. Exact installed Nginx behavior, per-site reliable detections, independently labeled effectiveness and matched resource/latency acceptance remain deployer work. Starter common patterns still cannot start bans.
