# Actual status — 2026-10-01

## Scoped selected-input constraints

The generic WordPress adapter now accepts optional evidence-bearing scalar input constraints with exact path/action/wire-method scope, explicit GP bindings, ordered falsey header/target fallbacks and raw/before-query projections. Strict multipart layout must agree with the independent MIME parser. Selected values never enter context/decision serialization; pre-backend denials retain site policy/profile provenance and do not automatically start bans. No site/plugin constraint is enabled by default.

All 78 Rust semantic cases and 28 neutral HTTP groups pass with clippy, formatting, foundation, scorer and statistics checks. The new protocol group preserves allowed bytes, correlates denied requests with zero neutral-backend execution, and preserves sibling/core inspection. This is a reusable mechanism, not plugin or deployment acceptance; actual sink/helper behavior, artifact resources, workflows, Browser and full independent/performance gates remain pending. See [the input contract](../crates/waf-wordpress/README.md).

## Conservative multipart text origins and explicit AJAX media

The shared engine can attribute canonical multipart UTF-8 text leaves through a bounded borrowed physical layout and an independent Multer agreement pass. Raw whole-body and existing per-part inspection remain complete. Files, filenames, names, headers, cross-part matches and ambiguous bindings cannot borrow text exceptions. Unsupported framing, headers or content-type parameters withhold provenance; malformed syntax still denies forwarding.

WordPress AJAX consumers may explicitly opt into multipart/form-data while existing declarations default to URL-encoded only. Literal MIME names/identity values, file separation, canonical tree checks and parser limits preserve consumer scope. Application authentication, tokens, timing, roles and ownership remain in WordPress. No actual site consumer is enabled by this public change. Candidate-specific concurrent resources, deployment, PHP parser/workflow qualification, Browser and independent/performance acceptance remain pending.

All 73 Rust semantic cases and 27 neutral HTTP groups pass with clippy, formatting, foundation, scorer and both statistics checks. New tests exercise MIME layout/parser agreement, boundary ambiguity, nested collisions, binary offset mapping, explicit media, original-byte forwarding and pre-backend negatives. The early-ban status fixture now avoids racing an unnecessary body write against deliberate connection closure; gateway behavior is unchanged.

## Explicit AJAX nested form consumer contract

The WordPress site module accepts optional evidence-bearing form_consumers with the canonical AJAX endpoint, POST action, stable scalar identity guards and explicit FPM parsing assumptions. Canonical nested leaves require unique original bindings; PHP aliases, append/malformed/ignored-suffix keys, ancestor/descendant collisions and count/depth excess withhold confirmation. No consumer is enabled by default. WordPress still performs nonce/token, timing, role and ownership checks; this API does not authorize a complete submission. Unsupported array shapes require further parser support and qualification before enabling those flows.

All 61 Rust semantic cases and 25 neutral HTTP groups pass, including five new application tests and two correlated protocol groups. Allowed bytes remain exact, unmatched sibling/query/dispatch/media/method/identity cases do not reach the neutral backend, and sibling-hit diagnostics remain body-free. Clippy with warnings denied, formatting, foundation, scorer and aggregation checks pass. Actual installation consumers, positive/negative plugin processing, artifact resources/deployment and Browser/independent/performance acceptance remain unqualified. See [the consumer contract](../crates/waf-wordpress/README.md).

## Canonical nested form origins

The core accepts bounded canonical bracket selectors for original URL-encoded leaf values. Duplicate/ancestor/descendant writes and related malformed paths withhold exceptions; disjoint sibling arrays remain separate. Numeric keys are not coerced. Configured paths affect deterministic fingerprints and never create route-wide exceptions. Application confirmation remains mandatory; the WordPress adapter confirms explicit login pwd bindings and opt-in AJAX consumer leaves. This source change does not qualify another plugin or implement PHP nested-key normalization.

All 56 Rust semantic cases and 23 neutral HTTP groups pass. New tests cover canonical/encoded nested keys, decoding, siblings, leading-zero keys, duplicate/valueless/ancestor/descendant/append/suffix collisions, metadata bounds and fingerprint/configuration rejection. A neutral protocol group verifies that nested configuration and a forged confirmation header cannot bypass a pre-backend denial. Clippy, formatting, foundation, aggregation and scorer checks pass. Artifact-specific resources, deployment, actual application consumers and browser workflows remain separate requirements. See [the field contract](form-field-origins.md).

## Unapplied field candidate observability

Optional unapplied_field_profiles record configured profile identities when at least one scoped, adapter-confirmed field occurrence exists but the rule remains unexcepted. A bounded field-range search preserves full haystack anchor/boundary context and detects local occurrences even after an earlier unscoped hit or in a later decoded view. Names, values and match positions are not serialized. Forwarding, effective scopes, confidence and ban eligibility still depend on the existing exception_profile decision.

Three core tests, expanded protocol boundaries and a new reliable-ban/observe protocol group verify these semantics. The collector separates applied exceptions from unapplied candidates and deduplicates per rule/profile. All 52 Rust cases and 22 neutral HTTP groups pass, with clippy, formatting, aggregation, foundation and scorer checks. Artifact-specific resources and actual deployed compatibility/collection remain pending; do not infer deployment or independent effectiveness from this checkpoint.

## Multiple form fields

The core now checks all accepting pattern spans using earliest-start tags on bounded Thompson states. It aggregates touched scalar fields across raw/decoded body views and requires a separate eligible exception plus adapter confirmation for every field. Cross-field, sibling, query/header/path and ambiguous bindings remain unexcepted. Zero-length rules and internal ordering/disagreement failures deny forwarding. Match/exception provenance and forwarded bytes remain unchanged.

One exhaustive differential scanner test and two multi-field integration tests cover all-match alternatives, overlap, anchors/Unicode boundaries, decoding, duplicate aliases and independent confirmation/method scopes. Forty-nine Rust cases and twenty-one neutral HTTP groups pass with clippy, formatting, foundation and scorer checks. Current default/WordPress consumers do not automatically confirm additional fields. Actual plugin consumers, JSON/multipart origins, partial-exception statistics, deployed candidate resources and full acceptance remain pending. See [field coverage scope and proof](form-field-origins.md).

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
