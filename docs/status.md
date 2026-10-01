# Actual status — 2026-10-01

## Implemented

`waf-core` parses versioned JSON profiles, rejects unknown and duplicate top-level fields, composes a selected core → application → site chain, fingerprints its canonical representation, preserves rule provenance and declares scoped site exceptions. Limits may tighten only. Core parsing, ingress, forwarding and authentication invariants cannot be excepted. WordPress is an application profile; its routes do not belong in engine code.

Eight integration tests cover ordering, fingerprints, missing parents, selected-chain cycles, duplicate identities, invariant/product constraints, bounds, explicit exception scope, invalid regular expressions and silent rule overrides.

Reproduce with `cargo test --workspace --locked`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `python3 tools/check_repository.py` and `python3 observability/evaluate_waf.py --self-test`. All passed locally. Run `cargo run --locked -p waf-core --example compose -- example-site profiles/core/base.json profiles/wordpress/base.json profiles/sites/example.json` to inspect the fictional composition fingerprint.

## Proxy implementation

The Unix-socket HTTP proxy inspects complete buffered request bodies before sending any backend bytes. Inspection targets include path, query, body and headers. Normalization handles bounded percent decoding, form bodies, JSON escapes and nested values, plus multipart fields/files. Duplicate JSON keys, invalid encodings, ambiguous paths, unsupported compressed bodies, missing trusted ingress metadata and unsafe connection tokens are denied. Rule patterns and exception patterns compile at startup. Original allowed bytes, URI and methods are forwarded unchanged to a fixed Unix backend socket. Public request IDs are replaced by generated correlation IDs.

The runtime has bounded concurrency, body/backend timeouts and response size, observe/enforce modes and body-free decision events. Backend failures return 502. No alternative backend destination can be supplied by the client. Socket permissions and public Nginx header replacement require deployment verification.

Evidence: eight contract tests, five normalization tests, four ban-table tests and thirteen Python HTTP integration scenarios invoked by `cargo test --workspace --locked` pass. The independent neutral server records correlation IDs and body hashes; sentinel/body/parse denials are checked against absence of backend receipt. The protocol suite also verifies original bytes/methods/cookies, spoofed-ID replacement, unsafe hop-header rejection, partial-body timeout and backend outage. Clippy passes with warnings denied. These are synthetic transport tests, not an independently labeled effectiveness corpus or PHP non-execution proof.

## Initial common rules and local bans

The core profile now supplies seven original, limited detection patterns for SQL union/time functions, active script elements/schemes, executable PHP tags, traversal and sensitive file references. They remain unqualified and all have `high_confidence: false`; no common pattern can start a ban before a trustworthy detection is established. A 30-case fictional development corpus produces 18 TP, 12 TN, zero FP/FN and correlated neutral-backend absence for all 18 denials. These labels were authored by the implementation agent; this is not the independent acceptance corpus and establishes no WordPress effectiveness rate.

The local HTTP ban table requires repeated high-confidence, unexcepted enforce-mode detections. Defaults: three requests in 60 seconds, 300-second bans and 4,096 entries. Configuration is bounded, bans do not extend on denied traffic, trusted/infrastructure identities are excluded, IPv4-mapped addresses are canonicalized and capacity exhaustion cannot become a global denial. The proxy checks bans after trusted identity parsing and before body buffering/inspection. Observe matches, generic uncertain detections, method errors and exceptions do not start bans. Synthetic high-confidence tests exercise expiry and trust boundaries. No upstream API exists in this implementation.

Original HTTP/1 headers are checked before Hyper can discard framing ambiguities. CL+TE and duplicate singleton fields are denied, incomplete headers time out, and each Unix connection serves one request to make this validation complete. Connection tasks are bounded; excess connections close without forwarding. Socket permissions still need deployment proof. The new raw framing tests caught and fixed a gap in the earlier post-parser checks.

## Not implemented or proven

Independent common-rule effectiveness, WordPress specialization, Nginx early-ban integration and laboratory deployment remain pending. Composition tests and the synthetic scorer are not effectiveness evidence. No detection rate, false-positive rate or proxy overhead has been measured. The core profile is marked implemented-unqualified; application and site examples remain design-only. The proxy uses a new backend connection per request and bounded response buffering; streaming/pooling behavior and performance acceptance remain to be assessed. XML and content decompression are not semantic parsers in this implementation. Browser workflows, effective REST-method overrides, field-scoped exceptions and Nginx/Rust path interpretation need additional verification. Origin metrics still report the pre-engine state.
