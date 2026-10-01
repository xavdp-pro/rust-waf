# Actual status — 2026-10-01

## Implemented

`waf-core` parses versioned JSON profiles, rejects unknown and duplicate top-level fields, composes a selected core → application → site chain, fingerprints its canonical representation, preserves rule provenance and declares scoped site exceptions. Limits may tighten only. Core parsing, ingress, forwarding and authentication invariants cannot be excepted. WordPress is an application profile; its routes do not belong in engine code.

Eight integration tests cover ordering, fingerprints, missing parents, selected-chain cycles, duplicate identities, invariant/product constraints, bounds, explicit exception scope, invalid regular expressions and silent rule overrides.

Reproduce with `cargo test --workspace --locked`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `python3 tools/check_repository.py` and `python3 observability/evaluate_waf.py --self-test`. All passed locally. Run `cargo run --locked -p waf-core --example compose -- example-site profiles/core/base.json profiles/wordpress/base.json profiles/sites/example.json` to inspect the fictional composition fingerprint.

## Proxy implementation

The Unix-socket HTTP proxy inspects complete buffered request bodies before sending any backend bytes. Inspection targets include path, query, body and headers. Normalization handles bounded percent decoding, form bodies, JSON escapes and nested values, plus multipart fields/files. Duplicate JSON keys, invalid encodings, ambiguous paths, unsupported compressed bodies, missing trusted ingress metadata and unsafe connection tokens are denied. Rule patterns and exception patterns compile at startup. Original allowed bytes, URI and methods are forwarded unchanged to a fixed Unix backend socket. Public request IDs are replaced by generated correlation IDs.

The runtime has bounded concurrency, body/backend timeouts and response size, observe/enforce modes and body-free decision events. Backend failures return 502. No alternative backend destination can be supplied by the client. Socket permissions and public Nginx header replacement require deployment verification.

Evidence: eight contract tests, five normalization tests and six Python HTTP integration scenarios invoked by `cargo test --workspace --locked` pass. The independent neutral server records correlation IDs and body hashes; sentinel/body/parse denials are checked against absence of backend receipt. The protocol suite also verifies original bytes/methods/cookies, spoofed-ID replacement, unsafe hop-header rejection, partial-body timeout and backend outage. Clippy passes with warnings denied. These are synthetic transport tests, not an independently labeled effectiveness corpus or PHP non-execution proof.

## Not implemented or proven

Common protection rules, WordPress specialization, temporary bans and laboratory deployment remain pending. Composition tests and the synthetic scorer are not effectiveness evidence. No detection rate, false-positive rate or proxy overhead has been measured. Public profile examples retain their design-only metadata because they contain no protection rules. The proxy uses a new backend connection per request and bounded response buffering; streaming/pooling behavior and performance acceptance remain to be assessed. XML and content decompression are not semantic parsers in this implementation. Browser workflows, effective REST-method overrides, field-scoped exceptions and Nginx/Rust path interpretation need additional verification. Origin metrics still report the pre-engine state.
