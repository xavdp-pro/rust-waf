# Shared engine

Implemented: strict profile parsing, deterministic composition, limits, immutable invariants, rule provenance and explicit site exceptions. Run `cargo test -p waf-core --locked`.

Bounded request normalization and compiled regex execution are implemented with synthetic tests. Common protection rules and measured effectiveness are pending. No application routes or installation assumptions belong in this crate.
