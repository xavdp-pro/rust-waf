# Shared engine

Implemented: strict profile parsing, deterministic composition, limits, immutable invariants, rule provenance and explicit site exceptions. Run `cargo test -p waf-core --locked`.

Request normalization, rule execution and measurements are the next implementation step. No application routes or installation assumptions belong in this crate.
