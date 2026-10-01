# Agent instructions

Read README.md, docs/status.md, docs/architecture.md, and docs/roadmap.md before changes. Keep documentation, comments, contracts, statistics labels, and issues in English.

## Architecture and scope

- Three layers: shared Rust engine, generic WordPress profile, externally maintained site profile.
- This public repository owns the first two layers and fictional examples only. Never import real site profiles, operational inventories, private installation information, or deployment history.
- No WAF control UI. Only useful read-only statistics.
- Do not hard-code site routes or deployment/network dependencies into the engine.
- Site exceptions must be explicit, versioned, tested, and observable. They must not silently disable core invariants.
- Preserve legitimate member login, AJAX/REST, and justified methods. Unobserved routes are unqualified, not automatically forbidden. DELETE can legitimately remove a cart item.
- Reuse Nginx static/transport features and its internal FastCGI bridge to PHP-FPM. No public backend bypass; fail closed for dynamic forwarding when the WAF is unavailable.
- Behind a tunnel, host packet filtering cannot ban the visitor IP carried in an HTTP header. Plan local early HTTP rejection. Packet filtering applies only to directly observed source addresses.
- Preserve existing upstream CDN protection. No per-request/per-detection Cloudflare API calls or automatic rule churn.
- Friend-IP exceptions do not remove application authentication or authorization.

## Evidence and publication

Rust profile composition exists; transport and request inspection are not yet implemented. Do not claim protection or complete qualification from configuration, status codes, source declarations, or synthetic fixtures alone. Separate observation, independently labeled decisions, backend proof, and actual user workflows. Missing metrics remain absent.

This repository is public. Never commit credentials, keys, tokens, database dumps, customer data, cookies, sessions, real access inventories, raw logs, or site-specific exceptions. Use fictional fixtures. A reusable tool must not contain private deployment names or paths. Public publication does not authorize any deployment.

## Workflow

Use short-lived branches per reviewable change. Run the foundation checker and scorer self-test, then add meaningful Rust checks when implementation begins. Do not create fake crates or no-op CI to suggest an engine exists. Do not create or message other tasks without direct authorization. Maintain docs/status.md with reproducible evidence and limitations.
