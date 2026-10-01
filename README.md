# Rust WAF

An open-source Rust WAF foundation with a shared engine, a generic WordPress profile, and independently maintained site specializations. Licensed under MIT.

**Current status: Rust composition, bounded inspection and a Unix-socket HTTP proxy pass neutral-backend tests. Site protection and laboratory deployment are not yet qualified.**

## Start here

- [Architecture](docs/architecture.md)
- [Actual status](docs/status.md)
- [Implementation roadmap](docs/roadmap.md)
- [Human contribution workflow](CONTRIBUTING.md)
- [Agent instructions](AGENTS.md)

## Repository layout

```text
crates/waf-core/         profile composition and bounded application-independent inspection
crates/waf-proxy/        Unix-socket HTTP gateway and correlated decision records
profiles/core/          shared design contract
profiles/wordpress/     generic WordPress design profile
profiles/sites/         fictional example only
contracts/              composition and event contracts
observability/          origin measurements and labeled-decision scoring
integrations/nginx/     Nginx integration contract
integrations/ingress/   trusted tunnel and direct-ingress adapters
fixtures/              synthetic-case requirements
```

The public repository owns the shared engine and generic WordPress specialization. Real site profiles, installation information, access policies, inventories, and operational evidence belong in separately maintained private repositories or local deployments. This repository has a fresh public history and includes no site-specific operational history.

The only human-facing WAF interface is a **read-only statistics page**. No control panel, rule editor, on/off toggle, or ban/unban buttons. Configuration uses versioned files and existing technical deployment tools.

Work from `main` on short-lived feature branches. Layers are directories, not permanent branches. Keep shared contract and generic WordPress changes in this repository; deployer-specific changes remain outside it.

## Local checks

No external Python dependencies or API calls are required:

```bash
python3 tools/check_repository.py
python3 observability/evaluate_waf.py --self-test
```

These Python commands check the foundation and a synthetic scoring fixture. Run `cargo test --workspace --locked` and `cargo clippy --workspace --all-targets --locked -- -D warnings` to verify Rust composition. The examples parse and compose but have no protection rules. No hosted CI or scheduled automation is enabled.
