# Architecture

## Three layers

The shared Rust engine handles HTTP normalization, limits, inspection, common rules, profile composition, decisions, correlation, and measurements. It is independent of an application, site, or private network.

The generic WordPress profile describes REST, AJAX, member login, uploads, methods, and integration with application permissions/nonces. Known plugin modules may be optional; site-specific routes or installed-plugin assumptions do not belong in this generic layer.

A separately maintained site profile declares qualified workflows, endpoints, installed plugins, justified methods, schemas, virtual patches, friend IPs, and ingress mode. Public examples are fictional and do not configure any real deployment.

## Agent-built site specialization

The site profile is authored by an analysis agent for the actual installation. The generic WordPress profile is a starting hypothesis, not a guarantee of behavior. Installed/active plugins, themes and child themes, must-use plugins, drop-ins, rewrite rules, hooks, custom code and modified core can alter request handling, authentication, methods and schemas.

The agent inventories this installation, checks core-file integrity against the exact upstream version when feasible, reads relevant dispatch/authorization code, observes real browser requests and cross-checks server declarations. It records what was observed, inferred or left unqualified. File-integrity checks establish differences; they do not by themselves prove maliciousness or security. Plugin names and source declarations alone cannot qualify a workflow.

The agent then creates a versioned site policy and scoped exceptions with reproducible positive/negative tests. Any plugin/theme/core/configuration change invalidates the affected qualification until reviewed and retested. Unknown changes are surfaced rather than silently adopting generic WordPress assumptions. Site-specific analysis artifacts remain private. The engine remains application-independent; it must not learn site routes by hard-coded changes.

Effective composition must be deterministic and versioned. Exceptions are explicit, tested, and traceable; no implicit weakening of engine invariants. Route filtering does not by itself establish application authorization or object ownership.

The analysis agent generates deployable policy from this evidence; it does not make live per-request decisions. Each generated rule identifies its layer, installation assumptions and qualification tests. Hooks may change core behavior without modifying core files, so an unchanged core checksum cannot replace runtime workflow checks. Site-specific behavior stays in the private profile; a reusable WordPress capability belongs in the generic profile only after qualification independent of that site. Human interaction remains limited to read-only statistics.

## Target request chain

```text
trusted CDN/tunnel ingress or direct ingress
  → public Nginx
      → explicitly public static resources
      → Rust HTTP WAF
          → isolated internal Nginx FastCGI block
              → PHP-FPM → WordPress
```

Both Nginx blocks may share an instance. The backend is inaccessible externally and dynamic forwarding cannot bypass the WAF. Engine failure denies forwarding. Nginx handles static files, connections, appropriate authentication, limits, compression, and HTTP-to-FastCGI conversion; Rust inspects complete dynamic requests including bodies. auth_request alone is not full-body inspection.

## Interface and operation

Only useful read-only statistics are human-facing. No WAF control panel, rule editor, on/off switch, or ban/unban controls. Configuration is versioned and deployed through existing technical tools.

Show traffic/method families, rule/layer decisions, errors, latency/overhead, profile versions, exceptions, temporary bans, and independently measured detection/false positives. Unavailable metrics remain absent. Do not expose sensitive request bodies, credentials, cookies, or tokens.

Keep upstream protection unchanged and avoid per-request/per-detection Cloudflare API calls. Behind a tunnel, visitor identity is verified HTTP metadata; host packet filtering cannot filter that identity inside tunnel packets. Plan bounded local temporary lists and early Nginx rejection after reliable detection. This reduces full inspection/backend work but not tunnel transit. A direct-ingress adapter may use expiring packet-filter sets for actual network sources.

Friend IPs and infrastructure are excluded from automatic bans; a single 405 or ambiguous event is not sufficient to ban a shared address. Application authentication and authorization still apply.
