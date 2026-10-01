# Architecture

## Three layers

The shared Rust engine handles HTTP normalization, limits, inspection, common rules, profile composition, decisions, correlation, and measurements. It is independent of an application, site, or private network.

The generic WordPress profile describes REST, AJAX, member login, uploads, methods, and integration with application permissions/nonces. Known plugin modules may be optional; site-specific routes or installed-plugin assumptions do not belong in this generic layer.

A separately maintained site profile declares qualified workflows, endpoints, installed plugins, justified methods, schemas, virtual patches, friend IPs, and ingress mode. Public examples are fictional and do not configure any real deployment.

Effective composition must be deterministic and versioned. Exceptions are explicit, tested, and traceable; no implicit weakening of engine invariants. Route filtering does not by itself establish application authorization or object ownership.

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
