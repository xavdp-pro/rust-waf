# Unix HTTP gateway

Build with `cargo build -p waf-proxy --locked`. Run `waf-proxy /absolute/path/config.json`. The configuration is strict JSON containing:

```json
{
  "listen_socket": "/run/waf/frontend.sock",
  "backend_socket": "/run/waf/backend.sock",
  "site_id": "example-site",
  "profiles": ["/etc/waf/core.json", "/etc/waf/application.json", "/etc/waf/site.json"],
  "mode": "enforce",
  "max_concurrent": 4,
  "request_timeout_seconds": 10,
  "backend_timeout_seconds": 30,
  "response_bytes": 33554432
}
```

These paths are illustrative. Create a protected runtime directory and separate service identity/group. The PHP user must have no access to either socket. The frontend socket uses mode 0660; a pre-existing socket is never unlinked automatically. A service manager should own stale-socket cleanup in its private runtime directory. No TCP listener, management endpoint or automatic upstream API exists.

Nginx must replace `X-Waf-Client-IP` and `X-Waf-Admin-Friend` using verified ingress identity and local trust configuration. Missing/duplicate/invalid values are rejected; client-supplied forwarding headers and request IDs are stripped. These headers are trusted only because Unix socket permissions exclude public callers and application workers. The internal backend converts them into server-side FastCGI values. Do not grant the application user the gateway group.

All allowed request bytes are forwarded only after bounded inspection. Compressed request bodies and upgrade/expect semantics are currently unsupported and denied. Invalid parsing is denied in both modes; observe mode forwards detection matches and records them. The response is buffered within a configured bound. Each backend connection is single-request. These limits require workflow and performance qualification before deployment.

Decision records are written as JSON lines to stdout; route query strings, bodies, cookies, credentials and matched payloads are absent. Capture stdout privately through the service manager. Run `cargo test -p waf-proxy --locked` for real Unix HTTP tests with a recording neutral backend.
