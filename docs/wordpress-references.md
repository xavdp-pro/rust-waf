# WordPress WAF references

Reviewed primary upstream sources on 2026-10-01. These are design and test references, not installed dependencies or evidence that this engine matches CRS coverage.

## Generic detection and application tuning

[OWASP CRS documentation](https://coreruleset.org/docs/index.print) describes generic detection on compatible engines, staged tuning and anomaly scoring. Its [WordPress exclusions plugin](https://github.com/coreruleset/wordpress-rule-exclusions-plugin) covers standard WordPress. Third-party plugins and page-builder plugins require separate custom tuning. This supports the separation between common engine, generic application behavior and site/plugin specialization.

The plugin uses ModSecurity SecRules. Rust regex rules do not implement that language, phase model, transformations or operators. Do not describe an unvalidated translation as CRS-compatible. Upstream CRS and its official plugins use Apache-2.0; any future copied or adapted material must preserve applicable licensing and attribution. No upstream rule source was copied for this implementation.

## Required compatibility tests

- [REST method overrides](https://developer.wordpress.org/rest-api/using-the-rest-api/global-parameters/) allow `_method` and `X-HTTP-Method-Override`. Inspect the effective method, including the query parameter precedence shown in [the server implementation](https://developer.wordpress.org/reference/classes/wp_rest_server/serve_request/). A wire POST can mean DELETE in WordPress.
- [REST authentication](https://developer.wordpress.org/rest-api/using-the-rest-api/authentication/) distinguishes cookie/nonces and application-password authentication. A WAF access decision does not replace application authorization.
- [ModSecurity's Nginx connector](https://github.com/owasp-modsecurity/ModSecurity-nginx) demonstrates an existing Nginx integration option for an upstream reference installation, not a dependency required by this Rust gateway.
- The [2021 CRS request-body bypass advisory](https://coreruleset.org/20210630/cve-2021-35368-crs-request-body-bypass/) illustrates the risk when exclusions and backend path interpretation disagree. Keep body inspection enabled; bound exceptions and test path-info/encoded-path alternatives.
- The [2024 CRS body-parser advisory](https://coreruleset.org/20241029/crs-versions-4-8-0-and-3-3-7-released/) illustrates mismatched multipart and JSON content types. Parse media types structurally and exercise all JSON suffixes and unsupported formats explicitly.

## Consequences for this roadmap

The present synthetic sentinel tests establish transport and parsing behavior only. Production-like WordPress tuning needs real browser workflows, captured sanitized request shapes and independent labels. Route-wide exceptions are an initial contract; field-scoped exclusions and effective-method handling require implementation before the WordPress specialization is complete. Generic exceptions must never turn off parsing, body bounds, ingress trust or backend isolation.
