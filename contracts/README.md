# Profile contract, schema version 1

`waf-core::profile::Profile::parse` accepts at most one MiB per profile and rejects unsupported schema versions, unknown fields and duplicate typed fields. `compose` accepts at most 256 registered profiles and selects exactly core → application → site. The legacy `wordpress` layer spelling aliases `application`; the engine has no WordPress route dependency. Every selected parent must exist and the selected chain must be acyclic. Unselected profiles are parsed but their ancestry is not traversed.

The core explicitly declares the five invariants, read-only statistics policy and prohibition on upstream per-request/per-detection API calls. Descendants cannot expand inherited bounds. Rules have unique IDs, nonempty inspection targets and bounded compiled regular expressions. Rule overrides are rejected. Configuration identity and version strings are bounded ASCII identifiers; versions are publisher-defined revision labels.

Site exceptions reference an existing detection rule and require anchored paths, explicit methods, a reason and an evidence reference. Invariants are not detection rules and cannot be excepted. An exception is not authorization. Its profile provenance is retained. These declarations become enforcement only when used by the request engine.

The SHA-256 fingerprint covers the selected ordered profiles after typed parsing, including metadata, versions, rules and exceptions. JSON object key order and registry order do not change it; array order is meaningful. Equivalent aliases and omitted defaults normalize to the same typed representation. No secrets belong in profile metadata.

Use the `compose` example described in the project status to check external site profiles offline. Proxy decision records use schema version 1: timestamp, generated request ID, policy fingerprint, decision (`allow`, `observe`, `block`, `error`), fixed reason code, rule/provenance/exception references, response status, elapsed microseconds `backend_attempted` and `ban_started`. This last field records an attempted forwarding operation, not proof of PHP execution. Correlate independent backend receipts or PHP instrumentation. No payloads or access secrets are included. See observability/README.md for effectiveness measurements.

Rule-match exceptions require every observed path representation to satisfy their anchored scope; decoding must not silently broaden an exception. The local ban contract is described in the gateway README.

Application/site profiles may declare bounded named modules with object settings. Composition retains opaque settings and provenance; the gateway validates supported implementations strictly before binding a socket. Duplicate module names and any duplicate JSON object key, including inside settings/metadata, are rejected. Core profiles cannot contain application modules. The WordPress application and site modules remain separate; the shared engine contains no WordPress routes.

Decision records may include an `application` classification with family, effective method and method source. Raw resolved routes and AJAX action values are intentionally omitted. A method-policy denial includes its ID and actual declaring site profile. Explicit application access/method policies are enforced in both modes; observe mode applies only to regex detection decisions.
