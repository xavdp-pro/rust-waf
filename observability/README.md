# Measurements and effectiveness

origin_metrics.py aggregates the current origin log into JSON and a read-only HTML statistics page: volume, routes, HTTP status, network/method denials, and origin p50/p95 latency. Override paths with --log and --output. Refresh scheduling belongs to the deployment, not this script. Synthetic verification traffic is included; the count is not a count of unique human visitors. The in-memory implementation must be reviewed before high-volume use.

The tool currently reports that Rust is not deployed. Integration must connect real engine decisions before changing that state. It does not infer attack detection from HTTP errors.

Expected origin fields: ts, id, method, path without query strings, status, seconds, upstream_seconds, admin_denied, method_denied, bytes. No body, cookie, Authorization, or client IP is recorded by this source.

Planned Rust events: correlated request_id, test case_id, profile/version, mode, decision, rule_id, rule_layer, analysis_duration_ms, optional bypass_reason. Backend evidence separately records whether the backend received a request. Verified client identity for banning is private metadata outside the statistics page.

evaluate_waf.py accepts a list of cases with label=malicious/legitimate and decision=block/allow. backend_reached=false proves non-execution; bypass=true excludes and separately counts an exception. It calculates TP/FP/TN/FN, detection, false positives, precision, and proof coverage. Metrics without denominators are null.

```bash
python3 observability/evaluate_waf.py --self-test
python3 observability/evaluate_waf.py results.private.json
```

The self-test is synthetic. results.private.json names a future actual result and is not shipped or committed. Compare baseline/protected cases under matching versions, load, and cache conditions. Origin latency is not automatically Rust overhead. Requests stopped upstream do not appear in the origin log.
