# Normalization allocation checkpoint

The normalizer moves already-owned strings into inspection views instead of cloning raw bodies or JSON strings repeatedly. Text/form bodies no longer retain an identical raw view twice. Percent decoding skips allocation when there is no percent escape or first-pass form plus sign, and valid decoded UTF-8 reuses its byte allocation. JSON values are consumed while creating views. The proxy drops views immediately after matching, before backend connection or response buffering.

The complete raw body, JSON keys/string values, multipart metadata and full file contents are still inspected. Distinct decoded views remain. Malformed encodings, duplicate JSON keys, ambiguous paths and parsing limits keep their existing behavior. Request bytes, profile limits and rule/exception semantics are unchanged.

## Reproduction

Build the synthetic, single-request probe and measure peak process RSS externally on Linux:

```bash
cargo build --release --locked -p waf-core --example normalization_probe
/usr/bin/time -f '%M KiB peak RSS' target/release/examples/normalization_probe opaque-binary
```

Run the same command with `opaque-text`, `form`, `json-string`, `json-nodes` and `multipart-binary`. The optional second argument is a body size in bytes, from 128 through the composed limit; default 8 MiB. The probe prints only synthetic case, body size, view count and retained view bytes. No HTTP backend is contacted. Use the same compiler, build mode, host and inputs for a comparison; invoke each case in a fresh process. The probe is not a load generator or an effectiveness benchmark.

## Local observation

One fresh process per case, release build, Rust 1.98, 8 MiB bodies (8 MiB minus one byte for the empty-array JSON construction). Baseline is the main implementation at de20f6ba0ccf5fdac474e5694052873540ff6456, using the identical probe. All twelve invocations completed successfully.

| Synthetic body | Baseline peak RSS, KiB | Optimized peak RSS, KiB |
| --- | ---: | ---: |
| Opaque text | 54,180 | 21,280 |
| Opaque invalid UTF-8 bytes | 135,848 | 37,700 |
| Form without escapes | 45,956 | 21,304 |
| Single JSON string | 70,568 | 29,652 |
| JSON containing many empty arrays | 117,116 | 108,628 |
| Multipart invalid UTF-8 file | 176,524 | 78,428 |

These are development measurements, not independent acceptance evidence. A byte limit does not establish a small JSON allocation limit: the JSON parser still builds an AST with per-node overhead. Concurrent normalization, multipart parser allocations, decoding expansion and backend buffers require further measurement and bounding. These results do not prove a gateway-wide 512 MiB ceiling, latency/throughput acceptance, or deployment behavior. No body limit or acceptance threshold was lowered.

Two additional normalization tests exercise complete 8 MiB form/binary bodies with nested encoding at their tail, benign binary/form retention, nested JSON keys/escapes, invalid form encoding and a binary multipart file with a tail detection. The workspace suite, neutral-backend HTTP scenarios and clippy remain required alongside these tests.
