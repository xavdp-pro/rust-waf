# Normalization resource checkpoints

## Current streaming inspection

The gateway now matches each body view as it is produced and retains only matching rule IDs. JSON array/scalar nodes and decoded string views are not accumulated. A streaming visitor validates the entire JSON document, including trailing bytes, escaped duplicate keys and recursion depth. Object keys are retained within each object for duplicate detection; unescaped keys borrow input. Multipart raw contents, metadata and complete file contents remain inspected. Fixed method/route exceptions are resolved after scanning, with the original provenance and confidence. No early hit can skip syntax validation or permit partial forwarding. Diagnostic normalize() still collects views and is not the production resource path.

The example now defaults to `streamed`; its optional third argument `collected` exercises diagnostic collection. Cases add `json-empty-strings`, `json-unique-strings` and `json-object-keys`. On the same local release environment, streamed 8 MiB peak RSS in KiB is: opaque text 13,588; opaque binary 38,048; form 13,752; JSON string 13,792; empty-array JSON 13,540; empty-string JSON 13,540; unique-string JSON 13,540; many-key object 51,696; multipart binary 53,988. Each case completed with zero rule hits and zero retained body view bytes. Zero retained views does not mean zero allocation; independent peak RSS is the relevant observation.

`tools/probe_gateway_memory.py` creates a temporary systemd service with a 512 MiB cap, four Tokio workers and a private neutral Unix backend. It uses an enforcement runtime with eight allowed tasks, unchanged profiles/limits and no public listener. Twelve synthetic body families run in three batches of eight simultaneous requests, with complete body hash/correlation checks and full-size backend responses for allowed controls. JSON ambiguity/malformed tails and a binary tail detection must have no neutral backend receipt. Per-batch service peak/current memory, restart count and cgroup OOM events are recorded. The script stops its own unit and backend; it never targets PHP or changes an existing service.

Example on an isolated Linux host only:

```bash
python3 tools/probe_gateway_memory.py --binary /path/to/candidate --runtime /path/to/enforce-runtime.json --service-user gateway --service-group gateway --output /path/to/private-resource-proof.json
```

This short adversarial probe is not the matching baseline/protected performance protocol, browser qualification or a mathematical memory bound for every permitted configuration. Key sets, worker count, maximum body/response sizes and allocator retention still matter. Full deployment acceptance remains required. No body limit, concurrency limit or acceptance threshold was reduced.

## Earlier copy-reduction checkpoint

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

These are historical development measurements, not independent acceptance evidence. At this earlier checkpoint, the JSON parser still built an AST with per-node overhead; the current streaming implementation above removes that tree from production inspection. Concurrent normalization, multipart parser allocations, decoding expansion and backend buffers require further measurement and bounding. These results do not prove a gateway-wide 512 MiB ceiling, latency/throughput acceptance, or deployment behavior. No body limit or acceptance threshold was lowered.

Two additional normalization tests exercise complete 8 MiB form/binary bodies with nested encoding at their tail, benign binary/form retention, nested JSON keys/escapes, invalid form encoding and a binary multipart file with a tail detection. The workspace suite, neutral-backend HTTP scenarios and clippy remain required alongside these tests.
