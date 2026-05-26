# rustmate

Fast traffic capture and analysis utility for CTF and investigation workflows.

The current codebase is an early core, shaped around a pipeline that can grow
without forcing each analyzer to re-parse packet bytes:

```text
PacketSource -> PacketBatch -> Flow-sharded workers -> Analyzer events -> Output sinks
```

## Current Features

- Offline PCAP ingest with batch reads.
- Live capture ingest from libpcap interfaces, with BPF filter, snaplen,
  kernel/libpcap buffer size, read timeout, promiscuous mode, immediate mode,
  Ctrl-C shutdown, optional packet limit, and source drop counters.
- Link-layer aware packet decoding for Ethernet, Linux SLL, and raw IP frames.
- Single-pass payload extraction through `etherparse`.
- Bounded flow table keyed by protocol and canonical endpoints.
- TCP direction state with sequence tracking, retransmission/overlap/gap
  detection, reset/finish tracking, and bounded out-of-order buffering.
- TCP stream assembler that emits ordered stream chunks to analyzer hooks.
  Current in-order payload is borrowed without copying; buffered gap-fill data is
  emitted as owned chunks.
- Stream Inventory Layer keyed by canonical flow ids. It tracks bounded stream
  records, stable `stream_id`s, service guesses, text/binary classification,
  per-direction counters, small previews, lifecycle status, and throttled
  `stream_open` / `stream_update` JSONL events.
- Stream Content Layer for bounded reassembled payload storage. It keeps
  direction-aware content ranges, merges adjacent TCP chunks, trims old bytes
  under per-stream pressure, evicts old content under global pressure, and does
  not dump stored payload into JSONL by default.
- Pattern Matching Engine on top of stored stream content. It supports repeated
  substring, regex, and binary hex patterns; scans across chunk boundaries; emits
  logical match ranges for highlighting; and has per-stream plus global match
  caps so noisy streams cannot dominate output.
- Stream View State and Filtering Layer for the future UI/API. The coordinator
  keeps bounded stream rows, retained match ranges, favorites, manual hidden
  flags, hide rules, service/pattern scopes, and cursor-based stream queries
  without making worker shards share mutable UI state.
- Service Profile Layer for grouping streams by protocol, service names, ports,
  content kind, and pattern ids. Built-in profiles cover HTTP, TLS, DNS,
  WebSocket-style traffic, binary streams, and matched streams; JSON profile
  files can override or add profiles without changing code.
- Highlight / Content Slice Layer for viewport-sized stream reads. It clips
  retained pattern matches to requested logical ranges, returns text, hex, or raw
  views, keeps segment boundaries for gaps, and provides bounded copy/export
  helpers without dumping full streams through the event path.
- Decode / Transform V2 for bounded content views. It supports explicit
  transform chains, URL decode, raw gzip, HTTP chunked body decode, gzip HTTP
  body inflation while preserving the header prefix, partial gzip slices, and
  compressed WebSocket message aggregation without letting decoded output run
  past configured caps.
- Parser Layer for protocol parsing above reassembled streams. It is a
  first-class pipeline/worker component with its own caps and stats, so
  coordinator code can track parser pressure separately from analyzers and
  output sinks.
- Protocol Message Layer for bounded logical message indexes above parser
  output. HTTP/1 parsing now records request/response boundaries, keep-alive
  messages, header and body logical ranges, `Content-Length` bodies, chunked
  bodies, summary metadata, and parse errors without forcing the UI to scrape raw
  JSONL analyzer output.
- Local live API for stream lists, stream details, match ranges, health stats,
  retained deltas, viewport content slices, service profiles, favorites, manual
  hidden state, and hide rules. In sharded runs, content requests are routed back
  to the shard that owns the stream while capture is active, then served from
  retained shard stores after shutdown.
- Frontend shell served by the local API. It gives a dense stream table, details
  pane, content viewport, retained match highlights, transform output, live
  delta polling, service profile filters, favorites, hidden-stream toggles,
  hide-by-service controls, keyboard stream navigation, match jumps, viewport
  row virtualization, lazy stream page loading, and copy formats for view text,
  raw text, decoded text, hex, and base64 without adding a separate web stack
  yet.
- Load / Perf Harness for repeatable throughput checks. The `rustmate-load`
  helper can replay synthetic HTTP, out-of-order, keep-alive, and mixed-service
  fixtures or a real PCAP across multiple worker counts, then emit per-run
  JSON/JSONL reports with packet, byte, event, stream throughput, and per-shard
  load skew diagnostics.
- Flow-sharded worker pool for multi-threaded analysis. Each shard owns its
  `FlowTable`, stream inventory, stream content store, and analyzer state;
  bounded queues provide backpressure, and the coordinator writes output batches
  without sink-level locking.
- Bounded worker input queues and bounded worker-to-output event queues; sharded
  packet routing moves captured packet buffers into workers without cloning.
- Route-only dispatcher parsing for sharded mode, so the worker is the only
  stage that builds a full decoded packet view for analyzers.
- Periodic health reporting with packet/event/byte rates, source drop rates,
  active flow counters, sharded queue pressure, and shard skew.
- Analyzer API that receives decoded packet views.
- Stream-based HTTP request/response analyzer, plus initial DNS and TLS metadata
  analyzers.
- Batch-oriented JSONL output sink.
- `analyze` and `dump` modes.
- Criterion benchmark for packet decode hot path.

## Usage

```bash
cargo run -- --pcap sample.pcap
cargo run -- --pcap sample.pcap --output findings.jsonl
cargo run -- --pcap sample.pcap --mode dump
cargo run -- --pcap sample.pcap --batch-size 8192 --max-flows 2000000
cargo run -- --pcap sample.pcap --max-tcp-buffered-bytes-per-flow 1048576
cargo run -- --pcap sample.pcap --workers 8 --worker-queue-depth 8192
cargo run -- --pcap sample.pcap --workers 8 --event-queue-depth 8192
cargo run -- --pcap sample.pcap --max-streams 2000000 --stream-preview-bytes 512
cargo run -- --pcap sample.pcap --stream-update-packets 128 --stream-update-bytes 131072
cargo run -- --pcap sample.pcap --disable-stream-inventory
cargo run -- --pcap sample.pcap --max-stream-content-bytes 536870912
cargo run -- --pcap sample.pcap --max-stream-content-bytes-per-stream 16777216
cargo run -- --pcap sample.pcap --disable-stream-content
cargo run -- --pcap sample.pcap --pattern flag --regex 'token=[a-z0-9]+'
cargo run -- --pcap sample.pcap --binary-pattern 'de ad be ef'
cargo run -- --pcap sample.pcap --max-pattern-matches-per-stream 256
cargo run -- --pcap sample.pcap --max-stream-view-matches-per-stream 512
cargo run -- --pcap sample.pcap --disable-stream-view
cargo run -- --pcap sample.pcap --max-stream-slice-bytes 131072
cargo run -- --pcap sample.pcap --max-stream-slice-highlights 8192
cargo run -- --pcap sample.pcap --max-stream-transform-bytes 1048576
cargo run -- --pcap sample.pcap --max-http1-parser-states 262144
cargo run -- --pcap sample.pcap --max-http1-header-bytes 131072
cargo run -- --pcap sample.pcap --max-parser-messages-per-chunk 1024
cargo run -- --pcap sample.pcap --disable-stream-parser
cargo run -- --pcap sample.pcap --api-listen 127.0.0.1:33111
cargo run -- --pcap sample.pcap --api-listen 127.0.0.1:33111 --api-delta-capacity 65536
cargo run -- --pcap sample.pcap --api-listen 127.0.0.1:33111 --service-profile-file profiles.json
cargo run -- --list-interfaces
cargo run -- --iface en0 --output live.jsonl --workers 0
cargo run -- --iface en0 --capture-filter "tcp or udp" --capture-buffer-size 67108864
cargo run -- --iface en0 --health-interval-ms 1000
cargo run -- --iface en0 --max-packets 10000
```

Load checks should be run before and after parser or stream-layer changes. Use
small synthetic runs while iterating, then replay real captures before committing
parser-heavy work:

```bash
cargo run --release --bin rustmate-load -- --fixture http-requests --flows 100000 --workers 1,4,adaptive,0 --runs 3 --warmups 1 --output perf-http.json
cargo run --release --bin rustmate-load -- --fixture out-of-order-http --flows 50000 --workers 1,4,adaptive,0 --output perf-streams.json
cargo run --release --bin rustmate-load -- --fixture mixed-services --flows 50000 --messages-per-flow 4 --workers 1,4,adaptive,0 --output-format jsonl --output perf-mixed.jsonl
cargo run --release --bin rustmate-load -- --pcap /path/to/capture.pcap --workers 1,4,adaptive,0 --runs 3 --warmups 1 --output perf-pcap.json
```

`--workers 0` means "available parallelism", while `--workers adaptive` uses the
input-driven worker planner. The planner picks the highest worker count that
still has enough packets/flows per worker and acceptable packet/byte skew; tune
it with `--adaptive-min-packets-per-worker`,
`--adaptive-min-flows-per-worker`, `--adaptive-max-packet-skew`, and
`--adaptive-max-byte-skew`. Summary rows exclude warmups by default; pass
`--include-warmups` when you need raw run-by-run diagnostics. The `pkt skew`
summary column and `diagnostics.shards` JSON field help separate real scaling
limits from uneven flow distribution in small or bursty captures.

Saved JSON reports are regression baselines. Compare a new run against a
baseline and fail CI when average packets/sec for a matching worker count drops
too far:

```bash
cargo run --release --bin rustmate-load -- --fixture http-requests --flows 100000 --workers adaptive --runs 5 --warmups 2 --output baselines/http.json
cargo run --release --bin rustmate-load -- --fixture http-requests --flows 100000 --workers adaptive --runs 5 --warmups 2 --baseline baselines/http.json --max-regression-pct 10 --fail-on-regression --output perf-current.json
```

`--workers 0` uses the machine's available parallelism. Packets from the same
flow are routed to the same worker, so TCP stream order is preserved per flow.
Global event order across unrelated flows is intentionally not serialized on the
hot path.

Stream inventory is enabled by default. It keeps only bounded previews, not full
payload bodies, so it can power stream lists and filters without becoming the
payload store. `stream_id` is deterministic for a canonical flow key, which keeps
single-threaded and flow-sharded output easy to correlate.

Stream content storage is also enabled by default, but bounded separately from
inventory. It is the in-memory base for pattern matching, highlighting,
copy/export, and decode layers; JSONL stays metadata-oriented unless a later sink
explicitly asks for payload bytes.

Pattern matching is opt-in. `--pattern` adds byte-exact text substring matches,
`--regex` adds byte regex matches, and `--binary-pattern` accepts hex bytes with
optional spaces, colons, underscores, dashes, or a `0x` prefix. Match events carry
`stream_id`, direction, logical byte offsets, base64 bytes, and text preview when
the matched bytes are printable.

Stream view state is enabled by default and is bounded separately from the
content store. It indexes stream inventory events and pattern match events into
typed rows for UI-style queries: favorites, hidden streams, hide rules, matched
only, service scopes, pattern scopes, ports, protocol, status, and content kind.
The sharded coordinator owns this state, so worker shards keep running even if a
future UI is slow or disconnected.

Service profiles sit on top of stream view state. A profile can match by
protocol, inferred service name, port group, content kind, or retained pattern
id, and can carry default content view preferences plus hide-rule templates. The
API supports `profile=<id>` on stream queries and `transform=profile` on content
requests. A custom profile file is JSON:

```json
{
  "include_builtins": true,
  "profiles": [
    {
      "id": "admin_web",
      "name": "Admin web",
      "priority": 150,
      "protocol": "tcp",
      "ports": [8080, 18080],
      "services": ["http"],
      "default_mode": "text",
      "default_transform": "auto",
      "default_transforms": ["http_chunked", "http_gzip", "url_decode"],
      "hide_rules": [{ "kind": "port", "value": 18080 }]
    }
  ]
}
```

Content slicing is designed for viewport reads, not bulk export. The reader asks
the shard-local content store for a logical byte window and combines it with the
view state's retained match ranges. The result carries clipped highlights plus
text, hex, or raw/base64 segment views. In sharded mode, slice requests use the
same flow hash as packet routing, so the coordinator does not clone payload
stores across shards.

Transforms sit on top of content slices and are also bounded. The API accepts
single transforms such as `transform=auto`, `url_decode`, `gzip`,
`http_chunked`, `http_gzip`, or `websocket_deflate`, and chain syntax such as
`transform=http_chunked,http_gzip,url_decode`. `transform=profile` uses the
selected stream's service profile defaults. Transform output is returned beside
the original slice with per-step status, so the UI can keep raw bytes visible
while showing decoded copies where it helps.

The parser layer is enabled by default and runs inside the same flow shard that
owns stream reassembly. Its caps are intentionally separate from stream content
caps: `--max-http1-parser-states`, `--max-http1-header-bytes`,
`--max-http1-buffer-bytes`, and `--max-parser-messages-per-chunk` control parser
memory and event bursts. Health and perf reports expose parser counters such as
`parser_stream_chunks`, `parser_emitted_messages`, `parser_evicted_states`, and
`parser_http1_active_states`.

Protocol messages sit beside content slices. The message index is keyed by the
same `stream_id` as stream rows and content windows, so the UI can jump from a
message row to the exact logical byte range. `/api/streams/{id}/messages`
supports `direction`, `protocol=http1`, `kind=request|response`, `status`, cursor,
and limit filters.

The local API starts before input processing and remains available after the
source finishes. Stream list, detail, match, health, and content endpoints are
safe for polling. `/api/live/deltas` exposes a bounded cursor log for UI clients:
stats updates, changed stream rows, match ranges, and status changes. If a client
falls behind the retained cursor window, the response marks `missed=true`; the
client should refresh `/api/streams` and continue from `latest_cursor`. Stream
rows, matches, and content slices include `stream_id_hex`, so browser clients do
not lose precision on 64-bit stream ids.

Open `http://127.0.0.1:33111/` while the API is running to use the built-in
frontend shell.

```bash
curl http://127.0.0.1:33111/api/health
curl http://127.0.0.1:33111/api/service-profiles
curl 'http://127.0.0.1:33111/api/live/deltas?cursor=0&limit=1024&wait_ms=1000'
curl 'http://127.0.0.1:33111/api/streams?limit=50&only_matched=true'
curl 'http://127.0.0.1:33111/api/streams?profile=http&limit=50'
curl http://127.0.0.1:33111/api/streams/123456789
curl -X PATCH http://127.0.0.1:33111/api/streams/123456789/state \
  -H 'content-type: application/json' -d '{"favorite":true}'
curl -X POST http://127.0.0.1:33111/api/view/hide-rules \
  -H 'content-type: application/json' -d '{"kind":"service","value":"dns"}'
curl http://127.0.0.1:33111/api/streams/123456789/matches
curl 'http://127.0.0.1:33111/api/streams/123456789/messages?protocol=http1&limit=128'
curl 'http://127.0.0.1:33111/api/streams/123456789/content?direction=a_to_b&start=0&len=65536&mode=text'
curl 'http://127.0.0.1:33111/api/streams/123456789/content?direction=a_to_b&start=0&len=65536&mode=text&transform=profile'
curl 'http://127.0.0.1:33111/api/streams/123456789/content?direction=a_to_b&start=0&len=65536&mode=text&transform=auto'
curl 'http://127.0.0.1:33111/api/streams/123456789/content?direction=a_to_b&start=0&len=65536&mode=text&transform=http_chunked,http_gzip,url_decode'
```

## Development Priorities

1. Add persistent view state: favorites, manual hidden streams, hide rules,
   profile choices, and UI preferences saved outside the capture process.
2. Extend service profiles with profile activation
   presets, and service-specific analyzer settings.
3. Expand transform coverage: charset handling, Brotli/zstd when useful, and
   transform-aware exported content slices.
4. Move TLS analyzer onto stream input, keeping packet-level analyzers for
   stateless heuristics.
5. Expand benchmark fixtures with real PCAP corpora and track throughput deltas
   across worker counts.
6. Split outputs into debug sinks and production sinks. JSONL is useful for
   inspection, but the high-load path should support faster formats and bounded
   queues.
7. Add machine-readable metrics export for long-running capture: Prometheus or
   lightweight JSON stats snapshots.
8. Add benchmarks with fixed PCAP fixtures and track packets/sec, bytes/sec,
   allocations, and dropped packets.
9. Grow analyzers around the flow layer: HTTP bodies, DNS names, TLS ClientHello
   metadata, secrets/flag extraction, and protocol heuristics.

## Checks

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo run --release --bin rustmate-load -- --fixture http-requests --flows 10000 --workers 1,adaptive --runs 1 --warmups 0
cargo bench --bench packet_decode
cargo bench --bench pipeline_throughput
```
