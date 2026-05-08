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
- Highlight / Content Slice Layer for viewport-sized stream reads. It clips
  retained pattern matches to requested logical ranges, returns text, hex, or raw
  views, keeps segment boundaries for gaps, and provides bounded copy/export
  helpers without dumping full streams through the event path.
- Decode / Transform Layer for bounded content views. It can URL-decode stream
  slices, decode raw gzip payloads, inflate gzip HTTP bodies while preserving the
  header prefix, and decode compressed WebSocket frames without letting decoded
  output run past configured caps.
- Read-only local live API for stream lists, stream details, match ranges,
  health stats, retained deltas, and viewport content slices. In sharded runs,
  content requests are routed back to the shard that owns the stream while
  capture is active, then served from retained shard stores after shutdown.
- Frontend shell served by the local API. It gives a dense stream table, details
  pane, content viewport, retained match highlights, transform output, live
  delta polling, and basic copy/navigation controls without adding a separate
  web stack yet.
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
cargo run -- --pcap sample.pcap --api-listen 127.0.0.1:33111
cargo run -- --pcap sample.pcap --api-listen 127.0.0.1:33111 --api-delta-capacity 65536
cargo run -- --list-interfaces
cargo run -- --iface en0 --output live.jsonl --workers 0
cargo run -- --iface en0 --capture-filter "tcp or udp" --capture-buffer-size 67108864
cargo run -- --iface en0 --health-interval-ms 1000
cargo run -- --iface en0 --max-packets 10000
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

Content slicing is designed for viewport reads, not bulk export. The reader asks
the shard-local content store for a logical byte window and combines it with the
view state's retained match ranges. The result carries clipped highlights plus
text, hex, or raw/base64 segment views. In sharded mode, slice requests use the
same flow hash as packet routing, so the coordinator does not clone payload
stores across shards.

Transforms sit on top of content slices and are also bounded. The API accepts
`transform=auto`, `url_decode`, `gzip`, `http_gzip`, or `websocket_deflate` on a
content request. Transform output is returned beside the original slice, so the
UI can keep raw bytes visible while showing decoded copies where it helps.

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
curl 'http://127.0.0.1:33111/api/live/deltas?cursor=0&limit=1024&wait_ms=1000'
curl 'http://127.0.0.1:33111/api/streams?limit=50&only_matched=true'
curl http://127.0.0.1:33111/api/streams/123456789
curl http://127.0.0.1:33111/api/streams/123456789/matches
curl 'http://127.0.0.1:33111/api/streams/123456789/content?direction=a_to_b&start=0&len=65536&mode=text'
curl 'http://127.0.0.1:33111/api/streams/123456789/content?direction=a_to_b&start=0&len=65536&mode=text&transform=auto'
```

## Development Priorities

1. Harden the frontend shell for real traffic: keyboard navigation, stable row
   virtualization, favorites, hide toggles, and richer copy/export formats.
2. Add service profiles: port groups, pattern scopes, auto-hide rules, default
   view filters, and service-specific decode preferences.
3. Expand transform coverage: chunked HTTP bodies, charset handling, Brotli/zstd
   when useful, and safer WebSocket message aggregation.
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
cargo bench --bench packet_decode
cargo bench --bench pipeline_throughput
```
