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
- Flow-sharded worker pool for multi-threaded analysis. Each shard owns its
  `FlowTable`, stream inventory, and analyzer state; bounded queues provide
  backpressure, and the coordinator writes output batches without sink-level
  locking.
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

## Development Priorities

1. Build stream filtering and view state on top of Stream Inventory: hide rules,
   favorites, service/pattern scopes, and per-stream navigation metadata.
2. Move TLS analyzer onto stream input, keeping packet-level analyzers for
   stateless heuristics.
3. Expand benchmark fixtures with real PCAP corpora and track throughput deltas
   across worker counts.
4. Split outputs into debug sinks and production sinks. JSONL is useful for
   inspection, but the high-load path should support faster formats and bounded
   queues.
5. Add machine-readable metrics export for long-running capture: Prometheus or
   lightweight JSON stats snapshots.
6. Add benchmarks with fixed PCAP fixtures and track packets/sec, bytes/sec,
   allocations, and dropped packets.
7. Grow analyzers around the flow layer: HTTP bodies, DNS names, TLS ClientHello
   metadata, secrets/flag extraction, and protocol heuristics.

## Checks

```bash
cargo fmt --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo bench --bench packet_decode
cargo bench --bench pipeline_throughput
```
