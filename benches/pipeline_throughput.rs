use std::{hint::black_box, sync::Arc};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use etherparse::PacketBuilder;
use pcap::Linktype;
use rustmate::{
    analyzers::{dns::DnsAnalyzer, http::HttpAnalyzer, tls_meta::TlsMetaAnalyzer},
    config::RunMode,
    event::Event,
    ingest::{PacketBatch, PacketSource},
    output::EventSink,
    packet::{LinkLayer, PacketTimestamp, RawPacket},
    pipeline::{Pipeline, PipelineConfig, PipelineStats},
    sharded_pipeline::{ShardedPipeline, ShardedPipelineConfig},
    stream_content::StreamContentConfig,
    stream_inventory::StreamInventoryConfig,
    stream_view::StreamViewConfig,
};
use tokio::runtime::Builder;

const BATCH_SIZE: usize = 4096;
const WORKERS: usize = 4;
const QUEUE_DEPTH: usize = 4096;

fn pipeline_throughput(c: &mut Criterion) {
    let runtime = Builder::new_current_thread().build().unwrap();
    let request_fixture = http_request_fixture(8_192);
    let stream_fixture = out_of_order_http_stream_fixture(2_048);

    let mut requests = c.benchmark_group("pipeline/http_requests");
    requests.throughput(Throughput::Elements(request_fixture.len() as u64));
    requests.bench_function("single_thread", |b| {
        b.iter(|| {
            let stats =
                runtime.block_on(run_single_thread(Arc::clone(&request_fixture), BATCH_SIZE));
            black_box(stats);
        })
    });
    requests.bench_function("sharded_4", |b| {
        b.iter(|| {
            let stats = runtime.block_on(run_sharded(Arc::clone(&request_fixture), BATCH_SIZE));
            black_box(stats);
        })
    });
    requests.finish();

    let mut streams = c.benchmark_group("pipeline/out_of_order_http_streams");
    streams.throughput(Throughput::Elements(stream_fixture.len() as u64));
    streams.bench_function("single_thread", |b| {
        b.iter(|| {
            let stats =
                runtime.block_on(run_single_thread(Arc::clone(&stream_fixture), BATCH_SIZE));
            black_box(stats);
        })
    });
    streams.bench_function("sharded_4", |b| {
        b.iter(|| {
            let stats = runtime.block_on(run_sharded(Arc::clone(&stream_fixture), BATCH_SIZE));
            black_box(stats);
        })
    });
    streams.finish();
}

async fn run_single_thread(packets: Arc<[RawPacket]>, batch_size: usize) -> PipelineStats {
    let mut pipeline = Pipeline::new(pipeline_config(batch_size));
    register_analyzers(&mut pipeline);
    pipeline.register_sink(Box::<CountingSink>::default());
    pipeline
        .run_with_source(FixtureSource::new(packets))
        .await
        .unwrap()
}

async fn run_sharded(packets: Arc<[RawPacket]>, batch_size: usize) -> PipelineStats {
    let mut pipeline = ShardedPipeline::new(ShardedPipelineConfig {
        pipeline: pipeline_config(batch_size),
        worker_count: WORKERS,
        worker_queue_depth: QUEUE_DEPTH,
        event_queue_depth: QUEUE_DEPTH,
    });
    register_sharded_analyzers(&mut pipeline);
    pipeline.register_sink(Box::<CountingSink>::default());
    pipeline
        .run_with_source(FixtureSource::new(packets))
        .await
        .unwrap()
}

fn pipeline_config(batch_size: usize) -> PipelineConfig {
    PipelineConfig {
        mode: RunMode::Analyze,
        batch_size,
        health_interval_ms: 0,
        max_flows: 131_072,
        flow_idle_timeout_ms: 120_000,
        max_tcp_buffered_bytes_per_flow: 1 << 20,
        max_tcp_out_of_order_segments_per_direction: 128,
        stream_inventory: StreamInventoryConfig {
            enabled: true,
            max_streams: 131_072,
            idle_timeout_ms: 120_000,
            preview_bytes_per_direction: 256,
            update_packet_interval: 64,
            update_byte_interval: 64 * 1024,
        },
        stream_content: StreamContentConfig {
            enabled: true,
            max_streams: 131_072,
            idle_timeout_ms: 120_000,
            max_total_bytes: 256 * 1024 * 1024,
            max_bytes_per_stream: 8 * 1024 * 1024,
            max_segment_bytes: 64 * 1024,
        },
        stream_view: StreamViewConfig {
            enabled: true,
            max_streams: 131_072,
            max_matches_per_stream: 256,
            max_query_limit: 512,
        },
    }
}

fn register_analyzers(pipeline: &mut Pipeline) {
    pipeline.register_analyzer(Box::new(HttpAnalyzer::new()));
    pipeline.register_analyzer(Box::new(DnsAnalyzer::new()));
    pipeline.register_analyzer(Box::new(TlsMetaAnalyzer::new()));
}

fn register_sharded_analyzers(pipeline: &mut ShardedPipeline) {
    pipeline.register_analyzer_factory(|| Box::new(HttpAnalyzer::new()));
    pipeline.register_analyzer_factory(|| Box::new(DnsAnalyzer::new()));
    pipeline.register_analyzer_factory(|| Box::new(TlsMetaAnalyzer::new()));
}

#[derive(Default)]
struct CountingSink {
    events: u64,
}

impl EventSink for CountingSink {
    fn write(&mut self, _event: &Event) -> anyhow::Result<()> {
        self.events = self.events.saturating_add(1);
        Ok(())
    }

    fn write_batch(&mut self, events: &[Event]) -> anyhow::Result<()> {
        self.events = self.events.saturating_add(events.len() as u64);
        black_box(self.events);
        Ok(())
    }
}

struct FixtureSource {
    packets: Arc<[RawPacket]>,
    cursor: usize,
}

impl FixtureSource {
    fn new(packets: Arc<[RawPacket]>) -> Self {
        Self { packets, cursor: 0 }
    }
}

#[async_trait::async_trait]
impl PacketSource for FixtureSource {
    async fn next_batch(&mut self, batch: &mut PacketBatch) -> anyhow::Result<usize> {
        batch.clear();

        while batch.len() < batch.capacity() {
            let Some(packet) = self.packets.get(self.cursor) else {
                break;
            };
            batch.push(packet.clone());
            self.cursor += 1;
        }

        Ok(batch.len())
    }
}

fn http_request_fixture(flows: usize) -> Arc<[RawPacket]> {
    let mut packets = Vec::with_capacity(flows);
    for flow in 0..flows {
        let payload = format!("GET /item/{flow} HTTP/1.1\r\nHost: fixture.local\r\n\r\n");
        packets.push(tcp_packet(
            source_ip(flow),
            source_port(flow),
            [192, 0, 2, 80],
            80,
            1,
            payload.as_bytes(),
            flow as u64,
        ));
    }
    Arc::from(packets.into_boxed_slice())
}

fn out_of_order_http_stream_fixture(flows: usize) -> Arc<[RawPacket]> {
    let mut packets = Vec::with_capacity(flows * 3);
    for flow in 0..flows {
        let source = source_ip(flow);
        let source_port = source_port(flow);
        let target = format!("item/{flow}");
        let prefix = b"GET /";
        let suffix = b" HTTP/1.1\r\nHost: stream.fixture\r\n\r\n";
        let sequence = 10_000 + (flow as u32).wrapping_mul(128);

        packets.push(tcp_packet(
            source,
            source_port,
            [192, 0, 2, 80],
            80,
            sequence,
            prefix,
            (flow * 3) as u64,
        ));
        packets.push(tcp_packet(
            source,
            source_port,
            [192, 0, 2, 80],
            80,
            sequence + prefix.len() as u32 + target.len() as u32,
            suffix,
            (flow * 3 + 1) as u64,
        ));
        packets.push(tcp_packet(
            source,
            source_port,
            [192, 0, 2, 80],
            80,
            sequence + prefix.len() as u32,
            target.as_bytes(),
            (flow * 3 + 2) as u64,
        ));
    }
    Arc::from(packets.into_boxed_slice())
}

fn source_ip(flow: usize) -> [u8; 4] {
    [
        10,
        ((flow >> 16) & 0xff) as u8,
        ((flow >> 8) & 0xff) as u8,
        ((flow & 0xff) as u8).max(1),
    ]
}

fn source_port(flow: usize) -> u16 {
    10_000 + (flow % 50_000) as u16
}

fn tcp_packet(
    source: [u8; 4],
    source_port: u16,
    destination: [u8; 4],
    destination_port: u16,
    sequence: u32,
    payload: &[u8],
    timestamp: u64,
) -> RawPacket {
    let builder = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
        .ipv4(source, destination, 20)
        .tcp(source_port, destination_port, sequence, 4096);
    let mut data = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut data, payload).unwrap();
    RawPacket {
        timestamp: PacketTimestamp {
            sec: timestamp,
            usec: 0,
        },
        link_layer: LinkLayer::Ethernet,
        linktype: Linktype::ETHERNET.0,
        data,
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = pipeline_throughput
}
criterion_main!(benches);
