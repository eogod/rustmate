use anyhow::Result;

use crate::{
    analyzers::Analyzer,
    config::RunMode,
    event::Event,
    flow::{FlowTable, FlowTableConfig, FlowTableStats},
    health::PipelineHealthReporter,
    ingest::{PacketBatch, PacketSource, PacketSourceStats},
    output::EventSink,
    packet::{DecodedPacket, RawPacket},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct PipelineStats {
    pub workers: usize,
    pub batches: u64,
    pub packets: u64,
    pub bytes: u64,
    pub events: u64,
    pub decode_errors: u64,
    pub fallback_routed_packets: u64,
    pub source_received_packets: u64,
    pub source_dropped_packets: u64,
    pub source_interface_dropped_packets: u64,
    pub active_flows: usize,
    pub created_flows: u64,
    pub evicted_flows: u64,
    pub dropped_new_flows: u64,
    pub tcp_stream_chunks: u64,
    pub tcp_stream_bytes: u64,
    pub tcp_gaps: u64,
    pub tcp_retransmissions: u64,
    pub tcp_overlaps: u64,
    pub tcp_out_of_order_buffered: u64,
    pub tcp_out_of_order_dropped: u64,
    pub tcp_resets: u64,
}

impl PipelineStats {
    pub(crate) fn set_flow_table_stats(&mut self, flow_stats: FlowTableStats) {
        self.active_flows = flow_stats.active_flows;
        self.created_flows = flow_stats.created_flows;
        self.evicted_flows = flow_stats.evicted_flows;
        self.dropped_new_flows = flow_stats.dropped_new_flows;
        self.tcp_stream_chunks = flow_stats.tcp_stream_chunks;
        self.tcp_stream_bytes = flow_stats.tcp_stream_bytes;
        self.tcp_gaps = flow_stats.tcp_gaps;
        self.tcp_retransmissions = flow_stats.tcp_retransmissions;
        self.tcp_overlaps = flow_stats.tcp_overlaps;
        self.tcp_out_of_order_buffered = flow_stats.tcp_out_of_order_buffered;
        self.tcp_out_of_order_dropped = flow_stats.tcp_out_of_order_dropped;
        self.tcp_resets = flow_stats.tcp_resets;
    }

    pub(crate) fn add_flow_table_stats(&mut self, flow_stats: FlowTableStats) {
        self.active_flows = self.active_flows.saturating_add(flow_stats.active_flows);
        self.created_flows = self.created_flows.saturating_add(flow_stats.created_flows);
        self.evicted_flows = self.evicted_flows.saturating_add(flow_stats.evicted_flows);
        self.dropped_new_flows = self
            .dropped_new_flows
            .saturating_add(flow_stats.dropped_new_flows);
        self.tcp_stream_chunks = self
            .tcp_stream_chunks
            .saturating_add(flow_stats.tcp_stream_chunks);
        self.tcp_stream_bytes = self
            .tcp_stream_bytes
            .saturating_add(flow_stats.tcp_stream_bytes);
        self.tcp_gaps = self.tcp_gaps.saturating_add(flow_stats.tcp_gaps);
        self.tcp_retransmissions = self
            .tcp_retransmissions
            .saturating_add(flow_stats.tcp_retransmissions);
        self.tcp_overlaps = self.tcp_overlaps.saturating_add(flow_stats.tcp_overlaps);
        self.tcp_out_of_order_buffered = self
            .tcp_out_of_order_buffered
            .saturating_add(flow_stats.tcp_out_of_order_buffered);
        self.tcp_out_of_order_dropped = self
            .tcp_out_of_order_dropped
            .saturating_add(flow_stats.tcp_out_of_order_dropped);
        self.tcp_resets = self.tcp_resets.saturating_add(flow_stats.tcp_resets);
    }

    pub(crate) fn set_source_stats(&mut self, source_stats: PacketSourceStats) {
        self.source_received_packets = source_stats.received;
        self.source_dropped_packets = source_stats.dropped;
        self.source_interface_dropped_packets = source_stats.interface_dropped;
    }
}

pub struct Pipeline {
    config: PipelineConfig,
    mode: RunMode,
    analyzers: Vec<Box<dyn Analyzer>>,
    sinks: Vec<Box<dyn EventSink>>,
    flow_table: FlowTable,
    events: Vec<Event>,
}

#[derive(Debug, Clone, Copy)]
pub struct PipelineConfig {
    pub mode: RunMode,
    pub batch_size: usize,
    pub health_interval_ms: u64,
    pub max_flows: usize,
    pub flow_idle_timeout_ms: u64,
    pub max_tcp_buffered_bytes_per_flow: usize,
    pub max_tcp_out_of_order_segments_per_direction: usize,
}

impl Pipeline {
    pub fn new(config: PipelineConfig) -> Self {
        Self {
            config,
            mode: config.mode,
            analyzers: Vec::new(),
            sinks: Vec::new(),
            flow_table: FlowTable::new(FlowTableConfig::new(
                config.max_flows,
                config.flow_idle_timeout_ms,
                config.max_tcp_buffered_bytes_per_flow,
                config.max_tcp_out_of_order_segments_per_direction,
            )),
            events: Vec::with_capacity(config.batch_size),
        }
    }

    pub fn register_analyzer(&mut self, analyzer: Box<dyn Analyzer>) {
        tracing::info!("Registering analyzer: {}", analyzer.name());
        self.analyzers.push(analyzer);
    }

    pub fn register_sink(&mut self, sink: Box<dyn EventSink>) {
        self.sinks.push(sink);
    }

    pub async fn run_with_source<T: PacketSource + 'static>(
        &mut self,
        mut source: T,
    ) -> Result<PipelineStats> {
        let mut stats = PipelineStats {
            workers: 1,
            ..PipelineStats::default()
        };
        let mut batch = PacketBatch::with_capacity(self.config.batch_size.max(1));
        let mut health = PipelineHealthReporter::new(self.config.health_interval_ms);

        loop {
            let read = source.next_batch(&mut batch).await?;
            if read == 0 {
                health.maybe_report(&mut stats, None, || source.stats())?;
                if source.is_finished() {
                    break;
                }
                continue;
            }

            stats.batches = stats.batches.saturating_add(1);
            stats.packets = stats.packets.saturating_add(batch.len() as u64);
            stats.bytes = stats.bytes.saturating_add(batch.byte_len() as u64);

            self.process_batch(&batch, &mut stats);
            stats.events = stats.events.saturating_add(self.events.len() as u64);

            for sink in &mut self.sinks {
                sink.write_batch(&self.events)?;
            }

            health.maybe_report(&mut stats, None, || source.stats())?;
        }

        let source_stats_result = source.stats();

        for sink in &mut self.sinks {
            sink.flush()?;
        }

        if let Some(source_stats) = source_stats_result? {
            stats.set_source_stats(source_stats);
        }

        Ok(stats)
    }

    fn process_batch(&mut self, batch: &PacketBatch, stats: &mut PipelineStats) {
        self.events.clear();

        for raw in batch.packets() {
            self.process_packet(raw, stats);
        }

        stats.set_flow_table_stats(self.flow_table.stats());
    }

    fn process_packet(&mut self, raw: &RawPacket, stats: &mut PipelineStats) {
        match self.mode {
            RunMode::Dump => self.events.push(Event::packet_dump(raw)),
            RunMode::Analyze => {
                let packet = DecodedPacket::from_raw(raw);
                if packet.decode_error().is_some() {
                    stats.decode_errors += 1;
                    return;
                }

                let flow = self.flow_table.observe(&packet);
                if let Some(flow) = flow
                    .as_ref()
                    .and_then(|flow| flow.tcp.as_ref().map(|tcp| (flow, tcp)))
                {
                    for chunk in &flow.1.stream_chunks {
                        for analyzer in &mut self.analyzers {
                            analyzer.analyze_stream(&packet, flow.0, chunk, &mut self.events);
                        }
                    }
                }

                for analyzer in &mut self.analyzers {
                    analyzer.analyze(&packet, &mut self.events);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
    };

    use etherparse::PacketBuilder;
    use pcap::Linktype;

    use crate::{
        analyzers::{Analyzer, http::HttpAnalyzer},
        flow::{FlowObservation, StreamChunk},
        ingest::{PacketBatch, PacketSource},
        output::EventSink,
        packet::{LinkLayer, PacketTimestamp},
    };

    use super::*;

    #[tokio::test]
    async fn sends_reassembled_stream_chunks_to_analyzers() {
        let chunks = Arc::new(Mutex::new(Vec::new()));
        let mut pipeline = Pipeline::new(PipelineConfig {
            mode: RunMode::Analyze,
            batch_size: 8,
            health_interval_ms: 0,
            max_flows: 1024,
            flow_idle_timeout_ms: 120_000,
            max_tcp_buffered_bytes_per_flow: 64 * 1024,
            max_tcp_out_of_order_segments_per_direction: 16,
        });
        pipeline.register_analyzer(Box::new(StreamCollector {
            chunks: Arc::clone(&chunks),
        }));

        let source = VecPacketSource::new(vec![
            tcp_packet(100, b"abc"),
            tcp_packet(106, b"gh"),
            tcp_packet(103, b"def"),
        ]);
        let stats = pipeline.run_with_source(source).await.unwrap();

        assert_eq!(3, stats.tcp_stream_chunks);
        assert_eq!(8, stats.tcp_stream_bytes);
        assert_eq!(
            vec![b"abc".to_vec(), b"def".to_vec(), b"gh".to_vec()],
            *chunks.lock().unwrap()
        );
    }

    #[tokio::test]
    async fn emits_http_event_from_out_of_order_stream_through_pipeline() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut pipeline = test_pipeline();
        pipeline.register_analyzer(Box::new(HttpAnalyzer::new()));
        pipeline.register_sink(Box::new(CollectSink {
            events: Arc::clone(&events),
        }));

        let source = VecPacketSource::new(vec![
            tcp_packet(100, b"GET /"),
            tcp_packet(111, b" HTTP/1.1\r\nHost: ctf.local\r\n\r\n"),
            tcp_packet(105, b"flagxx"),
        ]);

        pipeline.run_with_source(source).await.unwrap();

        let events = events.lock().unwrap();
        assert_eq!(1, events.len());
        assert_eq!("http_request", events[0]["event_type"]);
        assert_eq!("/flagxx", events[0]["fields"]["target"]);
        assert_eq!("ctf.local", events[0]["fields"]["headers"]["host"]);
    }

    #[tokio::test]
    async fn keeps_running_after_idle_source_tick() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut pipeline = test_pipeline();
        pipeline.register_analyzer(Box::new(HttpAnalyzer::new()));
        pipeline.register_sink(Box::new(CollectSink {
            events: Arc::clone(&events),
        }));

        let source = IdleThenPacketSource::new(vec![tcp_packet(
            1,
            b"GET /idle HTTP/1.1\r\nHost: idle.local\r\n\r\n",
        )]);

        let stats = pipeline.run_with_source(source).await.unwrap();

        let events = events.lock().unwrap();
        assert_eq!(1, stats.packets);
        assert_eq!(1, stats.events);
        assert_eq!("/idle", events[0]["fields"]["target"]);
    }

    struct StreamCollector {
        chunks: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl Analyzer for StreamCollector {
        fn name(&self) -> &'static str {
            "stream_collector"
        }

        fn analyze(&mut self, _packet: &DecodedPacket<'_>, _events: &mut Vec<Event>) {}

        fn analyze_stream(
            &mut self,
            _packet: &DecodedPacket<'_>,
            _flow: &FlowObservation<'_>,
            chunk: &StreamChunk<'_>,
            _events: &mut Vec<Event>,
        ) {
            self.chunks
                .lock()
                .unwrap()
                .push(chunk.bytes.as_slice().to_vec());
        }
    }

    struct CollectSink {
        events: Arc<Mutex<Vec<serde_json::Value>>>,
    }

    impl EventSink for CollectSink {
        fn write(&mut self, event: &Event) -> anyhow::Result<()> {
            self.events
                .lock()
                .unwrap()
                .push(serde_json::to_value(event)?);
            Ok(())
        }
    }

    struct VecPacketSource {
        packets: VecDeque<RawPacket>,
    }

    impl VecPacketSource {
        fn new(packets: Vec<RawPacket>) -> Self {
            Self {
                packets: VecDeque::from(packets),
            }
        }
    }

    struct IdleThenPacketSource {
        packets: VecDeque<RawPacket>,
        yielded_idle: bool,
    }

    impl IdleThenPacketSource {
        fn new(packets: Vec<RawPacket>) -> Self {
            Self {
                packets: VecDeque::from(packets),
                yielded_idle: false,
            }
        }
    }

    #[async_trait::async_trait]
    impl PacketSource for IdleThenPacketSource {
        async fn next_batch(&mut self, batch: &mut PacketBatch) -> anyhow::Result<usize> {
            batch.clear();
            if !self.yielded_idle {
                self.yielded_idle = true;
                return Ok(0);
            }

            while batch.len() < batch.capacity() {
                let Some(packet) = self.packets.pop_front() else {
                    break;
                };
                batch.push(packet);
            }

            Ok(batch.len())
        }

        fn is_finished(&self) -> bool {
            self.yielded_idle && self.packets.is_empty()
        }
    }

    fn test_pipeline() -> Pipeline {
        Pipeline::new(PipelineConfig {
            mode: RunMode::Analyze,
            batch_size: 8,
            health_interval_ms: 0,
            max_flows: 1024,
            flow_idle_timeout_ms: 120_000,
            max_tcp_buffered_bytes_per_flow: 64 * 1024,
            max_tcp_out_of_order_segments_per_direction: 16,
        })
    }

    #[async_trait::async_trait]
    impl PacketSource for VecPacketSource {
        async fn next_batch(&mut self, batch: &mut PacketBatch) -> anyhow::Result<usize> {
            batch.clear();
            while batch.len() < batch.capacity() {
                let Some(packet) = self.packets.pop_front() else {
                    break;
                };
                batch.push(packet);
            }
            Ok(batch.len())
        }
    }

    fn tcp_packet(sequence: u32, payload: &[u8]) -> RawPacket {
        let builder = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 20)
            .tcp(1111, 80, sequence, 1024);
        let mut data = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut data, payload).unwrap();
        RawPacket {
            timestamp: PacketTimestamp { sec: 1, usec: 0 },
            link_layer: LinkLayer::Ethernet,
            linktype: Linktype::ETHERNET.0,
            data,
        }
    }
}
