use anyhow::Result;

use crate::{
    analyzers::Analyzer,
    config::RunMode,
    event::Event,
    flow::{FlowTable, FlowTableConfig},
    ingest::{PacketBatch, PacketSource},
    output::EventSink,
    packet::{DecodedPacket, RawPacket},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct PipelineStats {
    pub batches: u64,
    pub packets: u64,
    pub bytes: u64,
    pub events: u64,
    pub decode_errors: u64,
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
        tracing::info!("Регистрация анализатора: {}", analyzer.name());
        self.analyzers.push(analyzer);
    }

    pub fn register_sink(&mut self, sink: Box<dyn EventSink>) {
        self.sinks.push(sink);
    }

    pub async fn run_with_source<T: PacketSource + 'static>(
        &mut self,
        mut source: T,
    ) -> Result<PipelineStats> {
        let mut stats = PipelineStats::default();
        let mut batch = PacketBatch::with_capacity(self.config.batch_size.max(1));

        while source.next_batch(&mut batch).await? != 0 {
            stats.batches = stats.batches.saturating_add(1);
            stats.packets = stats.packets.saturating_add(batch.len() as u64);
            stats.bytes = stats.bytes.saturating_add(batch.byte_len() as u64);

            self.process_batch(&batch, &mut stats);
            stats.events = stats.events.saturating_add(self.events.len() as u64);

            for sink in &mut self.sinks {
                sink.write_batch(&self.events)?;
            }
        }

        for sink in &mut self.sinks {
            sink.flush()?;
        }

        Ok(stats)
    }

    fn process_batch(&mut self, batch: &PacketBatch, stats: &mut PipelineStats) {
        self.events.clear();

        for raw in batch.packets() {
            self.process_packet(raw, stats);
        }

        let flow_stats = self.flow_table.stats();
        stats.active_flows = flow_stats.active_flows;
        stats.created_flows = flow_stats.created_flows;
        stats.evicted_flows = flow_stats.evicted_flows;
        stats.dropped_new_flows = flow_stats.dropped_new_flows;
        stats.tcp_stream_chunks = flow_stats.tcp_stream_chunks;
        stats.tcp_stream_bytes = flow_stats.tcp_stream_bytes;
        stats.tcp_gaps = flow_stats.tcp_gaps;
        stats.tcp_retransmissions = flow_stats.tcp_retransmissions;
        stats.tcp_overlaps = flow_stats.tcp_overlaps;
        stats.tcp_out_of_order_buffered = flow_stats.tcp_out_of_order_buffered;
        stats.tcp_out_of_order_dropped = flow_stats.tcp_out_of_order_dropped;
        stats.tcp_resets = flow_stats.tcp_resets;
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
                            analyzer.analyze_stream(flow.0, chunk, &mut self.events);
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
        analyzers::Analyzer,
        flow::{FlowObservation, StreamChunk},
        ingest::{PacketBatch, PacketSource},
        packet::{LinkLayer, PacketTimestamp},
    };

    use super::*;

    #[tokio::test]
    async fn sends_reassembled_stream_chunks_to_analyzers() {
        let chunks = Arc::new(Mutex::new(Vec::new()));
        let mut pipeline = Pipeline::new(PipelineConfig {
            mode: RunMode::Analyze,
            batch_size: 8,
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
