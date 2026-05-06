use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    thread::{self, JoinHandle},
};

use anyhow::{Result, anyhow};
use crossbeam_channel::{Receiver, Sender, TryRecvError, TrySendError, bounded};

use crate::{
    analyzers::Analyzer,
    config::RunMode,
    event::Event,
    flow::{Endpoint, FlowRoute, FlowTable, FlowTableConfig, FlowTableStats},
    health::{PipelineHealthReporter, ShardedQueueSnapshot, WorkerQueueSnapshot},
    ingest::{PacketBatch, PacketSource},
    output::EventSink,
    packet::{DecodedPacket, LinkLayer, RawPacket, TransportProtocol},
    pipeline::{PipelineConfig, PipelineStats},
    stream_inventory::{StreamInventory, StreamInventoryStats},
};

type AnalyzerFactory = Arc<dyn Fn() -> Box<dyn Analyzer> + Send + Sync + 'static>;

#[derive(Debug, Clone, Copy)]
pub struct ShardedPipelineConfig {
    pub pipeline: PipelineConfig,
    pub worker_count: usize,
    pub worker_queue_depth: usize,
    pub event_queue_depth: usize,
}

pub struct ShardedPipeline {
    config: ShardedPipelineConfig,
    analyzer_factories: Vec<AnalyzerFactory>,
    sinks: Vec<Box<dyn EventSink>>,
}

enum WorkerCommand {
    Packet(RoutedPacket),
    Shutdown,
}

struct RoutedPacket {
    raw: RawPacket,
    flow_route: Option<FlowRoute>,
}

enum WorkerMessage {
    Events(Vec<Event>),
    Stats(WorkerStats),
}

#[derive(Debug, Default)]
struct WorkerStats {
    id: usize,
    decode_errors: u64,
    flow_stats: FlowTableStats,
    stream_inventory_stats: StreamInventoryStats,
}

struct WorkerHandle {
    id: usize,
    sender: Sender<WorkerCommand>,
    join_handle: JoinHandle<Result<()>>,
}

struct WorkerPool {
    workers: Vec<WorkerHandle>,
    output_rx: Receiver<WorkerMessage>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PacketRoute {
    shard: usize,
    fallback: bool,
    flow_route: Option<FlowRoute>,
}

impl ShardedPipeline {
    pub fn new(config: ShardedPipelineConfig) -> Self {
        Self {
            config: ShardedPipelineConfig {
                worker_count: resolve_worker_count(config.worker_count),
                worker_queue_depth: config.worker_queue_depth.max(1),
                event_queue_depth: config.event_queue_depth.max(1),
                ..config
            },
            analyzer_factories: Vec::new(),
            sinks: Vec::new(),
        }
    }

    pub fn register_analyzer_factory<F>(&mut self, factory: F)
    where
        F: Fn() -> Box<dyn Analyzer> + Send + Sync + 'static,
    {
        self.analyzer_factories.push(Arc::new(factory));
    }

    pub fn register_sink(&mut self, sink: Box<dyn EventSink>) {
        self.sinks.push(sink);
    }

    pub async fn run_with_source<T: PacketSource + 'static>(
        &mut self,
        mut source: T,
    ) -> Result<PipelineStats> {
        let mut stats = PipelineStats {
            workers: self.config.worker_count,
            ..PipelineStats::default()
        };
        let mut batch = PacketBatch::with_capacity(self.config.pipeline.batch_size.max(1));
        let mut packet_sequence = 0u64;
        let mut pool = WorkerPool::start(self.config, Arc::new(self.analyzer_factories.clone()))?;
        let mut worker_packets = vec![0u64; self.config.worker_count];
        let mut health = PipelineHealthReporter::new(self.config.pipeline.health_interval_ms);
        let mut run_error = None;

        loop {
            match source.next_batch(&mut batch).await {
                Ok(0) => {
                    if let Err(err) = pool.drain_available(&mut self.sinks, &mut stats) {
                        run_error = Some(err);
                        break;
                    }

                    let queue = pool.queue_snapshot(&worker_packets);
                    if let Err(err) =
                        health.maybe_report(&mut stats, Some(&queue), || source.stats())
                    {
                        run_error = Some(err);
                        break;
                    }

                    if source.is_finished() {
                        break;
                    }
                }
                Ok(_) => {
                    let batch_len = batch.len();
                    let batch_bytes = batch.byte_len();
                    stats.batches = stats.batches.saturating_add(1);
                    stats.packets = stats.packets.saturating_add(batch_len as u64);
                    stats.bytes = stats.bytes.saturating_add(batch_bytes as u64);

                    for raw in batch.drain() {
                        let route = route_packet(
                            &raw,
                            self.config.pipeline.mode,
                            packet_sequence,
                            self.config.worker_count,
                        );
                        packet_sequence = packet_sequence.saturating_add(1);
                        stats.fallback_routed_packets = stats
                            .fallback_routed_packets
                            .saturating_add(u64::from(route.fallback));
                        if let Some(worker_packets) = worker_packets.get_mut(route.shard) {
                            *worker_packets = worker_packets.saturating_add(1);
                        }

                        let packet = RoutedPacket {
                            raw,
                            flow_route: route.flow_route,
                        };

                        if let Err(err) =
                            pool.send_packet(route.shard, packet, &mut self.sinks, &mut stats)
                        {
                            run_error = Some(err);
                            break;
                        }
                    }

                    if run_error.is_some() {
                        break;
                    }

                    if let Err(err) = pool.drain_available(&mut self.sinks, &mut stats) {
                        run_error = Some(err);
                        break;
                    }

                    let queue = pool.queue_snapshot(&worker_packets);
                    if let Err(err) =
                        health.maybe_report(&mut stats, Some(&queue), || source.stats())
                    {
                        run_error = Some(err);
                        break;
                    }
                }
                Err(err) => {
                    run_error = Some(err);
                    break;
                }
            }
        }

        let source_stats_result = if run_error.is_none() {
            Some(source.stats())
        } else {
            None
        };

        let shutdown_result = pool.shutdown(&mut self.sinks, &mut stats);
        if let Some(err) = run_error {
            if let Err(shutdown_err) = shutdown_result {
                tracing::warn!(
                    error = %shutdown_err,
                    "Failed to stop worker shards after a processing error"
                );
            }
            return Err(err);
        }

        shutdown_result?;
        if let Some(source_stats) = source_stats_result.transpose()?.flatten() {
            stats.set_source_stats(source_stats);
        }
        Ok(stats)
    }
}

impl WorkerPool {
    fn start(
        config: ShardedPipelineConfig,
        analyzer_factories: Arc<Vec<AnalyzerFactory>>,
    ) -> Result<Self> {
        let mut workers = Vec::with_capacity(config.worker_count);
        let (output_tx, output_rx) = bounded(config.event_queue_depth);

        for id in 0..config.worker_count {
            let (sender, receiver) = bounded(config.worker_queue_depth);
            let output_tx = output_tx.clone();
            let analyzer_factories = Arc::clone(&analyzer_factories);
            let flow_config = flow_table_config(config);
            let join_handle = thread::Builder::new()
                .name(format!("rustmate-flow-shard-{id}"))
                .spawn(move || {
                    run_worker(
                        id,
                        config.pipeline,
                        flow_config,
                        analyzer_factories,
                        receiver,
                        output_tx,
                    )
                })
                .map_err(|err| anyhow!("failed to spawn worker shard {id}: {err}"))?;

            workers.push(WorkerHandle {
                id,
                sender,
                join_handle,
            });
        }

        drop(output_tx);
        Ok(Self { workers, output_rx })
    }

    fn send_packet(
        &mut self,
        shard: usize,
        mut packet: RoutedPacket,
        sinks: &mut [Box<dyn EventSink>],
        stats: &mut PipelineStats,
    ) -> Result<()> {
        let sender = self
            .workers
            .get(shard)
            .ok_or_else(|| anyhow!("invalid worker shard index {shard}"))?
            .sender
            .clone();

        // Keep queues bounded. If a worker is backed up, drain events first so
        // slow output does not wedge the whole capture path.
        loop {
            match sender.try_send(WorkerCommand::Packet(packet)) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(WorkerCommand::Packet(returned_packet))) => {
                    packet = returned_packet;
                    self.drain_available(sinks, stats)?;
                    thread::yield_now();
                }
                Err(TrySendError::Full(WorkerCommand::Shutdown)) => {
                    return Err(anyhow!("worker shard {shard} send queue rejected shutdown"));
                }
                Err(TrySendError::Disconnected(_)) => {
                    return Err(anyhow!(
                        "worker shard {shard} stopped before accepting packet"
                    ));
                }
            }
        }
    }

    fn drain_available(
        &mut self,
        sinks: &mut [Box<dyn EventSink>],
        stats: &mut PipelineStats,
    ) -> Result<()> {
        loop {
            match self.output_rx.try_recv() {
                Ok(message) => write_worker_message(message, sinks, stats)?,
                Err(TryRecvError::Empty) => return Ok(()),
                Err(TryRecvError::Disconnected) => {
                    return Err(anyhow!("worker output channel disconnected"));
                }
            }
        }
    }

    fn queue_snapshot(&self, routed_packets: &[u64]) -> ShardedQueueSnapshot {
        ShardedQueueSnapshot {
            workers: self
                .workers
                .iter()
                .map(|worker| WorkerQueueSnapshot {
                    id: worker.id,
                    len: worker.sender.len(),
                    capacity: worker.sender.capacity().unwrap_or(0),
                    routed_packets: routed_packets.get(worker.id).copied().unwrap_or_default(),
                })
                .collect(),
            output_queue_len: self.output_rx.len(),
            output_queue_capacity: self.output_rx.capacity().unwrap_or(0),
        }
    }

    fn shutdown(self, sinks: &mut [Box<dyn EventSink>], stats: &mut PipelineStats) -> Result<()> {
        let worker_count = self.workers.len();
        let mut first_error = None;

        for worker in &self.workers {
            if worker.sender.send(WorkerCommand::Shutdown).is_err() {
                tracing::warn!(worker = worker.id, "Worker shard stopped before shutdown");
            }
        }

        let mut received_stats = 0usize;
        while received_stats < worker_count {
            match self.output_rx.recv() {
                Ok(WorkerMessage::Stats(worker_stats)) => {
                    stats.decode_errors = stats
                        .decode_errors
                        .saturating_add(worker_stats.decode_errors);
                    stats.add_flow_table_stats(worker_stats.flow_stats);
                    stats.add_stream_inventory_stats(worker_stats.stream_inventory_stats);
                    received_stats += 1;
                    tracing::debug!(
                        worker = worker_stats.id,
                        "Worker shard reported final stats"
                    );
                }
                Ok(WorkerMessage::Events(events)) => {
                    if let Err(err) = write_events(events, sinks, stats) {
                        record_first_error(&mut first_error, err);
                    }
                }
                Err(_) => {
                    record_first_error(
                        &mut first_error,
                        anyhow!("worker output channel closed before final stats"),
                    );
                    break;
                }
            }
        }

        for worker in self.workers {
            match worker.join_handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(err)) => record_first_error(&mut first_error, err),
                Err(_) => record_first_error(
                    &mut first_error,
                    anyhow!("worker shard {} panicked", worker.id),
                ),
            }
        }

        for sink in sinks.iter_mut() {
            if let Err(err) = sink.flush() {
                record_first_error(&mut first_error, err);
            }
        }

        if let Some(err) = first_error {
            Err(err)
        } else {
            Ok(())
        }
    }
}

fn run_worker(
    id: usize,
    config: PipelineConfig,
    flow_config: FlowTableConfig,
    analyzer_factories: Arc<Vec<AnalyzerFactory>>,
    receiver: Receiver<WorkerCommand>,
    output_tx: Sender<WorkerMessage>,
) -> Result<()> {
    let mut flow_table = FlowTable::new(flow_config);
    let mut stream_inventory = StreamInventory::new(config.stream_inventory);
    let mut analyzers = analyzer_factories
        .iter()
        .map(|factory| factory())
        .collect::<Vec<_>>();
    let event_batch_capacity = config.batch_size.clamp(1, 8192);
    let mut events = Vec::with_capacity(event_batch_capacity);
    let mut stats = WorkerStats {
        id,
        ..WorkerStats::default()
    };

    while let Ok(command) = receiver.recv() {
        match command {
            WorkerCommand::Packet(packet) => {
                process_worker_packet(
                    &packet,
                    config.mode,
                    &mut flow_table,
                    &mut stream_inventory,
                    &mut analyzers,
                    &mut events,
                    &mut stats,
                );

                if events.len() >= event_batch_capacity {
                    flush_worker_events(&output_tx, &mut events)?;
                }
            }
            WorkerCommand::Shutdown => break,
        }
    }

    flush_worker_events(&output_tx, &mut events)?;
    stats.flow_stats = flow_table.stats();
    stats.stream_inventory_stats = stream_inventory.stats();
    output_tx
        .send(WorkerMessage::Stats(stats))
        .map_err(|_| anyhow!("coordinator stopped before worker shard {id} sent stats"))?;
    Ok(())
}

fn process_worker_packet(
    routed: &RoutedPacket,
    mode: RunMode,
    flow_table: &mut FlowTable,
    stream_inventory: &mut StreamInventory,
    analyzers: &mut [Box<dyn Analyzer>],
    events: &mut Vec<Event>,
    stats: &mut WorkerStats,
) {
    let raw = &routed.raw;
    match mode {
        RunMode::Dump => events.push(Event::packet_dump(raw)),
        RunMode::Analyze => {
            let packet = DecodedPacket::from_raw(raw);
            if packet.decode_error().is_some() {
                stats.decode_errors = stats.decode_errors.saturating_add(1);
                return;
            }

            let flow = routed
                .flow_route
                .map(|route| flow_table.observe_with_route(&packet, route))
                .unwrap_or_else(|| flow_table.observe(&packet));
            if let Some(flow) = flow.as_ref() {
                stream_inventory.observe_flow(&packet, flow, events);
            }
            if let Some((flow, tcp)) = flow
                .as_ref()
                .and_then(|flow| flow.tcp.as_ref().map(|tcp| (flow, tcp)))
            {
                for chunk in &tcp.stream_chunks {
                    for analyzer in analyzers.iter_mut() {
                        analyzer.analyze_stream(&packet, flow, chunk, events);
                    }
                }
            }

            for analyzer in analyzers.iter_mut() {
                analyzer.analyze(&packet, events);
            }
        }
    }
}

fn flush_worker_events(output_tx: &Sender<WorkerMessage>, events: &mut Vec<Event>) -> Result<()> {
    if events.is_empty() {
        return Ok(());
    }

    let mut batch = Vec::with_capacity(events.capacity());
    std::mem::swap(events, &mut batch);
    output_tx
        .send(WorkerMessage::Events(batch))
        .map_err(|_| anyhow!("coordinator stopped before receiving worker events"))
}

fn write_worker_message(
    message: WorkerMessage,
    sinks: &mut [Box<dyn EventSink>],
    stats: &mut PipelineStats,
) -> Result<()> {
    match message {
        WorkerMessage::Events(events) => write_events(events, sinks, stats),
        WorkerMessage::Stats(worker_stats) => {
            stats.decode_errors = stats
                .decode_errors
                .saturating_add(worker_stats.decode_errors);
            stats.add_flow_table_stats(worker_stats.flow_stats);
            stats.add_stream_inventory_stats(worker_stats.stream_inventory_stats);
            Ok(())
        }
    }
}

fn write_events(
    events: Vec<Event>,
    sinks: &mut [Box<dyn EventSink>],
    stats: &mut PipelineStats,
) -> Result<()> {
    stats.events = stats.events.saturating_add(events.len() as u64);
    for sink in sinks {
        sink.write_batch(&events)?;
    }
    Ok(())
}

fn record_first_error(first_error: &mut Option<anyhow::Error>, err: anyhow::Error) {
    if first_error.is_none() {
        *first_error = Some(err);
    }
}

pub fn resolve_worker_count(worker_count: usize) -> usize {
    if worker_count == 0 {
        thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1)
            .max(1)
    } else {
        worker_count.max(1)
    }
}

fn route_packet(raw: &RawPacket, mode: RunMode, sequence: u64, worker_count: usize) -> PacketRoute {
    if worker_count <= 1 || matches!(mode, RunMode::Dump) {
        return PacketRoute {
            shard: 0,
            fallback: false,
            flow_route: None,
        };
    }

    let Some(flow_route) = flow_route_from_raw(raw) else {
        return PacketRoute {
            shard: fallback_shard(sequence, worker_count),
            fallback: true,
            flow_route: None,
        };
    };

    PacketRoute {
        shard: hash_to_shard(&flow_route.key, worker_count),
        fallback: false,
        flow_route: Some(flow_route),
    }
}

// Tiny parser for the dispatcher. Workers still do the full decode once analyzers need it.
fn flow_route_from_raw(raw: &RawPacket) -> Option<FlowRoute> {
    match raw.link_layer {
        LinkLayer::Ethernet => {
            let (ethertype, payload_offset) = ethernet_payload(&raw.data)?;
            route_ip_by_ethertype(&raw.data, payload_offset, ethertype)
        }
        LinkLayer::LinuxSll => {
            if raw.data.len() < 16 {
                return None;
            }
            let ethertype = read_u16(&raw.data, 14)?;
            route_ip_by_ethertype(&raw.data, 16, ethertype)
        }
        LinkLayer::RawIp => route_raw_ip(&raw.data, 0),
        LinkLayer::BsdLoopback => route_raw_ip(&raw.data, 4),
        LinkLayer::Unsupported => None,
    }
}

fn ethernet_payload(data: &[u8]) -> Option<(u16, usize)> {
    if data.len() < 14 {
        return None;
    }

    let mut ethertype = read_u16(data, 12)?;
    let mut offset = 14;
    for _ in 0..2 {
        if !matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
            break;
        }
        if data.len() < offset + 4 {
            return None;
        }
        ethertype = read_u16(data, offset + 2)?;
        offset += 4;
    }

    Some((ethertype, offset))
}

fn route_ip_by_ethertype(data: &[u8], offset: usize, ethertype: u16) -> Option<FlowRoute> {
    match ethertype {
        0x0800 => route_ipv4(data, offset),
        0x86dd => route_ipv6(data, offset),
        _ => None,
    }
}

fn route_raw_ip(data: &[u8], offset: usize) -> Option<FlowRoute> {
    let version = data.get(offset)? >> 4;
    match version {
        4 => route_ipv4(data, offset),
        6 => route_ipv6(data, offset),
        _ => None,
    }
}

fn route_ipv4(data: &[u8], offset: usize) -> Option<FlowRoute> {
    if data.len() < offset + 20 {
        return None;
    }

    let version = data[offset] >> 4;
    let header_len = usize::from(data[offset] & 0x0f) * 4;
    if version != 4 || header_len < 20 || data.len() < offset + header_len {
        return None;
    }

    let total_len = usize::from(read_u16(data, offset + 2)?);
    if total_len < header_len {
        return None;
    }

    let fragment = read_u16(data, offset + 6)?;
    if fragment & 0x1fff != 0 {
        return None;
    }

    let protocol = data[offset + 9];
    let source = IpAddr::V4(Ipv4Addr::new(
        data[offset + 12],
        data[offset + 13],
        data[offset + 14],
        data[offset + 15],
    ));
    let destination = IpAddr::V4(Ipv4Addr::new(
        data[offset + 16],
        data[offset + 17],
        data[offset + 18],
        data[offset + 19],
    ));

    route_transport(data, offset + header_len, protocol, source, destination)
}

fn route_ipv6(data: &[u8], offset: usize) -> Option<FlowRoute> {
    if data.len() < offset + 40 || data[offset] >> 4 != 6 {
        return None;
    }

    let source_bytes: [u8; 16] = data.get(offset + 8..offset + 24)?.try_into().ok()?;
    let destination_bytes: [u8; 16] = data.get(offset + 24..offset + 40)?.try_into().ok()?;
    let source = IpAddr::V6(Ipv6Addr::from(source_bytes));
    let destination = IpAddr::V6(Ipv6Addr::from(destination_bytes));

    route_ipv6_transport(data, offset + 40, data[offset + 6], source, destination)
}

fn route_ipv6_transport(
    data: &[u8],
    mut offset: usize,
    mut next_header: u8,
    source: IpAddr,
    destination: IpAddr,
) -> Option<FlowRoute> {
    for _ in 0..8 {
        match next_header {
            6 | 17 => return route_transport(data, offset, next_header, source, destination),
            0 | 43 | 60 => {
                if data.len() < offset + 2 {
                    return None;
                }
                next_header = data[offset];
                offset = offset.saturating_add((usize::from(data[offset + 1]) + 1) * 8);
            }
            44 => {
                if data.len() < offset + 8 {
                    return None;
                }
                let fragment = read_u16(data, offset + 2)?;
                if fragment & 0xfff8 != 0 {
                    return None;
                }
                next_header = data[offset];
                offset = offset.saturating_add(8);
            }
            51 => {
                if data.len() < offset + 2 {
                    return None;
                }
                next_header = data[offset];
                offset = offset.saturating_add((usize::from(data[offset + 1]) + 2) * 4);
            }
            _ => return None,
        }
    }

    None
}

fn route_transport(
    data: &[u8],
    offset: usize,
    protocol: u8,
    source_addr: IpAddr,
    destination_addr: IpAddr,
) -> Option<FlowRoute> {
    let protocol = match protocol {
        6 => TransportProtocol::Tcp,
        17 => TransportProtocol::Udp,
        _ => return None,
    };
    let source_port = read_u16(data, offset)?;
    let destination_port = read_u16(data, offset + 2)?;

    Some(FlowRoute::new(
        protocol,
        Endpoint {
            addr: source_addr,
            port: source_port,
        },
        Endpoint {
            addr: destination_addr,
            port: destination_port,
        },
    ))
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *data.get(offset)?,
        *data.get(offset + 1)?,
    ]))
}

fn fallback_shard(sequence: u64, worker_count: usize) -> usize {
    (sequence as usize) % worker_count
}

fn flow_table_config(config: ShardedPipelineConfig) -> FlowTableConfig {
    FlowTableConfig::new(
        max_flows_per_worker(config.pipeline.max_flows, config.worker_count),
        config.pipeline.flow_idle_timeout_ms,
        config.pipeline.max_tcp_buffered_bytes_per_flow,
        config.pipeline.max_tcp_out_of_order_segments_per_direction,
    )
}

fn max_flows_per_worker(max_flows: usize, worker_count: usize) -> usize {
    max_flows.max(1).div_ceil(worker_count.max(1))
}

fn hash_to_shard<T: Hash>(value: &T, worker_count: usize) -> usize {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    (hasher.finish() as usize) % worker_count
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        net::Ipv4Addr,
        sync::{Arc, Mutex},
    };

    use etherparse::PacketBuilder;
    use pcap::Linktype;

    use crate::{
        analyzers::http::HttpAnalyzer,
        config::RunMode,
        ingest::{PacketBatch, PacketSource},
        output::EventSink,
        packet::{LinkLayer, PacketTimestamp},
        stream_inventory::StreamInventoryConfig,
    };

    use super::*;

    #[tokio::test]
    async fn reassembles_http_stream_on_flow_shard() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut pipeline = test_pipeline(4);
        pipeline.register_analyzer_factory(|| Box::new(HttpAnalyzer::new()));
        pipeline.register_sink(Box::new(CollectSink {
            events: Arc::clone(&events),
        }));

        let source = VecPacketSource::new(vec![
            tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 100, b"GET /", 1),
            tcp_packet(
                [10, 0, 0, 1],
                1111,
                [10, 0, 0, 2],
                80,
                111,
                b" HTTP/1.1\r\nHost: shard.local\r\n\r\n",
                2,
            ),
            tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 105, b"flagxx", 3),
        ]);

        let stats = pipeline.run_with_source(source).await.unwrap();

        let events = events.lock().unwrap();
        assert_eq!(4, stats.workers);
        assert_eq!(3, stats.tcp_stream_chunks);
        assert_eq!(2, stats.events);
        assert_eq!(1, stats.inventory_created_streams);
        assert_eq!(1, stats.inventory_events);
        assert_eq!(2, events.len());
        let http = events
            .iter()
            .find(|event| event["event_type"] == "http_request")
            .unwrap();
        assert_eq!("/flagxx", http["fields"]["target"]);
        assert_eq!("shard.local", http["fields"]["headers"]["host"]);
    }

    #[tokio::test]
    async fn keeps_independent_flow_state_per_shard() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut pipeline = test_pipeline(4);
        pipeline.register_analyzer_factory(|| Box::new(HttpAnalyzer::new()));
        pipeline.register_sink(Box::new(CollectSink {
            events: Arc::clone(&events),
        }));

        let source = VecPacketSource::new(vec![
            tcp_packet(
                [10, 0, 0, 1],
                1111,
                [10, 0, 0, 2],
                80,
                1,
                b"GET /a HTTP/1.1\r\nHost: a.local\r\n\r\n",
                1,
            ),
            tcp_packet(
                [10, 0, 1, 1],
                2222,
                [10, 0, 1, 2],
                80,
                1,
                b"GET /b HTTP/1.1\r\nHost: b.local\r\n\r\n",
                2,
            ),
        ]);

        let stats = pipeline.run_with_source(source).await.unwrap();
        let events = events.lock().unwrap();
        let mut targets = events
            .iter()
            .filter(|event| event["event_type"] == "http_request")
            .map(|event| event["fields"]["target"].as_str().unwrap().to_owned())
            .collect::<Vec<_>>();
        targets.sort();

        assert_eq!(2, stats.created_flows);
        assert_eq!(4, stats.events);
        assert_eq!(2, stats.inventory_created_streams);
        assert_eq!(vec!["/a".to_owned(), "/b".to_owned()], targets);
    }

    #[test]
    fn routes_both_directions_of_flow_to_same_shard() {
        let forward = tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 1, b"x", 1);
        let reverse = tcp_packet([10, 0, 0, 2], 80, [10, 0, 0, 1], 1111, 1, b"y", 2);

        let forward_route = route_packet(&forward, RunMode::Analyze, 0, 8);
        let reverse_route = route_packet(&reverse, RunMode::Analyze, 1, 8);

        assert!(!forward_route.fallback);
        assert!(!reverse_route.fallback);
        assert!(forward_route.flow_route.is_some());
        assert!(reverse_route.flow_route.is_some());
        assert_eq!(forward_route.shard, reverse_route.shard);
    }

    #[test]
    fn lightweight_route_matches_decoded_packet_route() {
        let raw = tcp_packet(
            [10, 0, 0, 1],
            1111,
            [10, 0, 0, 2],
            80,
            1,
            b"GET / HTTP/1.1\r\n\r\n",
            1,
        );
        let decoded = DecodedPacket::from_raw(&raw);
        let expected = FlowRoute::from_packet(&decoded);

        assert_eq!(expected, flow_route_from_raw(&raw));
        assert_eq!(
            expected,
            route_packet(&raw, RunMode::Analyze, 0, 4).flow_route
        );
    }

    #[test]
    fn lightweight_route_supports_bsd_loopback() {
        let raw = bsd_loopback_tcp_packet(31337, 80, 1, b"GET /loop HTTP/1.1\r\n\r\n");
        let decoded = DecodedPacket::from_raw(&raw);

        assert_eq!(FlowRoute::from_packet(&decoded), flow_route_from_raw(&raw));
    }

    #[test]
    fn splits_global_flow_limit_across_workers() {
        assert_eq!(250, max_flows_per_worker(1_000, 4));
        assert_eq!(251, max_flows_per_worker(1_001, 4));
        assert_eq!(1, max_flows_per_worker(0, 16));
    }

    #[tokio::test]
    async fn counts_fallback_routes_and_worker_decode_errors() {
        let mut pipeline = test_pipeline(4);
        let source = VecPacketSource::new(vec![RawPacket {
            timestamp: PacketTimestamp { sec: 1, usec: 0 },
            link_layer: LinkLayer::Unsupported,
            linktype: 9999,
            data: b"not a supported packet".to_vec(),
        }]);

        let stats = pipeline.run_with_source(source).await.unwrap();

        assert_eq!(1, stats.fallback_routed_packets);
        assert_eq!(1, stats.decode_errors);
    }

    #[tokio::test]
    async fn keeps_sharded_pipeline_running_after_idle_source_tick() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut pipeline = test_pipeline(4);
        pipeline.register_analyzer_factory(|| Box::new(HttpAnalyzer::new()));
        pipeline.register_sink(Box::new(CollectSink {
            events: Arc::clone(&events),
        }));

        let source = IdleThenPacketSource::new(vec![tcp_packet(
            [10, 0, 0, 1],
            1111,
            [10, 0, 0, 2],
            80,
            1,
            b"GET /idle-shard HTTP/1.1\r\nHost: idle.local\r\n\r\n",
            1,
        )]);

        let stats = pipeline.run_with_source(source).await.unwrap();

        let events = events.lock().unwrap();
        assert_eq!(1, stats.packets);
        assert_eq!(2, stats.events);
        let http = events
            .iter()
            .find(|event| event["event_type"] == "http_request")
            .unwrap();
        assert_eq!("/idle-shard", http["fields"]["target"]);
    }

    #[tokio::test]
    async fn bounded_event_queue_backpressures_without_deadlock() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut pipeline = ShardedPipeline::new(ShardedPipelineConfig {
            pipeline: PipelineConfig {
                mode: RunMode::Analyze,
                batch_size: 16,
                health_interval_ms: 0,
                max_flows: 1024,
                flow_idle_timeout_ms: 120_000,
                max_tcp_buffered_bytes_per_flow: 64 * 1024,
                max_tcp_out_of_order_segments_per_direction: 16,
                stream_inventory: test_stream_inventory_config(),
            },
            worker_count: 2,
            worker_queue_depth: 1,
            event_queue_depth: 1,
        });
        pipeline.register_analyzer_factory(|| Box::new(HttpAnalyzer::new()));
        pipeline.register_sink(Box::new(CollectSink {
            events: Arc::clone(&events),
        }));

        let packets = (0..64)
            .map(|flow| {
                let source = [10, 0, 0, (flow + 1) as u8];
                let payload = format!("GET /q{flow} HTTP/1.1\r\nHost: backpressure.local\r\n\r\n");
                tcp_packet(
                    source,
                    10_000 + flow as u16,
                    [10, 0, 1, 1],
                    80,
                    1,
                    payload.as_bytes(),
                    flow as u64,
                )
            })
            .collect();

        let stats = pipeline
            .run_with_source(VecPacketSource::new(packets))
            .await
            .unwrap();

        assert_eq!(64, stats.packets);
        assert_eq!(128, stats.events);
        assert_eq!(64, stats.inventory_created_streams);
        assert_eq!(64, stats.inventory_events);
        assert_eq!(128, events.lock().unwrap().len());
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

    fn test_pipeline(worker_count: usize) -> ShardedPipeline {
        ShardedPipeline::new(ShardedPipelineConfig {
            pipeline: PipelineConfig {
                mode: RunMode::Analyze,
                batch_size: 2,
                health_interval_ms: 0,
                max_flows: 1024,
                flow_idle_timeout_ms: 120_000,
                max_tcp_buffered_bytes_per_flow: 64 * 1024,
                max_tcp_out_of_order_segments_per_direction: 16,
                stream_inventory: test_stream_inventory_config(),
            },
            worker_count,
            worker_queue_depth: 8,
            event_queue_depth: 8,
        })
    }

    fn test_stream_inventory_config() -> StreamInventoryConfig {
        StreamInventoryConfig {
            enabled: true,
            max_streams: 1024,
            idle_timeout_ms: 120_000,
            preview_bytes_per_direction: 128,
            update_packet_interval: 64,
            update_byte_interval: 64 * 1024,
        }
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
            .ipv4(
                Ipv4Addr::from(source).octets(),
                Ipv4Addr::from(destination).octets(),
                20,
            )
            .tcp(source_port, destination_port, sequence, 1024);
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

    fn bsd_loopback_tcp_packet(
        source_port: u16,
        destination_port: u16,
        sequence: u32,
        payload: &[u8],
    ) -> RawPacket {
        let ethernet = tcp_packet(
            [127, 0, 0, 1],
            source_port,
            [127, 0, 0, 1],
            destination_port,
            sequence,
            payload,
            1,
        );
        let mut data = vec![0, 0, 0, 2];
        data.extend_from_slice(&ethernet.data[14..]);

        RawPacket {
            timestamp: ethernet.timestamp,
            link_layer: LinkLayer::BsdLoopback,
            linktype: Linktype::NULL.0,
            data,
        }
    }
}
