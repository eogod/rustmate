use std::{
    sync::Arc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TryRecvError, TrySendError, bounded};
use tokio::sync::oneshot;

use crate::{
    analyzers::Analyzer,
    api::LiveApiHandle,
    config::RunMode,
    event::Event,
    flow::{FlowKey, FlowRoute, FlowTable, FlowTableConfig, FlowTableStats},
    health::{PipelineHealthReporter, ShardedQueueSnapshot},
    ingest::{PacketBatch, PacketSource},
    output::EventSink,
    packet::{DecodedPacket, PacketDecodeCounters, RawPacket},
    pattern::{PatternEngine, PatternEngineConfig, PatternEngineStats},
    pipeline::{PipelineConfig, PipelineStats},
    shard::{ShardCoordinator, ShardCoordinatorConfig, ShardLoadMetrics, ShardQueueLoad},
    stream_content::{StreamContent, StreamContentStats},
    stream_inventory::{StreamInventory, StreamInventoryStats},
    stream_message::StreamMessageStore,
    stream_parser::{StreamParserLayer, StreamParserStats},
    stream_slice::{
        StreamContentSlice, StreamSliceConfig, StreamSliceError, StreamSliceReader,
        StreamSliceRequest,
    },
    stream_view::{StreamPatternMatch, StreamViewEntry, StreamViewState},
};

pub use crate::shard::shard_for_flow_key;

type AnalyzerFactory = Arc<dyn Fn() -> Box<dyn Analyzer> + Send + Sync + 'static>;

const WORKER_LIVE_EVENT_FLUSH_MS: u64 = 100;
const WORKER_LIVE_STATS_FLUSH_MS: u64 = 500;

#[derive(Debug, Clone, Copy)]
pub struct ShardedPipelineConfig {
    pub pipeline: PipelineConfig,
    pub worker_count: usize,
    pub worker_queue_depth: usize,
    pub event_queue_depth: usize,
}

pub struct ShardedPipeline {
    config: ShardedPipelineConfig,
    pattern_config: PatternEngineConfig,
    stream_view: StreamViewState,
    stream_messages: StreamMessageStore,
    stream_content_shards: Vec<Option<StreamContent>>,
    live_api: Option<LiveApiHandle>,
    analyzer_factories: Vec<AnalyzerFactory>,
    sinks: Vec<Box<dyn EventSink>>,
}

enum WorkerCommand {
    Packet(RoutedPacket),
    ContentSlice(Box<WorkerSliceRequest>),
    Shutdown,
}

struct RoutedPacket {
    raw: RawPacket,
    owner_shard: usize,
    flow_route: Option<FlowRoute>,
}

struct WorkerSliceRequest {
    request: StreamSliceRequest,
    flow_key: FlowKey,
    matches: Vec<StreamPatternMatch>,
    response_tx: oneshot::Sender<std::result::Result<StreamContentSlice, StreamSliceError>>,
}

enum WorkerMessage {
    Events(Vec<Event>),
    StatsSnapshot(Box<WorkerStats>),
    Stats(Box<WorkerReport>),
}

struct WorkerReport {
    stats: WorkerStats,
    stream_content: StreamContent,
}

#[derive(Debug, Default, Clone, Copy)]
struct WorkerStats {
    id: usize,
    packet_decode: PacketDecodeCounters,
    flow_stats: FlowTableStats,
    stream_inventory_stats: StreamInventoryStats,
    stream_content_stats: StreamContentStats,
    stream_parser_stats: StreamParserStats,
    pattern_stats: PatternEngineStats,
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

struct CoordinatorState<'a> {
    sinks: &'a mut [Box<dyn EventSink>],
    stream_view: &'a mut StreamViewState,
    stream_messages: &'a mut StreamMessageStore,
    stream_content_shards: &'a mut [Option<StreamContent>],
    worker_stats_snapshots: &'a mut [Option<WorkerStats>],
    live_api: Option<&'a LiveApiHandle>,
    stats: &'a mut PipelineStats,
}

#[derive(Clone)]
pub struct ShardedContentSliceHandle {
    senders: Arc<Vec<Sender<WorkerCommand>>>,
    timeout: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardedContentSliceError {
    InvalidShard { shard: usize },
    QueueFull { shard: usize },
    Disconnected { shard: usize },
    Timeout { shard: usize },
}

struct WorkerRuntime {
    mode: RunMode,
    flow_table: FlowTable,
    stream_inventory: StreamInventory,
    stream_content: StreamContent,
    stream_parser: StreamParserLayer,
    pattern_engine: PatternEngine,
    analyzers: Vec<Box<dyn Analyzer>>,
    events: Vec<Event>,
    stats: WorkerStats,
}

struct WorkerLiveFlushState {
    event_batch_capacity: usize,
    event_flush_interval: Duration,
    stats_flush_interval: Duration,
    last_event_flush: Instant,
    last_stats_flush: Instant,
}

impl ShardedPipeline {
    pub fn new(config: ShardedPipelineConfig) -> Self {
        let config = ShardedPipelineConfig {
            worker_count: resolve_worker_count(config.worker_count),
            worker_queue_depth: config.worker_queue_depth.max(1),
            event_queue_depth: config.event_queue_depth.max(1),
            ..config
        };
        let stream_content_shards = (0..config.worker_count).map(|_| None).collect();

        Self {
            config,
            pattern_config: PatternEngineConfig::disabled(),
            stream_view: StreamViewState::new(config.pipeline.stream_view),
            stream_messages: StreamMessageStore::default(),
            stream_content_shards,
            live_api: None,
            analyzer_factories: Vec::new(),
            sinks: Vec::new(),
        }
    }

    pub fn set_pattern_config(&mut self, config: PatternEngineConfig) {
        self.pattern_config = config;
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

    pub fn attach_live_api(&mut self, live_api: LiveApiHandle) {
        self.live_api = Some(live_api);
    }

    pub fn stream_view(&self) -> &StreamViewState {
        &self.stream_view
    }

    pub fn content_slice(
        &self,
        request: &StreamSliceRequest,
    ) -> std::result::Result<StreamContentSlice, StreamSliceError> {
        let Some(entry) = self.stream_view.stream(request.stream_id) else {
            return Err(StreamSliceError::StreamNotFound {
                stream_id: request.stream_id,
            });
        };
        let shard = stream_content_shard_for_entry(entry, self.stream_content_shards.len());
        let Some(content) = self
            .stream_content_shards
            .get(shard)
            .and_then(Option::as_ref)
        else {
            return Err(StreamSliceError::ContentNotFound {
                stream_id: request.stream_id,
            });
        };

        StreamSliceReader::new(
            content,
            &self.stream_view,
            self.config.pipeline.stream_slice,
        )
        .slice(request)
    }

    pub fn into_api_parts(
        self,
    ) -> (
        StreamViewState,
        StreamMessageStore,
        Vec<Option<StreamContent>>,
        StreamSliceConfig,
    ) {
        (
            self.stream_view,
            self.stream_messages,
            self.stream_content_shards,
            self.config.pipeline.stream_slice,
        )
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
        let mut shard_coordinator = ShardCoordinator::new(
            ShardCoordinatorConfig::new(self.config.worker_count, self.config.pipeline.mode)
                .with_max_flow_owners(flow_owner_limit(self.config)),
        );
        let mut pool = WorkerPool::start(
            self.config,
            self.pattern_config.clone(),
            Arc::new(self.analyzer_factories.clone()),
        )?;
        let mut worker_stats_snapshots = vec![None; self.config.worker_count];
        if let Some(live_api) = &self.live_api {
            live_api.set_sharded_content(pool.content_slice_handle());
            live_api.publish_stats(stats);
        }
        let mut health = PipelineHealthReporter::new(self.config.pipeline.health_interval_ms);
        let mut run_error = None;

        loop {
            match source.next_batch(&mut batch).await {
                Ok(0) => {
                    if let Err(err) = pool.drain_available(&mut CoordinatorState {
                        sinks: &mut self.sinks,
                        stream_view: &mut self.stream_view,
                        stream_messages: &mut self.stream_messages,
                        stream_content_shards: &mut self.stream_content_shards,
                        worker_stats_snapshots: &mut worker_stats_snapshots,
                        live_api: self.live_api.as_ref(),
                        stats: &mut stats,
                    }) {
                        run_error = Some(err);
                        break;
                    }

                    apply_shard_metrics(&mut stats, shard_coordinator.metrics());
                    let queue = pool.queue_snapshot(shard_coordinator.metrics());
                    apply_queue_metrics(&mut stats, &queue);
                    publish_queue_snapshot(self.live_api.as_ref(), &queue);
                    match health.maybe_report(&mut stats, Some(&queue), || source.stats()) {
                        Ok(true) => publish_queue_stats(self.live_api.as_ref(), stats),
                        Ok(false) => {}
                        Err(err) => {
                            run_error = Some(err);
                            break;
                        }
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
                        let route = shard_coordinator.route_packet(&raw);

                        let packet = RoutedPacket {
                            raw,
                            owner_shard: route.shard,
                            flow_route: route.flow_route,
                        };

                        if let Err(err) = pool.send_packet(
                            route.shard,
                            packet,
                            &mut CoordinatorState {
                                sinks: &mut self.sinks,
                                stream_view: &mut self.stream_view,
                                stream_messages: &mut self.stream_messages,
                                stream_content_shards: &mut self.stream_content_shards,
                                worker_stats_snapshots: &mut worker_stats_snapshots,
                                live_api: self.live_api.as_ref(),
                                stats: &mut stats,
                            },
                        ) {
                            run_error = Some(err);
                            break;
                        }
                    }

                    if run_error.is_some() {
                        break;
                    }

                    if let Err(err) = pool.drain_available(&mut CoordinatorState {
                        sinks: &mut self.sinks,
                        stream_view: &mut self.stream_view,
                        stream_messages: &mut self.stream_messages,
                        stream_content_shards: &mut self.stream_content_shards,
                        worker_stats_snapshots: &mut worker_stats_snapshots,
                        live_api: self.live_api.as_ref(),
                        stats: &mut stats,
                    }) {
                        run_error = Some(err);
                        break;
                    }

                    apply_shard_metrics(&mut stats, shard_coordinator.metrics());
                    let queue = pool.queue_snapshot(shard_coordinator.metrics());
                    apply_queue_metrics(&mut stats, &queue);
                    publish_queue_snapshot(self.live_api.as_ref(), &queue);
                    match health.maybe_report(&mut stats, Some(&queue), || source.stats()) {
                        Ok(true) => publish_queue_stats(self.live_api.as_ref(), stats),
                        Ok(false) => {}
                        Err(err) => {
                            run_error = Some(err);
                            break;
                        }
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
        apply_shard_metrics(&mut stats, shard_coordinator.metrics());

        let shutdown_result = pool.shutdown(&mut CoordinatorState {
            sinks: &mut self.sinks,
            stream_view: &mut self.stream_view,
            stream_messages: &mut self.stream_messages,
            stream_content_shards: &mut self.stream_content_shards,
            worker_stats_snapshots: &mut worker_stats_snapshots,
            live_api: self.live_api.as_ref(),
            stats: &mut stats,
        });
        if let Some(err) = run_error {
            if let Some(live_api) = &self.live_api {
                live_api.mark_failed(stats);
            }
            if let Err(shutdown_err) = shutdown_result {
                tracing::warn!(
                    error = %shutdown_err,
                    "Failed to stop worker shards after a processing error"
                );
            }
            return Err(err);
        }

        shutdown_result?;
        apply_shard_metrics(&mut stats, shard_coordinator.metrics());
        let final_queue = final_queue_snapshot(self.config, shard_coordinator.metrics());
        apply_queue_metrics(&mut stats, &final_queue);
        publish_queue_snapshot(self.live_api.as_ref(), &final_queue);
        stats.set_stream_view_stats(self.stream_view.stats());
        stats.set_stream_message_stats(self.stream_messages.stats());
        if let Some(source_stats) = source_stats_result.transpose()?.flatten() {
            stats.set_source_stats(source_stats);
        }
        if let Some(live_api) = &self.live_api {
            let content_shards = std::mem::take(&mut self.stream_content_shards);
            live_api.set_snapshot_content(content_shards);
            live_api.mark_completed(stats);
        }
        Ok(stats)
    }
}

impl WorkerPool {
    fn start(
        config: ShardedPipelineConfig,
        pattern_config: PatternEngineConfig,
        analyzer_factories: Arc<Vec<AnalyzerFactory>>,
    ) -> Result<Self> {
        let mut workers = Vec::with_capacity(config.worker_count);
        let (output_tx, output_rx) = bounded(config.event_queue_depth);

        for id in 0..config.worker_count {
            let (sender, receiver) = bounded(config.worker_queue_depth);
            let output_tx = output_tx.clone();
            let analyzer_factories = Arc::clone(&analyzer_factories);
            let pattern_config = pattern_config.clone();
            let flow_config = flow_table_config(config);
            let join_handle = thread::Builder::new()
                .name(format!("rustmate-flow-shard-{id}"))
                .spawn(move || {
                    run_worker(
                        id,
                        config.pipeline,
                        flow_config,
                        pattern_config,
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

    fn content_slice_handle(&self) -> ShardedContentSliceHandle {
        ShardedContentSliceHandle {
            senders: Arc::new(
                self.workers
                    .iter()
                    .map(|worker| worker.sender.clone())
                    .collect(),
            ),
            timeout: Duration::from_millis(2_000),
        }
    }

    fn send_packet(
        &mut self,
        shard: usize,
        mut packet: RoutedPacket,
        coordinator: &mut CoordinatorState<'_>,
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
                    self.drain_available(coordinator)?;
                    thread::yield_now();
                }
                Err(TrySendError::Full(WorkerCommand::ContentSlice(_))) => {
                    return Err(anyhow!(
                        "worker shard {shard} send queue returned an unexpected content request"
                    ));
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

    fn drain_available(&mut self, coordinator: &mut CoordinatorState<'_>) -> Result<()> {
        loop {
            match self.output_rx.try_recv() {
                Ok(message) => write_worker_message(message, coordinator)?,
                Err(TryRecvError::Empty) => return Ok(()),
                Err(TryRecvError::Disconnected) => {
                    return Err(anyhow!("worker output channel disconnected"));
                }
            }
        }
    }

    fn queue_snapshot(&self, metrics: &ShardLoadMetrics) -> ShardedQueueSnapshot {
        metrics.queue_snapshot(
            self.workers.iter().map(|worker| ShardQueueLoad {
                shard: worker.id,
                len: worker.sender.len(),
                capacity: worker.sender.capacity().unwrap_or(0),
            }),
            self.output_rx.len(),
            self.output_rx.capacity().unwrap_or(0),
        )
    }

    fn shutdown(mut self, coordinator: &mut CoordinatorState<'_>) -> Result<()> {
        let worker_count = self.workers.len();
        let mut first_error = None;
        let mut received_stats = 0usize;

        for index in 0..worker_count {
            self.send_shutdown(index, coordinator, &mut received_stats, &mut first_error);
        }

        while received_stats < worker_count {
            match self.output_rx.recv() {
                Ok(WorkerMessage::Stats(worker_report)) => {
                    let worker_id = worker_report.stats.id;
                    replace_worker_stats_snapshot(
                        coordinator.stats,
                        coordinator.worker_stats_snapshots,
                        worker_report.stats,
                    );
                    store_worker_content(
                        coordinator.stream_content_shards,
                        worker_id,
                        worker_report.stream_content,
                    );
                    received_stats += 1;
                    tracing::debug!(worker = worker_id, "Worker shard reported final stats");
                }
                Ok(WorkerMessage::Events(events)) => {
                    if let Err(err) = write_events(events, coordinator) {
                        record_first_error(&mut first_error, err);
                    }
                }
                Ok(WorkerMessage::StatsSnapshot(worker_stats)) => {
                    replace_worker_stats_snapshot(
                        coordinator.stats,
                        coordinator.worker_stats_snapshots,
                        *worker_stats,
                    );
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

        for sink in coordinator.sinks.iter_mut() {
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

    fn send_shutdown(
        &mut self,
        worker_index: usize,
        coordinator: &mut CoordinatorState<'_>,
        received_stats: &mut usize,
        first_error: &mut Option<anyhow::Error>,
    ) {
        let Some(worker) = self.workers.get(worker_index) else {
            return;
        };
        let worker_id = worker.id;
        let sender = worker.sender.clone();

        loop {
            match sender.try_send(WorkerCommand::Shutdown) {
                Ok(()) => return,
                Err(TrySendError::Full(WorkerCommand::Shutdown)) => {
                    self.drain_shutdown_available(coordinator, received_stats, first_error);
                    thread::yield_now();
                }
                Err(TrySendError::Full(_)) => {
                    record_first_error(
                        first_error,
                        anyhow!(
                            "worker shard {worker_id} send queue returned an unexpected command"
                        ),
                    );
                    return;
                }
                Err(TrySendError::Disconnected(_)) => {
                    tracing::warn!(worker = worker_id, "Worker shard stopped before shutdown");
                    return;
                }
            }
        }
    }

    fn drain_shutdown_available(
        &mut self,
        coordinator: &mut CoordinatorState<'_>,
        received_stats: &mut usize,
        first_error: &mut Option<anyhow::Error>,
    ) {
        loop {
            match self.output_rx.try_recv() {
                Ok(WorkerMessage::Stats(worker_report)) => {
                    let worker_id = worker_report.stats.id;
                    replace_worker_stats_snapshot(
                        coordinator.stats,
                        coordinator.worker_stats_snapshots,
                        worker_report.stats,
                    );
                    store_worker_content(
                        coordinator.stream_content_shards,
                        worker_id,
                        worker_report.stream_content,
                    );
                    *received_stats = received_stats.saturating_add(1);
                    tracing::debug!(worker = worker_id, "Worker shard reported final stats");
                }
                Ok(WorkerMessage::Events(events)) => {
                    if let Err(err) = write_events(events, coordinator) {
                        record_first_error(first_error, err);
                    }
                }
                Ok(WorkerMessage::StatsSnapshot(worker_stats)) => {
                    replace_worker_stats_snapshot(
                        coordinator.stats,
                        coordinator.worker_stats_snapshots,
                        *worker_stats,
                    );
                }
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => {
                    record_first_error(
                        first_error,
                        anyhow!("worker output channel closed before final stats"),
                    );
                    return;
                }
            }
        }
    }
}

impl ShardedContentSliceHandle {
    pub fn shard_count(&self) -> usize {
        self.senders.len()
    }

    pub async fn slice(
        &self,
        shard: usize,
        request: StreamSliceRequest,
        flow_key: FlowKey,
        matches: Vec<StreamPatternMatch>,
    ) -> std::result::Result<
        std::result::Result<StreamContentSlice, StreamSliceError>,
        ShardedContentSliceError,
    > {
        let Some(sender) = self.senders.get(shard) else {
            return Err(ShardedContentSliceError::InvalidShard { shard });
        };
        let (response_tx, response_rx) = oneshot::channel();
        let command = WorkerCommand::ContentSlice(Box::new(WorkerSliceRequest {
            request,
            flow_key,
            matches,
            response_tx,
        }));

        match sender.try_send(command) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                return Err(ShardedContentSliceError::QueueFull { shard });
            }
            Err(TrySendError::Disconnected(_)) => {
                return Err(ShardedContentSliceError::Disconnected { shard });
            }
        }

        tokio::time::timeout(self.timeout, response_rx)
            .await
            .map_err(|_| ShardedContentSliceError::Timeout { shard })?
            .map_err(|_| ShardedContentSliceError::Disconnected { shard })
    }
}

fn run_worker(
    id: usize,
    config: PipelineConfig,
    flow_config: FlowTableConfig,
    pattern_config: PatternEngineConfig,
    analyzer_factories: Arc<Vec<AnalyzerFactory>>,
    receiver: Receiver<WorkerCommand>,
    output_tx: Sender<WorkerMessage>,
) -> Result<()> {
    let mut flush_state = WorkerLiveFlushState::new(config.batch_size.clamp(1, 8192));
    let mut runtime = WorkerRuntime {
        mode: config.mode,
        flow_table: FlowTable::new(flow_config),
        stream_inventory: StreamInventory::new(config.stream_inventory),
        stream_content: StreamContent::new(config.stream_content),
        stream_parser: StreamParserLayer::new(config.stream_parser),
        pattern_engine: PatternEngine::new(pattern_config),
        analyzers: analyzer_factories
            .iter()
            .map(|factory| factory())
            .collect::<Vec<_>>(),
        events: Vec::with_capacity(flush_state.event_batch_capacity),
        stats: WorkerStats {
            id,
            ..WorkerStats::default()
        },
    };

    loop {
        let command = match receiver.recv_timeout(flush_state.event_flush_interval) {
            Ok(command) => command,
            Err(RecvTimeoutError::Timeout) => {
                flush_state.flush(&output_tx, &mut runtime, true)?;
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        };

        match command {
            WorkerCommand::Packet(packet) => {
                runtime.process_packet(&packet);
            }
            WorkerCommand::ContentSlice(slice_request) => {
                let empty_view = StreamViewState::new(config.stream_view);
                let result = StreamSliceReader::new(
                    &runtime.stream_content,
                    &empty_view,
                    config.stream_slice,
                )
                .slice_with_context(
                    &slice_request.request,
                    slice_request.flow_key,
                    &slice_request.matches,
                );
                let _ = slice_request.response_tx.send(result);
            }
            WorkerCommand::Shutdown => break,
        }

        flush_state.flush(&output_tx, &mut runtime, false)?;
    }

    flush_worker_events(&output_tx, &mut runtime.events)?;
    runtime.refresh_stats();
    let report = WorkerReport {
        stats: runtime.stats,
        stream_content: runtime.stream_content,
    };
    output_tx
        .send(WorkerMessage::Stats(Box::new(report)))
        .map_err(|_| anyhow!("coordinator stopped before worker shard {id} sent stats"))?;
    Ok(())
}

impl WorkerRuntime {
    fn process_packet(&mut self, routed: &RoutedPacket) {
        let raw = &routed.raw;
        match self.mode {
            RunMode::Dump => self.events.push(Event::packet_dump(raw)),
            RunMode::Analyze => {
                let packet = DecodedPacket::from_raw(raw);
                let decode_status = packet.decode_status();
                self.stats.packet_decode.observe(decode_status);
                if decode_status.is_decode_error() {
                    return;
                }

                let flow = routed
                    .flow_route
                    .map(|route| self.flow_table.observe_with_route(&packet, route))
                    .unwrap_or_else(|| self.flow_table.observe(&packet));
                if let Some(flow) = flow.as_ref() {
                    self.stream_inventory.observe_flow(
                        &packet,
                        flow,
                        Some(routed.owner_shard),
                        &mut self.events,
                    );
                    if let Some(update) = self.stream_content.observe_flow(&packet, flow) {
                        self.pattern_engine.scan_update(
                            &packet,
                            &self.stream_content,
                            &update,
                            &mut self.events,
                        );
                    }
                    if flow.tcp.is_none()
                        && let Some(transport) = packet.transport_payload()
                    {
                        self.stream_parser.observe_datagram(
                            &packet,
                            flow,
                            transport.bytes,
                            &mut self.events,
                        );
                    }
                }
                if let Some((flow, tcp)) = flow
                    .as_ref()
                    .and_then(|flow| flow.tcp.as_ref().map(|tcp| (flow, tcp)))
                {
                    for chunk in &tcp.stream_chunks {
                        self.stream_parser
                            .observe_stream(&packet, flow, chunk, &mut self.events);
                        for analyzer in &mut self.analyzers {
                            analyzer.analyze_stream(&packet, flow, chunk, &mut self.events);
                        }
                    }
                }

                for analyzer in &mut self.analyzers {
                    analyzer.analyze(&packet, &mut self.events);
                }
            }
        }
    }

    fn refresh_stats(&mut self) {
        self.stats.flow_stats = self.flow_table.stats();
        self.stats.stream_inventory_stats = self.stream_inventory.stats();
        self.stats.stream_content_stats = self.stream_content.stats();
        self.stats.stream_parser_stats = self.stream_parser.stats();
        self.stats.pattern_stats = self.pattern_engine.stats();
    }

    fn stats_snapshot(&mut self) -> WorkerStats {
        self.refresh_stats();
        self.stats
    }
}

impl WorkerLiveFlushState {
    fn new(event_batch_capacity: usize) -> Self {
        Self {
            event_batch_capacity,
            event_flush_interval: Duration::from_millis(WORKER_LIVE_EVENT_FLUSH_MS),
            stats_flush_interval: Duration::from_millis(WORKER_LIVE_STATS_FLUSH_MS),
            last_event_flush: Instant::now(),
            last_stats_flush: Instant::now(),
        }
    }

    fn flush(
        &mut self,
        output_tx: &Sender<WorkerMessage>,
        runtime: &mut WorkerRuntime,
        force_events: bool,
    ) -> Result<()> {
        let now = Instant::now();
        if !runtime.events.is_empty()
            && (force_events
                || runtime.events.len() >= self.event_batch_capacity
                || now.duration_since(self.last_event_flush) >= self.event_flush_interval)
        {
            flush_worker_events(output_tx, &mut runtime.events)?;
            self.last_event_flush = now;
        }

        if now.duration_since(self.last_stats_flush) >= self.stats_flush_interval {
            try_flush_worker_stats(output_tx, runtime)?;
            self.last_stats_flush = now;
        }

        Ok(())
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

fn try_flush_worker_stats(
    output_tx: &Sender<WorkerMessage>,
    runtime: &mut WorkerRuntime,
) -> Result<()> {
    let snapshot = runtime.stats_snapshot();
    let worker_id = snapshot.id;
    match output_tx.try_send(WorkerMessage::StatsSnapshot(Box::new(snapshot))) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_)) => Ok(()),
        Err(TrySendError::Disconnected(_)) => Err(anyhow!(
            "coordinator stopped before receiving worker shard {} stats snapshot",
            worker_id
        )),
    }
}

fn write_worker_message(
    message: WorkerMessage,
    coordinator: &mut CoordinatorState<'_>,
) -> Result<()> {
    match message {
        WorkerMessage::Events(events) => write_events(events, coordinator),
        WorkerMessage::StatsSnapshot(worker_stats) => {
            replace_worker_stats_snapshot(
                coordinator.stats,
                coordinator.worker_stats_snapshots,
                *worker_stats,
            );
            Ok(())
        }
        WorkerMessage::Stats(worker_report) => {
            let worker_id = worker_report.stats.id;
            replace_worker_stats_snapshot(
                coordinator.stats,
                coordinator.worker_stats_snapshots,
                worker_report.stats,
            );
            store_worker_content(
                coordinator.stream_content_shards,
                worker_id,
                worker_report.stream_content,
            );
            Ok(())
        }
    }
}

fn replace_worker_stats_snapshot(
    stats: &mut PipelineStats,
    snapshots: &mut [Option<WorkerStats>],
    worker_stats: WorkerStats,
) {
    let worker_id = worker_stats.id;
    let Some(slot) = snapshots.get_mut(worker_id) else {
        tracing::warn!(
            worker = worker_id,
            "Worker stats snapshot index is out of range"
        );
        return;
    };

    *slot = Some(worker_stats);
    rebuild_worker_stats_from_snapshots(stats, snapshots);
}

fn rebuild_worker_stats_from_snapshots(
    stats: &mut PipelineStats,
    snapshots: &[Option<WorkerStats>],
) {
    stats.clear_worker_runtime_stats();
    for worker_stats in snapshots.iter().flatten() {
        add_worker_stats(stats, worker_stats);
    }
}

fn add_worker_stats(stats: &mut PipelineStats, worker_stats: &WorkerStats) {
    stats.add_packet_decode_counters(worker_stats.packet_decode);
    stats.add_flow_table_stats(worker_stats.flow_stats);
    stats.add_stream_inventory_stats(worker_stats.stream_inventory_stats);
    stats.add_stream_content_stats(worker_stats.stream_content_stats);
    stats.add_stream_parser_stats(worker_stats.stream_parser_stats);
    stats.add_pattern_stats(worker_stats.pattern_stats);
}

fn store_worker_content(
    stream_content_shards: &mut [Option<StreamContent>],
    worker_id: usize,
    stream_content: StreamContent,
) {
    if let Some(slot) = stream_content_shards.get_mut(worker_id) {
        *slot = Some(stream_content);
    } else {
        tracing::warn!(
            worker = worker_id,
            "Worker content shard index is out of range"
        );
    }
}

fn apply_shard_metrics(stats: &mut PipelineStats, metrics: &ShardLoadMetrics) {
    let snapshot = metrics.snapshot();
    stats.fallback_routed_packets = snapshot.fallback_packets;
    stats.fallback_unsupported_link_packets = snapshot.fallback_unsupported_link_packets;
    stats.fallback_non_ip_packets = snapshot.fallback_non_ip_packets;
    stats.fallback_malformed_packets = snapshot.fallback_malformed_packets;
    stats.fallback_fragmented_packets = snapshot.fallback_fragmented_packets;
    stats.fallback_unsupported_transport_packets = snapshot.fallback_unsupported_transport_packets;
    stats.busiest_shard = snapshot.busiest_shard;
    stats.busiest_shard_packets = snapshot.busiest_shard_packets;
    stats.busiest_shard_bytes = snapshot.busiest_shard_bytes;
    stats.shard_packet_skew_ratio_milli = snapshot.packet_skew_ratio_milli;
    stats.shard_byte_skew_ratio_milli = snapshot.byte_skew_ratio_milli;
}

fn apply_queue_metrics(stats: &mut PipelineStats, queue: &ShardedQueueSnapshot) {
    let summary = queue.summarize();
    stats.output_queue_len = summary.output_queue_len;
    stats.output_queue_capacity = summary.output_queue_capacity;
    stats.worker_queue_max_len = summary.max_worker_queue_len;
    stats.worker_queue_max_capacity = summary.max_worker_queue_capacity;
    stats.busiest_worker = summary.busiest_worker;
    stats.busiest_worker_packets = summary.busiest_worker_packets;
    stats.busiest_worker_bytes = summary.busiest_worker_bytes;
    stats.worker_fallback_routed_packets = summary.fallback_routed_packets;
    stats.worker_fallback_unsupported_link_packets = summary.fallback_unsupported_link_packets;
    stats.worker_fallback_non_ip_packets = summary.fallback_non_ip_packets;
    stats.worker_fallback_malformed_packets = summary.fallback_malformed_packets;
    stats.worker_fallback_fragmented_packets = summary.fallback_fragmented_packets;
    stats.worker_fallback_unsupported_transport_packets =
        summary.fallback_unsupported_transport_packets;
    stats.worker_packet_skew_ratio_milli = summary.worker_packet_skew_ratio_milli;
    stats.worker_byte_skew_ratio_milli = summary.worker_byte_skew_ratio_milli;
}

fn publish_queue_snapshot(live_api: Option<&LiveApiHandle>, queue: &ShardedQueueSnapshot) {
    if let Some(live_api) = live_api {
        live_api.publish_queue(queue.clone());
    }
}

fn publish_queue_stats(live_api: Option<&LiveApiHandle>, stats: PipelineStats) {
    if let Some(live_api) = live_api {
        live_api.publish_stats(stats);
    }
}

fn stream_content_shard_for_entry(entry: &StreamViewEntry, content_shards: usize) -> usize {
    if content_shards <= 1 {
        return 0;
    }

    entry
        .content_shard
        .filter(|shard| *shard < content_shards)
        .unwrap_or_else(|| shard_for_flow_key(&entry.flow_key(), content_shards))
}

fn final_queue_snapshot(
    config: ShardedPipelineConfig,
    metrics: &ShardLoadMetrics,
) -> ShardedQueueSnapshot {
    metrics.queue_snapshot(
        (0..config.worker_count).map(|shard| ShardQueueLoad {
            shard,
            len: 0,
            capacity: config.worker_queue_depth,
        }),
        0,
        config.event_queue_depth,
    )
}

fn write_events(events: Vec<Event>, coordinator: &mut CoordinatorState<'_>) -> Result<()> {
    coordinator.stats.events = coordinator.stats.events.saturating_add(events.len() as u64);
    coordinator.stream_view.observe_events(&events);
    coordinator.stream_messages.observe_events(&events);
    coordinator
        .stats
        .set_stream_view_stats(coordinator.stream_view.stats());
    coordinator
        .stats
        .set_stream_message_stats(coordinator.stream_messages.stats());
    if let Some(live_api) = coordinator.live_api {
        live_api.publish_events(&events, *coordinator.stats);
    }
    for sink in coordinator.sinks.iter_mut() {
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

fn flow_table_config(config: ShardedPipelineConfig) -> FlowTableConfig {
    FlowTableConfig::new(
        max_flows_per_worker(config.pipeline.max_flows, config.worker_count),
        config.pipeline.flow_idle_timeout_ms,
        config.pipeline.max_tcp_buffered_bytes_per_flow,
        config.pipeline.max_tcp_out_of_order_segments_per_direction,
    )
}

fn flow_owner_limit(config: ShardedPipelineConfig) -> usize {
    let worker_count = config.worker_count.max(1);
    [
        config.pipeline.max_flows,
        config
            .pipeline
            .stream_inventory
            .max_streams
            .saturating_mul(worker_count),
        config
            .pipeline
            .stream_content
            .max_streams
            .saturating_mul(worker_count),
        config.pipeline.stream_view.max_streams,
        worker_count,
    ]
    .into_iter()
    .max()
    .unwrap_or(1)
    .max(1)
}

fn max_flows_per_worker(max_flows: usize, worker_count: usize) -> usize {
    max_flows.max(1).div_ceil(worker_count.max(1))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        net::Ipv4Addr,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
    };

    use etherparse::PacketBuilder;
    use pcap::Linktype;

    use crate::{
        analyzers::http::HttpAnalyzer,
        config::RunMode,
        flow::FlowDirection,
        ingest::{PacketBatch, PacketSource},
        output::EventSink,
        packet::{LinkLayer, PacketTimestamp},
        pattern::{PatternDefinition, PatternEngineConfig},
        shard::{flow_route_from_raw, route_packet},
        stream_content::StreamContentConfig,
        stream_inventory::StreamInventoryConfig,
        stream_parser::StreamParserConfig,
        stream_slice::{
            StreamSliceConfig, StreamSliceCopyFormat, StreamSliceMode, StreamSliceRequest,
        },
        stream_view::{StreamViewConfig, StreamViewQuery},
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
        assert_eq!(43, stats.content_observed_bytes);
        assert_eq!(43, stats.content_stored_bytes);
        assert_eq!(1, stats.content_active_streams);
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

    #[tokio::test]
    async fn emits_pattern_match_on_flow_shard() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut pipeline = test_pipeline(4);
        pipeline.set_pattern_config(
            PatternEngineConfig::compile(
                vec![PatternDefinition::substring("substring:0", "flag")],
                1024,
                1024,
                4096,
            )
            .unwrap(),
        );
        pipeline.register_sink(Box::new(CollectSink {
            events: Arc::clone(&events),
        }));

        let source = VecPacketSource::new(vec![
            tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 100, b"fl", 1),
            tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 102, b"ag", 2),
        ]);

        let stats = pipeline.run_with_source(source).await.unwrap();

        let events = events.lock().unwrap();
        let pattern = events
            .iter()
            .find(|event| event["event_type"] == "pattern_match")
            .unwrap();
        assert_eq!(1, stats.pattern_matches);
        assert_eq!(1, stats.pattern_matched_streams);
        assert_eq!(1, stats.view_tracked_streams);
        assert_eq!(1, stats.view_matched_streams);
        assert_eq!(1, stats.view_stored_matches);
        assert_eq!("substring", pattern["fields"]["pattern_type"]);
        assert_eq!("flag", pattern["fields"]["match_text"]);
        assert_eq!(0, pattern["fields"]["logical_start"]);
        assert_eq!(4, pattern["fields"]["logical_end"]);
    }

    #[tokio::test]
    async fn reads_content_slice_from_owner_shard() {
        let mut pipeline = test_pipeline(4);
        pipeline.set_pattern_config(
            PatternEngineConfig::compile(
                vec![PatternDefinition::substring("substring:0", "flag")],
                1024,
                1024,
                4096,
            )
            .unwrap(),
        );

        let source = VecPacketSource::new(vec![
            tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 100, b"fl", 1),
            tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 102, b"ag", 2),
        ]);

        let stats = pipeline.run_with_source(source).await.unwrap();
        let rows = pipeline.stream_view().query(&StreamViewQuery {
            only_matched: true,
            ..StreamViewQuery::default()
        });
        let stream_id = rows.rows.first().unwrap().stream_id;
        let content_shard = rows.rows.first().unwrap().content_shard;
        let slice = pipeline
            .content_slice(&StreamSliceRequest {
                stream_id,
                direction: FlowDirection::AToB,
                logical_start: 0,
                max_bytes: 16,
                mode: StreamSliceMode::Text,
            })
            .unwrap();

        assert_eq!(1, stats.pattern_matches);
        assert!(content_shard.is_some());
        assert_eq!("flag", slice.copy_as(StreamSliceCopyFormat::Text));
        assert_eq!(1, slice.highlights.len());
        assert_eq!(0, slice.highlights[0].logical_start);
        assert_eq!(4, slice.highlights[0].logical_end);
    }

    #[test]
    fn routes_both_directions_of_flow_to_same_shard() {
        let forward = tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 1, b"x", 1);
        let reverse = tcp_packet([10, 0, 0, 2], 80, [10, 0, 0, 1], 1111, 1, b"y", 2);

        let forward_route = route_packet(&forward, RunMode::Analyze, 0, 8);
        let reverse_route = route_packet(&reverse, RunMode::Analyze, 1, 8);

        assert!(!forward_route.is_fallback());
        assert!(!reverse_route.is_fallback());
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

    #[test]
    fn flow_owner_limit_covers_worker_local_state_caps() {
        let config = ShardedPipelineConfig {
            pipeline: PipelineConfig {
                mode: RunMode::Analyze,
                batch_size: 2,
                health_interval_ms: 0,
                max_flows: 10,
                flow_idle_timeout_ms: 120_000,
                max_tcp_buffered_bytes_per_flow: 64 * 1024,
                max_tcp_out_of_order_segments_per_direction: 16,
                stream_inventory: StreamInventoryConfig {
                    max_streams: 100,
                    ..test_stream_inventory_config()
                },
                stream_content: StreamContentConfig {
                    max_streams: 200,
                    ..test_stream_content_config()
                },
                stream_parser: StreamParserConfig::disabled(),
                stream_view: StreamViewConfig {
                    max_streams: 50,
                    ..test_stream_view_config()
                },
                stream_slice: test_stream_slice_config(),
            },
            worker_count: 4,
            worker_queue_depth: 8,
            event_queue_depth: 8,
        };

        assert_eq!(800, flow_owner_limit(config));
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
        assert_eq!(1, stats.fallback_unsupported_link_packets);
        assert_eq!(0, stats.fallback_malformed_packets);
        assert_eq!(1, stats.decode_errors);
        assert_eq!(1, stats.packet_decode.packet_unsupported_link_packets);
        assert_eq!(0, stats.packet_decode.packet_malformed_packets);
        assert_eq!(Some(0), stats.busiest_shard);
        assert_eq!(1, stats.busiest_shard_packets);
        assert_eq!(22, stats.busiest_shard_bytes);
        assert_eq!(4000, stats.shard_packet_skew_ratio_milli);
        assert_eq!(4000, stats.shard_byte_skew_ratio_milli);
        assert_eq!(Some(0), stats.busiest_worker);
        assert_eq!(1, stats.busiest_worker_packets);
        assert_eq!(22, stats.busiest_worker_bytes);
        assert_eq!(1, stats.worker_fallback_routed_packets);
        assert_eq!(1, stats.worker_fallback_unsupported_link_packets);
        assert_eq!(0, stats.worker_fallback_malformed_packets);
        assert_eq!(4000, stats.worker_packet_skew_ratio_milli);
        assert_eq!(4000, stats.worker_byte_skew_ratio_milli);
        assert_eq!(0, stats.worker_queue_max_len);
        assert_eq!(8, stats.worker_queue_max_capacity);
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
    async fn flushes_small_live_event_batches_before_source_finishes() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let finish = Arc::new(AtomicBool::new(false));
        let mut pipeline = ShardedPipeline::new(ShardedPipelineConfig {
            pipeline: PipelineConfig {
                mode: RunMode::Analyze,
                batch_size: 4096,
                health_interval_ms: 0,
                max_flows: 1024,
                flow_idle_timeout_ms: 120_000,
                max_tcp_buffered_bytes_per_flow: 64 * 1024,
                max_tcp_out_of_order_segments_per_direction: 16,
                stream_inventory: test_stream_inventory_config(),
                stream_content: test_stream_content_config(),
                stream_parser: StreamParserConfig::disabled(),
                stream_view: test_stream_view_config(),
                stream_slice: test_stream_slice_config(),
            },
            worker_count: 2,
            worker_queue_depth: 8,
            event_queue_depth: 8,
        });
        pipeline.register_sink(Box::new(CollectSink {
            events: Arc::clone(&events),
        }));

        let source = HoldOpenAfterPacketsSource::new(
            vec![tcp_packet(
                [10, 0, 0, 1],
                1111,
                [10, 0, 0, 2],
                80,
                1,
                b"GET /live-flush HTTP/1.1\r\nHost: live.local\r\n\r\n",
                1,
            )],
            Arc::clone(&finish),
        );
        let run = tokio::spawn(async move { pipeline.run_with_source(source).await });

        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            if !events.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
        }

        assert_eq!(1, events.lock().unwrap().len());
        finish.store(true, Ordering::Relaxed);
        let stats = tokio::time::timeout(tokio::time::Duration::from_secs(2), run)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(1, stats.packets);
        assert_eq!(1, stats.events);
        assert_eq!(1, stats.packet_decode.packet_parsed_packets);
        assert_eq!(1, stats.view_tracked_streams);
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
                stream_content: test_stream_content_config(),
                stream_parser: StreamParserConfig::disabled(),
                stream_view: test_stream_view_config(),
                stream_slice: test_stream_slice_config(),
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

    struct HoldOpenAfterPacketsSource {
        packets: VecDeque<RawPacket>,
        finish: Arc<AtomicBool>,
    }

    impl IdleThenPacketSource {
        fn new(packets: Vec<RawPacket>) -> Self {
            Self {
                packets: VecDeque::from(packets),
                yielded_idle: false,
            }
        }
    }

    impl HoldOpenAfterPacketsSource {
        fn new(packets: Vec<RawPacket>, finish: Arc<AtomicBool>) -> Self {
            Self {
                packets: VecDeque::from(packets),
                finish,
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
    impl PacketSource for HoldOpenAfterPacketsSource {
        async fn next_batch(&mut self, batch: &mut PacketBatch) -> anyhow::Result<usize> {
            batch.clear();
            while batch.len() < batch.capacity() {
                let Some(packet) = self.packets.pop_front() else {
                    break;
                };
                batch.push(packet);
            }
            if batch.is_empty() {
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
            Ok(batch.len())
        }

        fn is_finished(&self) -> bool {
            self.packets.is_empty() && self.finish.load(Ordering::Relaxed)
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
                stream_content: test_stream_content_config(),
                stream_parser: StreamParserConfig::disabled(),
                stream_view: test_stream_view_config(),
                stream_slice: test_stream_slice_config(),
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

    fn test_stream_content_config() -> StreamContentConfig {
        StreamContentConfig {
            enabled: true,
            max_streams: 1024,
            idle_timeout_ms: 120_000,
            max_total_bytes: 1024 * 1024,
            max_bytes_per_stream: 64 * 1024,
            max_segment_bytes: 64 * 1024,
        }
    }

    fn test_stream_view_config() -> StreamViewConfig {
        StreamViewConfig {
            enabled: true,
            max_streams: 1024,
            max_matches_per_stream: 256,
            max_query_limit: 512,
        }
    }

    fn test_stream_slice_config() -> StreamSliceConfig {
        StreamSliceConfig {
            max_slice_bytes: 64 * 1024,
            max_highlights: 4096,
            hex_row_bytes: 16,
            max_transform_bytes: 1024 * 1024,
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
