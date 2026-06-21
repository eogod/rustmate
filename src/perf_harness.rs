use std::{
    collections::{BTreeMap, HashSet},
    hint::black_box,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use etherparse::PacketBuilder;
use pcap::Linktype;
use serde::{Deserialize, Serialize};

use crate::{
    analyzers::{dns::DnsAnalyzer, http::HttpAnalyzer, tls_meta::TlsMetaAnalyzer},
    config::RunMode,
    event::Event,
    flow::FlowKey,
    ingest::{PacketBatch, PacketSource},
    output::EventSink,
    packet::{LinkLayer, PacketTimestamp, RawPacket, TransportProtocol},
    pipeline::{Pipeline, PipelineConfig, PipelineStats},
    shard::{ShardCoordinator, ShardCoordinatorConfig, flow_route_from_raw},
    sharded_pipeline::{ShardedPipeline, ShardedPipelineConfig, resolve_worker_count},
    stream_content::StreamContentConfig,
    stream_inventory::StreamInventoryConfig,
    stream_parser::StreamParserConfig,
    stream_slice::StreamSliceConfig,
    stream_view::StreamViewConfig,
};

const DEFAULT_MAX_FLOWS: usize = 1_048_576;
const DEFAULT_FLOW_IDLE_TIMEOUT_MS: u64 = 120_000;
const DEFAULT_TCP_BUFFERED_BYTES_PER_FLOW: usize = 1 << 20;
const DEFAULT_TCP_OUT_OF_ORDER_SEGMENTS: usize = 128;
const DEFAULT_MAX_STREAM_CONTENT_BYTES: usize = 512 * 1024 * 1024;
const DEFAULT_MAX_STREAM_CONTENT_BYTES_PER_STREAM: usize = 8 * 1024 * 1024;
const WORKER_SELECTION_SCORE_BAND: f64 = 0.05;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PerfFixtureKind {
    HttpRequests,
    OutOfOrderHttp,
    HttpKeepAlive,
    MixedServices,
    UdpElephant,
    TcpElephant,
}

impl PerfFixtureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HttpRequests => "http_requests",
            Self::OutOfOrderHttp => "out_of_order_http",
            Self::HttpKeepAlive => "http_keep_alive",
            Self::MixedServices => "mixed_services",
            Self::UdpElephant => "udp_elephant",
            Self::TcpElephant => "tcp_elephant",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PerfInput {
    pub name: String,
    pub source: PerfInputSource,
    pub flows: Option<usize>,
    pub messages_per_flow: Option<usize>,
    packets: Arc<[RawPacket]>,
    packet_count: usize,
    byte_count: u64,
}

impl PerfInput {
    pub fn synthetic(fixture: PerfFixtureKind, flows: usize, messages_per_flow: usize) -> Self {
        let flows = flows.max(1);
        let messages_per_flow = messages_per_flow.max(1);
        let packets = generate_fixture(fixture, flows, messages_per_flow);
        Self::from_packets(
            fixture.as_str().to_owned(),
            PerfInputSource::Synthetic { fixture },
            Some(flows),
            Some(messages_per_flow),
            packets,
        )
    }

    pub fn from_pcap(name: impl Into<String>, packets: Vec<RawPacket>) -> Self {
        Self::from_packets(name.into(), PerfInputSource::Pcap, None, None, packets)
    }

    pub fn from_packets(
        name: String,
        source: PerfInputSource,
        flows: Option<usize>,
        messages_per_flow: Option<usize>,
        packets: Vec<RawPacket>,
    ) -> Self {
        let packet_count = packets.len();
        let byte_count = packets.iter().map(|packet| packet.data.len() as u64).sum();
        Self {
            name,
            source,
            flows,
            messages_per_flow,
            packets: Arc::from(packets.into_boxed_slice()),
            packet_count,
            byte_count,
        }
    }

    pub fn packet_count(&self) -> usize {
        self.packet_count
    }

    pub fn byte_count(&self) -> u64 {
        self.byte_count
    }

    pub fn diagnostics(&self, worker_count: usize) -> PerfRunDiagnostics {
        let shard_count = worker_count.max(1);
        let mut coordinator =
            ShardCoordinator::new(ShardCoordinatorConfig::new(shard_count, RunMode::Analyze));
        let mut shards = (0..shard_count)
            .map(|shard| ShardAccumulator {
                shard,
                packets: 0,
                bytes: 0,
                flows: HashSet::new(),
            })
            .collect::<Vec<_>>();
        let mut routed_packets = 0u64;
        let mut fallback_packets = 0u64;
        let mut all_flows = HashSet::new();
        let mut tcp_routed_packets = 0u64;
        let mut tcp_routed_bytes = 0u64;
        let mut tcp_flows = HashSet::new();

        for packet in self.packets.iter() {
            let route = coordinator.route_packet(packet);
            let shard = route.shard;
            let flow_route = route.flow_route.or_else(|| {
                (shard_count == 1)
                    .then(|| flow_route_from_raw(packet))
                    .flatten()
            });
            if let Some(flow_route) = flow_route {
                routed_packets = routed_packets.saturating_add(1);
                all_flows.insert(flow_route.key);
                if flow_route.key.protocol == TransportProtocol::Tcp {
                    tcp_routed_packets = tcp_routed_packets.saturating_add(1);
                    tcp_routed_bytes = tcp_routed_bytes.saturating_add(packet.data.len() as u64);
                    tcp_flows.insert(flow_route.key);
                }
                if let Some(accumulator) = shards.get_mut(shard) {
                    accumulator.flows.insert(flow_route.key);
                }
            } else if route.is_fallback() {
                fallback_packets = fallback_packets.saturating_add(1);
            }

            if let Some(accumulator) = shards.get_mut(shard) {
                accumulator.packets = accumulator.packets.saturating_add(1);
                accumulator.bytes = accumulator.bytes.saturating_add(packet.data.len() as u64);
            }
        }

        let shards = shards
            .into_iter()
            .map(|shard| PerfShardLoad {
                shard: shard.shard,
                packets: shard.packets,
                bytes: shard.bytes,
                unique_flows: shard.flows.len(),
            })
            .collect::<Vec<_>>();

        let route_snapshot = coordinator.metrics().snapshot();

        PerfRunDiagnostics {
            shard_count,
            routed_packets,
            fallback_packets,
            striped_flow_packets: route_snapshot.striped_flow_packets,
            fallback_unsupported_link_packets: route_snapshot.fallback_unsupported_link_packets,
            fallback_non_ip_packets: route_snapshot.fallback_non_ip_packets,
            fallback_malformed_packets: route_snapshot.fallback_malformed_packets,
            fallback_fragmented_packets: route_snapshot.fallback_fragmented_packets,
            fallback_unsupported_transport_packets: route_snapshot
                .fallback_unsupported_transport_packets,
            unique_flows: all_flows.len(),
            tcp_routed_packets,
            tcp_routed_bytes,
            tcp_unique_flows: tcp_flows.len(),
            packet_skew: skew(shards.iter().map(|shard| shard.packets)),
            byte_skew: skew(shards.iter().map(|shard| shard.bytes)),
            flow_skew: skew(shards.iter().map(|shard| shard.unique_flows as u64)),
            shards,
        }
    }

    pub fn plan_workers(&self, config: PerfWorkerPlannerConfig) -> PerfWorkerPlan {
        const PLANNER_VERSION: u32 = 3;
        let available_workers = resolve_worker_count(0);
        let max_workers = if config.max_workers == 0 {
            available_workers
        } else {
            config.max_workers.min(available_workers).max(1)
        };
        let candidate_counts = worker_candidates(max_workers);
        let mut candidates = Vec::with_capacity(candidate_counts.len());

        for workers in candidate_counts {
            let diagnostics = self.diagnostics(workers);
            candidates.push(evaluate_worker_candidate(
                workers,
                self.packet_count,
                self.byte_count,
                diagnostics,
                config,
            ));
        }

        let selected = select_worker_candidate(&candidates, config);
        let selected_workers = selected.map_or(1, |candidate| candidate.workers);
        let selected_score = selected.map_or(0.0, |candidate| candidate.score);
        let reason = selected
            .map(|candidate| candidate.reason.clone())
            .unwrap_or_else(|| "fallback to one worker".to_owned());
        let decision_notes = worker_plan_decision_notes(selected, &candidates);

        PerfWorkerPlan {
            planner_version: PLANNER_VERSION,
            selected_workers,
            available_workers,
            max_workers,
            selected_score,
            reason,
            decision_notes,
            candidates,
        }
    }
}

struct ShardAccumulator {
    shard: usize,
    packets: u64,
    bytes: u64,
    flows: HashSet<FlowKey>,
}

fn worker_candidates(max_workers: usize) -> Vec<usize> {
    let mut candidates = Vec::new();
    let mut workers = 1usize;
    while workers < max_workers {
        candidates.push(workers);
        workers = workers.saturating_mul(2);
    }
    candidates.push(max_workers.max(1));
    candidates.sort_unstable();
    candidates.dedup();
    candidates
}

fn evaluate_worker_candidate(
    workers: usize,
    packet_count: usize,
    byte_count: u64,
    diagnostics: PerfRunDiagnostics,
    config: PerfWorkerPlannerConfig,
) -> PerfWorkerCandidate {
    let packets_per_worker = average_per_worker_usize(packet_count, workers);
    let bytes_per_worker = average_per_worker_u64(byte_count, workers);
    let flows_per_worker = average_per_worker_usize(diagnostics.unique_flows, workers);
    let fallback_ratio = ratio(diagnostics.fallback_packets, packet_count as u64);
    let is_power_of_two = workers.is_power_of_two();
    let elephant_striping_active = diagnostics.striped_flow_packets != 0;
    let tcp_offload_active = workers > 1 && tcp_offload_candidate(&diagnostics, config);
    let tcp_offload_lanes = if tcp_offload_active {
        tcp_offload_lanes(workers, &diagnostics)
    } else {
        0
    };
    let mut rejections = Vec::new();
    let mut warnings = Vec::new();

    if workers == 1 {
        warnings.push("single worker baseline; no shard parallelism".to_owned());
    } else {
        if packets_per_worker < config.min_packets_per_worker {
            warnings.push(format!(
                "below minimum packet target: {packets_per_worker} < {}",
                config.min_packets_per_worker
            ));
        }
        if flows_per_worker < config.min_flows_per_worker
            && !elephant_striping_active
            && !tcp_offload_active
        {
            rejections.push(format!(
                "too few routed flows per worker: {flows_per_worker} < {}",
                config.min_flows_per_worker
            ));
        } else if flows_per_worker < config.min_flows_per_worker && elephant_striping_active {
            warnings.push(format!(
                "low routed-flow budget accepted because elephant striping is active: {flows_per_worker} < {}",
                config.min_flows_per_worker
            ));
        } else if flows_per_worker < config.min_flows_per_worker {
            warnings.push(format!(
                "low routed-flow budget accepted because TCP stream offload is active: {flows_per_worker} < {}",
                config.min_flows_per_worker
            ));
        }
        if diagnostics.packet_skew.max_over_average > config.max_packet_skew {
            if tcp_offload_active {
                warnings.push(format!(
                    "packet skew accepted because TCP stream offload is active: {:.2}x > {:.2}x",
                    diagnostics.packet_skew.max_over_average, config.max_packet_skew
                ));
            } else {
                rejections.push(format!(
                    "packet skew too high: {:.2}x > {:.2}x",
                    diagnostics.packet_skew.max_over_average, config.max_packet_skew
                ));
            }
        }
        if diagnostics.byte_skew.max_over_average > config.max_byte_skew {
            if tcp_offload_active {
                warnings.push(format!(
                    "byte skew accepted because TCP stream offload is active: {:.2}x > {:.2}x",
                    diagnostics.byte_skew.max_over_average, config.max_byte_skew
                ));
            } else {
                rejections.push(format!(
                    "byte skew too high: {:.2}x > {:.2}x",
                    diagnostics.byte_skew.max_over_average, config.max_byte_skew
                ));
            }
        }
        if diagnostics.flow_skew.max_over_average > config.max_flow_skew {
            if tcp_offload_active {
                warnings.push(format!(
                    "flow skew accepted because TCP stream offload is active: {:.2}x > {:.2}x",
                    diagnostics.flow_skew.max_over_average, config.max_flow_skew
                ));
            } else {
                rejections.push(format!(
                    "flow skew too high: {:.2}x > {:.2}x",
                    diagnostics.flow_skew.max_over_average, config.max_flow_skew
                ));
            }
        }
        if fallback_ratio > config.max_fallback_ratio {
            rejections.push(format!(
                "fallback route ratio too high: {:.2}% > {:.2}%",
                fallback_ratio * 100.0,
                config.max_fallback_ratio * 100.0
            ));
        }
        if packets_per_worker >= config.min_packets_per_worker
            && packets_per_worker < config.preferred_packets_per_worker
        {
            warnings.push(format!(
                "below preferred packet budget: {packets_per_worker} < {}",
                config.preferred_packets_per_worker
            ));
        }
        if config.preferred_bytes_per_worker != 0
            && bytes_per_worker < config.preferred_bytes_per_worker
        {
            warnings.push(format!(
                "below preferred byte budget: {bytes_per_worker} < {}",
                config.preferred_bytes_per_worker
            ));
        }
        if config.prefer_power_of_two && !is_power_of_two {
            warnings.push("non power-of-two worker count uses slower modulo routing".to_owned());
        }
        if fallback_ratio > 0.05 {
            warnings.push(format!(
                "fallback routing is {:.2}% of packets",
                fallback_ratio * 100.0
            ));
        }
        if tcp_offload_active {
            warnings.push(format!(
                "TCP stream offload candidate: {} TCP packets, {} bytes, {} lanes",
                diagnostics.tcp_routed_packets, diagnostics.tcp_routed_bytes, tcp_offload_lanes
            ));
        }
    }

    let eligible = rejections.is_empty();
    let score = if eligible && workers == 1 {
        0.50
    } else if eligible {
        worker_candidate_score(WorkerScoreInput {
            workers,
            packets_per_worker,
            bytes_per_worker,
            fallback_ratio,
            is_power_of_two,
            diagnostics: &diagnostics,
            config,
            tcp_offload_active,
            tcp_offload_lanes,
        })
    } else {
        0.0
    };
    let reason = if eligible {
        format!(
            "score {:.2}: {packets_per_worker} packets/worker, {bytes_per_worker} bytes/worker, {flows_per_worker} flows/worker, packet skew {:.2}x, byte skew {:.2}x, flow skew {:.2}x{}{}",
            score,
            diagnostics.packet_skew.max_over_average,
            diagnostics.byte_skew.max_over_average,
            diagnostics.flow_skew.max_over_average,
            tcp_offload_reason_suffix(tcp_offload_active, tcp_offload_lanes),
            warning_suffix(&warnings)
        )
    } else {
        rejections.join("; ")
    };

    PerfWorkerCandidate {
        workers,
        eligible,
        score,
        reason,
        packets_per_worker,
        bytes_per_worker,
        flows_per_worker,
        fallback_ratio,
        is_power_of_two,
        tcp_offload_active,
        tcp_offload_lanes,
        warnings,
        rejections,
        diagnostics,
    }
}

fn select_worker_candidate(
    candidates: &[PerfWorkerCandidate],
    config: PerfWorkerPlannerConfig,
) -> Option<&PerfWorkerCandidate> {
    let best_score = candidates
        .iter()
        .filter(|candidate| candidate.eligible)
        .map(|candidate| candidate.score)
        .max_by(f64::total_cmp)?;
    let score_floor = best_score * (1.0 - WORKER_SELECTION_SCORE_BAND);
    let in_selection_band =
        |candidate: &&PerfWorkerCandidate| candidate.eligible && candidate.score >= score_floor;

    if config.prefer_power_of_two
        && let Some(candidate) = candidates
            .iter()
            .filter(in_selection_band)
            .filter(|candidate| candidate.is_power_of_two)
            .max_by_key(|candidate| candidate.workers)
    {
        return Some(candidate);
    }

    candidates
        .iter()
        .filter(in_selection_band)
        .max_by_key(|candidate| candidate.workers)
}

fn worker_plan_decision_notes(
    selected: Option<&PerfWorkerCandidate>,
    candidates: &[PerfWorkerCandidate],
) -> Vec<String> {
    let Some(selected) = selected else {
        return vec!["no eligible worker candidate; falling back to one worker".to_owned()];
    };

    let mut notes = vec![format!(
        "selected {} workers at score {:.2}",
        selected.workers, selected.score
    )];

    if let Some(best_score) = candidates
        .iter()
        .filter(|candidate| candidate.eligible)
        .map(|candidate| candidate.score)
        .max_by(f64::total_cmp)
    {
        notes.push(format!(
            "selection band floor {:.2} from best score {:.2}",
            best_score * (1.0 - WORKER_SELECTION_SCORE_BAND),
            best_score
        ));
    }

    if let Some(larger) = candidates
        .iter()
        .find(|candidate| candidate.workers > selected.workers)
    {
        if larger.eligible {
            notes.push(format!(
                "{} workers stayed out: score {:.2} vs selected {:.2}",
                larger.workers, larger.score, selected.score
            ));
        } else {
            notes.push(format!(
                "{} workers skipped: {}",
                larger.workers,
                larger.rejections.join("; ")
            ));
        }
    }

    if selected.warnings.is_empty() {
        notes.push("selected candidate has no planner warnings".to_owned());
    } else {
        notes.push(format!(
            "selected warnings: {}",
            selected.warnings.join("; ")
        ));
    }

    notes
}

struct WorkerScoreInput<'a> {
    workers: usize,
    packets_per_worker: usize,
    bytes_per_worker: u64,
    fallback_ratio: f64,
    is_power_of_two: bool,
    diagnostics: &'a PerfRunDiagnostics,
    config: PerfWorkerPlannerConfig,
    tcp_offload_active: bool,
    tcp_offload_lanes: usize,
}

fn worker_candidate_score(input: WorkerScoreInput<'_>) -> f64 {
    let WorkerScoreInput {
        workers,
        packets_per_worker,
        bytes_per_worker,
        fallback_ratio,
        is_power_of_two,
        diagnostics,
        config,
        tcp_offload_active,
        tcp_offload_lanes,
    } = input;

    let packet_budget = saturation(
        packets_per_worker as f64,
        config.preferred_packets_per_worker,
    );
    let byte_budget = if config.preferred_bytes_per_worker == 0 {
        1.0
    } else {
        saturation(bytes_per_worker as f64, config.preferred_bytes_per_worker)
    };
    let work_budget = (packet_budget * 0.70 + byte_budget * 0.30).clamp(0.10, 1.0);
    let packet_balance = balance_factor(diagnostics.packet_skew.max_over_average, 0.50);
    let byte_balance = balance_factor(diagnostics.byte_skew.max_over_average, 0.25);
    let flow_balance = balance_factor(diagnostics.flow_skew.max_over_average, 0.35);
    let fallback_factor = (1.0 - (fallback_ratio * 0.30)).clamp(0.25, 1.0);
    let topology_factor = if config.prefer_power_of_two && !is_power_of_two {
        0.75
    } else {
        1.0
    };

    let route_score = workers as f64
        * work_budget
        * packet_balance
        * byte_balance
        * flow_balance
        * fallback_factor
        * topology_factor;

    if !tcp_offload_active || tcp_offload_lanes == 0 {
        return route_score;
    }

    route_score.max(tcp_offload_score(
        workers,
        tcp_offload_lanes,
        diagnostics,
        config,
        fallback_factor,
        topology_factor,
    ))
}

fn tcp_offload_score(
    workers: usize,
    tcp_offload_lanes: usize,
    diagnostics: &PerfRunDiagnostics,
    config: PerfWorkerPlannerConfig,
    fallback_factor: f64,
    topology_factor: f64,
) -> f64 {
    let effective_workers = tcp_offload_lanes.saturating_add(1).min(workers).max(1);
    let bytes_per_effective_worker = diagnostics.tcp_routed_bytes / effective_workers.max(1) as u64;
    let packets_per_effective_worker =
        diagnostics.tcp_routed_packets as f64 / effective_workers.max(1) as f64;
    let byte_budget = saturation(
        bytes_per_effective_worker as f64,
        config.preferred_tcp_offload_bytes_per_worker,
    )
    .clamp(0.20, 1.0);
    let packet_budget = saturation(
        packets_per_effective_worker,
        config.min_tcp_offload_packets.max(1),
    )
    .clamp(0.20, 1.0);
    let work_budget = (byte_budget * 0.70 + packet_budget * 0.30).clamp(0.20, 1.0);
    let lane_utilization = effective_workers as f64 / workers.max(1) as f64;

    effective_workers as f64
        * work_budget
        * lane_utilization.powf(0.05)
        * fallback_factor
        * topology_factor
}

fn tcp_offload_candidate(
    diagnostics: &PerfRunDiagnostics,
    config: PerfWorkerPlannerConfig,
) -> bool {
    diagnostics.tcp_unique_flows != 0
        && (diagnostics.tcp_routed_packets >= config.min_tcp_offload_packets as u64
            || diagnostics.tcp_routed_bytes >= config.min_tcp_offload_bytes)
}

fn tcp_offload_lanes(workers: usize, diagnostics: &PerfRunDiagnostics) -> usize {
    diagnostics
        .tcp_unique_flows
        .min(workers.saturating_sub(1))
        .max(1)
}

fn saturation<T>(value: f64, preferred: T) -> f64
where
    T: TryInto<u64>,
{
    let preferred = preferred.try_into().ok().unwrap_or(0) as f64;
    if preferred <= 0.0 {
        return 1.0;
    }
    (value / preferred).clamp(0.0, 1.0)
}

fn balance_factor(skew: f64, exponent: f64) -> f64 {
    if skew <= 1.0 {
        1.0
    } else {
        1.0 / skew.powf(exponent)
    }
}

fn average_per_worker_usize(value: usize, workers: usize) -> usize {
    value / workers.max(1)
}

fn average_per_worker_u64(value: u64, workers: usize) -> u64 {
    value / workers.max(1) as u64
}

fn ratio(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 / total as f64
    }
}

fn warning_suffix(warnings: &[String]) -> String {
    if warnings.is_empty() {
        String::new()
    } else {
        format!("; warnings: {}", warnings.join("; "))
    }
}

fn tcp_offload_reason_suffix(active: bool, lanes: usize) -> String {
    if active {
        format!(", TCP offload lanes {lanes}")
    } else {
        String::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PerfInputSource {
    Synthetic { fixture: PerfFixtureKind },
    Pcap,
}

#[derive(Debug, Clone)]
pub struct PerfHarnessConfig {
    pub runs: usize,
    pub warmups: usize,
    pub worker_counts: Vec<usize>,
    pub include_warmups: bool,
    pub batch_size: usize,
    pub worker_queue_depth: usize,
    pub event_queue_depth: usize,
    pub max_flows: usize,
    pub stream_content_bytes: usize,
    pub stream_content_bytes_per_stream: usize,
    pub worker_planner: PerfWorkerPlannerConfig,
}

impl Default for PerfHarnessConfig {
    fn default() -> Self {
        Self {
            runs: 3,
            warmups: 1,
            worker_counts: vec![1, 0],
            include_warmups: false,
            batch_size: 4096,
            worker_queue_depth: 8192,
            event_queue_depth: 8192,
            max_flows: DEFAULT_MAX_FLOWS,
            stream_content_bytes: DEFAULT_MAX_STREAM_CONTENT_BYTES,
            stream_content_bytes_per_stream: DEFAULT_MAX_STREAM_CONTENT_BYTES_PER_STREAM,
            worker_planner: PerfWorkerPlannerConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PerfRunReport {
    pub schema_version: u8,
    pub input: PerfInputReport,
    pub run: PerfRunMeta,
    #[serde(default)]
    pub diagnostics: PerfRunDiagnostics,
    pub elapsed_ms: f64,
    pub rates: PerfRates,
    pub stats: PipelineStats,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PerfInputReport {
    pub name: String,
    pub source: PerfInputSource,
    pub flows: Option<usize>,
    pub messages_per_flow: Option<usize>,
    pub packets: usize,
    pub bytes: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PerfRunMeta {
    pub workers: usize,
    pub requested_workers: usize,
    pub run_index: usize,
    pub warmup: bool,
    pub batch_size: usize,
    pub worker_queue_depth: usize,
    pub event_queue_depth: usize,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct PerfRates {
    pub packets_per_sec: f64,
    pub bytes_per_sec: f64,
    pub mb_per_sec: f64,
    pub events_per_sec: f64,
    pub stream_bytes_per_sec: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PerfRunDiagnostics {
    pub shard_count: usize,
    pub routed_packets: u64,
    pub fallback_packets: u64,
    #[serde(default)]
    pub striped_flow_packets: u64,
    pub fallback_unsupported_link_packets: u64,
    pub fallback_non_ip_packets: u64,
    pub fallback_malformed_packets: u64,
    pub fallback_fragmented_packets: u64,
    pub fallback_unsupported_transport_packets: u64,
    pub unique_flows: usize,
    #[serde(default)]
    pub tcp_routed_packets: u64,
    #[serde(default)]
    pub tcp_routed_bytes: u64,
    #[serde(default)]
    pub tcp_unique_flows: usize,
    pub packet_skew: PerfSkew,
    pub byte_skew: PerfSkew,
    pub flow_skew: PerfSkew,
    pub shards: Vec<PerfShardLoad>,
}

impl Default for PerfRunDiagnostics {
    fn default() -> Self {
        Self {
            shard_count: 1,
            routed_packets: 0,
            fallback_packets: 0,
            striped_flow_packets: 0,
            fallback_unsupported_link_packets: 0,
            fallback_non_ip_packets: 0,
            fallback_malformed_packets: 0,
            fallback_fragmented_packets: 0,
            fallback_unsupported_transport_packets: 0,
            unique_flows: 0,
            tcp_routed_packets: 0,
            tcp_routed_bytes: 0,
            tcp_unique_flows: 0,
            packet_skew: PerfSkew::default(),
            byte_skew: PerfSkew::default(),
            flow_skew: PerfSkew::default(),
            shards: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize)]
pub struct PerfSkew {
    pub min: u64,
    pub max: u64,
    pub average: f64,
    pub max_over_average: f64,
    pub max_over_min: Option<f64>,
}

impl Default for PerfSkew {
    fn default() -> Self {
        Self {
            min: 0,
            max: 0,
            average: 0.0,
            max_over_average: 0.0,
            max_over_min: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PerfShardLoad {
    pub shard: usize,
    pub packets: u64,
    pub bytes: u64,
    pub unique_flows: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PerfSuiteReport {
    pub summary: PerfSuiteSummary,
    pub runs: Vec<PerfRunReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comparison: Option<PerfBaselineComparison>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PerfSuiteSummary {
    pub input: PerfInputReport,
    #[serde(default)]
    pub worker_plan: PerfWorkerPlan,
    pub aggregates: Vec<PerfAggregate>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PerfAggregate {
    pub workers: usize,
    pub runs: usize,
    pub packets_per_sec_min: f64,
    pub packets_per_sec_avg: f64,
    pub packets_per_sec_median: f64,
    pub packets_per_sec_max: f64,
    pub mb_per_sec_avg: f64,
    pub elapsed_ms_avg: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct PerfWorkerPlannerConfig {
    pub max_workers: usize,
    pub min_packets_per_worker: usize,
    pub min_flows_per_worker: usize,
    pub preferred_packets_per_worker: usize,
    pub preferred_bytes_per_worker: u64,
    pub min_tcp_offload_packets: usize,
    pub min_tcp_offload_bytes: u64,
    pub preferred_tcp_offload_bytes_per_worker: u64,
    pub max_packet_skew: f64,
    pub max_byte_skew: f64,
    pub max_flow_skew: f64,
    pub max_fallback_ratio: f64,
    pub prefer_power_of_two: bool,
}

impl Default for PerfWorkerPlannerConfig {
    fn default() -> Self {
        Self {
            max_workers: 0,
            min_packets_per_worker: 4096,
            min_flows_per_worker: 8,
            preferred_packets_per_worker: 16_384,
            preferred_bytes_per_worker: 1_000_000,
            min_tcp_offload_packets: 256,
            min_tcp_offload_bytes: 128 * 1024,
            preferred_tcp_offload_bytes_per_worker: 256 * 1024,
            max_packet_skew: 2.5,
            max_byte_skew: 3.0,
            max_flow_skew: 4.0,
            max_fallback_ratio: 1.0,
            prefer_power_of_two: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PerfWorkerPlan {
    pub planner_version: u32,
    pub selected_workers: usize,
    pub available_workers: usize,
    pub max_workers: usize,
    pub selected_score: f64,
    pub reason: String,
    #[serde(default)]
    pub decision_notes: Vec<String>,
    pub candidates: Vec<PerfWorkerCandidate>,
}

impl Default for PerfWorkerPlan {
    fn default() -> Self {
        Self {
            planner_version: 1,
            selected_workers: 1,
            available_workers: 1,
            max_workers: 1,
            selected_score: 0.0,
            reason: "planner data unavailable".to_owned(),
            decision_notes: Vec::new(),
            candidates: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PerfWorkerCandidate {
    pub workers: usize,
    pub eligible: bool,
    pub score: f64,
    pub reason: String,
    pub packets_per_worker: usize,
    pub bytes_per_worker: u64,
    pub flows_per_worker: usize,
    pub fallback_ratio: f64,
    pub is_power_of_two: bool,
    #[serde(default)]
    pub tcp_offload_active: bool,
    #[serde(default)]
    pub tcp_offload_lanes: usize,
    pub warnings: Vec<String>,
    pub rejections: Vec<String>,
    pub diagnostics: PerfRunDiagnostics,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PerfBaselineComparison {
    pub metric: String,
    pub max_regression_pct: f64,
    pub current_input: PerfInputReport,
    pub baseline_input: PerfInputReport,
    pub failed: bool,
    pub results: Vec<PerfBaselineResult>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PerfBaselineResult {
    pub workers: usize,
    pub status: PerfBaselineStatus,
    pub baseline_value: Option<f64>,
    pub current_value: Option<f64>,
    pub delta_pct: Option<f64>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PerfBaselineStatus {
    Pass,
    Regression,
    MissingBaseline,
}

pub async fn run_perf_suite(
    input: &PerfInput,
    config: &PerfHarnessConfig,
) -> Result<PerfSuiteReport> {
    let mut reports = Vec::new();
    let worker_counts = if config.worker_counts.is_empty() {
        vec![1]
    } else {
        config.worker_counts.clone()
    };
    let total_runs = config.runs.max(1).saturating_add(config.warmups);

    for requested_workers in worker_counts {
        for index in 0..total_runs {
            let warmup = index < config.warmups;
            let report = run_once(input, config, requested_workers, index, warmup).await?;
            if config.include_warmups || !warmup {
                reports.push(report);
            }
        }
    }

    Ok(PerfSuiteReport {
        summary: summarize(input, &reports, input.plan_workers(config.worker_planner)),
        runs: reports,
        comparison: None,
    })
}

async fn run_once(
    input: &PerfInput,
    config: &PerfHarnessConfig,
    requested_workers: usize,
    run_index: usize,
    warmup: bool,
) -> Result<PerfRunReport> {
    let workers = resolve_worker_count(requested_workers);
    let packets = Arc::clone(&input.packets);
    let diagnostics = input.diagnostics(workers);
    let started = Instant::now();
    let stats = if workers <= 1 {
        run_single_thread(packets, config).await?
    } else {
        run_sharded(packets, config, workers).await?
    };
    let elapsed = started.elapsed();
    Ok(report_from_stats(
        input,
        config,
        PerfMeasurement {
            requested_workers,
            workers,
            run_index,
            warmup,
            elapsed,
            diagnostics,
            stats,
        },
    ))
}

async fn run_single_thread(
    packets: Arc<[RawPacket]>,
    config: &PerfHarnessConfig,
) -> Result<PipelineStats> {
    let mut pipeline = Pipeline::new(pipeline_config(config));
    register_analyzers(&mut pipeline);
    pipeline.register_sink(Box::<CountingSink>::default());
    pipeline
        .run_with_source(ArcPacketSource::new(packets))
        .await
        .context("single-thread perf run failed")
}

async fn run_sharded(
    packets: Arc<[RawPacket]>,
    config: &PerfHarnessConfig,
    workers: usize,
) -> Result<PipelineStats> {
    let mut pipeline = ShardedPipeline::new(ShardedPipelineConfig {
        pipeline: pipeline_config(config),
        worker_count: workers,
        worker_queue_depth: config.worker_queue_depth.max(1),
        event_queue_depth: config.event_queue_depth.max(1),
    });
    register_sharded_analyzers(&mut pipeline);
    pipeline.register_sink(Box::<CountingSink>::default());
    pipeline
        .run_with_source(ArcPacketSource::new(packets))
        .await
        .context("sharded perf run failed")
}

struct PerfMeasurement {
    requested_workers: usize,
    workers: usize,
    run_index: usize,
    warmup: bool,
    elapsed: Duration,
    diagnostics: PerfRunDiagnostics,
    stats: PipelineStats,
}

fn report_from_stats(
    input: &PerfInput,
    config: &PerfHarnessConfig,
    measurement: PerfMeasurement,
) -> PerfRunReport {
    let elapsed_secs = measurement.elapsed.as_secs_f64().max(f64::EPSILON);
    PerfRunReport {
        schema_version: 1,
        input: input_report(input),
        run: PerfRunMeta {
            workers: measurement.workers,
            requested_workers: measurement.requested_workers,
            run_index: measurement.run_index,
            warmup: measurement.warmup,
            batch_size: config.batch_size.max(1),
            worker_queue_depth: config.worker_queue_depth.max(1),
            event_queue_depth: config.event_queue_depth.max(1),
        },
        diagnostics: measurement.diagnostics,
        elapsed_ms: elapsed_secs * 1000.0,
        rates: PerfRates {
            packets_per_sec: measurement.stats.packets as f64 / elapsed_secs,
            bytes_per_sec: measurement.stats.bytes as f64 / elapsed_secs,
            mb_per_sec: measurement.stats.bytes as f64 / elapsed_secs / 1_000_000.0,
            events_per_sec: measurement.stats.events as f64 / elapsed_secs,
            stream_bytes_per_sec: measurement.stats.tcp_stream_bytes as f64 / elapsed_secs,
        },
        stats: measurement.stats,
    }
}

pub fn summarize(
    input: &PerfInput,
    reports: &[PerfRunReport],
    worker_plan: PerfWorkerPlan,
) -> PerfSuiteSummary {
    let mut by_workers: BTreeMap<usize, Vec<&PerfRunReport>> = BTreeMap::new();
    for report in reports.iter().filter(|report| !report.run.warmup) {
        by_workers
            .entry(report.run.workers)
            .or_default()
            .push(report);
    }

    let aggregates = by_workers
        .into_iter()
        .map(|(workers, reports)| aggregate(workers, &reports))
        .collect();

    PerfSuiteSummary {
        input: input_report(input),
        worker_plan,
        aggregates,
    }
}

fn aggregate(workers: usize, reports: &[&PerfRunReport]) -> PerfAggregate {
    let mut packets_per_sec = reports
        .iter()
        .map(|report| report.rates.packets_per_sec)
        .collect::<Vec<_>>();
    packets_per_sec.sort_by(f64::total_cmp);
    let runs = reports.len();
    let packets_per_sec_avg = average(&packets_per_sec);
    PerfAggregate {
        workers,
        runs,
        packets_per_sec_min: packets_per_sec.first().copied().unwrap_or(0.0),
        packets_per_sec_avg,
        packets_per_sec_median: median(&packets_per_sec),
        packets_per_sec_max: packets_per_sec.last().copied().unwrap_or(0.0),
        mb_per_sec_avg: reports
            .iter()
            .map(|report| report.rates.mb_per_sec)
            .sum::<f64>()
            / runs.max(1) as f64,
        elapsed_ms_avg: reports.iter().map(|report| report.elapsed_ms).sum::<f64>()
            / runs.max(1) as f64,
    }
}

pub fn compare_to_baseline(
    current: &PerfSuiteReport,
    baseline: &PerfSuiteReport,
    max_regression_pct: f64,
) -> PerfBaselineComparison {
    let mut baseline_by_workers = BTreeMap::new();
    for aggregate in &baseline.summary.aggregates {
        baseline_by_workers.insert(aggregate.workers, aggregate);
    }

    let mut results = Vec::with_capacity(current.summary.aggregates.len());
    for current_aggregate in &current.summary.aggregates {
        let Some(baseline_aggregate) = baseline_by_workers.get(&current_aggregate.workers) else {
            results.push(PerfBaselineResult {
                workers: current_aggregate.workers,
                status: PerfBaselineStatus::MissingBaseline,
                baseline_value: None,
                current_value: Some(current_aggregate.packets_per_sec_avg),
                delta_pct: None,
                message: "baseline has no aggregate for this worker count".to_owned(),
            });
            continue;
        };

        let baseline_value = baseline_aggregate.packets_per_sec_avg;
        let current_value = current_aggregate.packets_per_sec_avg;
        let delta_pct = if baseline_value > 0.0 {
            Some((current_value - baseline_value) / baseline_value * 100.0)
        } else {
            None
        };
        let regression = delta_pct.is_some_and(|delta| delta < -max_regression_pct);
        results.push(PerfBaselineResult {
            workers: current_aggregate.workers,
            status: if regression {
                PerfBaselineStatus::Regression
            } else {
                PerfBaselineStatus::Pass
            },
            baseline_value: Some(baseline_value),
            current_value: Some(current_value),
            delta_pct,
            message: match delta_pct {
                Some(delta) => format!("{delta:.2}% vs baseline"),
                None => "baseline value is zero; regression percentage unavailable".to_owned(),
            },
        });
    }

    let failed = results
        .iter()
        .any(|result| result.status == PerfBaselineStatus::Regression);
    PerfBaselineComparison {
        metric: "packets_per_sec_avg".to_owned(),
        max_regression_pct,
        current_input: current.summary.input.clone(),
        baseline_input: baseline.summary.input.clone(),
        failed,
        results,
    }
}

fn average(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len().max(1) as f64
}

fn median(sorted_values: &[f64]) -> f64 {
    match sorted_values.len() {
        0 => 0.0,
        len if len % 2 == 1 => sorted_values[len / 2],
        len => (sorted_values[len / 2 - 1] + sorted_values[len / 2]) / 2.0,
    }
}

fn skew(values: impl Iterator<Item = u64>) -> PerfSkew {
    let values = values.collect::<Vec<_>>();
    let min = values.iter().copied().min().unwrap_or(0);
    let max = values.iter().copied().max().unwrap_or(0);
    let average = values.iter().sum::<u64>() as f64 / values.len().max(1) as f64;
    PerfSkew {
        min,
        max,
        average,
        max_over_average: if average > 0.0 {
            max as f64 / average
        } else {
            0.0
        },
        max_over_min: (min != 0).then_some(max as f64 / min as f64),
    }
}

fn input_report(input: &PerfInput) -> PerfInputReport {
    PerfInputReport {
        name: input.name.clone(),
        source: input.source,
        flows: input.flows,
        messages_per_flow: input.messages_per_flow,
        packets: input.packet_count,
        bytes: input.byte_count,
    }
}

fn pipeline_config(config: &PerfHarnessConfig) -> PipelineConfig {
    PipelineConfig {
        mode: RunMode::Analyze,
        batch_size: config.batch_size.max(1),
        health_interval_ms: 0,
        max_flows: config.max_flows.max(1),
        flow_idle_timeout_ms: DEFAULT_FLOW_IDLE_TIMEOUT_MS,
        max_tcp_buffered_bytes_per_flow: DEFAULT_TCP_BUFFERED_BYTES_PER_FLOW,
        max_tcp_out_of_order_segments_per_direction: DEFAULT_TCP_OUT_OF_ORDER_SEGMENTS,
        stream_inventory: StreamInventoryConfig {
            enabled: true,
            max_streams: config.max_flows.max(1),
            idle_timeout_ms: DEFAULT_FLOW_IDLE_TIMEOUT_MS,
            preview_bytes_per_direction: 256,
            update_packet_interval: 64,
            update_byte_interval: 64 * 1024,
        },
        stream_content: StreamContentConfig {
            enabled: true,
            max_streams: config.max_flows.max(1),
            idle_timeout_ms: DEFAULT_FLOW_IDLE_TIMEOUT_MS,
            max_total_bytes: config.stream_content_bytes.max(1),
            max_bytes_per_stream: config.stream_content_bytes_per_stream.max(1),
            max_segment_bytes: 64 * 1024,
        },
        stream_parser: StreamParserConfig::default(),
        stream_view: StreamViewConfig {
            enabled: true,
            max_streams: config.max_flows.max(1),
            max_matches_per_stream: 512,
            max_query_limit: 1024,
        },
        stream_slice: StreamSliceConfig {
            max_slice_bytes: 64 * 1024,
            max_highlights: 8192,
            hex_row_bytes: 16,
            max_transform_bytes: 1024 * 1024,
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
    fn write(&mut self, _event: &Event) -> Result<()> {
        self.events = self.events.saturating_add(1);
        Ok(())
    }

    fn write_batch(&mut self, events: &[Event]) -> Result<()> {
        self.events = self.events.saturating_add(events.len() as u64);
        black_box(self.events);
        Ok(())
    }
}

struct ArcPacketSource {
    packets: Arc<[RawPacket]>,
    cursor: usize,
}

impl ArcPacketSource {
    fn new(packets: Arc<[RawPacket]>) -> Self {
        Self { packets, cursor: 0 }
    }
}

#[async_trait::async_trait]
impl PacketSource for ArcPacketSource {
    async fn next_batch(&mut self, batch: &mut PacketBatch) -> Result<usize> {
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

pub fn generate_fixture(
    fixture: PerfFixtureKind,
    flows: usize,
    messages_per_flow: usize,
) -> Vec<RawPacket> {
    match fixture {
        PerfFixtureKind::HttpRequests => http_request_fixture(flows),
        PerfFixtureKind::OutOfOrderHttp => out_of_order_http_fixture(flows),
        PerfFixtureKind::HttpKeepAlive => http_keep_alive_fixture(flows, messages_per_flow),
        PerfFixtureKind::MixedServices => mixed_services_fixture(flows, messages_per_flow),
        PerfFixtureKind::UdpElephant => udp_elephant_fixture(flows, messages_per_flow),
        PerfFixtureKind::TcpElephant => tcp_elephant_fixture(flows, messages_per_flow),
    }
}

fn http_request_fixture(flows: usize) -> Vec<RawPacket> {
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
    packets
}

fn out_of_order_http_fixture(flows: usize) -> Vec<RawPacket> {
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
    packets
}

fn http_keep_alive_fixture(flows: usize, messages_per_flow: usize) -> Vec<RawPacket> {
    let mut packets = Vec::with_capacity(flows * messages_per_flow);
    for flow in 0..flows {
        let source = source_ip(flow);
        let source_port = source_port(flow);
        let mut sequence = 20_000 + (flow as u32).wrapping_mul(4096);
        for message in 0..messages_per_flow {
            let payload = format!(
                "GET /flow/{flow}/message/{message} HTTP/1.1\r\nHost: keepalive.fixture\r\nConnection: keep-alive\r\n\r\n"
            );
            packets.push(tcp_packet(
                source,
                source_port,
                [192, 0, 2, 80],
                80,
                sequence,
                payload.as_bytes(),
                (flow * messages_per_flow + message) as u64,
            ));
            sequence = sequence.wrapping_add(payload.len() as u32);
        }
    }
    packets
}

fn mixed_services_fixture(flows: usize, messages_per_flow: usize) -> Vec<RawPacket> {
    let mut packets = Vec::with_capacity(flows * messages_per_flow);
    for flow in 0..flows {
        for message in 0..messages_per_flow {
            let ordinal = flow * messages_per_flow + message;
            match ordinal % 3 {
                0 => {
                    let payload = format!(
                        "GET /mixed/{flow}/{message} HTTP/1.1\r\nHost: mixed.fixture\r\n\r\n"
                    );
                    packets.push(tcp_packet(
                        source_ip(flow),
                        source_port(flow),
                        [192, 0, 2, 80],
                        80,
                        30_000 + ordinal as u32 * 128,
                        payload.as_bytes(),
                        ordinal as u64,
                    ));
                }
                1 => packets.push(udp_packet(
                    source_ip(flow),
                    source_port(flow),
                    [192, 0, 2, 53],
                    53,
                    &dns_query_payload(ordinal as u16),
                    ordinal as u64,
                )),
                _ => packets.push(tcp_packet(
                    source_ip(flow),
                    source_port(flow),
                    [192, 0, 2, 44],
                    443,
                    40_000 + ordinal as u32 * 128,
                    &tls_client_hello_like_payload(),
                    ordinal as u64,
                )),
            }
        }
    }
    packets
}

fn udp_elephant_fixture(flows: usize, messages_per_flow: usize) -> Vec<RawPacket> {
    let payload = vec![0xa5; 1200];
    let mut packets = Vec::with_capacity(flows.saturating_mul(messages_per_flow));
    for flow in 0..flows {
        for message in 0..messages_per_flow {
            packets.push(udp_packet(
                source_ip(flow),
                source_port(flow),
                [198, 51, 100, 44],
                443,
                &payload,
                (flow * messages_per_flow + message) as u64,
            ));
        }
    }
    packets
}

fn tcp_elephant_fixture(flows: usize, messages_per_flow: usize) -> Vec<RawPacket> {
    let mut packets = Vec::with_capacity(flows.saturating_mul(messages_per_flow));
    for flow in 0..flows {
        let source = source_ip(flow);
        let source_port = source_port(flow);
        let mut sequence = 60_000 + (flow as u32).wrapping_mul(1_048_576);
        for message in 0..messages_per_flow {
            let payload = format!(
                "GET /elephant/{flow}/{message} HTTP/1.1\r\nHost: tcp-elephant.fixture\r\nConnection: keep-alive\r\nX-Pad: {}\r\n\r\n",
                "a".repeat(900),
            );
            packets.push(tcp_packet(
                source,
                source_port,
                [198, 51, 100, 80],
                80,
                sequence,
                payload.as_bytes(),
                (flow * messages_per_flow + message) as u64,
            ));
            sequence = sequence.wrapping_add(payload.len() as u32);
        }
    }
    packets
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
    raw_packet(data, timestamp)
}

fn udp_packet(
    source: [u8; 4],
    source_port: u16,
    destination: [u8; 4],
    destination_port: u16,
    payload: &[u8],
    timestamp: u64,
) -> RawPacket {
    let builder = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
        .ipv4(source, destination, 20)
        .udp(source_port, destination_port);
    let mut data = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut data, payload).unwrap();
    raw_packet(data, timestamp)
}

fn raw_packet(data: Vec<u8>, timestamp: u64) -> RawPacket {
    RawPacket {
        timestamp: PacketTimestamp {
            sec: timestamp / 1_000_000,
            usec: (timestamp % 1_000_000) as u32,
        },
        link_layer: LinkLayer::Ethernet,
        linktype: Linktype::ETHERNET.0,
        data,
    }
}

fn dns_query_payload(id: u16) -> Vec<u8> {
    let mut payload = Vec::with_capacity(33);
    payload.extend_from_slice(&id.to_be_bytes());
    payload.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00]);
    payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    payload.push(7);
    payload.extend_from_slice(b"fixture");
    payload.push(5);
    payload.extend_from_slice(b"local");
    payload.push(0);
    payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    payload
}

fn tls_client_hello_like_payload() -> Vec<u8> {
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&[
        0x16, 0x03, 0x01, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b, 0x03, 0x03,
    ]);
    payload.extend_from_slice(&[0x11; 32]);
    payload.extend_from_slice(&[0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
    payload
}

#[cfg(test)]
mod tests {
    use tokio::runtime::Builder;

    use super::*;

    #[test]
    fn synthetic_fixture_generates_packets() {
        let input = PerfInput::synthetic(PerfFixtureKind::MixedServices, 9, 2);

        assert_eq!(18, input.packet_count());
        assert!(input.byte_count() > 0);
    }

    #[test]
    fn udp_elephant_fixture_exercises_striped_routing() {
        let input = PerfInput::synthetic(PerfFixtureKind::UdpElephant, 1, 2048);
        let diagnostics = input.diagnostics(4);
        let striped_shards = diagnostics
            .shards
            .iter()
            .filter(|shard| shard.packets != 0)
            .count();

        assert_eq!(2048, input.packet_count());
        assert_eq!(1, diagnostics.unique_flows);
        assert!(diagnostics.striped_flow_packets > 0);
        assert!(striped_shards > 1);
        assert!(diagnostics.packet_skew.max_over_average < 4.0);
    }

    #[test]
    fn tcp_elephant_fixture_exercises_stream_offload() {
        let runtime = Builder::new_current_thread().build().unwrap();
        let input = PerfInput::synthetic(PerfFixtureKind::TcpElephant, 1, 32);
        let config = PerfHarnessConfig {
            runs: 1,
            warmups: 0,
            worker_counts: vec![4],
            batch_size: 16,
            max_flows: 1024,
            stream_content_bytes: 4 * 1024 * 1024,
            stream_content_bytes_per_stream: 2 * 1024 * 1024,
            ..PerfHarnessConfig::default()
        };

        let report = runtime.block_on(run_perf_suite(&input, &config)).unwrap();
        let run = report.runs.first().unwrap();

        assert_eq!(32, input.packet_count());
        assert_eq!(1, run.diagnostics.unique_flows);
        assert_eq!(0, run.diagnostics.striped_flow_packets);
        assert_eq!(3, run.stats.stream_offload_workers);
        assert_eq!(32, run.stats.stream_offload_submitted_chunks);
        assert_eq!(32, run.stats.stream_offload_processed_chunks);
        assert_eq!(
            run.stats.tcp_stream_bytes,
            run.stats.stream_offload_processed_bytes
        );
        assert_eq!(32, run.stats.parser_stream_chunks);
    }

    #[test]
    fn harness_runs_single_and_sharded() {
        let runtime = Builder::new_current_thread().build().unwrap();
        let input = PerfInput::synthetic(PerfFixtureKind::HttpRequests, 32, 1);
        let config = PerfHarnessConfig {
            runs: 1,
            warmups: 0,
            worker_counts: vec![1, 2],
            batch_size: 16,
            max_flows: 1024,
            stream_content_bytes: 4 * 1024 * 1024,
            ..PerfHarnessConfig::default()
        };

        let report = runtime.block_on(run_perf_suite(&input, &config)).unwrap();

        assert_eq!(2, report.runs.len());
        assert_eq!(2, report.summary.aggregates.len());
        assert!(report.runs.iter().all(|run| run.stats.packets == 32));
        assert!(
            report
                .runs
                .iter()
                .all(|run| run.diagnostics.unique_flows == 32)
        );
        assert!(
            report
                .runs
                .iter()
                .all(|run| run.diagnostics.fallback_packets == 0)
        );
    }

    #[test]
    fn worker_planner_warns_on_small_packet_budget() {
        let candidate = evaluate_worker_candidate(
            4,
            32,
            4096,
            PerfRunDiagnostics {
                unique_flows: 16,
                packet_skew: PerfSkew {
                    max_over_average: 1.0,
                    ..PerfSkew::default()
                },
                byte_skew: PerfSkew {
                    max_over_average: 1.0,
                    ..PerfSkew::default()
                },
                flow_skew: PerfSkew {
                    max_over_average: 1.0,
                    ..PerfSkew::default()
                },
                ..PerfRunDiagnostics::default()
            },
            PerfWorkerPlannerConfig {
                max_workers: 12,
                min_packets_per_worker: 16,
                min_flows_per_worker: 4,
                max_packet_skew: 1.5,
                max_byte_skew: 1.5,
                ..PerfWorkerPlannerConfig::default()
            },
        );

        assert!(candidate.eligible);
        assert!(
            candidate
                .warnings
                .iter()
                .any(|warning| warning == "below minimum packet target: 8 < 16")
        );
    }

    #[test]
    fn worker_planner_rejects_low_flow_budget() {
        let candidate = evaluate_worker_candidate(
            4,
            32,
            4096,
            PerfRunDiagnostics {
                unique_flows: 12,
                packet_skew: PerfSkew {
                    max_over_average: 1.0,
                    ..PerfSkew::default()
                },
                byte_skew: PerfSkew {
                    max_over_average: 1.0,
                    ..PerfSkew::default()
                },
                flow_skew: PerfSkew {
                    max_over_average: 1.0,
                    ..PerfSkew::default()
                },
                ..PerfRunDiagnostics::default()
            },
            PerfWorkerPlannerConfig {
                min_packets_per_worker: 16,
                min_flows_per_worker: 4,
                ..PerfWorkerPlannerConfig::default()
            },
        );

        assert!(!candidate.eligible);
        assert_eq!("too few routed flows per worker: 3 < 4", candidate.reason);
    }

    #[test]
    fn worker_planner_accepts_low_flow_budget_for_striped_elephant() {
        let candidate = evaluate_worker_candidate(
            4,
            4096,
            4_000_000,
            PerfRunDiagnostics {
                unique_flows: 1,
                striped_flow_packets: 3000,
                packet_skew: PerfSkew {
                    max_over_average: 1.1,
                    ..PerfSkew::default()
                },
                byte_skew: PerfSkew {
                    max_over_average: 1.1,
                    ..PerfSkew::default()
                },
                flow_skew: PerfSkew {
                    max_over_average: 1.0,
                    ..PerfSkew::default()
                },
                ..PerfRunDiagnostics::default()
            },
            PerfWorkerPlannerConfig {
                min_flows_per_worker: 8,
                min_packets_per_worker: 512,
                max_packet_skew: 2.0,
                max_byte_skew: 2.0,
                ..PerfWorkerPlannerConfig::default()
            },
        );

        assert!(candidate.eligible);
        assert!(
            candidate
                .warnings
                .iter()
                .any(|warning| warning.contains("elephant striping is active"))
        );
    }

    #[test]
    fn worker_planner_accepts_skew_for_tcp_stream_offload() {
        let candidate = evaluate_worker_candidate(
            2,
            512,
            512_000,
            PerfRunDiagnostics {
                unique_flows: 1,
                tcp_routed_packets: 512,
                tcp_routed_bytes: 512_000,
                tcp_unique_flows: 1,
                packet_skew: PerfSkew {
                    max_over_average: 2.0,
                    ..PerfSkew::default()
                },
                byte_skew: PerfSkew {
                    max_over_average: 2.0,
                    ..PerfSkew::default()
                },
                flow_skew: PerfSkew {
                    max_over_average: 2.0,
                    ..PerfSkew::default()
                },
                ..PerfRunDiagnostics::default()
            },
            PerfWorkerPlannerConfig {
                min_flows_per_worker: 8,
                min_packets_per_worker: 256,
                max_packet_skew: 1.5,
                max_byte_skew: 1.5,
                max_flow_skew: 1.5,
                ..PerfWorkerPlannerConfig::default()
            },
        );

        assert!(candidate.eligible);
        assert!(candidate.tcp_offload_active);
        assert_eq!(1, candidate.tcp_offload_lanes);
        assert!(candidate.score > 0.50);
        assert!(
            candidate
                .warnings
                .iter()
                .any(|warning| warning.contains("TCP stream offload is active"))
        );
    }

    #[test]
    fn worker_planner_selects_multiworker_for_tcp_elephant() {
        let input = PerfInput::synthetic(PerfFixtureKind::TcpElephant, 1, 512);
        let plan = input.plan_workers(PerfWorkerPlannerConfig {
            max_workers: 4,
            ..PerfWorkerPlannerConfig::default()
        });

        assert!(plan.selected_workers > 1);
        assert!(
            plan.candidates
                .iter()
                .filter(|candidate| candidate.workers > 1)
                .any(|candidate| candidate.tcp_offload_active)
        );
    }

    #[test]
    fn worker_planner_keeps_selected_worker_within_resolved_cap() {
        let input = PerfInput::synthetic(PerfFixtureKind::HttpRequests, 128, 1);
        let plan = input.plan_workers(PerfWorkerPlannerConfig {
            max_workers: 12,
            min_packets_per_worker: 16,
            min_flows_per_worker: 4,
            max_packet_skew: 1.5,
            max_byte_skew: 1.5,
            ..PerfWorkerPlannerConfig::default()
        });

        assert!((1..=plan.max_workers).contains(&plan.selected_workers));
    }

    #[test]
    fn worker_planner_penalizes_weak_non_power_of_two_candidates() {
        let diagnostics = PerfRunDiagnostics {
            unique_flows: 96_000,
            packet_skew: PerfSkew {
                max_over_average: 1.0,
                ..PerfSkew::default()
            },
            byte_skew: PerfSkew {
                max_over_average: 1.0,
                ..PerfSkew::default()
            },
            flow_skew: PerfSkew {
                max_over_average: 1.0,
                ..PerfSkew::default()
            },
            ..PerfRunDiagnostics::default()
        };
        let config = PerfWorkerPlannerConfig {
            preferred_packets_per_worker: 16_384,
            preferred_bytes_per_worker: 0,
            ..PerfWorkerPlannerConfig::default()
        };
        let eight = evaluate_worker_candidate(8, 96_000, 96_000, diagnostics.clone(), config);
        let twelve = evaluate_worker_candidate(12, 96_000, 96_000, diagnostics, config);
        let candidates = vec![eight.clone(), twelve.clone()];

        let selected = select_worker_candidate(&candidates, config).unwrap();

        assert!(eight.eligible);
        assert!(twelve.eligible);
        assert!(eight.score > twelve.score);
        assert_eq!(8, selected.workers);
    }

    #[test]
    fn worker_planner_treats_single_worker_as_fallback_baseline() {
        let diagnostics = PerfRunDiagnostics {
            unique_flows: 20_000,
            packet_skew: PerfSkew {
                max_over_average: 1.0,
                ..PerfSkew::default()
            },
            byte_skew: PerfSkew {
                max_over_average: 1.0,
                ..PerfSkew::default()
            },
            flow_skew: PerfSkew {
                max_over_average: 1.0,
                ..PerfSkew::default()
            },
            ..PerfRunDiagnostics::default()
        };
        let config = PerfWorkerPlannerConfig {
            preferred_packets_per_worker: 16_384,
            preferred_bytes_per_worker: 0,
            ..PerfWorkerPlannerConfig::default()
        };
        let single = evaluate_worker_candidate(1, 20_000, 20_000, diagnostics.clone(), config);
        let two = evaluate_worker_candidate(2, 20_000, 20_000, diagnostics, config);
        let candidates = vec![single.clone(), two.clone()];
        let selected = select_worker_candidate(&candidates, config).unwrap();

        assert!(single.eligible);
        assert!(two.eligible);
        assert!(two.score > single.score);
        assert_eq!(2, selected.workers);
    }

    #[test]
    fn worker_planner_prefers_larger_power_of_two_inside_score_band() {
        let diagnostics = PerfRunDiagnostics {
            unique_flows: 20_000,
            packet_skew: PerfSkew {
                max_over_average: 1.02,
                ..PerfSkew::default()
            },
            byte_skew: PerfSkew {
                max_over_average: 1.02,
                ..PerfSkew::default()
            },
            flow_skew: PerfSkew {
                max_over_average: 1.02,
                ..PerfSkew::default()
            },
            ..PerfRunDiagnostics::default()
        };
        let config = PerfWorkerPlannerConfig {
            min_packets_per_worker: 4096,
            preferred_packets_per_worker: 16_384,
            preferred_bytes_per_worker: 1_000_000,
            ..PerfWorkerPlannerConfig::default()
        };
        let two = evaluate_worker_candidate(2, 20_000, 2_048_890, diagnostics.clone(), config);
        let four = evaluate_worker_candidate(4, 20_000, 2_048_890, diagnostics.clone(), config);
        let eight = evaluate_worker_candidate(8, 20_000, 2_048_890, diagnostics, config);
        let candidates = vec![two, four, eight];
        let selected = select_worker_candidate(&candidates, config).unwrap();

        assert_eq!(8, selected.workers);
    }

    #[test]
    fn baseline_comparison_detects_regression() {
        let input = PerfInput::synthetic(PerfFixtureKind::HttpRequests, 8, 1);
        let mut baseline = minimal_suite(&input, 4, 1000.0);
        let current = minimal_suite(&input, 4, 850.0);

        let comparison = compare_to_baseline(&current, &baseline, 10.0);

        assert!(comparison.failed);
        assert_eq!(PerfBaselineStatus::Regression, comparison.results[0].status);
        baseline.summary.aggregates[0].packets_per_sec_avg = 900.0;
        let comparison = compare_to_baseline(&current, &baseline, 10.0);
        assert!(!comparison.failed);
    }

    fn minimal_suite(input: &PerfInput, workers: usize, packets_per_sec: f64) -> PerfSuiteReport {
        PerfSuiteReport {
            summary: PerfSuiteSummary {
                input: input_report(input),
                worker_plan: PerfWorkerPlan::default(),
                aggregates: vec![PerfAggregate {
                    workers,
                    runs: 1,
                    packets_per_sec_min: packets_per_sec,
                    packets_per_sec_avg: packets_per_sec,
                    packets_per_sec_median: packets_per_sec,
                    packets_per_sec_max: packets_per_sec,
                    mb_per_sec_avg: 0.0,
                    elapsed_ms_avg: 0.0,
                }],
            },
            runs: Vec::new(),
            comparison: None,
        }
    }
}
