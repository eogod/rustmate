use std::time::{Duration, Instant};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::{ingest::PacketSourceStats, pipeline::PipelineStats};

#[derive(Debug, Clone)]
pub struct PipelineHealthReporter {
    interval: Option<Duration>,
    previous: HealthSample,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub struct PipelineQueueSnapshot {
    pub output_queue_len: usize,
    pub output_queue_capacity: usize,
    pub max_worker_queue_len: usize,
    pub max_worker_queue_capacity: usize,
    pub busiest_worker: Option<usize>,
    pub busiest_worker_packets: u64,
    pub busiest_worker_bytes: u64,
    pub fallback_routed_packets: u64,
    pub striped_flow_packets: u64,
    pub fallback_unsupported_link_packets: u64,
    pub fallback_non_ip_packets: u64,
    pub fallback_malformed_packets: u64,
    pub fallback_fragmented_packets: u64,
    pub fallback_unsupported_transport_packets: u64,
    pub worker_packet_skew_ratio_milli: u64,
    pub worker_byte_skew_ratio_milli: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct WorkerHotFlowSnapshot {
    pub stream_id: u64,
    pub stream_id_hex: String,
    pub protocol: String,
    pub endpoint_a: String,
    pub endpoint_b: String,
    pub packets: u64,
    pub bytes: u64,
    #[serde(default)]
    pub total_packets: u64,
    #[serde(default)]
    pub total_bytes: u64,
    #[serde(default)]
    pub striped: bool,
    #[serde(default)]
    pub stripe_shards: usize,
    pub packet_share_milli: u64,
    pub byte_share_milli: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct WorkerQueueSnapshot {
    pub id: usize,
    pub len: usize,
    pub capacity: usize,
    pub routed_packets: u64,
    pub routed_bytes: u64,
    pub flow_routed_packets: u64,
    #[serde(default)]
    pub striped_flow_packets: u64,
    pub fallback_packets: u64,
    pub fallback_unsupported_link_packets: u64,
    pub fallback_non_ip_packets: u64,
    pub fallback_malformed_packets: u64,
    pub fallback_fragmented_packets: u64,
    pub fallback_unsupported_transport_packets: u64,
    pub hot_flow: Option<WorkerHotFlowSnapshot>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct ShardedQueueSnapshot {
    pub workers: Vec<WorkerQueueSnapshot>,
    pub output_queue_len: usize,
    pub output_queue_capacity: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct ShardPressureSnapshot {
    pub state: ShardPressureState,
    pub shard_count: usize,
    pub routed_packets: u64,
    pub routed_bytes: u64,
    pub fallback_packets: u64,
    pub striped_flow_packets: u64,
    pub fallback_ratio_milli: u64,
    pub max_worker_queue_fill_milli: u64,
    pub output_queue_fill_milli: u64,
    pub busiest_shard: Option<usize>,
    pub busiest_shard_packets: u64,
    pub busiest_shard_bytes: u64,
    pub hot_flow: Option<WorkerHotFlowSnapshot>,
    pub packet_skew_ratio_milli: u64,
    pub byte_skew_ratio_milli: u64,
    pub warnings: Vec<ShardPressureWarning>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardPressureState {
    Idle,
    Healthy,
    Watch,
    Hot,
    Saturated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ShardPressureWarning {
    SingleShard,
    PacketSkew,
    ByteSkew,
    ElephantFlow,
    WorkerQueuePressure,
    OutputQueuePressure,
    FallbackRoutes,
    MalformedFallback,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct HealthTotals {
    packets: u64,
    bytes: u64,
    events: u64,
    source_received_packets: u64,
    source_dropped_packets: u64,
    source_interface_dropped_packets: u64,
}

#[derive(Debug, Clone)]
struct HealthSample {
    totals: HealthTotals,
    at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct HealthRates {
    packets_per_sec: f64,
    bytes_per_sec: f64,
    events_per_sec: f64,
    source_received_per_sec: f64,
    source_dropped_per_sec: f64,
    source_interface_dropped_per_sec: f64,
}

impl PipelineHealthReporter {
    pub fn new(interval_ms: u64) -> Self {
        Self {
            interval: (interval_ms != 0).then(|| Duration::from_millis(interval_ms)),
            previous: HealthSample {
                totals: HealthTotals::default(),
                at: Instant::now(),
            },
        }
    }

    pub fn maybe_report<F>(
        &mut self,
        stats: &mut PipelineStats,
        queue: Option<&ShardedQueueSnapshot>,
        source_stats: F,
    ) -> Result<bool>
    where
        F: FnOnce() -> Result<Option<PacketSourceStats>>,
    {
        let Some(interval) = self.interval else {
            return Ok(false);
        };

        let now = Instant::now();
        if now.duration_since(self.previous.at) < interval {
            return Ok(false);
        }

        if let Some(source_stats) = source_stats()? {
            stats.set_source_stats(source_stats);
        }

        let current = HealthSample {
            totals: HealthTotals::from_stats(stats),
            at: now,
        };
        let rates = HealthRates::between(&self.previous, &current);
        let queue = queue
            .map(ShardedQueueSnapshot::summarize)
            .unwrap_or_default();

        tracing::info!(
            packets = stats.packets,
            bytes = stats.bytes,
            events = stats.events,
            packets_per_sec = rates.packets_per_sec,
            bytes_per_sec = rates.bytes_per_sec,
            events_per_sec = rates.events_per_sec,
            decode_errors = stats.decode_errors,
            packet_parsed_packets = stats.packet_decode.packet_parsed_packets,
            packet_non_ip_packets = stats.packet_decode.packet_non_ip_packets,
            packet_fragmented_packets = stats.packet_decode.packet_fragmented_packets,
            packet_unsupported_transport_packets =
                stats.packet_decode.packet_unsupported_transport_packets,
            packet_malformed_packets = stats.packet_decode.packet_malformed_packets,
            packet_unsupported_link_packets = stats.packet_decode.packet_unsupported_link_packets,
            fallback_routed_packets = stats.fallback_routed_packets,
            striped_flow_packets = stats.striped_flow_packets,
            fallback_unsupported_link_packets = stats.fallback_unsupported_link_packets,
            fallback_non_ip_packets = stats.fallback_non_ip_packets,
            fallback_malformed_packets = stats.fallback_malformed_packets,
            fallback_fragmented_packets = stats.fallback_fragmented_packets,
            fallback_unsupported_transport_packets = stats.fallback_unsupported_transport_packets,
            busiest_shard = stats.busiest_shard,
            busiest_shard_packets = stats.busiest_shard_packets,
            busiest_shard_bytes = stats.busiest_shard_bytes,
            shard_packet_skew_ratio = stats.shard_packet_skew_ratio_milli as f64 / 1000.0,
            shard_byte_skew_ratio = stats.shard_byte_skew_ratio_milli as f64 / 1000.0,
            source_received_packets = stats.source_received_packets,
            source_dropped_packets = stats.source_dropped_packets,
            source_interface_dropped_packets = stats.source_interface_dropped_packets,
            source_received_per_sec = rates.source_received_per_sec,
            source_dropped_per_sec = rates.source_dropped_per_sec,
            source_interface_dropped_per_sec = rates.source_interface_dropped_per_sec,
            active_flows = stats.active_flows,
            created_flows = stats.created_flows,
            dropped_new_flows = stats.dropped_new_flows,
            inventory_active_streams = stats.inventory_active_streams,
            inventory_created_streams = stats.inventory_created_streams,
            inventory_dropped_new_streams = stats.inventory_dropped_new_streams,
            inventory_events = stats.inventory_events,
            content_active_streams = stats.content_active_streams,
            content_active_segments = stats.content_active_segments,
            content_stored_bytes = stats.content_stored_bytes,
            content_dropped_bytes = stats.content_dropped_bytes,
            content_evicted_streams = stats.content_evicted_streams,
            message_observed_messages = stats.message_observed_messages,
            message_http1_messages = stats.message_http1_messages,
            message_dns_messages = stats.message_dns_messages,
            message_websocket_messages = stats.message_websocket_messages,
            message_tls_messages = stats.message_tls_messages,
            message_parse_errors = stats.message_parse_errors,
            parser_http1_messages = stats.parser_http1_messages,
            parser_dns_messages = stats.parser_dns_messages,
            parser_websocket_messages = stats.parser_websocket_messages,
            parser_tls_messages = stats.parser_tls_messages,
            parser_dns_parse_errors = stats.parser_dns_parse_errors,
            parser_dns_dropped_datagrams = stats.parser_dns_dropped_datagrams,
            pattern_matches = stats.pattern_matches,
            pattern_dropped_matches = stats.pattern_dropped_matches,
            pattern_matched_streams = stats.pattern_matched_streams,
            view_tracked_streams = stats.view_tracked_streams,
            view_matched_streams = stats.view_matched_streams,
            view_stored_matches = stats.view_stored_matches,
            view_dropped_matches = stats.view_dropped_matches,
            view_orphan_matches = stats.view_orphan_matches,
            tcp_gaps = stats.tcp_gaps,
            tcp_retransmissions = stats.tcp_retransmissions,
            tcp_retransmitted_bytes = stats.tcp_retransmitted_bytes,
            tcp_out_of_order_dropped = stats.tcp_out_of_order_dropped,
            tcp_out_of_order_dropped_bytes = stats.tcp_out_of_order_dropped_bytes,
            tcp_out_of_order_buffered = stats.tcp_out_of_order_buffered,
            tcp_out_of_order_buffered_bytes = stats.tcp_out_of_order_buffered_bytes,
            tcp_buffered_stream_chunks = stats.tcp_buffered_stream_chunks,
            tcp_buffered_stream_bytes = stats.tcp_buffered_stream_bytes,
            tcp_overlap_trimmed_stream_chunks = stats.tcp_overlap_trimmed_stream_chunks,
            tcp_overlap_trimmed_stream_bytes = stats.tcp_overlap_trimmed_stream_bytes,
            tcp_reassembly_buffered_bytes_peak = stats.tcp_reassembly_buffered_bytes_peak,
            tcp_midstream_starts = stats.tcp_midstream_starts,
            worker_queue_max_len = queue.max_worker_queue_len,
            worker_queue_max_capacity = queue.max_worker_queue_capacity,
            output_queue_len = queue.output_queue_len,
            output_queue_capacity = queue.output_queue_capacity,
            busiest_worker = queue.busiest_worker,
            busiest_worker_packets = queue.busiest_worker_packets,
            busiest_worker_bytes = queue.busiest_worker_bytes,
            worker_fallback_routed_packets = queue.fallback_routed_packets,
            worker_striped_flow_packets = queue.striped_flow_packets,
            worker_fallback_unsupported_link_packets = queue.fallback_unsupported_link_packets,
            worker_fallback_non_ip_packets = queue.fallback_non_ip_packets,
            worker_fallback_malformed_packets = queue.fallback_malformed_packets,
            worker_fallback_fragmented_packets = queue.fallback_fragmented_packets,
            worker_fallback_unsupported_transport_packets =
                queue.fallback_unsupported_transport_packets,
            worker_packet_skew_ratio = queue.worker_packet_skew_ratio(),
            worker_byte_skew_ratio = queue.worker_byte_skew_ratio(),
            stream_offload_workers = stats.stream_offload_workers,
            stream_offload_queue_max_len = stats.stream_offload_queue_max_len,
            stream_offload_queue_max_capacity = stats.stream_offload_queue_max_capacity,
            stream_offload_submitted_chunks = stats.stream_offload_submitted_chunks,
            stream_offload_submitted_bytes = stats.stream_offload_submitted_bytes,
            stream_offload_processed_chunks = stats.stream_offload_processed_chunks,
            stream_offload_processed_bytes = stats.stream_offload_processed_bytes,
            "Pipeline health"
        );

        self.previous = current;
        Ok(true)
    }
}

impl HealthTotals {
    fn from_stats(stats: &PipelineStats) -> Self {
        Self {
            packets: stats.packets,
            bytes: stats.bytes,
            events: stats.events,
            source_received_packets: stats.source_received_packets,
            source_dropped_packets: stats.source_dropped_packets,
            source_interface_dropped_packets: stats.source_interface_dropped_packets,
        }
    }
}

impl HealthRates {
    fn between(previous: &HealthSample, current: &HealthSample) -> Self {
        let elapsed = current
            .at
            .duration_since(previous.at)
            .as_secs_f64()
            .max(f64::EPSILON);
        Self {
            packets_per_sec: rate(previous.totals.packets, current.totals.packets, elapsed),
            bytes_per_sec: rate(previous.totals.bytes, current.totals.bytes, elapsed),
            events_per_sec: rate(previous.totals.events, current.totals.events, elapsed),
            source_received_per_sec: rate(
                previous.totals.source_received_packets,
                current.totals.source_received_packets,
                elapsed,
            ),
            source_dropped_per_sec: rate(
                previous.totals.source_dropped_packets,
                current.totals.source_dropped_packets,
                elapsed,
            ),
            source_interface_dropped_per_sec: rate(
                previous.totals.source_interface_dropped_packets,
                current.totals.source_interface_dropped_packets,
                elapsed,
            ),
        }
    }
}

impl ShardedQueueSnapshot {
    pub fn summarize(&self) -> PipelineQueueSnapshot {
        let max_worker_queue = self
            .workers
            .iter()
            .max_by_key(|worker| worker.len)
            .map(|worker| (worker.len, worker.capacity))
            .unwrap_or_default();
        let total_packets = self
            .workers
            .iter()
            .map(|worker| worker.routed_packets)
            .sum::<u64>();
        let total_bytes = self
            .workers
            .iter()
            .map(|worker| worker.routed_bytes)
            .sum::<u64>();
        let fallback_packets = self
            .workers
            .iter()
            .map(|worker| worker.fallback_packets)
            .sum::<u64>();
        let striped_flow_packets = self
            .workers
            .iter()
            .map(|worker| worker.striped_flow_packets)
            .sum::<u64>();
        let fallback_unsupported_link_packets = self
            .workers
            .iter()
            .map(|worker| worker.fallback_unsupported_link_packets)
            .sum::<u64>();
        let fallback_non_ip_packets = self
            .workers
            .iter()
            .map(|worker| worker.fallback_non_ip_packets)
            .sum::<u64>();
        let fallback_malformed_packets = self
            .workers
            .iter()
            .map(|worker| worker.fallback_malformed_packets)
            .sum::<u64>();
        let fallback_fragmented_packets = self
            .workers
            .iter()
            .map(|worker| worker.fallback_fragmented_packets)
            .sum::<u64>();
        let fallback_unsupported_transport_packets = self
            .workers
            .iter()
            .map(|worker| worker.fallback_unsupported_transport_packets)
            .sum::<u64>();
        let busiest = (total_packets != 0)
            .then(|| {
                self.workers
                    .iter()
                    .max_by_key(|worker| worker.routed_packets)
            })
            .flatten();
        let busiest_bytes = (total_bytes != 0)
            .then(|| self.workers.iter().max_by_key(|worker| worker.routed_bytes))
            .flatten();
        let busiest_packets = busiest.map_or(0, |worker| worker.routed_packets);
        let busiest_worker_bytes = busiest_bytes.map_or(0, |worker| worker.routed_bytes);

        PipelineQueueSnapshot {
            output_queue_len: self.output_queue_len,
            output_queue_capacity: self.output_queue_capacity,
            max_worker_queue_len: max_worker_queue.0,
            max_worker_queue_capacity: max_worker_queue.1,
            busiest_worker: busiest.map(|worker| worker.id),
            busiest_worker_packets: busiest_packets,
            busiest_worker_bytes,
            fallback_routed_packets: fallback_packets,
            striped_flow_packets,
            fallback_unsupported_link_packets,
            fallback_non_ip_packets,
            fallback_malformed_packets,
            fallback_fragmented_packets,
            fallback_unsupported_transport_packets,
            worker_packet_skew_ratio_milli: skew_ratio_milli(
                busiest_packets,
                total_packets,
                self.workers.len(),
            ),
            worker_byte_skew_ratio_milli: skew_ratio_milli(
                busiest_worker_bytes,
                total_bytes,
                self.workers.len(),
            ),
        }
    }

    pub fn pressure(&self) -> ShardPressureSnapshot {
        const WATCH_PACKET_SKEW_MILLI: u64 = 1_800;
        const HOT_PACKET_SKEW_MILLI: u64 = 3_000;
        const WATCH_BYTE_SKEW_MILLI: u64 = 2_200;
        const HOT_BYTE_SKEW_MILLI: u64 = 3_500;
        const WATCH_QUEUE_FILL_MILLI: u64 = 600;
        const HOT_QUEUE_FILL_MILLI: u64 = 750;
        const SATURATED_QUEUE_FILL_MILLI: u64 = 900;
        const WATCH_FALLBACK_RATIO_MILLI: u64 = 10;

        let summary = self.summarize();
        let routed_packets = self
            .workers
            .iter()
            .map(|worker| worker.routed_packets)
            .sum::<u64>();
        let routed_bytes = self
            .workers
            .iter()
            .map(|worker| worker.routed_bytes)
            .sum::<u64>();
        let fallback_ratio_milli = ratio_milli(summary.fallback_routed_packets, routed_packets);
        let max_worker_queue_fill_milli = ratio_milli(
            summary.max_worker_queue_len as u64,
            summary.max_worker_queue_capacity as u64,
        );
        let output_queue_fill_milli = ratio_milli(
            summary.output_queue_len as u64,
            summary.output_queue_capacity as u64,
        );
        let mut warnings = Vec::new();

        if self.workers.len() <= 1 && routed_packets != 0 {
            warnings.push(ShardPressureWarning::SingleShard);
        }
        if summary.worker_packet_skew_ratio_milli >= WATCH_PACKET_SKEW_MILLI {
            warnings.push(ShardPressureWarning::PacketSkew);
        }
        if summary.worker_byte_skew_ratio_milli >= WATCH_BYTE_SKEW_MILLI {
            warnings.push(ShardPressureWarning::ByteSkew);
        }
        if summary.striped_flow_packets != 0 {
            warnings.push(ShardPressureWarning::ElephantFlow);
        }
        if max_worker_queue_fill_milli >= WATCH_QUEUE_FILL_MILLI {
            warnings.push(ShardPressureWarning::WorkerQueuePressure);
        }
        if output_queue_fill_milli >= WATCH_QUEUE_FILL_MILLI {
            warnings.push(ShardPressureWarning::OutputQueuePressure);
        }
        if fallback_ratio_milli >= WATCH_FALLBACK_RATIO_MILLI {
            warnings.push(ShardPressureWarning::FallbackRoutes);
        }
        if summary.fallback_malformed_packets != 0 {
            warnings.push(ShardPressureWarning::MalformedFallback);
        }

        let state = if routed_packets == 0 {
            ShardPressureState::Idle
        } else if max_worker_queue_fill_milli >= SATURATED_QUEUE_FILL_MILLI
            || output_queue_fill_milli >= SATURATED_QUEUE_FILL_MILLI
        {
            ShardPressureState::Saturated
        } else if summary.worker_packet_skew_ratio_milli >= HOT_PACKET_SKEW_MILLI
            || summary.worker_byte_skew_ratio_milli >= HOT_BYTE_SKEW_MILLI
            || max_worker_queue_fill_milli >= HOT_QUEUE_FILL_MILLI
            || output_queue_fill_milli >= HOT_QUEUE_FILL_MILLI
        {
            ShardPressureState::Hot
        } else if warnings.is_empty() {
            ShardPressureState::Healthy
        } else {
            ShardPressureState::Watch
        };

        ShardPressureSnapshot {
            state,
            shard_count: self.workers.len(),
            routed_packets,
            routed_bytes,
            fallback_packets: summary.fallback_routed_packets,
            striped_flow_packets: summary.striped_flow_packets,
            fallback_ratio_milli,
            max_worker_queue_fill_milli,
            output_queue_fill_milli,
            busiest_shard: summary.busiest_worker,
            busiest_shard_packets: summary.busiest_worker_packets,
            busiest_shard_bytes: summary.busiest_worker_bytes,
            hot_flow: summary
                .busiest_worker
                .and_then(|id| self.workers.iter().find(|worker| worker.id == id))
                .and_then(|worker| worker.hot_flow.clone()),
            packet_skew_ratio_milli: summary.worker_packet_skew_ratio_milli,
            byte_skew_ratio_milli: summary.worker_byte_skew_ratio_milli,
            warnings,
        }
    }
}

impl PipelineQueueSnapshot {
    pub fn worker_packet_skew_ratio(self) -> f64 {
        self.worker_packet_skew_ratio_milli as f64 / 1000.0
    }

    pub fn worker_byte_skew_ratio(self) -> f64 {
        self.worker_byte_skew_ratio_milli as f64 / 1000.0
    }
}

fn rate(previous: u64, current: u64, elapsed_secs: f64) -> f64 {
    current.saturating_sub(previous) as f64 / elapsed_secs
}

fn skew_ratio_milli(max: u64, total: u64, shard_count: usize) -> u64 {
    if total == 0 || shard_count == 0 {
        return 0;
    }

    max.saturating_mul(shard_count as u64).saturating_mul(1000) / total
}

fn ratio_milli(part: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }

    part.saturating_mul(1000) / total
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_queue_pressure_and_skew() {
        let snapshot = ShardedQueueSnapshot {
            output_queue_len: 3,
            output_queue_capacity: 16,
            workers: vec![
                WorkerQueueSnapshot {
                    id: 0,
                    len: 1,
                    capacity: 8,
                    routed_packets: 100,
                    routed_bytes: 1000,
                    flow_routed_packets: 90,
                    fallback_packets: 10,
                    fallback_non_ip_packets: 4,
                    fallback_malformed_packets: 6,
                    ..WorkerQueueSnapshot::default()
                },
                WorkerQueueSnapshot {
                    id: 1,
                    len: 7,
                    capacity: 8,
                    routed_packets: 300,
                    routed_bytes: 7000,
                    flow_routed_packets: 280,
                    fallback_packets: 20,
                    fallback_non_ip_packets: 8,
                    fallback_malformed_packets: 12,
                    ..WorkerQueueSnapshot::default()
                },
            ],
        };

        let summary = snapshot.summarize();

        assert_eq!(3, summary.output_queue_len);
        assert_eq!(16, summary.output_queue_capacity);
        assert_eq!(7, summary.max_worker_queue_len);
        assert_eq!(8, summary.max_worker_queue_capacity);
        assert_eq!(Some(1), summary.busiest_worker);
        assert_eq!(300, summary.busiest_worker_packets);
        assert_eq!(7000, summary.busiest_worker_bytes);
        assert_eq!(30, summary.fallback_routed_packets);
        assert_eq!(12, summary.fallback_non_ip_packets);
        assert_eq!(18, summary.fallback_malformed_packets);
        assert_eq!(1500, summary.worker_packet_skew_ratio_milli);
        assert_eq!(1750, summary.worker_byte_skew_ratio_milli);
        assert_eq!(1.5, summary.worker_packet_skew_ratio());
        assert_eq!(1.75, summary.worker_byte_skew_ratio());
    }

    #[test]
    fn classifies_shard_pressure_from_queue_snapshot() {
        let snapshot = ShardedQueueSnapshot {
            output_queue_len: 1,
            output_queue_capacity: 16,
            workers: vec![
                WorkerQueueSnapshot {
                    id: 0,
                    len: 1,
                    capacity: 8,
                    routed_packets: 100,
                    routed_bytes: 1_000,
                    flow_routed_packets: 100,
                    ..WorkerQueueSnapshot::default()
                },
                WorkerQueueSnapshot {
                    id: 1,
                    len: 7,
                    capacity: 8,
                    routed_packets: 900,
                    routed_bytes: 9_000,
                    flow_routed_packets: 880,
                    fallback_packets: 20,
                    fallback_malformed_packets: 5,
                    ..WorkerQueueSnapshot::default()
                },
            ],
        };

        let pressure = snapshot.pressure();

        assert_eq!(ShardPressureState::Hot, pressure.state);
        assert_eq!(Some(1), pressure.busiest_shard);
        assert_eq!(900, pressure.busiest_shard_packets);
        assert_eq!(1_800, pressure.packet_skew_ratio_milli);
        assert_eq!(875, pressure.max_worker_queue_fill_milli);
        assert!(
            pressure
                .warnings
                .contains(&ShardPressureWarning::PacketSkew)
        );
        assert!(
            pressure
                .warnings
                .contains(&ShardPressureWarning::WorkerQueuePressure)
        );
        assert!(
            pressure
                .warnings
                .contains(&ShardPressureWarning::MalformedFallback)
        );
    }

    #[test]
    fn computes_delta_rates() {
        let previous = HealthSample {
            totals: HealthTotals {
                packets: 100,
                bytes: 1000,
                events: 10,
                source_received_packets: 100,
                source_dropped_packets: 2,
                source_interface_dropped_packets: 1,
            },
            at: Instant::now(),
        };
        let current = HealthSample {
            totals: HealthTotals {
                packets: 300,
                bytes: 5000,
                events: 50,
                source_received_packets: 320,
                source_dropped_packets: 8,
                source_interface_dropped_packets: 3,
            },
            at: previous.at + Duration::from_secs(2),
        };

        let rates = HealthRates::between(&previous, &current);

        assert_eq!(100.0, rates.packets_per_sec);
        assert_eq!(2000.0, rates.bytes_per_sec);
        assert_eq!(20.0, rates.events_per_sec);
        assert_eq!(110.0, rates.source_received_per_sec);
        assert_eq!(3.0, rates.source_dropped_per_sec);
        assert_eq!(1.0, rates.source_interface_dropped_per_sec);
    }

    #[test]
    fn leaves_busiest_worker_empty_before_any_routing() {
        let snapshot = ShardedQueueSnapshot {
            output_queue_len: 0,
            output_queue_capacity: 16,
            workers: vec![
                WorkerQueueSnapshot {
                    id: 0,
                    len: 0,
                    capacity: 8,
                    routed_packets: 0,
                    routed_bytes: 0,
                    flow_routed_packets: 0,
                    fallback_packets: 0,
                    ..WorkerQueueSnapshot::default()
                },
                WorkerQueueSnapshot {
                    id: 1,
                    len: 0,
                    capacity: 8,
                    routed_packets: 0,
                    routed_bytes: 0,
                    flow_routed_packets: 0,
                    fallback_packets: 0,
                    ..WorkerQueueSnapshot::default()
                },
            ],
        };

        let summary = snapshot.summarize();

        assert_eq!(None, summary.busiest_worker);
        assert_eq!(0, summary.busiest_worker_packets);
        assert_eq!(0, summary.busiest_worker_bytes);
        assert_eq!(0.0, summary.worker_packet_skew_ratio());
        assert_eq!(0.0, summary.worker_byte_skew_ratio());
    }
}
