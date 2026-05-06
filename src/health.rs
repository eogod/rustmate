use std::time::{Duration, Instant};

use anyhow::Result;

use crate::{ingest::PacketSourceStats, pipeline::PipelineStats};

#[derive(Debug, Clone)]
pub struct PipelineHealthReporter {
    interval: Option<Duration>,
    previous: HealthSample,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PipelineQueueSnapshot {
    pub output_queue_len: usize,
    pub output_queue_capacity: usize,
    pub max_worker_queue_len: usize,
    pub max_worker_queue_capacity: usize,
    pub busiest_worker: Option<usize>,
    pub busiest_worker_packets: u64,
    pub worker_packet_skew_ratio_milli: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerQueueSnapshot {
    pub id: usize,
    pub len: usize,
    pub capacity: usize,
    pub routed_packets: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardedQueueSnapshot {
    pub workers: Vec<WorkerQueueSnapshot>,
    pub output_queue_len: usize,
    pub output_queue_capacity: usize,
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
    ) -> Result<()>
    where
        F: FnOnce() -> Result<Option<PacketSourceStats>>,
    {
        let Some(interval) = self.interval else {
            return Ok(());
        };

        let now = Instant::now();
        if now.duration_since(self.previous.at) < interval {
            return Ok(());
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
            fallback_routed_packets = stats.fallback_routed_packets,
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
            tcp_gaps = stats.tcp_gaps,
            tcp_retransmissions = stats.tcp_retransmissions,
            tcp_out_of_order_dropped = stats.tcp_out_of_order_dropped,
            worker_queue_max_len = queue.max_worker_queue_len,
            worker_queue_max_capacity = queue.max_worker_queue_capacity,
            output_queue_len = queue.output_queue_len,
            output_queue_capacity = queue.output_queue_capacity,
            busiest_worker = queue.busiest_worker,
            busiest_worker_packets = queue.busiest_worker_packets,
            worker_packet_skew_ratio = queue.worker_packet_skew_ratio(),
            "Pipeline health"
        );

        self.previous = current;
        Ok(())
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
        let busiest = (total_packets != 0)
            .then(|| {
                self.workers
                    .iter()
                    .max_by_key(|worker| worker.routed_packets)
            })
            .flatten();
        let average_packets = if self.workers.is_empty() {
            0
        } else {
            total_packets / self.workers.len() as u64
        };
        let busiest_packets = busiest.map_or(0, |worker| worker.routed_packets);

        PipelineQueueSnapshot {
            output_queue_len: self.output_queue_len,
            output_queue_capacity: self.output_queue_capacity,
            max_worker_queue_len: max_worker_queue.0,
            max_worker_queue_capacity: max_worker_queue.1,
            busiest_worker: busiest.map(|worker| worker.id),
            busiest_worker_packets: busiest_packets,
            worker_packet_skew_ratio_milli: skew_ratio_milli(busiest_packets, average_packets),
        }
    }
}

impl PipelineQueueSnapshot {
    pub fn worker_packet_skew_ratio(self) -> f64 {
        self.worker_packet_skew_ratio_milli as f64 / 1000.0
    }
}

fn rate(previous: u64, current: u64, elapsed_secs: f64) -> f64 {
    current.saturating_sub(previous) as f64 / elapsed_secs
}

fn skew_ratio_milli(max: u64, average: u64) -> u64 {
    if average == 0 {
        return 0;
    }

    max.saturating_mul(1000) / average
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
                },
                WorkerQueueSnapshot {
                    id: 1,
                    len: 7,
                    capacity: 8,
                    routed_packets: 300,
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
        assert_eq!(1500, summary.worker_packet_skew_ratio_milli);
        assert_eq!(1.5, summary.worker_packet_skew_ratio());
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
                },
                WorkerQueueSnapshot {
                    id: 1,
                    len: 0,
                    capacity: 8,
                    routed_packets: 0,
                },
            ],
        };

        let summary = snapshot.summarize();

        assert_eq!(None, summary.busiest_worker);
        assert_eq!(0, summary.busiest_worker_packets);
        assert_eq!(0.0, summary.worker_packet_skew_ratio());
    }
}
