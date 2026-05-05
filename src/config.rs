use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;

use clap::ValueEnum;

pub const DEFAULT_BATCH_SIZE: usize = 4096;
pub const DEFAULT_MAX_FLOWS: usize = 1_000_000;
pub const DEFAULT_FLOW_IDLE_TIMEOUT_MS: u64 = 120_000;
pub const DEFAULT_MAX_TCP_BUFFERED_BYTES_PER_FLOW: usize = 1 << 20;
pub const DEFAULT_MAX_TCP_OUT_OF_ORDER_SEGMENTS_PER_DIRECTION: usize = 128;
pub const DEFAULT_WORKERS: usize = 0;
pub const DEFAULT_WORKER_QUEUE_DEPTH: usize = 4096;
pub const DEFAULT_EVENT_QUEUE_DEPTH: usize = 4096;
pub const DEFAULT_CAPTURE_SNAPLEN: usize = 262_144;
pub const DEFAULT_CAPTURE_BUFFER_SIZE: usize = 64 * 1024 * 1024;
pub const DEFAULT_CAPTURE_READ_TIMEOUT_MS: usize = 100;
pub const DEFAULT_HEALTH_INTERVAL_MS: u64 = 1_000;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    Analyze,
    Dump,
}

impl fmt::Display for RunMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RunMode::Analyze => f.write_str("analyze"),
            RunMode::Dump => f.write_str("dump"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub output_json: PathBuf,
    pub sqlite_path: Option<String>,
    pub plugin_dir: Option<String>,
    pub batch_size: usize,
    pub max_flows: usize,
    pub flow_idle_timeout_ms: u64,
    pub max_tcp_buffered_bytes_per_flow: usize,
    pub max_tcp_out_of_order_segments_per_direction: usize,
    pub workers: usize,
    pub worker_queue_depth: usize,
    pub event_queue_depth: usize,
    pub capture_snaplen: usize,
    pub capture_buffer_size: usize,
    pub capture_read_timeout_ms: usize,
    pub health_interval_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            output_json: PathBuf::from("out.jsonl"),
            sqlite_path: None,
            plugin_dir: None,
            batch_size: DEFAULT_BATCH_SIZE,
            max_flows: DEFAULT_MAX_FLOWS,
            flow_idle_timeout_ms: DEFAULT_FLOW_IDLE_TIMEOUT_MS,
            max_tcp_buffered_bytes_per_flow: DEFAULT_MAX_TCP_BUFFERED_BYTES_PER_FLOW,
            max_tcp_out_of_order_segments_per_direction:
                DEFAULT_MAX_TCP_OUT_OF_ORDER_SEGMENTS_PER_DIRECTION,
            workers: DEFAULT_WORKERS,
            worker_queue_depth: DEFAULT_WORKER_QUEUE_DEPTH,
            event_queue_depth: DEFAULT_EVENT_QUEUE_DEPTH,
            capture_snaplen: DEFAULT_CAPTURE_SNAPLEN,
            capture_buffer_size: DEFAULT_CAPTURE_BUFFER_SIZE,
            capture_read_timeout_ms: DEFAULT_CAPTURE_READ_TIMEOUT_MS,
            health_interval_ms: DEFAULT_HEALTH_INTERVAL_MS,
        }
    }
}
