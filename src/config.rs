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
pub const DEFAULT_MAX_STREAMS: usize = DEFAULT_MAX_FLOWS;
pub const DEFAULT_STREAM_PREVIEW_BYTES: usize = 256;
pub const DEFAULT_STREAM_UPDATE_PACKETS: u64 = 64;
pub const DEFAULT_STREAM_UPDATE_BYTES: u64 = 64 * 1024;
pub const DEFAULT_MAX_STREAM_CONTENT_BYTES: usize = 256 * 1024 * 1024;
pub const DEFAULT_MAX_STREAM_CONTENT_BYTES_PER_STREAM: usize = 8 * 1024 * 1024;
pub const DEFAULT_STREAM_CONTENT_SEGMENT_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_PATTERN_MATCHES_PER_STREAM: u64 = 1024;
pub const DEFAULT_MAX_PATTERN_MATCHES_TOTAL: u64 = 1_000_000;
pub const DEFAULT_PATTERN_REGEX_WINDOW_BYTES: usize = 4096;
pub const DEFAULT_MAX_STREAM_VIEW_MATCHES_PER_STREAM: usize = 256;
pub const DEFAULT_STREAM_VIEW_QUERY_LIMIT: usize = 512;
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
    pub stream_inventory_enabled: bool,
    pub max_streams: usize,
    pub stream_preview_bytes: usize,
    pub stream_update_packets: u64,
    pub stream_update_bytes: u64,
    pub stream_content_enabled: bool,
    pub max_stream_content_bytes: usize,
    pub max_stream_content_bytes_per_stream: usize,
    pub stream_content_segment_bytes: usize,
    pub max_pattern_matches_per_stream: u64,
    pub max_pattern_matches_total: u64,
    pub pattern_regex_window_bytes: usize,
    pub stream_view_enabled: bool,
    pub max_stream_view_matches_per_stream: usize,
    pub stream_view_query_limit: usize,
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
            stream_inventory_enabled: true,
            max_streams: DEFAULT_MAX_STREAMS,
            stream_preview_bytes: DEFAULT_STREAM_PREVIEW_BYTES,
            stream_update_packets: DEFAULT_STREAM_UPDATE_PACKETS,
            stream_update_bytes: DEFAULT_STREAM_UPDATE_BYTES,
            stream_content_enabled: true,
            max_stream_content_bytes: DEFAULT_MAX_STREAM_CONTENT_BYTES,
            max_stream_content_bytes_per_stream: DEFAULT_MAX_STREAM_CONTENT_BYTES_PER_STREAM,
            stream_content_segment_bytes: DEFAULT_STREAM_CONTENT_SEGMENT_BYTES,
            max_pattern_matches_per_stream: DEFAULT_MAX_PATTERN_MATCHES_PER_STREAM,
            max_pattern_matches_total: DEFAULT_MAX_PATTERN_MATCHES_TOTAL,
            pattern_regex_window_bytes: DEFAULT_PATTERN_REGEX_WINDOW_BYTES,
            stream_view_enabled: true,
            max_stream_view_matches_per_stream: DEFAULT_MAX_STREAM_VIEW_MATCHES_PER_STREAM,
            stream_view_query_limit: DEFAULT_STREAM_VIEW_QUERY_LIMIT,
            capture_snaplen: DEFAULT_CAPTURE_SNAPLEN,
            capture_buffer_size: DEFAULT_CAPTURE_BUFFER_SIZE,
            capture_read_timeout_ms: DEFAULT_CAPTURE_READ_TIMEOUT_MS,
            health_interval_ms: DEFAULT_HEALTH_INTERVAL_MS,
        }
    }
}
