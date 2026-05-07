use clap::Parser;
use std::path::PathBuf;

use crate::config::{
    DEFAULT_BATCH_SIZE, DEFAULT_CAPTURE_BUFFER_SIZE, DEFAULT_CAPTURE_READ_TIMEOUT_MS,
    DEFAULT_CAPTURE_SNAPLEN, DEFAULT_EVENT_QUEUE_DEPTH, DEFAULT_FLOW_IDLE_TIMEOUT_MS,
    DEFAULT_HEALTH_INTERVAL_MS, DEFAULT_MAX_FLOWS, DEFAULT_MAX_PATTERN_MATCHES_PER_STREAM,
    DEFAULT_MAX_PATTERN_MATCHES_TOTAL, DEFAULT_MAX_STREAM_CONTENT_BYTES,
    DEFAULT_MAX_STREAM_CONTENT_BYTES_PER_STREAM, DEFAULT_MAX_STREAM_VIEW_MATCHES_PER_STREAM,
    DEFAULT_MAX_STREAMS, DEFAULT_MAX_TCP_BUFFERED_BYTES_PER_FLOW,
    DEFAULT_MAX_TCP_OUT_OF_ORDER_SEGMENTS_PER_DIRECTION, DEFAULT_PATTERN_REGEX_WINDOW_BYTES,
    DEFAULT_STREAM_CONTENT_SEGMENT_BYTES, DEFAULT_STREAM_PREVIEW_BYTES,
    DEFAULT_STREAM_UPDATE_BYTES, DEFAULT_STREAM_UPDATE_PACKETS, DEFAULT_STREAM_VIEW_QUERY_LIMIT,
    DEFAULT_WORKER_QUEUE_DEPTH, DEFAULT_WORKERS, RunMode,
};

/// CLI opts, kept flat so the tool stays script-friendly.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Opts {
    /// Path to an offline pcap file
    #[arg(short, long)]
    pub pcap: Option<PathBuf>,

    /// Interface name for live capture
    #[arg(short = 'i', long)]
    pub iface: Option<String>,

    /// List capture interfaces and exit
    #[arg(long)]
    pub list_interfaces: bool,

    /// JSONL output path
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Run mode: analyze | dump
    #[arg(short, long, value_enum, default_value_t = RunMode::Analyze)]
    pub mode: RunMode,

    /// Packets per ingest batch
    #[arg(long, default_value_t = DEFAULT_BATCH_SIZE)]
    pub batch_size: usize,

    /// Max flow states kept in memory
    #[arg(long, default_value_t = DEFAULT_MAX_FLOWS)]
    pub max_flows: usize,

    /// Flow idle timeout in milliseconds
    #[arg(long, default_value_t = DEFAULT_FLOW_IDLE_TIMEOUT_MS)]
    pub flow_idle_timeout_ms: u64,

    /// Out-of-order TCP payload byte limit per flow
    #[arg(long, default_value_t = DEFAULT_MAX_TCP_BUFFERED_BYTES_PER_FLOW)]
    pub max_tcp_buffered_bytes_per_flow: usize,

    /// Out-of-order TCP segment limit per flow direction
    #[arg(long, default_value_t = DEFAULT_MAX_TCP_OUT_OF_ORDER_SEGMENTS_PER_DIRECTION)]
    pub max_tcp_out_of_order_segments_per_direction: usize,

    /// Flow-shard worker threads; 0 means auto
    #[arg(long, default_value_t = DEFAULT_WORKERS)]
    pub workers: usize,

    /// Bounded input queue depth per worker shard
    #[arg(long, default_value_t = DEFAULT_WORKER_QUEUE_DEPTH)]
    pub worker_queue_depth: usize,

    /// Bounded event batch queue depth from workers to output
    #[arg(long, default_value_t = DEFAULT_EVENT_QUEUE_DEPTH)]
    pub event_queue_depth: usize,

    /// Disable stream inventory events and counters
    #[arg(long)]
    pub disable_stream_inventory: bool,

    /// Max stream inventory records kept in memory
    #[arg(long, default_value_t = DEFAULT_MAX_STREAMS)]
    pub max_streams: usize,

    /// Preview bytes kept per stream direction
    #[arg(long, default_value_t = DEFAULT_STREAM_PREVIEW_BYTES)]
    pub stream_preview_bytes: usize,

    /// Emit stream update after N packets in a stream; 0 disables this trigger
    #[arg(long, default_value_t = DEFAULT_STREAM_UPDATE_PACKETS)]
    pub stream_update_packets: u64,

    /// Emit stream update after N reassembled bytes in a stream; 0 disables this trigger
    #[arg(long, default_value_t = DEFAULT_STREAM_UPDATE_BYTES)]
    pub stream_update_bytes: u64,

    /// Disable bounded stream content storage
    #[arg(long)]
    pub disable_stream_content: bool,

    /// Max stored stream content bytes across all streams
    #[arg(long, default_value_t = DEFAULT_MAX_STREAM_CONTENT_BYTES)]
    pub max_stream_content_bytes: usize,

    /// Max stored stream content bytes per stream
    #[arg(long, default_value_t = DEFAULT_MAX_STREAM_CONTENT_BYTES_PER_STREAM)]
    pub max_stream_content_bytes_per_stream: usize,

    /// Max bytes per stored stream content segment
    #[arg(long, default_value_t = DEFAULT_STREAM_CONTENT_SEGMENT_BYTES)]
    pub stream_content_segment_bytes: usize,

    /// Substring pattern to match in stream content; repeatable
    #[arg(long = "pattern")]
    pub patterns: Vec<String>,

    /// Regex pattern to match in stream content; repeatable
    #[arg(long = "regex")]
    pub regex_patterns: Vec<String>,

    /// Binary hex pattern to match in stream content; repeatable
    #[arg(long = "binary-pattern")]
    pub binary_patterns: Vec<String>,

    /// Max emitted pattern matches per stream
    #[arg(long, default_value_t = DEFAULT_MAX_PATTERN_MATCHES_PER_STREAM)]
    pub max_pattern_matches_per_stream: u64,

    /// Max emitted pattern matches across the run
    #[arg(long, default_value_t = DEFAULT_MAX_PATTERN_MATCHES_TOTAL)]
    pub max_pattern_matches_total: u64,

    /// Regex lookbehind window bytes for boundary-spanning matches
    #[arg(long, default_value_t = DEFAULT_PATTERN_REGEX_WINDOW_BYTES)]
    pub pattern_regex_window_bytes: usize,

    /// Disable in-memory stream view indexes for future UI/query layers
    #[arg(long)]
    pub disable_stream_view: bool,

    /// Max retained pattern match ranges per stream in the view index
    #[arg(long, default_value_t = DEFAULT_MAX_STREAM_VIEW_MATCHES_PER_STREAM)]
    pub max_stream_view_matches_per_stream: usize,

    /// Max streams returned by one stream view query
    #[arg(long, default_value_t = DEFAULT_STREAM_VIEW_QUERY_LIMIT)]
    pub stream_view_query_limit: usize,

    /// Health log interval in milliseconds; 0 disables it
    #[arg(long, default_value_t = DEFAULT_HEALTH_INTERVAL_MS)]
    pub health_interval_ms: u64,

    /// BPF filter for live capture
    #[arg(long, alias = "bpf")]
    pub capture_filter: Option<String>,

    /// Live capture snaplen
    #[arg(long, default_value_t = DEFAULT_CAPTURE_SNAPLEN)]
    pub capture_snaplen: usize,

    /// Kernel/libpcap capture buffer size in bytes
    #[arg(long, default_value_t = DEFAULT_CAPTURE_BUFFER_SIZE)]
    pub capture_buffer_size: usize,

    /// Live capture read timeout in milliseconds
    #[arg(long, default_value_t = DEFAULT_CAPTURE_READ_TIMEOUT_MS)]
    pub capture_read_timeout_ms: usize,

    /// Enable promiscuous mode for live capture
    #[arg(long)]
    pub promisc: bool,

    /// Enable immediate mode for live capture
    #[arg(long)]
    pub immediate: bool,

    /// Stop live capture after N packets
    #[arg(long)]
    pub max_packets: Option<u64>,
}
