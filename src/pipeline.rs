use std::sync::{Arc, RwLock};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::{
    analyzers::Analyzer,
    api::LiveApiHandle,
    config::RunMode,
    event::Event,
    flow::{FlowTable, FlowTableConfig, FlowTableStats},
    health::PipelineHealthReporter,
    ingest::{PacketBatch, PacketSource, PacketSourceStats},
    output::EventSink,
    packet::{DecodedPacket, PacketDecodeCounters, PacketDecodeStatus, RawPacket},
    pattern::{PatternEngine, PatternEngineConfig, PatternEngineStats},
    stream_content::{StreamContent, StreamContentConfig, StreamContentStats},
    stream_inventory::{StreamInventory, StreamInventoryConfig, StreamInventoryStats},
    stream_message::{StreamMessageStats, StreamMessageStore},
    stream_parser::{StreamParserConfig, StreamParserLayer, StreamParserStats},
    stream_slice::{
        StreamContentSlice, StreamSliceConfig, StreamSliceError, StreamSliceReader,
        StreamSliceRequest,
    },
    stream_view::{StreamViewConfig, StreamViewState, StreamViewStats},
};

#[derive(Debug, Default, Clone, Copy, Deserialize, Serialize)]
pub struct PipelineStats {
    pub workers: usize,
    pub batches: u64,
    pub packets: u64,
    pub bytes: u64,
    pub events: u64,
    pub decode_errors: u64,
    #[serde(flatten)]
    pub packet_decode: PacketDecodeCounters,
    pub fallback_routed_packets: u64,
    pub striped_flow_packets: u64,
    pub fallback_unsupported_link_packets: u64,
    pub fallback_non_ip_packets: u64,
    pub fallback_malformed_packets: u64,
    pub fallback_fragmented_packets: u64,
    pub fallback_unsupported_transport_packets: u64,
    pub busiest_shard: Option<usize>,
    pub busiest_shard_packets: u64,
    pub busiest_shard_bytes: u64,
    pub shard_packet_skew_ratio_milli: u64,
    pub shard_byte_skew_ratio_milli: u64,
    pub output_queue_len: usize,
    pub output_queue_capacity: usize,
    pub worker_queue_max_len: usize,
    pub worker_queue_max_capacity: usize,
    pub busiest_worker: Option<usize>,
    pub busiest_worker_packets: u64,
    pub busiest_worker_bytes: u64,
    pub worker_fallback_routed_packets: u64,
    pub worker_striped_flow_packets: u64,
    pub worker_fallback_unsupported_link_packets: u64,
    pub worker_fallback_non_ip_packets: u64,
    pub worker_fallback_malformed_packets: u64,
    pub worker_fallback_fragmented_packets: u64,
    pub worker_fallback_unsupported_transport_packets: u64,
    pub worker_packet_skew_ratio_milli: u64,
    pub worker_byte_skew_ratio_milli: u64,
    pub stream_offload_workers: usize,
    pub stream_offload_queue_max_len: usize,
    pub stream_offload_queue_max_capacity: usize,
    pub stream_offload_submitted_chunks: u64,
    pub stream_offload_submitted_bytes: u64,
    pub stream_offload_processed_chunks: u64,
    pub stream_offload_processed_bytes: u64,
    pub source_received_packets: u64,
    pub source_dropped_packets: u64,
    pub source_interface_dropped_packets: u64,
    pub active_flows: usize,
    pub created_flows: u64,
    pub evicted_flows: u64,
    pub dropped_new_flows: u64,
    pub tcp_stream_chunks: u64,
    pub tcp_stream_bytes: u64,
    pub tcp_current_stream_chunks: u64,
    pub tcp_current_stream_bytes: u64,
    pub tcp_buffered_stream_chunks: u64,
    pub tcp_buffered_stream_bytes: u64,
    pub tcp_overlap_trimmed_stream_chunks: u64,
    pub tcp_overlap_trimmed_stream_bytes: u64,
    pub tcp_gaps: u64,
    pub tcp_retransmissions: u64,
    pub tcp_overlaps: u64,
    pub tcp_out_of_order_buffered: u64,
    pub tcp_out_of_order_buffered_bytes: u64,
    pub tcp_out_of_order_dropped: u64,
    pub tcp_out_of_order_dropped_bytes: u64,
    pub tcp_retransmitted_bytes: u64,
    pub tcp_overlap_trimmed_bytes: u64,
    pub tcp_reassembly_buffered_bytes_peak: usize,
    pub tcp_midstream_starts: u64,
    pub tcp_syns: u64,
    pub tcp_fins: u64,
    pub tcp_resets: u64,
    pub inventory_active_streams: usize,
    pub inventory_created_streams: u64,
    pub inventory_evicted_streams: u64,
    pub inventory_dropped_new_streams: u64,
    pub inventory_closed_streams: u64,
    pub inventory_events: u64,
    pub content_active_streams: usize,
    pub content_active_segments: usize,
    pub content_stored_bytes: usize,
    pub content_observed_bytes: u64,
    pub content_dropped_bytes: u64,
    pub content_evicted_streams: u64,
    pub content_truncated_streams: u64,
    pub content_updates: u64,
    pub content_merged_segments: u64,
    pub message_active_streams: usize,
    pub message_stored_messages: usize,
    pub message_dropped_messages: u64,
    pub message_observed_messages: u64,
    pub message_http1_messages: u64,
    pub message_dns_messages: u64,
    pub message_websocket_messages: u64,
    pub message_tls_messages: u64,
    pub message_parse_errors: u64,
    pub parser_enabled: bool,
    pub parser_stream_chunks: u64,
    pub parser_stream_bytes: u64,
    pub parser_emitted_messages: u64,
    pub parser_dropped_messages: u64,
    pub parser_active_states: usize,
    pub parser_evicted_states: u64,
    pub parser_http1_active_states: usize,
    pub parser_http1_messages: u64,
    pub parser_http1_parse_errors: u64,
    pub parser_http1_dropped_chunks: u64,
    pub parser_dns_active_states: usize,
    pub parser_dns_messages: u64,
    pub parser_dns_parse_errors: u64,
    pub parser_dns_dropped_datagrams: u64,
    pub parser_websocket_active_states: usize,
    pub parser_websocket_messages: u64,
    pub parser_websocket_parse_errors: u64,
    pub parser_websocket_dropped_chunks: u64,
    pub parser_tls_active_states: usize,
    pub parser_tls_messages: u64,
    pub parser_tls_parse_errors: u64,
    pub parser_tls_dropped_chunks: u64,
    pub pattern_matches: u64,
    pub pattern_dropped_matches: u64,
    pub pattern_matched_streams: usize,
    pub view_tracked_streams: usize,
    pub view_favorite_streams: usize,
    pub view_manually_hidden_streams: usize,
    pub view_matched_streams: usize,
    pub view_stored_matches: usize,
    pub view_dropped_matches: u64,
    pub view_orphan_matches: u64,
    pub view_evicted_streams: u64,
    pub view_hide_rules: usize,
}

impl PipelineStats {
    pub(crate) fn observe_packet_decode_status(&mut self, status: PacketDecodeStatus) {
        self.packet_decode.observe(status);
        if status.is_decode_error() {
            self.decode_errors = self.decode_errors.saturating_add(1);
        }
    }

    pub(crate) fn add_packet_decode_counters(&mut self, counters: PacketDecodeCounters) {
        self.packet_decode.add(counters);
        self.decode_errors = self
            .decode_errors
            .saturating_add(counters.decode_error_packets());
    }

    pub(crate) fn clear_worker_runtime_stats(&mut self) {
        self.packet_decode = PacketDecodeCounters::default();
        self.decode_errors = 0;
        self.set_flow_table_stats(FlowTableStats::default());
        self.set_stream_inventory_stats(StreamInventoryStats::default());
        self.set_stream_content_stats(StreamContentStats::default());
        self.set_stream_parser_stats(StreamParserStats::default());
        self.set_pattern_stats(PatternEngineStats::default());
        self.stream_offload_submitted_chunks = 0;
        self.stream_offload_submitted_bytes = 0;
        self.stream_offload_processed_chunks = 0;
        self.stream_offload_processed_bytes = 0;
    }

    pub(crate) fn set_flow_table_stats(&mut self, flow_stats: FlowTableStats) {
        self.active_flows = flow_stats.active_flows;
        self.created_flows = flow_stats.created_flows;
        self.evicted_flows = flow_stats.evicted_flows;
        self.dropped_new_flows = flow_stats.dropped_new_flows;
        self.tcp_stream_chunks = flow_stats.tcp_stream_chunks;
        self.tcp_stream_bytes = flow_stats.tcp_stream_bytes;
        self.tcp_current_stream_chunks = flow_stats.tcp_current_stream_chunks;
        self.tcp_current_stream_bytes = flow_stats.tcp_current_stream_bytes;
        self.tcp_buffered_stream_chunks = flow_stats.tcp_buffered_stream_chunks;
        self.tcp_buffered_stream_bytes = flow_stats.tcp_buffered_stream_bytes;
        self.tcp_overlap_trimmed_stream_chunks = flow_stats.tcp_overlap_trimmed_stream_chunks;
        self.tcp_overlap_trimmed_stream_bytes = flow_stats.tcp_overlap_trimmed_stream_bytes;
        self.tcp_gaps = flow_stats.tcp_gaps;
        self.tcp_retransmissions = flow_stats.tcp_retransmissions;
        self.tcp_overlaps = flow_stats.tcp_overlaps;
        self.tcp_out_of_order_buffered = flow_stats.tcp_out_of_order_buffered;
        self.tcp_out_of_order_buffered_bytes = flow_stats.tcp_out_of_order_buffered_bytes;
        self.tcp_out_of_order_dropped = flow_stats.tcp_out_of_order_dropped;
        self.tcp_out_of_order_dropped_bytes = flow_stats.tcp_out_of_order_dropped_bytes;
        self.tcp_retransmitted_bytes = flow_stats.tcp_retransmitted_bytes;
        self.tcp_overlap_trimmed_bytes = flow_stats.tcp_overlap_trimmed_bytes;
        self.tcp_reassembly_buffered_bytes_peak = flow_stats.tcp_reassembly_buffered_bytes_peak;
        self.tcp_midstream_starts = flow_stats.tcp_midstream_starts;
        self.tcp_syns = flow_stats.tcp_syns;
        self.tcp_fins = flow_stats.tcp_fins;
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
        self.tcp_current_stream_chunks = self
            .tcp_current_stream_chunks
            .saturating_add(flow_stats.tcp_current_stream_chunks);
        self.tcp_current_stream_bytes = self
            .tcp_current_stream_bytes
            .saturating_add(flow_stats.tcp_current_stream_bytes);
        self.tcp_buffered_stream_chunks = self
            .tcp_buffered_stream_chunks
            .saturating_add(flow_stats.tcp_buffered_stream_chunks);
        self.tcp_buffered_stream_bytes = self
            .tcp_buffered_stream_bytes
            .saturating_add(flow_stats.tcp_buffered_stream_bytes);
        self.tcp_overlap_trimmed_stream_chunks = self
            .tcp_overlap_trimmed_stream_chunks
            .saturating_add(flow_stats.tcp_overlap_trimmed_stream_chunks);
        self.tcp_overlap_trimmed_stream_bytes = self
            .tcp_overlap_trimmed_stream_bytes
            .saturating_add(flow_stats.tcp_overlap_trimmed_stream_bytes);
        self.tcp_gaps = self.tcp_gaps.saturating_add(flow_stats.tcp_gaps);
        self.tcp_retransmissions = self
            .tcp_retransmissions
            .saturating_add(flow_stats.tcp_retransmissions);
        self.tcp_overlaps = self.tcp_overlaps.saturating_add(flow_stats.tcp_overlaps);
        self.tcp_out_of_order_buffered = self
            .tcp_out_of_order_buffered
            .saturating_add(flow_stats.tcp_out_of_order_buffered);
        self.tcp_out_of_order_buffered_bytes = self
            .tcp_out_of_order_buffered_bytes
            .saturating_add(flow_stats.tcp_out_of_order_buffered_bytes);
        self.tcp_out_of_order_dropped = self
            .tcp_out_of_order_dropped
            .saturating_add(flow_stats.tcp_out_of_order_dropped);
        self.tcp_out_of_order_dropped_bytes = self
            .tcp_out_of_order_dropped_bytes
            .saturating_add(flow_stats.tcp_out_of_order_dropped_bytes);
        self.tcp_retransmitted_bytes = self
            .tcp_retransmitted_bytes
            .saturating_add(flow_stats.tcp_retransmitted_bytes);
        self.tcp_overlap_trimmed_bytes = self
            .tcp_overlap_trimmed_bytes
            .saturating_add(flow_stats.tcp_overlap_trimmed_bytes);
        self.tcp_reassembly_buffered_bytes_peak = self
            .tcp_reassembly_buffered_bytes_peak
            .max(flow_stats.tcp_reassembly_buffered_bytes_peak);
        self.tcp_midstream_starts = self
            .tcp_midstream_starts
            .saturating_add(flow_stats.tcp_midstream_starts);
        self.tcp_syns = self.tcp_syns.saturating_add(flow_stats.tcp_syns);
        self.tcp_fins = self.tcp_fins.saturating_add(flow_stats.tcp_fins);
        self.tcp_resets = self.tcp_resets.saturating_add(flow_stats.tcp_resets);
    }

    pub(crate) fn set_source_stats(&mut self, source_stats: PacketSourceStats) {
        self.source_received_packets = source_stats.received;
        self.source_dropped_packets = source_stats.dropped;
        self.source_interface_dropped_packets = source_stats.interface_dropped;
    }

    pub(crate) fn set_stream_inventory_stats(&mut self, inventory_stats: StreamInventoryStats) {
        self.inventory_active_streams = inventory_stats.active_streams;
        self.inventory_created_streams = inventory_stats.created_streams;
        self.inventory_evicted_streams = inventory_stats.evicted_streams;
        self.inventory_dropped_new_streams = inventory_stats.dropped_new_streams;
        self.inventory_closed_streams = inventory_stats.closed_streams;
        self.inventory_events = inventory_stats.stream_events;
    }

    pub(crate) fn add_stream_inventory_stats(&mut self, inventory_stats: StreamInventoryStats) {
        self.inventory_active_streams = self
            .inventory_active_streams
            .saturating_add(inventory_stats.active_streams);
        self.inventory_created_streams = self
            .inventory_created_streams
            .saturating_add(inventory_stats.created_streams);
        self.inventory_evicted_streams = self
            .inventory_evicted_streams
            .saturating_add(inventory_stats.evicted_streams);
        self.inventory_dropped_new_streams = self
            .inventory_dropped_new_streams
            .saturating_add(inventory_stats.dropped_new_streams);
        self.inventory_closed_streams = self
            .inventory_closed_streams
            .saturating_add(inventory_stats.closed_streams);
        self.inventory_events = self
            .inventory_events
            .saturating_add(inventory_stats.stream_events);
    }

    pub(crate) fn set_stream_content_stats(&mut self, content_stats: StreamContentStats) {
        self.content_active_streams = content_stats.active_content_streams;
        self.content_active_segments = content_stats.active_content_segments;
        self.content_stored_bytes = content_stats.stored_content_bytes;
        self.content_observed_bytes = content_stats.observed_content_bytes;
        self.content_dropped_bytes = content_stats.dropped_content_bytes;
        self.content_evicted_streams = content_stats.evicted_content_streams;
        self.content_truncated_streams = content_stats.truncated_content_streams;
        self.content_updates = content_stats.content_updates;
        self.content_merged_segments = content_stats.merged_content_segments;
    }

    pub(crate) fn add_stream_content_stats(&mut self, content_stats: StreamContentStats) {
        self.content_active_streams = self
            .content_active_streams
            .saturating_add(content_stats.active_content_streams);
        self.content_active_segments = self
            .content_active_segments
            .saturating_add(content_stats.active_content_segments);
        self.content_stored_bytes = self
            .content_stored_bytes
            .saturating_add(content_stats.stored_content_bytes);
        self.content_observed_bytes = self
            .content_observed_bytes
            .saturating_add(content_stats.observed_content_bytes);
        self.content_dropped_bytes = self
            .content_dropped_bytes
            .saturating_add(content_stats.dropped_content_bytes);
        self.content_evicted_streams = self
            .content_evicted_streams
            .saturating_add(content_stats.evicted_content_streams);
        self.content_truncated_streams = self
            .content_truncated_streams
            .saturating_add(content_stats.truncated_content_streams);
        self.content_updates = self
            .content_updates
            .saturating_add(content_stats.content_updates);
        self.content_merged_segments = self
            .content_merged_segments
            .saturating_add(content_stats.merged_content_segments);
    }

    pub(crate) fn set_pattern_stats(&mut self, pattern_stats: PatternEngineStats) {
        self.pattern_matches = pattern_stats.pattern_matches;
        self.pattern_dropped_matches = pattern_stats.pattern_dropped_matches;
        self.pattern_matched_streams = pattern_stats.pattern_matched_streams;
    }

    pub(crate) fn add_pattern_stats(&mut self, pattern_stats: PatternEngineStats) {
        self.pattern_matches = self
            .pattern_matches
            .saturating_add(pattern_stats.pattern_matches);
        self.pattern_dropped_matches = self
            .pattern_dropped_matches
            .saturating_add(pattern_stats.pattern_dropped_matches);
        self.pattern_matched_streams = self
            .pattern_matched_streams
            .saturating_add(pattern_stats.pattern_matched_streams);
    }

    pub(crate) fn set_stream_view_stats(&mut self, view_stats: StreamViewStats) {
        self.view_tracked_streams = view_stats.tracked_streams;
        self.view_favorite_streams = view_stats.favorite_streams;
        self.view_manually_hidden_streams = view_stats.manually_hidden_streams;
        self.view_matched_streams = view_stats.matched_streams;
        self.view_stored_matches = view_stats.stored_matches;
        self.view_dropped_matches = view_stats.dropped_matches;
        self.view_orphan_matches = view_stats.orphan_matches;
        self.view_evicted_streams = view_stats.evicted_streams;
        self.view_hide_rules = view_stats.hide_rules;
    }

    pub(crate) fn set_stream_message_stats(&mut self, message_stats: StreamMessageStats) {
        self.message_active_streams = message_stats.active_message_streams;
        self.message_stored_messages = message_stats.stored_messages;
        self.message_dropped_messages = message_stats.dropped_messages;
        self.message_observed_messages = message_stats.observed_messages;
        self.message_http1_messages = message_stats.http1_messages;
        self.message_dns_messages = message_stats.dns_messages;
        self.message_websocket_messages = message_stats.websocket_messages;
        self.message_tls_messages = message_stats.tls_messages;
        self.message_parse_errors = message_stats.parse_errors;
    }

    pub(crate) fn set_stream_parser_stats(&mut self, parser_stats: StreamParserStats) {
        self.parser_enabled = parser_stats.parser_enabled;
        self.parser_stream_chunks = parser_stats.parser_stream_chunks;
        self.parser_stream_bytes = parser_stats.parser_stream_bytes;
        self.parser_emitted_messages = parser_stats.parser_emitted_messages;
        self.parser_dropped_messages = parser_stats.parser_dropped_messages;
        self.parser_active_states = parser_stats.parser_active_states;
        self.parser_evicted_states = parser_stats.parser_evicted_states;
        self.parser_http1_active_states = parser_stats.http1_active_states;
        self.parser_http1_messages = parser_stats.http1_messages;
        self.parser_http1_parse_errors = parser_stats.http1_parse_errors;
        self.parser_http1_dropped_chunks = parser_stats.http1_dropped_chunks;
        self.parser_dns_active_states = parser_stats.dns_active_states;
        self.parser_dns_messages = parser_stats.dns_messages;
        self.parser_dns_parse_errors = parser_stats.dns_parse_errors;
        self.parser_dns_dropped_datagrams = parser_stats.dns_dropped_datagrams;
        self.parser_websocket_active_states = parser_stats.websocket_active_states;
        self.parser_websocket_messages = parser_stats.websocket_messages;
        self.parser_websocket_parse_errors = parser_stats.websocket_parse_errors;
        self.parser_websocket_dropped_chunks = parser_stats.websocket_dropped_chunks;
        self.parser_tls_active_states = parser_stats.tls_active_states;
        self.parser_tls_messages = parser_stats.tls_messages;
        self.parser_tls_parse_errors = parser_stats.tls_parse_errors;
        self.parser_tls_dropped_chunks = parser_stats.tls_dropped_chunks;
    }

    pub(crate) fn add_stream_parser_stats(&mut self, parser_stats: StreamParserStats) {
        self.parser_enabled |= parser_stats.parser_enabled;
        self.parser_stream_chunks = self
            .parser_stream_chunks
            .saturating_add(parser_stats.parser_stream_chunks);
        self.parser_stream_bytes = self
            .parser_stream_bytes
            .saturating_add(parser_stats.parser_stream_bytes);
        self.parser_emitted_messages = self
            .parser_emitted_messages
            .saturating_add(parser_stats.parser_emitted_messages);
        self.parser_dropped_messages = self
            .parser_dropped_messages
            .saturating_add(parser_stats.parser_dropped_messages);
        self.parser_active_states = self
            .parser_active_states
            .saturating_add(parser_stats.parser_active_states);
        self.parser_evicted_states = self
            .parser_evicted_states
            .saturating_add(parser_stats.parser_evicted_states);
        self.parser_http1_active_states = self
            .parser_http1_active_states
            .saturating_add(parser_stats.http1_active_states);
        self.parser_http1_messages = self
            .parser_http1_messages
            .saturating_add(parser_stats.http1_messages);
        self.parser_http1_parse_errors = self
            .parser_http1_parse_errors
            .saturating_add(parser_stats.http1_parse_errors);
        self.parser_http1_dropped_chunks = self
            .parser_http1_dropped_chunks
            .saturating_add(parser_stats.http1_dropped_chunks);
        self.parser_dns_active_states = self
            .parser_dns_active_states
            .saturating_add(parser_stats.dns_active_states);
        self.parser_dns_messages = self
            .parser_dns_messages
            .saturating_add(parser_stats.dns_messages);
        self.parser_dns_parse_errors = self
            .parser_dns_parse_errors
            .saturating_add(parser_stats.dns_parse_errors);
        self.parser_dns_dropped_datagrams = self
            .parser_dns_dropped_datagrams
            .saturating_add(parser_stats.dns_dropped_datagrams);
        self.parser_websocket_active_states = self
            .parser_websocket_active_states
            .saturating_add(parser_stats.websocket_active_states);
        self.parser_websocket_messages = self
            .parser_websocket_messages
            .saturating_add(parser_stats.websocket_messages);
        self.parser_websocket_parse_errors = self
            .parser_websocket_parse_errors
            .saturating_add(parser_stats.websocket_parse_errors);
        self.parser_websocket_dropped_chunks = self
            .parser_websocket_dropped_chunks
            .saturating_add(parser_stats.websocket_dropped_chunks);
        self.parser_tls_active_states = self
            .parser_tls_active_states
            .saturating_add(parser_stats.tls_active_states);
        self.parser_tls_messages = self
            .parser_tls_messages
            .saturating_add(parser_stats.tls_messages);
        self.parser_tls_parse_errors = self
            .parser_tls_parse_errors
            .saturating_add(parser_stats.tls_parse_errors);
        self.parser_tls_dropped_chunks = self
            .parser_tls_dropped_chunks
            .saturating_add(parser_stats.tls_dropped_chunks);
    }
}

pub struct Pipeline {
    config: PipelineConfig,
    mode: RunMode,
    analyzers: Vec<Box<dyn Analyzer>>,
    sinks: Vec<Box<dyn EventSink>>,
    flow_table: FlowTable,
    stream_inventory: StreamInventory,
    stream_content: StreamContent,
    stream_parser: StreamParserLayer,
    stream_messages: StreamMessageStore,
    live_content: Option<Arc<RwLock<StreamContent>>>,
    pattern_engine: PatternEngine,
    stream_view: StreamViewState,
    live_api: Option<LiveApiHandle>,
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
    pub stream_inventory: StreamInventoryConfig,
    pub stream_content: StreamContentConfig,
    pub stream_parser: StreamParserConfig,
    pub stream_view: StreamViewConfig,
    pub stream_slice: StreamSliceConfig,
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
            stream_inventory: StreamInventory::new(config.stream_inventory),
            stream_content: StreamContent::new(config.stream_content),
            stream_parser: StreamParserLayer::new(config.stream_parser),
            stream_messages: StreamMessageStore::default(),
            live_content: None,
            pattern_engine: PatternEngine::new(PatternEngineConfig::disabled()),
            stream_view: StreamViewState::new(config.stream_view),
            live_api: None,
            events: Vec::with_capacity(config.batch_size),
        }
    }

    pub fn set_pattern_config(&mut self, config: PatternEngineConfig) {
        self.pattern_engine = PatternEngine::new(config);
    }

    pub fn register_analyzer(&mut self, analyzer: Box<dyn Analyzer>) {
        tracing::info!("Registering analyzer: {}", analyzer.name());
        self.analyzers.push(analyzer);
    }

    pub fn register_sink(&mut self, sink: Box<dyn EventSink>) {
        self.sinks.push(sink);
    }

    pub fn attach_live_api(&mut self, live_api: LiveApiHandle) {
        self.live_content = Some(live_api.install_local_content(self.config.stream_content));
        self.live_api = Some(live_api);
    }

    pub fn stream_view(&self) -> &StreamViewState {
        &self.stream_view
    }

    pub fn content_slice(
        &self,
        request: &StreamSliceRequest,
    ) -> std::result::Result<StreamContentSlice, StreamSliceError> {
        if let Some(content) = &self.live_content {
            let content = content.read().expect("live content lock is poisoned");
            return StreamSliceReader::new(&content, &self.stream_view, self.config.stream_slice)
                .slice(request);
        }

        StreamSliceReader::new(
            &self.stream_content,
            &self.stream_view,
            self.config.stream_slice,
        )
        .slice(request)
    }

    pub fn into_api_parts(
        self,
    ) -> (
        StreamContent,
        StreamViewState,
        StreamMessageStore,
        StreamSliceConfig,
    ) {
        (
            self.stream_content,
            self.stream_view,
            self.stream_messages,
            self.config.stream_slice,
        )
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
        stats.set_stream_view_stats(self.stream_view.stats());
        if let Some(live_api) = &self.live_api {
            live_api.mark_completed(stats);
        }

        Ok(stats)
    }

    fn process_batch(&mut self, batch: &PacketBatch, stats: &mut PipelineStats) {
        self.events.clear();

        for raw in batch.packets() {
            self.process_packet(raw, stats);
        }

        stats.set_flow_table_stats(self.flow_table.stats());
        stats.set_stream_inventory_stats(self.stream_inventory.stats());
        stats.set_stream_content_stats(self.stream_content_stats());
        stats.set_stream_parser_stats(self.stream_parser.stats());
        stats.set_pattern_stats(self.pattern_engine.stats());
        self.stream_view.observe_events(&self.events);
        self.stream_messages.observe_events(&self.events);
        stats.set_stream_view_stats(self.stream_view.stats());
        stats.set_stream_message_stats(self.stream_messages.stats());
        if let Some(live_api) = &self.live_api {
            live_api.publish_events(&self.events, *stats);
        }
    }

    fn process_packet(&mut self, raw: &RawPacket, stats: &mut PipelineStats) {
        match self.mode {
            RunMode::Dump => self.events.push(Event::packet_dump(raw)),
            RunMode::Analyze => {
                let packet = DecodedPacket::from_raw(raw);
                let decode_status = packet.decode_status();
                stats.observe_packet_decode_status(decode_status);
                if decode_status.is_decode_error() {
                    return;
                }

                let flow = self.flow_table.observe(&packet);
                if let Some(flow) = flow.as_ref() {
                    self.stream_inventory
                        .observe_flow(&packet, flow, None, &mut self.events);
                    self.observe_stream_content(&packet, flow);
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
                if let Some(flow) = flow
                    .as_ref()
                    .and_then(|flow| flow.tcp.as_ref().map(|tcp| (flow, tcp)))
                {
                    for chunk in &flow.1.stream_chunks {
                        self.stream_parser
                            .observe_stream(&packet, flow.0, chunk, &mut self.events);
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

    fn observe_stream_content(
        &mut self,
        packet: &DecodedPacket<'_>,
        flow: &crate::flow::FlowObservation<'_>,
    ) {
        if let Some(content) = &self.live_content {
            let mut content = content.write().expect("live content lock is poisoned");
            if let Some(update) = content.observe_flow(packet, flow) {
                self.pattern_engine
                    .scan_update(packet, &content, &update, &mut self.events);
            }
            return;
        }

        if let Some(update) = self.stream_content.observe_flow(packet, flow) {
            self.pattern_engine.scan_update(
                packet,
                &self.stream_content,
                &update,
                &mut self.events,
            );
        }
    }

    fn stream_content_stats(&self) -> StreamContentStats {
        if let Some(content) = &self.live_content {
            return content
                .read()
                .expect("live content lock is poisoned")
                .stats();
        }

        self.stream_content.stats()
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
        flow::{FlowDirection, FlowObservation, StreamChunk},
        ingest::{PacketBatch, PacketSource},
        output::EventSink,
        packet::{LinkLayer, PacketTimestamp},
        pattern::{PatternDefinition, PatternEngineConfig},
        stream_parser::StreamParserConfig,
        stream_slice::{
            StreamSliceConfig, StreamSliceMode, StreamSliceRequest, StreamSliceSegmentView,
        },
        stream_view::StreamViewConfig,
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
            stream_inventory: test_stream_inventory_config(),
            stream_content: test_stream_content_config(),
            stream_parser: StreamParserConfig::disabled(),
            stream_view: test_stream_view_config(),
            stream_slice: test_stream_slice_config(),
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
        assert_eq!(8, stats.content_observed_bytes);
        assert_eq!(8, stats.content_stored_bytes);
        assert_eq!(1, stats.content_active_streams);
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

        let stats = pipeline.run_with_source(source).await.unwrap();

        let events = events.lock().unwrap();
        let http = events
            .iter()
            .find(|event| event["event_type"] == "http_request")
            .unwrap();
        assert_eq!(2, events.len());
        assert_eq!(1, stats.inventory_created_streams);
        assert_eq!(1, stats.inventory_events);
        assert_eq!("/flagxx", http["fields"]["target"]);
        assert_eq!("ctf.local", http["fields"]["headers"]["host"]);
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
        assert_eq!(2, stats.events);
        let http = events
            .iter()
            .find(|event| event["event_type"] == "http_request")
            .unwrap();
        assert_eq!("/idle", http["fields"]["target"]);
    }

    #[tokio::test]
    async fn emits_pattern_match_from_stream_content() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut pipeline = test_pipeline();
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

        let source = VecPacketSource::new(vec![tcp_packet(100, b"fl"), tcp_packet(102, b"ag")]);
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
    async fn returns_content_slice_with_highlights() {
        let mut pipeline = test_pipeline();
        pipeline.set_pattern_config(
            PatternEngineConfig::compile(
                vec![PatternDefinition::substring("substring:0", "flag")],
                1024,
                1024,
                4096,
            )
            .unwrap(),
        );

        let stats = pipeline
            .run_with_source(VecPacketSource::new(vec![tcp_packet(100, b"GET /flag")]))
            .await
            .unwrap();
        assert_eq!(1, stats.view_matched_streams);

        let stream_id = pipeline.stream_view().query(&Default::default()).rows[0].stream_id;
        let slice = pipeline
            .content_slice(&StreamSliceRequest {
                stream_id,
                direction: FlowDirection::AToB,
                logical_start: 0,
                max_bytes: 16,
                mode: StreamSliceMode::Text,
            })
            .unwrap();

        assert_eq!(1, slice.segments.len());
        assert_eq!(9, slice.returned_bytes);
        assert_eq!(1, slice.highlights.len());
        assert_eq!(5, slice.highlights[0].segment_start);
        assert_eq!(9, slice.highlights[0].segment_end);
        match &slice.segments[0].view {
            StreamSliceSegmentView::Text { text, lossy } => {
                assert_eq!("GET /flag", text);
                assert!(!lossy);
            }
            other => panic!("unexpected slice view: {other:?}"),
        }
    }

    #[tokio::test]
    async fn indexes_protocol_messages_in_pipeline_stats() {
        let mut pipeline = test_pipeline();
        pipeline.stream_parser = StreamParserLayer::default();

        let stats = pipeline
            .run_with_source(VecPacketSource::new(vec![tcp_packet(
                100,
                b"GET /messages HTTP/1.1\r\nHost: ctf.local\r\n\r\n",
            )]))
            .await
            .unwrap();

        assert_eq!(1, stats.message_active_streams);
        assert_eq!(1, stats.message_observed_messages);
        assert_eq!(1, stats.message_stored_messages);
        assert_eq!(1, stats.message_http1_messages);
        assert_eq!(0, stats.message_parse_errors);
        assert_eq!(1, stats.parser_emitted_messages);
        assert_eq!(1, stats.parser_http1_messages);
    }

    #[tokio::test]
    async fn indexes_dns_messages_in_pipeline_stats() {
        let mut pipeline = test_pipeline();
        pipeline.stream_parser = StreamParserLayer::default();

        let stats = pipeline
            .run_with_source(VecPacketSource::new(vec![udp_packet(
                49_000,
                53,
                &dns_query_packet(),
            )]))
            .await
            .unwrap();

        assert_eq!(1, stats.message_active_streams);
        assert_eq!(1, stats.message_observed_messages);
        assert_eq!(1, stats.message_stored_messages);
        assert_eq!(1, stats.message_dns_messages);
        assert_eq!(0, stats.message_parse_errors);
        assert_eq!(1, stats.parser_emitted_messages);
        assert_eq!(1, stats.parser_dns_messages);
        assert_eq!(0, stats.parser_dns_parse_errors);
        assert_eq!(1, stats.parser_dns_active_states);
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
            stream_inventory: test_stream_inventory_config(),
            stream_content: test_stream_content_config(),
            stream_parser: StreamParserConfig::disabled(),
            stream_view: test_stream_view_config(),
            stream_slice: test_stream_slice_config(),
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

    fn udp_packet(source_port: u16, destination_port: u16, payload: &[u8]) -> RawPacket {
        let builder = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 20)
            .udp(source_port, destination_port);
        let mut data = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut data, payload).unwrap();
        RawPacket {
            timestamp: PacketTimestamp { sec: 1, usec: 0 },
            link_layer: LinkLayer::Ethernet,
            linktype: Linktype::ETHERNET.0,
            data,
        }
    }

    fn dns_query_packet() -> Vec<u8> {
        let mut bytes = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        bytes.extend_from_slice(&[7]);
        bytes.extend_from_slice(b"example");
        bytes.extend_from_slice(&[3]);
        bytes.extend_from_slice(b"com");
        bytes.extend_from_slice(&[0, 0, 1, 0, 1]);
        bytes
    }
}
