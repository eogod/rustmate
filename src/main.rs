use clap::Parser;
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use tracing_subscriber::{EnvFilter, fmt};

use rustmate::{
    analyzers::{dns::DnsAnalyzer, http::HttpAnalyzer, tls_meta::TlsMetaAnalyzer},
    api::{ApiServer, LiveApiHandle, spawn_live},
    cli::Opts,
    config::Config,
    ingest::{
        LiveCaptureConfig, LiveCaptureSource, PacketSource, PcapFileSource, list_capture_devices,
    },
    output::jsonl::JsonlWriter,
    pattern::{PatternDefinition, PatternEngineConfig},
    pipeline::{Pipeline, PipelineConfig},
    service_profile::ServiceProfileSet,
    sharded_pipeline::{
        ShardedPipeline, ShardedPipelineConfig, StreamOffloadBackpressurePolicy,
        StreamOffloadConfig, resolve_worker_count,
    },
    stream_content::StreamContentConfig,
    stream_inventory::StreamInventoryConfig,
    stream_parser::StreamParserConfig,
    stream_slice::StreamSliceConfig,
    stream_view::StreamViewConfig,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();

    let opts = Opts::parse();
    let api_listen = opts.api_listen;
    tracing::info!("Starting rustmate, mode={}", opts.mode);

    if opts.list_interfaces {
        print_capture_devices()?;
        return Ok(());
    }

    if opts.pcap.is_some() && opts.iface.is_some() {
        anyhow::bail!("use either --pcap for offline input or --iface for live capture, not both");
    }

    let cfg = Config::default();
    let pipeline_config = PipelineConfig {
        mode: opts.mode,
        batch_size: opts.batch_size.max(1),
        health_interval_ms: opts.health_interval_ms,
        max_flows: opts.max_flows.max(1),
        flow_idle_timeout_ms: opts.flow_idle_timeout_ms,
        max_tcp_buffered_bytes_per_flow: opts.max_tcp_buffered_bytes_per_flow,
        max_tcp_out_of_order_segments_per_direction: opts
            .max_tcp_out_of_order_segments_per_direction,
        stream_inventory: StreamInventoryConfig {
            enabled: !opts.disable_stream_inventory,
            max_streams: opts.max_streams.max(1),
            idle_timeout_ms: opts.flow_idle_timeout_ms,
            preview_bytes_per_direction: opts.stream_preview_bytes,
            update_packet_interval: opts.stream_update_packets,
            update_byte_interval: opts.stream_update_bytes,
        },
        stream_content: StreamContentConfig {
            enabled: !opts.disable_stream_content,
            max_streams: opts.max_streams.max(1),
            idle_timeout_ms: opts.flow_idle_timeout_ms,
            max_total_bytes: opts.max_stream_content_bytes,
            max_bytes_per_stream: opts.max_stream_content_bytes_per_stream,
            max_segment_bytes: opts.stream_content_segment_bytes,
        },
        stream_parser: StreamParserConfig {
            enabled: !opts.disable_stream_parser,
            max_http1_states: opts.max_http1_parser_states,
            max_dns_states: opts.max_dns_parser_states,
            max_websocket_states: opts.max_websocket_parser_states,
            max_tls_states: opts.max_tls_parser_states,
            max_http1_header_bytes: opts.max_http1_header_bytes,
            max_http1_buffer_bytes: opts.max_http1_buffer_bytes,
            max_messages_per_chunk: opts.max_parser_messages_per_chunk,
        },
        stream_view: StreamViewConfig {
            enabled: !opts.disable_stream_view,
            max_streams: opts.max_streams.max(1),
            max_matches_per_stream: opts.max_stream_view_matches_per_stream,
            max_query_limit: opts.stream_view_query_limit.max(1),
        },
        stream_slice: StreamSliceConfig {
            max_slice_bytes: opts.max_stream_slice_bytes,
            max_highlights: opts.max_stream_slice_highlights,
            hex_row_bytes: opts.stream_slice_hex_row_bytes,
            max_transform_bytes: opts.max_stream_transform_bytes,
        },
    };
    let pattern_config = build_pattern_config(&opts)?;
    let service_profiles = load_service_profiles(opts.service_profile_file.as_deref())?;
    let worker_count = resolve_worker_count(opts.workers);

    let out_path = opts
        .output
        .clone()
        .or_else(|| {
            opts.pcap
                .as_ref()
                .map(|p| PathBuf::from(format!("{}.jsonl", p.display())))
        })
        .unwrap_or_else(|| cfg.output_json.clone());

    if let Some(pcap_path) = opts.pcap.as_deref() {
        tracing::info!("Reading pcap file: {}", pcap_path.display());
        let src = PcapFileSource::open(PathBuf::from(pcap_path))?;
        let (live_api, api_server) = start_live_api(
            api_listen,
            pipeline_config,
            opts.api_delta_capacity,
            service_profiles.clone(),
        )
        .await?;
        let run = run_pipeline(
            src,
            pipeline_config,
            pattern_config.clone(),
            PipelineRunOptions {
                worker_count,
                worker_queue_depth: opts.worker_queue_depth,
                event_queue_depth: opts.event_queue_depth,
                stream_offload_queue_depth: opts.stream_offload_queue_depth,
                stream_offload_backpressure: opts.stream_offload_backpressure,
                out_path: out_path.clone(),
                live_api,
            },
        )
        .await?;
        log_completed("Pcap processing completed", &run.stats, &out_path);
        if let Some(api_server) = api_server {
            tracing::info!(
                api = %api_server.local_addr(),
                "Input finished; live API remains available until Ctrl-C"
            );
            api_server.wait_for_shutdown_signal().await?;
        }
    } else if let Some(interface) = opts.iface.as_deref() {
        let shutdown = Arc::new(AtomicBool::new(false));
        install_shutdown_handler(Arc::clone(&shutdown))?;

        tracing::info!("Live capture: {}", interface);
        let src = LiveCaptureSource::open(LiveCaptureConfig {
            interface: interface.to_owned(),
            snaplen: opts.capture_snaplen,
            buffer_size: opts.capture_buffer_size,
            read_timeout_ms: opts.capture_read_timeout_ms.max(1),
            promisc: opts.promisc,
            immediate_mode: opts.immediate,
            bpf_filter: opts.capture_filter.clone(),
            max_packets: opts.max_packets,
            shutdown,
        })?;
        let (live_api, api_server) = start_live_api(
            api_listen,
            pipeline_config,
            opts.api_delta_capacity,
            service_profiles,
        )
        .await?;
        let run = run_pipeline(
            src,
            pipeline_config,
            pattern_config,
            PipelineRunOptions {
                worker_count,
                worker_queue_depth: opts.worker_queue_depth,
                event_queue_depth: opts.event_queue_depth,
                stream_offload_queue_depth: opts.stream_offload_queue_depth,
                stream_offload_backpressure: opts.stream_offload_backpressure,
                out_path: out_path.clone(),
                live_api,
            },
        )
        .await?;
        log_completed("Live capture completed", &run.stats, &out_path);
        if let Some(api_server) = api_server {
            tracing::info!(
                api = %api_server.local_addr(),
                "Input finished; live API remains available until Ctrl-C"
            );
            api_server.wait_for_shutdown_signal().await?;
        }
    } else {
        tracing::warn!("No input set. Use --pcap, --iface, or --list-interfaces.");
    }

    tracing::info!("rustmate stopped.");
    Ok(())
}

struct PipelineRun {
    stats: rustmate::pipeline::PipelineStats,
}

struct PipelineRunOptions {
    worker_count: usize,
    worker_queue_depth: usize,
    event_queue_depth: usize,
    stream_offload_queue_depth: usize,
    stream_offload_backpressure: StreamOffloadBackpressurePolicy,
    out_path: PathBuf,
    live_api: Option<LiveApiHandle>,
}

async fn run_pipeline<T: PacketSource + 'static>(
    source: T,
    pipeline_config: PipelineConfig,
    pattern_config: PatternEngineConfig,
    options: PipelineRunOptions,
) -> anyhow::Result<PipelineRun> {
    if options.worker_count > 1 {
        let mut pipeline = ShardedPipeline::new(ShardedPipelineConfig {
            pipeline: pipeline_config,
            worker_count: options.worker_count,
            worker_queue_depth: options.worker_queue_depth,
            event_queue_depth: options.event_queue_depth,
            stream_offload: StreamOffloadConfig {
                queue_depth: options.stream_offload_queue_depth,
                backpressure_policy: options.stream_offload_backpressure,
            },
        });
        pipeline.set_pattern_config(pattern_config);
        if let Some(live_api) = options.live_api {
            pipeline.attach_live_api(live_api);
        }
        register_sharded_analyzers(&mut pipeline);
        pipeline.register_sink(Box::new(JsonlWriter::create(options.out_path)?));
        let stats = pipeline.run_with_source(source).await?;
        Ok(PipelineRun { stats })
    } else {
        let mut pipeline = Pipeline::new(pipeline_config);
        pipeline.set_pattern_config(pattern_config);
        if let Some(live_api) = options.live_api {
            pipeline.attach_live_api(live_api);
        }
        register_analyzers(&mut pipeline);
        pipeline.register_sink(Box::new(JsonlWriter::create(options.out_path)?));
        let stats = pipeline.run_with_source(source).await?;
        Ok(PipelineRun { stats })
    }
}

async fn start_live_api(
    api_listen: Option<std::net::SocketAddr>,
    pipeline_config: PipelineConfig,
    delta_capacity: usize,
    service_profiles: ServiceProfileSet,
) -> anyhow::Result<(Option<LiveApiHandle>, Option<ApiServer>)> {
    let Some(addr) = api_listen else {
        return Ok((None, None));
    };

    let live_api = LiveApiHandle::new_with_profiles(
        pipeline_config.stream_view,
        pipeline_config.stream_slice,
        delta_capacity,
        service_profiles,
    );
    let server = spawn_live(live_api.clone(), addr).await?;
    Ok((Some(live_api), Some(server)))
}

fn load_service_profiles(path: Option<&Path>) -> anyhow::Result<ServiceProfileSet> {
    match path {
        Some(path) => ServiceProfileSet::from_json_file(path),
        None => Ok(ServiceProfileSet::builtin()),
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

fn build_pattern_config(opts: &Opts) -> anyhow::Result<PatternEngineConfig> {
    let mut definitions = Vec::with_capacity(
        opts.patterns.len() + opts.regex_patterns.len() + opts.binary_patterns.len(),
    );

    for (index, pattern) in opts.patterns.iter().enumerate() {
        definitions.push(PatternDefinition::substring(
            format!("substring:{index}"),
            pattern.clone(),
        ));
    }

    for (index, pattern) in opts.regex_patterns.iter().enumerate() {
        definitions.push(PatternDefinition::regex(
            format!("regex:{index}"),
            pattern.clone(),
        ));
    }

    for (index, pattern) in opts.binary_patterns.iter().enumerate() {
        definitions.push(PatternDefinition::binary_hex(
            format!("binary:{index}"),
            pattern.clone(),
        )?);
    }

    PatternEngineConfig::compile(
        definitions,
        opts.max_pattern_matches_per_stream,
        opts.max_pattern_matches_total,
        opts.pattern_regex_window_bytes,
    )
}

fn install_shutdown_handler(shutdown: Arc<AtomicBool>) -> anyhow::Result<()> {
    ctrlc::set_handler(move || {
        tracing::info!("Got Ctrl-C, stopping capture after the current read timeout");
        shutdown.store(true, Ordering::SeqCst);
    })?;
    Ok(())
}

fn print_capture_devices() -> anyhow::Result<()> {
    for device in list_capture_devices()? {
        let flags = [
            (device.is_up, "up"),
            (device.is_running, "running"),
            (device.is_loopback, "loopback"),
            (device.is_wireless, "wireless"),
        ]
        .into_iter()
        .filter_map(|(enabled, name)| enabled.then_some(name))
        .collect::<Vec<_>>()
        .join(",");
        let addresses = device
            .addresses
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{}\tdesc={}\tflags={}\taddrs={}",
            device.name,
            device.description.as_deref().unwrap_or(""),
            flags,
            addresses,
        );
    }

    Ok(())
}

fn log_completed(message: &str, stats: &rustmate::pipeline::PipelineStats, out_path: &Path) {
    tracing::info!(
        workers = stats.workers,
        batches = stats.batches,
        packets = stats.packets,
        bytes = stats.bytes,
        events = stats.events,
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
        source_received_packets = stats.source_received_packets,
        source_dropped_packets = stats.source_dropped_packets,
        source_interface_dropped_packets = stats.source_interface_dropped_packets,
        active_flows = stats.active_flows,
        created_flows = stats.created_flows,
        evicted_flows = stats.evicted_flows,
        dropped_new_flows = stats.dropped_new_flows,
        tcp_stream_chunks = stats.tcp_stream_chunks,
        tcp_stream_bytes = stats.tcp_stream_bytes,
        tcp_current_stream_chunks = stats.tcp_current_stream_chunks,
        tcp_current_stream_bytes = stats.tcp_current_stream_bytes,
        tcp_buffered_stream_chunks = stats.tcp_buffered_stream_chunks,
        tcp_buffered_stream_bytes = stats.tcp_buffered_stream_bytes,
        tcp_overlap_trimmed_stream_chunks = stats.tcp_overlap_trimmed_stream_chunks,
        tcp_overlap_trimmed_stream_bytes = stats.tcp_overlap_trimmed_stream_bytes,
        tcp_gaps = stats.tcp_gaps,
        tcp_retransmissions = stats.tcp_retransmissions,
        tcp_retransmitted_bytes = stats.tcp_retransmitted_bytes,
        tcp_overlaps = stats.tcp_overlaps,
        tcp_out_of_order_buffered = stats.tcp_out_of_order_buffered,
        tcp_out_of_order_buffered_bytes = stats.tcp_out_of_order_buffered_bytes,
        tcp_out_of_order_dropped = stats.tcp_out_of_order_dropped,
        tcp_out_of_order_dropped_bytes = stats.tcp_out_of_order_dropped_bytes,
        tcp_overlap_trimmed_bytes = stats.tcp_overlap_trimmed_bytes,
        tcp_reassembly_buffered_bytes_peak = stats.tcp_reassembly_buffered_bytes_peak,
        tcp_midstream_starts = stats.tcp_midstream_starts,
        tcp_syns = stats.tcp_syns,
        tcp_fins = stats.tcp_fins,
        tcp_resets = stats.tcp_resets,
        inventory_active_streams = stats.inventory_active_streams,
        inventory_created_streams = stats.inventory_created_streams,
        inventory_evicted_streams = stats.inventory_evicted_streams,
        inventory_dropped_new_streams = stats.inventory_dropped_new_streams,
        inventory_closed_streams = stats.inventory_closed_streams,
        inventory_events = stats.inventory_events,
        content_active_streams = stats.content_active_streams,
        content_active_segments = stats.content_active_segments,
        content_stored_bytes = stats.content_stored_bytes,
        content_observed_bytes = stats.content_observed_bytes,
        content_dropped_bytes = stats.content_dropped_bytes,
        content_evicted_streams = stats.content_evicted_streams,
        content_truncated_streams = stats.content_truncated_streams,
        content_updates = stats.content_updates,
        content_merged_segments = stats.content_merged_segments,
        message_active_streams = stats.message_active_streams,
        message_stored_messages = stats.message_stored_messages,
        message_dropped_messages = stats.message_dropped_messages,
        message_observed_messages = stats.message_observed_messages,
        message_http1_messages = stats.message_http1_messages,
        message_dns_messages = stats.message_dns_messages,
        message_websocket_messages = stats.message_websocket_messages,
        message_tls_messages = stats.message_tls_messages,
        message_parse_errors = stats.message_parse_errors,
        parser_enabled = stats.parser_enabled,
        parser_stream_chunks = stats.parser_stream_chunks,
        parser_stream_bytes = stats.parser_stream_bytes,
        parser_emitted_messages = stats.parser_emitted_messages,
        parser_dropped_messages = stats.parser_dropped_messages,
        parser_active_states = stats.parser_active_states,
        parser_evicted_states = stats.parser_evicted_states,
        parser_http1_active_states = stats.parser_http1_active_states,
        parser_http1_messages = stats.parser_http1_messages,
        parser_http1_parse_errors = stats.parser_http1_parse_errors,
        parser_http1_dropped_chunks = stats.parser_http1_dropped_chunks,
        parser_dns_active_states = stats.parser_dns_active_states,
        parser_dns_messages = stats.parser_dns_messages,
        parser_dns_parse_errors = stats.parser_dns_parse_errors,
        parser_dns_dropped_datagrams = stats.parser_dns_dropped_datagrams,
        parser_websocket_active_states = stats.parser_websocket_active_states,
        parser_websocket_messages = stats.parser_websocket_messages,
        parser_websocket_parse_errors = stats.parser_websocket_parse_errors,
        parser_websocket_dropped_chunks = stats.parser_websocket_dropped_chunks,
        parser_tls_active_states = stats.parser_tls_active_states,
        parser_tls_messages = stats.parser_tls_messages,
        parser_tls_parse_errors = stats.parser_tls_parse_errors,
        parser_tls_dropped_chunks = stats.parser_tls_dropped_chunks,
        stream_offload_workers = stats.stream_offload_workers,
        stream_offload_submitted_chunks = stats.stream_offload_submitted_chunks,
        stream_offload_submitted_bytes = stats.stream_offload_submitted_bytes,
        stream_offload_blocked_chunks = stats.stream_offload_blocked_chunks,
        stream_offload_blocked_bytes = stats.stream_offload_blocked_bytes,
        stream_offload_inline_chunks = stats.stream_offload_inline_chunks,
        stream_offload_inline_bytes = stats.stream_offload_inline_bytes,
        stream_offload_dropped_chunks = stats.stream_offload_dropped_chunks,
        stream_offload_dropped_bytes = stats.stream_offload_dropped_bytes,
        stream_offload_processed_chunks = stats.stream_offload_processed_chunks,
        stream_offload_processed_bytes = stats.stream_offload_processed_bytes,
        pattern_matches = stats.pattern_matches,
        pattern_dropped_matches = stats.pattern_dropped_matches,
        pattern_matched_streams = stats.pattern_matched_streams,
        view_tracked_streams = stats.view_tracked_streams,
        view_favorite_streams = stats.view_favorite_streams,
        view_manually_hidden_streams = stats.view_manually_hidden_streams,
        view_matched_streams = stats.view_matched_streams,
        view_stored_matches = stats.view_stored_matches,
        view_dropped_matches = stats.view_dropped_matches,
        view_orphan_matches = stats.view_orphan_matches,
        view_evicted_streams = stats.view_evicted_streams,
        view_hide_rules = stats.view_hide_rules,
        output = %out_path.display(),
        "{message}"
    );
}
