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
    cli::Opts,
    config::Config,
    ingest::{
        LiveCaptureConfig, LiveCaptureSource, PacketSource, PcapFileSource, list_capture_devices,
    },
    output::jsonl::JsonlWriter,
    pattern::{PatternDefinition, PatternEngineConfig},
    pipeline::{Pipeline, PipelineConfig},
    sharded_pipeline::{ShardedPipeline, ShardedPipelineConfig, resolve_worker_count},
    stream_content::StreamContentConfig,
    stream_inventory::StreamInventoryConfig,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();

    let opts = Opts::parse();
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
    };
    let pattern_config = build_pattern_config(&opts)?;
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
        let stats = run_pipeline(
            src,
            pipeline_config,
            pattern_config.clone(),
            worker_count,
            opts.worker_queue_depth,
            opts.event_queue_depth,
            out_path.clone(),
        )
        .await?;
        log_completed("Pcap processing completed", &stats, &out_path);
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
        let stats = run_pipeline(
            src,
            pipeline_config,
            pattern_config,
            worker_count,
            opts.worker_queue_depth,
            opts.event_queue_depth,
            out_path.clone(),
        )
        .await?;
        log_completed("Live capture completed", &stats, &out_path);
    } else {
        tracing::warn!("No input set. Use --pcap, --iface, or --list-interfaces.");
    }

    tracing::info!("rustmate stopped.");
    Ok(())
}

async fn run_pipeline<T: PacketSource + 'static>(
    source: T,
    pipeline_config: PipelineConfig,
    pattern_config: PatternEngineConfig,
    worker_count: usize,
    worker_queue_depth: usize,
    event_queue_depth: usize,
    out_path: PathBuf,
) -> anyhow::Result<rustmate::pipeline::PipelineStats> {
    if worker_count > 1 {
        let mut pipeline = ShardedPipeline::new(ShardedPipelineConfig {
            pipeline: pipeline_config,
            worker_count,
            worker_queue_depth,
            event_queue_depth,
        });
        pipeline.set_pattern_config(pattern_config);
        register_sharded_analyzers(&mut pipeline);
        pipeline.register_sink(Box::new(JsonlWriter::create(out_path)?));
        pipeline.run_with_source(source).await
    } else {
        let mut pipeline = Pipeline::new(pipeline_config);
        pipeline.set_pattern_config(pattern_config);
        register_analyzers(&mut pipeline);
        pipeline.register_sink(Box::new(JsonlWriter::create(out_path)?));
        pipeline.run_with_source(source).await
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
        fallback_routed_packets = stats.fallback_routed_packets,
        source_received_packets = stats.source_received_packets,
        source_dropped_packets = stats.source_dropped_packets,
        source_interface_dropped_packets = stats.source_interface_dropped_packets,
        active_flows = stats.active_flows,
        created_flows = stats.created_flows,
        evicted_flows = stats.evicted_flows,
        dropped_new_flows = stats.dropped_new_flows,
        tcp_stream_chunks = stats.tcp_stream_chunks,
        tcp_stream_bytes = stats.tcp_stream_bytes,
        tcp_gaps = stats.tcp_gaps,
        tcp_retransmissions = stats.tcp_retransmissions,
        tcp_overlaps = stats.tcp_overlaps,
        tcp_out_of_order_buffered = stats.tcp_out_of_order_buffered,
        tcp_out_of_order_dropped = stats.tcp_out_of_order_dropped,
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
        pattern_matches = stats.pattern_matches,
        pattern_dropped_matches = stats.pattern_dropped_matches,
        pattern_matched_streams = stats.pattern_matched_streams,
        output = %out_path.display(),
        "{message}"
    );
}
