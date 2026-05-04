use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::{EnvFilter, fmt};

use rustmate::{
    analyzers::{dns::DnsAnalyzer, http::HttpAnalyzer, tls_meta::TlsMetaAnalyzer},
    cli::Opts,
    config::Config,
    ingest::PcapFileSource,
    output::jsonl::JsonlWriter,
    pipeline::{Pipeline, PipelineConfig},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();

    let opts = Opts::parse();
    tracing::info!("Запуск rustmate, mode={}", opts.mode);

    let cfg = Config::default();
    let mut pipeline = Pipeline::new(PipelineConfig {
        mode: opts.mode,
        batch_size: opts.batch_size.max(1),
        max_flows: opts.max_flows.max(1),
        flow_idle_timeout_ms: opts.flow_idle_timeout_ms,
        max_tcp_buffered_bytes_per_flow: opts.max_tcp_buffered_bytes_per_flow,
        max_tcp_out_of_order_segments_per_direction: opts
            .max_tcp_out_of_order_segments_per_direction,
    });
    pipeline.register_analyzer(Box::new(HttpAnalyzer::new()));
    pipeline.register_analyzer(Box::new(DnsAnalyzer::new()));
    pipeline.register_analyzer(Box::new(TlsMetaAnalyzer::new()));

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
        pipeline.register_sink(Box::new(JsonlWriter::create(out_path.clone())?));
        tracing::info!("Чтение pcap-файла: {}", pcap_path.display());
        let src = PcapFileSource::open(PathBuf::from(pcap_path))?;
        let stats = pipeline.run_with_source(src).await?;

        tracing::info!(
            batches = stats.batches,
            packets = stats.packets,
            bytes = stats.bytes,
            events = stats.events,
            decode_errors = stats.decode_errors,
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
            output = %out_path.display(),
            "Обработка pcap завершена"
        );
    } else {
        tracing::warn!(
            "PCAP файл не указан. Live-capture будет следующим отдельным источником ingest."
        );
    }

    tracing::info!("Завершение работы rustmate.");
    Ok(())
}
