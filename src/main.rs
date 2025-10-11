mod cli;
mod config;
mod capture;
mod dispatcher;
mod analyzers;
mod storage;
mod utils;

use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Логирование
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();

    let opts = cli::Opts::parse();
    tracing::info!("Запуск ctf-sniffer, mode={}", opts.mode);

    let cfg = config::Config::default();
    let mut dispatcher = dispatcher::Dispatcher::new();
    dispatcher.register_analyzer(Box::new(analyzers::http::HttpAnalyzer::new()));

    let out_path = opts
        .pcap
        .as_ref()
        .map(|p| PathBuf::from(format!("{}.json", p.display())))
        .or_else(|| cfg.output_json.as_ref().map(|s| PathBuf::from(s)))
        .unwrap_or_else(|| PathBuf::from("out.json"));

    match storage::json_writer::JsonWriter::new(out_path.clone()) {
        Ok(w) => dispatcher.register_storage(Box::new(w)),
        Err(e) => tracing::error!("Не удалось создать json writer: {}", e),
    }

    if let Some(pcap_path) = opts.pcap.as_deref() {
        tracing::info!("Чтение pcap-файла: {}", pcap_path.display());
        let src = match capture::pcapfile::PcapFileSource::new(PathBuf::from(pcap_path)) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Не удалось открыть pcap: {}", e);
                return Err(e);
            }
        };

        if let Err(e) = dispatcher.run_with_source(src).await {
            tracing::error!("Ошибка в процессе обработки пакетов: {}", e);
            return Err(e);
        }
    } else {
        tracing::warn!("PCAP файл не указан. Поддержка live-capture пока не реализована.");
    }

    tracing::info!("Завершение работы rustmate.");
    Ok(())
}
