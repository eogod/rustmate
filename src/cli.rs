use clap::Parser;
use std::path::PathBuf;

use crate::config::{
    DEFAULT_BATCH_SIZE, DEFAULT_FLOW_IDLE_TIMEOUT_MS, DEFAULT_MAX_FLOWS,
    DEFAULT_MAX_TCP_BUFFERED_BYTES_PER_FLOW, DEFAULT_MAX_TCP_OUT_OF_ORDER_SEGMENTS_PER_DIRECTION,
    RunMode,
};

/// Аргументы командной строки.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Opts {
    /// Путь к pcap-файлу
    #[arg(short, long)]
    pub pcap: Option<PathBuf>,

    /// Путь к JSONL-выводу
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Режим работы: analyze | dump
    #[arg(short, long, value_enum, default_value_t = RunMode::Analyze)]
    pub mode: RunMode,

    /// Количество пакетов, обрабатываемых за одну пачку
    #[arg(long, default_value_t = DEFAULT_BATCH_SIZE)]
    pub batch_size: usize,

    /// Максимальное количество flow-состояний в памяти
    #[arg(long, default_value_t = DEFAULT_MAX_FLOWS)]
    pub max_flows: usize,

    /// Idle timeout для flow-состояний
    #[arg(long, default_value_t = DEFAULT_FLOW_IDLE_TIMEOUT_MS)]
    pub flow_idle_timeout_ms: u64,

    /// Лимит out-of-order TCP payload bytes на flow
    #[arg(long, default_value_t = DEFAULT_MAX_TCP_BUFFERED_BYTES_PER_FLOW)]
    pub max_tcp_buffered_bytes_per_flow: usize,

    /// Лимит out-of-order TCP сегментов на направление flow
    #[arg(long, default_value_t = DEFAULT_MAX_TCP_OUT_OF_ORDER_SEGMENTS_PER_DIRECTION)]
    pub max_tcp_out_of_order_segments_per_direction: usize,
}
