use clap::Parser;
use std::path::PathBuf;

/// Аргументы командной строки.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Opts {
    /// Путь к pcap-файлу
    #[arg(short, long)]
    pub pcap: Option<PathBuf>,

    /// Режим работы: analyze | dump
    #[arg(short, long, default_value = "analyze")]
    pub mode: String,
}
