use crate::dispatcher::Analyzer;

pub struct HttpAnalyzer;

impl HttpAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for HttpAnalyzer {
    fn name(&self) -> &'static str {
        "http"
    }

    fn analyze(&self, packet: &[u8]) {
        // минимальная заглушка анализа
        if packet.starts_with(b"GET ") || packet.starts_with(b"POST ") {
            tracing::info!("HTTP packet detected ({} bytes)", packet.len());
        }
    }
}
