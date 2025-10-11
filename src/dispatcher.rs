use crate::capture::PacketSource;
use crate::storage::json_writer::JsonWriter;
use anyhow::Result;

pub trait Analyzer: Send + Sync {
    fn name(&self) -> &'static str;
    fn analyze(&self, packet: &[u8]);
}

pub trait Storage: Send + Sync {
    fn store(&self, name: &str, data: &[u8]);
}

pub struct Dispatcher {
    analyzers: Vec<Box<dyn Analyzer>>,
    storages: Vec<Box<dyn Storage>>,
}

impl Dispatcher {
    pub fn new() -> Self {
        Self {
            analyzers: Vec::new(),
            storages: Vec::new(),
        }
    }

    pub fn register_analyzer(&mut self, analyzer: Box<dyn Analyzer>) {
        tracing::info!("Регистрация анализатора: {}", analyzer.name());
        self.analyzers.push(analyzer);
    }

    pub fn register_storage(&mut self, storage: Box<dyn Storage>) {
        self.storages.push(storage);
    }

    pub async fn run_with_source<T: PacketSource + 'static>(&mut self, mut src: T) -> Result<()> {
        while let Some((packet, _ts)) = src.next_packet().await? {
            for analyzer in &self.analyzers {
                analyzer.analyze(&packet);
            }
            for storage in &self.storages {
                storage.store("packet", &packet);
            }
        }
        Ok(())
    }
}
