pub mod pcapfile;

use async_trait::async_trait;

#[async_trait]
pub trait PacketSource: Send + Sync {
    async fn next_packet(&mut self) -> anyhow::Result<Option<(Vec<u8>, (u64, u32))>>;
}