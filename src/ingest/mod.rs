pub mod pcap_file;

use async_trait::async_trait;

use crate::packet::RawPacket;

pub use pcap_file::PcapFileSource;

pub struct PacketBatch {
    packets: Vec<RawPacket>,
    byte_len: usize,
}

impl PacketBatch {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            packets: Vec::with_capacity(capacity),
            byte_len: 0,
        }
    }

    pub fn push(&mut self, packet: RawPacket) {
        self.byte_len += packet.data.len();
        self.packets.push(packet);
    }

    pub fn clear(&mut self) {
        self.packets.clear();
        self.byte_len = 0;
    }

    pub fn capacity(&self) -> usize {
        self.packets.capacity()
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn byte_len(&self) -> usize {
        self.byte_len
    }

    pub fn packets(&self) -> &[RawPacket] {
        &self.packets
    }
}

#[async_trait]
pub trait PacketSource: Send {
    async fn next_batch(&mut self, batch: &mut PacketBatch) -> anyhow::Result<usize>;
}
