pub mod live;
pub mod pcap_file;

use std::vec::Drain;

use async_trait::async_trait;

use crate::packet::RawPacket;

pub use live::{CaptureDeviceInfo, LiveCaptureConfig, LiveCaptureSource, list_capture_devices};
pub use pcap_file::PcapFileSource;

#[derive(Debug, Default, Clone, Copy)]
pub struct PacketSourceStats {
    pub received: u64,
    pub dropped: u64,
    pub interface_dropped: u64,
}

#[derive(Debug)]
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

    /// Move packets out, but keep the allocation around for the next read.
    pub fn drain(&mut self) -> Drain<'_, RawPacket> {
        self.byte_len = 0;
        self.packets.drain(..)
    }
}

#[async_trait]
pub trait PacketSource: Send {
    /// Fill `batch` with the next packets we have right now.
    ///
    /// `0` is not EOF by itself. Live capture uses idle ticks so health logs keep
    /// moving even when the wire is quiet; check `is_finished()` for the real end.
    async fn next_batch(&mut self, batch: &mut PacketBatch) -> anyhow::Result<usize>;

    fn is_finished(&self) -> bool {
        true
    }

    fn stats(&mut self) -> anyhow::Result<Option<PacketSourceStats>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use pcap::Linktype;

    use crate::packet::{LinkLayer, PacketTimestamp};

    use super::*;

    #[test]
    fn drain_moves_packets_and_preserves_capacity() {
        let mut batch = PacketBatch::with_capacity(4);
        batch.push(raw_packet(vec![1, 2, 3]));
        batch.push(raw_packet(vec![4, 5]));

        let capacity = batch.capacity();
        let packets = batch.drain().collect::<Vec<_>>();

        assert_eq!(capacity, batch.capacity());
        assert_eq!(0, batch.len());
        assert_eq!(0, batch.byte_len());
        assert_eq!(2, packets.len());
        assert_eq!(vec![1, 2, 3], packets[0].data);
        assert_eq!(vec![4, 5], packets[1].data);
    }

    fn raw_packet(data: Vec<u8>) -> RawPacket {
        RawPacket {
            timestamp: PacketTimestamp { sec: 1, usec: 0 },
            link_layer: LinkLayer::Ethernet,
            linktype: Linktype::ETHERNET.0,
            data,
        }
    }
}
