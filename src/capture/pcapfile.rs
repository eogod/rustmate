use super::PacketSource;
use std::path::PathBuf;
use pcap::{Capture, Offline};

pub struct PcapFileSource {
    cap: Capture<Offline>,
}

impl PcapFileSource {
    pub fn new(path: PathBuf) -> anyhow::Result<Self> {
        let cap = Capture::from_file(path)?;
        Ok(Self { cap })
    }
}

#[async_trait::async_trait]
impl PacketSource for PcapFileSource {
    async fn next_packet(&mut self) -> anyhow::Result<Option<(Vec<u8>, (u64, u32))>> {
        match self.cap.next_packet() {
            Ok(pkt) => {
                let ts = pkt.header.ts;
                Ok(Some((pkt.data.to_vec(), (ts.tv_sec as u64, ts.tv_usec as u32))))
            }
            Err(pcap::Error::NoMorePackets) => Ok(None),
            Err(e) => Err(anyhow::anyhow!(e.to_string())),
        }
    }
}
