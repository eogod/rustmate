use std::path::PathBuf;

use pcap::{Capture, Offline};

use crate::{
    ingest::{PacketBatch, PacketSource},
    packet::{LinkLayer, PacketTimestamp, RawPacket},
};

pub struct PcapFileSource {
    cap: Capture<Offline>,
    link_layer: LinkLayer,
    linktype: i32,
}

impl PcapFileSource {
    pub fn open(path: PathBuf) -> anyhow::Result<Self> {
        let cap = Capture::from_file(path)?;
        let linktype = cap.get_datalink();

        Ok(Self {
            cap,
            link_layer: LinkLayer::from_pcap(linktype),
            linktype: linktype.0,
        })
    }
}

#[async_trait::async_trait]
impl PacketSource for PcapFileSource {
    async fn next_batch(&mut self, batch: &mut PacketBatch) -> anyhow::Result<usize> {
        batch.clear();
        let target = batch.capacity().max(1);

        while batch.len() < target {
            match self.cap.next_packet() {
                Ok(pkt) => {
                    let ts = pkt.header.ts;
                    batch.push(RawPacket {
                        timestamp: PacketTimestamp {
                            sec: u64::try_from(ts.tv_sec).unwrap_or(0),
                            usec: u32::try_from(ts.tv_usec).unwrap_or(0),
                        },
                        link_layer: self.link_layer,
                        linktype: self.linktype,
                        data: pkt.data.to_vec(),
                    });
                }
                Err(pcap::Error::NoMorePackets) => break,
                Err(e) => return Err(anyhow::anyhow!(e)),
            }
        }

        Ok(batch.len())
    }
}
