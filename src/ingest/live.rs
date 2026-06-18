use std::{
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, Result, anyhow};
use pcap::{Active, Capture, Device, Linktype};

use crate::{
    ingest::{PacketBatch, PacketSource, PacketSourceStats},
    packet::{LinkLayer, PacketTimestamp, RawPacket},
};

#[derive(Debug, Clone)]
pub struct LiveCaptureConfig {
    pub interface: String,
    pub snaplen: usize,
    pub buffer_size: usize,
    pub read_timeout_ms: usize,
    pub promisc: bool,
    pub immediate_mode: bool,
    pub bpf_filter: Option<String>,
    pub max_packets: Option<u64>,
    pub shutdown: Arc<AtomicBool>,
}

#[derive(Debug, Clone)]
pub struct CaptureDeviceInfo {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<IpAddr>,
    pub is_up: bool,
    pub is_running: bool,
    pub is_loopback: bool,
    pub is_wireless: bool,
}

pub struct LiveCaptureSource {
    cap: Capture<Active>,
    link_layer: LinkLayer,
    linktype: i32,
    shutdown: Arc<AtomicBool>,
    max_packets: Option<u64>,
    captured_packets: u64,
}

impl LiveCaptureSource {
    pub fn open(config: LiveCaptureConfig) -> Result<Self> {
        let inactive = Capture::from_device(config.interface.as_str())
            .with_context(|| format!("failed to create capture on {}", config.interface))?
            .promisc(config.promisc)
            .snaplen(to_i32(config.snaplen, "snaplen")?)
            .buffer_size(to_i32(config.buffer_size, "capture buffer size")?)
            .timeout(to_i32(config.read_timeout_ms, "read timeout")?);

        let inactive = if config.immediate_mode {
            inactive.immediate_mode(true)
        } else {
            inactive
        };

        let mut cap = inactive
            .open()
            .with_context(|| format!("failed to open capture on {}", config.interface))?;

        let linktype = choose_supported_datalink(&mut cap)?;

        if let Some(filter) = config
            .bpf_filter
            .as_deref()
            .filter(|filter| !filter.is_empty())
        {
            cap.filter(filter, true)
                .with_context(|| format!("failed to compile/apply BPF filter: {filter}"))?;
        }

        tracing::info!(
            interface = %config.interface,
            linktype = linktype.0,
            link_layer = LinkLayer::from_pcap(linktype).as_str(),
            snaplen = config.snaplen,
            buffer_size = config.buffer_size,
            read_timeout_ms = config.read_timeout_ms,
            promisc = config.promisc,
            immediate_mode = config.immediate_mode,
            bpf_filter = config.bpf_filter.as_deref().unwrap_or(""),
            "Live capture opened"
        );

        Ok(Self {
            cap,
            link_layer: LinkLayer::from_pcap(linktype),
            linktype: linktype.0,
            shutdown: config.shutdown,
            max_packets: config.max_packets,
            captured_packets: 0,
        })
    }

    fn should_stop(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
            || self
                .max_packets
                .is_some_and(|limit| self.captured_packets >= limit)
    }
}

fn choose_supported_datalink(cap: &mut Capture<Active>) -> Result<Linktype> {
    let current = cap.get_datalink();
    if LinkLayer::from_pcap(current) != LinkLayer::Unsupported {
        return Ok(current);
    }

    let datalinks = cap
        .list_datalinks()
        .context("failed to list live capture datalinks")?;
    let Some(linktype) = datalinks
        .into_iter()
        .find(|linktype| LinkLayer::from_pcap(*linktype) != LinkLayer::Unsupported)
    else {
        return Ok(current);
    };

    tracing::warn!(
        from_linktype = current.0,
        to_linktype = linktype.0,
        to_link_layer = LinkLayer::from_pcap(linktype).as_str(),
        "Switching live capture to a supported datalink"
    );
    cap.set_datalink(linktype)
        .with_context(|| format!("failed to switch live capture datalink to {}", linktype.0))?;
    Ok(cap.get_datalink())
}

#[async_trait::async_trait]
impl PacketSource for LiveCaptureSource {
    async fn next_batch(&mut self, batch: &mut PacketBatch) -> Result<usize> {
        batch.clear();
        let target = batch.capacity().max(1);

        while batch.len() < target {
            if self.should_stop() {
                break;
            }

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
                    self.captured_packets = self.captured_packets.saturating_add(1);
                }
                Err(pcap::Error::TimeoutExpired) => {
                    break;
                }
                Err(e) => return Err(anyhow!(e)),
            }
        }

        Ok(batch.len())
    }

    fn is_finished(&self) -> bool {
        self.should_stop()
    }

    fn stats(&mut self) -> Result<Option<PacketSourceStats>> {
        let stats = self.cap.stats()?;
        Ok(Some(PacketSourceStats {
            received: u64::from(stats.received),
            dropped: u64::from(stats.dropped),
            interface_dropped: u64::from(stats.if_dropped),
        }))
    }
}

pub fn list_capture_devices() -> Result<Vec<CaptureDeviceInfo>> {
    let mut devices = Device::list()?
        .into_iter()
        .map(|device| CaptureDeviceInfo {
            name: device.name,
            description: device.desc,
            addresses: device
                .addresses
                .into_iter()
                .map(|address| address.addr)
                .collect(),
            is_up: device.flags.is_up(),
            is_running: device.flags.is_running(),
            is_loopback: device.flags.is_loopback(),
            is_wireless: device.flags.is_wireless(),
        })
        .collect::<Vec<_>>();

    devices.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(devices)
}

fn to_i32(value: usize, name: &str) -> Result<i32> {
    i32::try_from(value).with_context(|| format!("{name} is too large: {value}"))
}
