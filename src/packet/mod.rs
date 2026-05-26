use std::net::IpAddr;

use etherparse::{NetSlice, SlicedPacket, TransportSlice};
use pcap::Linktype;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct RawPacket {
    pub timestamp: PacketTimestamp,
    pub link_layer: LinkLayer,
    pub linktype: i32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct PacketTimestamp {
    pub sec: u64,
    pub usec: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkLayer {
    Ethernet,
    LinuxSll,
    RawIp,
    BsdLoopback,
    Unsupported,
}

impl LinkLayer {
    pub fn from_pcap(linktype: Linktype) -> Self {
        match linktype {
            Linktype::ETHERNET => Self::Ethernet,
            Linktype::LINUX_SLL => Self::LinuxSll,
            Linktype::RAW | Linktype::IPV4 | Linktype::IPV6 => Self::RawIp,
            Linktype::NULL | Linktype::LOOP => Self::BsdLoopback,
            _ => Self::Unsupported,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            LinkLayer::Ethernet => "ethernet",
            LinkLayer::LinuxSll => "linux_sll",
            LinkLayer::RawIp => "raw_ip",
            LinkLayer::BsdLoopback => "bsd_loopback",
            LinkLayer::Unsupported => "unsupported",
        }
    }
}

pub struct DecodedPacket<'a> {
    pub timestamp: PacketTimestamp,
    pub link_layer: LinkLayer,
    pub linktype: i32,
    pub raw: &'a [u8],
    parsed: Option<SlicedPacket<'a>>,
    decode_error: Option<PacketDecodeError>,
}

enum PacketDecodeError {
    DecodeError(String),
    UnsupportedLinkLayer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmpv4,
    Icmpv6,
}

pub struct TransportPayload<'a> {
    pub protocol: TransportProtocol,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub bytes: &'a [u8],
    pub tcp: Option<TcpSegment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSegment {
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub flags: TcpFlags,
    pub window_size: u16,
    pub payload_len: usize,
}

impl TcpSegment {
    pub fn sequence_span(self) -> u32 {
        (self.payload_len as u32)
            .saturating_add(u32::from(self.flags.syn))
            .saturating_add(u32::from(self.flags.fin))
    }

    pub fn payload_sequence_start(self) -> u32 {
        self.sequence_number.wrapping_add(u32::from(self.flags.syn))
    }

    pub fn payload_sequence_end(self) -> u32 {
        self.payload_sequence_start()
            .wrapping_add(self.payload_len as u32)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl<'a> DecodedPacket<'a> {
    pub fn from_raw(packet: &'a RawPacket) -> Self {
        let (parsed, decode_error) = match packet.link_layer {
            LinkLayer::Ethernet => decode(SlicedPacket::from_ethernet(&packet.data)),
            LinkLayer::LinuxSll => decode(SlicedPacket::from_linux_sll(&packet.data)),
            LinkLayer::RawIp => decode(SlicedPacket::from_ip(&packet.data)),
            LinkLayer::BsdLoopback => decode_bsd_loopback(&packet.data),
            LinkLayer::Unsupported => (None, Some(PacketDecodeError::UnsupportedLinkLayer)),
        };

        Self {
            timestamp: packet.timestamp,
            link_layer: packet.link_layer,
            linktype: packet.linktype,
            raw: &packet.data,
            parsed,
            decode_error,
        }
    }

    pub fn decode_error(&self) -> Option<&str> {
        match &self.decode_error {
            None => None,
            Some(PacketDecodeError::DecodeError(err)) => Some(err.as_str()),
            Some(PacketDecodeError::UnsupportedLinkLayer) => Some("unsupported link layer"),
        }
    }

    pub fn ip_addresses(&self) -> (Option<IpAddr>, Option<IpAddr>) {
        let Some(packet) = &self.parsed else {
            return (None, None);
        };

        match packet.net.as_ref() {
            Some(NetSlice::Ipv4(ipv4)) => (
                Some(IpAddr::V4(ipv4.header().source_addr())),
                Some(IpAddr::V4(ipv4.header().destination_addr())),
            ),
            Some(NetSlice::Ipv6(ipv6)) => (
                Some(IpAddr::V6(ipv6.header().source_addr())),
                Some(IpAddr::V6(ipv6.header().destination_addr())),
            ),
            _ => (None, None),
        }
    }

    pub fn transport_payload(&self) -> Option<TransportPayload<'a>> {
        let Some(packet) = &self.parsed else {
            return None;
        };

        match packet.transport.as_ref()? {
            TransportSlice::Tcp(tcp) => Some(TransportPayload {
                protocol: TransportProtocol::Tcp,
                source_port: Some(tcp.source_port()),
                destination_port: Some(tcp.destination_port()),
                bytes: tcp.payload(),
                tcp: Some(TcpSegment {
                    sequence_number: tcp.sequence_number(),
                    acknowledgment_number: tcp.acknowledgment_number(),
                    flags: TcpFlags {
                        fin: tcp.fin(),
                        syn: tcp.syn(),
                        rst: tcp.rst(),
                        psh: tcp.psh(),
                        ack: tcp.ack(),
                        urg: tcp.urg(),
                        ece: tcp.ece(),
                        cwr: tcp.cwr(),
                    },
                    window_size: tcp.window_size(),
                    payload_len: tcp.payload().len(),
                }),
            }),
            TransportSlice::Udp(udp) => Some(TransportPayload {
                protocol: TransportProtocol::Udp,
                source_port: Some(udp.source_port()),
                destination_port: Some(udp.destination_port()),
                bytes: udp.payload(),
                tcp: None,
            }),
            TransportSlice::Icmpv4(icmp) => Some(TransportPayload {
                protocol: TransportProtocol::Icmpv4,
                source_port: None,
                destination_port: None,
                bytes: icmp.payload(),
                tcp: None,
            }),
            TransportSlice::Icmpv6(icmp) => Some(TransportPayload {
                protocol: TransportProtocol::Icmpv6,
                source_port: None,
                destination_port: None,
                bytes: icmp.payload(),
                tcp: None,
            }),
        }
    }
}

fn decode_bsd_loopback(data: &[u8]) -> (Option<SlicedPacket<'_>>, Option<PacketDecodeError>) {
    let Some(payload) = data.get(4..) else {
        return (
            None,
            Some(PacketDecodeError::DecodeError(
                "bsd loopback frame too short".to_owned(),
            )),
        );
    };
    // BSD/macOS loopback sticks a 4-byte address family header before the IP packet.
    decode(SlicedPacket::from_ip(payload))
}

fn decode(
    result: Result<SlicedPacket<'_>, etherparse::err::packet::SliceError>,
) -> (Option<SlicedPacket<'_>>, Option<PacketDecodeError>) {
    match result {
        Ok(packet) => (Some(packet), None),
        Err(err) => (None, Some(PacketDecodeError::DecodeError(err.to_string()))),
    }
}

#[cfg(test)]
mod tests {
    use etherparse::PacketBuilder;

    use super::*;

    #[test]
    fn decodes_tcp_payload_from_ethernet_frame() {
        let payload = b"GET /flag HTTP/1.1\r\n\r\n";
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 20)
            .tcp(31337, 80, 1, 1024);
        let mut data = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut data, payload).unwrap();

        let raw = RawPacket {
            timestamp: PacketTimestamp { sec: 1, usec: 2 },
            link_layer: LinkLayer::Ethernet,
            linktype: Linktype::ETHERNET.0,
            data,
        };

        let decoded = DecodedPacket::from_raw(&raw);
        let transport = decoded.transport_payload().unwrap();

        assert_eq!(TransportProtocol::Tcp, transport.protocol);
        assert_eq!(Some(31337), transport.source_port);
        assert_eq!(Some(80), transport.destination_port);
        assert_eq!(payload, transport.bytes);
        assert!(decoded.decode_error().is_none());
    }

    #[test]
    fn decodes_tcp_payload_from_bsd_loopback_frame() {
        let payload = b"GET /loop HTTP/1.1\r\n\r\n";
        let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([127, 0, 0, 1], [127, 0, 0, 1], 20)
            .tcp(31337, 80, 1, 1024);
        let mut ethernet = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut ethernet, payload).unwrap();
        let mut data = vec![0, 0, 0, 2];
        data.extend_from_slice(&ethernet[14..]);

        let raw = RawPacket {
            timestamp: PacketTimestamp { sec: 1, usec: 2 },
            link_layer: LinkLayer::BsdLoopback,
            linktype: Linktype::NULL.0,
            data,
        };

        let decoded = DecodedPacket::from_raw(&raw);
        let transport = decoded.transport_payload().unwrap();

        assert_eq!(TransportProtocol::Tcp, transport.protocol);
        assert_eq!(Some(31337), transport.source_port);
        assert_eq!(Some(80), transport.destination_port);
        assert_eq!(payload, transport.bytes);
        assert!(decoded.decode_error().is_none());
    }
}
