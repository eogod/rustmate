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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketDecodeStatus {
    Parsed,
    NonIp,
    Fragmented,
    UnsupportedTransport,
    Malformed,
    UnsupportedLink,
}

impl PacketDecodeStatus {
    pub fn is_decode_error(self) -> bool {
        matches!(self, Self::Malformed | Self::UnsupportedLink)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketDecodeCounters {
    pub packet_parsed_packets: u64,
    pub packet_non_ip_packets: u64,
    pub packet_fragmented_packets: u64,
    pub packet_unsupported_transport_packets: u64,
    pub packet_malformed_packets: u64,
    pub packet_unsupported_link_packets: u64,
}

impl PacketDecodeCounters {
    pub fn observe(&mut self, status: PacketDecodeStatus) {
        match status {
            PacketDecodeStatus::Parsed => {
                self.packet_parsed_packets = self.packet_parsed_packets.saturating_add(1);
            }
            PacketDecodeStatus::NonIp => {
                self.packet_non_ip_packets = self.packet_non_ip_packets.saturating_add(1);
            }
            PacketDecodeStatus::Fragmented => {
                self.packet_fragmented_packets = self.packet_fragmented_packets.saturating_add(1);
            }
            PacketDecodeStatus::UnsupportedTransport => {
                self.packet_unsupported_transport_packets =
                    self.packet_unsupported_transport_packets.saturating_add(1);
            }
            PacketDecodeStatus::Malformed => {
                self.packet_malformed_packets = self.packet_malformed_packets.saturating_add(1);
            }
            PacketDecodeStatus::UnsupportedLink => {
                self.packet_unsupported_link_packets =
                    self.packet_unsupported_link_packets.saturating_add(1);
            }
        }
    }

    pub fn add(&mut self, other: Self) {
        self.packet_parsed_packets = self
            .packet_parsed_packets
            .saturating_add(other.packet_parsed_packets);
        self.packet_non_ip_packets = self
            .packet_non_ip_packets
            .saturating_add(other.packet_non_ip_packets);
        self.packet_fragmented_packets = self
            .packet_fragmented_packets
            .saturating_add(other.packet_fragmented_packets);
        self.packet_unsupported_transport_packets = self
            .packet_unsupported_transport_packets
            .saturating_add(other.packet_unsupported_transport_packets);
        self.packet_malformed_packets = self
            .packet_malformed_packets
            .saturating_add(other.packet_malformed_packets);
        self.packet_unsupported_link_packets = self
            .packet_unsupported_link_packets
            .saturating_add(other.packet_unsupported_link_packets);
    }

    pub fn decode_error_packets(self) -> u64 {
        self.packet_malformed_packets
            .saturating_add(self.packet_unsupported_link_packets)
    }
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

    pub fn decode_status(&self) -> PacketDecodeStatus {
        match &self.decode_error {
            Some(PacketDecodeError::UnsupportedLinkLayer) => {
                return PacketDecodeStatus::UnsupportedLink;
            }
            Some(PacketDecodeError::DecodeError(_)) => {
                return if raw_packet_is_fragmented(self.link_layer, self.raw) {
                    PacketDecodeStatus::Fragmented
                } else {
                    PacketDecodeStatus::Malformed
                };
            }
            None => {}
        }

        let Some(packet) = &self.parsed else {
            return PacketDecodeStatus::Malformed;
        };
        if !matches!(
            packet.net.as_ref(),
            Some(NetSlice::Ipv4(_) | NetSlice::Ipv6(_))
        ) {
            return PacketDecodeStatus::NonIp;
        }
        if packet.transport.is_none() {
            return if raw_packet_is_fragmented(self.link_layer, self.raw) {
                PacketDecodeStatus::Fragmented
            } else {
                PacketDecodeStatus::UnsupportedTransport
            };
        }

        PacketDecodeStatus::Parsed
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

fn raw_packet_is_fragmented(link_layer: LinkLayer, data: &[u8]) -> bool {
    let Some((network, offset)) = network_payload(link_layer, data) else {
        return false;
    };

    match network {
        NetworkHeader::Ipv4 => ipv4_is_fragmented(data, offset),
        NetworkHeader::Ipv6 => ipv6_is_fragmented(data, offset),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NetworkHeader {
    Ipv4,
    Ipv6,
}

fn network_payload(link_layer: LinkLayer, data: &[u8]) -> Option<(NetworkHeader, usize)> {
    match link_layer {
        LinkLayer::Ethernet => {
            let (ethertype, offset) = ethernet_payload(data)?;
            network_from_ethertype(ethertype).map(|network| (network, offset))
        }
        LinkLayer::LinuxSll => {
            let ethertype = read_u16(data, 14)?;
            network_from_ethertype(ethertype).map(|network| (network, 16))
        }
        LinkLayer::RawIp => network_from_ip_version(data, 0).map(|network| (network, 0)),
        LinkLayer::BsdLoopback => network_from_ip_version(data, 4).map(|network| (network, 4)),
        LinkLayer::Unsupported => None,
    }
}

fn ethernet_payload(data: &[u8]) -> Option<(u16, usize)> {
    if data.len() < 14 {
        return None;
    }

    let mut ethertype = read_u16(data, 12)?;
    let mut offset = 14;
    for _ in 0..2 {
        if !matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
            break;
        }
        if data.len() < offset + 4 {
            return None;
        }
        ethertype = read_u16(data, offset + 2)?;
        offset += 4;
    }

    Some((ethertype, offset))
}

fn network_from_ethertype(ethertype: u16) -> Option<NetworkHeader> {
    match ethertype {
        0x0800 => Some(NetworkHeader::Ipv4),
        0x86dd => Some(NetworkHeader::Ipv6),
        _ => None,
    }
}

fn network_from_ip_version(data: &[u8], offset: usize) -> Option<NetworkHeader> {
    match data.get(offset)? >> 4 {
        4 => Some(NetworkHeader::Ipv4),
        6 => Some(NetworkHeader::Ipv6),
        _ => None,
    }
}

fn ipv4_is_fragmented(data: &[u8], offset: usize) -> bool {
    let Some(flags_and_offset) = read_u16(data, offset + 6) else {
        return false;
    };
    flags_and_offset & 0x3fff != 0
}

fn ipv6_is_fragmented(data: &[u8], offset: usize) -> bool {
    if data.len() < offset + 40 || data[offset] >> 4 != 6 {
        return false;
    }

    let mut next_header = data[offset + 6];
    let mut cursor = offset + 40;
    for _ in 0..8 {
        match next_header {
            44 => return true,
            0 | 43 | 60 => {
                if data.len() < cursor + 2 {
                    return false;
                }
                next_header = data[cursor];
                cursor = cursor.saturating_add((usize::from(data[cursor + 1]) + 1) * 8);
            }
            51 => {
                if data.len() < cursor + 2 {
                    return false;
                }
                next_header = data[cursor];
                cursor = cursor.saturating_add((usize::from(data[cursor + 1]) + 2) * 4);
            }
            _ => return false,
        }
    }

    false
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *data.get(offset)?,
        *data.get(offset + 1)?,
    ]))
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
        assert_eq!(PacketDecodeStatus::Parsed, decoded.decode_status());
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
        assert_eq!(PacketDecodeStatus::Parsed, decoded.decode_status());
        assert!(decoded.decode_error().is_none());
    }

    #[test]
    fn reports_non_ip_ethernet_payloads() {
        let mut data = ethernet_header(0x0806);
        data.extend_from_slice(&[0; 28]);
        let raw = raw_ethernet(data);

        let decoded = DecodedPacket::from_raw(&raw);

        assert_eq!(PacketDecodeStatus::NonIp, decoded.decode_status());
        assert!(decoded.decode_error().is_none());
        assert!(decoded.transport_payload().is_none());
    }

    #[test]
    fn reports_unsupported_link_layers() {
        let raw = RawPacket {
            timestamp: PacketTimestamp { sec: 1, usec: 2 },
            link_layer: LinkLayer::Unsupported,
            linktype: 9999,
            data: b"no link parser".to_vec(),
        };

        let decoded = DecodedPacket::from_raw(&raw);

        assert_eq!(PacketDecodeStatus::UnsupportedLink, decoded.decode_status());
        assert_eq!(Some("unsupported link layer"), decoded.decode_error());
    }

    #[test]
    fn reports_malformed_ipv4_packets() {
        let mut data = ethernet_header(0x0800);
        data.extend_from_slice(&[
            0x45, 0, 0, 0, 0, 1, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ]);
        let raw = raw_ethernet(data);

        let decoded = DecodedPacket::from_raw(&raw);

        assert_eq!(PacketDecodeStatus::Malformed, decoded.decode_status());
        assert!(decoded.decode_error().is_some());
    }

    #[test]
    fn reports_ipv4_fragments_before_malformed_transport() {
        let mut data = ethernet_header(0x0800);
        data.extend_from_slice(&[
            0x45, 0, 0, 20, 0, 1, 0x20, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ]);
        let raw = raw_ethernet(data);

        let decoded = DecodedPacket::from_raw(&raw);

        assert_eq!(PacketDecodeStatus::Fragmented, decoded.decode_status());
        assert!(decoded.transport_payload().is_none());
    }

    #[test]
    fn reports_unsupported_transport_protocols() {
        let mut data = ethernet_header(0x0800);
        data.extend_from_slice(&[
            0x45, 0, 0, 20, 0, 1, 0, 0, 64, 47, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ]);
        let raw = raw_ethernet(data);

        let decoded = DecodedPacket::from_raw(&raw);

        assert_eq!(
            PacketDecodeStatus::UnsupportedTransport,
            decoded.decode_status()
        );
        assert!(decoded.decode_error().is_none());
        assert!(decoded.transport_payload().is_none());
    }

    #[test]
    fn packet_decode_counters_are_additive() {
        let mut left = PacketDecodeCounters::default();
        left.observe(PacketDecodeStatus::Parsed);
        left.observe(PacketDecodeStatus::Malformed);

        let mut right = PacketDecodeCounters::default();
        right.observe(PacketDecodeStatus::NonIp);
        right.observe(PacketDecodeStatus::UnsupportedLink);

        left.add(right);

        assert_eq!(1, left.packet_parsed_packets);
        assert_eq!(1, left.packet_non_ip_packets);
        assert_eq!(1, left.packet_malformed_packets);
        assert_eq!(1, left.packet_unsupported_link_packets);
        assert_eq!(2, left.decode_error_packets());
    }

    fn raw_ethernet(data: Vec<u8>) -> RawPacket {
        RawPacket {
            timestamp: PacketTimestamp { sec: 1, usec: 2 },
            link_layer: LinkLayer::Ethernet,
            linktype: Linktype::ETHERNET.0,
            data,
        }
    }

    fn ethernet_header(ethertype: u16) -> Vec<u8> {
        let mut data = Vec::with_capacity(14);
        data.extend_from_slice(&[1, 2, 3, 4, 5, 6]);
        data.extend_from_slice(&[7, 8, 9, 10, 11, 12]);
        data.extend_from_slice(&ethertype.to_be_bytes());
        data
    }
}
