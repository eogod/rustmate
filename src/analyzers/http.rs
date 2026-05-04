use serde_json::json;

use crate::{
    analyzers::Analyzer,
    event::Event,
    packet::{DecodedPacket, TransportProtocol},
};

#[derive(Default)]
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

    fn analyze(&mut self, packet: &DecodedPacket<'_>, events: &mut Vec<Event>) {
        let Some(transport) = packet.transport_payload() else {
            return;
        };
        if transport.protocol != TransportProtocol::Tcp {
            return;
        }

        if let Some(method) = http_method(transport.bytes) {
            events.push(Event::from_packet(
                self.name(),
                "http_request",
                packet,
                transport.bytes.len(),
                json!({
                    "method": method,
                    "target": http_target(transport.bytes),
                    "line": first_line(transport.bytes),
                }),
            ));
        } else if transport.bytes.starts_with(b"HTTP/") {
            events.push(Event::from_packet(
                self.name(),
                "http_response",
                packet,
                transport.bytes.len(),
                json!({
                    "line": first_line(transport.bytes),
                }),
            ));
        }
    }
}

fn http_method(payload: &[u8]) -> Option<&'static str> {
    const METHODS: &[(&[u8], &str)] = &[
        (b"GET ", "GET"),
        (b"POST ", "POST"),
        (b"PUT ", "PUT"),
        (b"DELETE ", "DELETE"),
        (b"PATCH ", "PATCH"),
        (b"HEAD ", "HEAD"),
        (b"OPTIONS ", "OPTIONS"),
    ];

    METHODS
        .iter()
        .find_map(|(prefix, method)| payload.starts_with(prefix).then_some(*method))
}

fn http_target(payload: &[u8]) -> Option<String> {
    let line = first_line(payload)?;
    let mut parts = line.split_ascii_whitespace();
    let _method = parts.next()?;
    parts.next().map(ToOwned::to_owned)
}

fn first_line(payload: &[u8]) -> Option<String> {
    let end = payload
        .iter()
        .position(|byte| *byte == b'\r' || *byte == b'\n')
        .unwrap_or(payload.len());
    std::str::from_utf8(&payload[..end])
        .ok()
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use etherparse::PacketBuilder;
    use pcap::Linktype;

    use crate::packet::{DecodedPacket, LinkLayer, PacketTimestamp, RawPacket};

    use super::*;

    #[test]
    fn emits_http_request_from_tcp_payload() {
        let payload = b"GET /flag HTTP/1.1\r\nHost: ctf.local\r\n\r\n";
        let builder = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 20)
            .tcp(4242, 80, 1, 2048);
        let mut data = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut data, payload).unwrap();
        let raw = RawPacket {
            timestamp: PacketTimestamp { sec: 10, usec: 20 },
            link_layer: LinkLayer::Ethernet,
            linktype: Linktype::ETHERNET.0,
            data,
        };

        let packet = DecodedPacket::from_raw(&raw);
        let mut analyzer = HttpAnalyzer::new();
        let mut events = Vec::new();
        analyzer.analyze(&packet, &mut events);

        assert_eq!(1, events.len());
        assert_eq!("http_request", events[0].event_type);
        assert_eq!(Some(4242), events[0].source_port);
        assert_eq!(Some(80), events[0].destination_port);
        assert_eq!("GET", events[0].fields["method"]);
        assert_eq!("/flag", events[0].fields["target"]);
    }
}
