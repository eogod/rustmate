use serde_json::json;

use crate::{
    analyzers::Analyzer,
    event::Event,
    packet::{DecodedPacket, TransportProtocol},
};

#[derive(Default)]
pub struct DnsAnalyzer;

impl DnsAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for DnsAnalyzer {
    fn name(&self) -> &'static str {
        "dns"
    }

    fn analyze(&mut self, packet: &DecodedPacket<'_>, events: &mut Vec<Event>) {
        let Some(transport) = packet.transport_payload() else {
            return;
        };
        if transport.protocol != TransportProtocol::Udp {
            return;
        }
        if transport.source_port != Some(53) && transport.destination_port != Some(53) {
            return;
        }
        if transport.bytes.len() < 12 {
            return;
        }

        let flags = u16::from_be_bytes([transport.bytes[2], transport.bytes[3]]);
        events.push(Event::from_packet(
            self.name(),
            "dns_message",
            packet,
            transport.bytes.len(),
            json!({
                "transaction_id": u16::from_be_bytes([transport.bytes[0], transport.bytes[1]]),
                "is_response": flags & 0x8000 != 0,
                "opcode": (flags >> 11) & 0x0f,
                "rcode": flags & 0x0f,
                "questions": u16::from_be_bytes([transport.bytes[4], transport.bytes[5]]),
                "answers": u16::from_be_bytes([transport.bytes[6], transport.bytes[7]]),
                "authorities": u16::from_be_bytes([transport.bytes[8], transport.bytes[9]]),
                "additionals": u16::from_be_bytes([transport.bytes[10], transport.bytes[11]]),
            }),
        ));
    }
}
