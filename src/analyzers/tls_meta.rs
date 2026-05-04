use serde_json::json;

use crate::{
    analyzers::Analyzer,
    event::Event,
    packet::{DecodedPacket, TransportProtocol},
};

#[derive(Default)]
pub struct TlsMetaAnalyzer;

impl TlsMetaAnalyzer {
    pub fn new() -> Self {
        Self
    }
}

impl Analyzer for TlsMetaAnalyzer {
    fn name(&self) -> &'static str {
        "tls_meta"
    }

    fn analyze(&mut self, packet: &DecodedPacket<'_>, events: &mut Vec<Event>) {
        let Some(transport) = packet.transport_payload() else {
            return;
        };
        if transport.protocol != TransportProtocol::Tcp || transport.bytes.len() < 5 {
            return;
        }

        let content_type = transport.bytes[0];
        let major = transport.bytes[1];
        let minor = transport.bytes[2];
        if major != 3 || !(0..=4).contains(&minor) {
            return;
        }

        let record_len = u16::from_be_bytes([transport.bytes[3], transport.bytes[4]]);
        let handshake_type =
            (content_type == 22 && transport.bytes.len() > 5).then(|| match transport.bytes[5] {
                1 => "client_hello",
                2 => "server_hello",
                11 => "certificate",
                20 => "finished",
                _ => "handshake",
            });

        events.push(Event::from_packet(
            self.name(),
            "tls_record",
            packet,
            transport.bytes.len(),
            json!({
                "content_type": tls_content_type(content_type),
                "version": format!("3.{minor}"),
                "record_len": record_len,
                "handshake_type": handshake_type,
            }),
        ));
    }
}

fn tls_content_type(content_type: u8) -> &'static str {
    match content_type {
        20 => "change_cipher_spec",
        21 => "alert",
        22 => "handshake",
        23 => "application_data",
        _ => "unknown",
    }
}
