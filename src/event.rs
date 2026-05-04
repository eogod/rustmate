use std::net::IpAddr;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;
use serde_json::{Value, json};

use crate::packet::{DecodedPacket, RawPacket, TransportProtocol};

#[derive(Debug, Serialize)]
pub struct Event {
    pub ts_sec: u64,
    pub ts_usec: u32,
    pub analyzer: &'static str,
    pub event_type: &'static str,
    pub length: usize,
    pub link_layer: &'static str,
    pub linktype: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<TransportProtocol>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_addr: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_addr: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    #[serde(skip_serializing_if = "Value::is_null")]
    pub fields: Value,
}

impl Event {
    pub fn from_packet(
        analyzer: &'static str,
        event_type: &'static str,
        packet: &DecodedPacket<'_>,
        length: usize,
        fields: Value,
    ) -> Self {
        let (source_addr, destination_addr) = packet.ip_addresses();
        let transport = packet.transport_payload();

        Self {
            ts_sec: packet.timestamp.sec,
            ts_usec: packet.timestamp.usec,
            analyzer,
            event_type,
            length,
            link_layer: packet.link_layer.as_str(),
            linktype: packet.linktype,
            protocol: transport.as_ref().map(|transport| transport.protocol),
            source_addr,
            destination_addr,
            source_port: transport
                .as_ref()
                .and_then(|transport| transport.source_port),
            destination_port: transport
                .as_ref()
                .and_then(|transport| transport.destination_port),
            fields,
        }
    }

    pub fn packet_dump(packet: &RawPacket) -> Self {
        Self {
            ts_sec: packet.timestamp.sec,
            ts_usec: packet.timestamp.usec,
            analyzer: "packet",
            event_type: "raw_packet",
            length: packet.data.len(),
            link_layer: packet.link_layer.as_str(),
            linktype: packet.linktype,
            protocol: None,
            source_addr: None,
            destination_addr: None,
            source_port: None,
            destination_port: None,
            fields: json!({
                "data_base64": STANDARD.encode(&packet.data),
            }),
        }
    }
}
