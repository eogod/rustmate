use ahash::AHashMap;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};

use crate::{
    event::Event,
    flow::{Endpoint, FlowDirection, FlowKey, FlowObservation, StreamChunk, TcpSequenceStatus},
    packet::{DecodedPacket, PacketTimestamp},
    protocol_detection::{
        ProtocolDetection, ProtocolDetectionSource, ProtocolServiceSide, detect_payload,
    },
};

const DEFAULT_EVICTION_INTERVAL_PACKETS: u64 = 16_384;
const CONTENT_SAMPLE_LIMIT: usize = 4096;

#[derive(Debug, Clone, Copy)]
pub struct StreamInventoryConfig {
    pub enabled: bool,
    pub max_streams: usize,
    pub idle_timeout_ms: u64,
    pub preview_bytes_per_direction: usize,
    pub update_packet_interval: u64,
    pub update_byte_interval: u64,
}

impl StreamInventoryConfig {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            max_streams: 0,
            idle_timeout_ms: 0,
            preview_bytes_per_direction: 0,
            update_packet_interval: 0,
            update_byte_interval: 0,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StreamInventoryStats {
    pub active_streams: usize,
    pub created_streams: u64,
    pub evicted_streams: u64,
    pub dropped_new_streams: u64,
    pub closed_streams: u64,
    pub stream_events: u64,
}

pub struct StreamInventory {
    config: StreamInventoryConfig,
    streams: AHashMap<FlowKey, StreamRecord>,
    observed_packets: u64,
    stats: StreamInventoryStats,
}

#[derive(Debug, Clone)]
struct StreamRecord {
    id: u64,
    key: FlowKey,
    content_shard: Option<usize>,
    service: ServiceGuess,
    first_seen_us: u64,
    last_seen_us: u64,
    packets: u64,
    bytes: u64,
    payload_bytes: u64,
    stream_bytes: u64,
    stream_chunks: u64,
    directions: [DirectionRecord; 2],
    status: StreamStatus,
    last_emitted_packets: u64,
    last_emitted_stream_bytes: u64,
}

#[derive(Debug, Default, Clone)]
struct DirectionRecord {
    packets: u64,
    bytes: u64,
    payload_bytes: u64,
    stream_bytes: u64,
    stream_chunks: u64,
    first_sequence: Option<u32>,
    last_sequence: Option<u32>,
    fin_seen: bool,
    preview: Vec<u8>,
    content: ContentSampler,
}

#[derive(Debug, Default, Clone)]
struct ContentSampler {
    sampled: usize,
    printable: usize,
    whitespace: usize,
    control: usize,
    nulls: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamStatus {
    Open,
    Closing,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentKind {
    Unknown,
    Text,
    Binary,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ServiceGuess {
    name: &'static str,
    side: ProtocolServiceSide,
    confidence: u8,
    source: ProtocolDetectionSource,
    evidence: &'static str,
}

impl Default for ServiceGuess {
    fn default() -> Self {
        Self::from_detection(ProtocolDetection::unknown())
    }
}

impl ServiceGuess {
    fn from_detection(detection: ProtocolDetection) -> Self {
        Self {
            name: detection.service,
            side: detection.side,
            confidence: detection.confidence,
            source: detection.source,
            evidence: detection.evidence,
        }
    }

    fn observe_payload(&mut self, key: FlowKey, direction: FlowDirection, bytes: &[u8]) {
        let Some(detection) = detect_payload(key, direction, bytes) else {
            return;
        };
        let merged = ProtocolDetection {
            service: self.name,
            side: self.side,
            confidence: self.confidence,
            source: self.source,
            evidence: self.evidence,
        }
        .merge(detection);
        *self = Self::from_detection(merged);
    }
}

impl StreamInventory {
    pub fn new(config: StreamInventoryConfig) -> Self {
        let capacity = if config.enabled {
            config.max_streams.min(65_536)
        } else {
            0
        };
        Self {
            config,
            streams: AHashMap::with_capacity(capacity),
            observed_packets: 0,
            stats: StreamInventoryStats::default(),
        }
    }

    pub fn observe_flow(
        &mut self,
        packet: &DecodedPacket<'_>,
        flow: &FlowObservation<'_>,
        content_shard: Option<usize>,
        events: &mut Vec<Event>,
    ) {
        if !self.config.enabled {
            return;
        }

        self.observed_packets = self.observed_packets.saturating_add(1);
        let now_us = timestamp_us(packet.timestamp);
        if self.should_evict() {
            self.evict_idle(now_us);
        }

        let created = match self.ensure_stream(flow.key, now_us) {
            Some(created) => created,
            None => return,
        };

        let (closed_now, event) = {
            let Some(record) = self.streams.get_mut(&flow.key) else {
                return;
            };
            let previous_status = record.status;
            let previous_kind = record.content_kind();
            let previous_service = record.service;
            let previous_content_shard = record.content_shard;

            record.content_shard = content_shard.or(record.content_shard);
            record.observe_packet(packet, flow.direction);
            if let Some(tcp) = flow.tcp.as_ref() {
                record.observe_tcp_status(flow.direction, tcp.status);
                for chunk in &tcp.stream_chunks {
                    record.observe_stream_chunk(chunk, self.config.preview_bytes_per_direction);
                }
            } else if let Some(transport) = packet.transport_payload() {
                record.observe_payload_unit(
                    flow.direction,
                    transport.bytes,
                    None,
                    self.config.preview_bytes_per_direction,
                );
            }

            let closed_now =
                previous_status != StreamStatus::Closed && record.status == StreamStatus::Closed;
            let force_update = previous_status != record.status
                || previous_kind != record.content_kind()
                || previous_service != record.service
                || previous_content_shard != record.content_shard;
            let event = if created {
                record.mark_emitted();
                Some(("stream_open", record.fields()))
            } else if record.should_emit_update(
                self.config.update_packet_interval,
                self.config.update_byte_interval,
                force_update,
            ) {
                record.mark_emitted();
                Some(("stream_update", record.fields()))
            } else {
                None
            };
            (closed_now, event)
        };

        if closed_now {
            self.stats.closed_streams = self.stats.closed_streams.saturating_add(1);
        }

        if let Some((event_type, fields)) = event {
            events.push(Event::from_packet(
                "stream_inventory",
                event_type,
                packet,
                packet.raw.len(),
                fields,
            ));
            self.stats.stream_events = self.stats.stream_events.saturating_add(1);
        }
    }

    pub fn stats(&self) -> StreamInventoryStats {
        StreamInventoryStats {
            active_streams: self.streams.len(),
            ..self.stats
        }
    }

    fn ensure_stream(&mut self, key: FlowKey, now_us: u64) -> Option<bool> {
        if self.streams.contains_key(&key) {
            return Some(false);
        }

        if self.streams.len() >= self.config.max_streams {
            self.evict_idle(now_us);
            if self.streams.len() >= self.config.max_streams {
                self.evict_oldest();
            }
        }

        if self.streams.len() >= self.config.max_streams {
            self.stats.dropped_new_streams = self.stats.dropped_new_streams.saturating_add(1);
            return None;
        }

        self.streams.insert(key, StreamRecord::new(key, now_us));
        self.stats.created_streams = self.stats.created_streams.saturating_add(1);
        Some(true)
    }

    fn should_evict(&self) -> bool {
        self.observed_packets != 0
            && self
                .observed_packets
                .is_multiple_of(DEFAULT_EVICTION_INTERVAL_PACKETS)
    }

    fn evict_idle(&mut self, now_us: u64) {
        let before = self.streams.len();
        let timeout_us = self.config.idle_timeout_ms.saturating_mul(1_000);
        self.streams
            .retain(|_, record| now_us.saturating_sub(record.last_seen_us) <= timeout_us);
        self.stats.evicted_streams = self
            .stats
            .evicted_streams
            .saturating_add((before - self.streams.len()) as u64);
    }

    fn evict_oldest(&mut self) {
        let Some(key) = self
            .streams
            .iter()
            .min_by_key(|(_, record)| record.last_seen_us)
            .map(|(key, _)| *key)
        else {
            return;
        };
        self.streams.remove(&key);
        self.stats.evicted_streams = self.stats.evicted_streams.saturating_add(1);
    }
}

impl StreamRecord {
    fn new(key: FlowKey, now_us: u64) -> Self {
        Self {
            id: key.stable_id(),
            key,
            content_shard: None,
            service: infer_service(key),
            first_seen_us: now_us,
            last_seen_us: now_us,
            packets: 0,
            bytes: 0,
            payload_bytes: 0,
            stream_bytes: 0,
            stream_chunks: 0,
            directions: [DirectionRecord::default(), DirectionRecord::default()],
            status: StreamStatus::Open,
            last_emitted_packets: 0,
            last_emitted_stream_bytes: 0,
        }
    }

    fn observe_packet(&mut self, packet: &DecodedPacket<'_>, direction: FlowDirection) {
        self.last_seen_us = timestamp_us(packet.timestamp);
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(packet.raw.len() as u64);

        let payload_bytes = packet
            .transport_payload()
            .map_or(0, |transport| transport.bytes.len() as u64);
        self.payload_bytes = self.payload_bytes.saturating_add(payload_bytes);

        let direction = &mut self.directions[direction_index(direction)];
        direction.packets = direction.packets.saturating_add(1);
        direction.bytes = direction.bytes.saturating_add(packet.raw.len() as u64);
        direction.payload_bytes = direction.payload_bytes.saturating_add(payload_bytes);
    }

    fn observe_tcp_status(&mut self, direction: FlowDirection, status: TcpSequenceStatus) {
        match status {
            TcpSequenceStatus::Reset => {
                self.status = StreamStatus::Closed;
            }
            TcpSequenceStatus::Fin => {
                self.directions[direction_index(direction)].fin_seen = true;
                self.status = if self.directions.iter().all(|direction| direction.fin_seen) {
                    StreamStatus::Closed
                } else {
                    StreamStatus::Closing
                };
            }
            _ => {}
        }
    }

    fn observe_stream_chunk(&mut self, chunk: &StreamChunk<'_>, preview_limit: usize) {
        self.observe_payload_unit(
            chunk.direction,
            chunk.bytes.as_slice(),
            Some((chunk.sequence_start, chunk.sequence_end)),
            preview_limit,
        );
    }

    fn observe_payload_unit(
        &mut self,
        direction: FlowDirection,
        bytes: &[u8],
        sequence: Option<(u32, u32)>,
        preview_limit: usize,
    ) {
        if bytes.is_empty() {
            return;
        }

        self.service.observe_payload(self.key, direction, bytes);
        self.stream_bytes = self.stream_bytes.saturating_add(bytes.len() as u64);
        self.stream_chunks = self.stream_chunks.saturating_add(1);

        let direction = &mut self.directions[direction_index(direction)];
        direction.stream_bytes = direction.stream_bytes.saturating_add(bytes.len() as u64);
        direction.stream_chunks = direction.stream_chunks.saturating_add(1);
        if let Some((start, end)) = sequence {
            direction.first_sequence.get_or_insert(start);
            direction.last_sequence = Some(end);
        }
        direction.extend_preview(bytes, preview_limit);
        direction.content.observe(bytes);
    }

    fn content_kind(&self) -> ContentKind {
        self.service.adjust_content_kind(combine_content_kind(
            self.directions[0].content.kind(),
            self.directions[1].content.kind(),
        ))
    }

    fn should_emit_update(
        &self,
        packet_interval: u64,
        byte_interval: u64,
        force_update: bool,
    ) -> bool {
        force_update
            || (packet_interval != 0
                && self.packets.saturating_sub(self.last_emitted_packets) >= packet_interval)
            || (byte_interval != 0
                && self
                    .stream_bytes
                    .saturating_sub(self.last_emitted_stream_bytes)
                    >= byte_interval)
    }

    fn mark_emitted(&mut self) {
        self.last_emitted_packets = self.packets;
        self.last_emitted_stream_bytes = self.stream_bytes;
    }

    fn fields(&self) -> Value {
        json!({
            "stream_id": format!("{:016x}", self.id),
            "first_seen_us": self.first_seen_us,
            "last_seen_us": self.last_seen_us,
            "protocol": self.key.protocol,
            "endpoint_a": endpoint_fields(self.key.a),
            "endpoint_b": endpoint_fields(self.key.b),
            "content_shard": self.content_shard,
            "service": {
                "name": self.service.name,
                "side": self.service.side.as_str(),
                "confidence": self.service.confidence,
                "source": self.service.source.as_str(),
                "evidence": self.service.evidence,
            },
            "status": self.status.as_str(),
            "content_kind": self.content_kind().as_str(),
            "packets": self.packets,
            "bytes": self.bytes,
            "payload_bytes": self.payload_bytes,
            "stream_bytes": self.stream_bytes,
            "stream_chunks": self.stream_chunks,
            "directions": {
                "a_to_b": self.directions[0].fields(),
                "b_to_a": self.directions[1].fields(),
            }
        })
    }
}

impl DirectionRecord {
    fn extend_preview(&mut self, bytes: &[u8], limit: usize) {
        if self.preview.len() >= limit {
            return;
        }

        let take = limit.saturating_sub(self.preview.len()).min(bytes.len());
        self.preview.extend_from_slice(&bytes[..take]);
    }

    fn fields(&self) -> Value {
        json!({
            "packets": self.packets,
            "bytes": self.bytes,
            "payload_bytes": self.payload_bytes,
            "stream_bytes": self.stream_bytes,
            "stream_chunks": self.stream_chunks,
            "first_sequence": self.first_sequence,
            "last_sequence": self.last_sequence,
            "content_kind": self.content.kind().as_str(),
            "preview_base64": STANDARD.encode(&self.preview),
            "preview_text": preview_text(&self.preview, self.content.kind()),
        })
    }
}

impl ContentSampler {
    fn observe(&mut self, bytes: &[u8]) {
        if self.sampled >= CONTENT_SAMPLE_LIMIT {
            return;
        }

        let take = CONTENT_SAMPLE_LIMIT
            .saturating_sub(self.sampled)
            .min(bytes.len());
        for byte in &bytes[..take] {
            self.sampled += 1;
            match *byte {
                0 => self.nulls += 1,
                b'\n' | b'\r' | b'\t' | b' ' => self.whitespace += 1,
                0x20..=0x7e => self.printable += 1,
                0x01..=0x1f | 0x7f => self.control += 1,
                _ => self.printable += 1,
            }
        }
    }

    fn kind(&self) -> ContentKind {
        if self.sampled == 0 {
            return ContentKind::Unknown;
        }
        if self.nulls != 0 || self.control.saturating_mul(100) / self.sampled > 5 {
            return ContentKind::Binary;
        }

        let textish = self.printable.saturating_add(self.whitespace);
        if textish.saturating_mul(100) / self.sampled >= 90 {
            ContentKind::Text
        } else {
            ContentKind::Mixed
        }
    }
}

impl StreamStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closing => "closing",
            Self::Closed => "closed",
        }
    }
}

impl ContentKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Text => "text",
            Self::Binary => "binary",
            Self::Mixed => "mixed",
        }
    }
}

impl ServiceGuess {
    fn adjust_content_kind(self, kind: ContentKind) -> ContentKind {
        if kind != ContentKind::Binary {
            return kind;
        }

        if is_text_framed_service(self.name) {
            ContentKind::Mixed
        } else {
            kind
        }
    }
}

fn is_text_framed_service(service: &str) -> bool {
    matches!(
        service,
        "http"
            | "http2"
            | "websocket"
            | "ssh"
            | "smtp"
            | "ftp"
            | "redis"
            | "memcached"
            | "pop3"
            | "imap"
    )
}

fn endpoint_fields(endpoint: Endpoint) -> Value {
    json!({
        "addr": endpoint.addr,
        "port": endpoint.port,
    })
}

fn infer_service(key: FlowKey) -> ServiceGuess {
    ServiceGuess::from_detection(ProtocolDetection::from_port(key))
}

fn combine_content_kind(a: ContentKind, b: ContentKind) -> ContentKind {
    match (a, b) {
        (ContentKind::Unknown, other) | (other, ContentKind::Unknown) => other,
        (ContentKind::Binary, ContentKind::Text) | (ContentKind::Text, ContentKind::Binary) => {
            ContentKind::Mixed
        }
        (ContentKind::Mixed, _) | (_, ContentKind::Mixed) => ContentKind::Mixed,
        (ContentKind::Binary, ContentKind::Binary) => ContentKind::Binary,
        (ContentKind::Text, ContentKind::Text) => ContentKind::Text,
    }
}

fn preview_text(bytes: &[u8], kind: ContentKind) -> Option<String> {
    if !matches!(kind, ContentKind::Text | ContentKind::Mixed) || bytes.is_empty() {
        return None;
    }

    let mut out = String::with_capacity(bytes.len());
    for byte in bytes {
        match *byte {
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(*byte as char),
            _ => out.push('.'),
        }
    }
    Some(out)
}

fn direction_index(direction: FlowDirection) -> usize {
    match direction {
        FlowDirection::AToB => 0,
        FlowDirection::BToA => 1,
    }
}

fn timestamp_us(timestamp: PacketTimestamp) -> u64 {
    timestamp
        .sec
        .saturating_mul(1_000_000)
        .saturating_add(timestamp.usec as u64)
}

#[cfg(test)]
mod tests {
    use etherparse::PacketBuilder;
    use pcap::Linktype;

    use crate::{
        flow::{FlowRoute, FlowTable, FlowTableConfig},
        packet::{DecodedPacket, LinkLayer, PacketTimestamp, RawPacket, TransportProtocol},
    };

    use super::*;

    #[test]
    fn opens_stream_with_text_preview_and_service_guess() {
        let mut inventory = inventory(StreamInventoryConfig {
            update_packet_interval: 10,
            update_byte_interval: 10_000,
            ..config()
        });
        let mut flow_table = flow_table();
        let raw = tcp_packet(
            1,
            12345,
            80,
            b"GET /flag HTTP/1.1\r\nHost: ctf.local\r\n\r\n",
        );
        let mut events = Vec::new();

        feed(&mut inventory, &mut flow_table, &raw, &mut events);

        assert_eq!(1, events.len());
        assert_eq!("stream_inventory", events[0].analyzer);
        assert_eq!("stream_open", events[0].event_type);
        assert_eq!("http", events[0].fields["service"]["name"]);
        assert_eq!("text", events[0].fields["content_kind"]);
        assert_eq!(
            "GET /flag HTTP/1.1\\r\\nHost: ctf.local\\r\\n\\r\\n",
            events[0].fields["directions"]["a_to_b"]["preview_text"]
        );
        assert_eq!(1, inventory.stats().active_streams);
        assert_eq!(1, inventory.stats().created_streams);
    }

    #[test]
    fn emits_update_after_stream_byte_threshold() {
        let mut inventory = inventory(StreamInventoryConfig {
            update_packet_interval: 0,
            update_byte_interval: 4,
            ..config()
        });
        let mut flow_table = flow_table();
        let mut events = Vec::new();

        feed(
            &mut inventory,
            &mut flow_table,
            &tcp_packet(1, 1111, 2222, b"abc"),
            &mut events,
        );
        feed(
            &mut inventory,
            &mut flow_table,
            &tcp_packet(4, 1111, 2222, b"defg"),
            &mut events,
        );

        assert_eq!(2, events.len());
        assert_eq!("stream_open", events[0].event_type);
        assert_eq!("stream_update", events[1].event_type);
        assert_eq!(7, events[1].fields["stream_bytes"]);
        assert_eq!(2, inventory.stats().stream_events);
    }

    #[test]
    fn classifies_binary_payload() {
        let mut inventory = inventory(config());
        let mut flow_table = flow_table();
        let mut events = Vec::new();

        feed(
            &mut inventory,
            &mut flow_table,
            &tcp_packet(1, 1111, 4444, b"\x16\x03\x01\x00\x00"),
            &mut events,
        );

        assert_eq!("binary", events[0].fields["content_kind"]);
        assert!(events[0].fields["directions"]["a_to_b"]["preview_text"].is_null());
    }

    #[test]
    fn text_framed_services_with_binary_body_report_mixed() {
        let mut inventory = inventory(config());
        let mut flow_table = flow_table();
        let mut events = Vec::new();

        feed(
            &mut inventory,
            &mut flow_table,
            &tcp_packet(1, 1111, 80, b"\x1f\x8b\x08\x00\x00\x00\x00\x00"),
            &mut events,
        );

        assert_eq!("http", events[0].fields["service"]["name"]);
        assert_eq!("mixed", events[0].fields["content_kind"]);
        assert_eq!(
            "binary",
            events[0].fields["directions"]["a_to_b"]["content_kind"]
        );
    }

    #[test]
    fn detects_http_on_nonstandard_port_from_payload() {
        let mut inventory = inventory(config());
        let mut flow_table = flow_table();
        let mut events = Vec::new();

        feed(
            &mut inventory,
            &mut flow_table,
            &tcp_packet(
                1,
                49_000,
                31_337,
                b"GET /flag HTTP/1.1\r\nHost: ctf.local\r\n\r\n",
            ),
            &mut events,
        );

        assert_eq!("http", events[0].fields["service"]["name"]);
        assert_eq!("b", events[0].fields["service"]["side"]);
        assert_eq!("payload", events[0].fields["service"]["source"]);
        assert_eq!("http_request", events[0].fields["service"]["evidence"]);
    }

    #[test]
    fn detects_https_from_port_and_tls_payload() {
        let mut inventory = inventory(config());
        let mut flow_table = flow_table();
        let mut events = Vec::new();

        feed(
            &mut inventory,
            &mut flow_table,
            &tcp_packet(1, 49_000, 443, b"\x16\x03\x01\x00\x2a\x01\x00\x00"),
            &mut events,
        );

        assert_eq!("https", events[0].fields["service"]["name"]);
        assert_eq!("b", events[0].fields["service"]["side"]);
        assert_eq!("port_and_payload", events[0].fields["service"]["source"]);
        assert_eq!("https_tls_record", events[0].fields["service"]["evidence"]);
        assert_eq!("binary", events[0].fields["content_kind"]);
    }

    #[test]
    fn detects_websocket_upgrade_above_http_port_guess() {
        let mut inventory = inventory(config());
        let mut flow_table = flow_table();
        let mut events = Vec::new();

        feed(
            &mut inventory,
            &mut flow_table,
            &tcp_packet(
                1,
                49_000,
                80,
                b"GET /ws HTTP/1.1\r\nHost: ctf.local\r\nUpgrade: websocket\r\n\r\n",
            ),
            &mut events,
        );

        assert_eq!("websocket", events[0].fields["service"]["name"]);
        assert_eq!("b", events[0].fields["service"]["side"]);
        assert_eq!("payload", events[0].fields["service"]["source"]);
        assert_eq!(
            "http_websocket_upgrade",
            events[0].fields["service"]["evidence"]
        );
    }

    #[test]
    fn stable_id_is_direction_independent() {
        let a = Endpoint {
            addr: "10.0.0.1".parse().unwrap(),
            port: 1111,
        };
        let b = Endpoint {
            addr: "10.0.0.2".parse().unwrap(),
            port: 80,
        };

        let forward = FlowRoute::new(TransportProtocol::Tcp, a, b).key;
        let reverse = FlowRoute::new(TransportProtocol::Tcp, b, a).key;

        assert_eq!(forward.stable_id(), reverse.stable_id());
    }

    #[test]
    fn evicts_oldest_when_inventory_is_full() {
        let mut inventory = inventory(StreamInventoryConfig {
            max_streams: 1,
            ..config()
        });
        let mut flow_table = flow_table();
        let mut events = Vec::new();

        feed(
            &mut inventory,
            &mut flow_table,
            &tcp_packet(1, 1111, 80, b"a"),
            &mut events,
        );
        feed(
            &mut inventory,
            &mut flow_table,
            &tcp_packet(1, 2222, 80, b"b"),
            &mut events,
        );

        assert_eq!(1, inventory.stats().active_streams);
        assert_eq!(2, inventory.stats().created_streams);
        assert_eq!(1, inventory.stats().evicted_streams);
    }

    #[test]
    fn disabled_inventory_is_noop() {
        let mut inventory = inventory(StreamInventoryConfig::disabled());
        let mut flow_table = flow_table();
        let mut events = Vec::new();

        feed(
            &mut inventory,
            &mut flow_table,
            &tcp_packet(1, 1111, 80, b"GET / HTTP/1.1\r\n\r\n"),
            &mut events,
        );

        assert!(events.is_empty());
        assert_eq!(StreamInventoryStats::default(), inventory.stats());
    }

    #[test]
    fn stream_events_include_content_shard_when_known() {
        let mut inventory = inventory(config());
        let mut flow_table = flow_table();
        let mut events = Vec::new();
        let raw = tcp_packet(1, 1111, 80, b"GET / HTTP/1.1\r\n\r\n");
        let packet = DecodedPacket::from_raw(&raw);
        let flow = flow_table.observe(&packet).unwrap();

        inventory.observe_flow(&packet, &flow, Some(3), &mut events);

        assert_eq!(1, events.len());
        assert_eq!(Some(3), events[0].fields["content_shard"].as_u64());
    }

    fn inventory(config: StreamInventoryConfig) -> StreamInventory {
        StreamInventory::new(config)
    }

    fn config() -> StreamInventoryConfig {
        StreamInventoryConfig {
            enabled: true,
            max_streams: 1024,
            idle_timeout_ms: 120_000,
            preview_bytes_per_direction: 128,
            update_packet_interval: 64,
            update_byte_interval: 64 * 1024,
        }
    }

    fn flow_table() -> FlowTable {
        FlowTable::new(FlowTableConfig::new(1024, 120_000, 64 * 1024, 16))
    }

    fn feed(
        inventory: &mut StreamInventory,
        flow_table: &mut FlowTable,
        raw: &RawPacket,
        events: &mut Vec<Event>,
    ) {
        let packet = DecodedPacket::from_raw(raw);
        let flow = flow_table.observe(&packet).unwrap();
        inventory.observe_flow(&packet, &flow, None, events);
    }

    fn tcp_packet(
        sequence: u32,
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) -> RawPacket {
        let builder = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 20)
            .tcp(source_port, destination_port, sequence, 2048);
        let mut data = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut data, payload).unwrap();
        RawPacket {
            timestamp: PacketTimestamp { sec: 10, usec: 20 },
            link_layer: LinkLayer::Ethernet,
            linktype: Linktype::ETHERNET.0,
            data,
        }
    }
}
