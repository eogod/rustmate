use serde::{Deserialize, Serialize};

use crate::{
    event::Event,
    flow::{FlowObservation, StreamChunk},
    packet::DecodedPacket,
    stream_message::{
        ProtocolMessageAnalyzer, StreamMessage, StreamMessageProtocol, StreamMessageStatus,
    },
};

const DEFAULT_MAX_HTTP1_STATES: usize = 131_072;
const DEFAULT_MAX_DNS_STATES: usize = 131_072;
const DEFAULT_MAX_HTTP1_HEADER_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_HTTP1_BUFFER_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_MAX_MESSAGES_PER_CHUNK: usize = 512;

#[derive(Debug, Clone, Copy)]
pub struct StreamParserConfig {
    pub enabled: bool,
    pub max_http1_states: usize,
    pub max_dns_states: usize,
    pub max_http1_header_bytes: usize,
    pub max_http1_buffer_bytes: usize,
    pub max_messages_per_chunk: usize,
}

impl Default for StreamParserConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_http1_states: DEFAULT_MAX_HTTP1_STATES,
            max_dns_states: DEFAULT_MAX_DNS_STATES,
            max_http1_header_bytes: DEFAULT_MAX_HTTP1_HEADER_BYTES,
            max_http1_buffer_bytes: DEFAULT_MAX_HTTP1_BUFFER_BYTES,
            max_messages_per_chunk: DEFAULT_MAX_MESSAGES_PER_CHUNK,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamParserStats {
    pub parser_enabled: bool,
    pub parser_stream_chunks: u64,
    pub parser_stream_bytes: u64,
    pub parser_emitted_messages: u64,
    pub parser_dropped_messages: u64,
    pub parser_active_states: usize,
    pub parser_evicted_states: u64,
    pub http1_active_states: usize,
    pub http1_messages: u64,
    pub http1_parse_errors: u64,
    pub http1_dropped_chunks: u64,
    pub dns_active_states: usize,
    pub dns_messages: u64,
    pub dns_parse_errors: u64,
    pub dns_dropped_datagrams: u64,
}

pub struct StreamParserLayer {
    config: StreamParserConfig,
    registry: ProtocolMessageAnalyzer,
    stats: StreamParserStats,
}

impl StreamParserLayer {
    pub fn new(config: StreamParserConfig) -> Self {
        let config = config.normalized();
        let registry = ProtocolMessageAnalyzer::with_limits(
            config.max_http1_states,
            config.max_dns_states,
            config.max_http1_header_bytes,
            config.max_http1_buffer_bytes,
        );

        Self {
            config,
            registry,
            stats: StreamParserStats {
                parser_enabled: config.enabled,
                ..StreamParserStats::default()
            },
        }
    }

    pub fn observe_stream(
        &mut self,
        packet: &DecodedPacket<'_>,
        flow: &FlowObservation<'_>,
        chunk: &StreamChunk<'_>,
        events: &mut Vec<Event>,
    ) {
        if !self.config.enabled || chunk.is_empty() {
            return;
        }

        self.stats.parser_stream_chunks = self.stats.parser_stream_chunks.saturating_add(1);
        self.stats.parser_stream_bytes = self
            .stats
            .parser_stream_bytes
            .saturating_add(chunk.len() as u64);

        let event_start = events.len();
        self.registry
            .analyze_stream_packet(packet, flow, chunk, events);
        self.apply_event_cap(event_start, events);
        self.refresh_state_stats();
    }

    pub fn observe_datagram(
        &mut self,
        packet: &DecodedPacket<'_>,
        flow: &FlowObservation<'_>,
        payload: &[u8],
        events: &mut Vec<Event>,
    ) {
        if !self.config.enabled || payload.is_empty() {
            return;
        }

        self.stats.parser_stream_chunks = self.stats.parser_stream_chunks.saturating_add(1);
        self.stats.parser_stream_bytes = self
            .stats
            .parser_stream_bytes
            .saturating_add(payload.len() as u64);

        let event_start = events.len();
        self.registry
            .analyze_datagram_packet(packet, flow, payload, events);
        self.apply_event_cap(event_start, events);
        self.refresh_state_stats();
    }

    pub fn stats(&self) -> StreamParserStats {
        let mut stats = self.stats;
        stats.parser_enabled = self.config.enabled;
        stats.parser_active_states = self
            .registry
            .http1_active_states()
            .saturating_add(self.registry.dns_active_states());
        stats.parser_evicted_states = self
            .registry
            .http1_evicted_states()
            .saturating_add(self.registry.dns_evicted_states());
        stats.http1_active_states = self.registry.http1_active_states();
        stats.http1_dropped_chunks = self.registry.http1_dropped_chunks();
        stats.dns_active_states = self.registry.dns_active_states();
        stats.dns_dropped_datagrams = self.registry.dns_dropped_datagrams();
        stats
    }

    fn apply_event_cap(&mut self, event_start: usize, events: &mut Vec<Event>) {
        let emitted = events.len().saturating_sub(event_start);
        if emitted == 0 {
            return;
        }

        let keep = emitted.min(self.config.max_messages_per_chunk);
        let dropped = emitted.saturating_sub(keep);
        let kept_end = event_start.saturating_add(keep);
        for event in &events[event_start..kept_end] {
            if let Some(message) = StreamMessage::from_event(event) {
                self.stats.parser_emitted_messages =
                    self.stats.parser_emitted_messages.saturating_add(1);
                if message.protocol == StreamMessageProtocol::Http1 {
                    self.stats.http1_messages = self.stats.http1_messages.saturating_add(1);
                }
                if message.protocol == StreamMessageProtocol::Dns {
                    self.stats.dns_messages = self.stats.dns_messages.saturating_add(1);
                }
                if message.status == StreamMessageStatus::ParseError {
                    match message.protocol {
                        StreamMessageProtocol::Http1 => {
                            self.stats.http1_parse_errors =
                                self.stats.http1_parse_errors.saturating_add(1);
                        }
                        StreamMessageProtocol::Dns => {
                            self.stats.dns_parse_errors =
                                self.stats.dns_parse_errors.saturating_add(1);
                        }
                    }
                }
            }
        }

        if dropped != 0 {
            events.truncate(kept_end);
            self.stats.parser_dropped_messages = self
                .stats
                .parser_dropped_messages
                .saturating_add(dropped as u64);
        }
    }

    fn refresh_state_stats(&mut self) {
        self.stats.parser_active_states = self
            .registry
            .http1_active_states()
            .saturating_add(self.registry.dns_active_states());
        self.stats.parser_evicted_states = self
            .registry
            .http1_evicted_states()
            .saturating_add(self.registry.dns_evicted_states());
        self.stats.http1_active_states = self.registry.http1_active_states();
        self.stats.http1_dropped_chunks = self.registry.http1_dropped_chunks();
        self.stats.dns_active_states = self.registry.dns_active_states();
        self.stats.dns_dropped_datagrams = self.registry.dns_dropped_datagrams();
    }
}

impl Default for StreamParserLayer {
    fn default() -> Self {
        Self::new(StreamParserConfig::default())
    }
}

impl StreamParserConfig {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            max_http1_states: 0,
            max_dns_states: 0,
            max_http1_header_bytes: 0,
            max_http1_buffer_bytes: 0,
            max_messages_per_chunk: 0,
        }
    }

    fn normalized(self) -> Self {
        if !self.enabled {
            return Self::disabled();
        }

        Self {
            enabled: true,
            max_http1_states: self.max_http1_states.max(1),
            max_dns_states: self.max_dns_states.max(1),
            max_http1_header_bytes: self.max_http1_header_bytes.max(1),
            max_http1_buffer_bytes: self.max_http1_buffer_bytes.max(1),
            max_messages_per_chunk: self.max_messages_per_chunk.max(1),
        }
    }
}

#[cfg(test)]
mod tests {
    use etherparse::PacketBuilder;
    use pcap::Linktype;

    use crate::{
        flow::{FlowTable, FlowTableConfig},
        packet::{DecodedPacket, LinkLayer, PacketTimestamp, RawPacket},
    };

    use super::*;

    #[test]
    fn parser_layer_emits_http1_messages_and_stats() {
        let mut layer = StreamParserLayer::default();
        let mut flow_table = flow_table();
        let mut events = Vec::new();
        feed(
            &mut layer,
            &mut flow_table,
            &tcp_packet(100, b"GET /parser HTTP/1.1\r\nHost: parser.local\r\n\r\n"),
            &mut events,
        );

        let stats = layer.stats();
        assert_eq!(1, events.len());
        assert_eq!(1, stats.parser_stream_chunks);
        assert_eq!(1, stats.parser_emitted_messages);
        assert_eq!(1, stats.http1_messages);
        assert_eq!(1, stats.http1_active_states);
    }

    #[test]
    fn parser_layer_caps_messages_per_chunk() {
        let mut layer = StreamParserLayer::new(StreamParserConfig {
            max_messages_per_chunk: 1,
            ..StreamParserConfig::default()
        });
        let mut flow_table = flow_table();
        let mut events = Vec::new();
        feed(
            &mut layer,
            &mut flow_table,
            &tcp_packet(100, b"GET /one HTTP/1.1\r\n\r\nGET /two HTTP/1.1\r\n\r\n"),
            &mut events,
        );

        let stats = layer.stats();
        assert_eq!(1, events.len());
        assert_eq!(1, stats.parser_emitted_messages);
        assert_eq!(1, stats.parser_dropped_messages);
    }

    #[test]
    fn parser_layer_emits_dns_messages_from_datagrams() {
        let mut layer = StreamParserLayer::default();
        let mut flow_table = flow_table();
        let mut events = Vec::new();
        feed_datagram(
            &mut layer,
            &mut flow_table,
            &udp_packet(49_000, 53, &dns_query_packet()),
            &mut events,
        );

        let stats = layer.stats();
        assert_eq!(1, events.len());
        assert_eq!("dns_query", events[0].event_type);
        assert_eq!(1, stats.parser_stream_chunks);
        assert_eq!(1, stats.parser_emitted_messages);
        assert_eq!(1, stats.dns_messages);
        assert_eq!(0, stats.dns_parse_errors);
        assert_eq!(1, stats.dns_active_states);
    }

    fn feed(
        layer: &mut StreamParserLayer,
        flow_table: &mut FlowTable,
        raw: &RawPacket,
        events: &mut Vec<Event>,
    ) {
        let packet = DecodedPacket::from_raw(raw);
        let flow = flow_table.observe(&packet).unwrap();
        let tcp = flow.tcp.as_ref().unwrap();
        for chunk in &tcp.stream_chunks {
            layer.observe_stream(&packet, &flow, chunk, events);
        }
    }

    fn feed_datagram(
        layer: &mut StreamParserLayer,
        flow_table: &mut FlowTable,
        raw: &RawPacket,
        events: &mut Vec<Event>,
    ) {
        let packet = DecodedPacket::from_raw(raw);
        let flow = flow_table.observe(&packet).unwrap();
        let transport = packet.transport_payload().unwrap();
        layer.observe_datagram(&packet, &flow, transport.bytes, events);
    }

    fn flow_table() -> FlowTable {
        FlowTable::new(FlowTableConfig::new(1024, 120_000, 64 * 1024, 16))
    }

    fn tcp_packet(sequence: u32, payload: &[u8]) -> RawPacket {
        let builder = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 20)
            .tcp(4242, 80, sequence, 2048);
        let mut data = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut data, payload).unwrap();
        RawPacket {
            timestamp: PacketTimestamp { sec: 10, usec: 20 },
            link_layer: LinkLayer::Ethernet,
            linktype: Linktype::ETHERNET.0,
            data,
        }
    }

    fn udp_packet(source_port: u16, destination_port: u16, payload: &[u8]) -> RawPacket {
        let builder = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 20)
            .udp(source_port, destination_port);
        let mut data = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut data, payload).unwrap();
        RawPacket {
            timestamp: PacketTimestamp { sec: 10, usec: 20 },
            link_layer: LinkLayer::Ethernet,
            linktype: Linktype::ETHERNET.0,
            data,
        }
    }

    fn dns_query_packet() -> Vec<u8> {
        let mut bytes = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        bytes.extend_from_slice(&[7]);
        bytes.extend_from_slice(b"example");
        bytes.extend_from_slice(&[3]);
        bytes.extend_from_slice(b"com");
        bytes.extend_from_slice(&[0, 0, 1, 0, 1]);
        bytes
    }
}
