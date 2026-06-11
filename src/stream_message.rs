use std::{
    collections::VecDeque,
    net::{Ipv4Addr, Ipv6Addr},
};

use ahash::AHashMap;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    analyzers::Analyzer,
    event::Event,
    flow::{FlowDirection, FlowKey, FlowObservation, StreamChunk},
    packet::DecodedPacket,
    protocol_detection::detect_payload,
};

const ANALYZER_NAME: &str = "protocol_message";
const DEFAULT_MAX_STREAMS: usize = 65_536;
const DEFAULT_MAX_MESSAGES_PER_STREAM: usize = 2_048;
const DEFAULT_MAX_QUERY_LIMIT: usize = 512;
const DEFAULT_MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_HTTP_BUFFER_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_MAX_HTTP_PARSER_STATES: usize = DEFAULT_MAX_STREAMS * 2;
const MAX_STORED_HTTP_HEADERS: usize = 128;
const DEFAULT_MAX_DNS_PARSER_STATES: usize = DEFAULT_MAX_STREAMS * 2;
const MAX_STORED_DNS_QUESTIONS: usize = 16;
const MAX_STORED_DNS_RECORDS: usize = 32;
const MAX_DNS_NAME_JUMPS: usize = 16;

const HTTP_SIGNATURES: [&[u8]; 10] = [
    b"GET", b"POST", b"PUT", b"DELETE", b"PATCH", b"HEAD", b"OPTIONS", b"TRACE", b"CONNECT",
    b"HTTP/",
];

#[derive(Debug, Clone, Copy)]
pub struct StreamMessageStoreConfig {
    pub max_streams: usize,
    pub max_messages_per_stream: usize,
    pub max_query_limit: usize,
}

impl Default for StreamMessageStoreConfig {
    fn default() -> Self {
        Self {
            max_streams: DEFAULT_MAX_STREAMS,
            max_messages_per_stream: DEFAULT_MAX_MESSAGES_PER_STREAM,
            max_query_limit: DEFAULT_MAX_QUERY_LIMIT,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamMessageStats {
    pub active_message_streams: usize,
    pub stored_messages: usize,
    pub dropped_messages: u64,
    pub observed_messages: u64,
    pub http1_messages: u64,
    pub dns_messages: u64,
    pub parse_errors: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamMessageProtocol {
    Http1,
    Dns,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamMessageKind {
    Request,
    Response,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamMessageStatus {
    Complete,
    Partial,
    ParseError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamMessage {
    pub stream_id: u64,
    pub stream_id_hex: String,
    pub message_id: u64,
    pub protocol: StreamMessageProtocol,
    pub kind: StreamMessageKind,
    pub status: StreamMessageStatus,
    pub direction: FlowDirection,
    pub ordinal: u64,
    pub summary: String,
    pub logical_start: u64,
    pub logical_end: u64,
    pub header_start: Option<u64>,
    pub header_end: Option<u64>,
    pub body_start: Option<u64>,
    pub body_end: Option<u64>,
    pub wire_bytes: u64,
    pub header_bytes: u64,
    pub body_bytes: u64,
    pub http: Option<Http1MessageInfo>,
    pub dns: Option<DnsMessageInfo>,
    pub error: Option<String>,
}

impl StreamMessage {
    pub fn from_event(event: &Event) -> Option<Self> {
        if event.analyzer != ANALYZER_NAME {
            return None;
        }
        serde_json::from_value(event.fields.clone()).ok()
    }

    fn event_type(&self) -> &'static str {
        match (self.protocol, self.kind, self.status) {
            (StreamMessageProtocol::Http1, _, StreamMessageStatus::ParseError) => {
                "http1_parse_error"
            }
            (StreamMessageProtocol::Dns, _, StreamMessageStatus::ParseError) => "dns_parse_error",
            (StreamMessageProtocol::Http1, StreamMessageKind::Request, _) => "http1_request",
            (StreamMessageProtocol::Http1, StreamMessageKind::Response, _) => "http1_response",
            (StreamMessageProtocol::Http1, StreamMessageKind::Unknown, _) => "http1_message",
            (StreamMessageProtocol::Dns, StreamMessageKind::Request, _) => "dns_query",
            (StreamMessageProtocol::Dns, StreamMessageKind::Response, _) => "dns_response",
            (StreamMessageProtocol::Dns, StreamMessageKind::Unknown, _) => "dns_message",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Http1MessageInfo {
    pub start_line: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub headers: Vec<Http1Header>,
    pub headers_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transfer_encoding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_encoding: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Http1Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsMessageInfo {
    pub transaction_id: u16,
    pub opcode: u8,
    pub rcode: u8,
    pub query: bool,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsResourceRecord>,
    pub authorities: Vec<DnsResourceRecord>,
    pub additionals: Vec<DnsResourceRecord>,
    pub questions_truncated: bool,
    pub records_truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: String,
    pub qclass: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsResourceRecord {
    pub name: String,
    pub rr_type: String,
    pub class: String,
    pub ttl: u32,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamMessageQuery {
    pub cursor: usize,
    pub limit: usize,
    pub direction: Option<FlowDirection>,
    pub protocol: Option<StreamMessageProtocol>,
    pub kind: Option<StreamMessageKind>,
    pub status: Option<StreamMessageStatus>,
}

impl Default for StreamMessageQuery {
    fn default() -> Self {
        Self {
            cursor: 0,
            limit: 128,
            direction: None,
            protocol: None,
            kind: None,
            status: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamMessageQueryResult {
    pub stream_id: u64,
    pub stream_id_hex: String,
    pub cursor: usize,
    pub next_cursor: usize,
    pub total: usize,
    pub messages: Vec<StreamMessage>,
}

#[derive(Debug, Clone)]
pub struct StreamMessageStore {
    config: StreamMessageStoreConfig,
    streams: AHashMap<u64, VecDeque<StreamMessage>>,
    order: VecDeque<u64>,
    stats: StreamMessageStats,
}

impl Default for StreamMessageStore {
    fn default() -> Self {
        Self::new(StreamMessageStoreConfig::default())
    }
}

impl StreamMessageStore {
    pub fn new(config: StreamMessageStoreConfig) -> Self {
        let config = StreamMessageStoreConfig {
            max_streams: config.max_streams.max(1),
            max_messages_per_stream: config.max_messages_per_stream.max(1),
            max_query_limit: config.max_query_limit.max(1),
        };

        Self {
            streams: AHashMap::with_capacity(config.max_streams.min(65_536)),
            order: VecDeque::with_capacity(config.max_streams.min(65_536)),
            config,
            stats: StreamMessageStats::default(),
        }
    }

    pub fn observe_events(&mut self, events: &[Event]) {
        for event in events {
            if let Some(message) = StreamMessage::from_event(event) {
                self.insert(message);
            }
        }
    }

    pub fn insert(&mut self, message: StreamMessage) {
        self.ensure_stream(message.stream_id);
        let stream = self
            .streams
            .get_mut(&message.stream_id)
            .expect("stream slot was ensured");
        stream.push_back(message.clone());
        self.stats.observed_messages = self.stats.observed_messages.saturating_add(1);
        if message.protocol == StreamMessageProtocol::Http1 {
            self.stats.http1_messages = self.stats.http1_messages.saturating_add(1);
        }
        if message.protocol == StreamMessageProtocol::Dns {
            self.stats.dns_messages = self.stats.dns_messages.saturating_add(1);
        }
        if message.status == StreamMessageStatus::ParseError {
            self.stats.parse_errors = self.stats.parse_errors.saturating_add(1);
        }

        while stream.len() > self.config.max_messages_per_stream {
            stream.pop_front();
            self.stats.dropped_messages = self.stats.dropped_messages.saturating_add(1);
        }
        self.refresh_counts();
    }

    pub fn query(&self, stream_id: u64, query: &StreamMessageQuery) -> StreamMessageQueryResult {
        let limit = query.limit.clamp(1, self.config.max_query_limit);
        let Some(messages) = self.streams.get(&stream_id) else {
            return StreamMessageQueryResult {
                stream_id,
                stream_id_hex: format!("{stream_id:016x}"),
                cursor: query.cursor,
                next_cursor: query.cursor,
                total: 0,
                messages: Vec::new(),
            };
        };

        let filtered = messages
            .iter()
            .filter(|message| query.matches(message))
            .collect::<Vec<_>>();
        let total = filtered.len();
        let messages = filtered
            .iter()
            .skip(query.cursor)
            .take(limit)
            .map(|message| (*message).clone())
            .collect::<Vec<_>>();
        let next_cursor = query.cursor.saturating_add(messages.len()).min(total);

        StreamMessageQueryResult {
            stream_id,
            stream_id_hex: format!("{stream_id:016x}"),
            cursor: query.cursor,
            next_cursor,
            total,
            messages,
        }
    }

    pub fn stats(&self) -> StreamMessageStats {
        self.stats
    }

    fn ensure_stream(&mut self, stream_id: u64) {
        if self.streams.contains_key(&stream_id) {
            return;
        }

        while self.streams.len() >= self.config.max_streams {
            let Some(evicted_id) = self.order.pop_front() else {
                break;
            };
            if let Some(messages) = self.streams.remove(&evicted_id) {
                self.stats.dropped_messages = self
                    .stats
                    .dropped_messages
                    .saturating_add(messages.len() as u64);
            }
        }

        self.streams.insert(stream_id, VecDeque::new());
        self.order.push_back(stream_id);
        self.refresh_counts();
    }

    fn refresh_counts(&mut self) {
        self.stats.active_message_streams = self.streams.len();
        self.stats.stored_messages = self.streams.values().map(VecDeque::len).sum();
    }
}

impl StreamMessageQuery {
    fn matches(&self, message: &StreamMessage) -> bool {
        self.direction
            .is_none_or(|direction| direction == message.direction)
            && self
                .protocol
                .is_none_or(|protocol| protocol == message.protocol)
            && self.kind.is_none_or(|kind| kind == message.kind)
            && self.status.is_none_or(|status| status == message.status)
    }
}

pub struct ProtocolMessageAnalyzer {
    http1: AHashMap<Http1StreamKey, Http1DirectionState>,
    http1_order: VecDeque<Http1StreamKey>,
    dns: AHashMap<DnsStreamKey, DnsDirectionState>,
    dns_order: VecDeque<DnsStreamKey>,
    max_http1_states: usize,
    max_dns_states: usize,
    max_header_bytes: usize,
    max_buffer_bytes: usize,
    evicted_http1_states: u64,
    evicted_dns_states: u64,
    dropped_http1_chunks: u64,
    dropped_dns_datagrams: u64,
}

impl Default for ProtocolMessageAnalyzer {
    fn default() -> Self {
        Self {
            http1: AHashMap::new(),
            http1_order: VecDeque::new(),
            dns: AHashMap::new(),
            dns_order: VecDeque::new(),
            max_http1_states: DEFAULT_MAX_HTTP_PARSER_STATES,
            max_dns_states: DEFAULT_MAX_DNS_PARSER_STATES,
            max_header_bytes: DEFAULT_MAX_HTTP_HEADER_BYTES,
            max_buffer_bytes: DEFAULT_MAX_HTTP_BUFFER_BYTES,
            evicted_http1_states: 0,
            evicted_dns_states: 0,
            dropped_http1_chunks: 0,
            dropped_dns_datagrams: 0,
        }
    }
}

impl ProtocolMessageAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_limits(
        max_http1_states: usize,
        max_dns_states: usize,
        max_header_bytes: usize,
        max_buffer_bytes: usize,
    ) -> Self {
        Self {
            max_http1_states: max_http1_states.max(1),
            max_dns_states: max_dns_states.max(1),
            max_header_bytes: max_header_bytes.max(1),
            max_buffer_bytes: max_buffer_bytes.max(1),
            ..Self::default()
        }
    }

    pub fn analyze_stream_packet(
        &mut self,
        packet: &DecodedPacket<'_>,
        flow: &FlowObservation<'_>,
        chunk: &StreamChunk<'_>,
        events: &mut Vec<Event>,
    ) {
        self.emit_messages(packet, flow, chunk, events);
    }

    pub fn analyze_datagram_packet(
        &mut self,
        packet: &DecodedPacket<'_>,
        flow: &FlowObservation<'_>,
        payload: &[u8],
        events: &mut Vec<Event>,
    ) {
        self.emit_dns_datagram(packet, flow, payload, events);
    }

    pub fn http1_active_states(&self) -> usize {
        self.http1.len()
    }

    pub fn http1_evicted_states(&self) -> u64 {
        self.evicted_http1_states
    }

    pub fn http1_dropped_chunks(&self) -> u64 {
        self.dropped_http1_chunks
    }

    pub fn dns_active_states(&self) -> usize {
        self.dns.len()
    }

    pub fn dns_evicted_states(&self) -> u64 {
        self.evicted_dns_states
    }

    pub fn dns_dropped_datagrams(&self) -> u64 {
        self.dropped_dns_datagrams
    }

    fn emit_messages(
        &mut self,
        packet: &DecodedPacket<'_>,
        flow: &FlowObservation<'_>,
        chunk: &StreamChunk<'_>,
        events: &mut Vec<Event>,
    ) {
        let key = Http1StreamKey {
            flow: flow.key,
            direction: chunk.direction,
        };
        let max_header_bytes = self.max_header_bytes;
        let max_buffer_bytes = self.max_buffer_bytes;
        let Some(state) = self.http1_state(key) else {
            self.dropped_http1_chunks = self.dropped_http1_chunks.saturating_add(1);
            return;
        };
        let messages = state.push(
            flow.key.stable_id(),
            chunk.direction,
            chunk.bytes.as_slice(),
            max_header_bytes,
            max_buffer_bytes,
        );

        for message in messages {
            let length = message.wire_bytes.min(usize::MAX as u64) as usize;
            events.push(Event::from_packet(
                ANALYZER_NAME,
                message.event_type(),
                packet,
                length,
                json!(message),
            ));
        }
    }

    fn emit_dns_datagram(
        &mut self,
        packet: &DecodedPacket<'_>,
        flow: &FlowObservation<'_>,
        payload: &[u8],
        events: &mut Vec<Event>,
    ) {
        let Some(detection) = detect_payload(flow.key, flow.direction, payload) else {
            return;
        };
        if !matches!(detection.service, "dns" | "mdns" | "llmnr" | "netbios") {
            return;
        }
        if !looks_like_dns_datagram(payload) {
            return;
        }
        let key = DnsStreamKey {
            flow: flow.key,
            direction: flow.direction,
        };
        let Some(state) = self.dns_state(key) else {
            self.dropped_dns_datagrams = self.dropped_dns_datagrams.saturating_add(1);
            return;
        };
        let message = state.parse_datagram(flow.key.stable_id(), flow.direction, payload);
        let length = message.wire_bytes.min(usize::MAX as u64) as usize;
        events.push(Event::from_packet(
            ANALYZER_NAME,
            message.event_type(),
            packet,
            length,
            json!(message),
        ));
    }
}

impl Analyzer for ProtocolMessageAnalyzer {
    fn name(&self) -> &'static str {
        ANALYZER_NAME
    }

    fn analyze(&mut self, _packet: &DecodedPacket<'_>, _events: &mut Vec<Event>) {}

    fn analyze_stream(
        &mut self,
        packet: &DecodedPacket<'_>,
        flow: &FlowObservation<'_>,
        chunk: &StreamChunk<'_>,
        events: &mut Vec<Event>,
    ) {
        self.emit_messages(packet, flow, chunk, events);
    }
}

impl ProtocolMessageAnalyzer {
    fn http1_state(&mut self, key: Http1StreamKey) -> Option<&mut Http1DirectionState> {
        if !self.http1.contains_key(&key) {
            while self.http1.len() >= self.max_http1_states {
                let Some(evicted) = self.http1_order.pop_front() else {
                    break;
                };
                self.http1.remove(&evicted);
                self.evicted_http1_states = self.evicted_http1_states.saturating_add(1);
            }
            if self.http1.len() >= self.max_http1_states {
                return None;
            }
            self.http1.insert(key, Http1DirectionState::default());
            self.http1_order.push_back(key);
        }

        self.http1.get_mut(&key)
    }

    fn dns_state(&mut self, key: DnsStreamKey) -> Option<&mut DnsDirectionState> {
        if !self.dns.contains_key(&key) {
            while self.dns.len() >= self.max_dns_states {
                let Some(evicted) = self.dns_order.pop_front() else {
                    break;
                };
                self.dns.remove(&evicted);
                self.evicted_dns_states = self.evicted_dns_states.saturating_add(1);
            }
            if self.dns.len() >= self.max_dns_states {
                return None;
            }
            self.dns.insert(key, DnsDirectionState::default());
            self.dns_order.push_back(key);
        }

        self.dns.get_mut(&key)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Http1StreamKey {
    flow: FlowKey,
    direction: FlowDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct DnsStreamKey {
    flow: FlowKey,
    direction: FlowDirection,
}

#[derive(Debug, Default)]
struct Http1DirectionState {
    buffer: Vec<u8>,
    buffer_start: u64,
    next_logical: u64,
    next_ordinal: u64,
    pending: Option<PendingContentLengthMessage>,
}

#[derive(Debug, Default)]
struct DnsDirectionState {
    next_logical: u64,
    next_ordinal: u64,
}

impl DnsDirectionState {
    fn parse_datagram(
        &mut self,
        stream_id: u64,
        direction: FlowDirection,
        bytes: &[u8],
    ) -> StreamMessage {
        let logical_start = self.next_logical;
        let logical_end = logical_start.saturating_add(bytes.len() as u64);
        self.next_logical = logical_end;
        let ordinal = self.next_ordinal;
        self.next_ordinal = self.next_ordinal.saturating_add(1);

        match parse_dns_message(bytes) {
            Ok(dns) => dns_stream_message(
                stream_id,
                direction,
                ordinal,
                logical_start,
                logical_end,
                dns,
            ),
            Err(error) => dns_parse_error(
                stream_id,
                direction,
                ordinal,
                logical_start,
                logical_end,
                error,
            ),
        }
    }
}

struct DnsCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DnsCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u16(&mut self) -> Result<u16, &'static str> {
        let value = read_u16_at(self.bytes, self.offset)?;
        self.offset = self.offset.saturating_add(2);
        Ok(value)
    }

    fn read_u32(&mut self) -> Result<u32, &'static str> {
        let value = read_u32_at(self.bytes, self.offset)?;
        self.offset = self.offset.saturating_add(4);
        Ok(value)
    }

    fn read_name(&mut self) -> Result<String, &'static str> {
        let (name, next_offset) = read_dns_name(self.bytes, self.offset)?;
        self.offset = next_offset;
        Ok(name)
    }

    fn skip(&mut self, count: usize) -> Result<(), &'static str> {
        if self.bytes.len() < self.offset.saturating_add(count) {
            return Err("dns field is truncated");
        }
        self.offset = self.offset.saturating_add(count);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct Http1ParseContext {
    stream_id: u64,
    direction: FlowDirection,
    max_header_bytes: usize,
    max_buffer_bytes: usize,
}

fn parse_dns_message(bytes: &[u8]) -> Result<DnsMessageInfo, &'static str> {
    if bytes.len() < 12 {
        return Err("dns message is shorter than header");
    }

    let mut cursor = DnsCursor::new(bytes);
    let transaction_id = cursor.read_u16()?;
    let flags = cursor.read_u16()?;
    let question_count = cursor.read_u16()? as usize;
    let answer_count = cursor.read_u16()? as usize;
    let authority_count = cursor.read_u16()? as usize;
    let additional_count = cursor.read_u16()? as usize;

    let mut questions = Vec::with_capacity(question_count.min(MAX_STORED_DNS_QUESTIONS));
    let mut questions_truncated = false;
    for index in 0..question_count {
        let question = parse_dns_question(&mut cursor)?;
        if index < MAX_STORED_DNS_QUESTIONS {
            questions.push(question);
        } else {
            questions_truncated = true;
        }
    }

    let (answers, answers_truncated) = parse_dns_records(&mut cursor, answer_count)?;
    let (authorities, authorities_truncated) = parse_dns_records(&mut cursor, authority_count)?;
    let (additionals, additionals_truncated) = parse_dns_records(&mut cursor, additional_count)?;

    Ok(DnsMessageInfo {
        transaction_id,
        opcode: ((flags >> 11) & 0x0f) as u8,
        rcode: (flags & 0x0f) as u8,
        query: flags & 0x8000 == 0,
        authoritative: flags & 0x0400 != 0,
        truncated: flags & 0x0200 != 0,
        recursion_desired: flags & 0x0100 != 0,
        recursion_available: flags & 0x0080 != 0,
        questions,
        answers,
        authorities,
        additionals,
        questions_truncated,
        records_truncated: answers_truncated || authorities_truncated || additionals_truncated,
    })
}

fn parse_dns_question(cursor: &mut DnsCursor<'_>) -> Result<DnsQuestion, &'static str> {
    let name = cursor.read_name()?;
    let qtype = cursor.read_u16()?;
    let qclass = cursor.read_u16()?;
    Ok(DnsQuestion {
        name,
        qtype: dns_type_name(qtype).to_owned(),
        qclass: dns_class_name(qclass).to_owned(),
    })
}

fn parse_dns_records(
    cursor: &mut DnsCursor<'_>,
    count: usize,
) -> Result<(Vec<DnsResourceRecord>, bool), &'static str> {
    let mut records = Vec::with_capacity(count.min(MAX_STORED_DNS_RECORDS));
    let mut truncated = false;
    for index in 0..count {
        let record = parse_dns_record(cursor)?;
        if index < MAX_STORED_DNS_RECORDS {
            records.push(record);
        } else {
            truncated = true;
        }
    }
    Ok((records, truncated))
}

fn parse_dns_record(cursor: &mut DnsCursor<'_>) -> Result<DnsResourceRecord, &'static str> {
    let name = cursor.read_name()?;
    let rr_type = cursor.read_u16()?;
    let class = cursor.read_u16()?;
    let ttl = cursor.read_u32()?;
    let rdlen = cursor.read_u16()? as usize;
    let rdata_offset = cursor.offset;
    cursor.skip(rdlen)?;
    let rdata = cursor
        .bytes
        .get(rdata_offset..rdata_offset.saturating_add(rdlen))
        .ok_or("dns record data is truncated")?;

    Ok(DnsResourceRecord {
        name,
        rr_type: dns_type_name(rr_type).to_owned(),
        class: dns_class_name(class).to_owned(),
        ttl,
        data: dns_record_data(cursor.bytes, rdata_offset, rr_type, rdata),
    })
}

fn dns_record_data(message: &[u8], rdata_offset: usize, rr_type: u16, rdata: &[u8]) -> String {
    match rr_type {
        1 if rdata.len() == 4 => Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]).to_string(),
        2 | 5 | 12 => read_dns_name(message, rdata_offset)
            .map_or_else(|_| format_dns_hex(rdata), |(name, _)| name),
        6 => dns_soa_data(message, rdata_offset, rdata).unwrap_or_else(|| format_dns_hex(rdata)),
        15 => dns_mx_data(message, rdata_offset, rdata).unwrap_or_else(|| format_dns_hex(rdata)),
        16 => dns_txt_data(rdata),
        28 if rdata.len() == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rdata);
            Ipv6Addr::from(octets).to_string()
        }
        33 => dns_srv_data(message, rdata_offset, rdata).unwrap_or_else(|| format_dns_hex(rdata)),
        _ => format_dns_hex(rdata),
    }
}

fn dns_mx_data(message: &[u8], offset: usize, rdata: &[u8]) -> Option<String> {
    if rdata.len() < 3 {
        return None;
    }
    let preference = read_u16_at(rdata, 0).ok()?;
    let (exchange, _) = read_dns_name(message, offset + 2).ok()?;
    Some(format!("{preference} {exchange}"))
}

fn dns_srv_data(message: &[u8], offset: usize, rdata: &[u8]) -> Option<String> {
    if rdata.len() < 7 {
        return None;
    }
    let priority = read_u16_at(rdata, 0).ok()?;
    let weight = read_u16_at(rdata, 2).ok()?;
    let port = read_u16_at(rdata, 4).ok()?;
    let (target, _) = read_dns_name(message, offset + 6).ok()?;
    Some(format!("{priority} {weight} {port} {target}"))
}

fn dns_soa_data(message: &[u8], offset: usize, rdata: &[u8]) -> Option<String> {
    let (mname, after_mname) = read_dns_name(message, offset).ok()?;
    let (rname, after_rname) = read_dns_name(message, after_mname).ok()?;
    let relative = after_rname.checked_sub(offset)?;
    if rdata.len() < relative.saturating_add(20) {
        return None;
    }
    let serial = read_u32_at(message, after_rname).ok()?;
    Some(format!("{mname} {rname} serial={serial}"))
}

fn dns_txt_data(rdata: &[u8]) -> String {
    let mut offset = 0usize;
    let mut parts = Vec::new();
    while offset < rdata.len() {
        let len = usize::from(rdata[offset]);
        offset += 1;
        if rdata.len() < offset.saturating_add(len) {
            return format_dns_hex(rdata);
        }
        let text = String::from_utf8_lossy(&rdata[offset..offset + len]).to_string();
        parts.push(text);
        offset += len;
    }
    parts.join("")
}

fn read_dns_name(message: &[u8], offset: usize) -> Result<(String, usize), &'static str> {
    let mut labels = Vec::new();
    let mut cursor = offset;
    let mut next_offset = None;
    let mut jumps = 0usize;

    loop {
        let Some(&len) = message.get(cursor) else {
            return Err("dns name is truncated");
        };
        if len & 0xc0 == 0xc0 {
            let Some(&next) = message.get(cursor + 1) else {
                return Err("dns compression pointer is truncated");
            };
            let pointer = (((u16::from(len) & 0x3f) << 8) | u16::from(next)) as usize;
            if pointer >= message.len() {
                return Err("dns compression pointer is out of range");
            }
            next_offset.get_or_insert(cursor + 2);
            cursor = pointer;
            jumps = jumps.saturating_add(1);
            if jumps > MAX_DNS_NAME_JUMPS {
                return Err("dns compression pointer loop");
            }
            continue;
        }
        if len & 0xc0 != 0 {
            return Err("dns label uses an unsupported compression form");
        }
        cursor += 1;
        if len == 0 {
            let end = next_offset.unwrap_or(cursor);
            let name = if labels.is_empty() {
                ".".to_owned()
            } else {
                labels.join(".")
            };
            return Ok((name, end));
        }
        let len = usize::from(len);
        if len > 63 || message.len() < cursor.saturating_add(len) {
            return Err("dns label is truncated");
        }
        labels.push(String::from_utf8_lossy(&message[cursor..cursor + len]).to_string());
        cursor += len;
    }
}

fn dns_type_name(value: u16) -> &'static str {
    match value {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        41 => "OPT",
        255 => "ANY",
        _ => "UNKNOWN",
    }
}

fn dns_class_name(value: u16) -> &'static str {
    match value {
        1 => "IN",
        3 => "CH",
        4 => "HS",
        255 => "ANY",
        _ => "UNKNOWN",
    }
}

fn read_u16_at(bytes: &[u8], offset: usize) -> Result<u16, &'static str> {
    Ok(u16::from_be_bytes([
        *bytes.get(offset).ok_or("dns u16 is truncated")?,
        *bytes.get(offset + 1).ok_or("dns u16 is truncated")?,
    ]))
}

fn read_u32_at(bytes: &[u8], offset: usize) -> Result<u32, &'static str> {
    Ok(u32::from_be_bytes([
        *bytes.get(offset).ok_or("dns u32 is truncated")?,
        *bytes.get(offset + 1).ok_or("dns u32 is truncated")?,
        *bytes.get(offset + 2).ok_or("dns u32 is truncated")?,
        *bytes.get(offset + 3).ok_or("dns u32 is truncated")?,
    ]))
}

fn format_dns_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn looks_like_dns_datagram(bytes: &[u8]) -> bool {
    if bytes.len() < 12 {
        return false;
    }
    let questions = u16::from_be_bytes([bytes[4], bytes[5]]);
    let answers = u16::from_be_bytes([bytes[6], bytes[7]]);
    let opcode = (bytes[2] >> 3) & 0x0f;
    opcode <= 5 && questions != 0 && questions <= 64 && answers <= 512
}

fn dns_stream_message(
    stream_id: u64,
    direction: FlowDirection,
    ordinal: u64,
    logical_start: u64,
    logical_end: u64,
    dns: DnsMessageInfo,
) -> StreamMessage {
    let kind = if dns.query {
        StreamMessageKind::Request
    } else {
        StreamMessageKind::Response
    };
    let summary = dns_summary(&dns);
    StreamMessage {
        stream_id,
        stream_id_hex: format!("{stream_id:016x}"),
        message_id: stable_message_id(stream_id, direction, ordinal),
        protocol: StreamMessageProtocol::Dns,
        kind,
        status: StreamMessageStatus::Complete,
        direction,
        ordinal,
        summary,
        logical_start,
        logical_end,
        header_start: Some(logical_start),
        header_end: Some(logical_start.saturating_add(12)),
        body_start: Some(logical_start.saturating_add(12)),
        body_end: Some(logical_end),
        wire_bytes: logical_end.saturating_sub(logical_start),
        header_bytes: 12,
        body_bytes: logical_end.saturating_sub(logical_start).saturating_sub(12),
        http: None,
        dns: Some(dns),
        error: None,
    }
}

fn dns_parse_error(
    stream_id: u64,
    direction: FlowDirection,
    ordinal: u64,
    logical_start: u64,
    logical_end: u64,
    error: impl Into<String>,
) -> StreamMessage {
    StreamMessage {
        stream_id,
        stream_id_hex: format!("{stream_id:016x}"),
        message_id: stable_message_id(stream_id, direction, ordinal),
        protocol: StreamMessageProtocol::Dns,
        kind: StreamMessageKind::Unknown,
        status: StreamMessageStatus::ParseError,
        direction,
        ordinal,
        summary: "DNS parse error".to_owned(),
        logical_start,
        logical_end,
        header_start: Some(logical_start),
        header_end: Some(logical_end),
        body_start: None,
        body_end: None,
        wire_bytes: logical_end.saturating_sub(logical_start),
        header_bytes: logical_end.saturating_sub(logical_start),
        body_bytes: 0,
        http: None,
        dns: None,
        error: Some(error.into()),
    }
}

fn dns_summary(dns: &DnsMessageInfo) -> String {
    let prefix = if dns.query {
        "DNS query"
    } else {
        "DNS response"
    };
    let question = dns
        .questions
        .first()
        .map(|question| format!("{} {}", question.qtype, question.name))
        .unwrap_or_else(|| "no question".to_owned());
    if dns.query {
        format!("{prefix} {question}")
    } else {
        format!(
            "{prefix} {question} rcode={} answers={}",
            dns.rcode,
            dns.answers.len()
        )
    }
}

impl Http1DirectionState {
    fn push(
        &mut self,
        stream_id: u64,
        direction: FlowDirection,
        bytes: &[u8],
        max_header_bytes: usize,
        max_buffer_bytes: usize,
    ) -> Vec<StreamMessage> {
        let mut messages = Vec::new();
        if bytes.is_empty() {
            return messages;
        }
        let context = Http1ParseContext {
            stream_id,
            direction,
            max_header_bytes,
            max_buffer_bytes,
        };

        let mut input = bytes;
        let mut input_start = self.next_logical;
        self.next_logical = self.next_logical.saturating_add(bytes.len() as u64);

        while !input.is_empty() {
            if let Some(pending) = self.pending.as_mut() {
                let consumed = pending.remaining.min(input.len() as u64);
                pending.remaining -= consumed;
                input = &input[consumed as usize..];
                input_start = input_start.saturating_add(consumed);
                if pending.remaining == 0 {
                    let pending = self.pending.take().expect("pending message exists");
                    messages.push(pending.complete(stream_id, direction));
                    continue;
                }
                break;
            }

            self.append_input(context, input, input_start, &mut messages);
            break;
        }

        messages
    }

    fn append_input(
        &mut self,
        context: Http1ParseContext,
        input: &[u8],
        input_start: u64,
        messages: &mut Vec<StreamMessage>,
    ) {
        let Some((start_offset, input)) = self.http_input(input) else {
            return;
        };
        let input_start = input_start.saturating_add(start_offset as u64);
        if self.buffer.is_empty() {
            self.buffer_start = input_start;
        }
        self.buffer.extend_from_slice(input);
        self.parse_buffer(context, messages);
    }

    fn http_input<'a>(&mut self, input: &'a [u8]) -> Option<(usize, &'a [u8])> {
        if input.is_empty() {
            return None;
        }

        if !self.buffer.is_empty() {
            return Some((0, input));
        }

        let start = find_http_start(input)?;
        Some((start, &input[start..]))
    }

    fn parse_buffer(&mut self, context: Http1ParseContext, messages: &mut Vec<StreamMessage>) {
        loop {
            if self.buffer.is_empty() {
                return;
            }
            if !looks_like_http_prefix(&self.buffer) {
                self.resync_or_clear();
                continue;
            }
            if self.buffer.len() > context.max_buffer_bytes {
                messages.push(self.parse_error(
                    context.stream_id,
                    context.direction,
                    "http message exceeded parser buffer limit",
                ));
                self.clear_buffer();
                return;
            }

            let Some((header_len, header_total_len)) = find_header_end(&self.buffer) else {
                if self.buffer.len() > context.max_header_bytes {
                    messages.push(self.parse_error(
                        context.stream_id,
                        context.direction,
                        "http header exceeded parser limit",
                    ));
                    self.clear_buffer();
                }
                return;
            };

            let header = &self.buffer[..header_len];
            let head = match parse_http1_head(header) {
                Ok(head) => head,
                Err(err) => {
                    messages.push(self.parse_error(context.stream_id, context.direction, err));
                    self.drain_front(header_total_len);
                    continue;
                }
            };

            let body_start = self.buffer_start.saturating_add(header_total_len as u64);
            let available_body = self.buffer.len().saturating_sub(header_total_len);
            let framing = body_framing(&head);
            match framing {
                BodyFraming::ContentLength(body_len) => {
                    if body_len > available_body as u64 {
                        let observed = available_body as u64;
                        let pending = PendingContentLengthMessage {
                            ordinal: self.next_ordinal,
                            kind: head.kind,
                            summary: head.summary.clone(),
                            logical_start: self.buffer_start,
                            header_end: body_start,
                            body_start,
                            body_len,
                            remaining: body_len.saturating_sub(observed),
                            http: head.info,
                        };
                        self.next_ordinal = self.next_ordinal.saturating_add(1);
                        self.clear_buffer();
                        self.pending = Some(pending);
                        return;
                    }

                    let consumed = header_total_len.saturating_add(body_len as usize);
                    messages.push(build_message(
                        context.stream_id,
                        context.direction,
                        self.next_ordinal,
                        head,
                        self.buffer_start,
                        body_start,
                        body_len,
                    ));
                    self.next_ordinal = self.next_ordinal.saturating_add(1);
                    self.fix_message_context(messages.last_mut(), consumed);
                    self.drain_front(consumed);
                }
                BodyFraming::Chunked => {
                    match find_chunked_body_end(&self.buffer[header_total_len..]) {
                        ChunkedBodyEnd::Complete(body_len) => {
                            let consumed = header_total_len.saturating_add(body_len);
                            messages.push(build_message(
                                context.stream_id,
                                context.direction,
                                self.next_ordinal,
                                head,
                                self.buffer_start,
                                body_start,
                                body_len as u64,
                            ));
                            self.next_ordinal = self.next_ordinal.saturating_add(1);
                            self.fix_message_context(messages.last_mut(), consumed);
                            self.drain_front(consumed);
                        }
                        ChunkedBodyEnd::Incomplete => return,
                        ChunkedBodyEnd::Invalid(reason) => {
                            messages.push(self.parse_error(
                                context.stream_id,
                                context.direction,
                                reason,
                            ));
                            self.drain_front(header_total_len);
                        }
                    }
                }
                BodyFraming::None => {
                    messages.push(build_message(
                        context.stream_id,
                        context.direction,
                        self.next_ordinal,
                        head,
                        self.buffer_start,
                        body_start,
                        0,
                    ));
                    self.next_ordinal = self.next_ordinal.saturating_add(1);
                    self.fix_message_context(messages.last_mut(), header_total_len);
                    self.drain_front(header_total_len);
                }
            }
        }
    }

    fn fix_message_context(&self, message: Option<&mut StreamMessage>, consumed: usize) {
        if let Some(message) = message {
            message.logical_end = message.logical_start.saturating_add(consumed as u64);
            message.wire_bytes = consumed as u64;
            message.header_bytes = message
                .header_end
                .zip(message.header_start)
                .map_or(0, |(end, start)| end.saturating_sub(start));
            message.body_bytes = message
                .body_end
                .zip(message.body_start)
                .map_or(0, |(end, start)| end.saturating_sub(start));
        }
    }

    fn parse_error(
        &mut self,
        stream_id: u64,
        direction: FlowDirection,
        reason: impl Into<String>,
    ) -> StreamMessage {
        let start = self.buffer_start;
        let end = start.saturating_add(self.buffer.len() as u64);
        let ordinal = self.next_ordinal;
        self.next_ordinal = self.next_ordinal.saturating_add(1);
        StreamMessage {
            stream_id,
            stream_id_hex: format!("{stream_id:016x}"),
            message_id: stable_message_id(stream_id, direction, ordinal),
            protocol: StreamMessageProtocol::Http1,
            kind: StreamMessageKind::Unknown,
            status: StreamMessageStatus::ParseError,
            direction,
            ordinal,
            summary: "HTTP/1 parse error".to_owned(),
            logical_start: start,
            logical_end: end,
            header_start: Some(start),
            header_end: Some(end),
            body_start: None,
            body_end: None,
            wire_bytes: end.saturating_sub(start),
            header_bytes: end.saturating_sub(start),
            body_bytes: 0,
            http: None,
            dns: None,
            error: Some(reason.into()),
        }
    }

    fn resync_or_clear(&mut self) {
        if let Some(offset) = find_http_start_from(&self.buffer, 1) {
            self.drain_front(offset);
        } else {
            self.clear_buffer();
        }
    }

    fn drain_front(&mut self, count: usize) {
        if count >= self.buffer.len() {
            self.clear_buffer();
            return;
        }
        self.buffer.drain(..count);
        self.buffer_start = self.buffer_start.saturating_add(count as u64);
    }

    fn clear_buffer(&mut self) {
        self.buffer.clear();
        self.buffer_start = self.next_logical;
    }
}

#[derive(Debug, Clone)]
struct PendingContentLengthMessage {
    ordinal: u64,
    kind: StreamMessageKind,
    summary: String,
    logical_start: u64,
    header_end: u64,
    body_start: u64,
    body_len: u64,
    remaining: u64,
    http: Http1MessageInfo,
}

impl PendingContentLengthMessage {
    fn complete(self, stream_id: u64, direction: FlowDirection) -> StreamMessage {
        let logical_end = self.body_start.saturating_add(self.body_len);
        StreamMessage {
            stream_id,
            stream_id_hex: format!("{stream_id:016x}"),
            message_id: stable_message_id(stream_id, direction, self.ordinal),
            protocol: StreamMessageProtocol::Http1,
            kind: self.kind,
            status: StreamMessageStatus::Complete,
            direction,
            ordinal: self.ordinal,
            summary: self.summary,
            logical_start: self.logical_start,
            logical_end,
            header_start: Some(self.logical_start),
            header_end: Some(self.header_end),
            body_start: Some(self.body_start),
            body_end: Some(logical_end),
            wire_bytes: logical_end.saturating_sub(self.logical_start),
            header_bytes: self.header_end.saturating_sub(self.logical_start),
            body_bytes: self.body_len,
            http: Some(self.http),
            dns: None,
            error: None,
        }
    }
}

#[derive(Debug, Clone)]
struct Http1Head {
    kind: StreamMessageKind,
    summary: String,
    info: Http1MessageInfo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyFraming {
    None,
    ContentLength(u64),
    Chunked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ChunkedBodyEnd {
    Complete(usize),
    Incomplete,
    Invalid(String),
}

fn build_message(
    stream_id: u64,
    direction: FlowDirection,
    ordinal: u64,
    head: Http1Head,
    logical_start: u64,
    body_start: u64,
    body_len: u64,
) -> StreamMessage {
    let logical_end = body_start.saturating_add(body_len);
    StreamMessage {
        stream_id,
        stream_id_hex: format!("{stream_id:016x}"),
        message_id: stable_message_id(stream_id, direction, ordinal),
        protocol: StreamMessageProtocol::Http1,
        kind: head.kind,
        status: StreamMessageStatus::Complete,
        direction,
        ordinal,
        summary: head.summary,
        logical_start,
        logical_end,
        header_start: Some(logical_start),
        header_end: Some(body_start),
        body_start: Some(body_start),
        body_end: Some(logical_end),
        wire_bytes: logical_end.saturating_sub(logical_start),
        header_bytes: body_start.saturating_sub(logical_start),
        body_bytes: body_len,
        http: Some(head.info),
        dns: None,
        error: None,
    }
}

fn body_framing(head: &Http1Head) -> BodyFraming {
    if head
        .info
        .transfer_encoding
        .as_deref()
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
    {
        return BodyFraming::Chunked;
    }

    head.info
        .content_length
        .map_or(BodyFraming::None, BodyFraming::ContentLength)
}

fn parse_http1_head(header: &[u8]) -> Result<Http1Head, &'static str> {
    let text = String::from_utf8_lossy(header);
    let mut lines = text.split('\n');
    let start_line = lines
        .next()
        .map(trim_line)
        .filter(|line| !line.is_empty())
        .ok_or("empty http start line")?;

    let mut headers = Vec::new();
    let mut headers_truncated = false;
    for line in lines {
        let line = trim_line(line);
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if headers.len() >= MAX_STORED_HTTP_HEADERS {
            headers_truncated = true;
            continue;
        }
        headers.push(Http1Header {
            name: name.trim().to_ascii_lowercase(),
            value: value.trim().to_owned(),
        });
    }

    let host = header_value(&headers, "host").map(ToOwned::to_owned);
    let content_length = header_value(&headers, "content-length").and_then(parse_content_length);
    let transfer_encoding = header_value(&headers, "transfer-encoding").map(ToOwned::to_owned);
    let content_encoding = header_value(&headers, "content-encoding").map(ToOwned::to_owned);

    if start_line.starts_with("HTTP/") {
        parse_response_head(
            start_line,
            headers,
            headers_truncated,
            host,
            content_length,
            transfer_encoding,
            content_encoding,
        )
    } else {
        parse_request_head(
            start_line,
            headers,
            headers_truncated,
            host,
            content_length,
            transfer_encoding,
            content_encoding,
        )
    }
}

fn parse_request_head(
    start_line: &str,
    headers: Vec<Http1Header>,
    headers_truncated: bool,
    host: Option<String>,
    content_length: Option<u64>,
    transfer_encoding: Option<String>,
    content_encoding: Option<String>,
) -> Result<Http1Head, &'static str> {
    let mut parts = start_line.split_ascii_whitespace();
    let method = parts.next().ok_or("missing http method")?;
    if !is_http_method(method) {
        return Err("unknown http method");
    }
    let target = parts.next().ok_or("missing http target")?.to_owned();
    let version = parts.next().unwrap_or("").to_owned();
    let summary = format!("{method} {target}");

    Ok(Http1Head {
        kind: StreamMessageKind::Request,
        summary,
        info: Http1MessageInfo {
            start_line: start_line.to_owned(),
            method: Some(method.to_owned()),
            target: Some(target),
            version: (!version.is_empty()).then_some(version),
            status_code: None,
            reason: None,
            headers,
            headers_truncated,
            host,
            content_length,
            transfer_encoding,
            content_encoding,
        },
    })
}

fn parse_response_head(
    start_line: &str,
    headers: Vec<Http1Header>,
    headers_truncated: bool,
    host: Option<String>,
    content_length: Option<u64>,
    transfer_encoding: Option<String>,
    content_encoding: Option<String>,
) -> Result<Http1Head, &'static str> {
    let mut parts = start_line.splitn(3, ' ');
    let version = parts.next().ok_or("missing http version")?.to_owned();
    if !version.starts_with("HTTP/") {
        return Err("invalid http response version");
    }
    let status_code = parts
        .next()
        .ok_or("missing http status")?
        .parse::<u16>()
        .map_err(|_| "invalid http status")?;
    let reason = parts.next().unwrap_or("").to_owned();
    let summary = if reason.is_empty() {
        format!("HTTP {status_code}")
    } else {
        format!("HTTP {status_code} {reason}")
    };

    Ok(Http1Head {
        kind: StreamMessageKind::Response,
        summary,
        info: Http1MessageInfo {
            start_line: start_line.to_owned(),
            method: None,
            target: None,
            version: Some(version),
            status_code: Some(status_code),
            reason: (!reason.is_empty()).then_some(reason),
            headers,
            headers_truncated,
            host,
            content_length,
            transfer_encoding,
            content_encoding,
        },
    })
}

fn find_chunked_body_end(body: &[u8]) -> ChunkedBodyEnd {
    let mut position = 0usize;
    loop {
        let Some((line_len, line_total_len)) = find_line_end(&body[position..]) else {
            return ChunkedBodyEnd::Incomplete;
        };
        let line = &body[position..position + line_len];
        let size_token = line
            .split(|byte| *byte == b';')
            .next()
            .unwrap_or(line)
            .iter()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>();
        let Ok(size_raw) = std::str::from_utf8(&size_token) else {
            return ChunkedBodyEnd::Invalid("chunk size is not ascii".to_owned());
        };
        let Ok(size) = usize::from_str_radix(size_raw, 16) else {
            return ChunkedBodyEnd::Invalid("invalid chunk size".to_owned());
        };
        position = position.saturating_add(line_total_len);
        if size == 0 {
            if body.get(position..position + 2) == Some(b"\r\n") {
                return ChunkedBodyEnd::Complete(position + 2);
            }
            if body.get(position) == Some(&b'\n') {
                return ChunkedBodyEnd::Complete(position + 1);
            }
            return find_header_end(&body[position..])
                .map_or(ChunkedBodyEnd::Incomplete, |(_, end)| {
                    ChunkedBodyEnd::Complete(position.saturating_add(end))
                });
        }
        if body.len() < position.saturating_add(size) {
            return ChunkedBodyEnd::Incomplete;
        }
        position = position.saturating_add(size);
        if body.len() < position.saturating_add(1) {
            return ChunkedBodyEnd::Incomplete;
        }
        if body.get(position..position + 2) == Some(b"\r\n") {
            position += 2;
        } else if body.get(position) == Some(&b'\n') {
            position += 1;
        } else {
            return ChunkedBodyEnd::Invalid("chunk data is not followed by a newline".to_owned());
        }
    }
}

fn find_header_end(bytes: &[u8]) -> Option<(usize, usize)> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|pos| (pos, pos + 4))
        .or_else(|| {
            bytes
                .windows(2)
                .position(|window| window == b"\n\n")
                .map(|pos| (pos, pos + 2))
        })
}

fn find_line_end(bytes: &[u8]) -> Option<(usize, usize)> {
    bytes
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|pos| (pos, pos + 2))
        .or_else(|| {
            bytes
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|pos| (pos, pos + 1))
        })
}

fn find_http_start(bytes: &[u8]) -> Option<usize> {
    find_http_start_from(bytes, 0)
}

fn find_http_start_from(bytes: &[u8], start: usize) -> Option<usize> {
    (start..bytes.len()).find(|offset| looks_like_http_prefix(&bytes[*offset..]))
}

fn looks_like_http_prefix(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    HTTP_SIGNATURES
        .iter()
        .any(|signature| signature.starts_with(bytes) || bytes.starts_with(signature))
}

fn header_value<'a>(headers: &'a [Http1Header], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

fn parse_content_length(value: &str) -> Option<u64> {
    value
        .split(',')
        .next()
        .map(str::trim)
        .and_then(|value| value.parse::<u64>().ok())
}

fn trim_line(line: &str) -> &str {
    line.trim_end_matches('\r').trim()
}

fn is_http_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS" | "TRACE" | "CONNECT"
    )
}

fn stable_message_id(stream_id: u64, direction: FlowDirection, ordinal: u64) -> u64 {
    let direction_bit = match direction {
        FlowDirection::AToB => 0,
        FlowDirection::BToA => 1,
    };
    let seed = stream_id ^ ordinal.wrapping_add(1).wrapping_shl(1) ^ direction_bit;
    splitmix64(seed)
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut mixed = value;
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    mixed ^ (mixed >> 31)
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
    fn indexes_keep_alive_requests_with_body_ranges() {
        let mut analyzer = ProtocolMessageAnalyzer::new();
        let mut flow_table = flow_table();
        let mut events = Vec::new();
        let raw = tcp_packet(
            100,
            b"POST /upload HTTP/1.1\r\nHost: ctf.local\r\nContent-Length: 4\r\n\r\nDATAGET /next HTTP/1.1\r\n\r\n",
        );

        feed(&mut analyzer, &mut flow_table, &raw, &mut events);

        let mut store = StreamMessageStore::default();
        store.observe_events(&events);
        let stream_id = StreamMessage::from_event(&events[0]).unwrap().stream_id;
        let result = store.query(stream_id, &StreamMessageQuery::default());

        assert_eq!(2, result.messages.len());
        assert_eq!("POST /upload", result.messages[0].summary);
        assert_eq!(4, result.messages[0].body_bytes);
        assert_eq!(
            result.messages[0].body_start.unwrap() + 4,
            result.messages[0].body_end.unwrap()
        );
        assert_eq!("GET /next", result.messages[1].summary);
        assert_eq!(
            result.messages[0].logical_end,
            result.messages[1].logical_start
        );
    }

    #[test]
    fn completes_content_length_message_across_packets() {
        let mut analyzer = ProtocolMessageAnalyzer::new();
        let mut flow_table = flow_table();
        let mut events = Vec::new();

        feed(
            &mut analyzer,
            &mut flow_table,
            &tcp_packet(100, b"POST /slow HTTP/1.1\r\nContent-Length: 6\r\n\r\nabc"),
            &mut events,
        );
        assert!(events.is_empty());

        feed(
            &mut analyzer,
            &mut flow_table,
            &tcp_packet(145, b"defGET /after HTTP/1.1\r\n\r\n"),
            &mut events,
        );

        assert_eq!(2, events.len());
        let first = StreamMessage::from_event(&events[0]).unwrap();
        let second = StreamMessage::from_event(&events[1]).unwrap();
        assert_eq!("POST /slow", first.summary);
        assert_eq!(6, first.body_bytes);
        assert_eq!("GET /after", second.summary);
        assert_eq!(first.logical_end, second.logical_start);
    }

    #[test]
    fn parses_chunked_response_body_range() {
        let mut analyzer = ProtocolMessageAnalyzer::new();
        let mut flow_table = flow_table();
        let mut events = Vec::new();
        let raw = tcp_packet(
            100,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
        );

        feed(&mut analyzer, &mut flow_table, &raw, &mut events);

        assert_eq!(1, events.len());
        let message = StreamMessage::from_event(&events[0]).unwrap();
        assert_eq!(StreamMessageKind::Response, message.kind);
        assert_eq!("HTTP 200 OK", message.summary);
        assert_eq!(24, message.body_bytes);
        assert_eq!(message.logical_end, message.body_end.unwrap());
        assert_eq!(
            Some("chunked"),
            message.http.as_ref().unwrap().transfer_encoding.as_deref()
        );
    }

    #[test]
    fn emits_dns_query_from_udp_datagram() {
        let mut analyzer = ProtocolMessageAnalyzer::new();
        let mut flow_table = flow_table();
        let mut events = Vec::new();
        let raw = udp_packet(49_000, 53, &dns_query_packet());

        feed_datagram(&mut analyzer, &mut flow_table, &raw, &mut events);

        assert_eq!(1, events.len());
        assert_eq!("dns_query", events[0].event_type);
        let message = StreamMessage::from_event(&events[0]).unwrap();
        assert_eq!(StreamMessageProtocol::Dns, message.protocol);
        assert_eq!(StreamMessageKind::Request, message.kind);
        assert_eq!("DNS query A example.com", message.summary);
        let dns = message.dns.as_ref().unwrap();
        assert_eq!(0x1234, dns.transaction_id);
        assert_eq!("example.com", dns.questions[0].name);
        assert_eq!("A", dns.questions[0].qtype);
    }

    #[test]
    fn emits_dns_response_with_compressed_answer_name() {
        let mut analyzer = ProtocolMessageAnalyzer::new();
        let mut flow_table = flow_table();
        let mut events = Vec::new();
        let raw = udp_packet(53, 49_000, &dns_response_packet());

        feed_datagram(&mut analyzer, &mut flow_table, &raw, &mut events);

        assert_eq!(1, events.len());
        assert_eq!("dns_response", events[0].event_type);
        let message = StreamMessage::from_event(&events[0]).unwrap();
        assert_eq!(StreamMessageKind::Response, message.kind);
        let dns = message.dns.as_ref().unwrap();
        assert!(!dns.query);
        assert_eq!("example.com", dns.questions[0].name);
        assert_eq!("A", dns.answers[0].rr_type);
        assert_eq!("93.184.216.34", dns.answers[0].data);
    }

    #[test]
    fn filters_store_messages_by_kind_and_direction() {
        let mut store = StreamMessageStore::default();
        let mut request = sample_message(1, FlowDirection::AToB, 0, StreamMessageKind::Request);
        let response = sample_message(1, FlowDirection::BToA, 0, StreamMessageKind::Response);
        request.summary = "GET /a".to_owned();
        store.insert(request);
        store.insert(response);

        let result = store.query(
            1,
            &StreamMessageQuery {
                direction: Some(FlowDirection::AToB),
                kind: Some(StreamMessageKind::Request),
                ..StreamMessageQuery::default()
            },
        );

        assert_eq!(1, result.total);
        assert_eq!("GET /a", result.messages[0].summary);
    }

    #[test]
    fn filters_store_messages_by_dns_protocol() {
        let mut store = StreamMessageStore::default();
        store.insert(sample_message(
            1,
            FlowDirection::AToB,
            0,
            StreamMessageKind::Request,
        ));
        store.insert(sample_dns_message(1, FlowDirection::AToB, 1));

        let result = store.query(
            1,
            &StreamMessageQuery {
                protocol: Some(StreamMessageProtocol::Dns),
                ..StreamMessageQuery::default()
            },
        );

        assert_eq!(1, result.total);
        assert_eq!(StreamMessageProtocol::Dns, result.messages[0].protocol);
    }

    fn feed(
        analyzer: &mut ProtocolMessageAnalyzer,
        flow_table: &mut FlowTable,
        raw: &RawPacket,
        events: &mut Vec<Event>,
    ) {
        let packet = DecodedPacket::from_raw(raw);
        let flow = flow_table.observe(&packet).unwrap();
        let tcp = flow.tcp.as_ref().unwrap();
        for chunk in &tcp.stream_chunks {
            analyzer.analyze_stream(&packet, &flow, chunk, events);
        }
    }

    fn feed_datagram(
        analyzer: &mut ProtocolMessageAnalyzer,
        flow_table: &mut FlowTable,
        raw: &RawPacket,
        events: &mut Vec<Event>,
    ) {
        let packet = DecodedPacket::from_raw(raw);
        let flow = flow_table.observe(&packet).unwrap();
        let payload = packet.transport_payload().unwrap();
        analyzer.analyze_datagram_packet(&packet, &flow, payload.bytes, events);
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

    fn dns_response_packet() -> Vec<u8> {
        let mut bytes = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        bytes.extend_from_slice(&[7]);
        bytes.extend_from_slice(b"example");
        bytes.extend_from_slice(&[3]);
        bytes.extend_from_slice(b"com");
        bytes.extend_from_slice(&[0, 0, 1, 0, 1]);
        bytes.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        bytes.extend_from_slice(&[93, 184, 216, 34]);
        bytes
    }

    fn sample_message(
        stream_id: u64,
        direction: FlowDirection,
        ordinal: u64,
        kind: StreamMessageKind,
    ) -> StreamMessage {
        StreamMessage {
            stream_id,
            stream_id_hex: format!("{stream_id:016x}"),
            message_id: stable_message_id(stream_id, direction, ordinal),
            protocol: StreamMessageProtocol::Http1,
            kind,
            status: StreamMessageStatus::Complete,
            direction,
            ordinal,
            summary: "sample".to_owned(),
            logical_start: 0,
            logical_end: 10,
            header_start: Some(0),
            header_end: Some(10),
            body_start: Some(10),
            body_end: Some(10),
            wire_bytes: 10,
            header_bytes: 10,
            body_bytes: 0,
            http: None,
            dns: None,
            error: None,
        }
    }

    fn sample_dns_message(stream_id: u64, direction: FlowDirection, ordinal: u64) -> StreamMessage {
        StreamMessage {
            stream_id,
            stream_id_hex: format!("{stream_id:016x}"),
            message_id: stable_message_id(stream_id, direction, ordinal),
            protocol: StreamMessageProtocol::Dns,
            kind: StreamMessageKind::Request,
            status: StreamMessageStatus::Complete,
            direction,
            ordinal,
            summary: "DNS query A example.com".to_owned(),
            logical_start: 0,
            logical_end: 29,
            header_start: Some(0),
            header_end: Some(12),
            body_start: Some(12),
            body_end: Some(29),
            wire_bytes: 29,
            header_bytes: 12,
            body_bytes: 17,
            http: None,
            dns: Some(DnsMessageInfo {
                transaction_id: 0x1234,
                opcode: 0,
                rcode: 0,
                query: true,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: false,
                questions: vec![DnsQuestion {
                    name: "example.com".to_owned(),
                    qtype: "A".to_owned(),
                    qclass: "IN".to_owned(),
                }],
                answers: Vec::new(),
                authorities: Vec::new(),
                additionals: Vec::new(),
                questions_truncated: false,
                records_truncated: false,
            }),
            error: None,
        }
    }
}
