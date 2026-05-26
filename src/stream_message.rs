use std::collections::VecDeque;

use ahash::AHashMap;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    analyzers::Analyzer,
    event::Event,
    flow::{FlowDirection, FlowKey, FlowObservation, StreamChunk},
    packet::DecodedPacket,
};

const ANALYZER_NAME: &str = "protocol_message";
const DEFAULT_MAX_STREAMS: usize = 65_536;
const DEFAULT_MAX_MESSAGES_PER_STREAM: usize = 2_048;
const DEFAULT_MAX_QUERY_LIMIT: usize = 512;
const DEFAULT_MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_HTTP_BUFFER_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_MAX_HTTP_PARSER_STATES: usize = DEFAULT_MAX_STREAMS * 2;
const MAX_STORED_HTTP_HEADERS: usize = 128;

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
    pub parse_errors: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamMessageProtocol {
    Http1,
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
            (_, _, StreamMessageStatus::ParseError) => "http1_parse_error",
            (StreamMessageProtocol::Http1, StreamMessageKind::Request, _) => "http1_request",
            (StreamMessageProtocol::Http1, StreamMessageKind::Response, _) => "http1_response",
            (StreamMessageProtocol::Http1, StreamMessageKind::Unknown, _) => "http1_message",
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
    max_http1_states: usize,
    max_header_bytes: usize,
    max_buffer_bytes: usize,
    evicted_http1_states: u64,
    dropped_http1_chunks: u64,
}

impl Default for ProtocolMessageAnalyzer {
    fn default() -> Self {
        Self {
            http1: AHashMap::new(),
            http1_order: VecDeque::new(),
            max_http1_states: DEFAULT_MAX_HTTP_PARSER_STATES,
            max_header_bytes: DEFAULT_MAX_HTTP_HEADER_BYTES,
            max_buffer_bytes: DEFAULT_MAX_HTTP_BUFFER_BYTES,
            evicted_http1_states: 0,
            dropped_http1_chunks: 0,
        }
    }
}

impl ProtocolMessageAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_limits(
        max_http1_states: usize,
        max_header_bytes: usize,
        max_buffer_bytes: usize,
    ) -> Self {
        Self {
            max_http1_states: max_http1_states.max(1),
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

    pub fn http1_active_states(&self) -> usize {
        self.http1.len()
    }

    pub fn http1_evicted_states(&self) -> u64 {
        self.evicted_http1_states
    }

    pub fn http1_dropped_chunks(&self) -> u64 {
        self.dropped_http1_chunks
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Http1StreamKey {
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

#[derive(Debug, Clone, Copy)]
struct Http1ParseContext {
    stream_id: u64,
    direction: FlowDirection,
    max_header_bytes: usize,
    max_buffer_bytes: usize,
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
            error: None,
        }
    }
}
