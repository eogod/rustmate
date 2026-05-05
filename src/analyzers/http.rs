use ahash::AHashMap;
use serde_json::{Map, Value, json};

use crate::{
    analyzers::Analyzer,
    event::Event,
    flow::{FlowDirection, FlowKey, FlowObservation, StreamChunk},
    packet::DecodedPacket,
};

const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;

pub struct HttpAnalyzer {
    streams: AHashMap<HttpStreamKey, HttpStreamState>,
    max_header_bytes: usize,
}

impl Default for HttpAnalyzer {
    fn default() -> Self {
        Self {
            streams: AHashMap::new(),
            max_header_bytes: MAX_HTTP_HEADER_BYTES,
        }
    }
}

impl HttpAnalyzer {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Analyzer for HttpAnalyzer {
    fn name(&self) -> &'static str {
        "http"
    }

    fn analyze(&mut self, _packet: &DecodedPacket<'_>, _events: &mut Vec<Event>) {}

    fn analyze_stream(
        &mut self,
        packet: &DecodedPacket<'_>,
        flow: &FlowObservation<'_>,
        chunk: &StreamChunk<'_>,
        events: &mut Vec<Event>,
    ) {
        let key = HttpStreamKey {
            flow: flow.key,
            direction: chunk.direction,
        };
        let state = self.streams.entry(key).or_default();
        let parsed = state.push(chunk, self.max_header_bytes);

        for message in parsed {
            events.push(Event::from_packet(
                self.name(),
                message.kind.event_type(),
                packet,
                message.header_len,
                message.fields,
            ));
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct HttpStreamKey {
    flow: FlowKey,
    direction: FlowDirection,
}

#[derive(Debug, Default)]
struct HttpStreamState {
    buffer: Vec<u8>,
    skip_body_remaining: usize,
    message_sequence_start: Option<u32>,
}

impl HttpStreamState {
    fn push(&mut self, chunk: &StreamChunk<'_>, max_header_bytes: usize) -> Vec<HttpMessage> {
        let mut input = chunk.bytes.as_slice();
        if self.skip_body_remaining != 0 {
            let skipped = self.skip_body_remaining.min(input.len());
            self.skip_body_remaining -= skipped;
            input = &input[skipped..];
        }
        if input.is_empty() {
            return Vec::new();
        }

        if self.buffer.is_empty() {
            self.message_sequence_start = Some(chunk.sequence_start);
        }
        self.buffer.extend_from_slice(input);

        if self.buffer.len() > max_header_bytes {
            self.reset();
            return Vec::new();
        }

        let mut messages = Vec::new();
        while let Some((header_len, header_end)) = find_header_end(&self.buffer) {
            let header = self.buffer[..header_len].to_vec();
            let Some(mut message) = parse_http_header(&header, self.message_sequence_start) else {
                self.buffer.drain(..header_end);
                self.message_sequence_start = (!self.buffer.is_empty())
                    .then_some(chunk.sequence_end.wrapping_sub(self.buffer.len() as u32));
                continue;
            };

            let body_len = message.content_length.unwrap_or(0);
            let available_body = self.buffer.len().saturating_sub(header_end);
            let consumed_body = body_len.min(available_body);
            let drain_to = header_end + consumed_body;
            self.skip_body_remaining = body_len.saturating_sub(consumed_body);
            self.buffer.drain(..drain_to);
            message.fields["body_bytes_expected"] = json!(body_len);
            messages.push(message);

            if self.skip_body_remaining != 0 {
                self.message_sequence_start = None;
                break;
            }

            self.message_sequence_start = (!self.buffer.is_empty())
                .then_some(chunk.sequence_end.wrapping_sub(self.buffer.len() as u32));
        }

        messages
    }

    fn reset(&mut self) {
        self.buffer.clear();
        self.skip_body_remaining = 0;
        self.message_sequence_start = None;
    }
}

#[derive(Debug)]
struct HttpMessage {
    kind: HttpMessageKind,
    header_len: usize,
    content_length: Option<usize>,
    fields: Value,
}

#[derive(Debug, Clone, Copy)]
enum HttpMessageKind {
    Request,
    Response,
}

impl HttpMessageKind {
    fn event_type(self) -> &'static str {
        match self {
            Self::Request => "http_request",
            Self::Response => "http_response",
        }
    }
}

fn parse_http_header(header: &[u8], sequence_start: Option<u32>) -> Option<HttpMessage> {
    let text = std::str::from_utf8(header).ok()?;
    let mut lines = text.lines();
    let line = lines.next()?.trim_end_matches('\r').to_owned();
    let mut headers = Map::new();
    let mut content_length = None;

    for line in lines {
        let line = line.trim_end_matches('\r');
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_owned();
        if name == "content-length" {
            content_length = value.parse::<usize>().ok();
        }
        headers.insert(name, Value::String(value));
    }

    if line.starts_with("HTTP/") {
        parse_response(line, headers, header.len(), content_length, sequence_start)
    } else {
        parse_request(line, headers, header.len(), content_length, sequence_start)
    }
}

fn parse_request(
    line: String,
    headers: Map<String, Value>,
    header_len: usize,
    content_length: Option<usize>,
    sequence_start: Option<u32>,
) -> Option<HttpMessage> {
    let mut parts = line.split_ascii_whitespace();
    let method = parts.next()?;
    if !is_http_method(method) {
        return None;
    }
    let target = parts.next()?.to_owned();
    let version = parts.next().unwrap_or("").to_owned();

    Some(HttpMessage {
        kind: HttpMessageKind::Request,
        header_len,
        content_length,
        fields: json!({
            "line": line,
            "method": method,
            "target": target,
            "version": version,
            "headers": headers,
            "stream_sequence_start": sequence_start,
        }),
    })
}

fn parse_response(
    line: String,
    headers: Map<String, Value>,
    header_len: usize,
    content_length: Option<usize>,
    sequence_start: Option<u32>,
) -> Option<HttpMessage> {
    let mut parts = line.splitn(3, ' ');
    let version = parts.next()?.to_owned();
    let status_code = parts.next()?.parse::<u16>().ok()?;
    let reason = parts.next().unwrap_or("").to_owned();

    Some(HttpMessage {
        kind: HttpMessageKind::Response,
        header_len,
        content_length,
        fields: json!({
            "line": line,
            "version": version,
            "status_code": status_code,
            "reason": reason,
            "headers": headers,
            "stream_sequence_start": sequence_start,
        }),
    })
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

fn is_http_method(method: &str) -> bool {
    matches!(
        method,
        "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS" | "TRACE" | "CONNECT"
    )
}

#[cfg(test)]
mod tests {
    use etherparse::PacketBuilder;
    use pcap::Linktype;

    use crate::{
        flow::FlowTable,
        flow::FlowTableConfig,
        packet::{DecodedPacket, LinkLayer, PacketTimestamp, RawPacket},
    };

    use super::*;

    #[test]
    fn emits_request_from_split_stream() {
        let mut analyzer = HttpAnalyzer::new();
        let mut flow_table = flow_table();
        let mut events = Vec::new();
        let first = tcp_packet(100, b"GET /fl");
        let second = tcp_packet(107, b"ag HTTP/1.1\r\nHost: ctf.local\r\n\r\n");

        feed(&mut analyzer, &mut flow_table, &first, &mut events);
        assert!(events.is_empty());
        feed(&mut analyzer, &mut flow_table, &second, &mut events);

        assert_eq!(1, events.len());
        assert_eq!("http_request", events[0].event_type);
        assert_eq!("GET", events[0].fields["method"]);
        assert_eq!("/flag", events[0].fields["target"]);
        assert_eq!("ctf.local", events[0].fields["headers"]["host"]);
    }

    #[test]
    fn emits_request_after_out_of_order_gap_fill() {
        let mut analyzer = HttpAnalyzer::new();
        let mut flow_table = flow_table();
        let mut events = Vec::new();
        let first = tcp_packet(100, b"GET /");
        let out_of_order = tcp_packet(111, b" HTTP/1.1\r\nHost: ctf.local\r\n\r\n");
        let gap_fill = tcp_packet(105, b"flagxx");

        feed(&mut analyzer, &mut flow_table, &first, &mut events);
        feed(&mut analyzer, &mut flow_table, &out_of_order, &mut events);
        assert!(events.is_empty());
        feed(&mut analyzer, &mut flow_table, &gap_fill, &mut events);

        assert_eq!(1, events.len());
        assert_eq!("http_request", events[0].event_type);
        assert_eq!("/flagxx", events[0].fields["target"]);
    }

    #[test]
    fn skips_body_before_next_message() {
        let mut analyzer = HttpAnalyzer::new();
        let mut flow_table = flow_table();
        let mut events = Vec::new();
        let packet = tcp_packet(
            100,
            b"POST /upload HTTP/1.1\r\nContent-Length: 4\r\n\r\nDATAGET /next HTTP/1.1\r\n\r\n",
        );

        feed(&mut analyzer, &mut flow_table, &packet, &mut events);

        assert_eq!(2, events.len());
        assert_eq!("POST", events[0].fields["method"]);
        assert_eq!(4, events[0].fields["body_bytes_expected"]);
        assert_eq!("GET", events[1].fields["method"]);
        assert_eq!("/next", events[1].fields["target"]);
    }

    #[test]
    fn emits_response_from_stream() {
        let mut analyzer = HttpAnalyzer::new();
        let mut flow_table = flow_table();
        let mut events = Vec::new();
        let packet = tcp_packet(100, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

        feed(&mut analyzer, &mut flow_table, &packet, &mut events);

        assert_eq!(1, events.len());
        assert_eq!("http_response", events[0].event_type);
        assert_eq!(200, events[0].fields["status_code"]);
        assert_eq!("OK", events[0].fields["reason"]);
    }

    fn feed(
        analyzer: &mut HttpAnalyzer,
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
}
