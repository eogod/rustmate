use std::{collections::VecDeque, net::IpAddr};

use ahash::{AHashMap, AHashSet};
use serde::Serialize;
use serde_json::Value;

use crate::{
    event::Event,
    flow::{Endpoint, FlowDirection, FlowKey},
    packet::TransportProtocol,
    service_profile::{ServiceProfile, ServiceProfileSet, ServiceProfileStats},
    stream_message::{
        StreamMessage, StreamMessageKind, StreamMessageProtocol, StreamMessageStatus,
    },
};

const DEFAULT_QUERY_LIMIT: usize = 100;
const MATCH_TEXT_PREVIEW_LIMIT: usize = 256;

#[derive(Debug, Clone, Copy)]
pub struct StreamViewConfig {
    pub enabled: bool,
    pub max_streams: usize,
    pub max_matches_per_stream: usize,
    pub max_query_limit: usize,
}

impl StreamViewConfig {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            max_streams: 0,
            max_matches_per_stream: 0,
            max_query_limit: 0,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct StreamViewStats {
    pub tracked_streams: usize,
    pub favorite_streams: usize,
    pub manually_hidden_streams: usize,
    pub matched_streams: usize,
    pub stored_matches: usize,
    pub dropped_matches: u64,
    pub orphan_matches: u64,
    pub evicted_streams: u64,
    pub hide_rules: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamViewQuery {
    pub cursor: usize,
    pub limit: usize,
    pub include_hidden: bool,
    pub only_favorites: bool,
    pub only_matched: bool,
    pub profile: Option<ServiceProfile>,
    pub protocol: Option<TransportProtocol>,
    pub service: Option<String>,
    pub port: Option<u16>,
    pub content_kind: Option<StreamViewContentKind>,
    pub status: Option<StreamViewStatus>,
    pub pattern_id: Option<String>,
}

impl Default for StreamViewQuery {
    fn default() -> Self {
        Self {
            cursor: 0,
            limit: DEFAULT_QUERY_LIMIT,
            include_hidden: false,
            only_favorites: false,
            only_matched: false,
            profile: None,
            protocol: None,
            service: None,
            port: None,
            content_kind: None,
            status: None,
            pattern_id: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StreamViewQueryResult {
    pub rows: Vec<StreamViewRow>,
    pub next_cursor: Option<usize>,
    pub scanned: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StreamViewRow {
    pub stream_id: u64,
    pub stream_id_hex: String,
    pub content_shard: Option<usize>,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
    pub protocol: TransportProtocol,
    pub endpoint_a: StreamViewEndpoint,
    pub endpoint_b: StreamViewEndpoint,
    pub service: StreamViewService,
    pub status: StreamViewStatus,
    pub content_kind: StreamViewContentKind,
    pub packets: u64,
    pub bytes: u64,
    pub payload_bytes: u64,
    pub stream_bytes: u64,
    pub stream_chunks: u64,
    pub match_count: u64,
    pub stored_match_count: usize,
    pub pattern_ids: Vec<String>,
    pub favorite: bool,
    pub hidden: bool,
    pub hidden_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamViewEntry {
    pub stream_id: u64,
    pub content_shard: Option<usize>,
    pub first_seen_us: u64,
    pub last_seen_us: u64,
    pub protocol: TransportProtocol,
    pub endpoint_a: StreamViewEndpoint,
    pub endpoint_b: StreamViewEndpoint,
    pub service: StreamViewService,
    pub status: StreamViewStatus,
    pub content_kind: StreamViewContentKind,
    pub packets: u64,
    pub bytes: u64,
    pub payload_bytes: u64,
    pub stream_bytes: u64,
    pub stream_chunks: u64,
    pub directions: [StreamViewDirection; 2],
    pub matches: Vec<StreamPatternMatch>,
    pub match_count: u64,
    pattern_ids: AHashSet<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct StreamViewEndpoint {
    pub addr: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StreamViewService {
    pub name: String,
    pub side: String,
    pub confidence: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StreamViewDirection {
    pub packets: u64,
    pub bytes: u64,
    pub payload_bytes: u64,
    pub stream_bytes: u64,
    pub stream_chunks: u64,
    pub first_sequence: Option<u32>,
    pub last_sequence: Option<u32>,
    pub content_kind: StreamViewContentKind,
    pub preview_base64: String,
    pub preview_text: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StreamPatternMatch {
    pub stream_id: u64,
    pub stream_id_hex: String,
    pub pattern_id: String,
    pub pattern_name: String,
    pub pattern_type: StreamPatternType,
    pub direction: FlowDirection,
    pub logical_start: u64,
    pub logical_end: u64,
    pub match_len: usize,
    pub match_text: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamViewStatus {
    Open,
    Closing,
    Closed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamViewContentKind {
    Unknown,
    Text,
    Binary,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamPatternType {
    Substring,
    Regex,
    Binary,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum StreamHideRule {
    StreamId(u64),
    Service(String),
    Protocol(TransportProtocol),
    Port(u16),
    ContentKind(StreamViewContentKind),
    Status(StreamViewStatus),
    PatternId(String),
}

pub struct StreamViewState {
    config: StreamViewConfig,
    streams: AHashMap<u64, StreamViewEntry>,
    stream_order: VecDeque<u64>,
    favorites: AHashSet<u64>,
    manually_hidden: AHashSet<u64>,
    matched_streams: AHashSet<u64>,
    pattern_index: AHashMap<String, AHashSet<u64>>,
    hide_rules: Vec<StreamHideRule>,
    stats: StreamViewStats,
}

impl StreamViewState {
    pub fn new(config: StreamViewConfig) -> Self {
        let capacity = if config.enabled {
            config.max_streams.min(65_536)
        } else {
            0
        };
        Self {
            config,
            streams: AHashMap::with_capacity(capacity),
            stream_order: VecDeque::with_capacity(capacity),
            favorites: AHashSet::new(),
            manually_hidden: AHashSet::new(),
            matched_streams: AHashSet::new(),
            pattern_index: AHashMap::new(),
            hide_rules: Vec::new(),
            stats: StreamViewStats::default(),
        }
    }

    pub fn observe_events(&mut self, events: &[Event]) {
        if !self.config.enabled {
            return;
        }

        for event in events {
            self.observe_event(event);
        }
    }

    pub fn observe_event(&mut self, event: &Event) {
        if !self.config.enabled {
            return;
        }

        match (event.analyzer, event.event_type) {
            ("stream_inventory", "stream_open" | "stream_update") => {
                if let Some(entry) = StreamViewEntry::from_stream_event(event) {
                    self.upsert_stream(entry);
                }
            }
            ("pattern", "pattern_match") => {
                if let Some(pattern_match) = StreamPatternMatch::from_event(event) {
                    self.observe_match(pattern_match);
                }
            }
            ("protocol_message", _) => self.observe_protocol_message(event),
            _ => {}
        }
    }

    pub fn query(&self, query: &StreamViewQuery) -> StreamViewQueryResult {
        if !self.config.enabled {
            return StreamViewQueryResult {
                rows: Vec::new(),
                next_cursor: None,
                scanned: 0,
            };
        }

        let limit = query.limit.max(1).min(self.config.max_query_limit.max(1));
        let start = query.cursor.min(self.stream_order.len());
        let mut rows = Vec::with_capacity(limit);
        let mut scanned = 0usize;
        let mut next_cursor = None;

        for index in start..self.stream_order.len() {
            let Some(stream_id) = self.stream_order.get(index).copied() else {
                break;
            };
            let Some(entry) = self.streams.get(&stream_id) else {
                continue;
            };

            scanned = scanned.saturating_add(1);
            let hidden_reason = self.hidden_reason(entry);
            if !self.matches_query(entry, query, hidden_reason.as_deref()) {
                continue;
            }

            rows.push(self.row(entry, hidden_reason));
            if rows.len() == limit {
                next_cursor = (index + 1 < self.stream_order.len()).then_some(index + 1);
                break;
            }
        }

        StreamViewQueryResult {
            rows,
            next_cursor,
            scanned,
        }
    }

    pub fn stream(&self, stream_id: u64) -> Option<&StreamViewEntry> {
        self.streams.get(&stream_id)
    }

    pub fn stream_row(&self, stream_id: u64) -> Option<StreamViewRow> {
        let entry = self.streams.get(&stream_id)?;
        Some(self.row(entry, self.hidden_reason(entry)))
    }

    pub fn stream_matches(&self, stream_id: u64) -> Option<&[StreamPatternMatch]> {
        self.streams
            .get(&stream_id)
            .map(|entry| entry.matches.as_slice())
    }

    pub fn set_favorite(&mut self, stream_id: u64, favorite: bool) -> bool {
        if !self.streams.contains_key(&stream_id) {
            return false;
        }

        if favorite {
            self.favorites.insert(stream_id);
        } else {
            self.favorites.remove(&stream_id);
        }
        true
    }

    pub fn set_hidden(&mut self, stream_id: u64, hidden: bool) -> bool {
        if !self.streams.contains_key(&stream_id) {
            return false;
        }

        if hidden {
            self.manually_hidden.insert(stream_id);
        } else {
            self.manually_hidden.remove(&stream_id);
        }
        true
    }

    pub fn add_hide_rule(&mut self, rule: StreamHideRule) {
        let rule = rule.normalized();
        if !self.hide_rules.contains(&rule) {
            self.hide_rules.push(rule);
        }
    }

    pub fn clear_hide_rules(&mut self) {
        self.hide_rules.clear();
    }

    pub fn hide_rules(&self) -> &[StreamHideRule] {
        &self.hide_rules
    }

    pub fn profile_stats(&self, profile: &ServiceProfile) -> ServiceProfileStats {
        let mut stats = ServiceProfileStats::default();
        if !self.config.enabled {
            return stats;
        }

        for stream_id in &self.stream_order {
            let Some(entry) = self.streams.get(stream_id) else {
                continue;
            };
            if !matches_profile(entry, profile) {
                continue;
            }

            stats.total_streams = stats.total_streams.saturating_add(1);
            if entry.match_count != 0 {
                stats.matched_streams = stats.matched_streams.saturating_add(1);
            }
            if self.favorites.contains(&entry.stream_id) {
                stats.favorite_streams = stats.favorite_streams.saturating_add(1);
            }
            if self.hidden_reason(entry).is_some() {
                stats.hidden_streams = stats.hidden_streams.saturating_add(1);
            } else {
                stats.visible_streams = stats.visible_streams.saturating_add(1);
            }
        }
        stats
    }

    pub fn primary_profile<'a>(
        &self,
        profiles: &'a ServiceProfileSet,
        stream_id: u64,
    ) -> Option<&'a ServiceProfile> {
        let entry = self.streams.get(&stream_id)?;
        profiles
            .profiles()
            .iter()
            .find(|profile| matches_profile(entry, profile))
    }

    pub fn stats(&self) -> StreamViewStats {
        StreamViewStats {
            tracked_streams: self.streams.len(),
            favorite_streams: self.favorites.len(),
            manually_hidden_streams: self.manually_hidden.len(),
            matched_streams: self.matched_streams.len(),
            hide_rules: self.hide_rules.len(),
            ..self.stats
        }
    }

    fn upsert_stream(&mut self, mut entry: StreamViewEntry) {
        let stream_id = entry.stream_id;
        if let Some(existing) = self.streams.get_mut(&stream_id) {
            entry.matches = std::mem::take(&mut existing.matches);
            entry.match_count = existing.match_count;
            entry.pattern_ids = std::mem::take(&mut existing.pattern_ids);
            *existing = entry;
            return;
        }

        if self.streams.len() >= self.config.max_streams {
            self.evict_oldest();
        }
        if self.streams.len() >= self.config.max_streams {
            return;
        }

        self.stream_order.push_back(stream_id);
        self.streams.insert(stream_id, entry);
    }

    fn observe_match(&mut self, pattern_match: StreamPatternMatch) {
        let stream_id = pattern_match.stream_id;
        let Some(entry) = self.streams.get_mut(&stream_id) else {
            self.stats.orphan_matches = self.stats.orphan_matches.saturating_add(1);
            return;
        };

        entry.match_count = entry.match_count.saturating_add(1);
        entry.pattern_ids.insert(pattern_match.pattern_id.clone());
        self.matched_streams.insert(stream_id);
        self.pattern_index
            .entry(pattern_match.pattern_id.clone())
            .or_default()
            .insert(stream_id);

        if self.config.max_matches_per_stream == 0 {
            self.stats.dropped_matches = self.stats.dropped_matches.saturating_add(1);
            return;
        }

        if entry.matches.len() >= self.config.max_matches_per_stream {
            entry.matches.remove(0);
            self.stats.stored_matches = self.stats.stored_matches.saturating_sub(1);
            self.stats.dropped_matches = self.stats.dropped_matches.saturating_add(1);
        }

        entry.matches.push(pattern_match);
        self.stats.stored_matches = self.stats.stored_matches.saturating_add(1);
    }

    fn observe_protocol_message(&mut self, event: &Event) {
        let Some(message) = StreamMessage::from_event(event) else {
            return;
        };
        if message.status == StreamMessageStatus::ParseError {
            return;
        }
        let Some(entry) = self.streams.get_mut(&message.stream_id) else {
            return;
        };

        let service = service_from_message(&message, event.event_type);
        if should_replace_service(&entry.service, &service) {
            entry.service = service;
        }
        entry.content_kind = content_kind_from_message(message.protocol, entry.content_kind);
    }

    fn evict_oldest(&mut self) {
        while let Some(stream_id) = self.stream_order.pop_front() {
            if self.remove_stream(stream_id) {
                return;
            }
        }
    }

    fn remove_stream(&mut self, stream_id: u64) -> bool {
        let Some(entry) = self.streams.remove(&stream_id) else {
            return false;
        };

        self.stats.stored_matches = self
            .stats
            .stored_matches
            .saturating_sub(entry.matches.len());
        self.stats.evicted_streams = self.stats.evicted_streams.saturating_add(1);
        self.favorites.remove(&stream_id);
        self.manually_hidden.remove(&stream_id);
        self.matched_streams.remove(&stream_id);

        for pattern_id in entry.pattern_ids {
            let remove_index = self
                .pattern_index
                .get_mut(&pattern_id)
                .is_some_and(|streams| {
                    streams.remove(&stream_id);
                    streams.is_empty()
                });
            if remove_index {
                self.pattern_index.remove(&pattern_id);
            }
        }
        true
    }

    fn matches_query(
        &self,
        entry: &StreamViewEntry,
        query: &StreamViewQuery,
        hidden_reason: Option<&str>,
    ) -> bool {
        if hidden_reason.is_some() && !query.include_hidden {
            return false;
        }
        if query.only_favorites && !self.favorites.contains(&entry.stream_id) {
            return false;
        }
        if query.only_matched && entry.match_count == 0 {
            return false;
        }
        if query
            .profile
            .as_ref()
            .is_some_and(|profile| !matches_profile(entry, profile))
        {
            return false;
        }
        if query
            .protocol
            .is_some_and(|protocol| entry.protocol != protocol)
        {
            return false;
        }
        if query
            .service
            .as_ref()
            .is_some_and(|service| !entry.service.name.eq_ignore_ascii_case(service))
        {
            return false;
        }
        if query
            .port
            .is_some_and(|port| entry.endpoint_a.port != port && entry.endpoint_b.port != port)
        {
            return false;
        }
        if query
            .content_kind
            .is_some_and(|kind| entry.content_kind != kind)
        {
            return false;
        }
        if query.status.is_some_and(|status| entry.status != status) {
            return false;
        }
        if query
            .pattern_id
            .as_ref()
            .is_some_and(|pattern_id| !entry.pattern_ids.contains(pattern_id))
        {
            return false;
        }

        true
    }

    fn row(&self, entry: &StreamViewEntry, hidden_reason: Option<String>) -> StreamViewRow {
        let mut pattern_ids = entry.pattern_ids.iter().cloned().collect::<Vec<_>>();
        pattern_ids.sort_unstable();
        StreamViewRow {
            stream_id: entry.stream_id,
            stream_id_hex: stream_id_hex(entry.stream_id),
            content_shard: entry.content_shard,
            first_seen_us: entry.first_seen_us,
            last_seen_us: entry.last_seen_us,
            protocol: entry.protocol,
            endpoint_a: entry.endpoint_a,
            endpoint_b: entry.endpoint_b,
            service: entry.service.clone(),
            status: entry.status,
            content_kind: entry.content_kind,
            packets: entry.packets,
            bytes: entry.bytes,
            payload_bytes: entry.payload_bytes,
            stream_bytes: entry.stream_bytes,
            stream_chunks: entry.stream_chunks,
            match_count: entry.match_count,
            stored_match_count: entry.matches.len(),
            pattern_ids,
            favorite: self.favorites.contains(&entry.stream_id),
            hidden: hidden_reason.is_some(),
            hidden_reason,
        }
    }

    fn hidden_reason(&self, entry: &StreamViewEntry) -> Option<String> {
        if self.manually_hidden.contains(&entry.stream_id) {
            return Some("manual".to_owned());
        }

        self.hide_rules
            .iter()
            .find(|rule| rule.matches(entry))
            .map(StreamHideRule::label)
    }
}

impl StreamViewEntry {
    pub fn flow_key(&self) -> FlowKey {
        FlowKey {
            protocol: self.protocol,
            a: Endpoint {
                addr: self.endpoint_a.addr,
                port: self.endpoint_a.port,
            },
            b: Endpoint {
                addr: self.endpoint_b.addr,
                port: self.endpoint_b.port,
            },
        }
    }

    fn from_stream_event(event: &Event) -> Option<Self> {
        let fields = &event.fields;
        Some(Self {
            stream_id: stream_id_field(fields, "stream_id")?,
            content_shard: optional_usize_field(fields, "content_shard").unwrap_or(None),
            first_seen_us: u64_field(fields, "first_seen_us")?,
            last_seen_us: u64_field(fields, "last_seen_us")?,
            protocol: protocol_field(fields, "protocol")?,
            endpoint_a: endpoint_field(fields, "endpoint_a")?,
            endpoint_b: endpoint_field(fields, "endpoint_b")?,
            service: service_field(fields, "service")?,
            status: status_field(fields, "status").unwrap_or(StreamViewStatus::Unknown),
            content_kind: content_kind_field(fields, "content_kind")
                .unwrap_or(StreamViewContentKind::Unknown),
            packets: u64_field(fields, "packets")?,
            bytes: u64_field(fields, "bytes")?,
            payload_bytes: u64_field(fields, "payload_bytes")?,
            stream_bytes: u64_field(fields, "stream_bytes")?,
            stream_chunks: u64_field(fields, "stream_chunks")?,
            directions: directions_field(fields)?,
            matches: Vec::new(),
            match_count: 0,
            pattern_ids: AHashSet::new(),
        })
    }
}

impl StreamPatternMatch {
    pub fn from_event(event: &Event) -> Option<Self> {
        let fields = &event.fields;
        let stream_id = stream_id_field(fields, "stream_id")?;
        Some(Self {
            stream_id,
            stream_id_hex: stream_id_hex(stream_id),
            pattern_id: string_field(fields, "pattern_id")?.to_owned(),
            pattern_name: string_field(fields, "pattern_name")?.to_owned(),
            pattern_type: pattern_type_field(fields, "pattern_type")
                .unwrap_or(StreamPatternType::Unknown),
            direction: direction_field(fields, "direction")?,
            logical_start: u64_field(fields, "logical_start")?,
            logical_end: u64_field(fields, "logical_end")?,
            match_len: usize_field(fields, "match_len")?,
            match_text: string_field(fields, "match_text").map(trim_match_text),
        })
    }
}

fn stream_id_hex(stream_id: u64) -> String {
    format!("{stream_id:016x}")
}

impl StreamHideRule {
    pub fn normalized(self) -> Self {
        match self {
            Self::Service(service) => Self::Service(service.to_ascii_lowercase()),
            Self::PatternId(pattern_id) => Self::PatternId(pattern_id.trim().to_owned()),
            other => other,
        }
    }

    fn matches(&self, entry: &StreamViewEntry) -> bool {
        match self {
            Self::StreamId(stream_id) => entry.stream_id == *stream_id,
            Self::Service(service) => entry.service.name.eq_ignore_ascii_case(service),
            Self::Protocol(protocol) => entry.protocol == *protocol,
            Self::Port(port) => entry.endpoint_a.port == *port || entry.endpoint_b.port == *port,
            Self::ContentKind(kind) => entry.content_kind == *kind,
            Self::Status(status) => entry.status == *status,
            Self::PatternId(pattern_id) => entry.pattern_ids.contains(pattern_id),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::StreamId(stream_id) => format!("stream:{stream_id:016x}"),
            Self::Service(service) => format!("service:{service}"),
            Self::Protocol(protocol) => format!("protocol:{}", protocol_name(*protocol)),
            Self::Port(port) => format!("port:{port}"),
            Self::ContentKind(kind) => format!("content_kind:{}", kind.as_str()),
            Self::Status(status) => format!("status:{}", status.as_str()),
            Self::PatternId(pattern_id) => format!("pattern:{pattern_id}"),
        }
    }
}

fn matches_profile(entry: &StreamViewEntry, profile: &ServiceProfile) -> bool {
    if !profile.enabled {
        return false;
    }

    if profile
        .protocol
        .is_some_and(|protocol| entry.protocol != protocol)
    {
        return false;
    }

    if profile.id == "matched" {
        return entry.match_count != 0;
    }

    let service_matches = !profile.services.is_empty()
        && profile
            .services
            .iter()
            .any(|service| entry.service.name.eq_ignore_ascii_case(service));
    let port_matches = !profile.ports.is_empty()
        && profile
            .ports
            .iter()
            .any(|port| entry.endpoint_a.port == *port || entry.endpoint_b.port == *port);
    let content_matches = profile
        .content_kind
        .is_some_and(|kind| entry.content_kind == kind);
    let pattern_matches = !profile.pattern_ids.is_empty()
        && profile
            .pattern_ids
            .iter()
            .any(|pattern_id| entry.pattern_ids.contains(pattern_id));

    service_matches || port_matches || content_matches || pattern_matches
}

fn service_from_message(message: &StreamMessage, evidence: &'static str) -> StreamViewService {
    StreamViewService {
        name: service_name_from_message(message.protocol).to_owned(),
        side: service_side_from_message(message.direction, message.kind).to_owned(),
        confidence: 100,
        source: Some("parser".to_owned()),
        evidence: Some(evidence.to_owned()),
    }
}

fn service_name_from_message(protocol: StreamMessageProtocol) -> &'static str {
    match protocol {
        StreamMessageProtocol::Http1 => "http",
        StreamMessageProtocol::Dns => "dns",
        StreamMessageProtocol::WebSocket => "websocket",
        StreamMessageProtocol::Tls => "tls",
    }
}

fn service_side_from_message(direction: FlowDirection, kind: StreamMessageKind) -> &'static str {
    match (direction, kind) {
        (FlowDirection::AToB, StreamMessageKind::Request) => "b",
        (FlowDirection::BToA, StreamMessageKind::Request) => "a",
        (FlowDirection::AToB, StreamMessageKind::Response) => "a",
        (FlowDirection::BToA, StreamMessageKind::Response) => "b",
        (_, StreamMessageKind::Unknown) => "unknown",
    }
}

fn should_replace_service(current: &StreamViewService, next: &StreamViewService) -> bool {
    current.name == "unknown"
        || next.confidence >= current.confidence.saturating_add(5)
        || (current.name == "http" && next.name == "websocket")
        || current.source.as_deref() != Some("parser")
}

fn content_kind_from_message(
    protocol: StreamMessageProtocol,
    current: StreamViewContentKind,
) -> StreamViewContentKind {
    match protocol {
        StreamMessageProtocol::Http1 => match current {
            StreamViewContentKind::Unknown => StreamViewContentKind::Text,
            StreamViewContentKind::Binary => StreamViewContentKind::Mixed,
            other => other,
        },
        StreamMessageProtocol::WebSocket => match current {
            StreamViewContentKind::Unknown | StreamViewContentKind::Binary => {
                StreamViewContentKind::Mixed
            }
            other => other,
        },
        StreamMessageProtocol::Dns | StreamMessageProtocol::Tls => match current {
            StreamViewContentKind::Unknown => StreamViewContentKind::Binary,
            other => other,
        },
    }
}

impl StreamViewStatus {
    fn from_str(value: &str) -> Self {
        match value {
            "open" => Self::Open,
            "closing" => Self::Closing,
            "closed" => Self::Closed,
            _ => Self::Unknown,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closing => "closing",
            Self::Closed => "closed",
            Self::Unknown => "unknown",
        }
    }
}

impl StreamViewContentKind {
    fn from_str(value: &str) -> Self {
        match value {
            "text" => Self::Text,
            "binary" => Self::Binary,
            "mixed" => Self::Mixed,
            _ => Self::Unknown,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Text => "text",
            Self::Binary => "binary",
            Self::Mixed => "mixed",
        }
    }
}

impl StreamPatternType {
    fn from_str(value: &str) -> Self {
        match value {
            "substring" => Self::Substring,
            "regex" => Self::Regex,
            "binary" => Self::Binary,
            _ => Self::Unknown,
        }
    }
}

fn directions_field(fields: &Value) -> Option<[StreamViewDirection; 2]> {
    let directions = object_field(fields, "directions")?;
    Some([
        direction_snapshot_field(directions, "a_to_b")?,
        direction_snapshot_field(directions, "b_to_a")?,
    ])
}

fn direction_snapshot_field(value: &Value, name: &str) -> Option<StreamViewDirection> {
    let direction = object_field(value, name)?;
    Some(StreamViewDirection {
        packets: u64_field(direction, "packets")?,
        bytes: u64_field(direction, "bytes")?,
        payload_bytes: u64_field(direction, "payload_bytes")?,
        stream_bytes: u64_field(direction, "stream_bytes")?,
        stream_chunks: u64_field(direction, "stream_chunks")?,
        first_sequence: optional_u32_field(direction, "first_sequence")?,
        last_sequence: optional_u32_field(direction, "last_sequence")?,
        content_kind: content_kind_field(direction, "content_kind")
            .unwrap_or(StreamViewContentKind::Unknown),
        preview_base64: string_field(direction, "preview_base64")?.to_owned(),
        preview_text: string_field(direction, "preview_text").map(ToOwned::to_owned),
    })
}

fn endpoint_field(fields: &Value, name: &str) -> Option<StreamViewEndpoint> {
    let endpoint = object_field(fields, name)?;
    Some(StreamViewEndpoint {
        addr: string_field(endpoint, "addr")?.parse().ok()?,
        port: u16_field(endpoint, "port")?,
    })
}

fn service_field(fields: &Value, name: &str) -> Option<StreamViewService> {
    let service = object_field(fields, name)?;
    Some(StreamViewService {
        name: string_field(service, "name")?.to_owned(),
        side: string_field(service, "side")?.to_owned(),
        confidence: u8_field(service, "confidence")?,
        source: string_field(service, "source").map(ToOwned::to_owned),
        evidence: string_field(service, "evidence").map(ToOwned::to_owned),
    })
}

fn protocol_field(fields: &Value, name: &str) -> Option<TransportProtocol> {
    parse_protocol(string_field(fields, name)?)
}

fn status_field(fields: &Value, name: &str) -> Option<StreamViewStatus> {
    Some(StreamViewStatus::from_str(string_field(fields, name)?))
}

fn content_kind_field(fields: &Value, name: &str) -> Option<StreamViewContentKind> {
    Some(StreamViewContentKind::from_str(string_field(fields, name)?))
}

fn pattern_type_field(fields: &Value, name: &str) -> Option<StreamPatternType> {
    Some(StreamPatternType::from_str(string_field(fields, name)?))
}

fn direction_field(fields: &Value, name: &str) -> Option<FlowDirection> {
    match string_field(fields, name)? {
        "a_to_b" => Some(FlowDirection::AToB),
        "b_to_a" => Some(FlowDirection::BToA),
        _ => None,
    }
}

fn stream_id_field(fields: &Value, name: &str) -> Option<u64> {
    u64::from_str_radix(string_field(fields, name)?, 16).ok()
}

fn object_field<'a>(fields: &'a Value, name: &str) -> Option<&'a Value> {
    fields.get(name)
}

fn string_field<'a>(fields: &'a Value, name: &str) -> Option<&'a str> {
    match fields.get(name)? {
        Value::String(value) => Some(value.as_str()),
        Value::Null => None,
        _ => None,
    }
}

fn u64_field(fields: &Value, name: &str) -> Option<u64> {
    fields.get(name)?.as_u64()
}

fn usize_field(fields: &Value, name: &str) -> Option<usize> {
    u64_field(fields, name)?.try_into().ok()
}

fn optional_usize_field(fields: &Value, name: &str) -> Option<Option<usize>> {
    match fields.get(name) {
        Some(Value::Null) | None => Some(None),
        Some(value) => Some(Some(value.as_u64()?.try_into().ok()?)),
    }
}

fn u16_field(fields: &Value, name: &str) -> Option<u16> {
    u64_field(fields, name)?.try_into().ok()
}

fn u8_field(fields: &Value, name: &str) -> Option<u8> {
    u64_field(fields, name)?.try_into().ok()
}

fn optional_u32_field(fields: &Value, name: &str) -> Option<Option<u32>> {
    match fields.get(name)? {
        Value::Null => Some(None),
        value => Some(Some(value.as_u64()?.try_into().ok()?)),
    }
}

fn parse_protocol(value: &str) -> Option<TransportProtocol> {
    match value {
        "tcp" => Some(TransportProtocol::Tcp),
        "udp" => Some(TransportProtocol::Udp),
        "icmpv4" => Some(TransportProtocol::Icmpv4),
        "icmpv6" => Some(TransportProtocol::Icmpv6),
        _ => None,
    }
}

fn protocol_name(protocol: TransportProtocol) -> &'static str {
    match protocol {
        TransportProtocol::Tcp => "tcp",
        TransportProtocol::Udp => "udp",
        TransportProtocol::Icmpv4 => "icmpv4",
        TransportProtocol::Icmpv6 => "icmpv6",
    }
}

fn trim_match_text(value: &str) -> String {
    if value.len() <= MATCH_TEXT_PREVIEW_LIMIT {
        return value.to_owned();
    }

    value
        .chars()
        .take(MATCH_TEXT_PREVIEW_LIMIT)
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, str::FromStr};

    use serde_json::json;

    use super::*;

    #[test]
    fn queries_matched_streams_by_pattern() {
        let mut view = view();
        view.observe_event(&stream_event(0x10, "http", 80));
        view.observe_event(&pattern_event(0x10, "substring:0", "flag"));

        let result = view.query(&StreamViewQuery {
            only_matched: true,
            pattern_id: Some("substring:0".to_owned()),
            ..StreamViewQuery::default()
        });

        assert_eq!(1, result.rows.len());
        assert_eq!(0x10, result.rows[0].stream_id);
        assert_eq!(1, result.rows[0].match_count);
        assert_eq!(vec!["substring:0".to_owned()], result.rows[0].pattern_ids);
        assert_eq!(1, view.stats().matched_streams);
        assert_eq!(1, view.stats().stored_matches);
    }

    #[test]
    fn applies_favorites_manual_hidden_and_hide_rules() {
        let mut view = view();
        view.observe_event(&stream_event(0x10, "http", 80));
        view.observe_event(&stream_event(0x20, "dns", 53));

        assert!(view.set_favorite(0x10, true));
        assert!(view.set_hidden(0x20, true));
        view.add_hide_rule(StreamHideRule::Service("http".to_owned()));

        let visible = view.query(&StreamViewQuery::default());
        assert!(visible.rows.is_empty());

        let hidden = view.query(&StreamViewQuery {
            include_hidden: true,
            ..StreamViewQuery::default()
        });
        assert_eq!(2, hidden.rows.len());
        assert_eq!(
            Some("service:http".to_owned()),
            hidden.rows[0].hidden_reason
        );
        assert_eq!(Some("manual".to_owned()), hidden.rows[1].hidden_reason);

        let favorites = view.query(&StreamViewQuery {
            include_hidden: true,
            only_favorites: true,
            ..StreamViewQuery::default()
        });
        assert_eq!(1, favorites.rows.len());
        assert_eq!(0x10, favorites.rows[0].stream_id);
    }

    #[test]
    fn filters_streams_by_service_profile_before_pagination() {
        let mut view = view();
        view.observe_event(&stream_event(0x10, "dns", 53));
        view.observe_event(&stream_event(0x20, "http", 8080));
        view.observe_event(&stream_event(0x30, "tls", 443));
        let profile = ServiceProfileSet::builtin().get("http").unwrap().clone();

        let result = view.query(&StreamViewQuery {
            profile: Some(profile),
            limit: 1,
            ..StreamViewQuery::default()
        });

        assert_eq!(1, result.rows.len());
        assert_eq!(0x20, result.rows[0].stream_id);
        assert_eq!(Some(2), result.next_cursor);
    }

    #[test]
    fn bounds_matches_per_stream() {
        let mut view = StreamViewState::new(StreamViewConfig {
            max_matches_per_stream: 2,
            ..config()
        });
        view.observe_event(&stream_event(0x10, "http", 80));
        view.observe_event(&pattern_event(0x10, "substring:0", "a"));
        view.observe_event(&pattern_event(0x10, "substring:0", "b"));
        view.observe_event(&pattern_event(0x10, "substring:0", "c"));

        let matches = view.stream_matches(0x10).unwrap();
        assert_eq!(2, matches.len());
        assert_eq!("b", matches[0].pattern_name);
        assert_eq!("c", matches[1].pattern_name);
        assert_eq!(3, view.stream(0x10).unwrap().match_count);
        assert_eq!(1, view.stats().dropped_matches);
    }

    #[test]
    fn stores_content_shard_from_stream_event() {
        let mut view = view();
        let mut event = stream_event(0x10, "http", 80);
        event
            .fields
            .as_object_mut()
            .unwrap()
            .insert("content_shard".to_owned(), json!(3usize));

        view.observe_event(&event);

        assert_eq!(Some(3), view.stream(0x10).unwrap().content_shard);
        assert_eq!(Some(3), view.stream_row(0x10).unwrap().content_shard);
    }

    #[test]
    fn protocol_messages_enrich_stream_rows() {
        let mut view = view();
        let mut event = stream_event(0x10, "unknown", 12345);
        let fields = event.fields.as_object_mut().unwrap();
        fields.insert("content_kind".to_owned(), json!("binary"));
        fields.insert(
            "service".to_owned(),
            json!({"name": "unknown", "side": "unknown", "confidence": 0}),
        );
        view.observe_event(&event);

        view.observe_event(&protocol_message_event(
            0x10,
            "http1",
            "request",
            "a_to_b",
            "http1_request",
        ));

        let row = view.stream_row(0x10).unwrap();
        assert_eq!("http", row.service.name);
        assert_eq!("b", row.service.side);
        assert_eq!(100, row.service.confidence);
        assert_eq!(Some("parser".to_owned()), row.service.source);
        assert_eq!(Some("http1_request".to_owned()), row.service.evidence);
        assert_eq!(StreamViewContentKind::Mixed, row.content_kind);
    }

    #[test]
    fn evicts_oldest_stream() {
        let mut view = StreamViewState::new(StreamViewConfig {
            max_streams: 1,
            ..config()
        });
        view.observe_event(&stream_event(0x10, "http", 80));
        view.observe_event(&pattern_event(0x10, "substring:0", "flag"));
        view.observe_event(&stream_event(0x20, "dns", 53));

        assert!(view.stream(0x10).is_none());
        assert!(view.stream(0x20).is_some());
        assert_eq!(1, view.stats().tracked_streams);
        assert_eq!(0, view.stats().stored_matches);
        assert_eq!(1, view.stats().evicted_streams);
    }

    fn view() -> StreamViewState {
        StreamViewState::new(config())
    }

    fn config() -> StreamViewConfig {
        StreamViewConfig {
            enabled: true,
            max_streams: 1024,
            max_matches_per_stream: 16,
            max_query_limit: 256,
        }
    }

    fn stream_event(stream_id: u64, service: &str, service_port: u16) -> Event {
        Event {
            ts_sec: 1,
            ts_usec: 0,
            analyzer: "stream_inventory",
            event_type: "stream_open",
            length: 64,
            link_layer: "ethernet",
            linktype: 1,
            protocol: Some(TransportProtocol::Tcp),
            source_addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            destination_addr: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            source_port: Some(1111),
            destination_port: Some(service_port),
            fields: json!({
                "stream_id": format!("{stream_id:016x}"),
                "first_seen_us": 1_000_000u64,
                "last_seen_us": 1_000_000u64,
                "protocol": "tcp",
                "endpoint_a": {"addr": "10.0.0.1", "port": 1111},
                "endpoint_b": {"addr": "10.0.0.2", "port": service_port},
                "service": {"name": service, "side": "b", "confidence": 90},
                "status": "open",
                "content_kind": "text",
                "packets": 1u64,
                "bytes": 64u64,
                "payload_bytes": 16u64,
                "stream_bytes": 16u64,
                "stream_chunks": 1u64,
                "directions": {
                    "a_to_b": direction_fields("text"),
                    "b_to_a": direction_fields("unknown"),
                }
            }),
        }
    }

    fn pattern_event(stream_id: u64, pattern_id: &str, pattern_name: &str) -> Event {
        Event {
            ts_sec: 1,
            ts_usec: 1,
            analyzer: "pattern",
            event_type: "pattern_match",
            length: pattern_name.len(),
            link_layer: "ethernet",
            linktype: 1,
            protocol: Some(TransportProtocol::Tcp),
            source_addr: Some(IpAddr::from_str("10.0.0.1").unwrap()),
            destination_addr: Some(IpAddr::from_str("10.0.0.2").unwrap()),
            source_port: Some(1111),
            destination_port: Some(80),
            fields: json!({
                "stream_id": format!("{stream_id:016x}"),
                "pattern_id": pattern_id,
                "pattern_name": pattern_name,
                "pattern_type": "substring",
                "direction": "a_to_b",
                "logical_start": 0u64,
                "logical_end": pattern_name.len() as u64,
                "match_len": pattern_name.len(),
                "match_text": pattern_name,
            }),
        }
    }

    fn protocol_message_event(
        stream_id: u64,
        protocol: &str,
        kind: &str,
        direction: &str,
        event_type: &'static str,
    ) -> Event {
        Event {
            ts_sec: 1,
            ts_usec: 2,
            analyzer: "protocol_message",
            event_type,
            length: 16,
            link_layer: "ethernet",
            linktype: 1,
            protocol: Some(TransportProtocol::Tcp),
            source_addr: Some(IpAddr::from_str("10.0.0.1").unwrap()),
            destination_addr: Some(IpAddr::from_str("10.0.0.2").unwrap()),
            source_port: Some(1111),
            destination_port: Some(80),
            fields: json!({
                "stream_id": stream_id,
                "stream_id_hex": format!("{stream_id:016x}"),
                "message_id": 1u64,
                "protocol": protocol,
                "kind": kind,
                "status": "complete",
                "direction": direction,
                "ordinal": 1u64,
                "summary": event_type,
                "logical_start": 0u64,
                "logical_end": 16u64,
                "header_start": 0u64,
                "header_end": 16u64,
                "body_start": null,
                "body_end": null,
                "wire_bytes": 16u64,
                "header_bytes": 16u64,
                "body_bytes": 0u64,
                "http": null,
                "dns": null,
                "websocket": null,
                "tls": null,
                "error": null,
            }),
        }
    }

    fn direction_fields(kind: &str) -> Value {
        json!({
            "packets": 1u64,
            "bytes": 64u64,
            "payload_bytes": 16u64,
            "stream_bytes": 16u64,
            "stream_chunks": 1u64,
            "first_sequence": 1u32,
            "last_sequence": 17u32,
            "content_kind": kind,
            "preview_base64": "",
            "preview_text": null,
        })
    }
}
