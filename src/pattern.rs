use std::sync::Arc;

use ahash::{AHashMap, AHashSet};
use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use regex::bytes::Regex;
use serde_json::{Value, json};

use crate::{
    event::Event,
    flow::FlowDirection,
    packet::DecodedPacket,
    stream_content::{StreamContent, StreamContentUpdate, StreamContentWindow},
};

#[derive(Debug, Clone)]
pub struct PatternEngineConfig {
    enabled: bool,
    set: Arc<PatternSet>,
    max_matches_per_stream: u64,
    max_total_matches: u64,
    regex_window_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct PatternDefinition {
    pub id: String,
    pub name: String,
    kind: PatternDefinitionKind,
}

#[derive(Debug, Clone)]
enum PatternDefinitionKind {
    Substring(Vec<u8>),
    Binary(Vec<u8>),
    Regex(String),
}

#[derive(Debug)]
struct PatternSet {
    patterns: Vec<CompiledPattern>,
    literal_indices: Vec<usize>,
    literal_automaton: Option<AhoCorasick>,
    max_literal_len: usize,
}

#[derive(Debug)]
struct CompiledPattern {
    id: String,
    name: String,
    kind: PatternKind,
}

#[derive(Debug)]
enum PatternKind {
    Substring,
    Binary,
    Regex { regex: Regex },
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PatternEngineStats {
    pub pattern_matches: u64,
    pub pattern_dropped_matches: u64,
    pub pattern_matched_streams: usize,
}

pub struct PatternEngine {
    config: PatternEngineConfig,
    matches_by_stream: AHashMap<u64, u64>,
    stats: PatternEngineStats,
    scratch_candidates: Vec<CandidateMatch>,
    scratch_emitted: AHashSet<MatchKey>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NewRange {
    start: u64,
    end: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct MatchKey {
    pattern_index: usize,
    stream_id: u64,
    direction: FlowDirection,
    start: u64,
    end: u64,
}

#[derive(Debug, Clone, Copy)]
struct CandidateMatch {
    pattern_index: usize,
    start: usize,
    end: usize,
}

impl PatternEngineConfig {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            set: Arc::new(PatternSet::empty()),
            max_matches_per_stream: 0,
            max_total_matches: 0,
            regex_window_bytes: 0,
        }
    }

    pub fn compile(
        definitions: Vec<PatternDefinition>,
        max_matches_per_stream: u64,
        max_total_matches: u64,
        regex_window_bytes: usize,
    ) -> Result<Self> {
        if definitions.is_empty() || max_matches_per_stream == 0 || max_total_matches == 0 {
            return Ok(Self::disabled());
        }

        Ok(Self {
            enabled: true,
            set: Arc::new(PatternSet::compile(definitions)?),
            max_matches_per_stream,
            max_total_matches,
            regex_window_bytes,
        })
    }

    fn lookbehind_bytes(&self) -> usize {
        self.set
            .max_literal_len
            .saturating_sub(1)
            .max(self.regex_window_bytes)
    }
}

impl Default for PatternEngineConfig {
    fn default() -> Self {
        Self::disabled()
    }
}

impl PatternDefinition {
    pub fn substring(id: impl Into<String>, value: impl Into<String>) -> Self {
        let value = value.into();
        Self {
            id: id.into(),
            name: value.clone(),
            kind: PatternDefinitionKind::Substring(value.into_bytes()),
        }
    }

    pub fn regex(id: impl Into<String>, value: impl Into<String>) -> Self {
        let value = value.into();
        Self {
            id: id.into(),
            name: value.clone(),
            kind: PatternDefinitionKind::Regex(value),
        }
    }

    pub fn binary_hex(id: impl Into<String>, value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        let bytes = parse_hex_pattern(&value)?;
        Ok(Self {
            id: id.into(),
            name: value,
            kind: PatternDefinitionKind::Binary(bytes),
        })
    }
}

impl PatternSet {
    fn empty() -> Self {
        Self {
            patterns: Vec::new(),
            literal_indices: Vec::new(),
            literal_automaton: None,
            max_literal_len: 0,
        }
    }

    fn compile(definitions: Vec<PatternDefinition>) -> Result<Self> {
        let mut patterns = Vec::with_capacity(definitions.len());
        let mut literal_indices = Vec::new();
        let mut literal_needles = Vec::new();
        let mut max_literal_len = 0usize;

        for definition in definitions {
            let pattern_index = patterns.len();
            match definition.kind {
                PatternDefinitionKind::Substring(bytes) => {
                    if bytes.is_empty() {
                        return Err(anyhow!("substring pattern '{}' is empty", definition.id));
                    }
                    max_literal_len = max_literal_len.max(bytes.len());
                    literal_indices.push(pattern_index);
                    literal_needles.push(bytes.clone());
                    patterns.push(CompiledPattern {
                        id: definition.id,
                        name: definition.name,
                        kind: PatternKind::Substring,
                    });
                }
                PatternDefinitionKind::Binary(bytes) => {
                    if bytes.is_empty() {
                        return Err(anyhow!("binary pattern '{}' is empty", definition.id));
                    }
                    max_literal_len = max_literal_len.max(bytes.len());
                    literal_indices.push(pattern_index);
                    literal_needles.push(bytes.clone());
                    patterns.push(CompiledPattern {
                        id: definition.id,
                        name: definition.name,
                        kind: PatternKind::Binary,
                    });
                }
                PatternDefinitionKind::Regex(pattern) => {
                    let regex = Regex::new(&pattern)
                        .with_context(|| format!("failed to compile regex pattern: {pattern}"))?;
                    patterns.push(CompiledPattern {
                        id: definition.id,
                        name: definition.name,
                        kind: PatternKind::Regex { regex },
                    });
                }
            }
        }

        let literal_automaton = if literal_needles.is_empty() {
            None
        } else {
            Some(
                AhoCorasickBuilder::new()
                    .ascii_case_insensitive(false)
                    .build(literal_needles)
                    .context("failed to build literal pattern automaton")?,
            )
        };

        Ok(Self {
            patterns,
            literal_indices,
            literal_automaton,
            max_literal_len,
        })
    }
}

impl PatternEngine {
    pub fn new(config: PatternEngineConfig) -> Self {
        Self {
            config,
            matches_by_stream: AHashMap::new(),
            stats: PatternEngineStats::default(),
            scratch_candidates: Vec::new(),
            scratch_emitted: AHashSet::new(),
        }
    }

    pub fn scan_update(
        &mut self,
        packet: &DecodedPacket<'_>,
        content: &StreamContent,
        update: &StreamContentUpdate,
        events: &mut Vec<Event>,
    ) {
        if !self.config.enabled {
            return;
        }

        let lookbehind = self.config.lookbehind_bytes() as u64;
        let mut emitted = std::mem::take(&mut self.scratch_emitted);
        emitted.clear();

        for range in &update.ranges {
            let new_range = NewRange {
                start: range.logical_start,
                end: range.logical_end,
            };
            let window_start = range.logical_start.saturating_sub(lookbehind);
            let Some(windows) = content.direction_windows(
                &update.key,
                range.direction,
                window_start,
                range.logical_end,
            ) else {
                continue;
            };

            for window in windows {
                self.scan_window(packet, &window, new_range, events, &mut emitted);
            }
        }

        emitted.clear();
        self.scratch_emitted = emitted;
    }

    pub fn stats(&self) -> PatternEngineStats {
        PatternEngineStats {
            pattern_matched_streams: self.matches_by_stream.len(),
            ..self.stats
        }
    }

    fn scan_window(
        &mut self,
        packet: &DecodedPacket<'_>,
        window: &StreamContentWindow,
        new_range: NewRange,
        events: &mut Vec<Event>,
        emitted: &mut AHashSet<MatchKey>,
    ) {
        let mut candidates = std::mem::take(&mut self.scratch_candidates);
        candidates.clear();

        if let Some(automaton) = &self.config.set.literal_automaton {
            for matched in automaton.find_overlapping_iter(&window.bytes) {
                let pattern_index = self.config.set.literal_indices[matched.pattern().as_usize()];
                candidates.push(CandidateMatch {
                    pattern_index,
                    start: matched.start(),
                    end: matched.end(),
                });
            }
        }

        for (pattern_index, regex) in
            self.config
                .set
                .patterns
                .iter()
                .enumerate()
                .filter_map(|(pattern_index, pattern)| match &pattern.kind {
                    PatternKind::Regex { regex } => Some((pattern_index, regex)),
                    _ => None,
                })
        {
            for matched in regex.find_iter(&window.bytes) {
                candidates.push(CandidateMatch {
                    pattern_index,
                    start: matched.start(),
                    end: matched.end(),
                });
            }
        }

        for candidate in candidates.drain(..) {
            self.emit_match_if_new(packet, window, new_range, candidate, events, emitted);
        }

        self.scratch_candidates = candidates;
    }

    fn emit_match_if_new(
        &mut self,
        packet: &DecodedPacket<'_>,
        window: &StreamContentWindow,
        new_range: NewRange,
        candidate: CandidateMatch,
        events: &mut Vec<Event>,
        emitted: &mut AHashSet<MatchKey>,
    ) {
        let CandidateMatch {
            pattern_index,
            start,
            end,
        } = candidate;
        if start == end {
            return;
        }

        let absolute_start = window.logical_start.saturating_add(start as u64);
        let absolute_end = window.logical_start.saturating_add(end as u64);
        if absolute_start >= new_range.end || absolute_end <= new_range.start {
            return;
        }

        let key = MatchKey {
            pattern_index,
            stream_id: window.stream_id,
            direction: window.direction,
            start: absolute_start,
            end: absolute_end,
        };
        if !emitted.insert(key) {
            return;
        }

        if !self.reserve_match(window.stream_id) {
            return;
        }

        let pattern = &self.config.set.patterns[pattern_index];
        let bytes = &window.bytes[start..end];
        events.push(Event::from_packet(
            "pattern",
            "pattern_match",
            packet,
            bytes.len(),
            pattern_fields(pattern, window, absolute_start, absolute_end, bytes),
        ));
    }

    fn reserve_match(&mut self, stream_id: u64) -> bool {
        if self.stats.pattern_matches >= self.config.max_total_matches {
            self.stats.pattern_dropped_matches =
                self.stats.pattern_dropped_matches.saturating_add(1);
            return false;
        }

        let stream_matches = self.matches_by_stream.entry(stream_id).or_insert(0);
        if *stream_matches >= self.config.max_matches_per_stream {
            self.stats.pattern_dropped_matches =
                self.stats.pattern_dropped_matches.saturating_add(1);
            return false;
        }

        *stream_matches = stream_matches.saturating_add(1);
        self.stats.pattern_matches = self.stats.pattern_matches.saturating_add(1);
        true
    }
}

fn pattern_fields(
    pattern: &CompiledPattern,
    window: &StreamContentWindow,
    absolute_start: u64,
    absolute_end: u64,
    bytes: &[u8],
) -> Value {
    json!({
        "stream_id": format!("{:016x}", window.stream_id),
        "pattern_id": pattern.id.as_str(),
        "pattern_name": pattern.name.as_str(),
        "pattern_type": pattern.kind.as_str(),
        "direction": direction_name(window.direction),
        "logical_start": absolute_start,
        "logical_end": absolute_end,
        "match_len": bytes.len(),
        "match_base64": STANDARD.encode(bytes),
        "match_text": preview_text(bytes),
    })
}

impl PatternKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Substring => "substring",
            Self::Binary => "binary",
            Self::Regex { .. } => "regex",
        }
    }
}

fn parse_hex_pattern(value: &str) -> Result<Vec<u8>> {
    let digits = value
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace() && !matches!(ch, ':' | '_' | '-'))
        .collect::<String>();
    let digits = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
        .unwrap_or(&digits);

    if digits.is_empty() {
        return Err(anyhow!("binary pattern is empty"));
    }
    if digits.len() % 2 != 0 {
        return Err(anyhow!("binary pattern has an odd number of hex digits"));
    }

    let mut bytes = Vec::with_capacity(digits.len() / 2);
    for index in (0..digits.len()).step_by(2) {
        let byte = u8::from_str_radix(&digits[index..index + 2], 16)
            .with_context(|| format!("invalid hex byte '{}'", &digits[index..index + 2]))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn preview_text(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || !bytes.iter().all(|byte| is_textish(*byte)) {
        return None;
    }

    let mut text = String::with_capacity(bytes.len());
    for byte in bytes {
        match *byte {
            b'\n' => text.push_str("\\n"),
            b'\r' => text.push_str("\\r"),
            b'\t' => text.push_str("\\t"),
            0x20..=0x7e => text.push(*byte as char),
            _ => text.push('.'),
        }
    }
    Some(text)
}

fn is_textish(byte: u8) -> bool {
    matches!(byte, b'\n' | b'\r' | b'\t' | 0x20..=0x7e)
}

fn direction_name(direction: FlowDirection) -> &'static str {
    match direction {
        FlowDirection::AToB => "a_to_b",
        FlowDirection::BToA => "b_to_a",
    }
}

#[cfg(test)]
mod tests {
    use etherparse::PacketBuilder;
    use pcap::Linktype;

    use crate::{
        flow::{FlowTable, FlowTableConfig},
        packet::{DecodedPacket, LinkLayer, PacketTimestamp, RawPacket},
        stream_content::{StreamContentConfig, StreamContentUpdate},
    };

    use super::*;

    #[test]
    fn parses_binary_hex_pattern() {
        assert_eq!(
            vec![0xde, 0xad, 0xbe, 0xef],
            parse_hex_pattern("de ad:be-ef").unwrap()
        );
    }

    #[test]
    fn emits_substring_match_across_update_boundary() {
        let mut harness = Harness::new(vec![PatternDefinition::substring("substring:0", "flag")]);

        harness.feed(tcp_packet(1, b"fl"));
        harness.feed(tcp_packet(3, b"ag"));

        assert_eq!(1, harness.events.len());
        assert_eq!("pattern_match", harness.events[0].event_type);
        assert_eq!("substring", harness.events[0].fields["pattern_type"]);
        assert_eq!(0, harness.events[0].fields["logical_start"]);
        assert_eq!(4, harness.events[0].fields["logical_end"]);
        assert_eq!("flag", harness.events[0].fields["match_text"]);
    }

    #[test]
    fn emits_binary_and_regex_matches() {
        let mut harness = Harness::new(vec![
            PatternDefinition::binary_hex("binary:0", "de ad").unwrap(),
            PatternDefinition::regex("regex:0", "token=[a-z0-9]+"),
        ]);

        harness.feed(tcp_packet(1, b"\xde\xad token=abc123"));

        assert_eq!(2, harness.events.len());
        let types = harness
            .events
            .iter()
            .map(|event| event.fields["pattern_type"].as_str().unwrap())
            .collect::<Vec<_>>();
        assert!(types.contains(&"binary"));
        assert!(types.contains(&"regex"));
    }

    #[test]
    fn enforces_per_stream_match_limit() {
        let mut harness = Harness::new_with_limits(
            vec![PatternDefinition::substring("substring:0", "a")],
            2,
            100,
        );

        harness.feed(tcp_packet(1, b"aaaa"));

        assert_eq!(2, harness.events.len());
        assert_eq!(2, harness.engine.stats().pattern_matches);
        assert_eq!(2, harness.engine.stats().pattern_dropped_matches);
    }

    struct Harness {
        flow_table: FlowTable,
        content: StreamContent,
        engine: PatternEngine,
        events: Vec<Event>,
    }

    impl Harness {
        fn new(patterns: Vec<PatternDefinition>) -> Self {
            Self::new_with_limits(patterns, 1024, 1024)
        }

        fn new_with_limits(
            patterns: Vec<PatternDefinition>,
            max_matches_per_stream: u64,
            max_total_matches: u64,
        ) -> Self {
            Self {
                flow_table: FlowTable::new(FlowTableConfig::new(1024, 120_000, 64 * 1024, 16)),
                content: StreamContent::new(StreamContentConfig {
                    enabled: true,
                    max_streams: 1024,
                    idle_timeout_ms: 120_000,
                    max_total_bytes: 1024 * 1024,
                    max_bytes_per_stream: 64 * 1024,
                    max_segment_bytes: 64 * 1024,
                }),
                engine: PatternEngine::new(
                    PatternEngineConfig::compile(
                        patterns,
                        max_matches_per_stream,
                        max_total_matches,
                        4096,
                    )
                    .unwrap(),
                ),
                events: Vec::new(),
            }
        }

        fn feed(&mut self, raw: RawPacket) -> Option<StreamContentUpdate> {
            let packet = DecodedPacket::from_raw(&raw);
            let flow = self.flow_table.observe(&packet).unwrap();
            let update = self.content.observe_flow(&packet, &flow)?;
            self.engine
                .scan_update(&packet, &self.content, &update, &mut self.events);
            Some(update)
        }
    }

    fn tcp_packet(sequence: u32, payload: &[u8]) -> RawPacket {
        let builder = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 20)
            .tcp(1111, 80, sequence, 2048);
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
