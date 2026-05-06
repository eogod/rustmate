use ahash::AHashMap;

use crate::{
    flow::{FlowDirection, FlowKey, FlowObservation, StreamChunk},
    packet::{DecodedPacket, PacketTimestamp},
};

const DEFAULT_EVICTION_INTERVAL_PACKETS: u64 = 16_384;

#[derive(Debug, Clone, Copy)]
pub struct StreamContentConfig {
    pub enabled: bool,
    pub max_streams: usize,
    pub idle_timeout_ms: u64,
    pub max_total_bytes: usize,
    pub max_bytes_per_stream: usize,
    pub max_segment_bytes: usize,
}

impl StreamContentConfig {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            max_streams: 0,
            idle_timeout_ms: 0,
            max_total_bytes: 0,
            max_bytes_per_stream: 0,
            max_segment_bytes: 0,
        }
    }

    fn normalized(self) -> Self {
        if !self.enabled || self.max_total_bytes == 0 || self.max_bytes_per_stream == 0 {
            return Self::disabled();
        }

        let max_bytes_per_stream = self.max_bytes_per_stream.min(self.max_total_bytes).max(1);

        Self {
            enabled: true,
            max_streams: self.max_streams.max(1),
            idle_timeout_ms: self.idle_timeout_ms,
            max_total_bytes: self.max_total_bytes,
            max_bytes_per_stream,
            max_segment_bytes: self.max_segment_bytes.min(max_bytes_per_stream).max(1),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct StreamContentStats {
    pub active_content_streams: usize,
    pub active_content_segments: usize,
    pub stored_content_bytes: usize,
    pub observed_content_bytes: u64,
    pub dropped_content_bytes: u64,
    pub evicted_content_streams: u64,
    pub truncated_content_streams: u64,
    pub content_updates: u64,
    pub merged_content_segments: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamContentUpdate {
    pub stream_id: u64,
    pub key: FlowKey,
    pub ranges: Vec<StreamContentRange>,
    pub observed_bytes: u64,
    pub stored_bytes_after: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamContentRange {
    pub stream_id: u64,
    pub direction: FlowDirection,
    pub logical_start: u64,
    pub logical_end: u64,
    pub sequence_start: Option<u32>,
    pub sequence_end: Option<u32>,
    pub stored_bytes: usize,
}

pub struct StreamContent {
    config: StreamContentConfig,
    streams: AHashMap<FlowKey, ContentRecord>,
    observed_packets: u64,
    stored_bytes: usize,
    stats: StreamContentStats,
}

#[derive(Debug, Clone)]
struct ContentRecord {
    id: u64,
    last_seen_us: u64,
    directions: [DirectionContent; 2],
    truncated: bool,
}

#[derive(Debug, Default, Clone)]
struct DirectionContent {
    next_offset: u64,
    stored_bytes: usize,
    segments: Vec<ContentSegment>,
}

#[derive(Debug, Clone)]
struct ContentSegment {
    logical_start: u64,
    sequence_start: Option<u32>,
    observed_us: u64,
    bytes: Vec<u8>,
}

#[derive(Debug, Default, Clone, Copy)]
struct AppendStats {
    observed_bytes: u64,
    stored_bytes: usize,
    merged_segments: u64,
}

impl StreamContent {
    pub fn new(config: StreamContentConfig) -> Self {
        let config = config.normalized();
        let capacity = if config.enabled {
            config.max_streams.min(65_536)
        } else {
            0
        };

        Self {
            config,
            streams: AHashMap::with_capacity(capacity),
            observed_packets: 0,
            stored_bytes: 0,
            stats: StreamContentStats::default(),
        }
    }

    pub fn observe_flow(
        &mut self,
        packet: &DecodedPacket<'_>,
        flow: &FlowObservation<'_>,
    ) -> Option<StreamContentUpdate> {
        if !self.config.enabled {
            return None;
        }
        if !flow_has_content(packet, flow) {
            return None;
        }

        self.observed_packets = self.observed_packets.saturating_add(1);
        let now_us = timestamp_us(packet.timestamp);
        if self.should_evict() {
            self.evict_idle(now_us);
        }

        self.ensure_stream(flow.key, now_us)?;

        let update = {
            let record = self.streams.get_mut(&flow.key)?;
            record.last_seen_us = now_us;
            if let Some(tcp) = flow.tcp.as_ref() {
                record.observe_chunks(
                    &tcp.stream_chunks,
                    now_us,
                    self.config.max_segment_bytes,
                    self.config.max_bytes_per_stream,
                )
            } else {
                let payload = packet.transport_payload()?.bytes;
                record.observe_payload(
                    flow.direction,
                    payload,
                    None,
                    now_us,
                    self.config.max_segment_bytes,
                    self.config.max_bytes_per_stream,
                )
            }
        };

        if update.ranges.is_empty() {
            return None;
        }

        self.stored_bytes = self
            .stored_bytes
            .saturating_add(update.appended.stored_bytes)
            .saturating_sub(update.trimmed_bytes);
        self.stats.observed_content_bytes = self
            .stats
            .observed_content_bytes
            .saturating_add(update.appended.observed_bytes);
        self.stats.dropped_content_bytes = self
            .stats
            .dropped_content_bytes
            .saturating_add(update.trimmed_bytes as u64);
        self.stats.content_updates = self.stats.content_updates.saturating_add(1);
        self.stats.merged_content_segments = self
            .stats
            .merged_content_segments
            .saturating_add(update.appended.merged_segments);
        if update.newly_truncated {
            self.stats.truncated_content_streams =
                self.stats.truncated_content_streams.saturating_add(1);
        }

        self.enforce_global_limit(flow.key);

        Some(StreamContentUpdate {
            stream_id: flow.key.stable_id(),
            key: flow.key,
            ranges: update.ranges,
            observed_bytes: update.appended.observed_bytes,
            stored_bytes_after: self
                .streams
                .get(&flow.key)
                .map_or(0, ContentRecord::stored_bytes),
        })
    }

    pub fn direction_bytes(&self, key: &FlowKey, direction: FlowDirection) -> Option<Vec<u8>> {
        self.streams
            .get(key)
            .map(|record| record.direction_bytes(direction))
    }

    pub fn direction_ranges(
        &self,
        key: &FlowKey,
        direction: FlowDirection,
    ) -> Option<Vec<StreamContentRange>> {
        self.streams
            .get(key)
            .map(|record| record.direction_ranges(direction))
    }

    pub fn stats(&self) -> StreamContentStats {
        StreamContentStats {
            active_content_streams: self.streams.len(),
            active_content_segments: self
                .streams
                .values()
                .map(ContentRecord::segment_count)
                .sum(),
            stored_content_bytes: self.stored_bytes,
            ..self.stats
        }
    }

    fn ensure_stream(&mut self, key: FlowKey, now_us: u64) -> Option<()> {
        if self.streams.contains_key(&key) {
            return Some(());
        }

        if self.streams.len() >= self.config.max_streams {
            self.evict_idle(now_us);
            if self.streams.len() >= self.config.max_streams {
                self.evict_oldest(None);
            }
        }

        if self.streams.len() >= self.config.max_streams {
            return None;
        }

        self.streams.insert(key, ContentRecord::new(key, now_us));
        Some(())
    }

    fn should_evict(&self) -> bool {
        self.observed_packets != 0
            && self
                .observed_packets
                .is_multiple_of(DEFAULT_EVICTION_INTERVAL_PACKETS)
    }

    fn evict_idle(&mut self, now_us: u64) {
        let timeout_us = self.config.idle_timeout_ms.saturating_mul(1_000);
        let expired = self
            .streams
            .iter()
            .filter_map(|(key, record)| {
                (now_us.saturating_sub(record.last_seen_us) > timeout_us).then_some(*key)
            })
            .collect::<Vec<_>>();

        for key in expired {
            self.remove_stream(&key);
        }
    }

    fn enforce_global_limit(&mut self, current_key: FlowKey) {
        while self.stored_bytes > self.config.max_total_bytes {
            let except = (self.streams.len() > 1).then_some(current_key);
            if !self.evict_oldest(except) {
                break;
            }
        }
    }

    fn evict_oldest(&mut self, except: Option<FlowKey>) -> bool {
        let key = self
            .streams
            .iter()
            .filter(|(key, _)| Some(**key) != except)
            .min_by_key(|(_, record)| record.last_seen_us)
            .map(|(key, _)| *key);
        let Some(key) = key else {
            return false;
        };
        self.remove_stream(&key);
        true
    }

    fn remove_stream(&mut self, key: &FlowKey) {
        let Some(record) = self.streams.remove(key) else {
            return;
        };
        let stored = record.stored_bytes();
        self.stored_bytes = self.stored_bytes.saturating_sub(stored);
        self.stats.dropped_content_bytes = self
            .stats
            .dropped_content_bytes
            .saturating_add(stored as u64);
        self.stats.evicted_content_streams = self.stats.evicted_content_streams.saturating_add(1);
    }
}

impl ContentRecord {
    fn new(key: FlowKey, now_us: u64) -> Self {
        Self {
            id: key.stable_id(),
            last_seen_us: now_us,
            directions: [DirectionContent::default(), DirectionContent::default()],
            truncated: false,
        }
    }

    fn observe_chunks(
        &mut self,
        chunks: &[StreamChunk<'_>],
        observed_us: u64,
        max_segment_bytes: usize,
        max_bytes_per_stream: usize,
    ) -> RecordUpdate {
        let mut update = RecordUpdate::default();
        for chunk in chunks {
            let payload_update = self.observe_payload(
                chunk.direction,
                chunk.bytes.as_slice(),
                Some(chunk.sequence_start),
                observed_us,
                max_segment_bytes,
                max_bytes_per_stream,
            );
            update.merge(payload_update);
        }
        update
    }

    fn observe_payload(
        &mut self,
        direction: FlowDirection,
        bytes: &[u8],
        sequence_start: Option<u32>,
        observed_us: u64,
        max_segment_bytes: usize,
        max_bytes_per_stream: usize,
    ) -> RecordUpdate {
        if bytes.is_empty() {
            return RecordUpdate::default();
        }

        let direction_index = direction_index(direction);
        let appended = self.directions[direction_index].append(
            self.id,
            direction,
            bytes,
            sequence_start,
            observed_us,
            max_segment_bytes,
        );
        let was_truncated = self.truncated;
        let trimmed_bytes = self.trim_to_limit(max_bytes_per_stream);
        let newly_truncated = !was_truncated && self.truncated;

        RecordUpdate {
            ranges: appended.ranges,
            appended: appended.stats,
            trimmed_bytes,
            newly_truncated,
        }
    }

    fn trim_to_limit(&mut self, max_bytes_per_stream: usize) -> usize {
        let mut trimmed = 0usize;
        while self.stored_bytes() > max_bytes_per_stream {
            let excess = self.stored_bytes() - max_bytes_per_stream;
            let Some(direction) = self.oldest_direction() else {
                break;
            };
            let dropped = self.directions[direction].trim_oldest(excess);
            if dropped == 0 {
                break;
            }
            trimmed = trimmed.saturating_add(dropped);
            self.truncated = true;
        }
        trimmed
    }

    fn oldest_direction(&self) -> Option<usize> {
        self.directions
            .iter()
            .enumerate()
            .filter_map(|(index, direction)| {
                direction
                    .segments
                    .first()
                    .map(|segment| (index, segment.observed_us, segment.logical_start))
            })
            .min_by_key(|(_, observed_us, logical_start)| (*observed_us, *logical_start))
            .map(|(index, _, _)| index)
    }

    fn stored_bytes(&self) -> usize {
        self.directions
            .iter()
            .map(|direction| direction.stored_bytes)
            .sum()
    }

    fn segment_count(&self) -> usize {
        self.directions
            .iter()
            .map(|direction| direction.segments.len())
            .sum()
    }

    fn direction_bytes(&self, direction: FlowDirection) -> Vec<u8> {
        self.directions[direction_index(direction)].bytes()
    }

    fn direction_ranges(&self, direction: FlowDirection) -> Vec<StreamContentRange> {
        self.directions[direction_index(direction)].ranges(self.id, direction)
    }
}

#[derive(Debug, Default)]
struct RecordUpdate {
    ranges: Vec<StreamContentRange>,
    appended: AppendStats,
    trimmed_bytes: usize,
    newly_truncated: bool,
}

impl RecordUpdate {
    fn merge(&mut self, other: Self) {
        self.ranges.extend(other.ranges);
        self.appended.observed_bytes = self
            .appended
            .observed_bytes
            .saturating_add(other.appended.observed_bytes);
        self.appended.stored_bytes = self
            .appended
            .stored_bytes
            .saturating_add(other.appended.stored_bytes);
        self.appended.merged_segments = self
            .appended
            .merged_segments
            .saturating_add(other.appended.merged_segments);
        self.trimmed_bytes = self.trimmed_bytes.saturating_add(other.trimmed_bytes);
        self.newly_truncated |= other.newly_truncated;
    }
}

#[derive(Debug, Default)]
struct DirectionAppend {
    ranges: Vec<StreamContentRange>,
    stats: AppendStats,
}

impl DirectionContent {
    fn append(
        &mut self,
        stream_id: u64,
        direction: FlowDirection,
        bytes: &[u8],
        sequence_start: Option<u32>,
        observed_us: u64,
        max_segment_bytes: usize,
    ) -> DirectionAppend {
        let mut append = DirectionAppend::default();
        let mut consumed = 0usize;

        while consumed < bytes.len() {
            let take = (bytes.len() - consumed).min(max_segment_bytes);
            let slice = &bytes[consumed..consumed + take];
            let logical_start = self.next_offset;
            let logical_end = logical_start.saturating_add(take as u64);
            let segment_sequence_start =
                sequence_start.map(|sequence| sequence.wrapping_add(consumed as u32));
            let sequence_end =
                segment_sequence_start.map(|sequence| sequence.wrapping_add(take as u32));

            self.next_offset = logical_end;
            append.stats.observed_bytes = append.stats.observed_bytes.saturating_add(take as u64);
            append.stats.stored_bytes = append.stats.stored_bytes.saturating_add(take);

            if self.try_merge_last(segment_sequence_start, slice, max_segment_bytes) {
                append.stats.merged_segments = append.stats.merged_segments.saturating_add(1);
            } else {
                self.segments.push(ContentSegment {
                    logical_start,
                    sequence_start: segment_sequence_start,
                    observed_us,
                    bytes: slice.to_vec(),
                });
            }
            self.stored_bytes = self.stored_bytes.saturating_add(take);

            append.ranges.push(StreamContentRange {
                stream_id,
                direction,
                logical_start,
                logical_end,
                sequence_start: segment_sequence_start,
                sequence_end,
                stored_bytes: take,
            });

            consumed += take;
        }

        append
    }

    fn try_merge_last(
        &mut self,
        sequence_start: Option<u32>,
        bytes: &[u8],
        max_segment_bytes: usize,
    ) -> bool {
        let Some(last) = self.segments.last_mut() else {
            return false;
        };
        let Some(sequence_start) = sequence_start else {
            return false;
        };
        let Some(last_sequence_end) = last.sequence_end() else {
            return false;
        };
        if last_sequence_end != sequence_start {
            return false;
        }
        if last.bytes.len().saturating_add(bytes.len()) > max_segment_bytes {
            return false;
        }

        last.bytes.extend_from_slice(bytes);
        true
    }

    fn trim_oldest(&mut self, bytes: usize) -> usize {
        let mut remaining = bytes;
        let mut trimmed = 0usize;

        while remaining != 0 {
            let Some(first) = self.segments.first_mut() else {
                break;
            };
            let take = remaining.min(first.bytes.len());
            if take == first.bytes.len() {
                let first = self.segments.remove(0);
                remaining -= take;
                trimmed = trimmed.saturating_add(take);
                self.stored_bytes = self.stored_bytes.saturating_sub(take);
                drop(first);
            } else {
                first.logical_start = first.logical_start.saturating_add(take as u64);
                if let Some(sequence_start) = first.sequence_start.as_mut() {
                    *sequence_start = sequence_start.wrapping_add(take as u32);
                }
                first.bytes = first.bytes[take..].to_vec();
                remaining = 0;
                trimmed = trimmed.saturating_add(take);
                self.stored_bytes = self.stored_bytes.saturating_sub(take);
            }
        }

        trimmed
    }

    fn bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.stored_bytes);
        for segment in &self.segments {
            bytes.extend_from_slice(&segment.bytes);
        }
        bytes
    }

    fn ranges(&self, stream_id: u64, direction: FlowDirection) -> Vec<StreamContentRange> {
        self.segments
            .iter()
            .map(|segment| StreamContentRange {
                stream_id,
                direction,
                logical_start: segment.logical_start,
                logical_end: segment.logical_end(),
                sequence_start: segment.sequence_start,
                sequence_end: segment.sequence_end(),
                stored_bytes: segment.bytes.len(),
            })
            .collect()
    }
}

impl ContentSegment {
    fn logical_end(&self) -> u64 {
        self.logical_start.saturating_add(self.bytes.len() as u64)
    }

    fn sequence_end(&self) -> Option<u32> {
        self.sequence_start
            .map(|sequence| sequence.wrapping_add(self.bytes.len() as u32))
    }
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

fn flow_has_content(packet: &DecodedPacket<'_>, flow: &FlowObservation<'_>) -> bool {
    if let Some(tcp) = flow.tcp.as_ref() {
        return !tcp.stream_chunks.is_empty();
    }

    packet
        .transport_payload()
        .is_some_and(|transport| !transport.bytes.is_empty())
}

#[cfg(test)]
mod tests {
    use etherparse::PacketBuilder;
    use pcap::Linktype;

    use crate::{
        flow::{FlowDirection, FlowTable, FlowTableConfig},
        packet::{DecodedPacket, LinkLayer, PacketTimestamp, RawPacket},
    };

    use super::*;

    #[test]
    fn stores_and_merges_adjacent_tcp_chunks() {
        let mut content = StreamContent::new(config());
        let mut flow_table = flow_table();
        let first = tcp_packet(1, 1111, 80, b"GET ");
        let second = tcp_packet(5, 1111, 80, b"/flag");

        let key = feed(&mut content, &mut flow_table, &first).key;
        feed(&mut content, &mut flow_table, &second);

        assert_eq!(
            b"GET /flag".to_vec(),
            content.direction_bytes(&key, FlowDirection::AToB).unwrap()
        );
        assert_eq!(
            vec![StreamContentRange {
                stream_id: key.stable_id(),
                direction: FlowDirection::AToB,
                logical_start: 0,
                logical_end: 9,
                sequence_start: Some(1),
                sequence_end: Some(10),
                stored_bytes: 9,
            }],
            content.direction_ranges(&key, FlowDirection::AToB).unwrap()
        );
        assert_eq!(9, content.stats().stored_content_bytes);
        assert_eq!(1, content.stats().active_content_segments);
        assert_eq!(1, content.stats().merged_content_segments);
    }

    #[test]
    fn keeps_directions_separate() {
        let mut content = StreamContent::new(config());
        let mut flow_table = flow_table();
        let forward = tcp_packet(1, 1111, 80, b"request");
        let reverse = tcp_packet_from_to([10, 0, 0, 2], 80, [10, 0, 0, 1], 1111, 1, b"response");

        let key = feed(&mut content, &mut flow_table, &forward).key;
        feed(&mut content, &mut flow_table, &reverse);

        assert_eq!(
            b"request".to_vec(),
            content.direction_bytes(&key, FlowDirection::AToB).unwrap()
        );
        assert_eq!(
            b"response".to_vec(),
            content.direction_bytes(&key, FlowDirection::BToA).unwrap()
        );
    }

    #[test]
    fn trims_oldest_bytes_when_stream_cap_is_hit() {
        let mut content = StreamContent::new(StreamContentConfig {
            max_bytes_per_stream: 5,
            ..config()
        });
        let mut flow_table = flow_table();

        let key = feed(
            &mut content,
            &mut flow_table,
            &tcp_packet(1, 1111, 80, b"abc"),
        )
        .key;
        feed(
            &mut content,
            &mut flow_table,
            &tcp_packet(4, 1111, 80, b"defg"),
        );

        assert_eq!(
            b"cdefg".to_vec(),
            content.direction_bytes(&key, FlowDirection::AToB).unwrap()
        );
        assert_eq!(5, content.stats().stored_content_bytes);
        assert_eq!(2, content.stats().dropped_content_bytes);
        assert_eq!(1, content.stats().truncated_content_streams);
    }

    #[test]
    fn evicts_oldest_stream_when_global_cap_is_hit() {
        let mut content = StreamContent::new(StreamContentConfig {
            max_total_bytes: 5,
            max_bytes_per_stream: 5,
            ..config()
        });
        let mut flow_table = flow_table();

        let first = feed(
            &mut content,
            &mut flow_table,
            &tcp_packet(1, 1111, 80, b"aaa"),
        )
        .key;
        let second = feed(
            &mut content,
            &mut flow_table,
            &tcp_packet(1, 2222, 80, b"bbb"),
        )
        .key;

        assert!(
            content
                .direction_bytes(&first, FlowDirection::AToB)
                .is_none()
        );
        assert_eq!(
            b"bbb".to_vec(),
            content
                .direction_bytes(&second, FlowDirection::AToB)
                .unwrap()
        );
        assert_eq!(1, content.stats().active_content_streams);
        assert_eq!(1, content.stats().evicted_content_streams);
    }

    #[test]
    fn disabled_content_is_noop() {
        let mut content = StreamContent::new(StreamContentConfig::disabled());
        let mut flow_table = flow_table();

        let update = feed(
            &mut content,
            &mut flow_table,
            &tcp_packet(1, 1111, 80, b"abc"),
        );

        assert!(update.ranges.is_empty());
        assert_eq!(StreamContentStats::default(), content.stats());
    }

    fn config() -> StreamContentConfig {
        StreamContentConfig {
            enabled: true,
            max_streams: 1024,
            idle_timeout_ms: 120_000,
            max_total_bytes: 1024,
            max_bytes_per_stream: 1024,
            max_segment_bytes: 1024,
        }
    }

    fn flow_table() -> FlowTable {
        FlowTable::new(FlowTableConfig::new(1024, 120_000, 64 * 1024, 16))
    }

    fn feed(
        content: &mut StreamContent,
        flow_table: &mut FlowTable,
        raw: &RawPacket,
    ) -> StreamContentUpdate {
        let packet = DecodedPacket::from_raw(raw);
        let flow = flow_table.observe(&packet).unwrap();
        content
            .observe_flow(&packet, &flow)
            .unwrap_or_else(|| StreamContentUpdate {
                stream_id: flow.key.stable_id(),
                key: flow.key,
                ranges: Vec::new(),
                observed_bytes: 0,
                stored_bytes_after: 0,
            })
    }

    fn tcp_packet(
        sequence: u32,
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) -> RawPacket {
        tcp_packet_from_to(
            [10, 0, 0, 1],
            source_port,
            [10, 0, 0, 2],
            destination_port,
            sequence,
            payload,
        )
    }

    fn tcp_packet_from_to(
        source: [u8; 4],
        source_port: u16,
        destination: [u8; 4],
        destination_port: u16,
        sequence: u32,
        payload: &[u8],
    ) -> RawPacket {
        let builder = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
            .ipv4(source, destination, 20)
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
