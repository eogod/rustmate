use std::{collections::VecDeque, net::IpAddr};

use ahash::AHashMap;
use serde::Serialize;
use smallvec::SmallVec;

use crate::packet::{DecodedPacket, PacketTimestamp, TcpSegment, TransportProtocol};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub addr: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub protocol: TransportProtocol,
    pub a: Endpoint,
    pub b: Endpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowRoute {
    pub key: FlowKey,
    pub direction: FlowDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowDirection {
    AToB,
    BToA,
}

impl FlowDirection {
    fn index(self) -> usize {
        match self {
            Self::AToB => 0,
            Self::BToA => 1,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowObservation<'a> {
    pub key: FlowKey,
    pub direction: FlowDirection,
    pub packets: u64,
    pub bytes: u64,
    pub is_new: bool,
    pub tcp: Option<TcpObservation<'a>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpSequenceStatus {
    NoSequence,
    Init,
    InOrder,
    OutOfOrderBuffered,
    OutOfOrderDropped,
    GapFilled,
    Retransmission,
    Overlap,
    Reset,
    Fin,
}

#[derive(Debug, Clone)]
pub struct TcpObservation<'a> {
    pub sequence_number: u32,
    pub next_sequence: u32,
    pub acknowledgment_number: u32,
    pub payload_len: usize,
    pub status: TcpSequenceStatus,
    pub buffered_segments: usize,
    pub buffered_bytes: usize,
    pub stream_chunks: SmallVec<[StreamChunk<'a>; 2]>,
}

#[derive(Debug, Clone)]
pub struct StreamChunk<'a> {
    pub direction: FlowDirection,
    pub sequence_start: u32,
    pub sequence_end: u32,
    pub bytes: StreamBytes<'a>,
    pub source: StreamChunkSource,
}

impl StreamChunk<'_> {
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

#[derive(Debug, Clone)]
pub enum StreamBytes<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl StreamBytes<'_> {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes,
        }
    }

    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamChunkSource {
    CurrentSegment,
    BufferedSegment,
    OverlapTrimmed,
}

#[derive(Debug, Clone)]
pub struct FlowEntry {
    pub first_seen_us: u64,
    pub last_seen_us: u64,
    pub packets: u64,
    pub bytes: u64,
    pub directions: [FlowDirectionStats; 2],
    transport: TransportFlowState,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FlowDirectionStats {
    pub packets: u64,
    pub bytes: u64,
    pub payload_bytes: u64,
}

#[derive(Debug, Clone)]
enum TransportFlowState {
    Tcp(Box<TcpFlowState>),
    Datagram,
}

#[derive(Debug, Default, Clone)]
pub struct TcpFlowState {
    directions: [TcpDirectionState; 2],
    pub resets: u64,
    pub finished: bool,
}

#[derive(Debug, Default, Clone)]
pub struct TcpDirectionState {
    pub initial_seq: Option<u32>,
    pub next_seq: Option<u32>,
    pub highest_seq: Option<u32>,
    pub packets: u64,
    pub payload_bytes: u64,
    pub gaps: u64,
    pub retransmissions: u64,
    pub overlaps: u64,
    pub out_of_order_buffered: u64,
    pub out_of_order_dropped: u64,
    pub buffered_bytes: usize,
    pub fin_seen: bool,
    pub rst_seen: bool,
    pub syn_seen: bool,
    buffered: VecDeque<BufferedSegment>,
}

#[derive(Debug, Clone)]
struct BufferedSegment {
    start: u32,
    end: u32,
    payload_start: u32,
    bytes: Vec<u8>,
}

struct FlowPacket<'a> {
    direction: FlowDirection,
    now_us: u64,
    bytes: u64,
    payload_bytes: u64,
    tcp_segment: Option<TcpSegment>,
    payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BufferOutcome {
    Buffered,
    Duplicate,
    Dropped,
}

#[derive(Debug, Clone, Copy)]
pub struct FlowTableConfig {
    pub max_flows: usize,
    pub idle_timeout_us: u64,
    pub eviction_interval_packets: u64,
    pub max_tcp_buffered_bytes_per_flow: usize,
    pub max_tcp_out_of_order_segments_per_direction: usize,
}

impl FlowTableConfig {
    pub fn new(
        max_flows: usize,
        idle_timeout_ms: u64,
        max_tcp_buffered_bytes_per_flow: usize,
        max_tcp_out_of_order_segments_per_direction: usize,
    ) -> Self {
        Self {
            max_flows: max_flows.max(1),
            idle_timeout_us: idle_timeout_ms.saturating_mul(1_000),
            eviction_interval_packets: 16_384,
            max_tcp_buffered_bytes_per_flow,
            max_tcp_out_of_order_segments_per_direction,
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FlowTableStats {
    pub active_flows: usize,
    pub created_flows: u64,
    pub evicted_flows: u64,
    pub dropped_new_flows: u64,
    pub tcp_stream_chunks: u64,
    pub tcp_stream_bytes: u64,
    pub tcp_gaps: u64,
    pub tcp_retransmissions: u64,
    pub tcp_overlaps: u64,
    pub tcp_out_of_order_buffered: u64,
    pub tcp_out_of_order_dropped: u64,
    pub tcp_resets: u64,
}

pub struct FlowTable {
    config: FlowTableConfig,
    entries: AHashMap<FlowKey, FlowEntry>,
    observed_packets: u64,
    stats: FlowTableStats,
}

impl FlowTable {
    pub fn new(config: FlowTableConfig) -> Self {
        Self {
            config,
            entries: AHashMap::with_capacity(config.max_flows.min(65_536)),
            observed_packets: 0,
            stats: FlowTableStats::default(),
        }
    }

    pub fn observe<'a>(&mut self, packet: &DecodedPacket<'a>) -> Option<FlowObservation<'a>> {
        let route = FlowRoute::from_packet(packet)?;
        self.observe_with_route(packet, route)
    }

    pub fn observe_with_route<'a>(
        &mut self,
        packet: &DecodedPacket<'a>,
        route: FlowRoute,
    ) -> Option<FlowObservation<'a>> {
        self.observed_packets = self.observed_packets.saturating_add(1);

        let now_us = timestamp_us(packet.timestamp);
        if self.should_evict() {
            self.evict_idle(now_us);
        }

        let transport = packet.transport_payload()?;
        let bytes = packet.raw.len() as u64;
        let payload_bytes = transport.bytes.len() as u64;
        let key = route.key;
        let direction = route.direction;

        if self.entries.contains_key(&key) {
            let entry = self.entries.get_mut(&key).expect("entry exists");
            let tcp = entry.observe(
                FlowPacket {
                    direction,
                    now_us,
                    bytes,
                    payload_bytes,
                    tcp_segment: transport.tcp,
                    payload: transport.bytes,
                },
                &self.config,
                &mut self.stats,
            );
            return Some(FlowObservation {
                key,
                direction,
                packets: entry.packets,
                bytes: entry.bytes,
                is_new: false,
                tcp,
            });
        }

        if self.entries.len() >= self.config.max_flows {
            self.evict_idle(now_us);
            if self.entries.len() >= self.config.max_flows {
                self.evict_oldest();
            }
        }

        if self.entries.len() >= self.config.max_flows {
            self.stats.dropped_new_flows = self.stats.dropped_new_flows.saturating_add(1);
            return None;
        }

        let mut entry = FlowEntry::new(now_us, key.protocol);
        let tcp = entry.observe(
            FlowPacket {
                direction,
                now_us,
                bytes,
                payload_bytes,
                tcp_segment: transport.tcp,
                payload: transport.bytes,
            },
            &self.config,
            &mut self.stats,
        );
        let packets = entry.packets;
        let bytes = entry.bytes;
        self.entries.insert(key, entry);
        self.stats.created_flows = self.stats.created_flows.saturating_add(1);

        Some(FlowObservation {
            key,
            direction,
            packets,
            bytes,
            is_new: true,
            tcp,
        })
    }

    pub fn get(&self, key: &FlowKey) -> Option<&FlowEntry> {
        self.entries.get(key)
    }

    pub fn stats(&self) -> FlowTableStats {
        FlowTableStats {
            active_flows: self.entries.len(),
            ..self.stats
        }
    }

    fn should_evict(&self) -> bool {
        self.observed_packets != 0
            && self
                .observed_packets
                .is_multiple_of(self.config.eviction_interval_packets)
    }

    fn evict_idle(&mut self, now_us: u64) {
        let before = self.entries.len();
        let timeout_us = self.config.idle_timeout_us;
        self.entries
            .retain(|_, entry| now_us.saturating_sub(entry.last_seen_us) <= timeout_us);
        self.stats.evicted_flows = self
            .stats
            .evicted_flows
            .saturating_add((before - self.entries.len()) as u64);
    }

    fn evict_oldest(&mut self) {
        let Some(key) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_seen_us)
            .map(|(key, _)| *key)
        else {
            return;
        };
        self.entries.remove(&key);
        self.stats.evicted_flows = self.stats.evicted_flows.saturating_add(1);
    }
}

impl FlowEntry {
    fn new(now_us: u64, protocol: TransportProtocol) -> Self {
        Self {
            first_seen_us: now_us,
            last_seen_us: now_us,
            packets: 0,
            bytes: 0,
            directions: [FlowDirectionStats::default(); 2],
            transport: match protocol {
                TransportProtocol::Tcp => TransportFlowState::Tcp(Box::<TcpFlowState>::default()),
                _ => TransportFlowState::Datagram,
            },
        }
    }

    fn observe<'a>(
        &mut self,
        packet: FlowPacket<'a>,
        config: &FlowTableConfig,
        stats: &mut FlowTableStats,
    ) -> Option<TcpObservation<'a>> {
        self.last_seen_us = packet.now_us;
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(packet.bytes);

        let direction_stats = &mut self.directions[packet.direction.index()];
        direction_stats.packets = direction_stats.packets.saturating_add(1);
        direction_stats.bytes = direction_stats.bytes.saturating_add(packet.bytes);
        direction_stats.payload_bytes = direction_stats
            .payload_bytes
            .saturating_add(packet.payload_bytes);

        let TransportFlowState::Tcp(tcp) = &mut self.transport else {
            return None;
        };

        Some(tcp.observe(
            packet.direction,
            packet.tcp_segment?,
            packet.payload,
            config,
            stats,
        ))
    }
}

impl TcpFlowState {
    fn observe<'a>(
        &mut self,
        direction: FlowDirection,
        segment: TcpSegment,
        payload: &'a [u8],
        config: &FlowTableConfig,
        stats: &mut FlowTableStats,
    ) -> TcpObservation<'a> {
        let state = &mut self.directions[direction.index()];
        let observation = state.observe(direction, segment, payload, config, stats);
        stats.tcp_stream_chunks = stats
            .tcp_stream_chunks
            .saturating_add(observation.stream_chunks.len() as u64);
        stats.tcp_stream_bytes = stats
            .tcp_stream_bytes
            .saturating_add(stream_chunk_bytes(&observation.stream_chunks));

        if segment.flags.rst {
            self.resets = self.resets.saturating_add(1);
            self.finished = true;
            stats.tcp_resets = stats.tcp_resets.saturating_add(1);
        } else if self.directions.iter().all(|direction| direction.fin_seen) {
            self.finished = true;
        }

        observation
    }
}

impl TcpDirectionState {
    fn observe<'a>(
        &mut self,
        direction: FlowDirection,
        segment: TcpSegment,
        payload: &'a [u8],
        config: &FlowTableConfig,
        stats: &mut FlowTableStats,
    ) -> TcpObservation<'a> {
        let mut stream_chunks = SmallVec::new();
        self.packets = self.packets.saturating_add(1);
        self.payload_bytes = self
            .payload_bytes
            .saturating_add(segment.payload_len as u64);
        self.syn_seen |= segment.flags.syn;
        self.fin_seen |= segment.flags.fin;
        self.rst_seen |= segment.flags.rst;

        if segment.flags.rst {
            return self.observation(segment, TcpSequenceStatus::Reset, stream_chunks);
        }

        let start = segment.sequence_number;
        let span = segment.sequence_span();
        if span == 0 {
            return self.observation(segment, TcpSequenceStatus::NoSequence, stream_chunks);
        }

        let end = start.wrapping_add(span);
        self.highest_seq = Some(self.highest_seq.map_or(end, |highest| {
            if seq_after(end, highest) {
                end
            } else {
                highest
            }
        }));

        let Some(expected) = self.next_seq else {
            self.initial_seq = Some(start);
            self.next_seq = Some(end);
            push_current_stream_chunk(
                &mut stream_chunks,
                direction,
                segment,
                payload,
                StreamChunkSource::CurrentSegment,
            );
            self.consume_contiguous_buffer(direction, &mut stream_chunks);
            return self.observation(segment, TcpSequenceStatus::Init, stream_chunks);
        };

        let status = if seq_eq(start, expected) {
            push_current_stream_chunk(
                &mut stream_chunks,
                direction,
                segment,
                payload,
                StreamChunkSource::CurrentSegment,
            );
            self.next_seq = Some(end);
            if self.consume_contiguous_buffer(direction, &mut stream_chunks) {
                TcpSequenceStatus::GapFilled
            } else if segment.flags.fin {
                TcpSequenceStatus::Fin
            } else {
                TcpSequenceStatus::InOrder
            }
        } else if seq_before(start, expected) {
            if seq_after(end, expected) {
                self.overlaps = self.overlaps.saturating_add(1);
                stats.tcp_overlaps = stats.tcp_overlaps.saturating_add(1);
                push_trimmed_current_stream_chunk(
                    &mut stream_chunks,
                    direction,
                    segment,
                    payload,
                    expected,
                );
                self.next_seq = Some(end);
                self.consume_contiguous_buffer(direction, &mut stream_chunks);
                TcpSequenceStatus::Overlap
            } else {
                self.retransmissions = self.retransmissions.saturating_add(1);
                stats.tcp_retransmissions = stats.tcp_retransmissions.saturating_add(1);
                TcpSequenceStatus::Retransmission
            }
        } else {
            match self.buffer_out_of_order(segment, payload, config) {
                BufferOutcome::Buffered => {
                    self.gaps = self.gaps.saturating_add(1);
                    self.out_of_order_buffered = self.out_of_order_buffered.saturating_add(1);
                    stats.tcp_gaps = stats.tcp_gaps.saturating_add(1);
                    stats.tcp_out_of_order_buffered =
                        stats.tcp_out_of_order_buffered.saturating_add(1);
                    TcpSequenceStatus::OutOfOrderBuffered
                }
                BufferOutcome::Duplicate => {
                    self.retransmissions = self.retransmissions.saturating_add(1);
                    stats.tcp_retransmissions = stats.tcp_retransmissions.saturating_add(1);
                    TcpSequenceStatus::Retransmission
                }
                BufferOutcome::Dropped => {
                    self.gaps = self.gaps.saturating_add(1);
                    self.out_of_order_dropped = self.out_of_order_dropped.saturating_add(1);
                    stats.tcp_gaps = stats.tcp_gaps.saturating_add(1);
                    stats.tcp_out_of_order_dropped =
                        stats.tcp_out_of_order_dropped.saturating_add(1);
                    TcpSequenceStatus::OutOfOrderDropped
                }
            }
        };

        self.observation(segment, status, stream_chunks)
    }

    fn buffer_out_of_order(
        &mut self,
        segment: TcpSegment,
        payload: &[u8],
        config: &FlowTableConfig,
    ) -> BufferOutcome {
        let start = segment.sequence_number;
        let end = start.wrapping_add(segment.sequence_span());
        if self
            .buffered
            .iter()
            .any(|segment| segment.start == start && segment.end == end)
        {
            return BufferOutcome::Duplicate;
        }
        if self.buffered.len() >= config.max_tcp_out_of_order_segments_per_direction {
            return BufferOutcome::Dropped;
        }
        if self.buffered_bytes.saturating_add(payload.len())
            > config.max_tcp_buffered_bytes_per_flow
        {
            return BufferOutcome::Dropped;
        }

        let insert_at = self
            .buffered
            .iter()
            .position(|segment| seq_before(start, segment.start))
            .unwrap_or(self.buffered.len());
        self.buffered.insert(
            insert_at,
            BufferedSegment {
                start,
                end,
                payload_start: segment.payload_sequence_start(),
                bytes: payload.to_vec(),
            },
        );
        self.buffered_bytes = self.buffered_bytes.saturating_add(payload.len());
        BufferOutcome::Buffered
    }

    fn consume_contiguous_buffer<'a>(
        &mut self,
        direction: FlowDirection,
        stream_chunks: &mut SmallVec<[StreamChunk<'a>; 2]>,
    ) -> bool {
        let mut advanced = false;

        loop {
            let Some(expected) = self.next_seq else {
                return advanced;
            };
            let Some(index) = self.buffered.iter().position(|segment| {
                seq_eq(segment.start, expected)
                    || (seq_before(segment.start, expected) && seq_after(segment.end, expected))
            }) else {
                return advanced;
            };
            let Some(segment) = self.buffered.remove(index) else {
                return advanced;
            };

            let segment_end = segment.end;
            self.buffered_bytes = self.buffered_bytes.saturating_sub(segment.bytes.len());
            if let Some(chunk) = segment.into_stream_chunk(expected, direction) {
                stream_chunks.push(chunk);
            }
            if seq_after(segment_end, expected) {
                self.next_seq = Some(segment_end);
                advanced = true;
            }
        }
    }

    fn observation<'a>(
        &self,
        segment: TcpSegment,
        status: TcpSequenceStatus,
        stream_chunks: SmallVec<[StreamChunk<'a>; 2]>,
    ) -> TcpObservation<'a> {
        TcpObservation {
            sequence_number: segment.sequence_number,
            next_sequence: self.next_seq.unwrap_or(segment.sequence_number),
            acknowledgment_number: segment.acknowledgment_number,
            payload_len: segment.payload_len,
            status,
            buffered_segments: self.buffered.len(),
            buffered_bytes: self.buffered_bytes,
            stream_chunks,
        }
    }
}

impl BufferedSegment {
    fn into_stream_chunk<'a>(
        self,
        expected: u32,
        direction: FlowDirection,
    ) -> Option<StreamChunk<'a>> {
        if self.bytes.is_empty() {
            return None;
        }

        let payload_end = self.payload_start.wrapping_add(self.bytes.len() as u32);
        if seq_before(payload_end, expected) || seq_eq(payload_end, expected) {
            return None;
        }

        let (sequence_start, bytes) = if seq_before(self.payload_start, expected) {
            let offset = expected.wrapping_sub(self.payload_start) as usize;
            let mut bytes = self.bytes;
            bytes.drain(..offset.min(bytes.len()));
            (expected, bytes)
        } else {
            (self.payload_start, self.bytes)
        };

        if bytes.is_empty() {
            return None;
        }

        Some(StreamChunk {
            direction,
            sequence_start,
            sequence_end: sequence_start.wrapping_add(bytes.len() as u32),
            bytes: StreamBytes::Owned(bytes),
            source: StreamChunkSource::BufferedSegment,
        })
    }
}

fn push_current_stream_chunk<'a>(
    chunks: &mut SmallVec<[StreamChunk<'a>; 2]>,
    direction: FlowDirection,
    segment: TcpSegment,
    payload: &'a [u8],
    source: StreamChunkSource,
) {
    if payload.is_empty() {
        return;
    }

    let sequence_start = segment.payload_sequence_start();
    chunks.push(StreamChunk {
        direction,
        sequence_start,
        sequence_end: sequence_start.wrapping_add(payload.len() as u32),
        bytes: StreamBytes::Borrowed(payload),
        source,
    });
}

fn push_trimmed_current_stream_chunk<'a>(
    chunks: &mut SmallVec<[StreamChunk<'a>; 2]>,
    direction: FlowDirection,
    segment: TcpSegment,
    payload: &'a [u8],
    expected: u32,
) {
    if payload.is_empty() {
        return;
    }

    let payload_start = segment.payload_sequence_start();
    let payload_end = segment.payload_sequence_end();
    if seq_before(payload_end, expected) || seq_eq(payload_end, expected) {
        return;
    }

    let (sequence_start, bytes) = if seq_before(payload_start, expected) {
        let offset = expected.wrapping_sub(payload_start) as usize;
        (expected, &payload[offset.min(payload.len())..])
    } else {
        (payload_start, payload)
    };

    if bytes.is_empty() {
        return;
    }

    chunks.push(StreamChunk {
        direction,
        sequence_start,
        sequence_end: sequence_start.wrapping_add(bytes.len() as u32),
        bytes: StreamBytes::Borrowed(bytes),
        source: StreamChunkSource::OverlapTrimmed,
    });
}

fn stream_chunk_bytes(chunks: &[StreamChunk<'_>]) -> u64 {
    chunks.iter().map(|chunk| chunk.len() as u64).sum()
}

impl FlowKey {
    pub fn from_packet(packet: &DecodedPacket<'_>) -> Option<(Self, FlowDirection)> {
        FlowRoute::from_packet(packet).map(|route| (route.key, route.direction))
    }

    pub fn stable_id(&self) -> u64 {
        let mut hash = Fnv64::new();
        hash.write_u8(match self.protocol {
            TransportProtocol::Tcp => 1,
            TransportProtocol::Udp => 2,
            TransportProtocol::Icmpv4 => 3,
            TransportProtocol::Icmpv6 => 4,
        });
        hash.write_endpoint(self.a);
        hash.write_endpoint(self.b);
        hash.finish()
    }
}

impl FlowRoute {
    pub fn new(protocol: TransportProtocol, source: Endpoint, destination: Endpoint) -> Self {
        if endpoint_sort_key(source) <= endpoint_sort_key(destination) {
            Self {
                key: FlowKey {
                    protocol,
                    a: source,
                    b: destination,
                },
                direction: FlowDirection::AToB,
            }
        } else {
            Self {
                key: FlowKey {
                    protocol,
                    a: destination,
                    b: source,
                },
                direction: FlowDirection::BToA,
            }
        }
    }

    pub fn from_packet(packet: &DecodedPacket<'_>) -> Option<Self> {
        let transport = packet.transport_payload()?;
        let source_port = transport.source_port?;
        let destination_port = transport.destination_port?;
        let (source_addr, destination_addr) = packet.ip_addresses();
        let source = Endpoint {
            addr: source_addr?,
            port: source_port,
        };
        let destination = Endpoint {
            addr: destination_addr?,
            port: destination_port,
        };

        Some(Self::new(transport.protocol, source, destination))
    }
}

fn endpoint_sort_key(endpoint: Endpoint) -> (u8, [u8; 16], u16) {
    match endpoint.addr {
        IpAddr::V4(addr) => {
            let mut bytes = [0; 16];
            bytes[12..].copy_from_slice(&addr.octets());
            (4, bytes, endpoint.port)
        }
        IpAddr::V6(addr) => (6, addr.octets(), endpoint.port),
    }
}

struct Fnv64(u64);

impl Fnv64 {
    fn new() -> Self {
        Self(0xcbf29ce484222325)
    }

    fn write_u8(&mut self, byte: u8) {
        self.0 ^= byte as u64;
        self.0 = self.0.wrapping_mul(0x100000001b3);
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.write_u8(*byte);
        }
    }

    fn write_u16(&mut self, value: u16) {
        self.write_bytes(&value.to_be_bytes());
    }

    fn write_endpoint(&mut self, endpoint: Endpoint) {
        match endpoint.addr {
            IpAddr::V4(addr) => {
                self.write_u8(4);
                self.write_bytes(&addr.octets());
            }
            IpAddr::V6(addr) => {
                self.write_u8(6);
                self.write_bytes(&addr.octets());
            }
        }
        self.write_u16(endpoint.port);
    }

    fn finish(self) -> u64 {
        self.0
    }
}

fn timestamp_us(ts: PacketTimestamp) -> u64 {
    ts.sec.saturating_mul(1_000_000) + u64::from(ts.usec)
}

fn seq_eq(a: u32, b: u32) -> bool {
    a == b
}

fn seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn seq_after(a: u32, b: u32) -> bool {
    seq_before(b, a)
}

#[cfg(test)]
mod tests {
    use etherparse::PacketBuilder;
    use pcap::Linktype;

    use crate::packet::{LinkLayer, RawPacket};

    use super::*;

    #[test]
    fn normalizes_reverse_flow_to_same_key() {
        let forward_raw = tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 1, b"x", 1);
        let reverse_raw = tcp_packet([10, 0, 0, 2], 80, [10, 0, 0, 1], 1111, 1, b"x", 1);
        let forward = DecodedPacket::from_raw(&forward_raw);
        let reverse = DecodedPacket::from_raw(&reverse_raw);

        let (forward_key, forward_direction) = FlowKey::from_packet(&forward).unwrap();
        let (reverse_key, reverse_direction) = FlowKey::from_packet(&reverse).unwrap();

        assert_eq!(forward_key, reverse_key);
        assert_eq!(FlowDirection::AToB, forward_direction);
        assert_eq!(FlowDirection::BToA, reverse_direction);
    }

    #[test]
    fn tracks_in_order_tcp_sequence_progress() {
        let mut table = table();
        let first_raw = tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 100, b"abc", 1);
        let second_raw = tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 103, b"de", 2);
        let first = observe(&mut table, &first_raw);
        let second = observe(&mut table, &second_raw);

        assert!(first.is_new);
        let first_tcp = first.tcp.unwrap();
        let second_tcp = second.tcp.unwrap();
        assert_eq!(TcpSequenceStatus::Init, first_tcp.status);
        assert_eq!(TcpSequenceStatus::InOrder, second_tcp.status);
        assert_eq!(105, second_tcp.next_sequence);
        assert_stream(
            &first_tcp.stream_chunks[0],
            b"abc",
            100,
            StreamChunkSource::CurrentSegment,
        );
        assert_stream(
            &second_tcp.stream_chunks[0],
            b"de",
            103,
            StreamChunkSource::CurrentSegment,
        );
        assert_eq!(1, table.stats().active_flows);
        assert_eq!(2, table.stats().tcp_stream_chunks);
        assert_eq!(5, table.stats().tcp_stream_bytes);
    }

    #[test]
    fn buffers_out_of_order_and_fills_gap() {
        let mut table = table();
        let first_raw = tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 100, b"abc", 1);
        let out_of_order_raw = tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 106, b"gh", 2);
        let gap_fill_raw = tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 103, b"def", 3);
        let _ = observe(&mut table, &first_raw);
        let out_of_order = observe(&mut table, &out_of_order_raw);
        let gap_fill = observe(&mut table, &gap_fill_raw);

        let out_of_order_tcp = out_of_order.tcp.unwrap();
        let gap_fill_tcp = gap_fill.tcp.unwrap();
        assert_eq!(
            TcpSequenceStatus::OutOfOrderBuffered,
            out_of_order_tcp.status
        );
        assert_eq!(1, out_of_order_tcp.buffered_segments);
        assert!(out_of_order_tcp.stream_chunks.is_empty());
        assert_eq!(TcpSequenceStatus::GapFilled, gap_fill_tcp.status);
        assert_eq!(108, gap_fill_tcp.next_sequence);
        assert_eq!(0, gap_fill_tcp.buffered_segments);
        assert_eq!(2, gap_fill_tcp.stream_chunks.len());
        assert_stream(
            &gap_fill_tcp.stream_chunks[0],
            b"def",
            103,
            StreamChunkSource::CurrentSegment,
        );
        assert_stream(
            &gap_fill_tcp.stream_chunks[1],
            b"gh",
            106,
            StreamChunkSource::BufferedSegment,
        );
        assert_eq!(1, table.stats().tcp_gaps);
    }

    #[test]
    fn detects_retransmissions_and_overlaps() {
        let mut table = table();
        let first_raw = tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 100, b"abcdef", 1);
        let retransmission_raw = tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 100, b"abc", 2);
        let overlap_raw = tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 104, b"efgh", 3);
        let _ = observe(&mut table, &first_raw);
        let retransmission = observe(&mut table, &retransmission_raw);
        let overlap = observe(&mut table, &overlap_raw);

        let retransmission_tcp = retransmission.tcp.unwrap();
        let overlap_tcp = overlap.tcp.unwrap();
        assert_eq!(TcpSequenceStatus::Retransmission, retransmission_tcp.status);
        assert!(retransmission_tcp.stream_chunks.is_empty());
        assert_eq!(TcpSequenceStatus::Overlap, overlap_tcp.status);
        assert_stream(
            &overlap_tcp.stream_chunks[0],
            b"gh",
            106,
            StreamChunkSource::OverlapTrimmed,
        );
        assert_eq!(1, table.stats().tcp_retransmissions);
        assert_eq!(1, table.stats().tcp_overlaps);
    }

    #[test]
    fn enforces_out_of_order_buffer_limits() {
        let mut table = FlowTable::new(FlowTableConfig::new(16, 120_000, 2, 1));
        let first_raw = tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 100, b"a", 1);
        let dropped_raw = tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 103, b"bcdef", 2);
        let _ = observe(&mut table, &first_raw);
        let dropped = observe(&mut table, &dropped_raw);

        assert_eq!(
            TcpSequenceStatus::OutOfOrderDropped,
            dropped.tcp.unwrap().status
        );
        assert_eq!(1, table.stats().tcp_out_of_order_dropped);
    }

    #[test]
    fn treats_duplicate_out_of_order_segment_as_retransmission() {
        let mut table = table();
        let first_raw = tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 100, b"a", 1);
        let buffered_raw = tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 103, b"cd", 2);
        let duplicate_raw = tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 103, b"cd", 3);
        let _ = observe(&mut table, &first_raw);
        let _ = observe(&mut table, &buffered_raw);
        let duplicate = observe(&mut table, &duplicate_raw);

        assert_eq!(
            TcpSequenceStatus::Retransmission,
            duplicate.tcp.unwrap().status
        );
        assert_eq!(1, table.stats().tcp_retransmissions);
        assert_eq!(1, table.stats().tcp_out_of_order_buffered);
    }

    #[test]
    fn tcp_syn_consumes_sequence_number() {
        let mut table = table();
        let syn_raw = tcp_packet_with_flags(TestTcpPacket {
            source_addr: [10, 0, 0, 1],
            source_port: 1111,
            destination_addr: [10, 0, 0, 2],
            destination_port: 80,
            sequence: 500,
            payload: b"",
            sec: 1,
            flags: TestTcpFlags {
                syn: true,
                ..TestTcpFlags::default()
            },
        });
        let syn = observe(&mut table, &syn_raw);

        let syn_tcp = syn.tcp.as_ref().unwrap();
        assert_eq!(TcpSequenceStatus::Init, syn_tcp.status);
        assert_eq!(501, syn_tcp.next_sequence);
    }

    #[test]
    fn tcp_rst_updates_reset_stats() {
        let mut table = table();
        let rst_raw = tcp_packet_with_flags(TestTcpPacket {
            source_addr: [10, 0, 0, 1],
            source_port: 1111,
            destination_addr: [10, 0, 0, 2],
            destination_port: 80,
            sequence: 100,
            payload: b"",
            sec: 1,
            flags: TestTcpFlags {
                rst: true,
                ..TestTcpFlags::default()
            },
        });
        let rst = observe(&mut table, &rst_raw);

        assert_eq!(TcpSequenceStatus::Reset, rst.tcp.unwrap().status);
        assert_eq!(1, table.stats().tcp_resets);
    }

    #[test]
    fn evicts_oldest_flow_when_table_is_full() {
        let mut table = FlowTable::new(FlowTableConfig::new(1, 120_000, 4096, 16));
        let first_raw = tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 1, b"a", 1);
        let second_raw = tcp_packet([10, 0, 0, 3], 2222, [10, 0, 0, 4], 80, 1, b"b", 2);
        let first = observe(&mut table, &first_raw);
        let second = observe(&mut table, &second_raw);

        assert!(first.is_new);
        assert!(second.is_new);
        assert_eq!(1, table.stats().active_flows);
        assert_eq!(1, table.stats().evicted_flows);
    }

    fn table() -> FlowTable {
        FlowTable::new(FlowTableConfig::new(1024, 120_000, 64 * 1024, 16))
    }

    fn observe<'a>(table: &mut FlowTable, raw: &'a RawPacket) -> FlowObservation<'a> {
        let packet = DecodedPacket::from_raw(raw);
        table.observe(&packet).unwrap()
    }

    fn assert_stream(
        chunk: &StreamChunk<'_>,
        expected: &[u8],
        sequence_start: u32,
        source: StreamChunkSource,
    ) {
        assert_eq!(expected, chunk.bytes.as_slice());
        assert_eq!(sequence_start, chunk.sequence_start);
        assert_eq!(
            sequence_start.wrapping_add(expected.len() as u32),
            chunk.sequence_end
        );
        assert_eq!(source, chunk.source);
    }

    fn tcp_packet(
        source_addr: [u8; 4],
        source_port: u16,
        destination_addr: [u8; 4],
        destination_port: u16,
        sequence: u32,
        payload: &[u8],
        sec: u64,
    ) -> RawPacket {
        tcp_packet_with_flags(TestTcpPacket {
            source_addr,
            source_port,
            destination_addr,
            destination_port,
            sequence,
            payload,
            sec,
            flags: TestTcpFlags::default(),
        })
    }

    fn tcp_packet_with_flags(input: TestTcpPacket<'_>) -> RawPacket {
        let mut builder = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
            .ipv4(input.source_addr, input.destination_addr, 20)
            .tcp(
                input.source_port,
                input.destination_port,
                input.sequence,
                1024,
            );
        if input.flags.syn {
            builder = builder.syn();
        }
        if input.flags.fin {
            builder = builder.fin();
        }
        if input.flags.rst {
            builder = builder.rst();
        }
        if input.flags.ack {
            builder = builder.ack(input.sequence);
        }

        let mut data = Vec::with_capacity(builder.size(input.payload.len()));
        builder.write(&mut data, input.payload).unwrap();
        RawPacket {
            timestamp: PacketTimestamp {
                sec: input.sec,
                usec: 0,
            },
            link_layer: LinkLayer::Ethernet,
            linktype: Linktype::ETHERNET.0,
            data,
        }
    }

    struct TestTcpPacket<'a> {
        source_addr: [u8; 4],
        source_port: u16,
        destination_addr: [u8; 4],
        destination_port: u16,
        sequence: u32,
        payload: &'a [u8],
        sec: u64,
        flags: TestTcpFlags,
    }

    #[derive(Default, Clone, Copy)]
    struct TestTcpFlags {
        syn: bool,
        fin: bool,
        rst: bool,
        ack: bool,
    }
}
