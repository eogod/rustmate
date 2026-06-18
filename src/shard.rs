use std::{
    collections::VecDeque,
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use ahash::{AHashMap, RandomState};

use crate::{
    config::RunMode,
    flow::{Endpoint, FlowKey, FlowRoute},
    health::{ShardedQueueSnapshot, WorkerHotFlowSnapshot, WorkerQueueSnapshot},
    packet::{LinkLayer, RawPacket, TransportProtocol},
};

const ROUTE_HASHER: RandomState = RandomState::with_seeds(
    0x9e37_79b9_7f4a_7c15,
    0xbf58_476d_1ce4_e5b9,
    0x94d0_49bb_1331_11eb,
    0x2545_f491_4f6c_dd1d,
);
const DEFAULT_MAX_TRACKED_ROUTE_FLOWS: usize = 1_048_576;
const DEFAULT_MAX_FLOW_OWNERS: usize = 1_048_576;
const SECONDARY_ROUTE_HASH_SALT: u64 = 0x517c_c1b7_2722_0a95;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardCoordinatorConfig {
    pub shard_count: usize,
    pub mode: RunMode,
    pub routing_policy: RoutingPolicy,
    pub max_flow_owners: usize,
}

impl ShardCoordinatorConfig {
    pub fn new(shard_count: usize, mode: RunMode) -> Self {
        Self {
            shard_count,
            mode,
            routing_policy: RoutingPolicy::default(),
            max_flow_owners: DEFAULT_MAX_FLOW_OWNERS,
        }
    }

    pub fn with_max_flow_owners(mut self, max_flow_owners: usize) -> Self {
        self.max_flow_owners = max_flow_owners.max(1);
        self
    }
}

#[derive(Debug, Clone)]
pub struct ShardCoordinator {
    topology: ShardTopology,
    mode: RunMode,
    routing_policy: RoutingPolicy,
    next_sequence: u64,
    flow_owners: FlowOwnerTable,
    metrics: ShardLoadMetrics,
}

impl ShardCoordinator {
    pub fn new(config: ShardCoordinatorConfig) -> Self {
        let topology = ShardTopology::new(config.shard_count);
        Self {
            topology,
            mode: config.mode,
            routing_policy: config.routing_policy,
            next_sequence: 0,
            flow_owners: FlowOwnerTable::new(config.max_flow_owners),
            metrics: ShardLoadMetrics::new(topology.shard_count()),
        }
    }

    pub fn shard_count(&self) -> usize {
        self.topology.shard_count()
    }

    pub fn topology(&self) -> ShardTopology {
        self.topology
    }

    pub fn routing_policy(&self) -> RoutingPolicy {
        self.routing_policy
    }

    pub fn route_packet(&mut self, raw: &RawPacket) -> ShardRoute {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        let route = self.route_packet_inner(sequence, raw);
        self.metrics.observe_route(route, raw.data.len() as u64);
        route
    }

    pub fn metrics(&self) -> &ShardLoadMetrics {
        &self.metrics
    }

    pub fn flow_owner_count(&self) -> usize {
        self.flow_owners.len()
    }

    pub fn flow_owner_evictions(&self) -> u64 {
        self.flow_owners.evictions()
    }

    fn route_packet_inner(&mut self, sequence: u64, raw: &RawPacket) -> ShardRoute {
        if matches!(self.mode, RunMode::Dump) {
            return ShardRoute {
                shard: 0,
                kind: ShardRouteKind::Dump,
                flow_route: None,
                fallback_reason: None,
            };
        }
        if self.topology.is_single_shard() {
            return ShardRoute {
                shard: 0,
                kind: ShardRouteKind::SingleShard,
                flow_route: None,
                fallback_reason: None,
            };
        }

        match flow_route_from_raw_result(raw) {
            Ok(flow_route) => self.route_flow(flow_route),
            Err(reason) => ShardRoute {
                shard: self
                    .routing_policy
                    .fallback()
                    .route(sequence, &self.topology),
                kind: ShardRouteKind::Fallback,
                flow_route: None,
                fallback_reason: Some(reason),
            },
        }
    }

    fn route_flow(&mut self, flow_route: FlowRoute) -> ShardRoute {
        let shard = self.flow_owners.owner(flow_route.key).unwrap_or_else(|| {
            let shard = self.choose_shard_for_new_flow(flow_route.key);
            self.flow_owners.remember(flow_route.key, shard);
            shard
        });

        ShardRoute {
            shard,
            kind: ShardRouteKind::FlowAffinity,
            flow_route: Some(flow_route),
            fallback_reason: None,
        }
    }

    fn choose_shard_for_new_flow(&self, key: FlowKey) -> usize {
        let primary = self.topology.shard_for_hash(route_hash(key));
        let secondary = self
            .topology
            .shard_for_hash(route_hash((SECONDARY_ROUTE_HASH_SALT, key)));

        if primary == secondary {
            return primary;
        }

        let primary_load = self.placement_load(primary);
        let secondary_load = self.placement_load(secondary);
        if secondary_load < primary_load {
            secondary
        } else {
            primary
        }
    }

    fn placement_load(&self, shard: usize) -> ShardPlacementLoad {
        self.metrics
            .shard(shard)
            .map(ShardPlacementLoad::from)
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone)]
struct FlowOwnerTable {
    owners: AHashMap<FlowKey, usize>,
    order: VecDeque<FlowKey>,
    max_owners: usize,
    evictions: u64,
}

impl FlowOwnerTable {
    fn new(max_owners: usize) -> Self {
        Self {
            owners: AHashMap::new(),
            order: VecDeque::new(),
            max_owners: max_owners.max(1),
            evictions: 0,
        }
    }

    fn len(&self) -> usize {
        self.owners.len()
    }

    fn evictions(&self) -> u64 {
        self.evictions
    }

    fn owner(&self, key: FlowKey) -> Option<usize> {
        self.owners.get(&key).copied()
    }

    fn remember(&mut self, key: FlowKey, shard: usize) {
        if let Some(owner) = self.owners.get_mut(&key) {
            *owner = shard;
            return;
        }

        while self.owners.len() >= self.max_owners {
            let Some(evicted) = self.order.pop_front() else {
                break;
            };
            if self.owners.remove(&evicted).is_some() {
                self.evictions = self.evictions.saturating_add(1);
            }
        }

        if self.owners.len() >= self.max_owners {
            return;
        }

        self.owners.insert(key, shard);
        self.order.push_back(key);
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ShardPlacementLoad {
    bytes: u64,
    packets: u64,
}

impl From<&ShardLoad> for ShardPlacementLoad {
    fn from(load: &ShardLoad) -> Self {
        Self {
            bytes: load.bytes,
            packets: load.packets,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingPolicy {
    FlowAffinity { fallback: FallbackRoutingPolicy },
}

impl Default for RoutingPolicy {
    fn default() -> Self {
        Self::FlowAffinity {
            fallback: FallbackRoutingPolicy::RoundRobin,
        }
    }
}

impl RoutingPolicy {
    fn fallback(self) -> FallbackRoutingPolicy {
        match self {
            Self::FlowAffinity { fallback } => fallback,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackRoutingPolicy {
    RoundRobin,
    FirstShard,
}

impl FallbackRoutingPolicy {
    fn route(self, sequence: u64, topology: &ShardTopology) -> usize {
        match self {
            Self::RoundRobin => topology.shard_for_sequence(sequence),
            Self::FirstShard => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardTopology {
    shard_count: usize,
    shard_mask: Option<usize>,
}

impl ShardTopology {
    pub fn new(shard_count: usize) -> Self {
        let shard_count = shard_count.max(1);
        Self {
            shard_count,
            shard_mask: shard_count
                .is_power_of_two()
                .then_some(shard_count.saturating_sub(1)),
        }
    }

    pub fn shard_count(self) -> usize {
        self.shard_count
    }

    pub fn is_single_shard(self) -> bool {
        self.shard_count <= 1
    }

    pub fn is_power_of_two(self) -> bool {
        self.shard_mask.is_some()
    }

    pub fn shard_for_hash(self, hash: u64) -> usize {
        let hash = hash as usize;
        if let Some(mask) = self.shard_mask {
            hash & mask
        } else {
            hash % self.shard_count
        }
    }

    pub fn shard_for_sequence(self, sequence: u64) -> usize {
        if let Some(mask) = self.shard_mask {
            sequence as usize & mask
        } else {
            sequence as usize % self.shard_count
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardRoute {
    pub shard: usize,
    pub kind: ShardRouteKind,
    pub flow_route: Option<FlowRoute>,
    pub fallback_reason: Option<FallbackRouteReason>,
}

impl ShardRoute {
    pub fn is_fallback(self) -> bool {
        matches!(self.kind, ShardRouteKind::Fallback)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShardRouteKind {
    FlowAffinity,
    Fallback,
    SingleShard,
    Dump,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackRouteReason {
    UnsupportedLink,
    NonIp,
    Malformed,
    Fragmented,
    UnsupportedTransport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardLoadMetrics {
    shards: Vec<ShardLoad>,
    flow_loads: AHashMap<FlowKey, FlowRouteLoad>,
    flow_order: VecDeque<FlowKey>,
    max_tracked_flows: usize,
    total_packets: u64,
    total_bytes: u64,
    flow_routed_packets: u64,
    fallback_packets: u64,
    fallback_unsupported_link_packets: u64,
    fallback_non_ip_packets: u64,
    fallback_malformed_packets: u64,
    fallback_fragmented_packets: u64,
    fallback_unsupported_transport_packets: u64,
    dump_packets: u64,
    single_shard_packets: u64,
}

impl ShardLoadMetrics {
    pub fn new(shard_count: usize) -> Self {
        let shard_count = shard_count.max(1);
        Self {
            shards: (0..shard_count).map(ShardLoad::new).collect(),
            flow_loads: AHashMap::new(),
            flow_order: VecDeque::new(),
            max_tracked_flows: DEFAULT_MAX_TRACKED_ROUTE_FLOWS,
            total_packets: 0,
            total_bytes: 0,
            flow_routed_packets: 0,
            fallback_packets: 0,
            fallback_unsupported_link_packets: 0,
            fallback_non_ip_packets: 0,
            fallback_malformed_packets: 0,
            fallback_fragmented_packets: 0,
            fallback_unsupported_transport_packets: 0,
            dump_packets: 0,
            single_shard_packets: 0,
        }
    }

    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    pub fn total_packets(&self) -> u64 {
        self.total_packets
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub fn fallback_packets(&self) -> u64 {
        self.fallback_packets
    }

    pub fn shard(&self, shard: usize) -> Option<&ShardLoad> {
        self.shards.get(shard)
    }

    pub fn observe_route(&mut self, route: ShardRoute, bytes: u64) {
        self.total_packets = self.total_packets.saturating_add(1);
        self.total_bytes = self.total_bytes.saturating_add(bytes);

        match route.kind {
            ShardRouteKind::FlowAffinity => {
                self.flow_routed_packets = self.flow_routed_packets.saturating_add(1);
            }
            ShardRouteKind::Fallback => {
                self.fallback_packets = self.fallback_packets.saturating_add(1);
                self.observe_fallback_reason(route.fallback_reason);
            }
            ShardRouteKind::SingleShard => {
                self.single_shard_packets = self.single_shard_packets.saturating_add(1);
            }
            ShardRouteKind::Dump => {
                self.dump_packets = self.dump_packets.saturating_add(1);
            }
        }

        if let Some(load) = self.shards.get_mut(route.shard) {
            load.observe(route.kind, route.fallback_reason, bytes);
        }
        if route.kind == ShardRouteKind::FlowAffinity
            && let Some(flow_route) = route.flow_route
        {
            self.observe_flow_load(flow_route.key, route.shard, bytes);
        }
    }

    fn observe_flow_load(&mut self, key: FlowKey, shard: usize, bytes: u64) {
        if !self.flow_loads.contains_key(&key) {
            while self.flow_loads.len() >= self.max_tracked_flows {
                if self.flow_order.is_empty() {
                    break;
                }
                let Some(evicted) = self.flow_order.pop_front() else {
                    break;
                };
                self.flow_loads.remove(&evicted);
            }
            if self.flow_loads.len() >= self.max_tracked_flows {
                return;
            }
            self.flow_loads.insert(key, FlowRouteLoad::new(shard));
            self.flow_order.push_back(key);
        }

        if let Some(load) = self.flow_loads.get_mut(&key) {
            load.observe(shard, bytes);
        }
    }

    fn observe_fallback_reason(&mut self, reason: Option<FallbackRouteReason>) {
        match reason.unwrap_or(FallbackRouteReason::Malformed) {
            FallbackRouteReason::UnsupportedLink => {
                self.fallback_unsupported_link_packets =
                    self.fallback_unsupported_link_packets.saturating_add(1);
            }
            FallbackRouteReason::NonIp => {
                self.fallback_non_ip_packets = self.fallback_non_ip_packets.saturating_add(1);
            }
            FallbackRouteReason::Malformed => {
                self.fallback_malformed_packets = self.fallback_malformed_packets.saturating_add(1);
            }
            FallbackRouteReason::Fragmented => {
                self.fallback_fragmented_packets =
                    self.fallback_fragmented_packets.saturating_add(1);
            }
            FallbackRouteReason::UnsupportedTransport => {
                self.fallback_unsupported_transport_packets = self
                    .fallback_unsupported_transport_packets
                    .saturating_add(1);
            }
        }
    }

    pub fn snapshot(&self) -> ShardLoadSnapshot {
        let busiest_packets = self.shards.iter().max_by_key(|shard| shard.packets);
        let busiest_bytes = self.shards.iter().max_by_key(|shard| shard.bytes);
        ShardLoadSnapshot {
            shard_count: self.shard_count(),
            total_packets: self.total_packets,
            total_bytes: self.total_bytes,
            flow_routed_packets: self.flow_routed_packets,
            fallback_packets: self.fallback_packets,
            fallback_unsupported_link_packets: self.fallback_unsupported_link_packets,
            fallback_non_ip_packets: self.fallback_non_ip_packets,
            fallback_malformed_packets: self.fallback_malformed_packets,
            fallback_fragmented_packets: self.fallback_fragmented_packets,
            fallback_unsupported_transport_packets: self.fallback_unsupported_transport_packets,
            dump_packets: self.dump_packets,
            single_shard_packets: self.single_shard_packets,
            busiest_shard: busiest_packets
                .filter(|shard| shard.packets != 0)
                .map(|shard| shard.id),
            busiest_shard_packets: busiest_packets.map_or(0, |shard| shard.packets),
            packet_skew_ratio_milli: skew_ratio_milli(
                busiest_packets.map_or(0, |shard| shard.packets),
                self.total_packets,
                self.shard_count(),
            ),
            busiest_byte_shard: busiest_bytes
                .filter(|shard| shard.bytes != 0)
                .map(|shard| shard.id),
            busiest_shard_bytes: busiest_bytes.map_or(0, |shard| shard.bytes),
            byte_skew_ratio_milli: skew_ratio_milli(
                busiest_bytes.map_or(0, |shard| shard.bytes),
                self.total_bytes,
                self.shard_count(),
            ),
            shards: self.shards.clone(),
        }
    }

    pub fn queue_snapshot<I>(
        &self,
        queues: I,
        output_queue_len: usize,
        output_queue_capacity: usize,
    ) -> ShardedQueueSnapshot
    where
        I: IntoIterator<Item = ShardQueueLoad>,
    {
        let mut workers = self
            .shards
            .iter()
            .map(|load| WorkerQueueSnapshot {
                id: load.id,
                len: 0,
                capacity: 0,
                routed_packets: load.packets,
                routed_bytes: load.bytes,
                flow_routed_packets: load.flow_routed_packets,
                fallback_packets: load.fallback_packets,
                fallback_unsupported_link_packets: load.fallback_unsupported_link_packets,
                fallback_non_ip_packets: load.fallback_non_ip_packets,
                fallback_malformed_packets: load.fallback_malformed_packets,
                fallback_fragmented_packets: load.fallback_fragmented_packets,
                fallback_unsupported_transport_packets: load.fallback_unsupported_transport_packets,
                hot_flow: self.hot_flow_snapshot(load.id, load.packets, load.bytes),
            })
            .collect::<Vec<_>>();

        for queue in queues {
            if let Some(worker) = workers.get_mut(queue.shard) {
                worker.len = queue.len;
                worker.capacity = queue.capacity;
            }
        }

        ShardedQueueSnapshot {
            workers,
            output_queue_len,
            output_queue_capacity,
        }
    }

    fn hot_flow_snapshot(
        &self,
        shard: usize,
        shard_packets: u64,
        shard_bytes: u64,
    ) -> Option<WorkerHotFlowSnapshot> {
        let (key, load) = self
            .flow_loads
            .iter()
            .filter(|(_, load)| load.shard == shard)
            .max_by_key(|(_, load)| load.bytes)?;
        Some(WorkerHotFlowSnapshot {
            stream_id: key.stable_id(),
            stream_id_hex: format!("{:016x}", key.stable_id()),
            protocol: transport_name(key.protocol).to_owned(),
            endpoint_a: endpoint_label(key.a),
            endpoint_b: endpoint_label(key.b),
            packets: load.packets,
            bytes: load.bytes,
            packet_share_milli: ratio_milli(load.packets, shard_packets),
            byte_share_milli: ratio_milli(load.bytes, shard_bytes),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FlowRouteLoad {
    shard: usize,
    packets: u64,
    bytes: u64,
}

impl FlowRouteLoad {
    fn new(shard: usize) -> Self {
        Self {
            shard,
            packets: 0,
            bytes: 0,
        }
    }

    fn observe(&mut self, shard: usize, bytes: u64) {
        self.shard = shard;
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardLoad {
    pub id: usize,
    pub packets: u64,
    pub bytes: u64,
    pub flow_routed_packets: u64,
    pub fallback_packets: u64,
    pub fallback_unsupported_link_packets: u64,
    pub fallback_non_ip_packets: u64,
    pub fallback_malformed_packets: u64,
    pub fallback_fragmented_packets: u64,
    pub fallback_unsupported_transport_packets: u64,
    pub dump_packets: u64,
    pub single_shard_packets: u64,
}

impl ShardLoad {
    fn new(id: usize) -> Self {
        Self {
            id,
            packets: 0,
            bytes: 0,
            flow_routed_packets: 0,
            fallback_packets: 0,
            fallback_unsupported_link_packets: 0,
            fallback_non_ip_packets: 0,
            fallback_malformed_packets: 0,
            fallback_fragmented_packets: 0,
            fallback_unsupported_transport_packets: 0,
            dump_packets: 0,
            single_shard_packets: 0,
        }
    }

    fn observe(
        &mut self,
        kind: ShardRouteKind,
        fallback_reason: Option<FallbackRouteReason>,
        bytes: u64,
    ) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
        match kind {
            ShardRouteKind::FlowAffinity => {
                self.flow_routed_packets = self.flow_routed_packets.saturating_add(1);
            }
            ShardRouteKind::Fallback => {
                self.fallback_packets = self.fallback_packets.saturating_add(1);
                self.observe_fallback_reason(fallback_reason);
            }
            ShardRouteKind::SingleShard => {
                self.single_shard_packets = self.single_shard_packets.saturating_add(1);
            }
            ShardRouteKind::Dump => {
                self.dump_packets = self.dump_packets.saturating_add(1);
            }
        }
    }

    fn observe_fallback_reason(&mut self, reason: Option<FallbackRouteReason>) {
        match reason.unwrap_or(FallbackRouteReason::Malformed) {
            FallbackRouteReason::UnsupportedLink => {
                self.fallback_unsupported_link_packets =
                    self.fallback_unsupported_link_packets.saturating_add(1);
            }
            FallbackRouteReason::NonIp => {
                self.fallback_non_ip_packets = self.fallback_non_ip_packets.saturating_add(1);
            }
            FallbackRouteReason::Malformed => {
                self.fallback_malformed_packets = self.fallback_malformed_packets.saturating_add(1);
            }
            FallbackRouteReason::Fragmented => {
                self.fallback_fragmented_packets =
                    self.fallback_fragmented_packets.saturating_add(1);
            }
            FallbackRouteReason::UnsupportedTransport => {
                self.fallback_unsupported_transport_packets = self
                    .fallback_unsupported_transport_packets
                    .saturating_add(1);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardLoadSnapshot {
    pub shard_count: usize,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub flow_routed_packets: u64,
    pub fallback_packets: u64,
    pub fallback_unsupported_link_packets: u64,
    pub fallback_non_ip_packets: u64,
    pub fallback_malformed_packets: u64,
    pub fallback_fragmented_packets: u64,
    pub fallback_unsupported_transport_packets: u64,
    pub dump_packets: u64,
    pub single_shard_packets: u64,
    pub busiest_shard: Option<usize>,
    pub busiest_shard_packets: u64,
    pub packet_skew_ratio_milli: u64,
    pub busiest_byte_shard: Option<usize>,
    pub busiest_shard_bytes: u64,
    pub byte_skew_ratio_milli: u64,
    pub shards: Vec<ShardLoad>,
}

impl ShardLoadSnapshot {
    pub fn packet_skew_ratio(&self) -> f64 {
        self.packet_skew_ratio_milli as f64 / 1000.0
    }

    pub fn byte_skew_ratio(&self) -> f64 {
        self.byte_skew_ratio_milli as f64 / 1000.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardQueueLoad {
    pub shard: usize,
    pub len: usize,
    pub capacity: usize,
}

pub fn shard_for_flow_key(key: &FlowKey, shard_count: usize) -> usize {
    ShardTopology::new(shard_count).shard_for_hash(route_hash(key))
}

#[cfg(test)]
pub(crate) fn route_packet(
    raw: &RawPacket,
    mode: RunMode,
    sequence: u64,
    shard_count: usize,
) -> ShardRoute {
    let mut coordinator = ShardCoordinator::new(ShardCoordinatorConfig::new(shard_count, mode));
    coordinator.next_sequence = sequence;
    coordinator.route_packet(raw)
}

// Tiny parser for the dispatcher. Workers still do the full decode once analyzers need it.
pub(crate) fn flow_route_from_raw(raw: &RawPacket) -> Option<FlowRoute> {
    flow_route_from_raw_result(raw).ok()
}

fn flow_route_from_raw_result(raw: &RawPacket) -> Result<FlowRoute, FallbackRouteReason> {
    match raw.link_layer {
        LinkLayer::Ethernet => {
            let (ethertype, payload_offset) = ethernet_payload(&raw.data)?;
            route_ip_by_ethertype(&raw.data, payload_offset, ethertype)
        }
        LinkLayer::LinuxSll => {
            if raw.data.len() < 16 {
                return Err(FallbackRouteReason::Malformed);
            }
            let ethertype = read_u16(&raw.data, 14)?;
            route_ip_by_ethertype(&raw.data, 16, ethertype)
        }
        LinkLayer::RawIp => route_raw_ip(&raw.data, 0),
        LinkLayer::BsdLoopback => route_raw_ip(&raw.data, 4),
        LinkLayer::Unsupported => Err(FallbackRouteReason::UnsupportedLink),
    }
}

fn ethernet_payload(data: &[u8]) -> Result<(u16, usize), FallbackRouteReason> {
    if data.len() < 14 {
        return Err(FallbackRouteReason::Malformed);
    }

    let mut ethertype = read_u16(data, 12)?;
    let mut offset = 14;
    for _ in 0..2 {
        if !matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
            break;
        }
        if data.len() < offset + 4 {
            return Err(FallbackRouteReason::Malformed);
        }
        ethertype = read_u16(data, offset + 2)?;
        offset += 4;
    }

    Ok((ethertype, offset))
}

fn route_ip_by_ethertype(
    data: &[u8],
    offset: usize,
    ethertype: u16,
) -> Result<FlowRoute, FallbackRouteReason> {
    match ethertype {
        0x0800 => route_ipv4(data, offset),
        0x86dd => route_ipv6(data, offset),
        _ => Err(FallbackRouteReason::NonIp),
    }
}

fn route_raw_ip(data: &[u8], offset: usize) -> Result<FlowRoute, FallbackRouteReason> {
    let version = data.get(offset).ok_or(FallbackRouteReason::Malformed)? >> 4;
    match version {
        4 => route_ipv4(data, offset),
        6 => route_ipv6(data, offset),
        _ => Err(FallbackRouteReason::NonIp),
    }
}

fn route_ipv4(data: &[u8], offset: usize) -> Result<FlowRoute, FallbackRouteReason> {
    if data.len() < offset + 20 {
        return Err(FallbackRouteReason::Malformed);
    }

    let version = data[offset] >> 4;
    let header_len = usize::from(data[offset] & 0x0f) * 4;
    if version != 4 || header_len < 20 || data.len() < offset + header_len {
        return Err(FallbackRouteReason::Malformed);
    }

    let total_len = usize::from(read_u16(data, offset + 2)?);
    if total_len < header_len {
        return Err(FallbackRouteReason::Malformed);
    }

    let fragment = read_u16(data, offset + 6)?;
    if fragment & 0x1fff != 0 {
        return Err(FallbackRouteReason::Fragmented);
    }

    let protocol = data[offset + 9];
    let source = IpAddr::V4(Ipv4Addr::new(
        data[offset + 12],
        data[offset + 13],
        data[offset + 14],
        data[offset + 15],
    ));
    let destination = IpAddr::V4(Ipv4Addr::new(
        data[offset + 16],
        data[offset + 17],
        data[offset + 18],
        data[offset + 19],
    ));

    route_transport(data, offset + header_len, protocol, source, destination)
}

fn route_ipv6(data: &[u8], offset: usize) -> Result<FlowRoute, FallbackRouteReason> {
    if data.len() < offset + 40 || data[offset] >> 4 != 6 {
        return Err(FallbackRouteReason::Malformed);
    }

    let source_bytes: [u8; 16] = data
        .get(offset + 8..offset + 24)
        .ok_or(FallbackRouteReason::Malformed)?
        .try_into()
        .map_err(|_| FallbackRouteReason::Malformed)?;
    let destination_bytes: [u8; 16] = data
        .get(offset + 24..offset + 40)
        .ok_or(FallbackRouteReason::Malformed)?
        .try_into()
        .map_err(|_| FallbackRouteReason::Malformed)?;
    let source = IpAddr::V6(Ipv6Addr::from(source_bytes));
    let destination = IpAddr::V6(Ipv6Addr::from(destination_bytes));

    route_ipv6_transport(data, offset + 40, data[offset + 6], source, destination)
}

fn route_ipv6_transport(
    data: &[u8],
    mut offset: usize,
    mut next_header: u8,
    source: IpAddr,
    destination: IpAddr,
) -> Result<FlowRoute, FallbackRouteReason> {
    for _ in 0..8 {
        match next_header {
            6 | 17 => return route_transport(data, offset, next_header, source, destination),
            0 | 43 | 60 => {
                if data.len() < offset + 2 {
                    return Err(FallbackRouteReason::Malformed);
                }
                next_header = data[offset];
                offset = offset.saturating_add((usize::from(data[offset + 1]) + 1) * 8);
            }
            44 => {
                if data.len() < offset + 8 {
                    return Err(FallbackRouteReason::Malformed);
                }
                let fragment = read_u16(data, offset + 2)?;
                if fragment & 0xfff8 != 0 {
                    return Err(FallbackRouteReason::Fragmented);
                }
                next_header = data[offset];
                offset = offset.saturating_add(8);
            }
            51 => {
                if data.len() < offset + 2 {
                    return Err(FallbackRouteReason::Malformed);
                }
                next_header = data[offset];
                offset = offset.saturating_add((usize::from(data[offset + 1]) + 2) * 4);
            }
            _ => return Err(FallbackRouteReason::UnsupportedTransport),
        }
    }

    Err(FallbackRouteReason::UnsupportedTransport)
}

fn route_transport(
    data: &[u8],
    offset: usize,
    protocol: u8,
    source_addr: IpAddr,
    destination_addr: IpAddr,
) -> Result<FlowRoute, FallbackRouteReason> {
    let protocol = match protocol {
        6 => TransportProtocol::Tcp,
        17 => TransportProtocol::Udp,
        _ => return Err(FallbackRouteReason::UnsupportedTransport),
    };
    let source_port = read_u16(data, offset)?;
    let destination_port = read_u16(data, offset + 2)?;

    Ok(FlowRoute::new(
        protocol,
        Endpoint {
            addr: source_addr,
            port: source_port,
        },
        Endpoint {
            addr: destination_addr,
            port: destination_port,
        },
    ))
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, FallbackRouteReason> {
    Ok(u16::from_be_bytes([
        *data.get(offset).ok_or(FallbackRouteReason::Malformed)?,
        *data.get(offset + 1).ok_or(FallbackRouteReason::Malformed)?,
    ]))
}

fn route_hash<T: Hash>(value: T) -> u64 {
    ROUTE_HASHER.hash_one(value)
}

fn skew_ratio_milli(max: u64, total: u64, shard_count: usize) -> u64 {
    if total == 0 || shard_count == 0 {
        return 0;
    }
    let ratio = u128::from(max)
        .saturating_mul(shard_count as u128)
        .saturating_mul(1000)
        / u128::from(total);
    ratio.min(u128::from(u64::MAX)) as u64
}

fn ratio_milli(part: u64, total: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    let ratio = u128::from(part).saturating_mul(1000) / u128::from(total);
    ratio.min(u128::from(u64::MAX)) as u64
}

fn endpoint_label(endpoint: Endpoint) -> String {
    match endpoint.addr {
        IpAddr::V4(addr) => format!("{addr}:{}", endpoint.port),
        IpAddr::V6(addr) => format!("[{addr}]:{}", endpoint.port),
    }
}

fn transport_name(protocol: TransportProtocol) -> &'static str {
    match protocol {
        TransportProtocol::Tcp => "tcp",
        TransportProtocol::Udp => "udp",
        TransportProtocol::Icmpv4 => "icmpv4",
        TransportProtocol::Icmpv6 => "icmpv6",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{PacketTimestamp, RawPacket};
    use etherparse::PacketBuilder;
    use pcap::Linktype;

    #[test]
    fn topology_uses_mask_for_power_of_two_shards() {
        let topology = ShardTopology::new(8);

        assert!(topology.is_power_of_two());
        assert_eq!(7, topology.shard_for_hash(15));
        assert_eq!(3, topology.shard_for_sequence(11));
    }

    #[test]
    fn flow_affinity_routes_both_directions_to_same_shard() {
        let forward = tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 1, b"x");
        let reverse = tcp_packet([10, 0, 0, 2], 80, [10, 0, 0, 1], 1111, 1, b"y");

        let forward = route_packet(&forward, RunMode::Analyze, 0, 8);
        let reverse = route_packet(&reverse, RunMode::Analyze, 1, 8);

        assert_eq!(ShardRouteKind::FlowAffinity, forward.kind);
        assert_eq!(ShardRouteKind::FlowAffinity, reverse.kind);
        assert_eq!(forward.shard, reverse.shard);
        assert_eq!(
            forward.flow_route.map(|route| route.key),
            reverse.flow_route.map(|route| route.key)
        );
    }

    #[test]
    fn coordinator_reuses_flow_owner_for_reverse_direction() {
        let mut coordinator =
            ShardCoordinator::new(ShardCoordinatorConfig::new(4, RunMode::Analyze));
        let forward = tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 1, b"x");
        let reverse = tcp_packet([10, 0, 0, 2], 80, [10, 0, 0, 1], 1111, 1, b"y");

        let forward_route = coordinator.route_packet(&forward);
        let reverse_route = coordinator.route_packet(&reverse);

        assert_eq!(ShardRouteKind::FlowAffinity, forward_route.kind);
        assert_eq!(ShardRouteKind::FlowAffinity, reverse_route.kind);
        assert_eq!(forward_route.shard, reverse_route.shard);
        assert_eq!(1, coordinator.flow_owner_count());
    }

    #[test]
    fn stateful_placement_chooses_colder_secondary_candidate() {
        let mut coordinator =
            ShardCoordinator::new(ShardCoordinatorConfig::new(4, RunMode::Analyze));
        let (packet, flow_route, primary, secondary) = flow_with_distinct_candidates(4);

        coordinator
            .metrics
            .observe_route(flow_route_on_shard(flow_route, primary), 50_000);

        let first = coordinator.route_packet(&packet);
        let second = coordinator.route_packet(&packet);

        assert_eq!(secondary, first.shard);
        assert_eq!(secondary, second.shard);
        assert_eq!(1, coordinator.flow_owner_count());
    }

    #[test]
    fn flow_owner_table_is_bounded_by_config() {
        let mut coordinator = ShardCoordinator::new(
            ShardCoordinatorConfig::new(4, RunMode::Analyze).with_max_flow_owners(1),
        );
        let first = tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 1, b"x");
        let second = tcp_packet([10, 0, 0, 3], 2222, [10, 0, 0, 4], 443, 1, b"y");

        coordinator.route_packet(&first);
        coordinator.route_packet(&second);

        assert_eq!(1, coordinator.flow_owner_count());
        assert_eq!(1, coordinator.flow_owner_evictions());
    }

    #[test]
    fn coordinator_tracks_routing_load_without_queue_state() {
        let mut coordinator =
            ShardCoordinator::new(ShardCoordinatorConfig::new(4, RunMode::Analyze));
        let first = RawPacket {
            timestamp: PacketTimestamp { sec: 1, usec: 0 },
            link_layer: LinkLayer::Unsupported,
            linktype: 9999,
            data: b"bad-one".to_vec(),
        };
        let second = RawPacket {
            timestamp: PacketTimestamp { sec: 2, usec: 0 },
            link_layer: LinkLayer::Unsupported,
            linktype: 9999,
            data: b"bad-two".to_vec(),
        };

        let first_route = coordinator.route_packet(&first);
        let second_route = coordinator.route_packet(&second);
        let snapshot = coordinator.metrics().snapshot();

        assert_eq!(0, first_route.shard);
        assert_eq!(1, second_route.shard);
        assert_eq!(2, snapshot.total_packets);
        assert_eq!(14, snapshot.total_bytes);
        assert_eq!(2, snapshot.fallback_packets);
        assert_eq!(2, snapshot.fallback_unsupported_link_packets);
        assert_eq!(0, snapshot.fallback_malformed_packets);
        assert_eq!(2000, snapshot.packet_skew_ratio_milli);
        assert_eq!(2000, snapshot.byte_skew_ratio_milli);
    }

    #[test]
    fn dump_mode_uses_single_output_shard_without_flow_routing() {
        let mut coordinator = ShardCoordinator::new(ShardCoordinatorConfig::new(4, RunMode::Dump));
        let packet = tcp_packet([10, 0, 0, 1], 1111, [10, 0, 0, 2], 80, 1, b"x");

        let route = coordinator.route_packet(&packet);
        let snapshot = coordinator.metrics().snapshot();

        assert_eq!(0, route.shard);
        assert_eq!(ShardRouteKind::Dump, route.kind);
        assert_eq!(None, route.flow_route);
        assert_eq!(1, snapshot.dump_packets);
        assert_eq!(0, snapshot.flow_routed_packets);
    }

    #[test]
    fn queue_snapshot_merges_worker_queues_with_route_metrics() {
        let mut metrics = ShardLoadMetrics::new(2);
        metrics.observe_route(
            ShardRoute {
                shard: 1,
                kind: ShardRouteKind::Fallback,
                flow_route: None,
                fallback_reason: Some(FallbackRouteReason::Malformed),
            },
            32,
        );

        let snapshot = metrics.queue_snapshot(
            [
                ShardQueueLoad {
                    shard: 0,
                    len: 1,
                    capacity: 8,
                },
                ShardQueueLoad {
                    shard: 1,
                    len: 3,
                    capacity: 8,
                },
            ],
            2,
            16,
        );

        assert_eq!(2, snapshot.output_queue_len);
        assert_eq!(3, snapshot.workers[1].len);
        assert_eq!(1, snapshot.workers[1].routed_packets);
        assert_eq!(32, snapshot.workers[1].routed_bytes);
        assert_eq!(1, snapshot.workers[1].fallback_packets);
        assert_eq!(1, snapshot.workers[1].fallback_malformed_packets);
    }

    #[test]
    fn queue_snapshot_reports_hot_flow_per_shard() {
        let mut metrics = ShardLoadMetrics::new(2);
        let light = FlowRoute::new(
            TransportProtocol::Tcp,
            Endpoint {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                port: 1111,
            },
            Endpoint {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                port: 80,
            },
        );
        let heavy = FlowRoute::new(
            TransportProtocol::Tcp,
            Endpoint {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
                port: 2222,
            },
            Endpoint {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
                port: 443,
            },
        );

        metrics.observe_route(flow_route_on_shard(heavy, 1), 1000);
        metrics.observe_route(flow_route_on_shard(light, 1), 50);
        metrics.observe_route(flow_route_on_shard(heavy, 1), 500);

        let snapshot = metrics.queue_snapshot(
            [ShardQueueLoad {
                shard: 1,
                len: 0,
                capacity: 8,
            }],
            0,
            16,
        );
        let hot = snapshot.workers[1].hot_flow.as_ref().unwrap();

        assert_eq!(heavy.key.stable_id(), hot.stream_id);
        assert_eq!("tcp", hot.protocol);
        assert_eq!("10.0.0.3:2222", hot.endpoint_a);
        assert_eq!("10.0.0.4:443", hot.endpoint_b);
        assert_eq!(2, hot.packets);
        assert_eq!(1500, hot.bytes);
        assert_eq!(666, hot.packet_share_milli);
        assert_eq!(967, hot.byte_share_milli);
    }

    fn tcp_packet(
        source: [u8; 4],
        source_port: u16,
        destination: [u8; 4],
        destination_port: u16,
        sequence: u32,
        payload: &[u8],
    ) -> RawPacket {
        let builder = PacketBuilder::ethernet2([1, 1, 1, 1, 1, 1], [2, 2, 2, 2, 2, 2])
            .ipv4(
                Ipv4Addr::from(source).octets(),
                Ipv4Addr::from(destination).octets(),
                20,
            )
            .tcp(source_port, destination_port, sequence, 1024);
        let mut data = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut data, payload).unwrap();
        RawPacket {
            timestamp: PacketTimestamp { sec: 1, usec: 0 },
            link_layer: LinkLayer::Ethernet,
            linktype: Linktype::ETHERNET.0,
            data,
        }
    }

    fn flow_route_on_shard(flow_route: FlowRoute, shard: usize) -> ShardRoute {
        ShardRoute {
            shard,
            kind: ShardRouteKind::FlowAffinity,
            flow_route: Some(flow_route),
            fallback_reason: None,
        }
    }

    fn flow_with_distinct_candidates(shard_count: usize) -> (RawPacket, FlowRoute, usize, usize) {
        let topology = ShardTopology::new(shard_count);
        for host in 1..=254 {
            let packet = tcp_packet(
                [10, 0, 1, host],
                10_000 + host as u16,
                [10, 0, 2, 1],
                80,
                1,
                b"x",
            );
            let flow_route = flow_route_from_raw(&packet).unwrap();
            let primary = topology.shard_for_hash(route_hash(flow_route.key));
            let secondary =
                topology.shard_for_hash(route_hash((SECONDARY_ROUTE_HASH_SALT, flow_route.key)));
            if primary != secondary {
                return (packet, flow_route, primary, secondary);
            }
        }
        panic!("expected to find a flow with distinct placement candidates");
    }
}
