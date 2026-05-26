use std::{fs, path::Path};

use anyhow::{Context, anyhow};
use serde::{Deserialize, Serialize};

use crate::{
    flow::FlowDirection,
    packet::TransportProtocol,
    stream_slice::StreamSliceMode,
    stream_transform::{StreamTransformMode, StreamTransformPlan},
    stream_view::{StreamHideRule, StreamViewContentKind},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceProfile {
    pub id: String,
    pub name: String,
    pub description: String,
    pub priority: u16,
    pub enabled: bool,
    pub protocol: Option<TransportProtocol>,
    pub services: Vec<String>,
    pub ports: Vec<u16>,
    pub content_kind: Option<StreamViewContentKind>,
    pub pattern_ids: Vec<String>,
    pub default_direction: Option<FlowDirection>,
    pub default_mode: Option<StreamSliceMode>,
    pub default_transform: Option<StreamTransformMode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_transforms: Vec<StreamTransformMode>,
    pub hide_rules: Vec<StreamHideRule>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ServiceProfileStats {
    pub total_streams: usize,
    pub visible_streams: usize,
    pub hidden_streams: usize,
    pub matched_streams: usize,
    pub favorite_streams: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceProfileSet {
    profiles: Vec<ServiceProfile>,
}

impl Default for ServiceProfileSet {
    fn default() -> Self {
        Self::builtin()
    }
}

impl ServiceProfileSet {
    pub fn builtin() -> Self {
        let mut profiles = vec![
            ServiceProfile {
                id: "http".to_owned(),
                name: "HTTP".to_owned(),
                description: "Plain HTTP and common web challenge ports".to_owned(),
                priority: 100,
                enabled: true,
                protocol: Some(TransportProtocol::Tcp),
                services: vec!["http".to_owned()],
                ports: vec![80, 8000, 8008, 8080, 8081, 8888],
                content_kind: None,
                pattern_ids: Vec::new(),
                default_direction: Some(FlowDirection::AToB),
                default_mode: Some(StreamSliceMode::Text),
                default_transform: Some(StreamTransformMode::Auto),
                default_transforms: vec![
                    StreamTransformMode::HttpChunked,
                    StreamTransformMode::HttpGzip,
                    StreamTransformMode::UrlDecode,
                ],
                hide_rules: vec![StreamHideRule::Service("http".to_owned())],
            },
            ServiceProfile {
                id: "tls".to_owned(),
                name: "TLS".to_owned(),
                description: "TLS and HTTPS-like encrypted streams".to_owned(),
                priority: 95,
                enabled: true,
                protocol: Some(TransportProtocol::Tcp),
                services: vec!["tls".to_owned()],
                ports: vec![443, 8443],
                content_kind: None,
                pattern_ids: Vec::new(),
                default_direction: Some(FlowDirection::AToB),
                default_mode: Some(StreamSliceMode::Hex),
                default_transform: None,
                default_transforms: Vec::new(),
                hide_rules: vec![StreamHideRule::Service("tls".to_owned())],
            },
            ServiceProfile {
                id: "dns".to_owned(),
                name: "DNS".to_owned(),
                description: "DNS traffic on classic and multicast resolver ports".to_owned(),
                priority: 90,
                enabled: true,
                protocol: None,
                services: vec!["dns".to_owned()],
                ports: vec![53, 5353],
                content_kind: None,
                pattern_ids: Vec::new(),
                default_direction: Some(FlowDirection::AToB),
                default_mode: Some(StreamSliceMode::Hex),
                default_transform: None,
                default_transforms: Vec::new(),
                hide_rules: vec![StreamHideRule::Service("dns".to_owned())],
            },
            ServiceProfile {
                id: "websocket".to_owned(),
                name: "WebSocket".to_owned(),
                description: "WebSocket-heavy app streams and common upgrade ports".to_owned(),
                priority: 80,
                enabled: true,
                protocol: Some(TransportProtocol::Tcp),
                services: vec!["http".to_owned()],
                ports: vec![80, 8000, 8008, 8080, 8081, 8888],
                content_kind: None,
                pattern_ids: Vec::new(),
                default_direction: Some(FlowDirection::AToB),
                default_mode: Some(StreamSliceMode::Text),
                default_transform: Some(StreamTransformMode::WebSocketDeflate),
                default_transforms: vec![
                    StreamTransformMode::WebSocketDeflate,
                    StreamTransformMode::UrlDecode,
                ],
                hide_rules: Vec::new(),
            },
            ServiceProfile {
                id: "binary".to_owned(),
                name: "Binary".to_owned(),
                description: "Unknown or custom binary protocols".to_owned(),
                priority: 20,
                enabled: true,
                protocol: None,
                services: Vec::new(),
                ports: Vec::new(),
                content_kind: Some(StreamViewContentKind::Binary),
                pattern_ids: Vec::new(),
                default_direction: Some(FlowDirection::AToB),
                default_mode: Some(StreamSliceMode::Hex),
                default_transform: None,
                default_transforms: Vec::new(),
                hide_rules: vec![StreamHideRule::ContentKind(StreamViewContentKind::Binary)],
            },
            ServiceProfile {
                id: "matched".to_owned(),
                name: "Matched".to_owned(),
                description: "Streams with retained pattern matches".to_owned(),
                priority: 10,
                enabled: true,
                protocol: None,
                services: Vec::new(),
                ports: Vec::new(),
                content_kind: None,
                pattern_ids: Vec::new(),
                default_direction: Some(FlowDirection::AToB),
                default_mode: Some(StreamSliceMode::Text),
                default_transform: Some(StreamTransformMode::Auto),
                default_transforms: vec![StreamTransformMode::Auto],
                hide_rules: Vec::new(),
            },
        ];
        profiles = profiles
            .into_iter()
            .map(ServiceProfile::normalized)
            .collect();
        profiles.sort_by_key(|profile| std::cmp::Reverse(profile.priority));
        Self { profiles }
    }

    pub fn profiles(&self) -> &[ServiceProfile] {
        &self.profiles
    }

    pub fn get(&self, id: &str) -> Option<&ServiceProfile> {
        let id = normalized_id(id);
        self.profiles.iter().find(|profile| profile.id == id)
    }

    pub fn from_json_file(path: &Path) -> anyhow::Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read service profile file {}", path.display()))?;
        Self::from_json_str(&raw)
    }

    pub fn from_json_str(raw: &str) -> anyhow::Result<Self> {
        let file: ServiceProfileFile =
            serde_json::from_str(raw).context("failed to parse service profile JSON file")?;
        let mut set = if file.include_builtins.unwrap_or(true) {
            Self::builtin()
        } else {
            Self {
                profiles: Vec::new(),
            }
        };
        for profile in file.profiles {
            set.upsert(profile.into_profile()?);
        }
        set.sort();
        Ok(set)
    }

    fn upsert(&mut self, profile: ServiceProfile) {
        let profile = profile.normalized();
        self.profiles.retain(|existing| existing.id != profile.id);
        self.profiles.push(profile);
    }

    fn sort(&mut self) {
        self.profiles
            .sort_by_key(|profile| std::cmp::Reverse(profile.priority));
    }
}

impl ServiceProfile {
    pub fn normalized(mut self) -> Self {
        self.id = normalized_id(&self.id);
        self.services = self
            .services
            .into_iter()
            .map(|service| service.trim().to_ascii_lowercase())
            .filter(|service| !service.is_empty())
            .collect();
        self.pattern_ids = self
            .pattern_ids
            .into_iter()
            .map(|pattern_id| pattern_id.trim().to_owned())
            .filter(|pattern_id| !pattern_id.is_empty())
            .collect();
        self.ports.sort_unstable();
        self.ports.dedup();
        self.hide_rules = self
            .hide_rules
            .into_iter()
            .map(StreamHideRule::normalized)
            .collect();
        if self.default_transform.is_none() {
            self.default_transform = self.default_transforms.first().copied();
        }
        if self.default_transforms.is_empty()
            && let Some(default_transform) = self.default_transform
        {
            self.default_transforms.push(default_transform);
        }
        self
    }

    pub fn default_transform_plan(&self) -> Option<StreamTransformPlan> {
        (!self.default_transforms.is_empty())
            .then(|| StreamTransformPlan::new(self.default_transforms.clone()))
    }
}

fn normalized_id(id: &str) -> String {
    id.trim().to_ascii_lowercase().replace([' ', '-'], "_")
}

#[derive(Debug, Deserialize)]
struct ServiceProfileFile {
    include_builtins: Option<bool>,
    #[serde(default)]
    profiles: Vec<ServiceProfileConfig>,
}

#[derive(Debug, Deserialize)]
struct ServiceProfileConfig {
    id: String,
    name: Option<String>,
    description: Option<String>,
    priority: Option<u16>,
    enabled: Option<bool>,
    protocol: Option<String>,
    #[serde(default)]
    services: Vec<String>,
    #[serde(default)]
    ports: Vec<u16>,
    content_kind: Option<String>,
    #[serde(default)]
    pattern_ids: Vec<String>,
    default_direction: Option<String>,
    default_mode: Option<String>,
    default_transform: Option<String>,
    #[serde(default)]
    default_transforms: Vec<String>,
    #[serde(default)]
    hide_rules: Vec<HideRuleConfig>,
}

#[derive(Debug, Deserialize)]
struct HideRuleConfig {
    kind: String,
    value: serde_json::Value,
}

impl ServiceProfileConfig {
    fn into_profile(self) -> anyhow::Result<ServiceProfile> {
        let id = normalized_id(&self.id);
        if id.is_empty() {
            return Err(anyhow!("service profile id is empty"));
        }
        let default_transform = self
            .default_transform
            .as_deref()
            .map(parse_transform)
            .transpose()?;
        let default_transforms = self
            .default_transforms
            .iter()
            .map(|transform| parse_transform(transform))
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(ServiceProfile {
            name: self.name.unwrap_or_else(|| id.clone()),
            description: self.description.unwrap_or_default(),
            priority: self.priority.unwrap_or(50),
            enabled: self.enabled.unwrap_or(true),
            protocol: self.protocol.as_deref().map(parse_protocol).transpose()?,
            services: self.services,
            ports: self.ports,
            content_kind: self
                .content_kind
                .as_deref()
                .map(parse_content_kind)
                .transpose()?,
            pattern_ids: self.pattern_ids,
            default_direction: self
                .default_direction
                .as_deref()
                .map(parse_direction)
                .transpose()?,
            default_mode: self.default_mode.as_deref().map(parse_mode).transpose()?,
            default_transform,
            default_transforms,
            hide_rules: self
                .hide_rules
                .into_iter()
                .map(HideRuleConfig::into_rule)
                .collect::<anyhow::Result<Vec<_>>>()?,
            id,
        })
    }
}

impl HideRuleConfig {
    fn into_rule(self) -> anyhow::Result<StreamHideRule> {
        let value = json_scalar_to_string(&self.value)?;
        let rule = match normalized_token(&self.kind).as_str() {
            "stream" | "stream_id" => StreamHideRule::StreamId(parse_stream_id(&value)?),
            "service" => StreamHideRule::Service(value),
            "protocol" => StreamHideRule::Protocol(parse_protocol(&value)?),
            "port" => StreamHideRule::Port(value.parse::<u16>()?),
            "content_kind" | "kind" => StreamHideRule::ContentKind(parse_content_kind(&value)?),
            "status" => StreamHideRule::Status(parse_status(&value)?),
            "pattern" | "pattern_id" => StreamHideRule::PatternId(value),
            kind => return Err(anyhow!("invalid hide rule kind: {kind}")),
        };
        Ok(rule.normalized())
    }
}

fn parse_stream_id(raw: &str) -> anyhow::Result<u64> {
    let value = raw.trim();
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    let looks_hex = value.starts_with("0x")
        || value.starts_with("0X")
        || hex
            .bytes()
            .any(|byte| byte.is_ascii_hexdigit() && byte.is_ascii_alphabetic());
    if looks_hex {
        Ok(u64::from_str_radix(hex, 16)?)
    } else {
        Ok(value.parse::<u64>()?)
    }
}

fn parse_protocol(raw: &str) -> anyhow::Result<TransportProtocol> {
    match normalized_token(raw).as_str() {
        "tcp" => Ok(TransportProtocol::Tcp),
        "udp" => Ok(TransportProtocol::Udp),
        "icmpv4" | "icmp_v4" => Ok(TransportProtocol::Icmpv4),
        "icmpv6" | "icmp_v6" => Ok(TransportProtocol::Icmpv6),
        _ => Err(anyhow!("invalid protocol: {raw}")),
    }
}

fn parse_content_kind(raw: &str) -> anyhow::Result<StreamViewContentKind> {
    match normalized_token(raw).as_str() {
        "unknown" => Ok(StreamViewContentKind::Unknown),
        "text" => Ok(StreamViewContentKind::Text),
        "binary" => Ok(StreamViewContentKind::Binary),
        "mixed" => Ok(StreamViewContentKind::Mixed),
        _ => Err(anyhow!("invalid content_kind: {raw}")),
    }
}

fn parse_status(raw: &str) -> anyhow::Result<crate::stream_view::StreamViewStatus> {
    match normalized_token(raw).as_str() {
        "open" => Ok(crate::stream_view::StreamViewStatus::Open),
        "closing" => Ok(crate::stream_view::StreamViewStatus::Closing),
        "closed" => Ok(crate::stream_view::StreamViewStatus::Closed),
        "unknown" => Ok(crate::stream_view::StreamViewStatus::Unknown),
        _ => Err(anyhow!("invalid status: {raw}")),
    }
}

fn parse_direction(raw: &str) -> anyhow::Result<FlowDirection> {
    match normalized_token(raw).as_str() {
        "a_to_b" | "atob" | "a_b" => Ok(FlowDirection::AToB),
        "b_to_a" | "btoa" | "b_a" => Ok(FlowDirection::BToA),
        _ => Err(anyhow!("invalid direction: {raw}")),
    }
}

fn parse_mode(raw: &str) -> anyhow::Result<StreamSliceMode> {
    match normalized_token(raw).as_str() {
        "raw" => Ok(StreamSliceMode::Raw),
        "text" => Ok(StreamSliceMode::Text),
        "hex" => Ok(StreamSliceMode::Hex),
        _ => Err(anyhow!("invalid mode: {raw}")),
    }
}

fn parse_transform(raw: &str) -> anyhow::Result<StreamTransformMode> {
    match normalized_token(raw).as_str() {
        "auto" => Ok(StreamTransformMode::Auto),
        "url" | "url_decode" | "urldecode" => Ok(StreamTransformMode::UrlDecode),
        "gzip" => Ok(StreamTransformMode::Gzip),
        "http_chunked" | "chunked" => Ok(StreamTransformMode::HttpChunked),
        "http_gzip" => Ok(StreamTransformMode::HttpGzip),
        "websocket_deflate" | "ws_deflate" => Ok(StreamTransformMode::WebSocketDeflate),
        _ => Err(anyhow!("invalid transform: {raw}")),
    }
}

fn json_scalar_to_string(value: &serde_json::Value) -> anyhow::Result<String> {
    let value = match value {
        serde_json::Value::String(value) => value.trim().to_owned(),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        _ => return Err(anyhow!("hide rule value must be a scalar")),
    };
    if value.is_empty() {
        Err(anyhow!("hide rule value is empty"))
    } else {
        Ok(value)
    }
}

fn normalized_token(raw: &str) -> String {
    raw.trim().to_ascii_lowercase().replace(['-', ' '], "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_profile_file_and_overrides_builtin_id() {
        let profiles = ServiceProfileSet::from_json_str(
            r#"{
              "include_builtins": true,
              "profiles": [{
                "id": "http",
                "name": "HTTP custom",
                "priority": 200,
                "protocol": "tcp",
                "ports": [18080],
                "default_transform": "auto",
                "default_transforms": ["http_chunked", "http_gzip", "url_decode"],
                "hide_rules": [{"kind": "port", "value": 18080}]
              }]
            }"#,
        )
        .unwrap();
        let profile = profiles.get("http").unwrap();

        assert_eq!("HTTP custom", profile.name);
        assert_eq!(vec![18080], profile.ports);
        assert_eq!(
            vec![
                StreamTransformMode::HttpChunked,
                StreamTransformMode::HttpGzip,
                StreamTransformMode::UrlDecode
            ],
            profile.default_transform_plan().unwrap().steps
        );
        assert_eq!(1, profile.hide_rules.len());
    }
}
