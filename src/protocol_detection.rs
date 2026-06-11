use serde::{Deserialize, Serialize};

use crate::{
    flow::{FlowDirection, FlowKey},
    packet::TransportProtocol,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolDetectionSource {
    Unknown,
    Port,
    Payload,
    PortAndPayload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolServiceSide {
    A,
    B,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolDetection {
    pub service: &'static str,
    pub side: ProtocolServiceSide,
    pub confidence: u8,
    pub source: ProtocolDetectionSource,
    pub evidence: &'static str,
}

impl Default for ProtocolDetection {
    fn default() -> Self {
        Self::unknown()
    }
}

impl ProtocolDetection {
    pub fn unknown() -> Self {
        Self {
            service: "unknown",
            side: ProtocolServiceSide::Unknown,
            confidence: 0,
            source: ProtocolDetectionSource::Unknown,
            evidence: "none",
        }
    }

    pub fn from_port(key: FlowKey) -> Self {
        known_service(key.protocol, key.a.port)
            .map(|(service, confidence)| Self {
                service,
                side: ProtocolServiceSide::A,
                confidence,
                source: ProtocolDetectionSource::Port,
                evidence: "well_known_port",
            })
            .or_else(|| {
                known_service(key.protocol, key.b.port).map(|(service, confidence)| Self {
                    service,
                    side: ProtocolServiceSide::B,
                    confidence,
                    source: ProtocolDetectionSource::Port,
                    evidence: "well_known_port",
                })
            })
            .unwrap_or_else(Self::unknown)
    }

    pub fn merge(self, next: Self) -> Self {
        if next.service == "unknown" {
            return self;
        }
        if self.service == "unknown" {
            return next;
        }
        if self.service == next.service {
            return Self {
                service: self.service,
                side: merge_side(self.side, next.side),
                confidence: self
                    .confidence
                    .max(next.confidence)
                    .saturating_add(2)
                    .min(100),
                source: merge_source(self.source, next.source),
                evidence: next.evidence,
            };
        }
        if next.confidence >= self.confidence.saturating_add(8) {
            next
        } else {
            self
        }
    }
}

impl ProtocolDetectionSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Port => "port",
            Self::Payload => "payload",
            Self::PortAndPayload => "port_and_payload",
        }
    }
}

impl ProtocolServiceSide {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::B => "b",
            Self::Unknown => "unknown",
        }
    }
}

pub fn detect_payload(
    key: FlowKey,
    direction: FlowDirection,
    bytes: &[u8],
) -> Option<ProtocolDetection> {
    if bytes.is_empty() {
        return None;
    }

    let source_side = source_side(direction);
    let destination_side = destination_side(direction);
    let port_detection = ProtocolDetection::from_port(key);

    payload_rule(
        key.protocol,
        bytes,
        source_side,
        destination_side,
        port_detection.side,
    )
    .map(|payload| port_detection.merge(payload))
}

fn payload_rule(
    transport: TransportProtocol,
    bytes: &[u8],
    source_side: ProtocolServiceSide,
    destination_side: ProtocolServiceSide,
    port_side: ProtocolServiceSide,
) -> Option<ProtocolDetection> {
    if let Some(service) = detect_http(bytes, source_side, destination_side) {
        return Some(service);
    }
    if is_tls_record(bytes) {
        return Some(payload_detection(
            "tls",
            prefer_known_side(port_side, destination_side),
            98,
            "tls_record",
        ));
    }
    if bytes.starts_with(b"SSH-") {
        return Some(payload_detection("ssh", source_side, 98, "ssh_banner"));
    }
    if is_redis(bytes) {
        return Some(payload_detection(
            "redis",
            prefer_known_side(port_side, destination_side),
            96,
            "redis_resp",
        ));
    }
    if is_mysql_handshake(bytes) {
        return Some(payload_detection(
            "mysql",
            source_side,
            94,
            "mysql_handshake",
        ));
    }
    if is_postgres_startup(bytes) {
        return Some(payload_detection(
            "postgres",
            destination_side,
            92,
            "postgres_startup",
        ));
    }
    if is_mongodb(bytes) {
        return Some(payload_detection(
            "mongodb",
            prefer_known_side(port_side, destination_side),
            90,
            "mongodb_wire",
        ));
    }
    if is_memcached_ascii(bytes) {
        return Some(payload_detection(
            "memcached",
            prefer_known_side(port_side, destination_side),
            90,
            "memcached_ascii",
        ));
    }
    if is_dns_payload(transport, bytes) {
        return Some(payload_detection(
            "dns",
            dns_side(bytes, source_side, destination_side),
            91,
            "dns_header",
        ));
    }
    if matches!(transport, TransportProtocol::Udp) && is_quic_long_header(bytes) {
        return Some(payload_detection(
            "quic",
            prefer_known_side(port_side, destination_side),
            91,
            "quic_long_header",
        ));
    }
    if matches!(transport, TransportProtocol::Udp) && is_ntp(bytes) {
        return Some(payload_detection("ntp", destination_side, 90, "ntp_header"));
    }
    if is_smtp(bytes) {
        return Some(payload_detection(
            "smtp",
            prefer_known_side(port_side, source_side),
            88,
            "smtp_text",
        ));
    }
    if is_ftp(bytes) {
        return Some(payload_detection(
            "ftp",
            prefer_known_side(port_side, source_side),
            88,
            "ftp_text",
        ));
    }

    None
}

fn detect_http(
    bytes: &[u8],
    source_side: ProtocolServiceSide,
    destination_side: ProtocolServiceSide,
) -> Option<ProtocolDetection> {
    if bytes.starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") {
        return Some(payload_detection(
            "http2",
            destination_side,
            99,
            "http2_preface",
        ));
    }
    if looks_like_http_request(bytes) {
        if has_header_token(bytes, b"upgrade:", b"websocket") {
            return Some(payload_detection(
                "websocket",
                destination_side,
                99,
                "http_websocket_upgrade",
            ));
        }
        return Some(payload_detection(
            "http",
            destination_side,
            98,
            "http_request",
        ));
    }
    if bytes.starts_with(b"HTTP/1.") {
        return Some(payload_detection("http", source_side, 98, "http_response"));
    }
    None
}

fn payload_detection(
    service: &'static str,
    side: ProtocolServiceSide,
    confidence: u8,
    evidence: &'static str,
) -> ProtocolDetection {
    ProtocolDetection {
        service,
        side,
        confidence,
        source: ProtocolDetectionSource::Payload,
        evidence,
    }
}

fn known_service(protocol: TransportProtocol, port: u16) -> Option<(&'static str, u8)> {
    match (protocol, port) {
        (TransportProtocol::Tcp, 20 | 21) => Some(("ftp", 90)),
        (TransportProtocol::Tcp, 22) => Some(("ssh", 95)),
        (TransportProtocol::Udp, 67 | 68) => Some(("dhcp", 85)),
        (TransportProtocol::Tcp | TransportProtocol::Udp, 53) => Some(("dns", 95)),
        (TransportProtocol::Udp, 137) => Some(("netbios", 85)),
        (TransportProtocol::Udp, 123) => Some(("ntp", 85)),
        (TransportProtocol::Tcp, 80 | 8080 | 8000 | 8008 | 8081 | 8888) => Some(("http", 90)),
        (TransportProtocol::Tcp, 110 | 995) => Some(("pop3", 85)),
        (TransportProtocol::Tcp, 143 | 993) => Some(("imap", 85)),
        (TransportProtocol::Tcp, 443 | 8443) => Some(("tls", 90)),
        (TransportProtocol::Udp, 443 | 8443) => Some(("quic", 80)),
        (TransportProtocol::Tcp, 465 | 587 | 25) => Some(("smtp", 85)),
        (TransportProtocol::Udp, 1900) => Some(("ssdp", 85)),
        (TransportProtocol::Tcp, 3306) => Some(("mysql", 90)),
        (TransportProtocol::Tcp, 3389) => Some(("rdp", 90)),
        (TransportProtocol::Tcp, 5432) => Some(("postgres", 90)),
        (TransportProtocol::Udp, 5353) => Some(("mdns", 85)),
        (TransportProtocol::Udp, 5355) => Some(("llmnr", 85)),
        (TransportProtocol::Tcp, 6379) => Some(("redis", 90)),
        (TransportProtocol::Tcp | TransportProtocol::Udp, 11211) => Some(("memcached", 85)),
        (TransportProtocol::Tcp, 27017) => Some(("mongodb", 85)),
        _ => None,
    }
}

fn looks_like_http_request(bytes: &[u8]) -> bool {
    const METHODS: [&[u8]; 9] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"PATCH ",
        b"HEAD ",
        b"OPTIONS ",
        b"TRACE ",
        b"CONNECT ",
    ];
    METHODS.iter().any(|method| bytes.starts_with(method))
}

fn has_header_token(bytes: &[u8], header: &[u8], token: &[u8]) -> bool {
    let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let headers = &bytes[..header_end];
    headers.split(|byte| *byte == b'\n').any(|line| {
        let line = trim_ascii(line);
        line.len() >= header.len()
            && ascii_starts_with_ignore_case(line, header)
            && ascii_contains_ignore_case(line, token)
    })
}

fn is_tls_record(bytes: &[u8]) -> bool {
    bytes.len() >= 5
        && matches!(bytes[0], 0x14..=0x17)
        && bytes[1] == 0x03
        && bytes[2] <= 0x04
        && u16::from_be_bytes([bytes[3], bytes[4]]) != 0
}

fn is_redis(bytes: &[u8]) -> bool {
    matches!(bytes.first(), Some(b'*' | b'$' | b'+' | b'-' | b':'))
        && bytes.windows(2).any(|window| window == b"\r\n")
}

fn is_mysql_handshake(bytes: &[u8]) -> bool {
    bytes.len() >= 6 && bytes[0] == 0x0a && bytes[1..].windows(6).any(|w| w == b"mysql_")
}

fn is_postgres_startup(bytes: &[u8]) -> bool {
    if bytes.len() < 8 {
        return false;
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let version = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    len >= 8 && len <= bytes.len() && matches!(version, 196_608 | 80877103)
}

fn is_mongodb(bytes: &[u8]) -> bool {
    if bytes.len() < 16 {
        return false;
    }
    let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let opcode = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    len >= 16 && len <= bytes.len().saturating_add(16 * 1024) && matches!(opcode, 1 | 2001 | 2013)
}

fn is_memcached_ascii(bytes: &[u8]) -> bool {
    const COMMANDS: [&[u8]; 10] = [
        b"get ",
        b"gets ",
        b"set ",
        b"add ",
        b"replace ",
        b"append ",
        b"prepend ",
        b"delete ",
        b"incr ",
        b"decr ",
    ];
    COMMANDS
        .iter()
        .any(|command| ascii_starts_with_ignore_case(bytes, command))
}

fn is_dns_payload(transport: TransportProtocol, bytes: &[u8]) -> bool {
    let dns = match transport {
        TransportProtocol::Udp => bytes,
        TransportProtocol::Tcp if bytes.len() >= 14 => {
            let len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
            if len + 2 > bytes.len() || len < 12 {
                return false;
            }
            &bytes[2..]
        }
        _ => return false,
    };
    if dns.len() < 12 {
        return false;
    }
    let questions = u16::from_be_bytes([dns[4], dns[5]]);
    let answers = u16::from_be_bytes([dns[6], dns[7]]);
    let opcode = (dns[2] >> 3) & 0x0f;
    opcode <= 5 && questions != 0 && questions <= 64 && answers <= 512
}

fn dns_side(
    bytes: &[u8],
    source_side: ProtocolServiceSide,
    destination_side: ProtocolServiceSide,
) -> ProtocolServiceSide {
    let offset = if bytes.len() >= 14 {
        let tcp_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        usize::from(tcp_len + 2 <= bytes.len() && tcp_len >= 12) * 2
    } else {
        0
    };
    if bytes.get(offset + 2).is_some_and(|flags| flags & 0x80 != 0) {
        source_side
    } else {
        destination_side
    }
}

fn is_quic_long_header(bytes: &[u8]) -> bool {
    bytes.len() >= 6 && bytes[0] & 0xc0 == 0xc0 && bytes[1..5] != [0, 0, 0, 0]
}

fn is_ntp(bytes: &[u8]) -> bool {
    if bytes.len() < 48 {
        return false;
    }
    let mode = bytes[0] & 0x07;
    let version = (bytes[0] >> 3) & 0x07;
    (3..=4).contains(&mode) && (3..=4).contains(&version)
}

fn is_smtp(bytes: &[u8]) -> bool {
    const TOKENS: [&[u8]; 8] = [
        b"220 ",
        b"EHLO ",
        b"HELO ",
        b"MAIL FROM:",
        b"RCPT TO:",
        b"DATA\r\n",
        b"QUIT\r\n",
        b"STARTTLS\r\n",
    ];
    TOKENS
        .iter()
        .any(|token| ascii_starts_with_ignore_case(bytes, token))
}

fn is_ftp(bytes: &[u8]) -> bool {
    const TOKENS: [&[u8]; 8] = [
        b"220 ",
        b"USER ",
        b"PASS ",
        b"SYST\r\n",
        b"FEAT\r\n",
        b"PWD\r\n",
        b"TYPE ",
        b"PASV\r\n",
    ];
    TOKENS
        .iter()
        .any(|token| ascii_starts_with_ignore_case(bytes, token))
}

fn source_side(direction: FlowDirection) -> ProtocolServiceSide {
    match direction {
        FlowDirection::AToB => ProtocolServiceSide::A,
        FlowDirection::BToA => ProtocolServiceSide::B,
    }
}

fn destination_side(direction: FlowDirection) -> ProtocolServiceSide {
    match direction {
        FlowDirection::AToB => ProtocolServiceSide::B,
        FlowDirection::BToA => ProtocolServiceSide::A,
    }
}

fn prefer_known_side(
    known: ProtocolServiceSide,
    fallback: ProtocolServiceSide,
) -> ProtocolServiceSide {
    if known == ProtocolServiceSide::Unknown {
        fallback
    } else {
        known
    }
}

fn merge_side(left: ProtocolServiceSide, right: ProtocolServiceSide) -> ProtocolServiceSide {
    if left == ProtocolServiceSide::Unknown {
        right
    } else if right == ProtocolServiceSide::Unknown || left == right {
        left
    } else {
        right
    }
}

fn merge_source(
    left: ProtocolDetectionSource,
    right: ProtocolDetectionSource,
) -> ProtocolDetectionSource {
    match (left, right) {
        (ProtocolDetectionSource::Unknown, other) | (other, ProtocolDetectionSource::Unknown) => {
            other
        }
        (ProtocolDetectionSource::Port, ProtocolDetectionSource::Payload)
        | (ProtocolDetectionSource::Payload, ProtocolDetectionSource::Port)
        | (ProtocolDetectionSource::PortAndPayload, _)
        | (_, ProtocolDetectionSource::PortAndPayload) => ProtocolDetectionSource::PortAndPayload,
        (same, _) => same,
    }
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &bytes[start..end]
}

fn ascii_starts_with_ignore_case(bytes: &[u8], prefix: &[u8]) -> bool {
    bytes.len() >= prefix.len()
        && bytes[..prefix.len()]
            .iter()
            .zip(prefix)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn ascii_contains_ignore_case(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| ascii_starts_with_ignore_case(window, needle))
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use crate::flow::{Endpoint, FlowRoute};

    use super::*;

    #[test]
    fn detects_http_on_nonstandard_port() {
        let key = route(31_337, 40_000).key;
        let detection = detect_payload(
            key,
            FlowDirection::BToA,
            b"GET /flag HTTP/1.1\r\nHost: x\r\n\r\n",
        )
        .unwrap();

        assert_eq!("http", detection.service);
        assert_eq!(ProtocolServiceSide::A, detection.side);
        assert_eq!(ProtocolDetectionSource::Payload, detection.source);
        assert!(detection.confidence >= 98);
    }

    #[test]
    fn upgrades_http_to_websocket_from_headers() {
        let key = route(50_000, 80).key;
        let detection = detect_payload(
            key,
            FlowDirection::AToB,
            b"GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        )
        .unwrap();

        assert_eq!("websocket", detection.service);
        assert_eq!(ProtocolServiceSide::B, detection.side);
        assert_eq!(ProtocolDetectionSource::Payload, detection.source);
    }

    #[test]
    fn combines_port_and_tls_payload_evidence() {
        let key = route(50_000, 443).key;
        let detection = detect_payload(
            key,
            FlowDirection::AToB,
            &[0x16, 0x03, 0x01, 0x00, 0x2a, 1, 0, 0],
        )
        .unwrap();

        assert_eq!("tls", detection.service);
        assert_eq!(ProtocolServiceSide::B, detection.side);
        assert_eq!(ProtocolDetectionSource::PortAndPayload, detection.source);
    }

    #[test]
    fn detects_dns_queries_from_udp_payload() {
        let key = route_udp(40_000, 53).key;
        let detection = detect_payload(
            key,
            FlowDirection::AToB,
            &[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        )
        .unwrap();

        assert_eq!("dns", detection.service);
        assert_eq!(ProtocolServiceSide::B, detection.side);
    }

    #[test]
    fn keeps_more_specific_dns_like_port_service() {
        let key = route_udp(40_000, 5355).key;
        let detection = detect_payload(
            key,
            FlowDirection::AToB,
            &[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        )
        .unwrap();

        assert_eq!("llmnr", detection.service);
        assert_eq!(ProtocolDetectionSource::Port, detection.source);
    }

    fn route(source_port: u16, destination_port: u16) -> FlowRoute {
        FlowRoute::new(
            TransportProtocol::Tcp,
            endpoint("10.0.0.1", source_port),
            endpoint("10.0.0.2", destination_port),
        )
    }

    fn route_udp(source_port: u16, destination_port: u16) -> FlowRoute {
        FlowRoute::new(
            TransportProtocol::Udp,
            endpoint("10.0.0.1", source_port),
            endpoint("10.0.0.2", destination_port),
        )
    }

    fn endpoint(addr: &str, port: u16) -> Endpoint {
        Endpoint {
            addr: addr.parse::<IpAddr>().unwrap(),
            port,
        }
    }
}
