use std::io::{self, Read};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use flate2::read::{DeflateDecoder, GzDecoder};
use serde::Serialize;

use crate::stream_slice::{StreamContentSlice, StreamSliceHexRow, StreamSliceMode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamTransformConfig {
    pub max_output_bytes: usize,
    pub hex_row_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamTransformMode {
    Auto,
    UrlDecode,
    Gzip,
    HttpGzip,
    WebSocketDeflate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamTransformApplied {
    UrlDecode,
    Gzip,
    HttpGzip,
    WebSocketDeflate,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamTransformStatus {
    Applied,
    Noop,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StreamTransformOutput {
    pub requested: StreamTransformMode,
    pub applied: StreamTransformApplied,
    pub status: StreamTransformStatus,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub truncated_by_limit: bool,
    pub source_logical_start: Option<u64>,
    pub source_logical_end: Option<u64>,
    pub notes: Vec<String>,
    pub segments: Vec<StreamTransformSegment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StreamTransformSegment {
    pub source_logical_start: Option<u64>,
    pub source_logical_end: Option<u64>,
    pub bytes_len: usize,
    pub base64: String,
    pub view: StreamTransformSegmentView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StreamTransformSegmentView {
    Raw { base64: String },
    Text { text: String, lossy: bool },
    Hex { rows: Vec<StreamSliceHexRow> },
}

pub fn apply_transform(
    slice: &StreamContentSlice,
    requested: StreamTransformMode,
    view_mode: StreamSliceMode,
    config: StreamTransformConfig,
) -> StreamTransformOutput {
    let input = slice.concatenated_bytes();
    let source_logical_start = slice.segments.first().map(|segment| segment.logical_start);
    let source_logical_end = slice.segments.last().map(|segment| segment.logical_end);
    let config = StreamTransformConfig {
        max_output_bytes: config.max_output_bytes.max(1),
        hex_row_bytes: config.hex_row_bytes.clamp(1, 64),
    };

    let outcome = match requested {
        StreamTransformMode::Auto => auto_transform(&input, config.max_output_bytes),
        StreamTransformMode::UrlDecode => url_decode_transform(&input),
        StreamTransformMode::Gzip => gzip_transform(&input, config.max_output_bytes)
            .map_applied(StreamTransformApplied::Gzip),
        StreamTransformMode::HttpGzip => http_gzip_transform(&input, config.max_output_bytes),
        StreamTransformMode::WebSocketDeflate => {
            websocket_deflate_transform(&input, config.max_output_bytes)
        }
    };

    output_from_outcome(
        requested,
        outcome,
        input.len(),
        source_logical_start,
        source_logical_end,
        view_mode,
        config,
    )
}

#[derive(Debug)]
struct TransformOutcome {
    applied: StreamTransformApplied,
    status: StreamTransformStatus,
    bytes: Vec<u8>,
    truncated_by_limit: bool,
    notes: Vec<String>,
}

impl TransformOutcome {
    fn noop(note: impl Into<String>) -> Self {
        Self {
            applied: StreamTransformApplied::None,
            status: StreamTransformStatus::Noop,
            bytes: Vec::new(),
            truncated_by_limit: false,
            notes: vec![note.into()],
        }
    }

    fn failed(note: impl Into<String>) -> Self {
        Self {
            applied: StreamTransformApplied::None,
            status: StreamTransformStatus::Failed,
            bytes: Vec::new(),
            truncated_by_limit: false,
            notes: vec![note.into()],
        }
    }

    fn map_applied(mut self, applied: StreamTransformApplied) -> Self {
        if self.status == StreamTransformStatus::Applied {
            self.applied = applied;
        }
        self
    }
}

fn output_from_outcome(
    requested: StreamTransformMode,
    outcome: TransformOutcome,
    input_bytes: usize,
    source_logical_start: Option<u64>,
    source_logical_end: Option<u64>,
    view_mode: StreamSliceMode,
    config: StreamTransformConfig,
) -> StreamTransformOutput {
    let segments = if outcome.status == StreamTransformStatus::Applied {
        vec![segment_from_bytes(
            source_logical_start,
            source_logical_end,
            &outcome.bytes,
            view_mode,
            config.hex_row_bytes,
        )]
    } else {
        Vec::new()
    };

    StreamTransformOutput {
        requested,
        applied: outcome.applied,
        status: outcome.status,
        input_bytes,
        output_bytes: outcome.bytes.len(),
        truncated_by_limit: outcome.truncated_by_limit,
        source_logical_start,
        source_logical_end,
        notes: outcome.notes,
        segments,
    }
}

fn auto_transform(input: &[u8], max_output_bytes: usize) -> TransformOutcome {
    let http = http_gzip_transform(input, max_output_bytes);
    if http.status == StreamTransformStatus::Applied {
        return http;
    }

    if is_gzip(input) {
        let gzip =
            gzip_transform(input, max_output_bytes).map_applied(StreamTransformApplied::Gzip);
        if gzip.status == StreamTransformStatus::Applied {
            return gzip;
        }
    }

    let websocket = websocket_deflate_transform(input, max_output_bytes);
    if websocket.status == StreamTransformStatus::Applied {
        return websocket;
    }

    if looks_like_url_encoded_text(input) {
        let url = url_decode_transform(input);
        if url.status == StreamTransformStatus::Applied {
            return url;
        }
    }

    TransformOutcome::noop("no supported transform was detected")
}

fn url_decode_transform(input: &[u8]) -> TransformOutcome {
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0usize;
    let mut changed = false;
    let mut invalid_escapes = 0usize;

    while index < input.len() {
        match input[index] {
            b'%' if index + 2 < input.len() => {
                let hi = hex_value(input[index + 1]);
                let lo = hex_value(input[index + 2]);
                if let (Some(hi), Some(lo)) = (hi, lo) {
                    output.push((hi << 4) | lo);
                    changed = true;
                    index += 3;
                } else {
                    output.push(input[index]);
                    invalid_escapes += 1;
                    index += 1;
                }
            }
            b'%' => {
                output.push(input[index]);
                invalid_escapes += 1;
                index += 1;
            }
            b'+' => {
                output.push(b' ');
                changed = true;
                index += 1;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }

    if !changed {
        return TransformOutcome::noop("no URL-encoded bytes were found");
    }

    let mut notes = Vec::new();
    if invalid_escapes != 0 {
        notes.push(format!(
            "left {invalid_escapes} invalid percent escapes unchanged"
        ));
    }

    TransformOutcome {
        applied: StreamTransformApplied::UrlDecode,
        status: StreamTransformStatus::Applied,
        bytes: output,
        truncated_by_limit: false,
        notes,
    }
}

fn gzip_transform(input: &[u8], max_output_bytes: usize) -> TransformOutcome {
    if !is_gzip(input) {
        return TransformOutcome::noop("input does not start with a gzip header");
    }

    match read_limited(GzDecoder::new(input), max_output_bytes) {
        Ok(LimitedRead {
            bytes,
            truncated_by_limit,
        }) => TransformOutcome {
            applied: StreamTransformApplied::Gzip,
            status: StreamTransformStatus::Applied,
            bytes,
            truncated_by_limit,
            notes: Vec::new(),
        },
        Err(err) => TransformOutcome::failed(format!("gzip decode failed: {err}")),
    }
}

fn http_gzip_transform(input: &[u8], max_output_bytes: usize) -> TransformOutcome {
    let Some((header_len, header_end)) = find_http_header_end(input) else {
        return TransformOutcome::noop("no complete HTTP header was found");
    };
    let Ok(header_text) = std::str::from_utf8(&input[..header_len]) else {
        return TransformOutcome::noop("HTTP header is not valid UTF-8");
    };
    if !looks_like_http_header(header_text) {
        return TransformOutcome::noop("slice does not look like an HTTP message");
    }
    if !header_has_gzip_content_encoding(header_text) {
        return TransformOutcome::noop("HTTP content-encoding is not gzip");
    }

    let body = &input[header_end..];
    let decoded = gzip_transform(body, max_output_bytes);
    if decoded.status != StreamTransformStatus::Applied {
        return TransformOutcome::failed(
            decoded
                .notes
                .first()
                .cloned()
                .unwrap_or_else(|| "gzip HTTP body decode failed".to_owned()),
        );
    }

    let mut bytes = Vec::with_capacity(header_end.saturating_add(decoded.bytes.len()));
    bytes.extend_from_slice(&input[..header_end]);
    bytes.extend_from_slice(&decoded.bytes);
    let mut notes = decoded.notes;
    notes.push(format!(
        "decoded gzip HTTP body after {header_end} header bytes"
    ));

    TransformOutcome {
        applied: StreamTransformApplied::HttpGzip,
        status: StreamTransformStatus::Applied,
        bytes,
        truncated_by_limit: decoded.truncated_by_limit,
        notes,
    }
}

fn websocket_deflate_transform(input: &[u8], max_output_bytes: usize) -> TransformOutcome {
    let mut parser = WebSocketParser::new(input);
    let mut output = Vec::new();
    let mut decoded_frames = 0usize;
    let mut copied_frames = 0usize;

    while let Some(frame) = match parser.next_frame() {
        Ok(frame) => frame,
        Err(err) => return TransformOutcome::failed(err),
    } {
        if !matches!(frame.opcode, 0x0..=0x2) {
            continue;
        }

        if !output.is_empty() {
            output.push(b'\n');
        }

        if frame.rsv1 {
            let mut payload = frame.payload;
            payload.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);
            match read_limited(DeflateDecoder::new(payload.as_slice()), max_output_bytes) {
                Ok(decoded) => {
                    append_limited(&mut output, &decoded.bytes, max_output_bytes);
                    decoded_frames += 1;
                    if decoded.truncated_by_limit || output.len() >= max_output_bytes {
                        return TransformOutcome {
                            applied: StreamTransformApplied::WebSocketDeflate,
                            status: StreamTransformStatus::Applied,
                            bytes: output,
                            truncated_by_limit: true,
                            notes: vec![format!(
                                "decoded {decoded_frames} compressed websocket frames"
                            )],
                        };
                    }
                }
                Err(err) => {
                    return TransformOutcome::failed(format!(
                        "websocket deflate frame decode failed: {err}"
                    ));
                }
            }
        } else {
            append_limited(&mut output, &frame.payload, max_output_bytes);
            copied_frames += 1;
        }

        if output.len() >= max_output_bytes {
            return TransformOutcome {
                applied: StreamTransformApplied::WebSocketDeflate,
                status: StreamTransformStatus::Applied,
                bytes: output,
                truncated_by_limit: true,
                notes: vec![format!(
                    "decoded {decoded_frames} compressed websocket frames and copied {copied_frames} plain frames"
                )],
            };
        }
    }

    if decoded_frames == 0 {
        return TransformOutcome::noop("no compressed websocket frames were found");
    }

    TransformOutcome {
        applied: StreamTransformApplied::WebSocketDeflate,
        status: StreamTransformStatus::Applied,
        bytes: output,
        truncated_by_limit: false,
        notes: vec![format!(
            "decoded {decoded_frames} compressed websocket frames and copied {copied_frames} plain frames"
        )],
    }
}

#[derive(Debug)]
struct WebSocketFrame {
    opcode: u8,
    rsv1: bool,
    payload: Vec<u8>,
}

struct WebSocketParser<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> WebSocketParser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn next_frame(&mut self) -> Result<Option<WebSocketFrame>, String> {
        if self.offset == self.input.len() {
            return Ok(None);
        }
        if self.input.len().saturating_sub(self.offset) < 2 {
            return Err("truncated websocket frame header".to_owned());
        }

        let first = self.input[self.offset];
        let second = self.input[self.offset + 1];
        self.offset += 2;

        let rsv1 = first & 0x40 != 0;
        let opcode = first & 0x0f;
        let masked = second & 0x80 != 0;
        let mut payload_len = u64::from(second & 0x7f);

        if payload_len == 126 {
            payload_len = u64::from(self.read_u16()?);
        } else if payload_len == 127 {
            payload_len = self.read_u64()?;
        }

        if payload_len > usize::MAX as u64 {
            return Err("websocket frame payload is too large for this platform".to_owned());
        }
        let payload_len = payload_len as usize;

        let mask = if masked {
            Some(self.read_array::<4>()?)
        } else {
            None
        };

        if self.input.len().saturating_sub(self.offset) < payload_len {
            return Err("truncated websocket frame payload".to_owned());
        }
        let mut payload = self.input[self.offset..self.offset + payload_len].to_vec();
        self.offset += payload_len;

        if let Some(mask) = mask {
            for (index, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[index % 4];
            }
        }

        Ok(Some(WebSocketFrame {
            opcode,
            rsv1,
            payload,
        }))
    }

    fn read_u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_be_bytes(self.read_array::<2>()?))
    }

    fn read_u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_be_bytes(self.read_array::<8>()?))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        if self.input.len().saturating_sub(self.offset) < N {
            return Err("truncated websocket frame length or mask".to_owned());
        }
        let bytes = self.input[self.offset..self.offset + N]
            .try_into()
            .map_err(|_| "failed to read websocket frame bytes".to_owned())?;
        self.offset += N;
        Ok(bytes)
    }
}

struct LimitedRead {
    bytes: Vec<u8>,
    truncated_by_limit: bool,
}

fn read_limited<R: Read>(mut reader: R, max_output_bytes: usize) -> io::Result<LimitedRead> {
    let mut bytes = Vec::with_capacity(max_output_bytes.min(64 * 1024));
    let mut chunk = [0u8; 8192];
    let mut truncated_by_limit = false;

    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }

        let remaining = max_output_bytes.saturating_sub(bytes.len());
        if read > remaining {
            bytes.extend_from_slice(&chunk[..remaining]);
            truncated_by_limit = true;
            break;
        }
        bytes.extend_from_slice(&chunk[..read]);

        if bytes.len() == max_output_bytes {
            let mut probe = [0u8; 1];
            truncated_by_limit = reader.read(&mut probe)? != 0;
            break;
        }
    }

    Ok(LimitedRead {
        bytes,
        truncated_by_limit,
    })
}

fn append_limited(out: &mut Vec<u8>, bytes: &[u8], max_output_bytes: usize) {
    let remaining = max_output_bytes.saturating_sub(out.len());
    out.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
}

fn segment_from_bytes(
    source_logical_start: Option<u64>,
    source_logical_end: Option<u64>,
    bytes: &[u8],
    mode: StreamSliceMode,
    hex_row_bytes: usize,
) -> StreamTransformSegment {
    let base64 = STANDARD.encode(bytes);
    StreamTransformSegment {
        source_logical_start,
        source_logical_end,
        bytes_len: bytes.len(),
        base64: base64.clone(),
        view: match mode {
            StreamSliceMode::Raw => StreamTransformSegmentView::Raw { base64 },
            StreamSliceMode::Text => {
                let text = safe_text(bytes);
                StreamTransformSegmentView::Text {
                    text: text.text,
                    lossy: text.lossy,
                }
            }
            StreamSliceMode::Hex => StreamTransformSegmentView::Hex {
                rows: hex_rows(source_logical_start.unwrap_or(0), bytes, hex_row_bytes),
            },
        },
    }
}

fn find_http_header_end(bytes: &[u8]) -> Option<(usize, usize)> {
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

fn looks_like_http_header(header: &str) -> bool {
    let Some(line) = header.lines().next() else {
        return false;
    };
    line.starts_with("HTTP/")
        || line
            .split_ascii_whitespace()
            .nth(2)
            .is_some_and(|v| v.starts_with("HTTP/"))
}

fn header_has_gzip_content_encoding(header: &str) -> bool {
    header.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.trim().eq_ignore_ascii_case("content-encoding")
            && value
                .split(',')
                .any(|encoding| encoding.trim().eq_ignore_ascii_case("gzip"))
    })
}

fn is_gzip(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x1f, 0x8b])
}

fn looks_like_url_encoded_text(bytes: &[u8]) -> bool {
    has_valid_percent_escape(bytes) && is_mostly_text(bytes)
}

fn has_valid_percent_escape(bytes: &[u8]) -> bool {
    bytes.windows(3).any(|window| {
        window[0] == b'%' && hex_value(window[1]).is_some() && hex_value(window[2]).is_some()
    })
}

fn is_mostly_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }

    let sample_len = bytes.len().min(4096);
    let textish = bytes[..sample_len]
        .iter()
        .filter(|byte| matches!(**byte, b'\n' | b'\r' | b'\t' | 0x20..=0x7e))
        .count();
    textish.saturating_mul(100) >= sample_len.saturating_mul(85)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

struct SafeText {
    text: String,
    lossy: bool,
}

fn safe_text(bytes: &[u8]) -> SafeText {
    let mut text = String::with_capacity(bytes.len());
    let mut lossy = false;
    for byte in bytes {
        match *byte {
            b'\n' => text.push('\n'),
            b'\r' => text.push('\r'),
            b'\t' => text.push('\t'),
            0x20..=0x7e => text.push(*byte as char),
            _ => {
                text.push('.');
                lossy = true;
            }
        }
    }
    SafeText { text, lossy }
}

fn hex_rows(logical_start: u64, bytes: &[u8], row_bytes: usize) -> Vec<StreamSliceHexRow> {
    bytes
        .chunks(row_bytes)
        .enumerate()
        .map(|(row_index, row)| StreamSliceHexRow {
            logical_start: logical_start.saturating_add((row_index * row_bytes) as u64),
            hex: bytes_to_hex(row),
            ascii: row
                .iter()
                .map(|byte| match *byte {
                    0x20..=0x7e => *byte as char,
                    _ => '.',
                })
                .collect(),
        })
        .collect()
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(3).saturating_sub(1));
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            out.push(' ');
        }
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{flow::FlowDirection, stream_slice::StreamContentSlice};
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    #[test]
    fn decodes_url_encoded_bytes() {
        let slice = test_slice(b"GET /?q=flag%7Bok%7D+a");
        let output = apply_transform(
            &slice,
            StreamTransformMode::UrlDecode,
            StreamSliceMode::Text,
            config(),
        );

        assert_eq!(StreamTransformStatus::Applied, output.status);
        assert_eq!(StreamTransformApplied::UrlDecode, output.applied);
        match &output.segments[0].view {
            StreamTransformSegmentView::Text { text, .. } => {
                assert_eq!("GET /?q=flag{ok} a", text);
            }
            _ => panic!("expected text transform"),
        }
    }

    #[test]
    fn auto_url_decode_requires_text_like_input() {
        let slice = test_slice(b"\x16\x03\x03\x00%7B\x00\xff\x01%7D");
        let output = apply_transform(
            &slice,
            StreamTransformMode::Auto,
            StreamSliceMode::Text,
            config(),
        );

        assert_eq!(StreamTransformStatus::Noop, output.status);
        assert_eq!(StreamTransformApplied::None, output.applied);
    }

    #[test]
    fn auto_decodes_text_url_encoded_bytes() {
        let slice = test_slice(b"POST /x?q=flag%7Bok%7D HTTP/1.1\r\n\r\n");
        let output = apply_transform(
            &slice,
            StreamTransformMode::Auto,
            StreamSliceMode::Text,
            config(),
        );

        assert_eq!(StreamTransformStatus::Applied, output.status);
        assert_eq!(StreamTransformApplied::UrlDecode, output.applied);
    }

    #[test]
    fn decodes_gzip_bytes() {
        let compressed = gzip_bytes(b"hello gzip");
        let slice = test_slice(&compressed);
        let output = apply_transform(
            &slice,
            StreamTransformMode::Gzip,
            StreamSliceMode::Text,
            config(),
        );

        assert_eq!(StreamTransformStatus::Applied, output.status);
        assert_eq!(StreamTransformApplied::Gzip, output.applied);
        assert_eq!(b"hello gzip".len(), output.output_bytes);
    }

    #[test]
    fn decodes_http_gzip_body() {
        let body = gzip_bytes(b"decoded body");
        let mut message = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n".to_vec();
        message.extend_from_slice(&body);
        let slice = test_slice(&message);
        let output = apply_transform(
            &slice,
            StreamTransformMode::HttpGzip,
            StreamSliceMode::Text,
            config(),
        );

        assert_eq!(StreamTransformStatus::Applied, output.status);
        assert_eq!(StreamTransformApplied::HttpGzip, output.applied);
        match &output.segments[0].view {
            StreamTransformSegmentView::Text { text, .. } => {
                assert!(text.contains("decoded body"));
            }
            _ => panic!("expected text transform"),
        }
    }

    #[test]
    fn caps_gzip_output() {
        let compressed = gzip_bytes(&[b'a'; 128]);
        let slice = test_slice(&compressed);
        let output = apply_transform(
            &slice,
            StreamTransformMode::Gzip,
            StreamSliceMode::Text,
            StreamTransformConfig {
                max_output_bytes: 16,
                hex_row_bytes: 16,
            },
        );

        assert_eq!(16, output.output_bytes);
        assert!(output.truncated_by_limit);
    }

    fn test_slice(bytes: &[u8]) -> StreamContentSlice {
        StreamContentSlice {
            stream_id: 1,
            stream_id_hex: "0000000000000001".to_owned(),
            direction: FlowDirection::AToB,
            requested_start: 0,
            requested_end: bytes.len() as u64,
            returned_bytes: bytes.len(),
            truncated_by_limit: false,
            segments: vec![crate::stream_slice::StreamSliceSegment {
                logical_start: 0,
                logical_end: bytes.len() as u64,
                bytes_len: bytes.len(),
                base64: STANDARD.encode(bytes),
                view: crate::stream_slice::StreamSliceSegmentView::Raw {
                    base64: STANDARD.encode(bytes),
                },
            }],
            highlights: Vec::new(),
            dropped_highlights: 0,
            transforms: Vec::new(),
        }
    }

    fn gzip_bytes(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn config() -> StreamTransformConfig {
        StreamTransformConfig {
            max_output_bytes: 1024,
            hex_row_bytes: 16,
        }
    }
}
