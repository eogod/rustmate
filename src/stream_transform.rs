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
    HttpChunked,
    HttpGzip,
    WebSocketDeflate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamTransformApplied {
    UrlDecode,
    Gzip,
    HttpChunked,
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
pub struct StreamTransformPlan {
    pub steps: Vec<StreamTransformMode>,
}

impl StreamTransformPlan {
    pub fn new(steps: Vec<StreamTransformMode>) -> Self {
        Self { steps }
    }

    pub fn single(mode: StreamTransformMode) -> Self {
        Self { steps: vec![mode] }
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

impl From<StreamTransformMode> for StreamTransformPlan {
    fn from(mode: StreamTransformMode) -> Self {
        Self::single(mode)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StreamTransformOutput {
    pub requested: StreamTransformMode,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requested_chain: Vec<StreamTransformMode>,
    pub applied: StreamTransformApplied,
    pub status: StreamTransformStatus,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub truncated_by_limit: bool,
    pub source_logical_start: Option<u64>,
    pub source_logical_end: Option<u64>,
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<StreamTransformStep>,
    pub segments: Vec<StreamTransformSegment>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StreamTransformStep {
    pub requested: StreamTransformMode,
    pub applied: StreamTransformApplied,
    pub status: StreamTransformStatus,
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub truncated_by_limit: bool,
    pub notes: Vec<String>,
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
    apply_transform_plan(slice, requested.into(), view_mode, config)
}

pub fn apply_transform_plan(
    slice: &StreamContentSlice,
    plan: StreamTransformPlan,
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
    let context = TransformOutputContext {
        input_bytes: input.len(),
        source_logical_start,
        source_logical_end,
        view_mode,
        config,
    };

    let requested_chain = plan.steps;
    let requested = requested_chain
        .first()
        .copied()
        .unwrap_or(StreamTransformMode::Auto);

    if requested_chain.is_empty() {
        return output_from_outcome(
            requested,
            Vec::new(),
            Vec::new(),
            TransformOutcome::noop("empty transform plan"),
            context,
        );
    }

    let mut current = input.clone();
    let mut steps = Vec::with_capacity(requested_chain.len());
    let mut notes = Vec::new();
    let mut applied = StreamTransformApplied::None;
    let mut applied_count = 0usize;
    let mut truncated_by_limit = false;
    let mut failed = false;

    for mode in &requested_chain {
        let input_bytes = current.len();
        let outcome = if requested_chain.len() > 1
            && *mode == StreamTransformMode::UrlDecode
            && !is_mostly_text(&current)
        {
            TransformOutcome::noop("chain URL decode was skipped for non-text input")
        } else {
            transform_step(&current, *mode, config.max_output_bytes)
        };
        let TransformOutcome {
            applied: step_applied,
            status,
            bytes,
            truncated_by_limit: step_truncated,
            notes: step_notes,
        } = outcome;
        let output_bytes = bytes.len();

        if !step_notes.is_empty() {
            notes.push(format!(
                "{}: {}",
                transform_mode_name(*mode),
                step_notes.join("; ")
            ));
        }

        if status == StreamTransformStatus::Applied {
            current = bytes;
            applied = step_applied;
            applied_count += 1;
            truncated_by_limit |= step_truncated;
        } else if status == StreamTransformStatus::Failed {
            failed = true;
        }

        steps.push(StreamTransformStep {
            requested: *mode,
            applied: step_applied,
            status,
            input_bytes,
            output_bytes,
            truncated_by_limit: step_truncated,
            notes: step_notes,
        });

        if failed {
            break;
        }
    }

    let status = if failed {
        StreamTransformStatus::Failed
    } else if applied_count == 0 {
        StreamTransformStatus::Noop
    } else {
        StreamTransformStatus::Applied
    };
    let bytes = if status == StreamTransformStatus::Applied {
        current
    } else {
        Vec::new()
    };
    let outcome = TransformOutcome {
        applied: if status == StreamTransformStatus::Applied {
            applied
        } else {
            StreamTransformApplied::None
        },
        status,
        bytes,
        truncated_by_limit,
        notes,
    };

    output_from_outcome(requested, requested_chain, steps, outcome, context)
}

fn transform_step(
    input: &[u8],
    requested: StreamTransformMode,
    max_output_bytes: usize,
) -> TransformOutcome {
    match requested {
        StreamTransformMode::Auto => auto_transform(input, max_output_bytes),
        StreamTransformMode::UrlDecode => url_decode_transform(input),
        StreamTransformMode::Gzip => {
            gzip_transform(input, max_output_bytes).map_applied(StreamTransformApplied::Gzip)
        }
        StreamTransformMode::HttpChunked => http_chunked_transform(input, max_output_bytes),
        StreamTransformMode::HttpGzip => http_gzip_transform(input, max_output_bytes),
        StreamTransformMode::WebSocketDeflate => {
            websocket_deflate_transform(input, max_output_bytes)
        }
    }
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

#[derive(Debug, Clone, Copy)]
struct TransformOutputContext {
    input_bytes: usize,
    source_logical_start: Option<u64>,
    source_logical_end: Option<u64>,
    view_mode: StreamSliceMode,
    config: StreamTransformConfig,
}

fn output_from_outcome(
    requested: StreamTransformMode,
    requested_chain: Vec<StreamTransformMode>,
    steps: Vec<StreamTransformStep>,
    outcome: TransformOutcome,
    context: TransformOutputContext,
) -> StreamTransformOutput {
    let segments = if outcome.status == StreamTransformStatus::Applied {
        vec![segment_from_bytes(
            context.source_logical_start,
            context.source_logical_end,
            &outcome.bytes,
            context.view_mode,
            context.config.hex_row_bytes,
        )]
    } else {
        Vec::new()
    };

    StreamTransformOutput {
        requested,
        requested_chain,
        applied: outcome.applied,
        status: outcome.status,
        input_bytes: context.input_bytes,
        output_bytes: outcome.bytes.len(),
        truncated_by_limit: outcome.truncated_by_limit,
        source_logical_start: context.source_logical_start,
        source_logical_end: context.source_logical_end,
        notes: outcome.notes,
        steps,
        segments,
    }
}

fn auto_transform(input: &[u8], max_output_bytes: usize) -> TransformOutcome {
    let chunked = http_chunked_transform(input, max_output_bytes);
    if chunked.status == StreamTransformStatus::Applied {
        return chunked;
    }

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
            incomplete,
        }) => TransformOutcome {
            applied: StreamTransformApplied::Gzip,
            status: StreamTransformStatus::Applied,
            bytes,
            truncated_by_limit,
            notes: incomplete
                .then(|| "gzip stream ended before trailer; decoded partial output".to_owned())
                .into_iter()
                .collect(),
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

fn http_chunked_transform(input: &[u8], max_output_bytes: usize) -> TransformOutcome {
    let Some((header_len, header_end)) = find_http_header_end(input) else {
        return TransformOutcome::noop("no complete HTTP header was found");
    };
    let Ok(header_text) = std::str::from_utf8(&input[..header_len]) else {
        return TransformOutcome::noop("HTTP header is not valid UTF-8");
    };
    if !looks_like_http_header(header_text) {
        return TransformOutcome::noop("slice does not look like an HTTP message");
    }
    if !header_has_chunked_transfer_encoding(header_text) {
        return TransformOutcome::noop("HTTP transfer-encoding is not chunked");
    }

    match decode_chunked_body(&input[header_end..], max_output_bytes) {
        Ok(decoded) if decoded.chunks != 0 || decoded.reached_last_chunk => {
            let mut bytes = Vec::with_capacity(header_end.saturating_add(decoded.bytes.len()));
            bytes.extend_from_slice(&input[..header_end]);
            bytes.extend_from_slice(&decoded.bytes);
            let mut notes = vec![format!("decoded {} HTTP chunks", decoded.chunks)];
            if decoded.partial {
                notes.push("chunked body is incomplete; decoded available chunk data".to_owned());
            }
            if decoded.reached_last_chunk && decoded.trailing_bytes != 0 {
                notes.push(format!("ignored {} trailer bytes", decoded.trailing_bytes));
            }
            TransformOutcome {
                applied: StreamTransformApplied::HttpChunked,
                status: StreamTransformStatus::Applied,
                bytes,
                truncated_by_limit: decoded.truncated_by_limit,
                notes,
            }
        }
        Ok(_) => TransformOutcome::noop("no HTTP chunk data was available"),
        Err(err) => TransformOutcome::failed(format!("HTTP chunked decode failed: {err}")),
    }
}

fn websocket_deflate_transform(input: &[u8], max_output_bytes: usize) -> TransformOutcome {
    let mut parser = WebSocketParser::new(input);
    let mut output = Vec::new();
    let mut current_message: Option<WebSocketMessageBuffer> = None;
    let mut decoded_messages = 0usize;
    let mut copied_messages = 0usize;
    let mut control_frames = 0usize;

    while let Some(frame) = match parser.next_frame() {
        Ok(frame) => frame,
        Err(err) => return TransformOutcome::failed(err),
    } {
        if !matches!(frame.opcode, 0x0..=0x2) {
            control_frames += 1;
            continue;
        }

        if frame.opcode == 0x0 {
            let Some(message) = current_message.as_mut() else {
                return TransformOutcome::failed(
                    "websocket continuation frame arrived without a message".to_owned(),
                );
            };
            message.payload.extend_from_slice(&frame.payload);
        } else {
            if current_message.is_some() {
                return TransformOutcome::failed(
                    "websocket data frame interrupted an unfinished fragmented message".to_owned(),
                );
            }
            current_message = Some(WebSocketMessageBuffer {
                compressed: frame.rsv1,
                payload: frame.payload,
            });
        }

        if frame.fin {
            let Some(message) = current_message.take() else {
                return TransformOutcome::failed("websocket message state is empty".to_owned());
            };
            if !output.is_empty() {
                append_limited(&mut output, b"\n", max_output_bytes);
            }
            if message.compressed {
                let mut payload = message.payload;
                payload.extend_from_slice(&[0x00, 0x00, 0xff, 0xff]);
                match read_limited(DeflateDecoder::new(payload.as_slice()), max_output_bytes) {
                    Ok(decoded) => {
                        append_limited(&mut output, &decoded.bytes, max_output_bytes);
                        decoded_messages += 1;
                    }
                    Err(err) => {
                        return TransformOutcome::failed(format!(
                            "websocket deflate message decode failed: {err}"
                        ));
                    }
                }
            } else {
                append_limited(&mut output, &message.payload, max_output_bytes);
                copied_messages += 1;
            }

            if output.len() >= max_output_bytes {
                return TransformOutcome {
                    applied: StreamTransformApplied::WebSocketDeflate,
                    status: StreamTransformStatus::Applied,
                    bytes: output,
                    truncated_by_limit: true,
                    notes: vec![websocket_note(
                        decoded_messages,
                        copied_messages,
                        control_frames,
                    )],
                };
            }
        }
    }

    if current_message.is_some() {
        return TransformOutcome::failed("truncated fragmented websocket message".to_owned());
    }

    if decoded_messages == 0 {
        return TransformOutcome::noop("no compressed websocket messages were found");
    }

    TransformOutcome {
        applied: StreamTransformApplied::WebSocketDeflate,
        status: StreamTransformStatus::Applied,
        bytes: output,
        truncated_by_limit: false,
        notes: vec![websocket_note(
            decoded_messages,
            copied_messages,
            control_frames,
        )],
    }
}

#[derive(Debug)]
struct WebSocketFrame {
    fin: bool,
    opcode: u8,
    rsv1: bool,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct WebSocketMessageBuffer {
    compressed: bool,
    payload: Vec<u8>,
}

fn websocket_note(
    decoded_messages: usize,
    copied_messages: usize,
    control_frames: usize,
) -> String {
    format!(
        "decoded {decoded_messages} compressed websocket messages, copied {copied_messages} plain messages, skipped {control_frames} control frames"
    )
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

        let fin = first & 0x80 != 0;
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
            fin,
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
    incomplete: bool,
}

fn read_limited<R: Read>(mut reader: R, max_output_bytes: usize) -> io::Result<LimitedRead> {
    let mut bytes = Vec::with_capacity(max_output_bytes.min(64 * 1024));
    let mut chunk = [0u8; 8192];
    let mut truncated_by_limit = false;
    let mut incomplete = false;

    loop {
        let read = match reader.read(&mut chunk) {
            Ok(read) => read,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof && !bytes.is_empty() => {
                incomplete = true;
                break;
            }
            Err(err) => return Err(err),
        };
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
            truncated_by_limit = match reader.read(&mut probe) {
                Ok(read) => read != 0,
                Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                    incomplete = true;
                    false
                }
                Err(err) => return Err(err),
            };
            break;
        }
    }

    Ok(LimitedRead {
        bytes,
        truncated_by_limit,
        incomplete,
    })
}

fn append_limited(out: &mut Vec<u8>, bytes: &[u8], max_output_bytes: usize) {
    let remaining = max_output_bytes.saturating_sub(out.len());
    out.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
}

#[derive(Debug)]
struct ChunkedDecode {
    bytes: Vec<u8>,
    chunks: usize,
    truncated_by_limit: bool,
    partial: bool,
    reached_last_chunk: bool,
    trailing_bytes: usize,
}

fn decode_chunked_body(input: &[u8], max_output_bytes: usize) -> Result<ChunkedDecode, String> {
    let mut bytes = Vec::with_capacity(max_output_bytes.min(input.len()));
    let mut offset = 0usize;
    let mut chunks = 0usize;
    let mut truncated_by_limit = false;
    let mut partial = false;
    let mut reached_last_chunk = false;
    let mut trailing_bytes = 0usize;

    loop {
        let Some((line_end, next_offset)) = find_line_end(input, offset) else {
            partial = offset < input.len();
            break;
        };
        let line = trim_ascii(&input[offset..line_end]);
        if line.is_empty() {
            return Err("empty chunk size line".to_owned());
        }
        let size = parse_chunk_size(line)?;
        offset = next_offset;

        if size == 0 {
            reached_last_chunk = true;
            trailing_bytes = input.len().saturating_sub(offset);
            break;
        }

        let available = input.len().saturating_sub(offset);
        let take = size.min(available);
        let before = bytes.len();
        append_limited(&mut bytes, &input[offset..offset + take], max_output_bytes);
        truncated_by_limit |= bytes.len().saturating_sub(before) < take;
        chunks += 1;
        offset += take;

        if take < size {
            partial = true;
            break;
        }

        if input.get(offset..offset + 2) == Some(b"\r\n") {
            offset += 2;
        } else if input.get(offset) == Some(&b'\n') {
            offset += 1;
        } else if offset == input.len() {
            partial = true;
            break;
        } else {
            return Err("chunk payload is not followed by CRLF".to_owned());
        }

        if bytes.len() >= max_output_bytes {
            truncated_by_limit = offset < input.len();
            break;
        }
    }

    Ok(ChunkedDecode {
        bytes,
        chunks,
        truncated_by_limit,
        partial,
        reached_last_chunk,
        trailing_bytes,
    })
}

fn find_line_end(input: &[u8], offset: usize) -> Option<(usize, usize)> {
    input[offset..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|relative| {
            let newline = offset + relative;
            let line_end = if newline > offset && input[newline - 1] == b'\r' {
                newline - 1
            } else {
                newline
            };
            (line_end, newline + 1)
        })
}

fn parse_chunk_size(line: &[u8]) -> Result<usize, String> {
    let size = line
        .split(|byte| *byte == b';')
        .next()
        .map(trim_ascii)
        .unwrap_or_default();
    let size = std::str::from_utf8(size).map_err(|_| "chunk size is not UTF-8".to_owned())?;
    usize::from_str_radix(size, 16).map_err(|_| format!("invalid chunk size: {size}"))
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map(|index| index + 1)
        .unwrap_or(start);
    &bytes[start..end]
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

fn header_has_chunked_transfer_encoding(header: &str) -> bool {
    header.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        name.trim().eq_ignore_ascii_case("transfer-encoding")
            && value
                .split(',')
                .any(|encoding| encoding.trim().eq_ignore_ascii_case("chunked"))
    })
}

fn transform_mode_name(mode: StreamTransformMode) -> &'static str {
    match mode {
        StreamTransformMode::Auto => "auto",
        StreamTransformMode::UrlDecode => "url_decode",
        StreamTransformMode::Gzip => "gzip",
        StreamTransformMode::HttpChunked => "http_chunked",
        StreamTransformMode::HttpGzip => "http_gzip",
        StreamTransformMode::WebSocketDeflate => "websocket_deflate",
    }
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
    fn decodes_http_chunked_body() {
        let mut message = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        message.extend_from_slice(&chunked_body(&[
            b"hello".as_slice(),
            b" chunked".as_slice(),
        ]));
        let slice = test_slice(&message);
        let output = apply_transform(
            &slice,
            StreamTransformMode::HttpChunked,
            StreamSliceMode::Text,
            config(),
        );

        assert_eq!(StreamTransformStatus::Applied, output.status);
        assert_eq!(StreamTransformApplied::HttpChunked, output.applied);
        match &output.segments[0].view {
            StreamTransformSegmentView::Text { text, .. } => {
                assert!(text.contains("hello chunked"));
                assert!(!text.contains("\r\n0\r\n"));
            }
            _ => panic!("expected text transform"),
        }
    }

    #[test]
    fn transform_plan_decodes_chunked_gzip_url_encoded_http() {
        let body = gzip_bytes(b"flag%7Bok%7D+done");
        let mut message =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n"
                .to_vec();
        message.extend_from_slice(&chunked_body(&[body.as_slice()]));
        let slice = test_slice(&message);
        let output = apply_transform_plan(
            &slice,
            StreamTransformPlan::new(vec![
                StreamTransformMode::HttpChunked,
                StreamTransformMode::HttpGzip,
                StreamTransformMode::UrlDecode,
            ]),
            StreamSliceMode::Text,
            config(),
        );

        assert_eq!(StreamTransformStatus::Applied, output.status);
        assert_eq!(StreamTransformApplied::UrlDecode, output.applied);
        assert_eq!(3, output.steps.len());
        assert!(
            output
                .steps
                .iter()
                .all(|step| step.status == StreamTransformStatus::Applied)
        );
        match &output.segments[0].view {
            StreamTransformSegmentView::Text { text, .. } => {
                assert!(text.contains("flag{ok} done"));
            }
            _ => panic!("expected text transform"),
        }
    }

    #[test]
    fn gzip_decodes_output_without_trailer() {
        let mut compressed = gzip_bytes(&[b'a'; 4096]);
        compressed.truncate(compressed.len() - 8);
        let slice = test_slice(&compressed);
        let output = apply_transform(
            &slice,
            StreamTransformMode::Gzip,
            StreamSliceMode::Text,
            config(),
        );

        assert_eq!(StreamTransformStatus::Applied, output.status);
        assert!(output.output_bytes > 0);
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

    fn chunked_body(chunks: &[&[u8]]) -> Vec<u8> {
        let mut body = Vec::new();
        for chunk in chunks {
            write!(&mut body, "{:x}\r\n", chunk.len()).unwrap();
            body.extend_from_slice(chunk);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(b"0\r\n\r\n");
        body
    }

    fn config() -> StreamTransformConfig {
        StreamTransformConfig {
            max_output_bytes: 1024,
            hex_row_bytes: 16,
        }
    }
}
