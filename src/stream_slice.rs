use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;

use crate::{
    flow::FlowDirection,
    stream_content::{StreamContent, StreamContentWindow},
    stream_transform::StreamTransformOutput,
    stream_view::{StreamPatternMatch, StreamPatternType, StreamViewState},
};

const DEFAULT_HEX_ROW_BYTES: usize = 16;

#[derive(Debug, Clone, Copy)]
pub struct StreamSliceConfig {
    pub max_slice_bytes: usize,
    pub max_highlights: usize,
    pub hex_row_bytes: usize,
    pub max_transform_bytes: usize,
}

impl Default for StreamSliceConfig {
    fn default() -> Self {
        Self {
            max_slice_bytes: 64 * 1024,
            max_highlights: 4096,
            hex_row_bytes: DEFAULT_HEX_ROW_BYTES,
            max_transform_bytes: 1024 * 1024,
        }
    }
}

impl StreamSliceConfig {
    pub fn normalized(self) -> Self {
        Self {
            max_slice_bytes: self.max_slice_bytes.max(1),
            max_highlights: self.max_highlights,
            hex_row_bytes: self.hex_row_bytes.clamp(1, 64),
            max_transform_bytes: self.max_transform_bytes.max(1),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamSliceRequest {
    pub stream_id: u64,
    pub direction: FlowDirection,
    pub logical_start: u64,
    pub max_bytes: usize,
    pub mode: StreamSliceMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamSliceMode {
    Raw,
    Text,
    Hex,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StreamContentSlice {
    pub stream_id: u64,
    pub stream_id_hex: String,
    pub direction: FlowDirection,
    pub requested_start: u64,
    pub requested_end: u64,
    pub returned_bytes: usize,
    pub truncated_by_limit: bool,
    pub segments: Vec<StreamSliceSegment>,
    pub highlights: Vec<StreamSliceHighlight>,
    pub dropped_highlights: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub transforms: Vec<StreamTransformOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StreamSliceSegment {
    pub logical_start: u64,
    pub logical_end: u64,
    pub bytes_len: usize,
    pub base64: String,
    pub view: StreamSliceSegmentView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StreamSliceSegmentView {
    Raw { base64: String },
    Text { text: String, lossy: bool },
    Hex { rows: Vec<StreamSliceHexRow> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StreamSliceHexRow {
    pub logical_start: u64,
    pub hex: String,
    pub ascii: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StreamSliceHighlight {
    pub stream_id: u64,
    pub pattern_id: String,
    pub pattern_name: String,
    pub pattern_type: StreamPatternType,
    pub direction: FlowDirection,
    pub logical_start: u64,
    pub logical_end: u64,
    pub segment_index: usize,
    pub segment_start: usize,
    pub segment_end: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamSliceError {
    StreamNotFound { stream_id: u64 },
    ContentNotFound { stream_id: u64 },
    EmptyRequest,
}

impl fmt::Display for StreamSliceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StreamNotFound { stream_id } => {
                write!(
                    f,
                    "stream {stream_id:016x} is not tracked in the view index"
                )
            }
            Self::ContentNotFound { stream_id } => {
                write!(f, "stream {stream_id:016x} has no stored content")
            }
            Self::EmptyRequest => {
                f.write_str("stream slice request must ask for at least one byte")
            }
        }
    }
}

impl std::error::Error for StreamSliceError {}

pub struct StreamSliceReader<'a> {
    content: &'a StreamContent,
    view: &'a StreamViewState,
    config: StreamSliceConfig,
}

impl<'a> StreamSliceReader<'a> {
    pub fn new(
        content: &'a StreamContent,
        view: &'a StreamViewState,
        config: StreamSliceConfig,
    ) -> Self {
        Self {
            content,
            view,
            config: config.normalized(),
        }
    }

    pub fn slice(
        &self,
        request: &StreamSliceRequest,
    ) -> Result<StreamContentSlice, StreamSliceError> {
        if request.max_bytes == 0 {
            return Err(StreamSliceError::EmptyRequest);
        }

        let Some(entry) = self.view.stream(request.stream_id) else {
            return Err(StreamSliceError::StreamNotFound {
                stream_id: request.stream_id,
            });
        };

        self.slice_with_context(
            request,
            entry.flow_key(),
            self.view
                .stream_matches(request.stream_id)
                .unwrap_or_default(),
        )
    }

    pub fn slice_with_context(
        &self,
        request: &StreamSliceRequest,
        key: crate::flow::FlowKey,
        matches: &[StreamPatternMatch],
    ) -> Result<StreamContentSlice, StreamSliceError> {
        if request.max_bytes == 0 {
            return Err(StreamSliceError::EmptyRequest);
        }

        let max_bytes = request.max_bytes.min(self.config.max_slice_bytes).max(1);
        let requested_end = request.logical_start.saturating_add(max_bytes as u64);
        let Some(windows) = self.content.direction_windows(
            &key,
            request.direction,
            request.logical_start,
            requested_end,
        ) else {
            return Err(StreamSliceError::ContentNotFound {
                stream_id: request.stream_id,
            });
        };

        let mut segments = Vec::with_capacity(windows.len());
        let mut returned_bytes = 0usize;
        for window in windows {
            returned_bytes = returned_bytes.saturating_add(window.bytes.len());
            segments.push(segment_from_window(
                &window,
                request.mode,
                self.config.hex_row_bytes,
            ));
        }

        let (highlights, dropped_highlights) =
            self.highlights(request.stream_id, request.direction, matches, &segments);

        Ok(StreamContentSlice {
            stream_id: request.stream_id,
            stream_id_hex: format!("{:016x}", request.stream_id),
            direction: request.direction,
            requested_start: request.logical_start,
            requested_end,
            returned_bytes,
            truncated_by_limit: request.max_bytes > self.config.max_slice_bytes,
            segments,
            highlights,
            dropped_highlights,
            transforms: Vec::new(),
        })
    }

    fn highlights(
        &self,
        stream_id: u64,
        direction: FlowDirection,
        matches: &[StreamPatternMatch],
        segments: &[StreamSliceSegment],
    ) -> (Vec<StreamSliceHighlight>, u64) {
        if self.config.max_highlights == 0 {
            let dropped = count_overlapping_matches(direction, matches, segments);
            return (Vec::new(), dropped);
        }

        let mut highlights = Vec::new();
        for pattern_match in matches {
            if pattern_match.direction != direction {
                continue;
            }

            for (segment_index, segment) in segments.iter().enumerate() {
                let start = pattern_match.logical_start.max(segment.logical_start);
                let end = pattern_match.logical_end.min(segment.logical_end);
                if start >= end {
                    continue;
                }

                highlights.push(StreamSliceHighlight {
                    stream_id,
                    pattern_id: pattern_match.pattern_id.clone(),
                    pattern_name: pattern_match.pattern_name.clone(),
                    pattern_type: pattern_match.pattern_type,
                    direction,
                    logical_start: start,
                    logical_end: end,
                    segment_index,
                    segment_start: start.saturating_sub(segment.logical_start) as usize,
                    segment_end: end.saturating_sub(segment.logical_start) as usize,
                });
            }
        }

        highlights.sort_by_key(|highlight| {
            (
                highlight.logical_start,
                highlight.logical_end,
                highlight.segment_index,
            )
        });
        let dropped = highlights.len().saturating_sub(self.config.max_highlights) as u64;
        highlights.truncate(self.config.max_highlights);
        (highlights, dropped)
    }
}

impl StreamContentSlice {
    pub fn copy_as(&self, format: StreamSliceCopyFormat) -> String {
        let bytes = self.concatenated_bytes();
        match format {
            StreamSliceCopyFormat::Base64 => STANDARD.encode(bytes),
            StreamSliceCopyFormat::Hex => bytes_to_hex(&bytes),
            StreamSliceCopyFormat::Text => safe_text(&bytes).text,
        }
    }

    pub fn concatenated_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.returned_bytes);
        for segment in &self.segments {
            if let Ok(decoded) = STANDARD.decode(&segment.base64) {
                bytes.extend_from_slice(&decoded);
            }
        }
        bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamSliceCopyFormat {
    Base64,
    Hex,
    Text,
}

fn segment_from_window(
    window: &StreamContentWindow,
    mode: StreamSliceMode,
    hex_row_bytes: usize,
) -> StreamSliceSegment {
    let logical_end = window
        .logical_start
        .saturating_add(window.bytes.len() as u64);
    let base64 = STANDARD.encode(&window.bytes);
    StreamSliceSegment {
        logical_start: window.logical_start,
        logical_end,
        bytes_len: window.bytes.len(),
        base64: base64.clone(),
        view: match mode {
            StreamSliceMode::Raw => StreamSliceSegmentView::Raw { base64 },
            StreamSliceMode::Text => {
                let text = safe_text(&window.bytes);
                StreamSliceSegmentView::Text {
                    text: text.text,
                    lossy: text.lossy,
                }
            }
            StreamSliceMode::Hex => StreamSliceSegmentView::Hex {
                rows: hex_rows(window.logical_start, &window.bytes, hex_row_bytes),
            },
        },
    }
}

fn count_overlapping_matches(
    direction: FlowDirection,
    matches: &[StreamPatternMatch],
    segments: &[StreamSliceSegment],
) -> u64 {
    let mut count = 0u64;
    for pattern_match in matches {
        if pattern_match.direction != direction {
            continue;
        }

        for segment in segments {
            if pattern_match.logical_start < segment.logical_end
                && pattern_match.logical_end > segment.logical_start
            {
                count = count.saturating_add(1);
            }
        }
    }
    count
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

    #[test]
    fn renders_safe_text() {
        let text = safe_text(b"GET /\x00flag\n");

        assert_eq!("GET /.flag\n", text.text);
        assert!(text.lossy);
    }

    #[test]
    fn renders_hex_rows() {
        let rows = hex_rows(32, b"abcdefghijklmnopq", 8);

        assert_eq!(3, rows.len());
        assert_eq!(32, rows[0].logical_start);
        assert_eq!("61 62 63 64 65 66 67 68", rows[0].hex);
        assert_eq!("abcdefgh", rows[0].ascii);
        assert_eq!(40, rows[1].logical_start);
        assert_eq!("69 6a 6b 6c 6d 6e 6f 70", rows[1].hex);
        assert_eq!("ijklmnop", rows[1].ascii);
        assert_eq!(48, rows[2].logical_start);
        assert_eq!("71", rows[2].hex);
        assert_eq!("q", rows[2].ascii);
    }
}
