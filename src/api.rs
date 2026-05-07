use std::{net::SocketAddr, sync::Arc};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::{Deserialize, Serialize};

use crate::{
    flow::FlowDirection,
    packet::TransportProtocol,
    pipeline::PipelineStats,
    sharded_pipeline::shard_for_flow_key,
    stream_content::StreamContent,
    stream_slice::{
        StreamContentSlice, StreamSliceConfig, StreamSliceError, StreamSliceMode,
        StreamSliceReader, StreamSliceRequest,
    },
    stream_view::{
        StreamPatternMatch, StreamViewContentKind, StreamViewDirection, StreamViewQuery,
        StreamViewQueryResult, StreamViewRow, StreamViewState, StreamViewStats, StreamViewStatus,
    },
};

pub struct ApiSnapshot {
    stats: PipelineStats,
    view: StreamViewState,
    content_shards: Vec<Option<StreamContent>>,
    slice_config: StreamSliceConfig,
}

impl ApiSnapshot {
    pub fn single(
        stats: PipelineStats,
        content: StreamContent,
        view: StreamViewState,
        slice_config: StreamSliceConfig,
    ) -> Self {
        Self {
            stats,
            view,
            content_shards: vec![Some(content)],
            slice_config,
        }
    }

    pub fn sharded(
        stats: PipelineStats,
        view: StreamViewState,
        content_shards: Vec<Option<StreamContent>>,
        slice_config: StreamSliceConfig,
    ) -> Self {
        Self {
            stats,
            view,
            content_shards,
            slice_config,
        }
    }

    fn stream_shard(&self, stream_id: u64) -> Result<usize, ApiError> {
        let Some(entry) = self.view.stream(stream_id) else {
            return Err(ApiError::not_found(format!(
                "stream {stream_id:016x} is not tracked"
            )));
        };

        if self.content_shards.len() <= 1 {
            Ok(0)
        } else {
            Ok(shard_for_flow_key(
                &entry.flow_key(),
                self.content_shards.len(),
            ))
        }
    }

    fn slice(&self, request: &StreamSliceRequest) -> Result<StreamContentSlice, ApiError> {
        let shard = self.stream_shard(request.stream_id)?;
        let Some(content) = self.content_shards.get(shard).and_then(Option::as_ref) else {
            return Err(ApiError::not_found(format!(
                "stream {stream_id:016x} has no stored content shard",
                stream_id = request.stream_id
            )));
        };

        StreamSliceReader::new(content, &self.view, self.slice_config)
            .slice(request)
            .map_err(ApiError::from_slice_error)
    }
}

pub async fn serve_snapshot(snapshot: ApiSnapshot, addr: SocketAddr) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    tracing::info!(%local_addr, "Serving read-only local API snapshot");
    axum::serve(listener, router(Arc::new(snapshot)))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn router(state: Arc<ApiSnapshot>) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/streams", get(streams))
        .route("/api/streams/{id}", get(stream_detail))
        .route("/api/streams/{id}/matches", get(stream_matches))
        .route("/api/streams/{id}/content", get(stream_content))
        .with_state(state)
}

async fn shutdown_signal() {
    if tokio::signal::ctrl_c().await.is_ok() {
        tracing::info!("Stopping local API server");
    }
}

async fn health(State(state): State<Arc<ApiSnapshot>>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        stats: state.stats,
        view: state.view.stats(),
        content_shards: state.content_shards.len(),
        active_content_shards: state
            .content_shards
            .iter()
            .filter(|shard| shard.is_some())
            .count(),
    })
}

async fn streams(
    State(state): State<Arc<ApiSnapshot>>,
    Query(params): Query<StreamQueryParams>,
) -> Result<Json<StreamViewQueryResult>, ApiError> {
    let query = params.into_view_query()?;
    Ok(Json(state.view.query(&query)))
}

async fn stream_detail(
    State(state): State<Arc<ApiSnapshot>>,
    Path(id): Path<String>,
) -> Result<Json<StreamDetailResponse>, ApiError> {
    let stream_id = parse_stream_id(&id)?;
    let row = state
        .view
        .stream_row(stream_id)
        .ok_or_else(|| ApiError::not_found(format!("stream {stream_id:016x} is not tracked")))?;
    let entry = state
        .view
        .stream(stream_id)
        .expect("stream row came from entry");
    let content_shard = state.stream_shard(stream_id).ok();

    Ok(Json(StreamDetailResponse {
        row,
        directions: entry.directions.clone(),
        matches: entry.matches.clone(),
        content_shard,
    }))
}

async fn stream_matches(
    State(state): State<Arc<ApiSnapshot>>,
    Path(id): Path<String>,
) -> Result<Json<StreamMatchesResponse>, ApiError> {
    let stream_id = parse_stream_id(&id)?;
    let Some(matches) = state.view.stream_matches(stream_id) else {
        return Err(ApiError::not_found(format!(
            "stream {stream_id:016x} is not tracked"
        )));
    };

    Ok(Json(StreamMatchesResponse {
        stream_id,
        matches: matches.to_vec(),
    }))
}

async fn stream_content(
    State(state): State<Arc<ApiSnapshot>>,
    Path(id): Path<String>,
    Query(params): Query<ContentQueryParams>,
) -> Result<Json<StreamContentSlice>, ApiError> {
    let stream_id = parse_stream_id(&id)?;
    let request = StreamSliceRequest {
        stream_id,
        direction: params.direction()?,
        logical_start: params.start.unwrap_or(0),
        max_bytes: params.len.unwrap_or(state.slice_config.max_slice_bytes),
        mode: params.mode()?,
    };

    Ok(Json(state.slice(&request)?))
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    stats: PipelineStats,
    view: StreamViewStats,
    content_shards: usize,
    active_content_shards: usize,
}

#[derive(Debug, Serialize)]
struct StreamDetailResponse {
    row: StreamViewRow,
    directions: [StreamViewDirection; 2],
    matches: Vec<StreamPatternMatch>,
    content_shard: Option<usize>,
}

#[derive(Debug, Serialize)]
struct StreamMatchesResponse {
    stream_id: u64,
    matches: Vec<StreamPatternMatch>,
}

#[derive(Debug, Default, Deserialize)]
struct StreamQueryParams {
    cursor: Option<usize>,
    limit: Option<usize>,
    include_hidden: Option<bool>,
    only_favorites: Option<bool>,
    only_matched: Option<bool>,
    protocol: Option<String>,
    service: Option<String>,
    port: Option<u16>,
    content_kind: Option<String>,
    status: Option<String>,
    pattern_id: Option<String>,
}

impl StreamQueryParams {
    fn into_view_query(self) -> Result<StreamViewQuery, ApiError> {
        let mut query = StreamViewQuery::default();
        query.cursor = self.cursor.unwrap_or(query.cursor);
        query.limit = self.limit.unwrap_or(query.limit);
        query.include_hidden = self.include_hidden.unwrap_or(query.include_hidden);
        query.only_favorites = self.only_favorites.unwrap_or(query.only_favorites);
        query.only_matched = self.only_matched.unwrap_or(query.only_matched);
        query.protocol = self.protocol.as_deref().map(parse_protocol).transpose()?;
        query.service = non_empty(self.service);
        query.port = self.port;
        query.content_kind = self
            .content_kind
            .as_deref()
            .map(parse_content_kind)
            .transpose()?;
        query.status = self.status.as_deref().map(parse_status).transpose()?;
        query.pattern_id = non_empty(self.pattern_id);
        Ok(query)
    }
}

#[derive(Debug, Default, Deserialize)]
struct ContentQueryParams {
    direction: Option<String>,
    start: Option<u64>,
    len: Option<usize>,
    mode: Option<String>,
}

impl ContentQueryParams {
    fn direction(&self) -> Result<FlowDirection, ApiError> {
        self.direction
            .as_deref()
            .map(parse_direction)
            .unwrap_or(Ok(FlowDirection::AToB))
    }

    fn mode(&self) -> Result<StreamSliceMode, ApiError> {
        self.mode
            .as_deref()
            .map(parse_slice_mode)
            .unwrap_or(Ok(StreamSliceMode::Text))
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    error: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn from_slice_error(error: StreamSliceError) -> Self {
        match error {
            StreamSliceError::EmptyRequest => Self::bad_request(error.to_string()),
            StreamSliceError::StreamNotFound { .. } | StreamSliceError::ContentNotFound { .. } => {
                Self::not_found(error.to_string())
            }
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ApiErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

fn parse_stream_id(raw: &str) -> Result<u64, ApiError> {
    let value = raw.trim();
    if value.is_empty() {
        return Err(ApiError::bad_request("stream id is empty"));
    }

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
        u64::from_str_radix(hex, 16)
            .map_err(|_| ApiError::bad_request(format!("invalid stream id: {raw}")))
    } else {
        value
            .parse::<u64>()
            .or_else(|_| u64::from_str_radix(hex, 16))
            .map_err(|_| ApiError::bad_request(format!("invalid stream id: {raw}")))
    }
}

fn parse_protocol(raw: &str) -> Result<TransportProtocol, ApiError> {
    match normalized_token(raw).as_str() {
        "tcp" => Ok(TransportProtocol::Tcp),
        "udp" => Ok(TransportProtocol::Udp),
        "icmpv4" | "icmp_v4" => Ok(TransportProtocol::Icmpv4),
        "icmpv6" | "icmp_v6" => Ok(TransportProtocol::Icmpv6),
        _ => Err(ApiError::bad_request(format!("invalid protocol: {raw}"))),
    }
}

fn parse_content_kind(raw: &str) -> Result<StreamViewContentKind, ApiError> {
    match normalized_token(raw).as_str() {
        "unknown" => Ok(StreamViewContentKind::Unknown),
        "text" => Ok(StreamViewContentKind::Text),
        "binary" => Ok(StreamViewContentKind::Binary),
        "mixed" => Ok(StreamViewContentKind::Mixed),
        _ => Err(ApiError::bad_request(format!(
            "invalid content_kind: {raw}"
        ))),
    }
}

fn parse_status(raw: &str) -> Result<StreamViewStatus, ApiError> {
    match normalized_token(raw).as_str() {
        "open" => Ok(StreamViewStatus::Open),
        "closing" => Ok(StreamViewStatus::Closing),
        "closed" => Ok(StreamViewStatus::Closed),
        "unknown" => Ok(StreamViewStatus::Unknown),
        _ => Err(ApiError::bad_request(format!("invalid status: {raw}"))),
    }
}

fn parse_direction(raw: &str) -> Result<FlowDirection, ApiError> {
    match normalized_token(raw).as_str() {
        "a_to_b" | "atob" | "a_b" => Ok(FlowDirection::AToB),
        "b_to_a" | "btoa" | "b_a" => Ok(FlowDirection::BToA),
        _ => Err(ApiError::bad_request(format!("invalid direction: {raw}"))),
    }
}

fn parse_slice_mode(raw: &str) -> Result<StreamSliceMode, ApiError> {
    match normalized_token(raw).as_str() {
        "raw" => Ok(StreamSliceMode::Raw),
        "text" => Ok(StreamSliceMode::Text),
        "hex" => Ok(StreamSliceMode::Hex),
        _ => Err(ApiError::bad_request(format!("invalid mode: {raw}"))),
    }
}

fn normalized_token(raw: &str) -> String {
    raw.trim().to_ascii_lowercase().replace(['-', ' '], "_")
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim().to_owned();
        (!value.is_empty()).then_some(value)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decimal_and_hex_stream_ids() {
        assert_eq!(123, parse_stream_id("123").unwrap());
        assert_eq!(0x123abc, parse_stream_id("0x123abc").unwrap());
        assert_eq!(0x123abc, parse_stream_id("123abc").unwrap());
    }

    #[test]
    fn stream_query_keeps_view_defaults_when_params_are_absent() {
        let query = StreamQueryParams::default().into_view_query().unwrap();
        let default = StreamViewQuery::default();

        assert_eq!(default.cursor, query.cursor);
        assert_eq!(default.limit, query.limit);
        assert_eq!(default.include_hidden, query.include_hidden);
        assert_eq!(default.only_matched, query.only_matched);
    }

    #[test]
    fn content_query_defaults_to_forward_text_slice() {
        let query = ContentQueryParams::default();

        assert_eq!(FlowDirection::AToB, query.direction().unwrap());
        assert_eq!(StreamSliceMode::Text, query.mode().unwrap());
    }

    #[test]
    fn rejects_bad_filter_tokens() {
        assert_eq!(
            StatusCode::BAD_REQUEST,
            parse_direction("sideways").unwrap_err().status
        );
        assert_eq!(
            StatusCode::BAD_REQUEST,
            parse_protocol("gre").unwrap_err().status
        );
    }
}
