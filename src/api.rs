use std::{
    collections::{BTreeSet, VecDeque},
    net::SocketAddr,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, patch, post},
};
use serde::{Deserialize, Serialize};
use tokio::{sync::oneshot, task::JoinHandle};

use crate::{
    event::Event,
    flow::{FlowDirection, FlowKey},
    packet::TransportProtocol,
    pipeline::PipelineStats,
    service_profile::{ServiceProfile, ServiceProfileSet, ServiceProfileStats},
    sharded_pipeline::{ShardedContentSliceError, ShardedContentSliceHandle, shard_for_flow_key},
    stream_content::{StreamContent, StreamContentConfig},
    stream_message::{
        StreamMessageKind, StreamMessageProtocol, StreamMessageQuery, StreamMessageQueryResult,
        StreamMessageStatus, StreamMessageStore,
    },
    stream_slice::{
        StreamContentSlice, StreamSliceConfig, StreamSliceError, StreamSliceMode,
        StreamSliceReader, StreamSliceRequest,
    },
    stream_transform::{
        StreamTransformConfig, StreamTransformMode, StreamTransformPlan, apply_transform_plan,
    },
    stream_view::{
        StreamHideRule, StreamPatternMatch, StreamViewConfig, StreamViewContentKind,
        StreamViewDirection, StreamViewQuery, StreamViewQueryResult, StreamViewRow,
        StreamViewState, StreamViewStats, StreamViewStatus,
    },
};

const DEFAULT_DELTA_QUERY_LIMIT: usize = 1024;
const MAX_DELTA_QUERY_LIMIT: usize = 8192;
const MAX_DELTA_POLL_MS: u64 = 30_000;

pub struct ApiSnapshot {
    stats: PipelineStats,
    view: StreamViewState,
    messages: StreamMessageStore,
    content_shards: Vec<Option<StreamContent>>,
    slice_config: StreamSliceConfig,
    profiles: ServiceProfileSet,
}

impl ApiSnapshot {
    pub fn single(
        stats: PipelineStats,
        content: StreamContent,
        view: StreamViewState,
        messages: StreamMessageStore,
        slice_config: StreamSliceConfig,
    ) -> Self {
        Self {
            stats,
            view,
            messages,
            content_shards: vec![Some(content)],
            slice_config,
            profiles: ServiceProfileSet::builtin(),
        }
    }

    pub fn sharded(
        stats: PipelineStats,
        view: StreamViewState,
        messages: StreamMessageStore,
        content_shards: Vec<Option<StreamContent>>,
        slice_config: StreamSliceConfig,
    ) -> Self {
        Self {
            stats,
            view,
            messages,
            content_shards,
            slice_config,
            profiles: ServiceProfileSet::builtin(),
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

    fn content_counts(&self) -> (usize, usize) {
        (
            self.content_shards.len(),
            self.content_shards
                .iter()
                .filter(|shard| shard.is_some())
                .count(),
        )
    }
}

#[derive(Clone)]
pub struct LiveApiHandle {
    inner: Arc<LiveApiState>,
}

struct LiveApiState {
    core: RwLock<LiveApiCore>,
    content: RwLock<LiveContentBackend>,
    deltas: Mutex<LiveDeltaLog>,
    notify: tokio::sync::Notify,
    slice_config: StreamSliceConfig,
    profiles: ServiceProfileSet,
}

struct LiveApiCore {
    stats: PipelineStats,
    view: StreamViewState,
    messages: StreamMessageStore,
    run_status: ApiRunStatus,
}

enum LiveContentBackend {
    None,
    Local(Arc<RwLock<StreamContent>>),
    Sharded(ShardedContentSliceHandle),
    Snapshot(Vec<Option<StreamContent>>),
}

impl LiveApiHandle {
    pub fn new(
        view_config: StreamViewConfig,
        slice_config: StreamSliceConfig,
        delta_capacity: usize,
    ) -> Self {
        Self::new_with_profiles(
            view_config,
            slice_config,
            delta_capacity,
            ServiceProfileSet::builtin(),
        )
    }

    pub fn new_with_profiles(
        view_config: StreamViewConfig,
        slice_config: StreamSliceConfig,
        delta_capacity: usize,
        profiles: ServiceProfileSet,
    ) -> Self {
        Self {
            inner: Arc::new(LiveApiState {
                core: RwLock::new(LiveApiCore {
                    stats: PipelineStats::default(),
                    view: StreamViewState::new(view_config),
                    messages: StreamMessageStore::default(),
                    run_status: ApiRunStatus::Running,
                }),
                content: RwLock::new(LiveContentBackend::None),
                deltas: Mutex::new(LiveDeltaLog::new(delta_capacity)),
                notify: tokio::sync::Notify::new(),
                slice_config,
                profiles,
            }),
        }
    }

    pub fn install_local_content(&self, config: StreamContentConfig) -> Arc<RwLock<StreamContent>> {
        let content = Arc::new(RwLock::new(StreamContent::new(config)));
        self.replace_content_backend(LiveContentBackend::Local(Arc::clone(&content)));
        content
    }

    pub fn set_sharded_content(&self, handle: ShardedContentSliceHandle) {
        self.replace_content_backend(LiveContentBackend::Sharded(handle));
    }

    pub fn set_snapshot_content(&self, shards: Vec<Option<StreamContent>>) {
        self.replace_content_backend(LiveContentBackend::Snapshot(shards));
    }

    pub fn publish_events(&self, events: &[Event], stats: PipelineStats) {
        let mut exact_matches = Vec::new();
        let mut stream_ids = BTreeSet::new();
        for event in events {
            if let Some(stream_id) = event_stream_id(event) {
                stream_ids.insert(stream_id);
            }
            if let Some(pattern_match) = StreamPatternMatch::from_event(event) {
                stream_ids.insert(pattern_match.stream_id);
                exact_matches.push(pattern_match);
            }
        }

        let rows = {
            let Ok(mut core) = self.inner.core.write() else {
                tracing::warn!("Live API core lock is poisoned");
                return;
            };
            core.view.observe_events(events);
            core.messages.observe_events(events);
            core.stats = stats;
            stream_ids
                .iter()
                .filter_map(|stream_id| core.view.stream_row(*stream_id))
                .collect::<Vec<_>>()
        };

        let mut deltas = Vec::new();
        if !rows.is_empty() {
            deltas.push(LiveDeltaPayload::Streams { rows });
        }
        if !exact_matches.is_empty() {
            deltas.push(LiveDeltaPayload::Matches {
                matches: exact_matches,
            });
        }
        deltas.push(LiveDeltaPayload::Stats { stats });
        self.append_deltas(deltas);
    }

    pub fn publish_stats(&self, stats: PipelineStats) {
        let Ok(mut core) = self.inner.core.write() else {
            tracing::warn!("Live API core lock is poisoned");
            return;
        };
        core.stats = stats;
        drop(core);

        self.append_deltas(vec![LiveDeltaPayload::Stats { stats }]);
    }

    pub fn mark_completed(&self, stats: PipelineStats) {
        self.mark_status(ApiRunStatus::Completed, stats);
    }

    pub fn mark_failed(&self, stats: PipelineStats) {
        self.mark_status(ApiRunStatus::Failed, stats);
    }

    fn mark_status(&self, run_status: ApiRunStatus, stats: PipelineStats) {
        let Ok(mut core) = self.inner.core.write() else {
            tracing::warn!("Live API core lock is poisoned");
            return;
        };
        core.stats = stats;
        core.run_status = run_status;
        drop(core);

        self.append_deltas(vec![LiveDeltaPayload::Status { run_status, stats }]);
    }

    fn replace_content_backend(&self, backend: LiveContentBackend) {
        let Ok(mut content) = self.inner.content.write() else {
            tracing::warn!("Live API content lock is poisoned");
            return;
        };
        *content = backend;
    }

    fn append_deltas(&self, payloads: Vec<LiveDeltaPayload>) {
        if payloads.is_empty() {
            return;
        }

        let Ok(mut deltas) = self.inner.deltas.lock() else {
            tracing::warn!("Live API delta lock is poisoned");
            return;
        };
        for payload in payloads {
            deltas.push(payload);
        }
        drop(deltas);
        self.inner.notify.notify_waiters();
    }

    fn health(&self) -> Result<HealthResponse, ApiError> {
        let core = self
            .inner
            .core
            .read()
            .map_err(|_| ApiError::internal("live API core lock is poisoned"))?;
        let (latest_delta_cursor, dropped_delta_cursor) = self.delta_cursors()?;
        let (content_shards, active_content_shards) = self.content_counts()?;

        Ok(HealthResponse {
            status: "ok",
            run_status: core.run_status,
            stats: core.stats,
            view: core.view.stats(),
            content_shards,
            active_content_shards,
            latest_delta_cursor,
            dropped_delta_cursor,
        })
    }

    fn streams(&self, query: &StreamViewQuery) -> Result<StreamViewQueryResult, ApiError> {
        let core = self
            .inner
            .core
            .read()
            .map_err(|_| ApiError::internal("live API core lock is poisoned"))?;
        Ok(core.view.query(query))
    }

    fn service_profiles(&self) -> Result<Vec<ServiceProfileView>, ApiError> {
        let core = self
            .inner
            .core
            .read()
            .map_err(|_| ApiError::internal("live API core lock is poisoned"))?;
        Ok(profile_views(&core.view, &self.inner.profiles))
    }

    fn service_profile(&self, id: &str) -> Result<ServiceProfileView, ApiError> {
        let core = self
            .inner
            .core
            .read()
            .map_err(|_| ApiError::internal("live API core lock is poisoned"))?;
        let profile = self
            .inner
            .profiles
            .get(id)
            .ok_or_else(|| ApiError::not_found(format!("service profile not found: {id}")))?;
        Ok(ServiceProfileView {
            profile: profile.clone(),
            stats: core.view.profile_stats(profile),
        })
    }

    fn stream_detail(&self, stream_id: u64) -> Result<StreamDetailResponse, ApiError> {
        let core = self
            .inner
            .core
            .read()
            .map_err(|_| ApiError::internal("live API core lock is poisoned"))?;
        let row = core.view.stream_row(stream_id).ok_or_else(|| {
            ApiError::not_found(format!("stream {stream_id:016x} is not tracked"))
        })?;
        let entry = core
            .view
            .stream(stream_id)
            .expect("stream row came from entry");
        let content_shard = live_stream_shard(&core.view, stream_id, self.content_shard_count()?);

        Ok(StreamDetailResponse {
            row,
            directions: entry.directions.clone(),
            matches: entry.matches.clone(),
            content_shard,
        })
    }

    fn update_stream_state(
        &self,
        stream_id: u64,
        patch: StreamStatePatch,
    ) -> Result<StreamStateResponse, ApiError> {
        let (response, stats, row) = {
            let mut core = self
                .inner
                .core
                .write()
                .map_err(|_| ApiError::internal("live API core lock is poisoned"))?;
            if core.view.stream(stream_id).is_none() {
                return Err(ApiError::not_found(format!(
                    "stream {stream_id:016x} is not tracked"
                )));
            }
            if let Some(favorite) = patch.favorite {
                core.view.set_favorite(stream_id, favorite);
            }
            if let Some(hidden) = patch.hidden {
                core.view.set_hidden(stream_id, hidden);
            }
            let view = core.view.stats();
            core.stats.set_stream_view_stats(view);
            let row = core
                .view
                .stream_row(stream_id)
                .expect("stream was checked before state update");
            let response = StreamStateResponse {
                row: row.clone(),
                view,
            };
            (response, core.stats, row)
        };

        self.append_deltas(vec![
            LiveDeltaPayload::Streams { rows: vec![row] },
            LiveDeltaPayload::Stats { stats },
        ]);
        Ok(response)
    }

    fn hide_rules(&self) -> Result<ViewRulesResponse, ApiError> {
        let core = self
            .inner
            .core
            .read()
            .map_err(|_| ApiError::internal("live API core lock is poisoned"))?;
        Ok(view_rules_response(&core.view))
    }

    fn add_hide_rule(&self, rule: StreamHideRule) -> Result<ViewRulesResponse, ApiError> {
        let (response, stats) = {
            let mut core = self
                .inner
                .core
                .write()
                .map_err(|_| ApiError::internal("live API core lock is poisoned"))?;
            core.view.add_hide_rule(rule);
            let view = core.view.stats();
            core.stats.set_stream_view_stats(view);
            (view_rules_response(&core.view), core.stats)
        };

        self.append_deltas(vec![LiveDeltaPayload::Stats { stats }]);
        Ok(response)
    }

    fn add_profile_hide_rules(&self, id: &str) -> Result<ViewRulesResponse, ApiError> {
        let profile = self
            .inner
            .profiles
            .get(id)
            .ok_or_else(|| ApiError::not_found(format!("service profile not found: {id}")))?
            .clone();
        let (response, stats) = {
            let mut core = self
                .inner
                .core
                .write()
                .map_err(|_| ApiError::internal("live API core lock is poisoned"))?;
            for rule in profile.hide_rules {
                core.view.add_hide_rule(rule);
            }
            let view = core.view.stats();
            core.stats.set_stream_view_stats(view);
            (view_rules_response(&core.view), core.stats)
        };

        self.append_deltas(vec![LiveDeltaPayload::Stats { stats }]);
        Ok(response)
    }

    fn clear_hide_rules(&self) -> Result<ViewRulesResponse, ApiError> {
        let (response, stats) = {
            let mut core = self
                .inner
                .core
                .write()
                .map_err(|_| ApiError::internal("live API core lock is poisoned"))?;
            core.view.clear_hide_rules();
            let view = core.view.stats();
            core.stats.set_stream_view_stats(view);
            (view_rules_response(&core.view), core.stats)
        };

        self.append_deltas(vec![LiveDeltaPayload::Stats { stats }]);
        Ok(response)
    }

    fn stream_matches(&self, stream_id: u64) -> Result<StreamMatchesResponse, ApiError> {
        let core = self
            .inner
            .core
            .read()
            .map_err(|_| ApiError::internal("live API core lock is poisoned"))?;
        let Some(matches) = core.view.stream_matches(stream_id) else {
            return Err(ApiError::not_found(format!(
                "stream {stream_id:016x} is not tracked"
            )));
        };

        Ok(StreamMatchesResponse {
            stream_id,
            stream_id_hex: format!("{stream_id:016x}"),
            matches: matches.to_vec(),
        })
    }

    fn stream_messages(
        &self,
        stream_id: u64,
        query: &StreamMessageQuery,
    ) -> Result<StreamMessageQueryResult, ApiError> {
        let core = self
            .inner
            .core
            .read()
            .map_err(|_| ApiError::internal("live API core lock is poisoned"))?;
        if core.view.stream(stream_id).is_none() {
            return Err(ApiError::not_found(format!(
                "stream {stream_id:016x} is not tracked"
            )));
        }
        Ok(core.messages.query(stream_id, query))
    }

    async fn stream_content(
        &self,
        request: StreamSliceRequest,
    ) -> Result<StreamContentSlice, ApiError> {
        let (flow_key, matches, shard) = {
            let core = self
                .inner
                .core
                .read()
                .map_err(|_| ApiError::internal("live API core lock is poisoned"))?;
            let Some(entry) = core.view.stream(request.stream_id) else {
                return Err(ApiError::not_found(format!(
                    "stream {stream_id:016x} is not tracked",
                    stream_id = request.stream_id
                )));
            };
            let shard =
                live_stream_shard(&core.view, request.stream_id, self.content_shard_count()?)
                    .unwrap_or(0);
            (entry.flow_key(), entry.matches.clone(), shard)
        };

        let sharded = {
            let content = self
                .inner
                .content
                .read()
                .map_err(|_| ApiError::internal("live API content lock is poisoned"))?;
            match &*content {
                LiveContentBackend::None => {
                    return Err(ApiError::service_unavailable(
                        "stream content backend is not ready",
                    ));
                }
                LiveContentBackend::Local(content) => {
                    let content = content
                        .read()
                        .map_err(|_| ApiError::internal("live content lock is poisoned"))?;
                    return slice_from_content(
                        &content,
                        &request,
                        flow_key,
                        &matches,
                        self.inner.slice_config,
                    );
                }
                LiveContentBackend::Snapshot(shards) => {
                    let Some(content) = shards.get(shard).and_then(Option::as_ref) else {
                        return Err(ApiError::not_found(format!(
                            "stream {stream_id:016x} has no stored content shard",
                            stream_id = request.stream_id
                        )));
                    };
                    return slice_from_content(
                        content,
                        &request,
                        flow_key,
                        &matches,
                        self.inner.slice_config,
                    );
                }
                LiveContentBackend::Sharded(handle) => handle.clone(),
            }
        };

        sharded
            .slice(shard, request, flow_key, matches)
            .await
            .map_err(ApiError::from_sharded_slice_error)?
            .map_err(ApiError::from_slice_error)
    }

    async fn deltas(&self, params: LiveDeltaQueryParams) -> Result<LiveDeltaResponse, ApiError> {
        let cursor = params.cursor.unwrap_or_default();
        let limit = params
            .limit
            .unwrap_or(DEFAULT_DELTA_QUERY_LIMIT)
            .clamp(1, MAX_DELTA_QUERY_LIMIT);
        let wait_ms = params.wait_ms.unwrap_or_default().min(MAX_DELTA_POLL_MS);

        let response = self.delta_response(cursor, limit)?;
        if wait_ms == 0
            || !response.deltas.is_empty()
            || response.run_status != ApiRunStatus::Running
        {
            return Ok(response);
        }

        let notified = self.inner.notify.notified();
        let _ = tokio::time::timeout(Duration::from_millis(wait_ms), notified).await;
        self.delta_response(cursor, limit)
    }

    fn delta_response(&self, cursor: u64, limit: usize) -> Result<LiveDeltaResponse, ApiError> {
        let deltas = self
            .inner
            .deltas
            .lock()
            .map_err(|_| ApiError::internal("live API delta lock is poisoned"))?;
        let core = self
            .inner
            .core
            .read()
            .map_err(|_| ApiError::internal("live API core lock is poisoned"))?;
        Ok(deltas.response(cursor, limit, core.run_status))
    }

    fn delta_cursors(&self) -> Result<(u64, u64), ApiError> {
        let deltas = self
            .inner
            .deltas
            .lock()
            .map_err(|_| ApiError::internal("live API delta lock is poisoned"))?;
        Ok((deltas.latest_cursor(), deltas.dropped_before))
    }

    fn content_counts(&self) -> Result<(usize, usize), ApiError> {
        let content = self
            .inner
            .content
            .read()
            .map_err(|_| ApiError::internal("live API content lock is poisoned"))?;
        Ok(match &*content {
            LiveContentBackend::None => (0, 0),
            LiveContentBackend::Local(_) => (1, 1),
            LiveContentBackend::Sharded(handle) => (handle.shard_count(), handle.shard_count()),
            LiveContentBackend::Snapshot(shards) => (
                shards.len(),
                shards.iter().filter(|shard| shard.is_some()).count(),
            ),
        })
    }

    fn content_shard_count(&self) -> Result<usize, ApiError> {
        let (shards, _) = self.content_counts()?;
        Ok(shards)
    }
}

pub struct ApiServer {
    local_addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join: JoinHandle<anyhow::Result<()>>,
}

impl ApiServer {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn wait_for_shutdown_signal(mut self) -> anyhow::Result<()> {
        tokio::select! {
            result = &mut self.join => join_server_result(result),
            signal = tokio::signal::ctrl_c() => {
                signal?;
                self.shutdown().await
            }
        }
    }

    pub async fn shutdown(mut self) -> anyhow::Result<()> {
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }
        join_server_result(self.join.await)
    }
}

#[derive(Clone)]
enum ApiState {
    Snapshot(Arc<ApiSnapshot>),
    Live(LiveApiHandle),
}

pub async fn serve_snapshot(snapshot: ApiSnapshot, addr: SocketAddr) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    tracing::info!(%local_addr, "Serving read-only local API snapshot");
    axum::serve(listener, router(ApiState::Snapshot(Arc::new(snapshot))))
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

pub async fn spawn_live(handle: LiveApiHandle, addr: SocketAddr) -> anyhow::Result<ApiServer> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let local_addr = listener.local_addr()?;
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let join = tokio::spawn(async move {
        axum::serve(listener, router(ApiState::Live(handle)))
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await
            .map_err(anyhow::Error::from)
    });
    tracing::info!(%local_addr, "Serving live local API");
    Ok(ApiServer {
        local_addr,
        shutdown_tx: Some(shutdown_tx),
        join,
    })
}

fn router(state: ApiState) -> Router {
    Router::new()
        .route("/", get(frontend_index))
        .route("/app.js", get(frontend_js))
        .route("/styles.css", get(frontend_css))
        .route("/api/health", get(health))
        .route("/api/service-profiles", get(service_profiles))
        .route(
            "/api/service-profiles/{id}",
            get(service_profile).post(add_profile_hide_rules),
        )
        .route(
            "/api/service-profiles/{id}/hide-rules",
            post(add_profile_hide_rules),
        )
        .route("/api/streams", get(streams))
        .route("/api/streams/{id}", get(stream_detail))
        .route("/api/streams/{id}/state", patch(patch_stream_state))
        .route("/api/streams/{id}/matches", get(stream_matches))
        .route("/api/streams/{id}/messages", get(stream_messages))
        .route("/api/streams/{id}/content", get(stream_content))
        .route(
            "/api/view/hide-rules",
            get(hide_rules).post(add_hide_rule).delete(clear_hide_rules),
        )
        .route("/api/live/deltas", get(live_deltas))
        .with_state(state)
}

async fn frontend_index() -> Html<&'static str> {
    Html(include_str!("frontend/index.html"))
}

async fn frontend_js() -> impl IntoResponse {
    (
        [("content-type", "application/javascript; charset=utf-8")],
        include_str!("frontend/app.js"),
    )
}

async fn frontend_css() -> impl IntoResponse {
    (
        [("content-type", "text/css; charset=utf-8")],
        include_str!("frontend/styles.css"),
    )
}

async fn shutdown_signal() {
    if tokio::signal::ctrl_c().await.is_ok() {
        tracing::info!("Stopping local API server");
    }
}

fn join_server_result(
    result: Result<anyhow::Result<()>, tokio::task::JoinError>,
) -> anyhow::Result<()> {
    match result {
        Ok(result) => result,
        Err(err) => Err(anyhow::Error::from(err)),
    }
}

async fn health(State(state): State<ApiState>) -> Result<Json<HealthResponse>, ApiError> {
    match state {
        ApiState::Snapshot(snapshot) => {
            let (content_shards, active_content_shards) = snapshot.content_counts();
            Ok(Json(HealthResponse {
                status: "ok",
                run_status: ApiRunStatus::Completed,
                stats: snapshot.stats,
                view: snapshot.view.stats(),
                content_shards,
                active_content_shards,
                latest_delta_cursor: 0,
                dropped_delta_cursor: 0,
            }))
        }
        ApiState::Live(live) => Ok(Json(live.health()?)),
    }
}

async fn service_profiles(
    State(state): State<ApiState>,
) -> Result<Json<ServiceProfilesResponse>, ApiError> {
    let profiles = match state {
        ApiState::Snapshot(snapshot) => profile_views(&snapshot.view, &snapshot.profiles),
        ApiState::Live(live) => live.service_profiles()?,
    };
    Ok(Json(ServiceProfilesResponse { profiles }))
}

async fn service_profile(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<ServiceProfileView>, ApiError> {
    match state {
        ApiState::Snapshot(snapshot) => {
            let profile = snapshot
                .profiles
                .get(&id)
                .ok_or_else(|| ApiError::not_found(format!("service profile not found: {id}")))?;
            Ok(Json(ServiceProfileView {
                profile: profile.clone(),
                stats: snapshot.view.profile_stats(profile),
            }))
        }
        ApiState::Live(live) => Ok(Json(live.service_profile(&id)?)),
    }
}

async fn streams(
    State(state): State<ApiState>,
    Query(params): Query<StreamQueryParams>,
) -> Result<Json<StreamViewQueryResult>, ApiError> {
    let query = params.into_view_query(profiles_for_state(&state))?;
    match state {
        ApiState::Snapshot(snapshot) => Ok(Json(snapshot.view.query(&query))),
        ApiState::Live(live) => Ok(Json(live.streams(&query)?)),
    }
}

async fn patch_stream_state(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(patch): Json<StreamStatePatch>,
) -> Result<Json<StreamStateResponse>, ApiError> {
    let stream_id = parse_stream_id(&id)?;
    match state {
        ApiState::Snapshot(_) => Err(ApiError::bad_request(
            "stream state mutations are not available for snapshot API",
        )),
        ApiState::Live(live) => Ok(Json(live.update_stream_state(stream_id, patch)?)),
    }
}

async fn stream_detail(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<StreamDetailResponse>, ApiError> {
    let stream_id = parse_stream_id(&id)?;
    match state {
        ApiState::Snapshot(snapshot) => {
            let row = snapshot.view.stream_row(stream_id).ok_or_else(|| {
                ApiError::not_found(format!("stream {stream_id:016x} is not tracked"))
            })?;
            let entry = snapshot
                .view
                .stream(stream_id)
                .expect("stream row came from entry");
            let content_shard = snapshot.stream_shard(stream_id).ok();

            Ok(Json(StreamDetailResponse {
                row,
                directions: entry.directions.clone(),
                matches: entry.matches.clone(),
                content_shard,
            }))
        }
        ApiState::Live(live) => Ok(Json(live.stream_detail(stream_id)?)),
    }
}

async fn stream_matches(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<StreamMatchesResponse>, ApiError> {
    let stream_id = parse_stream_id(&id)?;
    match state {
        ApiState::Snapshot(snapshot) => {
            let Some(matches) = snapshot.view.stream_matches(stream_id) else {
                return Err(ApiError::not_found(format!(
                    "stream {stream_id:016x} is not tracked"
                )));
            };

            Ok(Json(StreamMatchesResponse {
                stream_id,
                stream_id_hex: format!("{stream_id:016x}"),
                matches: matches.to_vec(),
            }))
        }
        ApiState::Live(live) => Ok(Json(live.stream_matches(stream_id)?)),
    }
}

async fn stream_messages(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(params): Query<MessageQueryParams>,
) -> Result<Json<StreamMessageQueryResult>, ApiError> {
    let stream_id = parse_stream_id(&id)?;
    let query = params.into_message_query()?;
    match state {
        ApiState::Snapshot(snapshot) => {
            if snapshot.view.stream(stream_id).is_none() {
                return Err(ApiError::not_found(format!(
                    "stream {stream_id:016x} is not tracked"
                )));
            }
            Ok(Json(snapshot.messages.query(stream_id, &query)))
        }
        ApiState::Live(live) => Ok(Json(live.stream_messages(stream_id, &query)?)),
    }
}

async fn stream_content(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Query(params): Query<ContentQueryParams>,
) -> Result<Json<StreamContentSlice>, ApiError> {
    let stream_id = parse_stream_id(&id)?;
    let view_mode = params.mode()?;
    let transform_plan = match params.transform()? {
        ContentTransformRequest::None => None,
        ContentTransformRequest::Plan(plan) => Some(plan),
        ContentTransformRequest::ProfileDefault => default_profile_transform(&state, stream_id)?,
    };
    let transform_config = transform_config(&state);
    let request = StreamSliceRequest {
        stream_id,
        direction: params.direction()?,
        logical_start: params.start.unwrap_or(0),
        max_bytes: params.len.unwrap_or(default_slice_len(&state)),
        mode: view_mode,
    };

    let mut slice = match &state {
        ApiState::Snapshot(snapshot) => snapshot.slice(&request)?,
        ApiState::Live(live) => live.stream_content(request).await?,
    };

    if let Some(transform_plan) = transform_plan {
        let output = apply_transform_plan(&slice, transform_plan, view_mode, transform_config);
        slice.transforms.push(output);
    }

    Ok(Json(slice))
}

async fn live_deltas(
    State(state): State<ApiState>,
    Query(params): Query<LiveDeltaQueryParams>,
) -> Result<Json<LiveDeltaResponse>, ApiError> {
    match state {
        ApiState::Snapshot(_) => Err(ApiError::bad_request(
            "live deltas are not available for snapshot API",
        )),
        ApiState::Live(live) => Ok(Json(live.deltas(params).await?)),
    }
}

async fn hide_rules(State(state): State<ApiState>) -> Result<Json<ViewRulesResponse>, ApiError> {
    match state {
        ApiState::Snapshot(snapshot) => Ok(Json(view_rules_response(&snapshot.view))),
        ApiState::Live(live) => Ok(Json(live.hide_rules()?)),
    }
}

async fn add_hide_rule(
    State(state): State<ApiState>,
    Json(request): Json<HideRuleRequest>,
) -> Result<Json<ViewRulesResponse>, ApiError> {
    let rule = request.into_rule()?;
    match state {
        ApiState::Snapshot(_) => Err(ApiError::bad_request(
            "hide rule mutations are not available for snapshot API",
        )),
        ApiState::Live(live) => Ok(Json(live.add_hide_rule(rule)?)),
    }
}

async fn add_profile_hide_rules(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<ViewRulesResponse>, ApiError> {
    match state {
        ApiState::Snapshot(_) => Err(ApiError::bad_request(
            "hide rule mutations are not available for snapshot API",
        )),
        ApiState::Live(live) => Ok(Json(live.add_profile_hide_rules(&id)?)),
    }
}

async fn clear_hide_rules(
    State(state): State<ApiState>,
) -> Result<Json<ViewRulesResponse>, ApiError> {
    match state {
        ApiState::Snapshot(_) => Err(ApiError::bad_request(
            "hide rule mutations are not available for snapshot API",
        )),
        ApiState::Live(live) => Ok(Json(live.clear_hide_rules()?)),
    }
}

fn default_slice_len(state: &ApiState) -> usize {
    match state {
        ApiState::Snapshot(snapshot) => snapshot.slice_config.max_slice_bytes,
        ApiState::Live(live) => live.inner.slice_config.max_slice_bytes,
    }
}

fn transform_config(state: &ApiState) -> StreamTransformConfig {
    let slice_config = match state {
        ApiState::Snapshot(snapshot) => snapshot.slice_config,
        ApiState::Live(live) => live.inner.slice_config,
    }
    .normalized();

    StreamTransformConfig {
        max_output_bytes: slice_config.max_transform_bytes,
        hex_row_bytes: slice_config.hex_row_bytes,
    }
}

fn profiles_for_state(state: &ApiState) -> &ServiceProfileSet {
    match state {
        ApiState::Snapshot(snapshot) => &snapshot.profiles,
        ApiState::Live(live) => &live.inner.profiles,
    }
}

fn default_profile_transform(
    state: &ApiState,
    stream_id: u64,
) -> Result<Option<StreamTransformPlan>, ApiError> {
    Ok(match state {
        ApiState::Snapshot(snapshot) => {
            if snapshot.view.stream(stream_id).is_none() {
                return Err(ApiError::not_found(format!(
                    "stream {stream_id:016x} is not tracked"
                )));
            }
            snapshot
                .view
                .primary_profile(&snapshot.profiles, stream_id)
                .and_then(ServiceProfile::default_transform_plan)
        }
        ApiState::Live(live) => {
            let core = live
                .inner
                .core
                .read()
                .map_err(|_| ApiError::internal("live API core lock is poisoned"))?;
            if core.view.stream(stream_id).is_none() {
                return Err(ApiError::not_found(format!(
                    "stream {stream_id:016x} is not tracked"
                )));
            }
            core.view
                .primary_profile(&live.inner.profiles, stream_id)
                .and_then(ServiceProfile::default_transform_plan)
        }
    })
}

fn profile_views(view: &StreamViewState, profiles: &ServiceProfileSet) -> Vec<ServiceProfileView> {
    profiles
        .profiles()
        .iter()
        .map(|profile| ServiceProfileView {
            profile: profile.clone(),
            stats: view.profile_stats(profile),
        })
        .collect()
}

fn view_rules_response(view: &StreamViewState) -> ViewRulesResponse {
    ViewRulesResponse {
        rules: view
            .hide_rules()
            .iter()
            .enumerate()
            .map(|(index, rule)| ViewRule {
                index,
                label: rule.label(),
                rule: rule.clone(),
            })
            .collect(),
        view: view.stats(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiRunStatus {
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    status: &'static str,
    run_status: ApiRunStatus,
    stats: PipelineStats,
    view: StreamViewStats,
    content_shards: usize,
    active_content_shards: usize,
    latest_delta_cursor: u64,
    dropped_delta_cursor: u64,
}

#[derive(Debug, Serialize)]
struct ServiceProfilesResponse {
    profiles: Vec<ServiceProfileView>,
}

#[derive(Debug, Serialize)]
struct ServiceProfileView {
    profile: ServiceProfile,
    stats: ServiceProfileStats,
}

#[derive(Debug, Serialize)]
struct StreamDetailResponse {
    row: StreamViewRow,
    directions: [StreamViewDirection; 2],
    matches: Vec<StreamPatternMatch>,
    content_shard: Option<usize>,
}

#[derive(Debug, Serialize)]
struct StreamStateResponse {
    row: StreamViewRow,
    view: StreamViewStats,
}

#[derive(Debug, Serialize)]
struct ViewRulesResponse {
    rules: Vec<ViewRule>,
    view: StreamViewStats,
}

#[derive(Debug, Serialize)]
struct ViewRule {
    index: usize,
    label: String,
    rule: StreamHideRule,
}

#[derive(Debug, Serialize)]
struct StreamMatchesResponse {
    stream_id: u64,
    stream_id_hex: String,
    matches: Vec<StreamPatternMatch>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveDelta {
    cursor: u64,
    #[serde(flatten)]
    payload: LiveDeltaPayload,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LiveDeltaPayload {
    Stats {
        stats: PipelineStats,
    },
    Streams {
        rows: Vec<StreamViewRow>,
    },
    Matches {
        matches: Vec<StreamPatternMatch>,
    },
    Status {
        run_status: ApiRunStatus,
        stats: PipelineStats,
    },
}

#[derive(Debug, Serialize)]
pub struct LiveDeltaResponse {
    deltas: Vec<LiveDelta>,
    next_cursor: u64,
    latest_cursor: u64,
    dropped_before: u64,
    missed: bool,
    run_status: ApiRunStatus,
}

struct LiveDeltaLog {
    capacity: usize,
    next_cursor: u64,
    dropped_before: u64,
    entries: VecDeque<LiveDelta>,
}

impl LiveDeltaLog {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            next_cursor: 1,
            dropped_before: 0,
            entries: VecDeque::with_capacity(capacity.min(65_536)),
        }
    }

    fn push(&mut self, payload: LiveDeltaPayload) {
        let cursor = self.next_cursor;
        self.next_cursor = self.next_cursor.saturating_add(1);
        self.entries.push_back(LiveDelta { cursor, payload });
        while self.entries.len() > self.capacity {
            if let Some(delta) = self.entries.pop_front() {
                self.dropped_before = delta.cursor;
            }
        }
    }

    fn response(&self, cursor: u64, limit: usize, run_status: ApiRunStatus) -> LiveDeltaResponse {
        let missed = cursor < self.dropped_before;
        let deltas = self
            .entries
            .iter()
            .filter(|delta| delta.cursor > cursor.max(self.dropped_before))
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        let next_cursor = deltas
            .last()
            .map_or(cursor.max(self.dropped_before), |delta| delta.cursor);

        LiveDeltaResponse {
            deltas,
            next_cursor,
            latest_cursor: self.latest_cursor(),
            dropped_before: self.dropped_before,
            missed,
            run_status,
        }
    }

    fn latest_cursor(&self) -> u64 {
        self.next_cursor.saturating_sub(1)
    }
}

#[derive(Debug, Default, Deserialize)]
struct StreamQueryParams {
    cursor: Option<usize>,
    limit: Option<usize>,
    include_hidden: Option<bool>,
    only_favorites: Option<bool>,
    only_matched: Option<bool>,
    profile: Option<String>,
    protocol: Option<String>,
    service: Option<String>,
    port: Option<u16>,
    content_kind: Option<String>,
    status: Option<String>,
    pattern_id: Option<String>,
}

impl StreamQueryParams {
    fn into_view_query(self, profiles: &ServiceProfileSet) -> Result<StreamViewQuery, ApiError> {
        let mut query = StreamViewQuery::default();
        query.cursor = self.cursor.unwrap_or(query.cursor);
        query.limit = self.limit.unwrap_or(query.limit);
        query.include_hidden = self.include_hidden.unwrap_or(query.include_hidden);
        query.only_favorites = self.only_favorites.unwrap_or(query.only_favorites);
        query.only_matched = self.only_matched.unwrap_or(query.only_matched);
        query.profile = non_empty(self.profile)
            .map(|profile| {
                profiles
                    .get(&profile)
                    .cloned()
                    .ok_or_else(|| ApiError::bad_request(format!("unknown profile: {profile}")))
            })
            .transpose()?;
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum ContentTransformRequest {
    None,
    Plan(StreamTransformPlan),
    ProfileDefault,
}

#[derive(Debug, Default, Deserialize)]
struct ContentQueryParams {
    direction: Option<String>,
    start: Option<u64>,
    len: Option<usize>,
    mode: Option<String>,
    transform: Option<String>,
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

    fn transform(&self) -> Result<ContentTransformRequest, ApiError> {
        let Some(raw) = self.transform.as_deref() else {
            return Ok(ContentTransformRequest::None);
        };
        match normalized_token(raw).as_str() {
            "" | "none" | "raw" => Ok(ContentTransformRequest::None),
            "profile" | "default" | "profile_default" => {
                Ok(ContentTransformRequest::ProfileDefault)
            }
            _ => parse_transform_plan(raw).map(ContentTransformRequest::Plan),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct MessageQueryParams {
    cursor: Option<usize>,
    limit: Option<usize>,
    direction: Option<String>,
    protocol: Option<String>,
    kind: Option<String>,
    status: Option<String>,
}

impl MessageQueryParams {
    fn into_message_query(self) -> Result<StreamMessageQuery, ApiError> {
        Ok(StreamMessageQuery {
            cursor: self.cursor.unwrap_or_default(),
            limit: self.limit.unwrap_or(128),
            direction: self.direction.as_deref().map(parse_direction).transpose()?,
            protocol: self
                .protocol
                .as_deref()
                .map(parse_message_protocol)
                .transpose()?,
            kind: self.kind.as_deref().map(parse_message_kind).transpose()?,
            status: self
                .status
                .as_deref()
                .map(parse_message_status)
                .transpose()?,
        })
    }
}

#[derive(Debug, Default, Deserialize)]
struct StreamStatePatch {
    favorite: Option<bool>,
    hidden: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct HideRuleRequest {
    kind: String,
    value: serde_json::Value,
}

impl HideRuleRequest {
    fn into_rule(self) -> Result<StreamHideRule, ApiError> {
        let kind = normalized_token(&self.kind);
        let value = json_scalar_to_string(&self.value)?;
        let rule =
            match kind.as_str() {
                "stream" | "stream_id" => StreamHideRule::StreamId(parse_stream_id(&value)?),
                "service" => StreamHideRule::Service(value),
                "protocol" => StreamHideRule::Protocol(parse_protocol(&value)?),
                "port" => StreamHideRule::Port(value.parse::<u16>().map_err(|_| {
                    ApiError::bad_request(format!("invalid hide rule port: {value}"))
                })?),
                "content_kind" | "kind" => StreamHideRule::ContentKind(parse_content_kind(&value)?),
                "status" => StreamHideRule::Status(parse_status(&value)?),
                "pattern" | "pattern_id" => StreamHideRule::PatternId(value),
                _ => {
                    return Err(ApiError::bad_request(format!(
                        "invalid hide rule kind: {}",
                        self.kind
                    )));
                }
            };
        Ok(rule.normalized())
    }
}

#[derive(Debug, Default, Deserialize)]
struct LiveDeltaQueryParams {
    cursor: Option<u64>,
    limit: Option<usize>,
    wait_ms: Option<u64>,
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

    fn service_unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
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

    fn from_sharded_slice_error(error: ShardedContentSliceError) -> Self {
        match error {
            ShardedContentSliceError::InvalidShard { shard } => {
                Self::not_found(format!("invalid content shard: {shard}"))
            }
            ShardedContentSliceError::QueueFull { shard } => {
                Self::service_unavailable(format!("content shard {shard} is busy; retry shortly"))
            }
            ShardedContentSliceError::Disconnected { shard } => {
                Self::service_unavailable(format!("content shard {shard} is not available"))
            }
            ShardedContentSliceError::Timeout { shard } => {
                Self::service_unavailable(format!("content shard {shard} timed out"))
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

fn slice_from_content(
    content: &StreamContent,
    request: &StreamSliceRequest,
    flow_key: FlowKey,
    matches: &[StreamPatternMatch],
    slice_config: StreamSliceConfig,
) -> Result<StreamContentSlice, ApiError> {
    let empty_view = StreamViewState::new(StreamViewConfig::disabled());
    StreamSliceReader::new(content, &empty_view, slice_config)
        .slice_with_context(request, flow_key, matches)
        .map_err(ApiError::from_slice_error)
}

fn live_stream_shard(
    view: &StreamViewState,
    stream_id: u64,
    content_shards: usize,
) -> Option<usize> {
    let entry = view.stream(stream_id)?;
    if content_shards <= 1 {
        Some(0)
    } else {
        Some(shard_for_flow_key(&entry.flow_key(), content_shards))
    }
}

fn event_stream_id(event: &Event) -> Option<u64> {
    let value = event.fields.get("stream_id")?;
    if let Some(stream_id) = value.as_u64() {
        return Some(stream_id);
    }
    let raw = value.as_str()?;
    parse_stream_id(raw).ok()
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

fn parse_message_protocol(raw: &str) -> Result<StreamMessageProtocol, ApiError> {
    match normalized_token(raw).as_str() {
        "http" | "http1" | "http_1" | "http/1" | "http/1.1" => Ok(StreamMessageProtocol::Http1),
        _ => Err(ApiError::bad_request(format!(
            "invalid message protocol: {raw}"
        ))),
    }
}

fn parse_message_kind(raw: &str) -> Result<StreamMessageKind, ApiError> {
    match normalized_token(raw).as_str() {
        "request" | "req" => Ok(StreamMessageKind::Request),
        "response" | "resp" => Ok(StreamMessageKind::Response),
        "unknown" => Ok(StreamMessageKind::Unknown),
        _ => Err(ApiError::bad_request(format!(
            "invalid message kind: {raw}"
        ))),
    }
}

fn parse_message_status(raw: &str) -> Result<StreamMessageStatus, ApiError> {
    match normalized_token(raw).as_str() {
        "complete" => Ok(StreamMessageStatus::Complete),
        "partial" => Ok(StreamMessageStatus::Partial),
        "parse_error" | "error" => Ok(StreamMessageStatus::ParseError),
        _ => Err(ApiError::bad_request(format!(
            "invalid message status: {raw}"
        ))),
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

fn parse_transform_plan(raw: &str) -> Result<StreamTransformPlan, ApiError> {
    let raw = raw
        .trim()
        .strip_prefix("chain:")
        .or_else(|| raw.trim().strip_prefix("pipeline:"))
        .unwrap_or_else(|| raw.trim());
    let steps = raw
        .split([',', '|', '+', '>'])
        .map(str::trim)
        .filter(|step| !step.is_empty())
        .map(parse_transform_mode)
        .collect::<Result<Vec<_>, _>>()?;
    if steps.is_empty() {
        Err(ApiError::bad_request("transform plan is empty"))
    } else {
        Ok(StreamTransformPlan::new(steps))
    }
}

fn parse_transform_mode(raw: &str) -> Result<StreamTransformMode, ApiError> {
    match normalized_token(raw).as_str() {
        "auto" => Ok(StreamTransformMode::Auto),
        "url" | "url_decode" | "urldecode" => Ok(StreamTransformMode::UrlDecode),
        "gzip" => Ok(StreamTransformMode::Gzip),
        "http_chunked" | "http-chunked" | "chunked" => Ok(StreamTransformMode::HttpChunked),
        "http_gzip" | "http-gzip" => Ok(StreamTransformMode::HttpGzip),
        "websocket_deflate" | "websocket-deflate" | "ws_deflate" | "ws-deflate" => {
            Ok(StreamTransformMode::WebSocketDeflate)
        }
        _ => Err(ApiError::bad_request(format!("invalid transform: {raw}"))),
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

fn json_scalar_to_string(value: &serde_json::Value) -> Result<String, ApiError> {
    match value {
        serde_json::Value::String(value) => {
            let value = value.trim().to_owned();
            if value.is_empty() {
                Err(ApiError::bad_request("hide rule value is empty"))
            } else {
                Ok(value)
            }
        }
        serde_json::Value::Number(value) => Ok(value.to_string()),
        serde_json::Value::Bool(value) => Ok(value.to_string()),
        _ => Err(ApiError::bad_request(
            "hide rule value must be a string, number, or boolean",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream_view::StreamViewConfig;

    #[test]
    fn parses_decimal_and_hex_stream_ids() {
        assert_eq!(123, parse_stream_id("123").unwrap());
        assert_eq!(0x123abc, parse_stream_id("0x123abc").unwrap());
        assert_eq!(0x123abc, parse_stream_id("123abc").unwrap());
    }

    #[test]
    fn stream_query_keeps_view_defaults_when_params_are_absent() {
        let profiles = ServiceProfileSet::builtin();
        let query = StreamQueryParams::default()
            .into_view_query(&profiles)
            .unwrap();
        let default = StreamViewQuery::default();

        assert_eq!(default.cursor, query.cursor);
        assert_eq!(default.limit, query.limit);
        assert_eq!(default.include_hidden, query.include_hidden);
        assert_eq!(default.only_matched, query.only_matched);
    }

    #[test]
    fn stream_query_accepts_service_profile_filter() {
        let profiles = ServiceProfileSet::builtin();
        let query = StreamQueryParams {
            profile: Some("http".to_owned()),
            ..StreamQueryParams::default()
        }
        .into_view_query(&profiles)
        .unwrap();

        assert_eq!("http", query.profile.unwrap().id);
    }

    #[test]
    fn parses_hide_rule_requests() {
        let request = HideRuleRequest {
            kind: "service".to_owned(),
            value: serde_json::json!("http"),
        };

        assert_eq!(
            StreamHideRule::Service("http".to_owned()),
            request.into_rule().unwrap()
        );
    }

    #[test]
    fn content_query_defaults_to_forward_text_slice() {
        let query = ContentQueryParams::default();

        assert_eq!(FlowDirection::AToB, query.direction().unwrap());
        assert_eq!(StreamSliceMode::Text, query.mode().unwrap());
    }

    #[test]
    fn message_query_accepts_protocol_filters() {
        let query = MessageQueryParams {
            direction: Some("b_to_a".to_owned()),
            protocol: Some("http1".to_owned()),
            kind: Some("response".to_owned()),
            status: Some("complete".to_owned()),
            limit: Some(64),
            ..MessageQueryParams::default()
        }
        .into_message_query()
        .unwrap();

        assert_eq!(Some(FlowDirection::BToA), query.direction);
        assert_eq!(Some(StreamMessageProtocol::Http1), query.protocol);
        assert_eq!(Some(StreamMessageKind::Response), query.kind);
        assert_eq!(Some(StreamMessageStatus::Complete), query.status);
        assert_eq!(64, query.limit);
    }

    #[test]
    fn parses_transform_chains() {
        let plan = parse_transform_plan("http_chunked,http_gzip,url_decode").unwrap();

        assert_eq!(
            vec![
                StreamTransformMode::HttpChunked,
                StreamTransformMode::HttpGzip,
                StreamTransformMode::UrlDecode
            ],
            plan.steps
        );
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

    #[test]
    fn delta_log_reports_retention_gaps() {
        let mut log = LiveDeltaLog::new(2);
        log.push(LiveDeltaPayload::Stats {
            stats: PipelineStats::default(),
        });
        log.push(LiveDeltaPayload::Stats {
            stats: PipelineStats::default(),
        });
        log.push(LiveDeltaPayload::Stats {
            stats: PipelineStats::default(),
        });

        let response = log.response(0, 10, ApiRunStatus::Running);

        assert!(response.missed);
        assert_eq!(1, response.dropped_before);
        assert_eq!(2, response.deltas.len());
        assert_eq!(3, response.latest_cursor);
    }

    #[test]
    fn live_handle_installs_local_content_backend() {
        let live = LiveApiHandle::new(
            StreamViewConfig::disabled(),
            StreamSliceConfig::default(),
            16,
        );

        live.install_local_content(StreamContentConfig::disabled());
        let health = live.health().unwrap();

        assert_eq!(ApiRunStatus::Running, health.run_status);
        assert_eq!(1, health.content_shards);
        assert_eq!(1, health.active_content_shards);
    }
}
