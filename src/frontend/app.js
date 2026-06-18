const ROW_HEIGHT = 34;
const ROW_OVERSCAN = 12;
const STREAM_LIMIT = 500;

const state = {
  streams: new Map(),
  rowIds: [],
  profiles: [],
  selectedId: null,
  deltaCursor: 0,
  nextCursor: null,
  onlyFavorites: false,
  onlyMatched: false,
  showHidden: false,
  lastSlice: null,
  matches: [],
  matchIndex: -1,
  pendingMatchScroll: false,
  loadingStreams: false,
  polling: false,
  lastHealthRefresh: 0,
};

const el = {
  status: document.getElementById("status-line"),
  streams: document.getElementById("stat-streams"),
  matches: document.getElementById("stat-matches"),
  packets: document.getElementById("stat-packets"),
  decode: document.getElementById("stat-decode"),
  drops: document.getElementById("stat-drops"),
  queue: document.getElementById("stat-queue"),
  hotShard: document.getElementById("stat-hot-shard"),
  skew: document.getElementById("stat-skew"),
  fallback: document.getElementById("stat-fallback"),
  shardPressureState: document.getElementById("shard-pressure-state"),
  shardPressureSummary: document.getElementById("shard-pressure-summary"),
  shardDiagnostics: document.getElementById("shard-diagnostics"),
  tableWrap: document.querySelector(".table-wrap"),
  rows: document.getElementById("stream-rows"),
  profile: document.getElementById("filter-profile"),
  service: document.getElementById("filter-service"),
  port: document.getElementById("filter-port"),
  favorites: document.getElementById("toggle-favorites"),
  matched: document.getElementById("toggle-matched"),
  hidden: document.getElementById("toggle-hidden"),
  reload: document.getElementById("reload-streams"),
  title: document.getElementById("stream-title"),
  subtitle: document.getElementById("stream-subtitle"),
  favorite: document.getElementById("favorite-stream"),
  hide: document.getElementById("hide-stream"),
  hideService: document.getElementById("hide-service"),
  direction: document.getElementById("direction-select"),
  mode: document.getElementById("mode-select"),
  transform: document.getElementById("transform-select"),
  start: document.getElementById("slice-start"),
  len: document.getElementById("slice-len"),
  prev: document.getElementById("slice-prev"),
  next: document.getElementById("slice-next"),
  matchPrev: document.getElementById("match-prev"),
  matchNext: document.getElementById("match-next"),
  copyFormat: document.getElementById("copy-format"),
  copy: document.getElementById("copy-content"),
  content: document.getElementById("content-view"),
  matchesList: document.getElementById("match-list"),
  transformView: document.getElementById("transform-view"),
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    cache: "no-store",
    headers: options.body ? { "content-type": "application/json" } : undefined,
    ...options,
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({ error: response.statusText }));
    throw new Error(body.error || response.statusText);
  }
  return response.json();
}

function query(params) {
  const out = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      out.set(key, String(value));
    }
  }
  return out.toString();
}

async function loadHealth() {
  await refreshHealthTelemetry({ force: true });
}

async function refreshHealthTelemetry(options = {}) {
  const now = Date.now();
  if (!options.force && now - state.lastHealthRefresh < 1000) return;
  state.lastHealthRefresh = now;
  const health = await api("/api/health");
  updateStats(health);
  updateShardDiagnostics(health);
  state.deltaCursor = Math.max(state.deltaCursor, health.latest_delta_cursor || 0);
}

async function loadProfiles() {
  const result = await api("/api/service-profiles");
  state.profiles = result.profiles || [];
  const current = el.profile.value;
  const options = [optionElement("", "all profiles")];
  for (const item of state.profiles) {
    const profile = item.profile;
    const count = profileCountForCurrentToggles(item.stats || {});
    options.push(optionElement(profile.id, `${profile.name} (${formatNumber(count)})`));
  }
  el.profile.replaceChildren(...options);
  el.profile.value = [...el.profile.options].some(option => option.value === current) ? current : "";
}

function profileCountForCurrentToggles(stats) {
  if (state.onlyFavorites && state.onlyMatched) {
    return Math.min(stats.favorite_streams ?? 0, stats.matched_streams ?? 0);
  }
  if (state.onlyFavorites) return stats.favorite_streams ?? 0;
  if (state.onlyMatched) return stats.matched_streams ?? 0;
  return state.showHidden ? stats.total_streams ?? 0 : stats.visible_streams ?? 0;
}

function updateStats(healthOrDelta) {
  const stats = healthOrDelta.stats || {};
  const queue = healthOrDelta.queue_summary || {};
  const view = healthOrDelta.view || {};
  el.status.textContent = `${healthOrDelta.run_status || "running"} / cursor ${healthOrDelta.latest_delta_cursor ?? state.deltaCursor}`;
  el.streams.textContent = formatNumber(view.tracked_streams ?? stats.view_tracked_streams ?? 0);
  el.matches.textContent = formatNumber(stats.pattern_matches ?? 0);
  el.packets.textContent = formatNumber(stats.packets ?? 0);
  updateDecodeStats(stats);
  el.drops.textContent = formatNumber((stats.source_dropped_packets ?? 0) + (stats.source_interface_dropped_packets ?? 0));
  const workerQueueLen = firstPositive(stats.worker_queue_max_len, queue.max_worker_queue_len);
  const workerQueueCap = firstPositive(stats.worker_queue_max_capacity, queue.max_worker_queue_capacity);
  const outputQueueLen = firstPositive(stats.output_queue_len, queue.output_queue_len);
  const outputQueueCap = firstPositive(stats.output_queue_capacity, queue.output_queue_capacity);
  const busiestShard = stats.busiest_shard ?? stats.busiest_worker ?? queue.busiest_worker;
  const busiestBytes = firstPositive(stats.busiest_shard_bytes, stats.busiest_worker_bytes, queue.busiest_worker_bytes);
  const packetSkew = firstPositive(
    stats.shard_packet_skew_ratio_milli,
    stats.worker_packet_skew_ratio_milli,
    queue.worker_packet_skew_ratio_milli,
  );
  const byteSkew = firstPositive(
    stats.shard_byte_skew_ratio_milli,
    stats.worker_byte_skew_ratio_milli,
    queue.worker_byte_skew_ratio_milli,
  );
  const fallback = firstPositive(
    stats.fallback_routed_packets,
    stats.worker_fallback_routed_packets,
    queue.fallback_routed_packets,
  );
  const malformedFallback = firstPositive(
    stats.fallback_malformed_packets,
    stats.worker_fallback_malformed_packets,
    queue.fallback_malformed_packets,
  );

  el.queue.textContent = `${formatNumber(workerQueueLen)}/${formatNumber(workerQueueCap)} · ${formatNumber(outputQueueLen)}/${formatNumber(outputQueueCap)}`;
  el.hotShard.textContent = busiestShard === undefined || busiestShard === null
    ? "-"
    : `${busiestShard} / ${formatBytes(busiestBytes)}`;
  el.skew.textContent = `${formatMilliRatio(packetSkew)} / ${formatMilliRatio(byteSkew)}`;
  el.fallback.textContent = malformedFallback > 0
    ? `${formatNumber(fallback)} / bad ${formatNumber(malformedFallback)}`
    : formatNumber(fallback);
}

function updateDecodeStats(stats) {
  const parsed = Number(stats.packet_parsed_packets || 0);
  const nonIp = Number(stats.packet_non_ip_packets || 0);
  const fragmented = Number(stats.packet_fragmented_packets || 0);
  const unsupportedTransport = Number(stats.packet_unsupported_transport_packets || 0);
  const bad = Number(stats.packet_malformed_packets || 0)
    + Number(stats.packet_unsupported_link_packets || 0);
  const parts = [`ok ${formatNumber(parsed)}`];
  if (nonIp) parts.push(`ni ${formatNumber(nonIp)}`);
  if (fragmented) parts.push(`frag ${formatNumber(fragmented)}`);
  if (unsupportedTransport) parts.push(`other ${formatNumber(unsupportedTransport)}`);
  if (bad) parts.push(`bad ${formatNumber(bad)}`);
  el.decode.textContent = parts.join(" / ");
}

async function reloadStreams() {
  state.streams.clear();
  state.rowIds = [];
  state.nextCursor = null;
  state.selectedId = null;
  state.matches = [];
  state.matchIndex = -1;
  clearDetails();
  el.rows.replaceChildren();
  await loadProfiles().catch(() => {});
  await loadStreamsPage(0);
}

async function loadStreamsPage(cursor = state.nextCursor) {
  if (state.loadingStreams || cursor === null && state.rowIds.length !== 0) return;
  state.loadingStreams = true;
  try {
    const params = {
      cursor,
      limit: STREAM_LIMIT,
      include_hidden: state.showHidden,
      only_favorites: state.onlyFavorites,
      only_matched: state.onlyMatched,
      profile: el.profile.value,
      service: el.service.value.trim(),
      port: el.port.value.trim(),
    };
    const result = await api(`/api/streams?${query(params)}`);
    for (const row of result.rows || []) {
      state.streams.set(streamId(row), row);
    }
    state.nextCursor = result.next_cursor ?? null;
    rebuildRowOrder();
    renderRows();
    if (!state.selectedId && state.rowIds[0]) {
      await selectStream(state.rowIds[0], { preserveScroll: true });
    } else if (!state.rowIds.length) {
      clearDetails();
    }
  } finally {
    state.loadingStreams = false;
  }
}

function rebuildRowOrder() {
  state.rowIds = [...state.streams.values()]
    .sort((a, b) => Number(b.last_seen_us || 0) - Number(a.last_seen_us || 0))
    .map(streamId);
}

function renderRows() {
  if (!state.rowIds.length) {
    const tr = document.createElement("tr");
    tr.className = "empty-row";
    tr.innerHTML = '<td colspan="5">No streams for current filters.</td>';
    el.rows.replaceChildren(tr);
    return;
  }

  const viewportRows = Math.ceil(el.tableWrap.clientHeight / ROW_HEIGHT);
  const first = Math.max(0, Math.floor(el.tableWrap.scrollTop / ROW_HEIGHT) - ROW_OVERSCAN);
  const last = Math.min(state.rowIds.length, first + viewportRows + ROW_OVERSCAN * 2);
  const top = spacerRow(first * ROW_HEIGHT);
  const bottom = spacerRow((state.rowIds.length - last) * ROW_HEIGHT);
  const rows = state.rowIds.slice(first, last).map((id, offset) => rowElement(state.streams.get(id), first + offset));
  el.rows.replaceChildren(top, ...rows, bottom);
}

function rowElement(row, rowIndex) {
  const tr = document.createElement("tr");
  const id = streamId(row);
  tr.className = [id === state.selectedId ? "selected" : "", row.hidden ? "hidden-row" : ""]
    .filter(Boolean)
    .join(" ");
  tr.dataset.streamId = id;
  tr.dataset.rowIndex = String(rowIndex);
  tr.addEventListener("click", () => selectStream(id));
  tr.innerHTML = `
    <td title="${id}">${shortId(id)}</td>
    <td title="${escapeHtml(serviceEvidence(row.service))}">${escapeHtml(row.service?.name || "unknown")}</td>
    <td>${escapeHtml(row.content_kind || "unknown")}</td>
    <td>${formatNumber(row.stream_bytes || row.payload_bytes || 0)}</td>
    <td>${formatNumber(row.match_count || 0)}</td>
  `;
  return tr;
}

function spacerRow(height) {
  const tr = document.createElement("tr");
  tr.className = "table-spacer";
  const td = document.createElement("td");
  td.colSpan = 5;
  td.style.height = `${Math.max(0, height)}px`;
  tr.append(td);
  return tr;
}

async function selectStream(id, options = {}) {
  if (!id) return;
  state.selectedId = id;
  if (!options.preserveScroll) {
    ensureRowVisible(id);
  }
  renderRows();
  const detail = await api(`/api/streams/${encodeURIComponent(id)}`);
  const row = detail.row;
  state.streams.set(streamId(row), row);
  el.title.textContent = shortId(id);
  el.subtitle.textContent = `${row.protocol} ${endpoint(row.endpoint_a)} -> ${endpoint(row.endpoint_b)} / ${serviceSummary(row.service)}`;
  updateStateButtons(row);
  state.matches = detail.matches || [];
  if (!state.matches.length) {
    state.matchIndex = -1;
  } else if (state.matchIndex < 0 || state.matchIndex >= state.matches.length || streamId(state.matches[state.matchIndex]) !== id) {
    state.matchIndex = 0;
  }
  renderMatches();
  await loadContent();
}

function updateStateButtons(row) {
  el.favorite.setAttribute("aria-pressed", String(Boolean(row.favorite)));
  el.hide.setAttribute("aria-pressed", String(Boolean(row.hidden)));
  el.favorite.textContent = row.favorite ? "favorited" : "favorite";
  el.hide.textContent = row.hidden ? "hidden" : "hide";
}

async function loadContent() {
  if (!state.selectedId) return;
  const params = {
    direction: el.direction.value,
    start: numberValue(el.start.value, 0),
    len: numberValue(el.len.value, 65536),
    mode: el.mode.value,
    transform: el.transform.value,
  };
  const slice = await api(`/api/streams/${encodeURIComponent(state.selectedId)}/content?${query(params)}`);
  state.lastSlice = slice;
  renderContent(slice);
  renderTransform(slice.transforms || []);
}

function renderContent(slice) {
  el.content.replaceChildren();
  if (!slice.segments.length) {
    el.content.textContent = "No content in this range.";
    return;
  }

  for (let index = 0; index < slice.segments.length; index += 1) {
    const segment = slice.segments[index];
    const prefix = document.createElement("span");
    prefix.className = "muted";
    prefix.textContent = `[${segment.logical_start}-${segment.logical_end})\n`;
    el.content.append(prefix);
    appendSegmentView(segment, slice.highlights.filter(hit => hit.segment_index === index));
    if (index + 1 < slice.segments.length) {
      el.content.append("\n\n");
    }
  }

  if (state.pendingMatchScroll) {
    state.pendingMatchScroll = false;
    requestAnimationFrame(() => el.content.querySelector("mark")?.scrollIntoView({ block: "center" }));
  }
}

function appendSegmentView(segment, highlights) {
  if (segment.view.kind === "text") {
    appendHighlightedText(segment.view.text || "", highlights);
  } else if (segment.view.kind === "hex") {
    el.content.append((segment.view.rows || []).map(row => `${String(row.logical_start).padStart(8, "0")}  ${row.hex.padEnd(48, " ")}  ${row.ascii}`).join("\n"));
  } else {
    el.content.append(segment.view.base64 || segment.base64 || "");
  }
}

function appendHighlightedText(text, highlights) {
  let offset = 0;
  const sorted = [...highlights].sort((a, b) => a.segment_start - b.segment_start);
  for (const hit of sorted) {
    const start = Math.max(0, Math.min(text.length, hit.segment_start));
    const end = Math.max(start, Math.min(text.length, hit.segment_end));
    if (start > offset) {
      el.content.append(text.slice(offset, start));
    }
    if (end > start) {
      const mark = document.createElement("mark");
      mark.textContent = text.slice(start, end);
      el.content.append(mark);
    }
    offset = end;
  }
  if (offset < text.length) {
    el.content.append(text.slice(offset));
  }
}

function renderMatches() {
  if (!state.matches.length) {
    el.matchesList.innerHTML = '<div class="muted">No retained matches</div>';
    return;
  }
  el.matchesList.replaceChildren(...state.matches.map((match, index) => {
    const item = document.createElement("button");
    item.type = "button";
    item.className = `match-item ${index === state.matchIndex ? "selected" : ""}`;
    item.innerHTML = `<b>${escapeHtml(match.pattern_name)}</b><br>
      ${escapeHtml(match.direction)} ${match.logical_start}-${match.logical_end}<br>
      <span class="muted">${escapeHtml(match.pattern_type)} / ${escapeHtml(match.pattern_id)}</span>`;
    item.addEventListener("click", () => jumpToMatch(index).catch(showError));
    return item;
  }));
}

async function jumpMatch(delta) {
  if (!state.matches.length) return;
  const next = state.matchIndex < 0
    ? 0
    : (state.matchIndex + delta + state.matches.length) % state.matches.length;
  await jumpToMatch(next);
}

async function jumpToMatch(index) {
  const match = state.matches[index];
  if (!match) return;
  state.matchIndex = index;
  el.direction.value = match.direction;
  el.start.value = Math.max(0, Number(match.logical_start) - 64);
  state.pendingMatchScroll = true;
  renderMatches();
  await loadContent();
}

function renderTransform(transforms) {
  if (!transforms.length) {
    el.transformView.innerHTML = '<div class="muted">No transform selected</div>';
    return;
  }
  el.transformView.replaceChildren(...transforms.map(transform => {
    const item = document.createElement("div");
    item.className = "transform-item";
    const statusClass = transform.status === "failed" ? "warn" : "muted";
    const chain = (transform.requested_chain || []).join(" -> ") || transform.requested || "";
    item.innerHTML = `<b>${escapeHtml(transform.applied)}</b> <span class="${statusClass}">${escapeHtml(transform.status)}</span><br>
      <span class="muted">${escapeHtml(chain)}</span><br>
      ${formatNumber(transform.input_bytes)} -> ${formatNumber(transform.output_bytes)} bytes<br>
      <span class="muted">${escapeHtml((transform.notes || []).join("; "))}</span>`;
    if (transform.steps?.length) {
      const steps = document.createElement("div");
      steps.className = "transform-steps";
      steps.replaceChildren(...transform.steps.map(step => {
        const row = document.createElement("div");
        row.className = `transform-step ${step.status === "failed" ? "warn" : ""}`;
        row.textContent = `${step.requested}: ${step.status}, ${formatNumber(step.input_bytes)} -> ${formatNumber(step.output_bytes)} bytes`;
        return row;
      }));
      item.append(steps);
    }
    if (transform.segments?.length) {
      const pre = document.createElement("pre");
      pre.textContent = transform.segments.map(segmentText).join("\n\n");
      item.append(pre);
    }
    return item;
  }));
}

function segmentText(segment) {
  if (segment.view.kind === "text") return segment.view.text || "";
  if (segment.view.kind === "hex") return (segment.view.rows || []).map(row => `${row.hex}  ${row.ascii}`).join("\n");
  return segment.view.base64 || segment.base64 || "";
}

async function pollDeltas() {
  if (state.polling) return;
  state.polling = true;
  while (state.polling) {
    try {
      const result = await api(`/api/live/deltas?${query({ cursor: state.deltaCursor, limit: 1024, wait_ms: 1000 })}`);
      if (result.missed) {
        await reloadStreams();
      }
      for (const delta of result.deltas || []) {
        applyDelta(delta);
      }
      state.deltaCursor = result.next_cursor ?? state.deltaCursor;
      el.status.textContent = `${result.run_status || "running"} / cursor ${state.deltaCursor}`;
      await refreshHealthTelemetry();
    } catch (error) {
      el.status.textContent = error.message;
      await sleep(1000);
    }
  }
}

function applyDelta(delta) {
  if (delta.kind === "stats" || delta.kind === "status") {
    updateStats({ stats: delta.stats, run_status: delta.run_status, latest_delta_cursor: delta.cursor });
    return;
  }
  if (delta.kind === "streams") {
    for (const row of delta.rows || []) {
      const id = streamId(row);
      if (rowPassesCurrentFilters(row)) {
        state.streams.set(id, row);
      } else {
        state.streams.delete(id);
      }
    }
    rebuildRowOrder();
    if (state.selectedId && state.streams.has(state.selectedId)) {
      updateStateButtons(state.streams.get(state.selectedId));
    } else if (state.selectedId && !state.streams.has(state.selectedId)) {
      state.selectedId = null;
      if (state.rowIds[0]) {
        selectStream(state.rowIds[0]).catch(showError);
      } else {
        clearDetails();
      }
    }
    renderRows();
  }
  if (delta.kind === "matches" && state.selectedId) {
    const touched = (delta.matches || []).some(match => streamId(match) === state.selectedId);
    if (touched) {
      selectStream(state.selectedId, { preserveScroll: true }).catch(showError);
    }
  }
}

function updateShardDiagnostics(health) {
  const pressure = health.shard_pressure || {};
  const queue = health.queue || {};
  const summary = health.queue_summary || {};
  const workers = queue.workers || [];
  const stateName = pressure.state || "idle";
  const busiest = pressure.busiest_shard ?? summary.busiest_worker;
  const warnings = pressure.warnings || [];
  const warningText = warnings.length ? ` / ${warnings.map(formatWarning).join(", ")}` : "";

  el.shardPressureState.textContent = stateName;
  el.shardPressureState.dataset.state = stateName;
  el.shardPressureSummary.textContent = workers.length
    ? `${workers.length} shards / hot ${busiest ?? "-"} / pkt ${formatMilliRatio(pressure.packet_skew_ratio_milli ?? summary.worker_packet_skew_ratio_milli)} / byte ${formatMilliRatio(pressure.byte_skew_ratio_milli ?? summary.worker_byte_skew_ratio_milli)}${warningText}`
    : "no shard telemetry";

  if (!workers.length) {
    const tr = document.createElement("tr");
    tr.className = "empty-row";
    tr.innerHTML = '<td colspan="6">No shard telemetry.</td>';
    el.shardDiagnostics.replaceChildren(tr);
    return;
  }

  el.shardDiagnostics.replaceChildren(...workers.map(worker => shardRow(worker, busiest)));
}

function shardRow(worker, busiest) {
  const tr = document.createElement("tr");
  const queueFill = ratio(worker.len, worker.capacity);
  const fallback = Number(worker.fallback_packets || 0);
  const malformed = Number(worker.fallback_malformed_packets || 0);
  tr.className = worker.id === busiest ? "hot-shard" : "";
  tr.innerHTML = `
    <td>${formatNumber(worker.id)}</td>
    <td class="${queueFill >= 0.60 ? "queue-warn" : ""}">${formatNumber(worker.len)}/${formatNumber(worker.capacity)}</td>
    <td>${formatNumber(worker.routed_packets)}</td>
    <td>${formatBytes(worker.routed_bytes)}</td>
    <td>${fallbackBreakdown(fallback, malformed)}</td>
    <td title="${escapeHtml(hotFlowTitle(worker.hot_flow))}">${escapeHtml(hotFlowSummary(worker.hot_flow))}</td>
  `;
  return tr;
}

function hotFlowSummary(flow) {
  if (!flow) return "-";
  return `${flow.protocol} ${shortEndpoint(flow.endpoint_a)} -> ${shortEndpoint(flow.endpoint_b)} / ${formatBytes(flow.bytes)} ${formatMilliPercent(flow.byte_share_milli)}`;
}

function hotFlowTitle(flow) {
  if (!flow) return "no flow-routed packets on this shard";
  return [
    flow.stream_id_hex || "",
    `${flow.protocol} ${flow.endpoint_a} -> ${flow.endpoint_b}`,
    `${formatNumber(flow.packets)} packets, ${formatBytes(flow.bytes)}`,
    `packet share ${formatMilliPercent(flow.packet_share_milli)}, byte share ${formatMilliPercent(flow.byte_share_milli)}`,
  ].filter(Boolean).join(" / ");
}

function shortEndpoint(endpoint) {
  const value = String(endpoint || "");
  return value.length > 24 ? `${value.slice(0, 10)}..${value.slice(-10)}` : value;
}

function rowPassesCurrentFilters(row) {
  if (!state.showHidden && row.hidden) return false;
  if (state.onlyFavorites && !row.favorite) return false;
  if (state.onlyMatched && Number(row.match_count || 0) === 0) return false;
  const service = el.service.value.trim().toLowerCase();
  if (service && (row.service?.name || "").toLowerCase() !== service) return false;
  const port = Number.parseInt(el.port.value, 10);
  if (Number.isFinite(port) && row.endpoint_a?.port !== port && row.endpoint_b?.port !== port) return false;
  const profileId = el.profile.value;
  if (profileId && !rowMatchesProfile(row, profileId)) return false;
  return true;
}

function bindControls() {
  el.reload.addEventListener("click", () => reloadStreams().catch(showError));
  el.favorites.addEventListener("click", () => {
    state.onlyFavorites = !state.onlyFavorites;
    el.favorites.setAttribute("aria-pressed", String(state.onlyFavorites));
    reloadStreams().catch(showError);
  });
  el.matched.addEventListener("click", () => {
    state.onlyMatched = !state.onlyMatched;
    el.matched.setAttribute("aria-pressed", String(state.onlyMatched));
    reloadStreams().catch(showError);
  });
  el.hidden.addEventListener("click", () => {
    state.showHidden = !state.showHidden;
    el.hidden.setAttribute("aria-pressed", String(state.showHidden));
    reloadStreams().catch(showError);
  });
  el.profile.addEventListener("change", () => reloadStreams().catch(showError));
  el.service.addEventListener("change", () => reloadStreams().catch(showError));
  el.port.addEventListener("change", () => reloadStreams().catch(showError));
  el.favorite.addEventListener("click", () => {
    const row = selectedRow();
    if (!row) return;
    patchStreamState({ favorite: !row.favorite }).catch(showError);
  });
  el.hide.addEventListener("click", () => {
    const row = selectedRow();
    if (!row) return;
    patchStreamState({ hidden: !row.hidden }).catch(showError);
  });
  el.hideService.addEventListener("click", async () => {
    const row = selectedRow();
    const service = row?.service?.name;
    if (!service || service === "unknown") return;
    await api("/api/view/hide-rules", {
      method: "POST",
      body: JSON.stringify({ kind: "service", value: service }),
    });
    await reloadStreams();
  });
  for (const control of [el.direction, el.mode, el.transform]) {
    control.addEventListener("change", () => loadContent().catch(showError));
  }
  el.prev.addEventListener("click", () => {
    const len = numberValue(el.len.value, 65536);
    el.start.value = Math.max(0, numberValue(el.start.value, 0) - len);
    loadContent().catch(showError);
  });
  el.next.addEventListener("click", () => {
    const len = numberValue(el.len.value, 65536);
    el.start.value = numberValue(el.start.value, 0) + len;
    loadContent().catch(showError);
  });
  el.matchPrev.addEventListener("click", () => jumpMatch(-1).catch(showError));
  el.matchNext.addEventListener("click", () => jumpMatch(1).catch(showError));
  el.start.addEventListener("change", () => loadContent().catch(showError));
  el.len.addEventListener("change", () => loadContent().catch(showError));
  el.copy.addEventListener("click", () => copyContent().catch(showError));
  el.tableWrap.addEventListener("scroll", () => {
    renderRows();
    const nearBottom = el.tableWrap.scrollTop + el.tableWrap.clientHeight > el.tableWrap.scrollHeight - ROW_HEIGHT * 20;
    if (nearBottom && state.nextCursor !== null) {
      loadStreamsPage().catch(showError);
    }
  });
  window.addEventListener("keydown", event => handleKeydown(event).catch(showError));
}

async function patchStreamState(patch) {
  if (!state.selectedId) return;
  const response = await api(`/api/streams/${encodeURIComponent(state.selectedId)}/state`, {
    method: "PATCH",
    body: JSON.stringify(patch),
  });
  const id = streamId(response.row);
  if (rowPassesCurrentFilters(response.row)) {
    state.streams.set(id, response.row);
  } else {
    state.streams.delete(id);
    state.selectedId = null;
  }
  rebuildRowOrder();
  updateStateButtons(response.row);
  renderRows();
  if (!state.selectedId && state.rowIds[0]) {
    await selectStream(state.rowIds[0]);
  } else if (!state.rowIds.length) {
    clearDetails();
  }
}

async function handleKeydown(event) {
  if (event.defaultPrevented || isTypingTarget(event.target)) return;
  const key = event.key.toLowerCase();
  if (key === "arrowdown" || key === "j") {
    event.preventDefault();
    await moveSelection(1);
  } else if (key === "arrowup" || key === "k") {
    event.preventDefault();
    await moveSelection(-1);
  } else if (key === "enter") {
    event.preventDefault();
    await selectStream(state.selectedId);
  } else if (key === "n") {
    event.preventDefault();
    await jumpMatch(1);
  } else if (key === "p") {
    event.preventDefault();
    await jumpMatch(-1);
  } else if (key === "f") {
    event.preventDefault();
    const row = selectedRow();
    if (row) await patchStreamState({ favorite: !row.favorite });
  } else if (key === "h") {
    event.preventDefault();
    const row = selectedRow();
    if (row) await patchStreamState({ hidden: !row.hidden });
  } else if (key === "c") {
    event.preventDefault();
    await copyContent();
  } else if (key === "/") {
    event.preventDefault();
    el.service.focus();
    el.service.select();
  }
}

async function moveSelection(delta) {
  if (!state.rowIds.length) return;
  const selectedIndex = state.rowIds.indexOf(state.selectedId);
  if (selectedIndex < 0) {
    await selectStream(state.rowIds[0]);
    return;
  }
  const current = Math.max(0, selectedIndex);
  let next = Math.max(0, Math.min(state.rowIds.length - 1, current + delta));
  if (delta > 0 && next >= state.rowIds.length - 3 && state.nextCursor !== null) {
    await loadStreamsPage();
    next = Math.max(0, Math.min(state.rowIds.length - 1, current + delta));
  }
  await selectStream(state.rowIds[next]);
}

function ensureRowVisible(id) {
  const index = state.rowIds.indexOf(id);
  if (index < 0) return;
  const rowTop = index * ROW_HEIGHT;
  const rowBottom = rowTop + ROW_HEIGHT;
  if (rowTop < el.tableWrap.scrollTop) {
    el.tableWrap.scrollTop = rowTop;
  } else if (rowBottom > el.tableWrap.scrollTop + el.tableWrap.clientHeight) {
    el.tableWrap.scrollTop = rowBottom - el.tableWrap.clientHeight;
  }
}

async function copyContent() {
  if (!state.lastSlice) return;
  const format = el.copyFormat.value;
  let text;
  if (format === "decoded") {
    text = decodedText() || viewText();
  } else if (format === "text") {
    text = sliceText(state.lastSlice);
  } else if (format === "hex") {
    text = bytesToHex(sliceBytes(state.lastSlice));
  } else if (format === "base64") {
    text = bytesToBase64(sliceBytes(state.lastSlice));
  } else {
    text = viewText();
  }
  await writeClipboard(text);
  el.status.textContent = `copied ${format} / ${formatNumber(text.length)} chars`;
}

async function writeClipboard(text) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(text);
    return;
  }
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  document.body.append(textarea);
  textarea.select();
  document.execCommand("copy");
  textarea.remove();
}

function decodedText() {
  const transforms = state.lastSlice?.transforms || [];
  const applied = transforms.find(transform => transform.status === "applied" && transform.segments?.length);
  return applied ? applied.segments.map(segmentText).join("\n\n") : "";
}

function viewText() {
  return el.content.textContent || "";
}

function sliceText(slice) {
  return (slice.segments || []).map(segment => {
    if (segment.view.kind === "text") return segment.view.text || "";
    if (segment.view.kind === "hex") return (segment.view.rows || []).map(row => row.ascii).join("\n");
    return bytesToSafeText(base64ToBytes(segment.base64 || segment.view.base64 || ""));
  }).join("\n\n");
}

function sliceBytes(slice) {
  const parts = (slice.segments || []).map(segment => base64ToBytes(segment.base64 || segment.view.base64 || ""));
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function base64ToBytes(base64) {
  const binary = atob(base64 || "");
  const out = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    out[index] = binary.charCodeAt(index);
  }
  return out;
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function bytesToHex(bytes) {
  return [...bytes].map(byte => byte.toString(16).padStart(2, "0")).join(" ");
}

function bytesToSafeText(bytes) {
  return [...bytes].map(byte => {
    if (byte === 10) return "\n";
    if (byte === 13) return "\r";
    if (byte === 9) return "\t";
    return byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : ".";
  }).join("");
}

function showError(error) {
  el.status.textContent = error.message;
}

function shortId(id) {
  const value = String(id);
  return value.length > 12 ? `${value.slice(0, 6)}..${value.slice(-6)}` : value;
}

function streamId(value) {
  return value?.stream_id_hex || String(value?.stream_id || "");
}

function selectedRow() {
  return state.selectedId ? state.streams.get(state.selectedId) : null;
}

function clearDetails() {
  state.selectedId = null;
  state.lastSlice = null;
  state.matches = [];
  state.matchIndex = -1;
  el.title.textContent = "No stream selected";
  el.subtitle.textContent = "Select a row to inspect content";
  el.content.textContent = "";
  el.matchesList.innerHTML = '<div class="muted">No retained matches</div>';
  el.transformView.innerHTML = '<div class="muted">No transform selected</div>';
  updateStateButtons({});
}

function rowMatchesProfile(row, profileId) {
  const profile = state.profiles.find(item => item.profile?.id === profileId)?.profile;
  if (!profile?.enabled) return false;
  if (profile.protocol && row.protocol !== profile.protocol) return false;
  if (profile.id === "matched") return Number(row.match_count || 0) !== 0;
  const serviceMatch = (profile.services || []).some(service => (row.service?.name || "").toLowerCase() === service.toLowerCase());
  const portMatch = (profile.ports || []).some(port => row.endpoint_a?.port === port || row.endpoint_b?.port === port);
  const contentMatch = profile.content_kind && row.content_kind === profile.content_kind;
  const patternMatch = (profile.pattern_ids || []).some(pattern => (row.pattern_ids || []).includes(pattern));
  return serviceMatch || portMatch || contentMatch || patternMatch;
}

function optionElement(value, text) {
  const option = document.createElement("option");
  option.value = value;
  option.textContent = text;
  return option;
}

function endpoint(endpointValue) {
  if (!endpointValue) return "";
  return `${endpointValue.addr}:${endpointValue.port}`;
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString("en-US");
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${formatNumber(bytes)} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let scaled = bytes / 1024;
  let unit = units[0];
  for (let index = 1; index < units.length && scaled >= 1024; index += 1) {
    scaled /= 1024;
    unit = units[index];
  }
  return `${scaled >= 10 ? scaled.toFixed(1) : scaled.toFixed(2)} ${unit}`;
}

function formatMilliRatio(value) {
  return `${(Number(value || 0) / 1000).toFixed(2)}x`;
}

function formatMilliPercent(value) {
  return `${(Number(value || 0) / 10).toFixed(1)}%`;
}

function formatWarning(value) {
  return String(value || "").replaceAll("_", " ");
}

function fallbackBreakdown(fallback, malformed) {
  if (malformed > 0) return `${formatNumber(fallback)} / bad ${formatNumber(malformed)}`;
  return formatNumber(fallback);
}

function serviceSummary(service) {
  if (!service) return "unknown";
  const source = service.source ? ` ${service.source}` : "";
  const evidence = service.evidence ? ` ${service.evidence}` : "";
  return `${service.name || "unknown"}${source}${evidence} ${formatNumber(service.confidence || 0)}%`;
}

function serviceEvidence(service) {
  if (!service) return "unknown";
  return serviceSummary(service);
}

function ratio(part, total) {
  const denominator = Number(total || 0);
  if (denominator <= 0) return 0;
  return Number(part || 0) / denominator;
}

function firstPositive(...values) {
  for (const value of values) {
    const number = Number(value);
    if (Number.isFinite(number) && number > 0) return number;
  }
  return 0;
}

function numberValue(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function isTypingTarget(target) {
  return ["INPUT", "SELECT", "TEXTAREA"].includes(target?.tagName) || target?.isContentEditable;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

bindControls();
loadHealth()
  .then(loadProfiles)
  .then(() => loadStreamsPage(0))
  .then(pollDeltas)
  .catch(showError);
