const state = {
  streams: new Map(),
  selectedId: null,
  deltaCursor: 0,
  onlyMatched: true,
  lastSlice: null,
  polling: false,
};

const el = {
  status: document.getElementById("status-line"),
  streams: document.getElementById("stat-streams"),
  matches: document.getElementById("stat-matches"),
  packets: document.getElementById("stat-packets"),
  drops: document.getElementById("stat-drops"),
  rows: document.getElementById("stream-rows"),
  service: document.getElementById("filter-service"),
  port: document.getElementById("filter-port"),
  matched: document.getElementById("toggle-matched"),
  reload: document.getElementById("reload-streams"),
  title: document.getElementById("stream-title"),
  subtitle: document.getElementById("stream-subtitle"),
  direction: document.getElementById("direction-select"),
  mode: document.getElementById("mode-select"),
  transform: document.getElementById("transform-select"),
  start: document.getElementById("slice-start"),
  len: document.getElementById("slice-len"),
  prev: document.getElementById("slice-prev"),
  next: document.getElementById("slice-next"),
  copy: document.getElementById("copy-content"),
  content: document.getElementById("content-view"),
  matchesList: document.getElementById("match-list"),
  transformView: document.getElementById("transform-view"),
};

async function api(path) {
  const response = await fetch(path, { cache: "no-store" });
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
  const health = await api("/api/health");
  updateStats(health);
  state.deltaCursor = Math.max(state.deltaCursor, health.latest_delta_cursor || 0);
}

function updateStats(healthOrDelta) {
  const stats = healthOrDelta.stats || {};
  const view = healthOrDelta.view || {};
  el.status.textContent = `${healthOrDelta.run_status || "running"} / cursor ${healthOrDelta.latest_delta_cursor ?? state.deltaCursor}`;
  el.streams.textContent = formatNumber(view.tracked_streams ?? stats.view_tracked_streams ?? 0);
  el.matches.textContent = formatNumber(stats.pattern_matches ?? 0);
  el.packets.textContent = formatNumber(stats.packets ?? 0);
  el.drops.textContent = formatNumber((stats.source_dropped_packets ?? 0) + (stats.source_interface_dropped_packets ?? 0));
}

async function loadStreams() {
  const params = {
    limit: 500,
    include_hidden: true,
    only_matched: state.onlyMatched,
    service: el.service.value.trim(),
    port: el.port.value.trim(),
  };
  const result = await api(`/api/streams?${query(params)}`);
  state.streams.clear();
  for (const row of result.rows) {
    state.streams.set(streamId(row), row);
  }
  renderRows();
  if (!state.selectedId && result.rows[0]) {
    selectStream(streamId(result.rows[0]));
  }
}

function renderRows() {
  const rows = [...state.streams.values()].sort((a, b) => b.last_seen_us - a.last_seen_us);
  el.rows.replaceChildren(...rows.map(rowElement));
}

function rowElement(row) {
  const tr = document.createElement("tr");
  const id = streamId(row);
  tr.className = id === state.selectedId ? "selected" : "";
  tr.addEventListener("click", () => selectStream(id));
  tr.innerHTML = `
    <td title="${id}">${shortId(id)}</td>
    <td>${escapeHtml(row.service?.name || "unknown")}</td>
    <td>${escapeHtml(row.content_kind || "unknown")}</td>
    <td>${formatNumber(row.stream_bytes || row.payload_bytes || 0)}</td>
    <td>${formatNumber(row.match_count || 0)}</td>
  `;
  return tr;
}

async function selectStream(id) {
  state.selectedId = id;
  renderRows();
  const detail = await api(`/api/streams/${encodeURIComponent(id)}`);
  const row = detail.row;
  el.title.textContent = shortId(id);
  el.subtitle.textContent = `${row.protocol} ${endpoint(row.endpoint_a)} -> ${endpoint(row.endpoint_b)} / ${row.service?.name || "unknown"}`;
  renderMatches(detail.matches || []);
  await loadContent();
}

async function loadContent() {
  if (!state.selectedId) {
    return;
  }
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
    appendSegmentView(segment, slice.highlights.filter(h => h.segment_index === index));
    if (index + 1 < slice.segments.length) {
      el.content.append("\n\n");
    }
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

function renderMatches(matches) {
  if (!matches.length) {
    el.matchesList.innerHTML = '<div class="muted">No retained matches</div>';
    return;
  }
  el.matchesList.replaceChildren(...matches.map(match => {
    const item = document.createElement("div");
    item.className = "match-item";
    item.innerHTML = `<b>${escapeHtml(match.pattern_name)}</b><br>
      ${escapeHtml(match.direction)} ${match.logical_start}-${match.logical_end}<br>
      <span class="muted">${escapeHtml(match.pattern_type)} / ${escapeHtml(match.pattern_id)}</span>`;
    item.addEventListener("click", () => {
      el.direction.value = match.direction;
      el.start.value = Math.max(0, Number(match.logical_start) - 64);
      loadContent().catch(showError);
    });
    return item;
  }));
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
    item.innerHTML = `<b>${escapeHtml(transform.applied)}</b> <span class="${statusClass}">${escapeHtml(transform.status)}</span><br>
      ${formatNumber(transform.input_bytes)} -> ${formatNumber(transform.output_bytes)} bytes<br>
      <span class="muted">${escapeHtml((transform.notes || []).join("; "))}</span>`;
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
        await loadStreams();
      }
      for (const delta of result.deltas || []) {
        applyDelta(delta);
      }
      state.deltaCursor = result.next_cursor ?? state.deltaCursor;
      el.status.textContent = `${result.run_status || "running"} / cursor ${state.deltaCursor}`;
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
      if (!state.onlyMatched || row.match_count > 0) {
        state.streams.set(streamId(row), row);
      }
    }
    renderRows();
  }
  if (delta.kind === "matches" && state.selectedId) {
    const touched = (delta.matches || []).some(match => streamId(match) === state.selectedId);
    if (touched) {
      selectStream(state.selectedId).catch(showError);
    }
  }
}

function bindControls() {
  el.reload.addEventListener("click", () => loadStreams().catch(showError));
  el.matched.addEventListener("click", () => {
    state.onlyMatched = !state.onlyMatched;
    el.matched.setAttribute("aria-pressed", String(state.onlyMatched));
    loadStreams().catch(showError);
  });
  el.service.addEventListener("change", () => loadStreams().catch(showError));
  el.port.addEventListener("change", () => loadStreams().catch(showError));
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
  el.start.addEventListener("change", () => loadContent().catch(showError));
  el.len.addEventListener("change", () => loadContent().catch(showError));
  el.copy.addEventListener("click", async () => {
    if (!state.lastSlice) return;
    await navigator.clipboard.writeText(el.content.textContent || "");
  });
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

function endpoint(endpointValue) {
  if (!endpointValue) return "";
  return `${endpointValue.addr}:${endpointValue.port}`;
}

function formatNumber(value) {
  return Number(value || 0).toLocaleString("en-US");
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

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

bindControls();
loadHealth()
  .then(loadStreams)
  .then(pollDeltas)
  .catch(showError);
