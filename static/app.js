const el = (id) => document.getElementById(id);

const statusEl = el("status");
const rowsEl = el("deviceRows");
const segRowsEl = el("segmentRows");
const trendRowsEl = el("trendRows");
const unknownRowsEl = el("unknownRows");
const ifaceRowsEl = el("ifaceRows");
const sparkEl = el("spark");
const logRowsEl = el("logRows");
const timelineRowsEl = el("timelineRows");
const hookRowsEl = el("hookRows");
const toastEl = el("toast");
const loadingEl = el("deviceLoading");
const brandLogoEl = document.querySelector(".brand-logo");
const API_KEY = (window.APP_API_KEY || "").trim();

let latestState = null;
let lastUpdateTs = 0;
let toastTimer = null;

const esc = (v) =>
  String(v)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");

const fmtTime = (iso) => (iso ? new Date(iso).toLocaleString() : "-");
const fmtRate = (bps) => {
  const n = Number(bps || 0);
  if (n >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(2)} GB/s`;
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)} MB/s`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(2)} KB/s`;
  return `${Math.round(n)} B/s`;
};

const levelBadge = (level) => {
  const l = (level || "info").toLowerCase();
  if (l === "warn") return `<span class="badge badge-warn">WARN</span>`;
  if (l === "error") return `<span class="badge badge-error">ERROR</span>`;
  return `<span class="badge badge-info">INFO</span>`;
};

const statusBadge = (status) => {
  const s = (status || "unknown").toLowerCase();
  if (s === "online") return `<span class="badge badge-online">ONLINE</span>`;
  if (s === "offline") return `<span class="badge badge-offline">OFFLINE</span>`;
  return esc(status || "unknown");
};

const apiUrl = (path) => {
  if (!API_KEY) return path;
  const joiner = path.includes("?") ? "&" : "?";
  return `${path}${joiner}api_key=${encodeURIComponent(API_KEY)}`;
};

const apiHeaders = (base = {}) => (API_KEY ? { ...base, "X-API-Key": API_KEY } : base);

function showToast(message, tone = "info") {
  toastEl.textContent = message;
  toastEl.style.borderLeftColor = tone === "error" ? "#ef4444" : tone === "warn" ? "#f59e0b" : "#38bdf8";
  toastEl.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toastEl.classList.remove("show"), 2600);
}

function validateMac(value) {
  return /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(value || "");
}

function validateUrl(value) {
  try {
    const u = new URL(value);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

function setLoading(loading) {
  loadingEl.style.display = loading ? "block" : "none";
}

function updateLastLive() {
  if (!lastUpdateTs) {
    el("lastLiveUpdate").textContent = "-";
    return;
  }
  const sec = Math.max(0, Math.floor((Date.now() - lastUpdateTs) / 1000));
  el("lastLiveUpdate").textContent = `${sec}s ago`;
}

function renderSegments(segments) {
  segRowsEl.innerHTML = "";
  if (!segments || !segments.length) {
    segRowsEl.innerHTML = '<tr><td colspan="2">No segments</td></tr>';
    return;
  }
  segments.forEach((s) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(s.segment)}</td><td>${esc(s.online)}</td>`;
    segRowsEl.appendChild(tr);
  });
}

function renderTraffic(t) {
  t = t || {};
  el("rxRate").textContent = fmtRate(t.rx_bps);
  el("txRate").textContent = fmtRate(t.tx_bps);
  el("totalRate").textContent = fmtRate(t.total_bps);

  ifaceRowsEl.innerHTML = "";
  (t.interfaces || []).forEach((i) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(i.name)}</td><td>${esc(fmtRate(i.total_bps))}</td>`;
    ifaceRowsEl.appendChild(tr);
  });
  if (!ifaceRowsEl.innerHTML) ifaceRowsEl.innerHTML = '<tr><td colspan="2">No data</td></tr>';

  sparkEl.innerHTML = "";
  const history = (t.history || []).slice(-40);
  if (!history.length) return;
  const max = Math.max(...history.map((h) => h.total_bps || 0), 1);
  history.forEach((p) => {
    const bar = document.createElement("span");
    bar.className = "bar";
    bar.style.height = `${Math.max(6, Math.round((p.total_bps / max) * 100))}%`;
    bar.title = `${fmtTime(p.ts)} ${fmtRate(p.total_bps)}`;
    sparkEl.appendChild(bar);
  });
}

function renderTrends(tr) {
  const daily = tr?.daily || [];
  trendRowsEl.innerHTML = "";
  if (!daily.length) {
    trendRowsEl.innerHTML = '<tr><td colspan="5">No trend data</td></tr>';
  } else {
    daily.forEach((d) => {
      const trEl = document.createElement("tr");
      trEl.innerHTML = `<td>${esc(d.day)}</td><td>${esc(d.online_count || 0)}</td><td>${esc(d.new_count || 0)}</td><td>${esc(d.offline_count || 0)}</td><td>${esc(d.anomaly_count || 0)}</td>`;
      trendRowsEl.appendChild(trEl);
    });
  }

  el("churnNew").textContent = tr?.churn?.new_devices || 0;
  el("churnOffline").textContent = tr?.churn?.offline_devices || 0;

  unknownRowsEl.innerHTML = "";
  (tr?.top_unknown_devices || []).forEach((u) => {
    const trEl = document.createElement("tr");
    trEl.innerHTML = `<td>${esc(u.mac)}</td><td>${esc(u.last_ip || "-")}</td><td>${esc(u.recurring_unknown_score || 0)}</td>`;
    unknownRowsEl.appendChild(trEl);
  });
  if (!unknownRowsEl.innerHTML) unknownRowsEl.innerHTML = '<tr><td colspan="3">No unknown recurring devices</td></tr>';
}

function getEventFilterState() {
  return {
    level: el("eventFilter").value,
    q: el("eventSearch").value.trim().toLowerCase(),
  };
}

function renderLogs(logs) {
  const f = getEventFilterState();
  logRowsEl.innerHTML = "";
  let items = (logs || []).slice(0, 120);

  if (f.level !== "all") items = items.filter((l) => (l.level || "info") === f.level);
  if (f.q) items = items.filter((l) => (l.message || "").toLowerCase().includes(f.q));

  items = items.slice(0, 40);

  if (!items.length) {
    logRowsEl.innerHTML = '<tr><td colspan="3">No events</td></tr>';
    return;
  }
  items.forEach((l) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${esc(fmtTime(l.ts))}</td><td>${levelBadge(l.level)}</td><td>${esc(l.message || "")}</td>`;
    logRowsEl.appendChild(tr);
  });
}

function getDeviceFilterState() {
  return {
    q: el("deviceSearch").value.trim().toLowerCase(),
    status: el("statusFilter").value,
    type: el("typeFilter").value.trim().toLowerCase(),
    segment: el("segmentFilter").value.trim().toLowerCase(),
    sortBy: el("sortBy").value,
    sortDir: el("sortDir").value,
  };
}

function ipToInt(ip) {
  if (!ip || ip === "-") return Number.MAX_SAFE_INTEGER;
  return ip.split(".").reduce((a, x) => (a * 256) + Number(x), 0);
}

function applyDeviceFilters(devices) {
  const f = getDeviceFilterState();
  let list = [...(devices || [])];

  if (f.status !== "all") list = list.filter((d) => (d.status || "").toLowerCase() === f.status);
  if (f.type) list = list.filter((d) => (d.type || "").toLowerCase().includes(f.type));
  if (f.segment) list = list.filter((d) => (d.segment || "").toLowerCase().includes(f.segment));
  if (f.q) {
    list = list.filter((d) => {
      const blob = `${d.name || ""} ${d.ip || ""} ${d.mac || ""} ${d.vendor || ""} ${d.type || ""}`.toLowerCase();
      return blob.includes(f.q);
    });
  }

  list.sort((a, b) => {
    let va = "";
    let vb = "";
    if (f.sortBy === "ip") {
      va = ipToInt(a.ip);
      vb = ipToInt(b.ip);
    } else if (f.sortBy === "last_seen") {
      va = Date.parse(a.last_seen || 0);
      vb = Date.parse(b.last_seen || 0);
    } else if (f.sortBy === "unknown_score") {
      va = Number(a.recurring_unknown_score || 0);
      vb = Number(b.recurring_unknown_score || 0);
    } else if (f.sortBy === "status") {
      va = (a.status || "");
      vb = (b.status || "");
    } else {
      va = (a.name || "").toLowerCase();
      vb = (b.name || "").toLowerCase();
    }

    const cmp = va > vb ? 1 : va < vb ? -1 : 0;
    return f.sortDir === "desc" ? -cmp : cmp;
  });

  return list;
}

function renderDevices(devices) {
  rowsEl.innerHTML = "";
  const filtered = applyDeviceFilters(devices || []);

  if (!filtered.length) {
    rowsEl.innerHTML = '<tr><td colspan="12">No devices found</td></tr>';
    return;
  }

  filtered.forEach((d) => {
    const tr = document.createElement("tr");
    const ports = (d.open_ports || []).join(", ") || "-";
    tr.innerHTML = `
      <td>${statusBadge(d.status)}</td>
      <td>${esc(d.name || "-")}</td>
      <td>${esc(d.type || "Unknown")}</td>
      <td>${esc(d.vendor || "Unknown")}</td>
      <td>${esc(d.ip || "-")}</td>
      <td>${esc(d.mac || "-")}</td>
      <td>${esc(d.segment || "-")}</td>
      <td>${esc(ports)}</td>
      <td>${esc(d.avg_session_seconds || 0)}s</td>
      <td>${esc(d.recurring_unknown_score || 0)}</td>
      <td>${esc(d.confidence || "low")}</td>
      <td>${esc(fmtTime(d.last_seen))}</td>
    `;
    rowsEl.appendChild(tr);
  });
}

function renderHooks(hooks) {
  hookRowsEl.innerHTML = "";
  (hooks || []).forEach((h) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${h.id}</td><td>${esc(h.url)}</td><td>${esc(h.events)}</td><td>${h.enabled ? "yes" : "no"}</td><td>${esc(fmtTime(h.created_at))}</td>`;
    hookRowsEl.appendChild(tr);
  });
  if (!hookRowsEl.innerHTML) hookRowsEl.innerHTML = '<tr><td colspan="5">No webhooks</td></tr>';
}

function render(state) {
  latestState = state;
  el("subnets").textContent = (state.subnets || []).join(", ") || "-";
  el("lastScan").textContent = fmtTime(state.scanned_at);
  el("count").textContent = state.count || 0;
  el("queueDepth").textContent = state.queue_depth || 0;

  if (state.nmap_enabled && state.nmap_available) el("nmapStatus").textContent = "enabled";
  else if (state.nmap_enabled && !state.nmap_available) el("nmapStatus").textContent = "enabled (binary missing)";
  else el("nmapStatus").textContent = "disabled";

  statusEl.textContent = state.scan_in_progress ? `Scanning (${state.last_profile || "fast"})...` : "Live";
  if (brandLogoEl) {
    const hasThreat = (state.logs || []).slice(0, 40).some((entry) => (entry.level || "").toLowerCase() === "error");
    brandLogoEl.dataset.state = hasThreat ? "threat" : state.scan_in_progress ? "monitoring" : "idle";
  }

  renderSegments(state.segments || []);
  renderTraffic(state.traffic || {});
  renderTrends(state.trends || {});
  renderLogs(state.logs || []);
  renderDevices(state.devices || []);

  lastUpdateTs = Date.now();
  updateLastLive();
}

async function loadDevices() {
  try {
    setLoading(true);
    const res = await fetch(apiUrl("/api/devices"), { headers: apiHeaders() });
    const data = await res.json();
    render(data);
  } catch (_) {
    statusEl.textContent = "Failed to load";
    showToast("Failed to load devices", "error");
  } finally {
    setLoading(false);
  }
}

async function queueScan() {
  try {
    const profile = el("scanProfile").value;
    statusEl.textContent = `Queueing ${profile} scan...`;
    const res = await fetch(apiUrl("/api/scan"), {
      method: "POST",
      headers: apiHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ profile }),
    });
    const data = await res.json();
    render(data);
    showToast(`${profile} scan queued`, "info");
  } catch (_) {
    statusEl.textContent = "Scan queue failed";
    showToast("Scan queue failed", "error");
  }
}

async function loadTimeline() {
  const mac = el("timelineMac").value.trim().toLowerCase();
  if (!validateMac(mac)) {
    showToast("Invalid MAC format. Use aa:bb:cc:dd:ee:ff", "warn");
    return;
  }
  try {
    const res = await fetch(apiUrl(`/api/timeline/${encodeURIComponent(mac)}`), { headers: apiHeaders() });
    const data = await res.json();
    timelineRowsEl.innerHTML = "";
    (data.events || []).slice(0, 100).forEach((ev) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `<td>${esc(fmtTime(ev.ts))}</td><td>${esc(ev.event_type)}</td><td>${esc(ev.severity)}</td><td>${esc(ev.ip || "-")}</td><td>${esc(ev.details?.summary || "-")}</td>`;
      timelineRowsEl.appendChild(tr);
    });
    if (!timelineRowsEl.innerHTML) timelineRowsEl.innerHTML = '<tr><td colspan="5">No events</td></tr>';
    showToast(`Timeline loaded for ${mac}`, "info");
  } catch (_) {
    timelineRowsEl.innerHTML = '<tr><td colspan="5">Failed to load timeline</td></tr>';
    showToast("Failed to load timeline", "error");
  }
}

async function loadHooks() {
  try {
    const res = await fetch(apiUrl("/api/webhooks"), { headers: apiHeaders() });
    const data = await res.json();
    renderHooks(data.webhooks || []);
  } catch (_) {
    renderHooks([]);
  }
}

async function addHook() {
  const url = el("hookUrl").value.trim();
  if (!validateUrl(url)) {
    showToast("Invalid webhook URL", "warn");
    return;
  }

  const eventsRaw = el("hookEvents").value.trim();
  const events = eventsRaw ? eventsRaw.split(",").map((x) => x.trim()).filter(Boolean) : ["*"];
  try {
    const res = await fetch(apiUrl("/api/webhooks"), {
      method: "POST",
      headers: apiHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({ url, events }),
    });
    if (res.ok) {
      el("hookUrl").value = "";
      el("hookEvents").value = "";
      await loadHooks();
      showToast("Webhook added", "info");
    } else {
      showToast("Failed to add webhook", "error");
    }
  } catch (_) {
    showToast("Failed to add webhook", "error");
  }
}

function connectStream() {
  const source = new EventSource(apiUrl("/api/stream"));
  source.addEventListener("update", (event) => {
    try {
      render(JSON.parse(event.data));
    } catch (_) {
      statusEl.textContent = "Stream parse error";
      showToast("Stream parse error", "error");
    }
  });
  source.onerror = () => {
    statusEl.textContent = "Stream reconnecting...";
  };
}

["eventFilter", "eventSearch", "deviceSearch", "statusFilter", "typeFilter", "segmentFilter", "sortBy", "sortDir"].forEach((id) => {
  el(id).addEventListener("input", () => {
    if (latestState) {
      renderLogs(latestState.logs || []);
      renderDevices(latestState.devices || []);
    }
  });
  el(id).addEventListener("change", () => {
    if (latestState) {
      renderLogs(latestState.logs || []);
      renderDevices(latestState.devices || []);
    }
  });
});

el("refreshButton").addEventListener("click", queueScan);
el("loadTimelineBtn").addEventListener("click", loadTimeline);
el("addHookBtn").addEventListener("click", addHook);

loadDevices();
loadHooks();
connectStream();
setInterval(loadDevices, 60000);
setInterval(loadHooks, 120000);
setInterval(updateLastLive, 1000);
