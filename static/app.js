const subnetEl = document.getElementById("subnet");
const lastScanEl = document.getElementById("lastScan");
const countEl = document.getElementById("count");
const rowsEl = document.getElementById("deviceRows");
const statusEl = document.getElementById("status");
const refreshButton = document.getElementById("refreshButton");
const nmapStatusEl = document.getElementById("nmapStatus");

const formatTime = (iso) => {
  if (!iso) return "-";
  return new Date(iso).toLocaleString();
};

const escapeHtml = (value) =>
  String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");

const setStatus = (message) => {
  statusEl.textContent = message;
};

const servicesLabel = (services) => {
  if (!services || !services.length) return "-";
  return services.slice(0, 3).join(" | ");
};

const renderRows = (devices) => {
  rowsEl.innerHTML = "";

  if (!devices.length) {
    rowsEl.innerHTML = '<tr><td colspan="11">No devices found.</td></tr>';
    return;
  }

  devices.forEach((device) => {
    const tr = document.createElement("tr");

    const status = escapeHtml(device.status || "unknown");
    const statusClass = status === "online" ? "status-online" : "status-offline";

    tr.innerHTML = `
      <td><span class="status ${statusClass}">${status}</span></td>
      <td>${escapeHtml(device.name || "-")}</td>
      <td>${escapeHtml(device.type || "Unknown")}</td>
      <td>${escapeHtml(device.os_guess || "Unknown")}</td>
      <td>${escapeHtml(servicesLabel(device.nmap_services))}</td>
      <td>${escapeHtml(device.vendor || "Unknown")}</td>
      <td>${escapeHtml(device.ip || "-")}</td>
      <td>${escapeHtml(device.mac || "-")}</td>
      <td>${escapeHtml(device.hostname || "unknown")}</td>
      <td>${escapeHtml(device.confidence || "low")}</td>
      <td>${formatTime(device.last_seen)}</td>
    `;

    rowsEl.appendChild(tr);
  });
};

const updateView = (payload) => {
  subnetEl.textContent = payload.subnet || "-";
  lastScanEl.textContent = formatTime(payload.scanned_at);
  countEl.textContent = payload.count || 0;

  if (payload.nmap_enabled && payload.nmap_available) {
    nmapStatusEl.textContent = "enabled";
  } else if (payload.nmap_enabled && !payload.nmap_available) {
    nmapStatusEl.textContent = "enabled (binary missing)";
  } else {
    nmapStatusEl.textContent = "disabled";
  }

  renderRows(payload.devices || []);
};

const loadDevices = async () => {
  try {
    setStatus("Loading devices...");
    const res = await fetch("/api/devices");
    const data = await res.json();
    updateView(data);
    setStatus("Live updates connected");
  } catch (error) {
    setStatus("Failed to load devices");
  }
};

const runScan = async () => {
  try {
    refreshButton.disabled = true;
    setStatus("Running network scan...");
    const res = await fetch("/api/scan", { method: "POST" });
    const data = await res.json();
    updateView(data);
    setStatus("Scan complete");
  } catch (error) {
    setStatus("Scan failed");
  } finally {
    refreshButton.disabled = false;
  }
};

const connectStream = () => {
  const source = new EventSource("/api/stream");

  source.addEventListener("devices", (event) => {
    try {
      const data = JSON.parse(event.data);
      updateView(data);
      setStatus("Live updates connected");
    } catch (_) {
      setStatus("Live stream parse error");
    }
  });

  source.onerror = () => {
    setStatus("Live stream reconnecting...");
  };
};

refreshButton.addEventListener("click", runScan);
loadDevices();
connectStream();
setInterval(loadDevices, 60000);
