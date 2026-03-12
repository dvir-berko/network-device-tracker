import ipaddress
import os
import shutil
import socket
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Dict, List

import psutil
from flask import Flask, Response, jsonify, render_template
from scapy.all import ARP, Ether, conf, srp

app = Flask(__name__)

SCAN_INTERVAL_SECONDS = int(os.getenv("SCAN_INTERVAL_SECONDS", "25"))
HEARTBEAT_SECONDS = int(os.getenv("HEARTBEAT_SECONDS", "12"))
ENABLE_NMAP_FINGERPRINT = os.getenv("ENABLE_NMAP_FINGERPRINT", "true").lower() in {"1", "true", "yes"}
NMAP_TIMEOUT_SECONDS = int(os.getenv("NMAP_TIMEOUT_SECONDS", "20"))
NMAP_REFRESH_SECONDS = int(os.getenv("NMAP_REFRESH_SECONDS", "1800"))
NMAP_MAX_TARGETS_PER_SCAN = int(os.getenv("NMAP_MAX_TARGETS_PER_SCAN", "2"))
NMAP_BINARY = shutil.which("nmap")
NMAP_AVAILABLE = ENABLE_NMAP_FINGERPRINT and bool(NMAP_BINARY)

_cache_lock = threading.Lock()
_scan_state = {
    "scanned_at": None,
    "subnet": None,
    "count": 0,
    "devices": [],
    "revision": 0,
    "nmap_enabled": ENABLE_NMAP_FINGERPRINT,
    "nmap_available": NMAP_AVAILABLE,
}
_device_registry: Dict[str, dict] = {}
_bg_thread_started = False


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


def _parse_iso(iso_value: str):
    if not iso_value:
        return None
    try:
        return datetime.fromisoformat(iso_value)
    except Exception:
        return None


def _normalize_mac(mac: str) -> str:
    return mac.strip().lower()


def _vendor_for_mac(mac: str) -> str:
    try:
        vendor = conf.manufdb._get_manuf(mac)
        if (
            not vendor
            or vendor.lower().startswith("unknown")
            or _normalize_mac(vendor) == _normalize_mac(mac)
            or ":" in vendor
        ):
            return "Unknown"
        return vendor
    except Exception:
        return "Unknown"


def _resolve_hostname(ip: str) -> str:
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name if name else "unknown"
    except Exception:
        return "unknown"


def _probe_ports(ip: str) -> List[int]:
    common_ports = [22, 53, 80, 443, 445, 554, 8008, 8443, 9100]
    open_ports = []

    for port in common_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        try:
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
        except Exception:
            pass
        finally:
            sock.close()

    return open_ports


def _infer_device_type(hostname: str, vendor: str, open_ports: List[int]) -> str:
    h = (hostname or "").lower()
    v = (vendor or "").lower()
    ports = set(open_ports)

    if 9100 in ports:
        return "Printer"
    if 554 in ports:
        return "Camera"
    if 53 in ports and (80 in ports or 443 in ports):
        return "Router"
    if "iphone" in h or "android" in h or "pixel" in h or "galaxy" in h:
        return "Phone"
    if "ipad" in h or "tablet" in h:
        return "Tablet"
    if "macbook" in h or "laptop" in h or "thinkpad" in h:
        return "Laptop"
    if "desktop" in h or "workstation" in h:
        return "Desktop"
    if "tv" in h or "roku" in h or "chromecast" in h or "firetv" in h:
        return "TV"
    if "playstation" in h or "xbox" in h or "nintendo" in h or "switch" in h:
        return "Game Console"

    if "apple" in v:
        return "Apple Device"
    if "samsung" in v or "xiaomi" in v or "huawei" in v:
        return "Mobile/IoT"
    if "hp" in v or "epson" in v or "canon" in v or "brother" in v:
        return "Printer"

    if ports:
        return "IoT"
    return "Unknown"


def _infer_type_from_nmap(current_type: str, os_guess: str, services: List[str]) -> str:
    os_low = (os_guess or "").lower()
    svc = " ".join(services).lower()

    if "printer" in svc or "ipp" in svc or "jetdirect" in svc:
        return "Printer"
    if "rtsp" in svc or "onvif" in svc:
        return "Camera"
    if "dns" in svc and ("http" in svc or "https" in svc):
        return "Router"
    if "airplay" in svc or "appletv" in svc:
        return "TV"
    if "xbox" in os_low or "playstation" in os_low:
        return "Game Console"
    if "android" in os_low or "ios" in os_low:
        return "Phone"
    if "windows" in os_low:
        return "Desktop" if current_type in {"Unknown", "IoT"} else current_type
    if "linux" in os_low and current_type == "Unknown":
        return "IoT"

    return current_type


def _infer_name(ip: str, hostname: str, vendor: str, device_type: str, os_guess: str) -> str:
    if hostname and hostname != "unknown":
        return hostname

    last_octet = ip.split(".")[-1]
    if vendor != "Unknown":
        return f"{vendor} {device_type} ({last_octet})"
    if os_guess and os_guess != "Unknown":
        short_os = os_guess.split("(")[0].strip()
        return f"{short_os} {device_type} ({last_octet})"
    return f"{device_type} ({last_octet})"


def _confidence(hostname: str, vendor: str, open_ports: List[int], os_guess: str, services: List[str]) -> str:
    score = 0
    if hostname and hostname != "unknown":
        score += 1
    if vendor != "Unknown":
        score += 1
    if open_ports:
        score += 1
    if os_guess and os_guess != "Unknown":
        score += 1
    if services:
        score += 1

    if score >= 4:
        return "high"
    if score >= 2:
        return "medium"
    return "low"


def _get_primary_subnet() -> ipaddress.IPv4Network:
    candidates = []

    for iface_name, addresses in psutil.net_if_addrs().items():
        if iface_name.startswith("lo"):
            continue

        stats = psutil.net_if_stats().get(iface_name)
        if not stats or not stats.isup:
            continue

        for addr in addresses:
            if addr.family.name != "AF_INET":
                continue
            if not addr.address or not addr.netmask:
                continue

            ip_obj = ipaddress.ip_address(addr.address)
            if ip_obj.is_loopback:
                continue

            network = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
            if network.is_private:
                candidates.append(network)

    if not candidates:
        return ipaddress.ip_network("192.168.1.0/24")

    return sorted(candidates, key=lambda n: n.num_addresses, reverse=True)[0]


def _run_nmap_fingerprint(ip: str) -> dict:
    if not NMAP_AVAILABLE:
        return {}

    cmd = [
        NMAP_BINARY,
        "-F",
        "-Pn",
        "--max-retries",
        "1",
        "--host-timeout",
        f"{NMAP_TIMEOUT_SECONDS}s",
        "-oX",
        "-",
        ip,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=NMAP_TIMEOUT_SECONDS + 5,
            check=False,
        )
    except Exception:
        return {}

    if not proc.stdout.strip():
        return {}

    try:
        root = ET.fromstring(proc.stdout)
    except ET.ParseError:
        return {}

    host = root.find("host")
    if host is None:
        return {}

    os_guess = "Unknown"

    services = []
    for port in host.findall("./ports/port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue

        proto = port.get("protocol", "tcp")
        portid = port.get("portid", "?")
        service = port.find("service")

        if service is not None:
            parts = [
                service.get("name", "service"),
                service.get("product", ""),
                service.get("version", ""),
                service.get("extrainfo", ""),
            ]
            service_label = " ".join([p for p in parts if p]).strip()
        else:
            service_label = "service"

        services.append(f"{portid}/{proto} {service_label}")

    return {
        "os_guess": os_guess,
        "nmap_services": services[:6],
        "nmap_scanned_at": _utc_now_iso(),
    }


def _should_refresh_nmap(existing: dict, current_type: str, confidence: str) -> bool:
    if not NMAP_AVAILABLE:
        return False

    if not existing:
        return True

    if existing.get("status") == "offline":
        return False

    last = _parse_iso(existing.get("nmap_scanned_at"))
    if last is None:
        return True

    if _utc_now() - last < timedelta(seconds=NMAP_REFRESH_SECONDS):
        return False

    return current_type in {"Unknown", "IoT", "Mobile/IoT"} or confidence != "high"


def _scan_devices_on_subnet(subnet: ipaddress.IPv4Network) -> List[dict]:
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(subnet))
    answered, _ = srp(packet, timeout=2, retry=1, verbose=0)

    seen = []
    seen_macs = set()
    nmap_runs = 0

    for _, response in answered:
        ip_addr = response.psrc
        mac_addr = _normalize_mac(response.hwsrc)

        if mac_addr in seen_macs:
            continue
        seen_macs.add(mac_addr)

        with _cache_lock:
            existing = dict(_device_registry.get(mac_addr, {}))

        hostname = _resolve_hostname(ip_addr)
        vendor = _vendor_for_mac(mac_addr)
        ports = _probe_ports(ip_addr)
        device_type = _infer_device_type(hostname, vendor, ports)

        os_guess = existing.get("os_guess", "Unknown")
        nmap_services = existing.get("nmap_services", [])
        nmap_scanned_at = existing.get("nmap_scanned_at")

        base_confidence = _confidence(hostname, vendor, ports, os_guess, nmap_services)
        if _should_refresh_nmap(existing, device_type, base_confidence) and nmap_runs < NMAP_MAX_TARGETS_PER_SCAN:
            nmap_data = _run_nmap_fingerprint(ip_addr)
            if nmap_data:
                os_guess = nmap_data.get("os_guess", os_guess)
                nmap_services = nmap_data.get("nmap_services", nmap_services)
                nmap_scanned_at = nmap_data.get("nmap_scanned_at", nmap_scanned_at)
            nmap_runs += 1

        device_type = _infer_type_from_nmap(device_type, os_guess, nmap_services)
        display_name = _infer_name(ip_addr, hostname, vendor, device_type, os_guess)

        seen.append(
            {
                "ip": ip_addr,
                "mac": mac_addr,
                "hostname": hostname,
                "vendor": vendor,
                "type": device_type,
                "name": display_name,
                "open_ports": ports,
                "os_guess": os_guess,
                "nmap_services": nmap_services,
                "nmap_scanned_at": nmap_scanned_at,
                "confidence": _confidence(hostname, vendor, ports, os_guess, nmap_services),
            }
        )

    seen.sort(key=lambda d: ipaddress.ip_address(d["ip"]))
    return seen


def scan_network() -> dict:
    subnet = _get_primary_subnet()
    scanned_devices = _scan_devices_on_subnet(subnet)
    now = _utc_now_iso()

    with _cache_lock:
        online_macs = set()

        for dev in scanned_devices:
            mac = dev["mac"]
            online_macs.add(mac)

            existing = _device_registry.get(mac)
            if existing:
                first_seen = existing["first_seen"]
            else:
                first_seen = now

            _device_registry[mac] = {
                **dev,
                "status": "online",
                "first_seen": first_seen,
                "last_seen": now,
            }

        for mac, dev in _device_registry.items():
            if mac not in online_macs:
                dev["status"] = "offline"

        devices = list(_device_registry.values())
        devices.sort(key=lambda d: (d["status"] != "online", ipaddress.ip_address(d["ip"])))

        _scan_state["scanned_at"] = now
        _scan_state["subnet"] = str(subnet)
        _scan_state["devices"] = devices
        _scan_state["count"] = len([d for d in devices if d["status"] == "online"])
        _scan_state["revision"] += 1
        _scan_state["nmap_enabled"] = ENABLE_NMAP_FINGERPRINT
        _scan_state["nmap_available"] = NMAP_AVAILABLE

        return dict(_scan_state)


def _background_scanner() -> None:
    while True:
        try:
            scan_network()
        except Exception:
            pass
        time.sleep(SCAN_INTERVAL_SECONDS)


def _ensure_background_scanner() -> None:
    global _bg_thread_started
    if _bg_thread_started:
        return

    t = threading.Thread(target=_background_scanner, daemon=True)
    t.start()
    _bg_thread_started = True


@app.before_request
def _startup_once():
    _ensure_background_scanner()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/devices")
def get_devices():
    with _cache_lock:
        is_empty = _scan_state["scanned_at"] is None

    if is_empty:
        return jsonify(scan_network())

    with _cache_lock:
        return jsonify(dict(_scan_state))


@app.route("/api/scan", methods=["POST"])
def trigger_scan():
    return jsonify(scan_network())


@app.route("/api/stream")
def stream_devices():
    def event_stream():
        last_revision = -1

        while True:
            with _cache_lock:
                payload = dict(_scan_state)

            if payload["scanned_at"] is None:
                payload = scan_network()

            if payload["revision"] != last_revision:
                last_revision = payload["revision"]
                yield f"event: devices\\ndata: {json_dumps(payload)}\\n\\n"
            else:
                yield "event: heartbeat\\ndata: {}\\n\\n"

            time.sleep(HEARTBEAT_SECONDS)

    return Response(event_stream(), mimetype="text/event-stream")


def json_dumps(payload: dict) -> str:
    import json

    return json.dumps(payload, separators=(",", ":"))


if __name__ == "__main__":
    _ensure_background_scanner()
    app.run(host="0.0.0.0", port=8080, threaded=True)
