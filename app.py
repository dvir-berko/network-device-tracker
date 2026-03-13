import ipaddress
import hmac
import json
import os
import queue
import shutil
import socket
import sqlite3
import subprocess
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Dict, List
from urllib.parse import urlparse

import psutil
from flask import Flask, Response, jsonify, render_template, request
from scapy.all import ARP, Ether, conf, srp

app = Flask(__name__)

APP_PORT = int(os.getenv("APP_PORT", "8080"))
HEARTBEAT_SECONDS = int(os.getenv("HEARTBEAT_SECONDS", "8"))
SCAN_FAST_INTERVAL = int(os.getenv("SCAN_FAST_INTERVAL", "60"))
SCAN_DEEP_INTERVAL = int(os.getenv("SCAN_DEEP_INTERVAL", "900"))
SCAN_MAX_HOSTS = int(os.getenv("SCAN_MAX_HOSTS", "64"))
NMAP_TIMEOUT_SECONDS = int(os.getenv("NMAP_TIMEOUT_SECONDS", "20"))
NMAP_MAX_TARGETS_PER_SCAN = int(os.getenv("NMAP_MAX_TARGETS_PER_SCAN", "4"))
HOST_CACHE_TTL_SECONDS = int(os.getenv("HOST_CACHE_TTL_SECONDS", "300"))
SCAN_WORKERS = int(os.getenv("SCAN_WORKERS", "1"))
ENRICH_WORKERS = int(os.getenv("ENRICH_WORKERS", "16"))
TRAFFIC_SAMPLE_SECONDS = int(os.getenv("TRAFFIC_SAMPLE_SECONDS", "2"))
TRAFFIC_HISTORY_POINTS = int(os.getenv("TRAFFIC_HISTORY_POINTS", "150"))
DB_PATH = os.getenv("DB_PATH", "data/tracker.db")
ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "").strip()
SCAN_SUBNETS = os.getenv("SCAN_SUBNETS", "").strip()
API_KEYS = {x.strip() for x in os.getenv("API_KEYS", "").split(",") if x.strip()}
UI_API_KEY = os.getenv("UI_API_KEY", "").strip()
CRITICAL_DEVICE_TYPES = {x.strip() for x in os.getenv("CRITICAL_DEVICE_TYPES", "Router,Camera").split(",") if x.strip()}
ENABLE_NMAP_SERVICE_PROBES = os.getenv("ENABLE_NMAP_SERVICE_PROBES", "true").lower() in {"1", "true", "yes"}
MAX_SCAN_SUBNET_HOSTS = int(os.getenv("MAX_SCAN_SUBNET_HOSTS", "512"))
MAX_SUBNETS_PER_SCAN = int(os.getenv("MAX_SUBNETS_PER_SCAN", "8"))
ALLOW_PRIVATE_WEBHOOKS = os.getenv("ALLOW_PRIVATE_WEBHOOKS", "false").lower() in {"1", "true", "yes"}
WEBHOOK_ALLOWLIST = [x.strip().lower() for x in os.getenv("WEBHOOK_ALLOWLIST", "").split(",") if x.strip()]

NMAP_BINARY = shutil.which("nmap")
NMAP_AVAILABLE = ENABLE_NMAP_SERVICE_PROBES and bool(NMAP_BINARY)
NMBLOOKUP_BINARY = shutil.which("nmblookup")
AVAHI_BINARY = shutil.which("avahi-resolve-address")

state_lock = threading.Lock()
scan_queue: queue.Queue = queue.Queue()
worker_started = False
scheduler_started = False
traffic_started = False

scan_cache = {}
event_logs = deque(maxlen=300)
rate_limit_lock = threading.Lock()
rate_limit_state: Dict[str, Dict[str, deque]] = {}

state = {
    "scanned_at": None,
    "count": 0,
    "devices": [],
    "subnets": [],
    "segments": [],
    "revision": 0,
    "live_revision": 0,
    "scan_in_progress": False,
    "queue_depth": 0,
    "last_profile": "fast",
    "nmap_enabled": ENABLE_NMAP_SERVICE_PROBES,
    "nmap_available": NMAP_AVAILABLE,
    "traffic": {
        "updated_at": None,
        "rx_bps": 0,
        "tx_bps": 0,
        "total_bps": 0,
        "interfaces": [],
        "history": [],
    },
}

last_deep_scan_at = None

if not UI_API_KEY and API_KEYS:
    UI_API_KEY = next(iter(API_KEYS))


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat()


def db_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = db_conn()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS devices (
          mac TEXT PRIMARY KEY,
          first_seen TEXT,
          last_seen TEXT,
          last_ip TEXT,
          segment TEXT,
          last_status TEXT,
          last_status_change TEXT,
          total_online_seconds INTEGER DEFAULT 0,
          session_count INTEGER DEFAULT 0,
          avg_session_seconds REAL DEFAULT 0,
          baseline_ports TEXT DEFAULT '[]',
          unknown_vendor_hits INTEGER DEFAULT 0,
          recurring_unknown_score INTEGER DEFAULT 0,
          name TEXT,
          type TEXT,
          vendor TEXT
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS device_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts TEXT,
          mac TEXT,
          ip TEXT,
          event_type TEXT,
          severity TEXT,
          details TEXT
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_runs (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts TEXT,
          profile TEXT,
          subnets TEXT,
          online_count INTEGER,
          new_count INTEGER,
          offline_count INTEGER,
          anomaly_count INTEGER
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS webhooks (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          url TEXT,
          events TEXT,
          enabled INTEGER DEFAULT 1,
          created_at TEXT
        )
        """
    )

    conn.commit()
    conn.close()


def require_api_key(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not is_request_authorized():
            return jsonify({"error": "invalid api key"}), 401
        return fn(*args, **kwargs)

    return wrapped


def get_request_api_key() -> str:
    return (request.headers.get("X-API-Key") or request.args.get("api_key") or "").strip()


def is_request_authorized() -> bool:
    if not API_KEYS:
        return False
    key = get_request_api_key()
    if not key:
        return False
    for valid in API_KEYS:
        if hmac.compare_digest(key, valid):
            return True
    return False


def is_forbidden_webhook_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True
    if not ALLOW_PRIVATE_WEBHOOKS and (ip.is_private or ip.is_site_local):
        return True
    return False


def host_allowed_by_allowlist(host: str) -> bool:
    if not WEBHOOK_ALLOWLIST:
        return True
    host = host.lower()
    return any(host == allowed or host.endswith(f".{allowed}") for allowed in WEBHOOK_ALLOWLIST)


def validate_webhook_url(url: str) -> (bool, str):
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "invalid webhook url"

    if parsed.scheme not in {"http", "https"}:
        return False, "webhook must use http or https"
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return False, "webhook host is required"
    if host in {"localhost", "localhost.localdomain"}:
        return False, "localhost webhook targets are blocked"
    if not host_allowed_by_allowlist(host):
        return False, "webhook host is not in allowlist"

    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except Exception:
        return False, "unable to resolve webhook host"

    ips = {info[4][0] for info in infos if info and info[4]}
    if not ips:
        return False, "unable to resolve webhook host"
    for ip in ips:
        if is_forbidden_webhook_ip(ip):
            return False, f"webhook target {ip} is blocked"

    return True, ""


def validate_requested_subnets(raw_subnets: List[str]) -> (List[ipaddress.IPv4Network], str):
    if not isinstance(raw_subnets, list):
        return [], "subnets must be an array"
    if len(raw_subnets) > MAX_SUBNETS_PER_SCAN:
        return [], f"too many subnets (max {MAX_SUBNETS_PER_SCAN})"

    subnets = []
    for raw in raw_subnets:
        s = str(raw).strip()
        if not s:
            continue
        try:
            net = ipaddress.ip_network(s, strict=False)
        except Exception:
            return [], f"invalid subnet: {s}"
        if net.version != 4:
            return [], "only IPv4 subnets are supported"
        if not net.is_private:
            return [], f"subnet must be private: {s}"
        if net.num_addresses > MAX_SCAN_SUBNET_HOSTS:
            return [], f"subnet too large: {s} ({net.num_addresses} hosts, max {MAX_SCAN_SUBNET_HOSTS})"
        subnets.append(net)

    return subnets, ""


def allow_rate_limit(bucket: str, key: str, limit: int, per_seconds: int) -> bool:
    now = time.time()
    with rate_limit_lock:
        slot = rate_limit_state.setdefault(bucket, {}).setdefault(key, deque())
        while slot and now - slot[0] > per_seconds:
            slot.popleft()
        if len(slot) >= limit:
            return False
        slot.append(now)
    return True


def add_log(level: str, message: str):
    with state_lock:
        event_logs.appendleft({"ts": utc_now_iso(), "level": level, "message": message})
        state["live_revision"] += 1


def emit_event(event_type: str, severity: str, mac: str, ip: str, details: dict):
    conn = db_conn()
    conn.execute(
        "INSERT INTO device_events(ts,mac,ip,event_type,severity,details) VALUES (?,?,?,?,?,?)",
        (utc_now_iso(), mac, ip, event_type, severity, json.dumps(details, separators=(",", ":"))),
    )
    conn.commit()
    conn.close()

    add_log(severity, f"{event_type} {ip} {details.get('summary', '')}".strip())
    notify_integrations(event_type, severity, mac, ip, details)


def notify_integrations(event_type: str, severity: str, mac: str, ip: str, details: dict):
    payload = {
        "ts": utc_now_iso(),
        "event_type": event_type,
        "severity": severity,
        "mac": mac,
        "ip": ip,
        "details": details,
    }

    targets = []
    if ALERT_WEBHOOK_URL:
        targets.append((ALERT_WEBHOOK_URL, ["*"]))

    conn = db_conn()
    rows = conn.execute("SELECT url, events FROM webhooks WHERE enabled=1").fetchall()
    conn.close()

    for row in rows:
        events = [x.strip() for x in (row["events"] or "*").split(",") if x.strip()]
        targets.append((row["url"], events or ["*"]))

    data = json.dumps(payload).encode("utf-8")
    for url, events in targets:
        if "*" not in events and event_type not in events:
            continue
        ok, _ = validate_webhook_url(url)
        if not ok:
            continue
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=4).read()
        except Exception:
            pass


def configured_subnets() -> List[ipaddress.IPv4Network]:
    if SCAN_SUBNETS:
        out = []
        for raw in SCAN_SUBNETS.split(","):
            raw = raw.strip()
            if not raw:
                continue
            try:
                net = ipaddress.ip_network(raw, strict=False)
                if net.version != 4 or not net.is_private:
                    continue
                if net.num_addresses > MAX_SCAN_SUBNET_HOSTS:
                    continue
                out.append(net)
            except Exception:
                continue
        if out:
            return out

    nets = []
    for iface_name, addresses in psutil.net_if_addrs().items():
        if iface_name.startswith("lo"):
            continue
        stats = psutil.net_if_stats().get(iface_name)
        if not stats or not stats.isup:
            continue
        for addr in addresses:
            fam = addr.family
            if fam != socket.AF_INET and getattr(fam, "name", "") != "AF_INET":
                continue
            if not addr.address or not addr.netmask:
                continue
            ip_obj = ipaddress.ip_address(addr.address)
            if ip_obj.is_loopback:
                continue
            network = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
            if network.is_private and network.num_addresses <= MAX_SCAN_SUBNET_HOSTS:
                nets.append(network)

    if not nets:
        return [ipaddress.ip_network("192.168.1.0/24")]

    uniq = {}
    for n in nets:
        uniq[str(n)] = n
    return list(uniq.values())


def normalize_mac(mac: str) -> str:
    return mac.strip().lower()


def vendor_for_mac(mac: str) -> str:
    try:
        vendor = conf.manufdb._get_manuf(mac)
        if not vendor or vendor.lower().startswith("unknown") or normalize_mac(vendor) == normalize_mac(mac) or ":" in vendor:
            return "Unknown"
        return vendor
    except Exception:
        return "Unknown"


def resolve_reverse(ip: str) -> str:
    try:
        n = socket.gethostbyaddr(ip)[0]
        return n if n else "unknown"
    except Exception:
        return "unknown"


def parse_dhcp_leases() -> Dict[str, str]:
    lease_files = [
        "/var/lib/misc/dnsmasq.leases",
        "/var/lib/NetworkManager/dnsmasq.leases",
    ]
    out = {}
    for path in lease_files:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        ip = parts[2]
                        host = parts[3]
                        if host and host != "*":
                            out[ip] = host
        except Exception:
            pass
    return out


def resolve_mdns(ip: str) -> str:
    if not AVAHI_BINARY:
        return ""
    try:
        run = subprocess.run([AVAHI_BINARY, ip], capture_output=True, text=True, timeout=1.5)
        if run.returncode != 0:
            return ""
        out = (run.stdout or "").strip()
        if "\t" in out:
            return out.split("\t")[-1].strip()
        return ""
    except Exception:
        return ""


def resolve_netbios(ip: str) -> str:
    if not NMBLOOKUP_BINARY:
        return ""
    try:
        run = subprocess.run([NMBLOOKUP_BINARY, "-A", ip], capture_output=True, text=True, timeout=1.5)
        if run.returncode != 0:
            return ""
        for line in (run.stdout or "").splitlines():
            if "<00>" in line and "GROUP" not in line:
                name = line.split("<00>")[0].strip()
                if name:
                    return name
        return ""
    except Exception:
        return ""


def discover_ssdp(timeout=1.2) -> Dict[str, str]:
    msg = "\r\n".join(
        [
            "M-SEARCH * HTTP/1.1",
            "HOST:239.255.255.250:1900",
            "MAN:\"ssdp:discover\"",
            "MX:1",
            "ST:ssdp:all",
            "",
            "",
        ]
    ).encode("utf-8")

    out = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        sock.sendto(msg, ("239.255.255.250", 1900))

        while True:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                break
            txt = data.decode("utf-8", errors="ignore").lower()
            server = ""
            for line in txt.splitlines():
                if line.startswith("server:"):
                    server = line.split(":", 1)[1].strip()
                    break
            if server:
                out[addr[0]] = server
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass

    return out


def probe_ports(ip: str) -> List[int]:
    common_ports = [22, 53, 80, 139, 443, 445, 5353, 554, 8008, 8443, 9100]
    opened = []
    for p in common_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.15)
        try:
            if s.connect_ex((ip, p)) == 0:
                opened.append(p)
        except Exception:
            pass
        finally:
            s.close()
    return opened


def run_nmap_services(ip: str, profile: str) -> dict:
    if not NMAP_AVAILABLE:
        return {"os_guess": "Unknown", "services": []}

    cache_key = f"nmap:{profile}:{ip}"
    cached = scan_cache.get(cache_key)
    now_ts = time.time()
    if cached and now_ts - cached["ts"] < HOST_CACHE_TTL_SECONDS:
        return cached["data"]

    args = [
        NMAP_BINARY,
        "-F",
        "-Pn",
        "--max-retries",
        "1",
        "--host-timeout",
        f"{NMAP_TIMEOUT_SECONDS if profile == 'fast' else max(NMAP_TIMEOUT_SECONDS, 35)}s",
        "-oX",
        "-",
        ip,
    ]
    if profile == "deep":
        args.insert(1, "-sV")

    try:
        run = subprocess.run(args, capture_output=True, text=True, timeout=NMAP_TIMEOUT_SECONDS + 10)
    except Exception:
        return {"os_guess": "Unknown", "services": []}

    if not run.stdout.strip():
        return {"os_guess": "Unknown", "services": []}

    try:
        root = ET.fromstring(run.stdout)
    except ET.ParseError:
        return {"os_guess": "Unknown", "services": []}

    host = root.find("host")
    if host is None:
        return {"os_guess": "Unknown", "services": []}

    services = []
    for port in host.findall("./ports/port"):
        st = port.find("state")
        if st is None or st.get("state") != "open":
            continue
        proto = port.get("protocol", "tcp")
        pid = port.get("portid", "?")
        svc = port.find("service")
        name = svc.get("name", "service") if svc is not None else "service"
        services.append(f"{pid}/{proto} {name}")

    data = {"os_guess": "Unknown", "services": services[:8]}
    scan_cache[cache_key] = {"ts": now_ts, "data": data}
    return data


def infer_type(hostname: str, vendor: str, ports: List[int], ssdp: str, services: List[str]) -> str:
    h = (hostname or "").lower()
    v = (vendor or "").lower()
    s = (ssdp or "").lower() + " " + " ".join(services).lower()
    p = set(ports)

    if 9100 in p or "printer" in s:
        return "Printer"
    if 554 in p or "onvif" in s:
        return "Camera"
    if 53 in p and (80 in p or 443 in p):
        return "Router"
    if "iphone" in h or "android" in h or "pixel" in h or "galaxy" in h:
        return "Phone"
    if "ipad" in h or "tablet" in h:
        return "Tablet"
    if "tv" in h or "roku" in h or "chromecast" in h or "appletv" in h or "dlna" in s:
        return "TV"
    if "playstation" in h or "xbox" in h or "nintendo" in h:
        return "Game Console"
    if "router" in h or "gateway" in h:
        return "Router"
    if "apple" in v:
        return "Apple Device"
    if ports:
        return "IoT"
    return "Unknown"


def infer_name(ip: str, hostname: str, vendor: str, dev_type: str, dhcp_name: str, mdns_name: str, netbios_name: str):
    for name in [hostname, dhcp_name, mdns_name, netbios_name]:
        if name and name != "unknown":
            return name
    last = ip.split(".")[-1]
    if vendor != "Unknown":
        return f"{vendor} {dev_type} ({last})"
    return f"{dev_type} ({last})"


def confidence(hostname: str, vendor: str, ports: List[int], mdns_name: str, netbios_name: str, services: List[str]) -> str:
    score = 0
    if hostname and hostname != "unknown":
        score += 1
    if vendor != "Unknown":
        score += 1
    if ports:
        score += 1
    if mdns_name:
        score += 1
    if netbios_name:
        score += 1
    if services:
        score += 1
    if score >= 4:
        return "high"
    if score >= 2:
        return "medium"
    return "low"


def enrich_host(host: dict, profile: str, dhcp_map: Dict[str, str], ssdp_map: Dict[str, str], nmap_budget: threading.Semaphore) -> dict:
    ip = host["ip"]
    mac = normalize_mac(host["mac"])

    reverse = resolve_reverse(ip)
    dhcp_name = dhcp_map.get(ip, "")
    mdns_name = resolve_mdns(ip)
    netbios_name = resolve_netbios(ip)
    ssdp_server = ssdp_map.get(ip, "")

    ports = probe_ports(ip)

    services = []
    os_guess = "Unknown"
    should_nmap = (profile == "deep") or (not ports) or (reverse == "unknown")
    if should_nmap and NMAP_AVAILABLE and nmap_budget.acquire(blocking=False):
        try:
            nmap_data = run_nmap_services(ip, profile)
            services = nmap_data.get("services", [])
            os_guess = nmap_data.get("os_guess", "Unknown")
        finally:
            nmap_budget.release()

    vendor = vendor_for_mac(mac)
    dtype = infer_type(reverse, vendor, ports, ssdp_server, services)
    display_name = infer_name(ip, reverse, vendor, dtype, dhcp_name, mdns_name, netbios_name)

    segment = "unknown"
    for subnet in configured_subnets():
        if ipaddress.ip_address(ip) in subnet:
            segment = str(subnet)
            break

    return {
        "ip": ip,
        "mac": mac,
        "hostname": reverse,
        "dhcp_name": dhcp_name or "unknown",
        "mdns_name": mdns_name or "unknown",
        "netbios_name": netbios_name or "unknown",
        "ssdp": ssdp_server or "unknown",
        "vendor": vendor,
        "type": dtype,
        "name": display_name,
        "open_ports": ports,
        "os_guess": os_guess,
        "nmap_services": services,
        "segment": segment,
        "confidence": confidence(reverse, vendor, ports, mdns_name, netbios_name, services),
    }


def build_device_snapshot(profile: str, subnets: List[ipaddress.IPv4Network]) -> List[dict]:
    arp_hosts = []
    for subnet in subnets:
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(subnet))
        answered, _ = srp(packet, timeout=2, retry=1, verbose=0)
        for _, response in answered:
            arp_hosts.append({"ip": response.psrc, "mac": response.hwsrc.lower()})

    uniq_by_mac = {}
    for h in arp_hosts:
        uniq_by_mac[normalize_mac(h["mac"])] = h

    hosts = sorted(uniq_by_mac.values(), key=lambda h: ipaddress.ip_address(h["ip"]))[:SCAN_MAX_HOSTS]

    dhcp_map = parse_dhcp_leases()
    ssdp_map = discover_ssdp()
    nmap_budget = threading.Semaphore(NMAP_MAX_TARGETS_PER_SCAN if profile == "fast" else max(NMAP_MAX_TARGETS_PER_SCAN, 8))

    enriched = []
    with ThreadPoolExecutor(max_workers=ENRICH_WORKERS) as ex:
        futures = [ex.submit(enrich_host, h, profile, dhcp_map, ssdp_map, nmap_budget) for h in hosts]
        for f in as_completed(futures):
            try:
                enriched.append(f.result())
            except Exception:
                pass

    enriched.sort(key=lambda d: ipaddress.ip_address(d["ip"]))
    return enriched


def update_baseline_and_history(devices: List[dict], profile: str, subnets: List[ipaddress.IPv4Network]):
    now_iso = utc_now_iso()
    now_dt = utc_now()
    now_macs = {d["mac"] for d in devices}

    conn = db_conn()
    existing_rows = conn.execute("SELECT * FROM devices").fetchall()
    existing = {r["mac"]: dict(r) for r in existing_rows}

    new_count = 0
    offline_count = 0
    anomaly_count = 0
    pending_events = []

    def queue_event(event_type: str, severity: str, mac: str, ip: str, details: dict):
        pending_events.append((event_type, severity, mac, ip, details))

    for dev in devices:
        mac = dev["mac"]
        ex = existing.get(mac)
        ports_now = sorted(set(dev["open_ports"]))

        if not ex:
            new_count += 1
            conn.execute(
                """
                INSERT INTO devices(
                  mac, first_seen, last_seen, last_ip, segment, last_status, last_status_change,
                  baseline_ports, unknown_vendor_hits, recurring_unknown_score,
                  name, type, vendor
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    mac,
                    now_iso,
                    now_iso,
                    dev["ip"],
                    dev["segment"],
                    "online",
                    now_iso,
                    json.dumps(ports_now),
                    1 if dev["vendor"] == "Unknown" else 0,
                    1 if dev["vendor"] == "Unknown" else 0,
                    dev["name"],
                    dev["type"],
                    dev["vendor"],
                ),
            )
            queue_event("device_new", "info", mac, dev["ip"], {"summary": "new device discovered"})
        else:
            baseline = set(json.loads(ex.get("baseline_ports") or "[]"))
            new_ports = sorted(set(ports_now) - baseline)
            merged_baseline = sorted(set(baseline).union(ports_now))

            unknown_hits = int(ex.get("unknown_vendor_hits") or 0)
            recurring_unknown = int(ex.get("recurring_unknown_score") or 0)
            if dev["vendor"] == "Unknown":
                unknown_hits += 1
                recurring_unknown += 1
                if recurring_unknown % 5 == 0:
                    queue_event("unknown_vendor_recurring", "warn", mac, dev["ip"], {"summary": f"unknown vendor seen {recurring_unknown} times"})

            if ex.get("last_ip") and ex.get("last_ip") != dev["ip"]:
                anomaly_count += 1
                queue_event("anomaly_ip_change", "warn", mac, dev["ip"], {"summary": f"ip changed {ex.get('last_ip')} -> {dev['ip']}"})

            if new_ports:
                anomaly_count += 1
                queue_event("anomaly_new_ports", "warn", mac, dev["ip"], {"summary": f"new ports opened: {new_ports}"})

            if ex.get("last_status") == "offline":
                queue_event("device_online", "info", mac, dev["ip"], {"summary": "device returned online"})

            conn.execute(
                """
                UPDATE devices SET
                  last_seen=?, last_ip=?, segment=?, last_status='online',
                  name=?, type=?, vendor=?,
                  baseline_ports=?, unknown_vendor_hits=?, recurring_unknown_score=?
                WHERE mac=?
                """,
                (
                    now_iso,
                    dev["ip"],
                    dev["segment"],
                    dev["name"],
                    dev["type"],
                    dev["vendor"],
                    json.dumps(merged_baseline),
                    unknown_hits,
                    recurring_unknown,
                    mac,
                ),
            )

    # Mark offline + uptime anomaly.
    for ex in existing_rows:
        mac = ex["mac"]
        if mac in now_macs:
            continue
        if ex["last_status"] == "offline":
            continue

        offline_count += 1
        start = datetime.fromisoformat(ex["last_status_change"]) if ex["last_status_change"] else now_dt
        session_seconds = max(int((now_dt - start).total_seconds()), 0)

        prev_sessions = int(ex["session_count"] or 0)
        prev_avg = float(ex["avg_session_seconds"] or 0)
        new_sessions = prev_sessions + 1
        new_avg = ((prev_avg * prev_sessions) + session_seconds) / new_sessions if new_sessions else session_seconds

        total_online = int(ex["total_online_seconds"] or 0) + session_seconds

        if prev_sessions >= 3 and prev_avg > 0:
            if session_seconds > prev_avg * 2.5 or session_seconds < prev_avg * 0.3:
                anomaly_count += 1
                queue_event(
                    "anomaly_uptime_pattern",
                    "warn",
                    mac,
                    ex["last_ip"] or "",
                    {"summary": f"session {session_seconds}s deviates from average {int(prev_avg)}s"},
                )

        conn.execute(
            """
            UPDATE devices SET
              last_status='offline',
              last_status_change=?,
              total_online_seconds=?,
              session_count=?,
              avg_session_seconds=?
            WHERE mac=?
            """,
            (now_iso, total_online, new_sessions, new_avg, mac),
        )
        queue_event("device_offline", "warn" if ex["type"] in CRITICAL_DEVICE_TYPES else "info", mac, ex["last_ip"] or "", {"summary": "device went offline"})

    conn.execute(
        "INSERT INTO scan_runs(ts,profile,subnets,online_count,new_count,offline_count,anomaly_count) VALUES (?,?,?,?,?,?,?)",
        (now_iso, profile, ",".join([str(s) for s in subnets]), len(devices), new_count, offline_count, anomaly_count),
    )

    conn.commit()
    conn.close()

    for evt in pending_events:
        emit_event(*evt)


def query_device_rows() -> List[dict]:
    conn = db_conn()
    rows = conn.execute("SELECT * FROM devices ORDER BY last_status='online' DESC, last_seen DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def merge_live_with_db(live_devices: List[dict], db_rows: List[dict]) -> List[dict]:
    by_mac_live = {d["mac"]: d for d in live_devices}
    merged = []

    for row in db_rows:
        mac = row["mac"]
        d = by_mac_live.get(mac)
        status = row.get("last_status", "offline")

        if d:
            merged.append(
                {
                    **d,
                    "status": "online",
                    "first_seen": row.get("first_seen"),
                    "last_seen": row.get("last_seen"),
                    "total_online_seconds": row.get("total_online_seconds", 0),
                    "avg_session_seconds": int(row.get("avg_session_seconds") or 0),
                    "recurring_unknown_score": row.get("recurring_unknown_score", 0),
                }
            )
        else:
            merged.append(
                {
                    "ip": row.get("last_ip", "-"),
                    "mac": mac,
                    "hostname": "unknown",
                    "dhcp_name": "unknown",
                    "mdns_name": "unknown",
                    "netbios_name": "unknown",
                    "ssdp": "unknown",
                    "vendor": row.get("vendor", "Unknown"),
                    "type": row.get("type", "Unknown"),
                    "name": row.get("name", mac),
                    "open_ports": json.loads(row.get("baseline_ports") or "[]"),
                    "os_guess": "Unknown",
                    "nmap_services": [],
                    "segment": row.get("segment", "unknown"),
                    "confidence": "low",
                    "status": status,
                    "first_seen": row.get("first_seen"),
                    "last_seen": row.get("last_seen"),
                    "total_online_seconds": row.get("total_online_seconds", 0),
                    "avg_session_seconds": int(row.get("avg_session_seconds") or 0),
                    "recurring_unknown_score": row.get("recurring_unknown_score", 0),
                }
            )

    merged.sort(key=lambda d: (d["status"] != "online", ipaddress.ip_address(d["ip"] if d["ip"] != "-" else "255.255.255.255")))
    return merged


def load_trends() -> dict:
    conn = db_conn()

    by_day = conn.execute(
        """
        SELECT substr(ts,1,10) AS day,
               SUM(online_count) AS online_count,
               SUM(new_count) AS new_count,
               SUM(offline_count) AS offline_count,
               SUM(anomaly_count) AS anomaly_count
        FROM scan_runs
        WHERE ts >= ?
        GROUP BY substr(ts,1,10)
        ORDER BY day ASC
        """,
        ((utc_now() - timedelta(days=14)).isoformat(),),
    ).fetchall()

    unknowns = conn.execute(
        """
        SELECT mac, recurring_unknown_score, last_ip
        FROM devices
        WHERE recurring_unknown_score > 0
        ORDER BY recurring_unknown_score DESC
        LIMIT 10
        """
    ).fetchall()

    churn = conn.execute(
        """
        SELECT
          COALESCE(SUM(CASE WHEN event_type='device_new' THEN 1 ELSE 0 END), 0) AS new_devices,
          COALESCE(SUM(CASE WHEN event_type='device_offline' THEN 1 ELSE 0 END), 0) AS offline_devices
        FROM device_events
        WHERE ts >= ?
        """,
        ((utc_now() - timedelta(days=14)).isoformat(),),
    ).fetchone()

    conn.close()

    return {
        "daily": [dict(r) for r in by_day],
        "churn": dict(churn) if churn else {"new_devices": 0, "offline_devices": 0},
        "top_unknown_devices": [dict(r) for r in unknowns],
    }


def recent_events(limit=80) -> List[dict]:
    conn = db_conn()
    rows = conn.execute("SELECT ts, mac, ip, event_type, severity, details FROM device_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()

    out = []
    for r in rows:
        details = {}
        try:
            details = json.loads(r["details"] or "{}")
        except Exception:
            pass
        out.append({**dict(r), "details": details})
    return out


def rebuild_state(profile: str, subnets: List[ipaddress.IPv4Network], live_devices: List[dict]):
    db_rows = query_device_rows()
    merged = merge_live_with_db(live_devices, db_rows)

    seg_counts = {}
    for d in merged:
        seg = d.get("segment", "unknown")
        seg_counts[seg] = seg_counts.get(seg, 0) + (1 if d.get("status") == "online" else 0)

    with state_lock:
        state["scanned_at"] = utc_now_iso()
        state["count"] = len([d for d in merged if d.get("status") == "online"])
        state["devices"] = merged
        state["subnets"] = [str(s) for s in subnets]
        state["segments"] = [{"segment": k, "online": v} for k, v in sorted(seg_counts.items())]
        state["last_profile"] = profile
        state["scan_in_progress"] = False
        state["revision"] += 1
        state["live_revision"] += 1


def run_scan(profile: str, subnets_raw: List[str] = None):
    with state_lock:
        state["scan_in_progress"] = True
        state["live_revision"] += 1

    if subnets_raw:
        subnets, _ = validate_requested_subnets(subnets_raw)
        if not subnets:
            subnets = configured_subnets()
    else:
        subnets = configured_subnets()

    add_log("info", f"scan started ({profile})")

    try:
        live_devices = build_device_snapshot(profile, subnets)
        update_baseline_and_history(live_devices, profile, subnets)
        rebuild_state(profile, subnets, live_devices)
        add_log("info", f"scan complete ({profile}) devices={len(live_devices)}")
    except Exception as exc:
        add_log("error", f"scan failed ({profile}): {exc}")
        with state_lock:
            state["scan_in_progress"] = False
            state["live_revision"] += 1


def enqueue_scan(profile="fast", subnets=None):
    scan_queue.put({"profile": profile, "subnets": subnets})
    with state_lock:
        state["queue_depth"] = scan_queue.qsize()
        state["live_revision"] += 1


def scan_worker_loop():
    while True:
        job = scan_queue.get()
        if job is None:
            return
        try:
            run_scan(job.get("profile", "fast"), job.get("subnets"))
        finally:
            scan_queue.task_done()
            with state_lock:
                state["queue_depth"] = scan_queue.qsize()
                state["live_revision"] += 1


def recent_anomaly_count(minutes=10) -> int:
    conn = db_conn()
    row = conn.execute(
        "SELECT COUNT(*) AS c FROM device_events WHERE ts >= ? AND event_type LIKE 'anomaly_%'",
        ((utc_now() - timedelta(minutes=minutes)).isoformat(),),
    ).fetchone()
    conn.close()
    return int(row["c"] if row else 0)


def scheduler_loop():
    global last_deep_scan_at
    while True:
        anomalies = recent_anomaly_count(10)
        fast_wait = max(10, SCAN_FAST_INTERVAL // 2) if anomalies > 0 else SCAN_FAST_INTERVAL

        if scan_queue.qsize() < 3:
            enqueue_scan("fast")

        now = utc_now()
        if last_deep_scan_at is None or (now - last_deep_scan_at).total_seconds() >= SCAN_DEEP_INTERVAL:
            if scan_queue.qsize() < 5:
                enqueue_scan("deep")
                last_deep_scan_at = now

        time.sleep(fast_wait)


def traffic_loop():
    prev = psutil.net_io_counters(pernic=True)
    prev_t = time.time()

    while True:
        time.sleep(TRAFFIC_SAMPLE_SECONDS)
        curr = psutil.net_io_counters(pernic=True)
        now_t = time.time()
        dt = max(now_t - prev_t, 0.001)

        rx = 0
        tx = 0
        interfaces = []
        for iface, c in curr.items():
            if iface.startswith("lo"):
                continue
            p = prev.get(iface)
            if not p:
                continue
            rx_delta = c.bytes_recv - p.bytes_recv
            tx_delta = c.bytes_sent - p.bytes_sent
            if rx_delta < 0 or tx_delta < 0:
                continue
            rx_bps = int(rx_delta / dt)
            tx_bps = int(tx_delta / dt)
            total = rx_bps + tx_bps
            rx += rx_bps
            tx += tx_bps
            interfaces.append({"name": iface, "rx_bps": rx_bps, "tx_bps": tx_bps, "total_bps": total})

        interfaces.sort(key=lambda x: x["total_bps"], reverse=True)
        total = rx + tx

        with state_lock:
            t = state["traffic"]
            t["updated_at"] = utc_now_iso()
            t["rx_bps"] = rx
            t["tx_bps"] = tx
            t["total_bps"] = total
            t["interfaces"] = interfaces[:6]
            t["history"].append({"ts": t["updated_at"], "total_bps": total, "rx_bps": rx, "tx_bps": tx})
            if len(t["history"]) > TRAFFIC_HISTORY_POINTS:
                t["history"] = t["history"][-TRAFFIC_HISTORY_POINTS:]
            state["live_revision"] += 1
            history_vals = [p["total_bps"] for p in t["history"][:-1]]

        avg = sum(history_vals) / len(history_vals) if history_vals else 0
        if avg > 0 and total > avg * 3 and total > 5_000_000:
            emit_event("anomaly_traffic_spike", "warn", "system", "", {"summary": f"traffic spike {total} B/s (avg {int(avg)})"})

        prev = curr
        prev_t = now_t


def get_snapshot():
    with state_lock:
        base = {
            "scanned_at": state["scanned_at"],
            "count": state["count"],
            "devices": list(state["devices"]),
            "subnets": list(state["subnets"]),
            "segments": list(state["segments"]),
            "revision": state["revision"],
            "live_revision": state["live_revision"],
            "scan_in_progress": state["scan_in_progress"],
            "queue_depth": state["queue_depth"],
            "last_profile": state["last_profile"],
            "nmap_enabled": state["nmap_enabled"],
            "nmap_available": state["nmap_available"],
            "traffic": {
                "updated_at": state["traffic"]["updated_at"],
                "rx_bps": state["traffic"]["rx_bps"],
                "tx_bps": state["traffic"]["tx_bps"],
                "total_bps": state["traffic"]["total_bps"],
                "interfaces": list(state["traffic"]["interfaces"]),
                "history": list(state["traffic"]["history"]),
            },
            "logs": list(event_logs),
        }
    base["trends"] = load_trends()
    return base


def ensure_workers():
    global worker_started, scheduler_started, traffic_started

    if not worker_started:
        for _ in range(max(SCAN_WORKERS, 1)):
            threading.Thread(target=scan_worker_loop, daemon=True).start()
        worker_started = True

    if not scheduler_started:
        threading.Thread(target=scheduler_loop, daemon=True).start()
        scheduler_started = True

    if not traffic_started:
        threading.Thread(target=traffic_loop, daemon=True).start()
        traffic_started = True


@app.before_request
def startup():
    ensure_workers()
    if request.path.startswith("/api/") and request.path != "/api/healthz":
        if not is_request_authorized():
            return jsonify({"error": "invalid api key"}), 401


@app.route("/")
def index():
    return render_template("index.html", api_key=UI_API_KEY)


@app.route("/api/healthz")
def api_healthz():
    return jsonify({"ok": True})


@app.route("/api/devices")
def api_devices():
    should_enqueue = False
    with state_lock:
        if state["scanned_at"] is None and scan_queue.qsize() == 0:
            should_enqueue = True
    if should_enqueue:
        enqueue_scan("fast")
    return jsonify(get_snapshot())


@app.route("/api/scan", methods=["POST"])
def api_scan():
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    if not allow_rate_limit("scan", client_ip, limit=12, per_seconds=60):
        return jsonify({"error": "rate limit exceeded"}), 429

    data = request.get_json(silent=True) or {}
    profile = str(data.get("profile", "fast")).strip().lower()
    if profile not in {"fast", "deep"}:
        profile = "fast"
    subnets = data.get("subnets")
    if subnets is not None:
        parsed, err = validate_requested_subnets(subnets)
        if err:
            return jsonify({"error": err}), 400
        subnets = [str(n) for n in parsed]

    enqueue_scan(profile, subnets)
    return jsonify(get_snapshot())


@app.route("/api/timeline/<mac>")
def api_timeline(mac: str):
    conn = db_conn()
    rows = conn.execute(
        "SELECT ts, event_type, severity, ip, details FROM device_events WHERE mac=? ORDER BY id DESC LIMIT 200",
        (normalize_mac(mac),),
    ).fetchall()
    conn.close()

    out = []
    for r in rows:
        details = {}
        try:
            details = json.loads(r["details"] or "{}")
        except Exception:
            pass
        out.append({**dict(r), "details": details})

    return jsonify({"mac": normalize_mac(mac), "events": out})


@app.route("/api/trends")
def api_trends():
    return jsonify(load_trends())


@app.route("/api/webhooks", methods=["GET", "POST"])
def api_webhooks():
    if request.method == "GET":
        conn = db_conn()
        rows = conn.execute("SELECT id, url, events, enabled, created_at FROM webhooks ORDER BY id DESC").fetchall()
        conn.close()
        return jsonify({"webhooks": [dict(r) for r in rows]})

    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()
    events = data.get("events")
    if not url:
        return jsonify({"error": "url required"}), 400
    ok, reason = validate_webhook_url(url)
    if not ok:
        return jsonify({"error": reason}), 400

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    if not allow_rate_limit("webhooks", client_ip, limit=10, per_seconds=60):
        return jsonify({"error": "rate limit exceeded"}), 429

    if isinstance(events, list):
        events_str = ",".join([str(x).strip() for x in events if str(x).strip()])
    else:
        events_str = "*"

    conn = db_conn()
    conn.execute(
        "INSERT INTO webhooks(url,events,enabled,created_at) VALUES (?,?,1,?)",
        (url, events_str or "*", utc_now_iso()),
    )
    conn.commit()
    conn.close()

    add_log("info", f"webhook registered: {url}")
    return jsonify({"ok": True})


@app.route("/api/integrations/state")
@require_api_key
def api_integration_state():
    return jsonify(get_snapshot())


@app.route("/api/integrations/hooks/test", methods=["POST"])
@require_api_key
def api_hooks_test():
    emit_event("integration_test", "info", "integration", "", {"summary": "test event emitted"})
    return jsonify({"ok": True})


@app.route("/api/stream")
def api_stream():
    def event_stream():
        last_rev = -1
        while True:
            payload = get_snapshot()
            cur = payload["live_revision"]

            if cur != last_rev:
                last_rev = cur
                yield f"event: update\\ndata: {json.dumps(payload, separators=(',', ':'))}\\n\\n"
            else:
                yield "event: heartbeat\\ndata: {}\\n\\n"
            time.sleep(HEARTBEAT_SECONDS)

    return Response(event_stream(), mimetype="text/event-stream")


if __name__ == "__main__":
    init_db()
    ensure_workers()
    app.run(host="0.0.0.0", port=APP_PORT, threaded=True)
