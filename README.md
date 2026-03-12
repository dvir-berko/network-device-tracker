# Network Device Tracker

Web app to discover devices on your local network and classify them automatically.

## Features

- Automatic ARP scan on interval (no manual labeling)
- Auto-detects per device:
  - name
  - type
  - vendor (MAC OUI)
  - confidence
- Nmap fingerprinting for better detection:
  - OS guess
  - top detected services
- Tracks online/offline status and last seen time
- Live updates in browser using server-sent events (SSE)

## Run

```bash
docker compose up --build -d
```

Open `http://localhost:8080`.

## Nmap settings (docker-compose)

- `ENABLE_NMAP_FINGERPRINT=true`
- `NMAP_TIMEOUT_SECONDS=20`
- `NMAP_REFRESH_SECONDS=1800`
- `NMAP_MAX_TARGETS_PER_SCAN=2` (limits per-scan nmap work to keep UI responsive)

## API

- `GET /api/devices`: current device state
- `POST /api/scan`: trigger immediate scan
- `GET /api/stream`: live event stream for updates

## Notes

- ARP scan and nmap OS scan require raw socket capabilities.
- `network_mode: host` lets the container see the host LAN interfaces.
