# Network Device Tracker

Upgraded local-network tracker with anomaly detection, enrichment, timelines, trends, webhooks, and integration APIs.

## Implemented (per your request)

- Done: behavior baseline + anomaly detection
  - new ports anomalies
  - IP change anomalies
  - uptime/session pattern anomalies
  - traffic spike anomalies
- Done: persistent device timelines/history
  - first/last seen
  - online durations + average session duration
  - IP changes + event timeline
- Done: notifications
  - new devices
  - recurring unknown vendors
  - offline critical device types
  - outbound webhooks + optional default alert webhook
- Done: enrichment
  - reverse DNS + DHCP lease parsing
  - mDNS (`avahi-resolve-address` if available)
  - NetBIOS (`nmblookup` if available)
  - SSDP discovery
  - optional nmap service probing
- Done: subnet/VLAN support + scheduling profiles
  - multi-subnet scanning from `SCAN_SUBNETS` or auto-discovery
  - fast/deep profiles + scheduler
- Done: trends dashboard
  - 14-day daily counts
  - churn stats
  - top recurring unknown devices
- Done: API keys + webhook integration
  - `X-API-Key` protected integration endpoints
  - webhook registration endpoint
- Done: performance controls
  - async scan queue + workers
  - host scan caching TTL
  - adaptive scheduler when anomalies are active

Skipped (as requested): 5, 6, 8, 10.

## Run

```bash
export API_KEYS="replace-with-strong-key"
export UI_API_KEY="replace-with-strong-key"
docker compose up --build -d
```

Open:

- `http://localhost:8080`

## Environment

Set in `docker-compose.yml`:

- `SCAN_SUBNETS` comma-separated, optional (example: `10.0.0.0/24,192.168.1.0/24`)
- `ALERT_WEBHOOK_URL` optional default outbound alert target
- `API_KEYS` comma-separated integration keys (set a strong secret)
- `UI_API_KEY` key used by browser dashboard to call API (should match one of `API_KEYS`)
- `MAX_SCAN_SUBNET_HOSTS` max hosts allowed per requested subnet (`512` default)
- `MAX_SUBNETS_PER_SCAN` max subnet count allowed in a manual scan request
- `ALLOW_PRIVATE_WEBHOOKS` allow webhook delivery to private IP ranges (`false` default)
- `WEBHOOK_ALLOWLIST` optional comma-separated host/domain allowlist for webhooks

## Security Notes

- All `/api/*` endpoints now require API key auth (`X-API-Key` header or `api_key` query param).
- Dashboard uses `UI_API_KEY` to authenticate API requests automatically.
- Webhook URLs are validated to reduce SSRF risk (scheme/host resolution/private-IP rules).
- Manual scan requests are rate-limited and subnet-size limited.

## API

- `GET /api/devices`
- `POST /api/scan` body: `{ "profile": "fast" | "deep", "subnets": ["10.0.0.0/24"] }`
- `GET /api/stream`
- `GET /api/timeline/<mac>`
- `GET /api/trends`
- `GET|POST /api/webhooks`
- `GET /api/integrations/state` (requires `X-API-Key`)
- `POST /api/integrations/hooks/test` (requires `X-API-Key`)
