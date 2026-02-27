# Cajal ICBM

Cajal ICBM (Internal Connectivity & Bandwidth Monitor) is a web-based network monitoring dashboard focused on connectivity health and telemetry flow.
It combines:

- Live telemetry collection from Syslog, SNMP, NetFlow
- Site/device operations UI with role-based management
- Local auth and optional Entra SSO
- Persistent audit/event logging with a CLI-style Event Viewer

This README is the canonical operator/developer guide for running and extending the project.

## Patch Notes {#patch-notes}

- Version 1.3:
  - Zero-config install — `bash docker-reload.sh rebuild` auto-generates all secrets on first run (no `.env` editing required)
  - First-run setup wizard guides new admins through initial configuration on first login
  - Update Now button visible in all installs by default (no env vars required)
  - All destructive confirmations moved in-app — no native `confirm()` or `prompt()` dialogs
  - Factory reset now requires typing "FACTORY RESET" in a styled in-app dialog
  - Docker and Node.js presence validated before setup begins with clear install guidance
  - 127 unit tests (up from 124)

- Version 1.2:
  - Welcome dialog on first login with direct link to Help
  - In-app version check and one-click Update Now button (Settings → System Health)
  - Auto-update via Watchtower companion container — triggered from the UI, no SSH required
  - Docker socket hardened through `tecnativa/docker-socket-proxy` whitelist (Watchtower no longer holds direct socket access)
  - Direct HTTPS support without a reverse proxy (`CAJAL_HTTPS_PORT`, HTTP auto-redirects to HTTPS)
  - CSP `style-src 'unsafe-inline'` removed — all styles are now file-served
  - Server modularized from single 6800-line file into `lib/` modules
  - 124 unit tests (up from 118)

- Version 1.1:
  - Teams/Power Automate webhook routing controls with per-alert templates and test sends
  - Collector and device UI alignment improvements, button placement cleanup, and terminal UX polish
  - Collector WAN speed-test badges and improved agent tooling/download workflows
  - API token management section in Settings
  - Login hardening: account-aware lockout/backoff in addition to IP rate limiting
  - Security headers/CSP hardening and browser E2E smoke coverage in CI

## 1. Current capabilities

### 1.1 Dashboard

- Sticky top bar with global refresh countdown, smooth refresh progress fill, system clock, and process uptime
- Sticky change ticker showing recent management/runtime activity
- Two primary location groups (Location 1 and Location 2)
- Site tiles with:
  - Firewall and WAN/IP metadata
  - Collector status and per-protocol flow badges (Syslog/SNMP/NetFlow)
  - Tools tile workflow:
    - `Launch` opens full terminal mode
    - `Close` returns to compact mode
    - compact mode shows a `Learn` button that jumps to the Tools Terminal help section
  - Heartbeat card with Target 1 + Target 2 and independent last check-in fields
  - Uptime graph with selectable time scale (`1h`, `3h`, `6h`, `12h`, `24h`, `3d`, `7d`, `14d`) and secondary target line
  - NetFlow top bandwidth talkers by IP
  - SNMP + Syslog signal card (flow, EPS, totals, SNMP response/health)
  - WAN test results
- Device tile purple refresh blink on global data refresh
- Notification toggle per site
- Automatic status-change Teams notifications (`UP/WARN/DOWN` transitions) when notifications are enabled per site

### 1.2 Admin operations

- Add device
- Add location
- Edit site metadata
- Edit monitor configuration with protocol-specific editors and close controls
- Run monitor diagnostics and on-demand monitor tests (`Test SNMP Now`, `Test Syslog Now`, `Test NetFlow Now`)
- Clock settings (timezone + 12h/24h display)
- System Health panel in Settings
- Local Firewall Checker panel in Settings
- Storage panel with retention summary, current usage, estimated cap, and purge logs action
- Error Logs, Diagnostics Console, and Raw Telemetry Stream panels (with pop-out console views)
- Backup export/restore
- User and role management (Admin, Monitor)
- Reset local password and reset local TOTP state per user
- Self-service TOTP reset under `My Security`

### 1.3 Observability and logging

- Sticky change ticker near top of page
- Audit Trail panel (configuration and management changes)
- Event Viewer panel (detailed runtime and system events, including syslog stream events)
- Numeric event class IDs with filtering by class and source
- Diagnostic and raw telemetry logs for protocol-level troubleshooting

### 1.4 Authentication

- Default login page (`/login.html`) in front of the app
- Local auth (username/password) enabled by default
- Entra SSO configuration supported
- Local TOTP is enabled by default (can be disabled in runtime settings)

### 1.5 Settings menu sections (Admin)

- 1. User Management
- 2. Location Management
- 3. SSO Configuration
- 4. SSL Certificate
- 5. Teams Notifications
- 6. Webhook Routing
- 7. Clock Settings
- 8. System Health
- 9. Backup
- 10. Advanced Options (Ports)
- 11. Error Logs
- 12. Diagnostics Console
- 13. Raw Telemetry Stream
- 14. Local Firewall Checker
- 15. Storage
- 16. API
- My Security

## 2. Default credentials

Default local admin bootstrap user is:

- Username: `admin`
- Password: none pre-seeded

On first local login, the user is prompted to set a password (and enroll TOTP when enabled).

## 3. Architecture overview

### 3.1 Runtime model

- Single Node.js process
- HTTP server for UI + API
- UDP/TCP listeners for telemetry collectors
- Periodic pollers for SNMP, ping, uptime sampling, WAN tests
- Optional collector agent (Linux package + Windows PowerShell script or hosted `.exe`) for remote tools terminal execution

### 3.2 Data persistence

Cajal uses a PostgreSQL storage backend for tracked datasets via table `cajal_store`.

Tracked datasets:

- `sites`
- `devices`
- `users`
- `sso`
- `events`
- `errorLog`
- `diagnosticsLog`
- `telemetryLog`
- `runtime`
- `locationSettings`
- `ssl`
- `backupMeta`
- `apiTokens`

At startup, Cajal performs a one-time import from existing local `data/*` tracked files into `cajal_store` for keys that are not already present.

### 3.3 Secrets handling

- Site monitor credentials are encrypted at rest using AES-256-GCM
- Encryption key derived from `CAJAL_CONFIG_KEY`
- SSO secret settings also stored encrypted

## 4. Event and audit model

### 4.1 Event classes

Numeric class IDs are used to categorize events:

- `101-199` config/admin changes
- `201-299` site/system management changes
- `301-399` runtime/telemetry transitions
- `401-499` authentication/security events
- `900+` fallback/misc

### 4.2 Examples

- `101` user updates, SSO config updates
- `201` location creation
- `202` site metadata update
- `203` monitor config update
- `204` notifications update
- `205` device add
- `301` test notification
- `302` telemetry flow state change
- `320` syslog ingest activity
- `321` netflow ingest activity
- `322` SNMP success
- `323` ping poll/state
- `324` WAN speed test
- `401` login/logout success
- `402` login/TOTP failures
- `422` SNMP poll errors

### 4.3 Panels

- Audit Trail:
  - Focused management/change records (`classId < 400`)
- Event Viewer:
  - Full runtime stream
  - Class/source filters
  - CLI-style text output

## 5. Local setup and run

### 5.1 Prerequisites

- Node.js `>=20`
- `snmpget` command available for SNMP polling (Net-SNMP tools)
- Optional: `speedtest` CLI for WAN throughput tests
- Optional: Teams webhook endpoint

### 5.2 Required environment

Set encryption key:

```bash
export CAJAL_CONFIG_KEY='replace-with-strong-random-secret'
```

Or persist it in `auvik-lite/.env`:

```bash
CAJAL_CONFIG_KEY=replace-with-strong-random-secret
```

Then run:

```bash
npm start
```

Open:

- Login: `http://localhost:4000/login.html`
- App (redirected to login if not authenticated): `http://localhost:4000/`

### 5.3 Docker quick start (recommended)

From `auvik-lite/`:

```bash
bash docker-reload.sh rebuild
```

That's it. The script auto-generates all required secrets (encryption key, database
password, Watchtower token) on first run and stores them in `.env`.

Then open:

- `http://localhost:4000`

The first admin account is created through the browser on first login.

This starts four containers:

| Container | Purpose |
|---|---|
| `cajal-postgres` | PostgreSQL data store |
| `cajal-app` | Application (port 4000, syslog 5514, NetFlow 2055) |
| `cajal-socket-proxy` | Docker socket whitelist proxy (internal only) |
| `cajal-watchtower` | Auto-update via HTTP API, monitors only labeled containers |

Restart app only (fast, no rebuild):

```bash
bash docker-reload.sh fast
```

Rebuild image and restart all containers:

```bash
bash docker-reload.sh rebuild
```

### 5.4 Docker Compose (alternative)

```bash
docker compose up -d --build
```

Stop:

```bash
docker compose down
```

Stop and remove DB volume:

```bash
docker compose down -v
```

## 6. Configuration reference

### 6.1 Core server

- `PORT` default `4000`
- `CAJAL_CONFIG_KEY` required for decrypting monitor/SSO secrets
- `CAJAL_DATABASE_URL` required (PostgreSQL is mandatory)
- `CAJAL_DATABASE_SSL` default `disable` (`disable`, `require`, `verify-ca`, `verify-full`)
- `CAJAL_DATABASE_POOL_MAX` default `20`
- `CAJAL_DATABASE_POOL_IDLE_TIMEOUT_MS` default `30000`
- `CAJAL_DATABASE_POOL_CONNECTION_TIMEOUT_MS` default `10000`
- `CAJAL_DATABASE_STATEMENT_TIMEOUT_MS` default `30000`
- `CAJAL_DATABASE_QUERY_TIMEOUT_MS` default `30000`

### 6.2 Telemetry and polling

- `CAJAL_SYSLOG_UDP_PORT` default `5514`
- `CAJAL_SYSLOG_TCP_PORT` default `5514`
- `CAJAL_NETFLOW_PORT` default `2055`
- `CAJAL_FLOW_TIMEOUT_MS` default `120000`
- `CAJAL_SYSLOG_FLOW_TIMEOUT_MIN_MS` default `900000` (15m minimum stale window for SYSLOG flow state)
- `CAJAL_NETFLOW_FLOW_TIMEOUT_MIN_MS` default `900000` (15m minimum stale window for NETFLOW flow state)
- `CAJAL_SNMP_POLL_INTERVAL_MS` default `60000`
- `CAJAL_PING_INTERVAL_MS` default `45000`
- `CAJAL_UPTIME_SAMPLE_INTERVAL_MS` default `300000`
- `CAJAL_WAN_TEST_INTERVAL_MS` default `14400000` (4h)
- `CAJAL_WAN_TEST_HISTORY` default `6`
- `CAJAL_NETFLOW_TOP_WINDOW_MS` default `1800000`
- `CAJAL_ENABLE_SPEEDTEST` default `0`
- `CAJAL_GLOBAL_REFRESH_MS` default `60000`
- `CAJAL_GLOBAL_CLOCK_TIMEZONE` default `UTC`
- `CAJAL_GLOBAL_CLOCK_HOUR_MODE` default `24h` (`12h` or `24h`)
- `CAJAL_AGENT_SESSION_TTL_MS` default `120000`
- `CAJAL_AGENT_COMMAND_TIMEOUT_MS` default `30000`
- `CAJAL_AGENT_COMMAND_LEASE_MS` default `12000`
- `CAJAL_AGENT_POLL_INTERVAL_MS` default `1500`

### 6.3 Sessions and auth

- `CAJAL_SESSION_TTL_MS` default `28800000`
- `CAJAL_PASSWORD_HASH_ITERATIONS` default `210000`
- `CAJAL_LOCAL_TOTP_ENABLED` default `1`
- `CAJAL_LOCAL_SETUP_TTL_MS` default `600000`
- `CAJAL_API_TOKEN_MAX_COUNT` default `200`
- `CAJAL_LOGIN_RATE_LIMIT_MAX` default `20`
- `CAJAL_LOGIN_RATE_LIMIT_WINDOW_MS` default `60000`
- `CAJAL_LOGIN_ACCOUNT_FAILURE_THRESHOLD` default `8`
- `CAJAL_LOGIN_ACCOUNT_FAILURE_WINDOW_MS` default `900000` (15m)
- `CAJAL_LOGIN_ACCOUNT_LOCK_MS` default `900000` (15m)

### 6.4 HTTPS (direct TLS)

When an SSL certificate and key are configured in Settings → SSL Certificate, Cajal automatically:
- Starts an HTTPS server on `CAJAL_HTTPS_PORT`
- Redirects all HTTP requests on `PORT` to HTTPS

- `CAJAL_HTTPS_PORT` default `4443`

No reverse proxy required. Ports must be open on the host firewall.

### 6.5 Auto-update (Watchtower)

Configure all four to enable version checking and the "Update Now" button in Settings → System Health. Leave any unset to hide the update UI entirely.

- `CAJAL_GITHUB_REPO` — `owner/repo` format, queried against GitHub Releases API
- `CAJAL_UPDATE_IMAGE` — image shown in update panel (e.g. `ghcr.io/nniell90/cajal:latest`)
- `CAJAL_WATCHTOWER_URL` — Watchtower HTTP API URL, internal Docker network only (e.g. `http://cajal-watchtower:8080`)
- `CAJAL_WATCHTOWER_TOKEN` — must match `CAJAL_WATCHTOWER_TOKEN` in `.env` and `WATCHTOWER_HTTP_API_TOKEN` used by the `cajal-watchtower` container

The update button triggers Watchtower via its HTTP API, which pulls the new image and hot-swaps the `cajal-app` container. The page polls `/api/health` and reloads automatically when the new version is detected (~30s). Update triggers are rate-limited to 1 per 5 minutes per admin and logged to the security audit trail.

### 6.6 SSO (Entra)

- `CAJAL_ENTRA_TENANT_ID`
- `CAJAL_ENTRA_CLIENT_ID`
- `CAJAL_ENTRA_CLIENT_SECRET`
- `CAJAL_ENTRA_REDIRECT_URI`
- `CAJAL_ENTRA_SCOPE` default `openid profile email`

### 6.7 Authorization mapping

- `CAJAL_ADMIN_USERS` comma-separated emails
- `CAJAL_MONITOR_USERS` comma-separated emails

### 6.8 Events and notifications

- `CAJAL_EVENT_RETENTION` default `5000`
- `CAJAL_DATA_RETENTION_DAYS` default `90`
- `CAJAL_TEAMS_WEBHOOK_URL` Teams Incoming Webhook URL (optional if you set it in Settings -> Teams Notifications)
- `CAJAL_TEAMS_WEBHOOK_TIMEOUT_MS` default `8000`
- `CAJAL_TEAMS_PAYLOAD_GROUP` default `cajal` (used as webhook `group`)
- `CAJAL_WAN_PUBLIC_IP_POLL_INTERVAL_MS` default `60000` (collector WAN failover probe interval)
- Webhook payload format (Power Automate): JSON with `title`, `group`, `message`
- Route message templates support tokens: `{{status}}`, `{{previousStatus}}`, `{{siteName}}`, `{{locationName}}`, `{{reason}}`, `{{detail}}`, `{{timestamp}}`, `{{wanIp1}}`, `{{wanIp2}}`, `{{wanPublicIp}}`, `{{wanPublicIpPrevious}}`, `{{wanPublicIpCurrent}}`

## 7. API reference (operational)

### 7.1 Auth/session

- `GET /api/auth/me`
- `POST /api/auth/local/login`
- `POST /api/auth/local/setup-password` (only used when TOTP enabled)
- `POST /api/auth/local/verify-totp` (only used when TOTP enabled)
- `GET /api/auth/local/totp-qr` (TOTP enrollment QR helper)
- `POST /api/auth/logout`
- API tokens are supported via `Authorization: Bearer <token>` on authenticated API routes.

### 7.2 SSO settings

- `GET /api/settings/sso` admin only
- `PATCH /api/settings/sso` admin only

### 7.3 Runtime, SSL, diagnostics, and health settings

- `GET /api/settings/runtime` admin only
- `PATCH /api/settings/runtime` admin only
- `GET /api/settings/webhook-routing` admin only
- `PATCH /api/settings/webhook-routing` admin only (`routes` on/off, `sectionModes` global WARN/OFFLINE/RESTORE/NEVER per section, and `messages` per route)
- `POST /api/settings/webhook-routing/test` admin only (uses Teams settings webhook URL + payload group)
  - Route messages are preloaded with dynamic token templates; leaving a route message blank reverts it to the default template.
- `GET /api/settings/ssl` admin only
- `PATCH /api/settings/ssl` admin only
- `POST /api/settings/teams/test` admin only (send test Teams message from Settings)
- `GET /api/settings/system-health` admin only
  - Includes SNMP + Teams notification dependency status and self-monitor badge data
- `GET /api/settings/api/tokens` admin only
- `POST /api/settings/api/tokens` admin only
- `DELETE /api/settings/api/tokens/:tokenId` admin only
- `GET /api/system/version/check` admin only — checks GitHub Releases API for a newer version; result cached 1 hour
- `POST /api/system/update/apply` admin only — triggers Watchtower to pull and hot-swap the app container; rate-limited to 1 per 5 minutes; security audit logged
- `GET /api/settings/firewall-check` admin only
- `GET /api/settings/storage` admin only
- `POST /api/settings/storage/purge-logs` admin only
- `GET /api/settings/error-logs?limit=` admin only
- `GET /api/settings/diagnostics-logs?limit=&protocol=&level=&site=` admin only
- `DELETE /api/settings/diagnostics-logs` admin only
- `GET /api/telemetry/raw?limit=&protocol=&site=&search=` admin only
- `DELETE /api/telemetry/raw` admin only

### 7.4 Location and backup settings

- `GET /api/settings/locations`
- `PATCH /api/settings/locations` admin only
- `POST /api/settings/locations/sections` admin only
- `PATCH /api/settings/locations/sections/:sectionId` admin only
- `DELETE /api/settings/locations/sections/:sectionId` admin only
- `POST /api/backup/export` admin only
- `POST /api/backup/import` admin only

### 7.5 Events and audit

- `GET /api/events?limit=&class=&source=&since=`
- `GET /api/audit?limit=`
- `GET /api/help/readme`

### 7.6 User management

- `GET /api/users` admin only
- `POST /api/users` admin only
- `PATCH /api/users/:email` admin only
- `POST /api/users/:email/reset-local` admin only

### 7.7 Site and monitor management

- `GET /api/sites`
- `POST /api/sites` admin only
- `PATCH /api/sites/:siteId/meta` admin only
- `PATCH /api/sites/:siteId/monitors/:protocol` admin only
- `POST /api/sites/:siteId/monitors/:protocol/diagnostics` admin only
- `POST /api/sites/:siteId/monitors/snmp/test` admin only
- `POST /api/sites/:siteId/monitors/syslog/test` admin only
- `POST /api/sites/:siteId/monitors/netflow/test` admin only
- `POST /api/sites/:siteId/tools/terminal` admin only
- `POST /api/sites/:siteId/collector/terminal` admin only
- `POST /api/sites/:siteId/collector/agent/password` admin only
- `PATCH /api/sites/:siteId/notifications` admin only
- `POST /api/sites/:siteId/test-notify` admin only

### 7.8 Devices and health

- `GET /api/devices`
- `POST /api/devices` admin only
- `GET /api/health`
- `GET /api/summary`

### 7.9 Collector agents (Linux + Windows)

- `GET /api/agent/linux/download` download installable Linux agent script (`.py`)
- `GET /api/agent/linux/download?format=deb` download installable Linux agent package (`.deb`)
- `GET /api/agent/windows/download` download Windows collector agent PowerShell script (`.ps1`)
  - Optional: `?format=exe` to download a native `.exe` package if one is hosted on the server
- `GET /api/agent/collectors` list collector sites for setup picker / CLI setup workflows
- `POST /api/agent/register` agent phone-home registration with site/password
- `POST /api/agent/poll` agent command poll endpoint
- `POST /api/agent/result` agent command result endpoint

## 8. Security notes

### 8.1 What is good in current build

- Sensitive monitor/SSO values encrypted at rest
- Passwords stored as PBKDF2 hashes with salt and configurable iterations
- Session cookies are `HttpOnly` and `SameSite=Lax`
- Role checks on mutating admin endpoints
- CSRF origin checks for state-changing cookie-auth API requests
- Login protection uses IP rate limiting plus account-level lockout/backoff
- Response headers include a hardened CSP (`script-src 'self'`)

### 8.2 Gaps for production

- No centralized secret manager integration
- File backend has no HA locking model (use PostgreSQL backend for production)
- Limited SNMPv3 profile support (`authNoPriv`)

### 8.3 Docker socket security model

The auto-update stack uses `tecnativa/docker-socket-proxy` as a whitelist firewall between Watchtower and `/var/run/docker.sock`. Watchtower connects to the proxy over the internal Docker network and can only perform: list/inspect containers, pull images, authenticate to registries, stop/start/recreate containers, and reconnect networks. It cannot exec into containers, create arbitrary new containers, mount host paths, or access Docker system/swarm APIs. The proxy itself holds the socket mount.

## 9. Troubleshooting

### 9.1 `CAJAL_CONFIG_KEY is required`

Set the key before start:

```bash
export CAJAL_CONFIG_KEY='your-secret'
npm start
```

### 9.2 `Unsupported state or unable to authenticate data`

The key used to decrypt existing encrypted data does not match the key used when it was written.
Use the original key or reinitialize encrypted files.

### 9.3 SNMP errors (`spawn snmpget ENOENT`)

Install Net-SNMP tools so `snmpget` is in PATH.
You can verify this in Settings -> System Health -> SNMP CLI Checker.

### 9.4 WAN tests show `n/a`

Either speedtest is disabled (`CAJAL_ENABLE_SPEEDTEST` not `1`) or speedtest CLI is not installed.
Latency can still be shown from ping.

### 9.5 Login loops or unauthorized API calls

- Confirm session cookie is accepted by browser
- Confirm you are on `/login.html` first
- Verify default user exists (`admin`) in current backend (`users` key in `cajal_store`)

### 9.6 Teams notifications not delivered

- Confirm site notifications are enabled
- Confirm `CAJAL_TEAMS_WEBHOOK_URL` is set correctly and reachable from the CAJAL host
- Check Event Viewer for `status_notify_sent` or `status_notify_failed` events

### 9.7 Syslog packets visible in `tcpdump` but not visible in dashboard

- Confirm saved monitor config with `GET /api/sites` while authenticated (source IP, protocol, enabled)
- Use `Test Syslog Now` from the monitor editor to force a known-good ingest event
- Check Settings -> Diagnostics Console and Settings -> Raw Telemetry Stream for unmatched source IP entries
- Run Settings -> Local Firewall Checker to validate host firewall/port rules
- Verify flow state window settings if badges flap: `CAJAL_FLOW_TIMEOUT_MS` and `CAJAL_SYSLOG_FLOW_TIMEOUT_MIN_MS`

### 9.8 NetFlow/IPFIX enabled but no traffic in top talkers

- Confirm exporter sends to the Cajal host IP and configured NetFlow UDP port
- Confirm exporter format matches supported parsing path (IPFIX v10, NetFlow v9/v5)
- Verify packets with `tcpdump` on port `2055`; if none arrive, this is upstream of Cajal
- Use `Test NetFlow Now` to validate UI pipeline independently of exporter traffic
- Verify flow state window settings if badges flap: `CAJAL_FLOW_TIMEOUT_MS` and `CAJAL_NETFLOW_FLOW_TIMEOUT_MIN_MS`

### 9.9 PostgreSQL startup/connectivity issues

- Confirm `CAJAL_DATABASE_URL` is reachable from the app host/container
- If TLS is required by your DB, set `CAJAL_DATABASE_SSL=require` (or `verify-ca`/`verify-full`)
- Check startup log for `Storage backend: postgres`
- Run `docker compose logs -f postgres cajal` to inspect container-side failures

### Tools Terminal {#tools-terminal}

- In compact Tools mode:
  - Click `Launch` to open the full terminal surface
  - Click `Learn` to open this section in Help
- In expanded Tools mode:
  - Click `Close` to collapse back to compact mode
- Commands and switches:
  - `help` show command reference
  - `status` show per-protocol health snapshot for the site
  - `snmp poll` / `snmp test` run live SNMP uptime query
  - `snmp diag` / `snmp diagnostics` run SNMP diagnostics checks
  - `syslog diag` / `syslog diagnostics` run Syslog diagnostics checks
  - `netflow top` / `netflow talkers` show top talkers list
  - `netflow diag` / `netflow diagnostics` run NetFlow diagnostics checks
  - `listeners` verify local listener ports and firewall visibility
  - `ping [host]` ICMP reachability test (default host from site context)
  - `traceroute [host]` route path test
  - `dns [hostname]` DNS lookup
  - `clear` / `cls` clear terminal output
  - `?` suffix (example: `snmp ?`) lists valid completions for entered text
  - `Tab` auto-completes command/subcommand text
- Collector role terminal behavior:
  - Allowed commands: `doctor`/`deps`/`capabilities`, `update`, `speedtest`, `ping`, `traceroute`/`tracert`, `dns`/`resolve`/`nslookup`, `ipconfig`
  - Execution runs on the remote collector agent host (Linux or Windows), not on Cajal server
  - Linux Agent button sets/rotates per-site agent password and downloads a Debian package (`cajal-agent*.deb`)
  - Windows Agent button sets/rotates per-site agent password and downloads `cajal-windows-agent.ps1`
  - Collector card includes `Copy Enroll Cmd` for one-shot install/setup commands with `--server` and `--site` prefilled
  - Installed collector diagnostics CLI: `cajal-connect-test`
  - Example remote install:
    - `curl -fsSL http://<cajal-host>:4000/api/agent/linux/download?format=deb -o cajal-agent.deb`
    - `sudo dpkg -i ./cajal-agent.deb || sudo apt-get -f install -y`
    - Package dependencies now enforce core collector tools (`iproute2`, `ping`, `traceroute`, DNS tools, `speedtest-cli`/`speedtest`, `curl`/`wget`)
    - `sudo cajal-agent-setup --server 'http://<cajal-host>:4000' --site 'site-collector-id'`
    - Setup verifies `/api/agent/register` + `/api/agent/poll` before writing config
    - Run `cajal-connect-test --strict-tools` to verify DNS/TCP/health/register/poll and local command dependencies
    - Service auto-enables/starts when config is valid and auto-starts on reboot
  - Example Windows collector install:
    - `powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -UseBasicParsing 'http://<cajal-host>:4000/api/agent/windows/download?format=ps1' -OutFile 'cajal-windows-agent.ps1'"`
    - `powershell -NoProfile -ExecutionPolicy Bypass -File .\cajal-windows-agent.ps1 -Server 'http://<cajal-host>:4000' -Site 'site-collector-id' -Password '<agent-password>'`
    - Optional if hosted: `http://<cajal-host>:4000/api/agent/windows/download?format=exe`
    - Optional: run that command from Task Scheduler at startup as `SYSTEM` with highest privileges

### 9.10 Collector agent not checking in

- On the collector host run `cajal-connect-test`
  - This validates:
    - config fields in `/etc/cajal-agent/agent.env`
    - local troubleshooting toolchain (`ping`, `traceroute`/`tracepath`, DNS lookup tools, `speedtest`/`speedtest-cli`)
    - DNS resolution of the Cajal server host
    - TCP connectivity to Cajal server port
    - `GET /api/health`
    - `POST /api/agent/register` and `POST /api/agent/poll`
- In collector terminal, run `doctor` to check the remote agent toolchain directly from CAJAL UI
- Collector card includes an `UPDATE` button:
  - Shows current agent version and next package version
  - Pushes remote agent self-update using the CAJAL-hosted `.deb` package URL
  - If agent is too old to support `update`, terminal output includes manual one-shot install commands
- If it fails:
  - Re-run setup: `sudo cajal-agent-setup` (or include `--server` and `--site`)
  - List collectors from setup host: `sudo cajal-agent-setup --server 'http://<cajal-host>:4000' --list-collectors`
  - Confirm service state: `sudo systemctl status cajal-agent --no-pager`
  - Confirm recent logs: `sudo journalctl -u cajal-agent -n 120 --no-pager`

### 9.11 Syslog or NetFlow shows offline while traffic still works

- Cajal now uses protocol-aware stale windows to reduce false offline toggles for bursty traffic.
- Defaults:
  - `CAJAL_FLOW_TIMEOUT_MS=120000` (base)
  - `CAJAL_SYSLOG_FLOW_TIMEOUT_MIN_MS=900000` (15m minimum)
  - `CAJAL_NETFLOW_FLOW_TIMEOUT_MIN_MS=900000` (15m minimum)
- If your traffic is sparse/bursty, increase minimum windows (example 30 minutes):
  - `CAJAL_SYSLOG_FLOW_TIMEOUT_MIN_MS=1800000`
  - `CAJAL_NETFLOW_FLOW_TIMEOUT_MIN_MS=1800000`
- Apply changes by restarting/rebuilding your runtime (for Docker: `npm run docker:rebuild`).

## 10. Development notes

### 10.1 Code layout

- `server.js` entry point — starts servers, registers shutdown handlers, calls `main()`
- `lib/` — modularized server logic:
  - `router.js` HTTP request handler (~3800 lines, all API routes)
  - `constants.js` environment variable bindings and defaults
  - `session.js` auth, CSP, security headers
  - `monitoring.js` ping, SNMP, NetFlow, syslog pollers
  - `ratelimit.js` rate limiting and account lockout helpers
  - and 14 other focused modules
- `public/index.html` main dashboard
- `public/app.js` dashboard client logic
- `public/login.html` + `public/login.js` local login flow
- `public/styles.css` complete UI styling
- `docs/architecture.md` system architecture and data-flow reference

### 10.2 Unit tests

- Run all tests:
  - `npm test`
- Run Node unit tests only:
  - `npm run test:node`
- Run Python agent unit tests only:
  - `npm run test:python`
- Run browser E2E smoke tests:
  - `npm run test:e2e`
- CI workflow:
  - `.github/workflows/ci.yml` runs unit tests plus Playwright smoke checks on push/PR
- Current unit coverage focus:
  - Core Syslog parsing/source matching/metric update logic
  - Core NetFlow/IPFIX parsing + top talker calculation
  - SNMP uptime formatting + flow timeout logic
  - Heartbeat target/status/freshness logic
  - Collector agent session/queue/update fallback helpers
  - Linux agent speedtest fallback + command validation helpers

### 10.3 Suggested next hardening steps

- Add event export/download and retention controls in UI
- Add structured alerting pipeline expansion (Teams/webhook/Slack + policy packs)
- Add distributed deployment controls for multi-node runtime (leader election/locks)
- Add centralized secret manager integration for `CAJAL_CONFIG_KEY` rotation
