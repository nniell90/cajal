# CAJAL Architecture

## Overview

CAJAL runs as a single Node.js service that combines:

- Web UI static hosting
- REST API for configuration/operations
- Real-time telemetry collectors (Syslog, NetFlow, SNMP poller, heartbeat poller)
- Collector-agent control channel (register, poll, command execution results)

The dashboard (`public/app.js`) is a stateful client that refreshes snapshots from the API and renders location/device cards with operational controls.

## Runtime Components

### 1. API + state engine (`server.js`)

- Owns in-memory runtime state for sites, devices, telemetry health, agent sessions, and event streams.
- Persists durable data in Postgres key/value store (`cajal_store`).
- Computes derived status:
  - per-protocol telemetry health (syslog/snmp/netflow)
  - site status (`up`/`warn`/`down`)
  - alert and notification behavior

### 2. Telemetry collectors

- Syslog collector:
  - UDP + TCP listeners
  - source-IP to site matching
  - EPS counters + ingest events
- NetFlow/IPFIX collector:
  - supports v5, v9, and IPFIX via template decoding
  - tracks top talkers with rolling bandwidth windows
- SNMP poller:
  - periodic `snmpget` uptime polling
  - emits success/failure diagnostics and flow state updates
- Heartbeat poller:
  - pings primary/secondary target links
  - drives WAN status badges + uptime trend samples

### 3. Collector agent channel

- Agent authenticates/registers against a specific collector site id.
- Agent polls server for queued read-only troubleshooting commands.
- Server uses per-site FIFO command queues and lease windows so commands are not duplicated.
- Agent returns normalized output + optional metrics (for example speedtest metrics).

## UI Architecture (`public/app.js`)

- Maintains snapshots for:
  - auth/runtime/health payloads
  - site cards and metrics
  - diagnostics/raw telemetry views
- Uses delegated click handlers so dynamic cards do not need per-render rebinding.
- "Server self monitor" badges are composed from `/api/settings/system-health` and `/api/settings/firewall-check`.

## Linux Agent (`agent/cajal-linux-agent.py`)

- Strict allowlist command dispatcher (no arbitrary shell).
- Executes troubleshooting commands locally on collector host:
  - `doctor`, `ping`, `traceroute`, `dns`, `speedtest`, `update`
- Uses command fallbacks for portability:
  - `speedtest` -> `speedtest-cli`
  - `traceroute` -> `tracepath`
  - `dns` tries `nslookup/getent/dig`

## Testing Strategy

256 total tests (243 Node + 13 Python) covering:

- Syslog parsing/source matching/metric updates
- NetFlow parser paths (v5, v9 template+data) and top-talker ranking
- SNMP/flow timeout behavior
- Heartbeat normalization/status derivation
- Collector-agent queue/session/update fallback helpers
- Linux agent command validation and speedtest fallback behavior
- Exhaustive unauthenticated endpoint scan (allowlist-based)
- Database SSL auto-detection and all SSL mode configurations
- Schema versioning, migration ordering, and startup integration
- PostgreSQL connection retry with exponential backoff
- Setup token single-use consumption
- TCP syslog stream framing and SNMPv3 credential isolation
- AsyncMutex serialization and error recovery
- TOTP replay map pruning and conditional metric decay

Run test suites:

- `npm test`
- `npm run test:node`
- `npm run test:python`
