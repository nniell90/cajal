'use strict';
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const os = require('os');
const net = require('net');
const crypto = require('crypto');
const { execFile } = require('child_process');
const shared = require('./shared');
const {
  PORT,
  TOOLS_TERMINAL_MAX_LINES,
  COLLECTOR_AGENT_SESSION_TTL_MS,
  COLLECTOR_AGENT_COMMAND_TIMEOUT_MS,
  COLLECTOR_AGENT_COMMAND_LEASE_MS,
  LINUX_AGENT_SCRIPT_FILE,
  LINUX_AGENT_SETUP_SCRIPT_FILE,
  LINUX_AGENT_CONNECT_TEST_SCRIPT_FILE,
  LINUX_AGENT_DEB_PACKAGE_NAME,
  LINUX_AGENT_DEB_VERSION,
  LINUX_AGENT_SERVICE_NAME,
  LINUX_AGENT_DEB_ARCH,
  SYSLOG_UDP_PORT,
  SYSLOG_TCP_PORT,
  NETFLOW_PORT,
  TOOLS_TERMINAL_TIMEOUT_MS,
} = require('./constants');
const { smartReadFile, smartStat } = require('./storage');
const { locationNameForSite } = require('./events');
const { normalizeUserEntry } = require('./auth');

// ── Exec helpers ──────────────────────────────────────────────────────────────
function runExecFile(cmd, args = [], timeout = 5000) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout }, (err, stdout = '', stderr = '') => {
      resolve({ err, stdout: String(stdout || ''), stderr: String(stderr || '') });
    });
  });
}

function runExecFileWithOptions(cmd, args = [], options = {}) {
  const timeout = Number(options?.timeout || 5000);
  const cwd = options?.cwd ? String(options.cwd) : undefined;
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout, cwd }, (err, stdout = '', stderr = '') => {
      resolve({ err, stdout: String(stdout || ''), stderr: String(stderr || '') });
    });
  });
}

// ── Linux agent deb package builder ──────────────────────────────────────────
async function buildLinuxAgentDebPackage() {
  const scriptStat = await smartStat(LINUX_AGENT_SCRIPT_FILE);
  const scriptMtimeMs = Number(scriptStat?.mtimeMs || 0);
  const setupScriptStat = await smartStat(LINUX_AGENT_SETUP_SCRIPT_FILE);
  const setupScriptMtimeMs = Number(setupScriptStat?.mtimeMs || 0);
  const connectTestScriptStat = await smartStat(LINUX_AGENT_CONNECT_TEST_SCRIPT_FILE);
  const connectTestScriptMtimeMs = Number(connectTestScriptStat?.mtimeMs || 0);
  if (
    shared.linuxAgentDebCache.body
    && shared.linuxAgentDebCache.fileName
    && shared.linuxAgentDebCache.scriptMtimeMs === scriptMtimeMs
    && shared.linuxAgentDebCache.setupScriptMtimeMs === setupScriptMtimeMs
    && shared.linuxAgentDebCache.connectTestScriptMtimeMs === connectTestScriptMtimeMs
  ) {
    return {
      fileName: shared.linuxAgentDebCache.fileName,
      body: shared.linuxAgentDebCache.body
    };
  }

  const dpkgCheck = await runExecFile('dpkg-deb', ['--version'], 5000);
  if (dpkgCheck.err) {
    throw new Error('dpkg-deb is not available on this Cajal host. Install dpkg and try again.');
  }

  const packageName = LINUX_AGENT_DEB_PACKAGE_NAME;
  const packageVersion = LINUX_AGENT_DEB_VERSION;
  const packageFileName = `${packageName}_${packageVersion}_${LINUX_AGENT_DEB_ARCH}.deb`;
  const tempRoot = await fsp.mkdtemp(path.join(os.tmpdir(), 'cajal-agent-deb-'));
  const pkgRoot = path.join(tempRoot, 'pkgroot');
  const controlDir = path.join(pkgRoot, 'DEBIAN');
  const installScriptPath = path.join(pkgRoot, 'usr', 'lib', 'cajal-agent', 'cajal-linux-agent.py');
  const setupScriptPath = path.join(pkgRoot, 'usr', 'lib', 'cajal-agent', 'cajal-agent-setup.py');
  const connectTestScriptPath = path.join(pkgRoot, 'usr', 'lib', 'cajal-agent', 'cajal-connect-test.py');
  const launcherPath = path.join(pkgRoot, 'usr', 'bin', 'cajal-agent');
  const setupLauncherPath = path.join(pkgRoot, 'usr', 'bin', 'cajal-agent-setup');
  const connectTestLauncherPath = path.join(pkgRoot, 'usr', 'bin', 'cajal-connect-test');
  const unitPath = path.join(pkgRoot, 'usr', 'lib', 'systemd', 'system', `${LINUX_AGENT_SERVICE_NAME}.service`);
  const envExamplePath = path.join(pkgRoot, 'etc', 'cajal-agent', 'agent.env.example');
  const outputDebPath = path.join(tempRoot, packageFileName);

  const controlContent = [
    `Package: ${packageName}`,
    `Version: ${packageVersion}`,
    'Section: net',
    'Priority: optional',
    `Architecture: ${LINUX_AGENT_DEB_ARCH}`,
    'Maintainer: Cajal <admin@cajal.local>',
    'Depends: python3, iproute2, iputils-ping | inetutils-ping, traceroute | iputils-tracepath, dnsutils | bind9-dnsutils, speedtest-cli | speedtest, curl | wget',
    'Description: Cajal Collector Agent',
    ' Read-only collector agent for remote ping, traceroute, DNS, and WAN speed checks.',
    ' It securely polls Cajal for allowed troubleshooting commands and returns output.'
  ].join('\n') + '\n';

const launcherContent = `#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/etc/cajal-agent/agent.env"
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

SERVER="\${CAJAL_AGENT_SERVER:-\${CAJAL_AGENT_SERVER_URL:-}}"
SITE="\${CAJAL_AGENT_SITE:-\${CAJAL_AGENT_SITE_ID:-}}"
PASSWORD="\${CAJAL_AGENT_PASSWORD:-}"

if [[ -z "$SERVER" || -z "$SITE" || -z "$PASSWORD" ]]; then
  echo "Missing CAJAL_AGENT_SERVER, CAJAL_AGENT_SITE, or CAJAL_AGENT_PASSWORD in /etc/cajal-agent/agent.env" >&2
  exit 2
fi

ARGS=(--server "$SERVER" --site "$SITE" --password-env "CAJAL_AGENT_PASSWORD")
if [[ -n "\${CAJAL_AGENT_POLL_INTERVAL:-}" ]]; then
  ARGS+=(--poll-interval "$CAJAL_AGENT_POLL_INTERVAL")
fi
if [[ "\${CAJAL_AGENT_INSECURE:-0}" == "1" ]]; then
  ARGS+=(--insecure)
fi

exec /usr/bin/python3 /usr/lib/cajal-agent/cajal-linux-agent.py "\${ARGS[@]}" "$@"
`;

  const setupLauncherContent = `#!/usr/bin/env bash
set -euo pipefail
exec /usr/bin/python3 /usr/lib/cajal-agent/cajal-agent-setup.py "$@"
`;

  const connectTestLauncherContent = `#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/etc/cajal-agent/agent.env"
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

SERVER="\${CAJAL_AGENT_SERVER:-\${CAJAL_AGENT_SERVER_URL:-}}"
SITE="\${CAJAL_AGENT_SITE:-\${CAJAL_AGENT_SITE_ID:-}}"
PASSWORD="\${CAJAL_AGENT_PASSWORD:-}"

ARGS=()
if [[ -n "$SERVER" ]]; then
  ARGS+=(--server "$SERVER")
fi
if [[ -n "$SITE" ]]; then
  ARGS+=(--site "$SITE")
fi
if [[ -n "$PASSWORD" ]]; then
  ARGS+=(--password-env "CAJAL_AGENT_PASSWORD")
fi
if [[ "\${CAJAL_AGENT_INSECURE:-0}" == "1" ]]; then
  ARGS+=(--insecure)
fi

exec /usr/bin/python3 /usr/lib/cajal-agent/cajal-connect-test.py "\${ARGS[@]}" "$@"
`;

  const serviceContent = `[Unit]
Description=Cajal Collector Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=-/etc/cajal-agent/agent.env
ExecStart=/usr/bin/cajal-agent
Restart=on-failure
RestartSec=5
User=cajal-agent
Group=cajal-agent
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
CapabilityBoundingSet=
ReadWritePaths=/var/log/cajal /etc/cajal-agent

[Install]
WantedBy=multi-user.target
`;

  const envExampleContent = `CAJAL_AGENT_SERVER=http://127.0.0.1:4000
CAJAL_AGENT_SITE=
CAJAL_AGENT_PASSWORD=
CAJAL_AGENT_POLL_INTERVAL=1.5
CAJAL_AGENT_INSECURE=0
`;

  const postinstContent = `#!/bin/sh
set -e

ENV_FILE="/etc/cajal-agent/agent.env"
ENV_EXAMPLE="/etc/cajal-agent/agent.env.example"
SETUP_CMD="/usr/bin/cajal-agent-setup"

ensure_agent_account() {
  if command -v getent >/dev/null 2>&1 && ! getent group cajal-agent >/dev/null 2>&1; then
    if command -v groupadd >/dev/null 2>&1; then
      groupadd --system cajal-agent >/dev/null 2>&1 || true
    fi
  fi
  if ! id -u cajal-agent >/dev/null 2>&1; then
    if command -v useradd >/dev/null 2>&1; then
      useradd --system --gid cajal-agent --home-dir /nonexistent --shell /usr/sbin/nologin cajal-agent >/dev/null 2>&1 || true
    elif command -v adduser >/dev/null 2>&1; then
      adduser --system --ingroup cajal-agent --no-create-home --home /nonexistent --shell /usr/sbin/nologin cajal-agent >/dev/null 2>&1 || true
    fi
  fi
}

has_required_config() {
  [ -f "$ENV_FILE" ] || return 1
  server=$(sed -n 's/^CAJAL_AGENT_SERVER=//p' "$ENV_FILE" | tail -n 1 | tr -d '\\r')
  site=$(sed -n 's/^CAJAL_AGENT_SITE=//p' "$ENV_FILE" | tail -n 1 | tr -d '\\r')
  password=$(sed -n 's/^CAJAL_AGENT_PASSWORD=//p' "$ENV_FILE" | tail -n 1 | tr -d '\\r')
  [ -n "$server" ] && [ -n "$site" ] && [ -n "$password" ]
}

run_setup_wizard() {
  [ -x "$SETUP_CMD" ] || return 1
  target_user=""
  if [ -n "\${SUDO_USER:-}" ] && [ "\${SUDO_USER}" != "root" ]; then
    target_user="\${SUDO_USER}"
  fi
  if [ -z "$target_user" ] && [ -n "\${PKEXEC_UID:-}" ] && command -v getent >/dev/null 2>&1; then
    target_user=$(getent passwd "\${PKEXEC_UID}" | cut -d: -f1)
  fi

  if [ -n "$target_user" ] && command -v runuser >/dev/null 2>&1 && [ -n "\${DISPLAY:-}" ]; then
    tmpfile=$(mktemp /tmp/cajal-agent-env.XXXXXX)
    if runuser -u "$target_user" -- env DISPLAY="\${DISPLAY}" XAUTHORITY="\${XAUTHORITY:-}" "$SETUP_CMD" --print-env > "$tmpfile"; then
      if [ -s "$tmpfile" ]; then
        install -m 600 "$tmpfile" "$ENV_FILE"
        rm -f "$tmpfile"
        return 0
      fi
    fi
    rm -f "$tmpfile"
  fi

  if [ -t 0 ]; then
    "$SETUP_CMD" --env-file "$ENV_FILE" && return 0
  fi
  return 1
}

ensure_agent_account
install -d -m 750 -o root -g cajal-agent /etc/cajal-agent
if [ ! -f "$ENV_FILE" ]; then
  install -m 640 -o root -g cajal-agent "$ENV_EXAMPLE" "$ENV_FILE"
else
  chown root:cajal-agent "$ENV_FILE" >/dev/null 2>&1 || true
  chmod 640 "$ENV_FILE" >/dev/null 2>&1 || true
fi

if ! has_required_config; then
  run_setup_wizard || true
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  if has_required_config; then
    systemctl enable --now ${LINUX_AGENT_SERVICE_NAME} || true
    echo "Cajal agent installed and started (${LINUX_AGENT_SERVICE_NAME})."
  else
    systemctl disable --now ${LINUX_AGENT_SERVICE_NAME} >/dev/null 2>&1 || true
    echo "Cajal agent installed but not configured."
    echo "Run: sudo cajal-agent-setup"
    echo "Then: sudo systemctl enable --now ${LINUX_AGENT_SERVICE_NAME}"
  fi
fi

if ! command -v speedtest >/dev/null 2>&1 && ! command -v speedtest-cli >/dev/null 2>&1; then
  echo "Optional: install speedtest or speedtest-cli for WAN throughput checks."
fi
exit 0
`;

  const postrmContent = `#!/bin/sh
set -e

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi
exit 0
`;

  try {
    await Promise.all([
      fsp.mkdir(controlDir, { recursive: true }),
      fsp.mkdir(path.dirname(installScriptPath), { recursive: true }),
      fsp.mkdir(path.dirname(connectTestScriptPath), { recursive: true }),
      fsp.mkdir(path.dirname(launcherPath), { recursive: true }),
      fsp.mkdir(path.dirname(setupLauncherPath), { recursive: true }),
      fsp.mkdir(path.dirname(connectTestLauncherPath), { recursive: true }),
      fsp.mkdir(path.dirname(unitPath), { recursive: true }),
      fsp.mkdir(path.dirname(envExamplePath), { recursive: true })
    ]);

    const scriptContent = await smartReadFile(LINUX_AGENT_SCRIPT_FILE, 'utf8');
    const setupScriptContent = await smartReadFile(LINUX_AGENT_SETUP_SCRIPT_FILE, 'utf8');
    const connectTestScriptContent = await smartReadFile(LINUX_AGENT_CONNECT_TEST_SCRIPT_FILE, 'utf8');
    await Promise.all([
      fsp.writeFile(path.join(controlDir, 'control'), controlContent, 'utf8'),
      fsp.writeFile(path.join(controlDir, 'postinst'), postinstContent, 'utf8'),
      fsp.writeFile(path.join(controlDir, 'postrm'), postrmContent, 'utf8'),
      fsp.writeFile(installScriptPath, scriptContent, 'utf8'),
      fsp.writeFile(setupScriptPath, setupScriptContent, 'utf8'),
      fsp.writeFile(connectTestScriptPath, connectTestScriptContent, 'utf8'),
      fsp.writeFile(launcherPath, launcherContent, 'utf8'),
      fsp.writeFile(setupLauncherPath, setupLauncherContent, 'utf8'),
      fsp.writeFile(connectTestLauncherPath, connectTestLauncherContent, 'utf8'),
      fsp.writeFile(unitPath, serviceContent, 'utf8'),
      fsp.writeFile(envExamplePath, envExampleContent, 'utf8')
    ]);
    await Promise.all([
      fsp.chmod(path.join(controlDir, 'postinst'), 0o755),
      fsp.chmod(path.join(controlDir, 'postrm'), 0o755),
      fsp.chmod(installScriptPath, 0o755),
      fsp.chmod(setupScriptPath, 0o755),
      fsp.chmod(connectTestScriptPath, 0o755),
      fsp.chmod(launcherPath, 0o755),
      fsp.chmod(setupLauncherPath, 0o755),
      fsp.chmod(connectTestLauncherPath, 0o755),
      fsp.chmod(unitPath, 0o644),
      fsp.chmod(envExamplePath, 0o644)
    ]);

    const buildResult = await runExecFileWithOptions('dpkg-deb', ['--build', pkgRoot, outputDebPath], { timeout: 45000 });
    if (buildResult.err) {
      const detail = String(buildResult.stderr || buildResult.err.message || 'dpkg-deb build failed').trim();
      throw new Error(`Failed to build Linux agent .deb: ${detail}`);
    }

    const body = await fsp.readFile(outputDebPath);
    if (!body?.length) throw new Error('Built Linux agent .deb is empty');
    shared.linuxAgentDebCache = {
      scriptMtimeMs,
      setupScriptMtimeMs,
      connectTestScriptMtimeMs,
      fileName: packageFileName,
      body
    };
    return {
      fileName: packageFileName,
      body
    };
  } finally {
    await fsp.rm(tempRoot, { recursive: true, force: true }).catch(() => {});
  }
}

// ── Tools terminal helpers ────────────────────────────────────────────────────
function splitNonEmptyLines(text = '') {
  return String(text || '')
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function normalizeToolsTerminalLines(lines = [], maxLines = TOOLS_TERMINAL_MAX_LINES) {
  const rows = Array.isArray(lines) ? lines : splitNonEmptyLines(String(lines || ''));
  return rows
    .map((line) => String(line || '').trim())
    .filter(Boolean)
    .slice(0, maxLines);
}

function parseToolsTerminalTokens(value = '') {
  const raw = String(value || '').trim();
  if (!raw) return [];
  return raw.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/g) || [];
}

function sanitizeToolsTerminalHostToken(value = '') {
  const raw = String(value || '').trim();
  if (!raw) return '';
  if (raw.length > 255) return '';
  if (!/^[A-Za-z0-9._:\[\]-]+$/.test(raw)) return '';
  return raw;
}

function formatToolsTerminalMbps(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return 'n/a';
  if (n >= 1000) return `${(n / 1000).toFixed(2)} Gbps`;
  if (n >= 1) return `${n.toFixed(1)} Mbps`;
  return `${(n * 1000).toFixed(0)} Kbps`;
}

function toolsTerminalDefaultHost(site) {
  const ip = String(site?.collector?.ip || '').trim();
  const terminalHost = String(site?.collector?.terminalHost || '').trim();
  const localIp = String(site?.collector?.localIp || '').trim();
  return terminalHost || localIp || ip || '';
}

// ── Collector agent presence ──────────────────────────────────────────────────
function getCollectorAgentPresence(state, siteId, now = Date.now()) {
  const key = String(siteId || '').trim();
  if (!key) return null;
  const current = state?.agentBySite?.get(key);
  if (!current) return null;
  const token = String(current.token || '').trim();
  const session = token ? state?.agentSessions?.get(token) : null;
  if (!session) {
    state?.agentBySite?.delete(key);
    return null;
  }
  const lastSeenAt = Number(session.lastSeenAt || current.lastSeenAt || 0);
  const connected = lastSeenAt > 0 && now - lastSeenAt <= COLLECTOR_AGENT_SESSION_TTL_MS;
  if (!connected) return null;
  return {
    connected: true,
    siteId: key,
    token,
    sessionId: String(session.sessionId || ''),
    hostname: String(session.hostname || current.hostname || '').trim(),
    platform: String(session.platform || current.platform || '').trim(),
    version: String(session.version || current.version || '').trim(),
    remoteIp: String(session.remoteIp || current.remoteIp || '').trim(),
    localIp: String(session.localIp || current.localIp || '').trim(),
    lastSeenAt
  };
}

function setCollectorAgentPresence(state, session, now = Date.now()) {
  const siteId = String(session?.siteId || '').trim();
  const token = String(session?.token || '').trim();
  if (!siteId || !token) return;
  const payload = {
    token,
    lastSeenAt: now,
    hostname: String(session?.hostname || '').trim(),
    platform: String(session?.platform || '').trim(),
    version: String(session?.version || '').trim(),
    remoteIp: String(session?.remoteIp || '').trim(),
    localIp: String(session?.localIp || '').trim()
  };
  state.agentBySite.set(siteId, payload);
}

function collectorSiteById(state, siteId = '') {
  const key = String(siteId || '').trim();
  if (!key) return null;
  return state?.sites?.find((row) => String(row?.id || '').trim() === key) || null;
}

// ── Agent session management ──────────────────────────────────────────────────
function pruneCollectorAgentSessions(state, now = Date.now()) {
  const activeSiteIds = new Set();
  for (const [token, session] of state.agentSessions.entries()) {
    const expiresAt = Number(session?.expiresAt || 0);
    if (!expiresAt || expiresAt <= now) {
      state.agentSessions.delete(token);
      continue;
    }
    if (session?.siteId) activeSiteIds.add(String(session.siteId));
  }
  for (const siteId of state.agentBySite.keys()) {
    if (!activeSiteIds.has(siteId)) state.agentBySite.delete(siteId);
  }
}

function ensureCollectorAgentQueue(state, siteId) {
  const key = String(siteId || '').trim();
  if (!key) return [];
  if (!state.agentCommandQueue.has(key)) state.agentCommandQueue.set(key, []);
  return state.agentCommandQueue.get(key);
}

function removeCollectorAgentQueuedCommand(state, siteId, commandId) {
  const key = String(siteId || '').trim();
  const cmdId = String(commandId || '').trim();
  if (!key || !cmdId) return;
  const queue = ensureCollectorAgentQueue(state, key);
  const idx = queue.findIndex((row) => String(row?.id || '') === cmdId);
  if (idx >= 0) queue.splice(idx, 1);
}

function dequeueCollectorAgentCommandForPoll(state, siteId, now = Date.now()) {
  const queue = ensureCollectorAgentQueue(state, siteId);
  for (const item of queue) {
    const leaseUntil = Number(item?.leaseUntil || 0);
    if (leaseUntil > now) continue;
    item.leaseUntil = now + COLLECTOR_AGENT_COMMAND_LEASE_MS;
    item.attempts = Number(item.attempts || 0) + 1;
    item.lastIssuedAt = now;
    return item;
  }
  return null;
}

// ── Shell quote helper ────────────────────────────────────────────────────────
function shellQuoteArg(value = '') {
  return `'${String(value || '').replace(/'/g, `'\"'\"'`)}'`;
}

function collectorResultHasUnsupportedCommand(result = {}, command = '') {
  const cmd = String(command || '').trim().toLowerCase();
  if (!cmd) return false;
  const needle = `unsupported agent command: ${cmd}`;
  const lines = Array.isArray(result?.lines) ? result.lines : [];
  return lines.some((line) => String(line || '').toLowerCase().includes(needle));
}

function collectorManualUpdateLines(downloadUrl = '', targetVersion = '') {
  const rawUrl = String(downloadUrl || '').trim();
  const safeUrl = /^https?:\/\/[^ "'\t\r\n]+$/i.test(rawUrl)
    ? rawUrl
    : `http://localhost:${PORT}/api/agent/linux/download?format=deb`;
  const version = String(targetVersion || '').trim() || 'latest';
  const quotedUrl = shellQuoteArg(safeUrl);
  return normalizeToolsTerminalLines([
    'Legacy collector agent detected: remote update command not supported.',
    `Target agent version: ${version}`,
    'Run these commands directly on the collector host:',
    `curl -fsSL ${quotedUrl} -o /tmp/cajal-agent.deb || wget -qO /tmp/cajal-agent.deb ${quotedUrl}`,
    'sudo dpkg -i /tmp/cajal-agent.deb || sudo apt-get -f install -y'
  ]);
}

// ── Command waiter management ─────────────────────────────────────────────────
function resolveCollectorCommandWaiter(state, siteId, commandId, payload = {}) {
  const cmdId = String(commandId || '').trim();
  if (!cmdId) return false;
  const pending = state.agentPending.get(cmdId);
  if (!pending) return false;
  const expectedSiteId = String(pending.siteId || '').trim();
  if (expectedSiteId && expectedSiteId !== String(siteId || '').trim()) return false;
  clearTimeout(pending.timeout);
  state.agentPending.delete(cmdId);
  removeCollectorAgentQueuedCommand(state, expectedSiteId || siteId, cmdId);
  pending.resolve(payload);
  return true;
}

function rejectCollectorCommandWaiter(state, commandId, reason = 'Agent command timed out') {
  const cmdId = String(commandId || '').trim();
  if (!cmdId) return;
  const pending = state.agentPending.get(cmdId);
  if (!pending) return;
  clearTimeout(pending.timeout);
  state.agentPending.delete(cmdId);
  removeCollectorAgentQueuedCommand(state, pending.siteId, cmdId);
  pending.reject(new Error(reason));
}

function queueCollectorAgentCommand(state, site, commandText = '') {
  const siteId = String(site?.id || '').trim();
  const command = String(commandText || '').trim();
  if (!siteId) return Promise.reject(new Error('Site id missing'));
  if (!command) return Promise.reject(new Error('Command missing'));
  const commandId = `agent-cmd-${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;
  const now = Date.now();
  const row = {
    id: commandId,
    command,
    createdAt: now,
    leaseUntil: 0,
    attempts: 0,
    lastIssuedAt: 0
  };
  const queue = ensureCollectorAgentQueue(state, siteId);
  queue.push(row);
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      rejectCollectorCommandWaiter(state, commandId, 'Timed out waiting for collector agent response');
    }, COLLECTOR_AGENT_COMMAND_TIMEOUT_MS);
    state.agentPending.set(commandId, {
      siteId,
      command,
      createdAt: now,
      timeout,
      resolve,
      reject
    });
  });
}

// ── Collector agent session ───────────────────────────────────────────────────
function touchCollectorAgentSession(state, session, now = Date.now()) {
  if (!session || !session.token) return;
  session.lastSeenAt = now;
  session.expiresAt = now + COLLECTOR_AGENT_SESSION_TTL_MS;
  state.agentSessions.set(session.token, session);
  setCollectorAgentPresence(state, session, now);
}

function revokeCollectorAgentSiteSessions(state, siteId) {
  const key = String(siteId || '').trim();
  if (!key) return;
  for (const [token, session] of state.agentSessions.entries()) {
    if (String(session?.siteId || '').trim() === key) {
      state.agentSessions.delete(token);
    }
  }
  state.agentBySite.delete(key);
}

function clearCollectorAgentSiteRuntime(state, siteId, reason = 'Collector agent state cleared') {
  const key = String(siteId || '').trim();
  if (!key) return;
  revokeCollectorAgentSiteSessions(state, key);
  state.agentCommandQueue.delete(key);
  for (const [commandId, pending] of state.agentPending.entries()) {
    if (String(pending?.siteId || '').trim() !== key) continue;
    rejectCollectorCommandWaiter(state, commandId, reason);
  }
}

function issueCollectorAgentSession(state, site, payload = {}, remoteIp = '') {
  const siteId = String(site?.id || '').trim();
  if (!siteId) return null;
  revokeCollectorAgentSiteSessions(state, siteId);
  const now = Date.now();
  const token = crypto.randomBytes(24).toString('hex');
  const session = {
    token,
    sessionId: crypto.randomBytes(8).toString('hex'),
    siteId,
    createdAt: now,
    lastSeenAt: now,
    expiresAt: now + COLLECTOR_AGENT_SESSION_TTL_MS,
    hostname: String(payload?.hostname || payload?.host || '').trim(),
    localIp: String(payload?.localIp || payload?.ip || '').trim(),
    platform: String(payload?.platform || payload?.os || '').trim(),
    version: String(payload?.version || '').trim(),
    remoteIp: String(remoteIp || '').trim()
  };
  state.agentSessions.set(token, session);
  setCollectorAgentPresence(state, session, now);
  return session;
}

function getCollectorAgentSession(state, token, now = Date.now()) {
  const { notifyCollectorAgentState } = require('./notifications');
  const key = String(token || '').trim();
  if (!key) return null;
  const session = state.agentSessions.get(key);
  if (!session) return null;
  const expiresAt = Number(session.expiresAt || 0);
  if (!expiresAt || expiresAt <= now) {
    state.agentSessions.delete(key);
    if (session.siteId) {
      const siteId = String(session.siteId);
      const site = collectorSiteById(state, siteId);
      const agent = state.agentBySite.get(siteId) || session;
      notifyCollectorAgentState(
        state,
        site,
        'collector_agent_offline',
        'up',
        'down',
        'collector_agent_session_expired',
        'Collector agent poll session expired.',
        agent
      );
      state.agentBySite.delete(siteId);
    }
    return null;
  }
  return session;
}

function toolsTerminalRecentAgeLabel(state, site, protocol) {
  const ts = Number(state?.lastSeen?.[protocol]?.get(site.id) || 0);
  if (!ts) return 'never';
  return `${Math.max(0, Math.floor((Date.now() - ts) / 1000))}s ago`;
}

function toolsTerminalDiagnosticsLines(result = {}, protocol = '') {
  const summary = result?.summary?.message || 'n/a';
  const checks = Array.isArray(result?.checks) ? result.checks : [];
  const lines = [`${String(protocol || '').toUpperCase()} diagnostics: ${summary}`];
  checks.slice(0, 80).forEach((check) => {
    const status = String(check?.status || 'fail').toUpperCase();
    const id = String(check?.id || 'check');
    const detail = String(check?.detail || '');
    lines.push(`[${status}] ${id}${detail ? ` :: ${detail}` : ''}`);
  });
  return normalizeToolsTerminalLines(lines);
}

function toolsTerminalStatusLines(state, site, collectorMode = false) {
  const { collectorAgentPasswordConfigured } = require('./auth');
  if (collectorMode) {
    const collector = site?.collector || {};
    const presence = getCollectorAgentPresence(state, site?.id);
    const host = String(presence?.hostname || collector.terminalHost || collector.ip || site?.internalIp || 'unknown').trim() || 'unknown';
    const agentConnected = Boolean(presence?.connected);
    const agentLastSeen = presence?.lastSeenAt ? new Date(presence.lastSeenAt).toISOString() : 'never';
    const pingTs = Number(state?.lastSeen?.ping?.get(site.id) || state?.lastSeen?.pingSecondary?.get(site.id) || 0);
    const lastHeartbeat = pingTs ? new Date(pingTs).toISOString() : 'never';
    const heartbeatAge = pingTs ? `${Math.max(0, Math.floor((Date.now() - pingTs) / 1000))}s ago` : 'never';
    const tests = Array.isArray(site?.metrics?.wanTests) ? site.metrics.wanTests : [];
    const latest = tests[0] || null;
    return normalizeToolsTerminalLines([
      `Site: ${site?.name || site?.id || 'unknown'} (${locationNameForSite(site)})`,
      `Role: collector (agent read-only command mode)`,
      `Agent: ${agentConnected ? 'connected' : 'disconnected'}`,
      `Agent auth password: ${collectorAgentPasswordConfigured(site) ? 'set' : 'not set'}`,
      `Host: ${host}`,
      `Agent last seen: ${agentLastSeen}`,
      `Last heartbeat: ${lastHeartbeat} (${heartbeatAge})`,
      latest
        ? `Last WAN test: ts=${latest.timestamp || 'n/a'} down=${latest.downloadMbps ?? 'n/a'} Mbps up=${latest.uploadMbps ?? 'n/a'} Mbps latency=${latest.latencyMs ?? 'n/a'} ms`
        : 'Last WAN test: none'
    ]);
  }
  const runtimeSettings = shared.runtimeSettings;
  const snmpCfg = site?.monitorConfig?.snmp || {};
  const syslogCfg = site?.monitorConfig?.syslog || {};
  const netflowCfg = site?.monitorConfig?.netflow || {};
  const snmpMetrics = site?.metrics?.snmp || {};
  const syslogMetrics = site?.metrics?.syslog || {};
  const netflowMetrics = site?.metrics?.netflow || {};
  const topTalkers = Array.isArray(netflowMetrics.topTalkers) ? netflowMetrics.topTalkers : [];
  const top = topTalkers[0];
  return normalizeToolsTerminalLines([
    `Site: ${site?.name || site?.id || 'unknown'} (${locationNameForSite(site)})`,
    `SNMP: enabled=${Boolean(snmpCfg.enabled)} target=${snmpCfg.targetHost || 'n/a'} flowing=${Boolean(site?.telemetry?.snmp)} last=${toolsTerminalRecentAgeLabel(state, site, 'snmp')}`,
    `SNMP uptime=${snmpMetrics.uptime || 'Unknown'} errors=${snmpMetrics.lastError || 'none'}`,
    `SYSLOG: enabled=${Boolean(syslogCfg.enabled)} source=${syslogCfg.sourceIp || 'n/a'} transport=${String(syslogCfg.protocol || 'udp').toUpperCase()} port=${String(syslogCfg.port || runtimeSettings.syslogUdpPort || SYSLOG_UDP_PORT)} flowing=${Boolean(site?.telemetry?.syslog)} last=${toolsTerminalRecentAgeLabel(state, site, 'syslog')}`,
    `SYSLOG eps=${Number(syslogMetrics.eventsPerSecond || 0)} total=${Number(syslogMetrics.totalIngested || 0)} error=${syslogMetrics.lastError || 'none'}`,
    `NETFLOW: enabled=${Boolean(netflowCfg.enabled)} source=${netflowCfg.sourceIp || 'n/a'} collector=${netflowCfg.collectorIp || 'n/a'}:${String(netflowCfg.collectorPort || runtimeSettings.netflowPort || NETFLOW_PORT)} flowing=${Boolean(site?.telemetry?.netflow)} last=${toolsTerminalRecentAgeLabel(state, site, 'netflow')}`,
    top ? `NETFLOW top=${top.ip || 'unknown'} down=${formatToolsTerminalMbps(top.downMbps)} up=${formatToolsTerminalMbps(top.upMbps)}` : 'NETFLOW top=n/a'
  ]);
}

function toolsTerminalHelpLines(state, site, collectorMode = false) {
  const runtimeSettings = shared.runtimeSettings;
  if (collectorMode) {
    const defaultHost = toolsTerminalDefaultHost(site) || '<host>';
    return normalizeToolsTerminalLines([
      'Cajal Collector Agent Terminal',
      'Allowed commands:',
      'help',
      'status',
      'doctor | deps | capabilities',
      'update [downloadUrl] [targetVersion]',
      'publicip | public-ip | wanip',
      'speedtest [target]',
      'ping [host]',
      'traceroute [host] | tracert [host]',
      'dns [hostname] | resolve [hostname] | nslookup [hostname]',
      'ipconfig [interface]',
      'clear | cls',
      '',
      'Notes:',
      'read-only mode: command execution only, no shell access',
      'suffix "?" to list matching commands (example: trac?)',
      'press Tab for auto-complete',
      '',
      'Quick checks:',
      '1) doctor',
      `2) ping ${defaultHost}`,
      '3) speedtest 8.8.8.8',
      '4) nslookup cloudflare.com',
      '5) update https://<cajal-host>/api/agent/linux/download?format=deb 1.0.0'
    ]);
  }
  const snmpHost = sanitizeToolsTerminalHostToken(site?.monitorConfig?.snmp?.targetHost || '');
  const defaultHost = toolsTerminalDefaultHost(site) || '<host>';
  const syslogPort = Number(runtimeSettings?.syslogUdpPort || SYSLOG_UDP_PORT);
  const netflowPort = Number(runtimeSettings?.netflowPort || NETFLOW_PORT);
  return normalizeToolsTerminalLines([
    'Cajal Tools Terminal',
    'Command reference:',
    'help',
    'status',
    'snmp poll | snmp test',
    'snmp diag | snmp diagnostics',
    'syslog diag | syslog diagnostics',
    'netflow top | netflow talkers',
    'netflow diag | netflow diagnostics',
    'listeners',
    'ping [host]',
    'traceroute [host]',
    'dns [hostname]',
    'clear | cls',
    '',
    'Command switches:',
    'suffix "?" to list matching commands (example: snmp ?)',
    'press Tab for auto-complete',
    '',
    'Recommended troubleshooting sequence:',
    '1) status',
    `2) ping ${snmpHost || defaultHost}`,
    '3) snmp poll',
    '4) syslog diag',
    '5) netflow diag',
    '6) netflow top',
    `7) listeners   # verify local ${syslogPort}/UDP+TCP and ${netflowPort}/UDP listeners`
  ]);
}

async function runToolsTerminalExecCandidates(candidates = [], timeoutMs = TOOLS_TERMINAL_TIMEOUT_MS) {
  let lastResult = null;
  for (const row of candidates) {
    const cmd = String(row?.cmd || '').trim();
    if (!cmd) continue;
    const args = Array.isArray(row?.args) ? row.args.map((v) => String(v)) : [];
    const result = await runExecFile(cmd, args, timeoutMs);
    const merged = { ...result, cmd, args };
    if (!result.err) return merged;
    lastResult = merged;
    if (String(result.err?.code || '').toUpperCase() !== 'ENOENT') return merged;
  }
  return lastResult || {
    err: new Error('No executable candidates configured'),
    stdout: '',
    stderr: '',
    cmd: '',
    args: []
  };
}

function toolsTerminalLinesFromExec(result, fallbackLabel = '') {
  const cmdLabel = result?.cmd ? `${result.cmd}${Array.isArray(result.args) && result.args.length ? ` ${result.args.join(' ')}` : ''}` : fallbackLabel;
  const stdoutLines = splitNonEmptyLines(result?.stdout || '');
  const stderrLines = splitNonEmptyLines(result?.stderr || '');
  const lines = [];
  if (cmdLabel) lines.push(`$ ${cmdLabel}`);
  if (!stdoutLines.length && !stderrLines.length && !result?.err) {
    lines.push('(no output)');
  }
  lines.push(...stdoutLines.slice(0, 120));
  if (stderrLines.length) {
    lines.push(...stderrLines.slice(0, 120).map((line) => `stderr: ${line}`));
  }
  if (result?.err) {
    lines.push(`error: ${String(result.err?.message || 'command failed')}`);
  }
  return normalizeToolsTerminalLines(lines);
}

async function runCollectorAgentTerminalCommand(state, site, commandText = '') {
  const result = await queueCollectorAgentCommand(state, site, commandText);
  return result || { ok: false, exitCode: 1, lines: ['No response from collector agent'] };
}

async function runToolsTerminalCommand(state, site, commandText = '') {
  const { runMonitorDiagnostics } = require('./health');
  const { runSnmpGet, formatSysUpTimeTicks, mergeConfig } = require('./monitoring');
  const runtimeSettings = shared.runtimeSettings;
  const raw = String(commandText || '').trim();
  if (!raw) {
    return { ok: false, exitCode: 1, lines: ['No command entered. Type "help".'] };
  }
  const tokens = parseToolsTerminalTokens(raw);
  const command = String(tokens[0] || '').toLowerCase();
  const sub = String(tokens[1] || '').toLowerCase();
  const args = tokens.slice(1);
  const snmpCfg = mergeConfig(site?.monitorConfig?.snmp || {}, {});
  const syslogCfg = mergeConfig(site?.monitorConfig?.syslog || {}, {});
  const netflowCfg = mergeConfig(site?.monitorConfig?.netflow || {}, {});

  if (command === 'help' || command === '?') {
    return { ok: true, exitCode: 0, lines: toolsTerminalHelpLines(state, site, false) };
  }

  if (command === 'status') {
    return { ok: true, exitCode: 0, lines: toolsTerminalStatusLines(state, site, false) };
  }

  if (command === 'clear' || command === 'cls') {
    return { ok: true, exitCode: 0, lines: ['Terminal cleared.'] };
  }

  if (command === 'speedtest') {
    return {
      ok: false,
      exitCode: 1,
      lines: normalizeToolsTerminalLines([
        'Server-side speedtest is disabled.',
        'Use the Collector Terminal (agent mode): speedtest [target]'
      ])
    };
  }

  if (command === 'snmp') {
    if (!sub || sub === 'poll' || sub === 'test') {
      if (!String(snmpCfg.targetHost || '').trim()) {
        return { ok: false, exitCode: 1, lines: ['SNMP targetHost missing in monitor config.'] };
      }
      try {
        const startedAt = Date.now();
        const ticks = await runSnmpGet(snmpCfg);
        const durationMs = Date.now() - startedAt;
        return {
          ok: true,
          exitCode: 0,
          lines: normalizeToolsTerminalLines([
            `SNMP poll ok for ${site.name}`,
            `target=${snmpCfg.targetHost} version=${snmpCfg.version || '2c'} uptime=${formatSysUpTimeTicks(ticks)} durationMs=${durationMs}`
          ])
        };
      } catch (err) {
        return { ok: false, exitCode: 1, lines: [`SNMP poll failed: ${String(err?.message || err || 'Unknown error')}`] };
      }
    }
    if (sub === 'diag' || sub === 'diagnostics') {
      const diagnostics = await runMonitorDiagnostics(state, site, 'snmp', snmpCfg, { runLiveProbe: true });
      return { ok: Boolean(diagnostics?.ok), exitCode: diagnostics?.ok ? 0 : 1, lines: toolsTerminalDiagnosticsLines(diagnostics, 'snmp') };
    }
    return { ok: false, exitCode: 1, lines: ['Unknown SNMP command. Try: snmp poll | snmp diag'] };
  }

  if (command === 'syslog') {
    if (sub === 'diag' || sub === 'diagnostics' || !sub) {
      const diagnostics = await runMonitorDiagnostics(state, site, 'syslog', syslogCfg, { runLiveProbe: false });
      return { ok: Boolean(diagnostics?.ok), exitCode: diagnostics?.ok ? 0 : 1, lines: toolsTerminalDiagnosticsLines(diagnostics, 'syslog') };
    }
    return { ok: false, exitCode: 1, lines: ['Unknown SYSLOG command. Try: syslog diag'] };
  }

  if (command === 'netflow') {
    if (sub === 'diag' || sub === 'diagnostics') {
      const diagnostics = await runMonitorDiagnostics(state, site, 'netflow', netflowCfg, { runLiveProbe: false });
      return { ok: Boolean(diagnostics?.ok), exitCode: diagnostics?.ok ? 0 : 1, lines: toolsTerminalDiagnosticsLines(diagnostics, 'netflow') };
    }
    if (!sub || sub === 'top' || sub === 'talkers') {
      const rows = Array.isArray(site?.metrics?.netflow?.topTalkers) ? site.metrics.netflow.topTalkers : [];
      if (!rows.length) {
        return { ok: false, exitCode: 1, lines: ['No NetFlow top talkers available yet.'] };
      }
      const lines = rows.map((row, idx) => `${idx + 1}. ${row.ip || 'unknown'} | down ${formatToolsTerminalMbps(row.downMbps)} | up ${formatToolsTerminalMbps(row.upMbps)}`);
      return { ok: true, exitCode: 0, lines: normalizeToolsTerminalLines(lines) };
    }
    return { ok: false, exitCode: 1, lines: ['Unknown NETFLOW command. Try: netflow top | netflow diag'] };
  }

  if (command === 'listeners') {
    const syslogUdpPort = Number(runtimeSettings?.syslogUdpPort || SYSLOG_UDP_PORT);
    const syslogTcpPort = Number(runtimeSettings?.syslogTcpPort || SYSLOG_TCP_PORT);
    const netflowPort = Number(runtimeSettings?.netflowPort || NETFLOW_PORT);
    const ssUdp = await runExecFile('ss', ['-lunp'], 8000);
    const ssTcp = await runExecFile('ss', ['-ltnp'], 8000);
    const ufw = await runExecFile('ufw', ['status', 'verbose'], 8000);
    const lines = [];
    if (ssUdp.err) {
      lines.push(`ss -lunp failed: ${ssUdp.err.message}`);
    } else {
      const udpRows = splitNonEmptyLines(ssUdp.stdout).filter((row) => row.includes(`:${syslogUdpPort}`) || row.includes(`:${netflowPort}`));
      lines.push(`UDP listeners (${syslogUdpPort}, ${netflowPort}):`);
      lines.push(...(udpRows.length ? udpRows : ['none found']));
    }
    if (ssTcp.err) {
      lines.push(`ss -ltnp failed: ${ssTcp.err.message}`);
    } else {
      const tcpRows = splitNonEmptyLines(ssTcp.stdout).filter((row) => row.includes(`:${syslogTcpPort}`));
      lines.push(`TCP listeners (${syslogTcpPort}):`);
      lines.push(...(tcpRows.length ? tcpRows : ['none found']));
    }
    if (!ufw.err) {
      lines.push(...splitNonEmptyLines(ufw.stdout).slice(0, 12).map((row) => `ufw: ${row}`));
    }
    return { ok: !ssUdp.err && !ssTcp.err, exitCode: ssUdp.err || ssTcp.err ? 1 : 0, lines: normalizeToolsTerminalLines(lines) };
  }

  if (command === 'ping') {
    const host = sanitizeToolsTerminalHostToken(args[0] || toolsTerminalDefaultHost(site));
    if (!host) return { ok: false, exitCode: 1, lines: ['Usage: ping [host]'] };
    const result = await runToolsTerminalExecCandidates([{ cmd: 'ping', args: ['-c', '3', '-W', '1', host] }], TOOLS_TERMINAL_TIMEOUT_MS);
    return { ok: !result.err, exitCode: result.err ? 1 : 0, lines: toolsTerminalLinesFromExec(result, `ping ${host}`) };
  }

  if (command === 'traceroute' || command === 'trace' || command === 'tracert') {
    const host = sanitizeToolsTerminalHostToken(args[0] || toolsTerminalDefaultHost(site));
    if (!host) return { ok: false, exitCode: 1, lines: ['Usage: traceroute [host]'] };
    const result = await runToolsTerminalExecCandidates([
      { cmd: 'traceroute', args: ['-n', '-m', '8', '-w', '1', host] },
      { cmd: 'tracepath', args: ['-n', '-m', '8', host] }
    ], TOOLS_TERMINAL_TIMEOUT_MS);
    return { ok: !result.err, exitCode: result.err ? 1 : 0, lines: toolsTerminalLinesFromExec(result, `traceroute ${host}`) };
  }

  if (command === 'dns' || command === 'resolve' || command === 'nslookup') {
    const hostToken = command === 'dns' && String(args[0] || '').toLowerCase() === 'resolve'
      ? args[1]
      : args[0];
    const host = sanitizeToolsTerminalHostToken(hostToken || toolsTerminalDefaultHost(site));
    if (!host) return { ok: false, exitCode: 1, lines: ['Usage: dns [hostname]'] };
    const result = await runToolsTerminalExecCandidates([
      { cmd: 'nslookup', args: [host] },
      { cmd: 'getent', args: ['hosts', host] },
      { cmd: 'dig', args: ['+short', host] }
    ], TOOLS_TERMINAL_TIMEOUT_MS);
    return { ok: !result.err, exitCode: result.err ? 1 : 0, lines: toolsTerminalLinesFromExec(result, `dns ${host}`) };
  }

  return { ok: false, exitCode: 1, lines: ['Unknown command. Type "help" for supported commands.'] };
}

async function runCollectorTerminalCommand(state, site, commandText = '') {
  const raw = String(commandText || '').trim();
  if (!raw) {
    return { ok: false, exitCode: 1, lines: ['No command entered. Type "help".'] };
  }
  const tokens = parseToolsTerminalTokens(raw);
  const command = String(tokens[0] || '').toLowerCase();

  if (command === 'help' || command === '?') {
    return { ok: true, exitCode: 0, lines: toolsTerminalHelpLines(state, site, true) };
  }

  if (command === 'status') {
    return { ok: true, exitCode: 0, lines: toolsTerminalStatusLines(state, site, true) };
  }

  if (command === 'clear' || command === 'cls') {
    return { ok: true, exitCode: 0, lines: ['Terminal cleared.'] };
  }

  const collectorAllowedCommands = new Set([
    'doctor',
    'deps',
    'capabilities',
    'update',
    'publicip',
    'public-ip',
    'wanip',
    'speedtest',
    'ping',
    'traceroute',
    'tracert',
    'dns',
    'resolve',
    'nslookup',
    'ipconfig'
  ]);
  if (!collectorAllowedCommands.has(command)) {
    return {
      ok: false,
      exitCode: 1,
      lines: ['Collector terminal allows only: doctor/deps/capabilities, update, publicip/public-ip/wanip, speedtest, ping, traceroute/tracert, dns/resolve/nslookup, ipconfig, status, help, clear.']
    };
  }

  return runCollectorAgentTerminalCommand(state, site, raw);
}

function factoryResetBaselineUsers() {
  return [
    normalizeUserEntry({ email: 'admin', displayName: 'Local Admin', role: 'admin' }, {})
  ];
}

async function performFactoryResetForDeployment(state, options = {}) {
  const {
    persistSsoConfig,
    persistRuntimeSettings,
    persistSslSettings,
    persistLocationSettings,
    persistBackupMeta,
    persistApiTokenSettings,
    persistWindowsAgentPackageSettings,
    defaultSsoConfig: defSso,
  } = require('./settings');
  const {
    defaultApiTokenSettings: defApiTokens,
    defaultWindowsAgentPackageSettings: defWindowsPackage,
  } = require('./constants');
  const { persistSites, persistUsers } = require('./sites');
  const { buildUserRoleDirectory, saveApiTokenSettingsToState } = require('./auth');
  const { buildApiTokenHashIndex } = require('./tokens');
  const { setConfigIntegrityState } = require('./storage');
  const { clearDiagnosticLogEntries, clearTelemetryLogEntries } = require('./logging');
  const { persistEvents } = require('./events');
  const { initialPublicServiceState, initialLocationPingMonitorState } = require('./monitoring');
  const {
    DEVICES_FILE,
    ERROR_LOG_FILE,
    defaultRuntimeSettings,
    defaultSslSettings,
    defaultLocationSettings,
    defaultBackupMeta,
  } = require('./constants');
  const { smartWriteFile } = require('./storage');

  const actor = String(options?.actor || 'system').trim() || 'system';
  const resetAt = new Date().toISOString();

  const nextSites = [];
  const nextDevices = [];
  const nextUsers = factoryResetBaselineUsers();
  const nextSso = { ...defSso };
  const nextRuntime = { ...defaultRuntimeSettings };
  const nextSsl = { ...defaultSslSettings };
  const nextLocation = { ...defaultLocationSettings };
  const nextBackupMeta = { ...defaultBackupMeta };
  const nextApiTokens = { ...defApiTokens };
  const nextWindowsPackage = { ...defWindowsPackage };

  shared.configIntegrityState = shared.defaultConfigIntegrityState();

  const { rateLimitBuckets, loginAccountFailures } = require('./ratelimit');
  shared.sessions.clear();
  shared.oauthState.clear();
  shared.localSetupState.clear();
  rateLimitBuckets.clear();
  loginAccountFailures.clear();

  shared.ssoRuntimeConfig = nextSso;
  shared.runtimeSettings = nextRuntime;
  shared.sslRuntimeConfig = nextSsl;
  shared.locationSettings = nextLocation;
  shared.backupMeta = nextBackupMeta;

  state.sites = nextSites;
  state.devices = nextDevices;
  state.users = nextUsers;
  state.links = [];
  state.alerts = [];
  state.events = [];
  state.backupMeta = nextBackupMeta;
  state.apiTokens = [];
  state.apiTokenByHash = buildApiTokenHashIndex(nextApiTokens.tokens);
  state.apiTokensDirty = false;
  state.dirtySites = false;
  state.dirtyEvents = false;
  state.syslogWindows = new Map();
  state.netflowTalkers = new Map();
  state.netflowTemplates = new Map();
  state.flowState = new Map();
  state.pingState = new Map();
  state.wanPingState = new Map();
  state.alertSilenceUntilMs = 0;
  state.eventThrottle = new Map();
  state.diagnosticThrottle = new Map();
  state.agentSessions = new Map();
  state.agentBySite = new Map();
  state.agentCommandQueue = new Map();
  state.agentPending = new Map();
  state.publicServices = initialPublicServiceState();
  state.locationPingMonitors = initialLocationPingMonitorState(shared.locationSettings);
  state.notificationState = {
    systemDependencySignal: '',
    collectorWanPublicIp: {}
  };
  state.startupBootstrapSeededKeys = [];
  state.lastSeen = {
    ping: new Map(),
    pingSecondary: new Map(),
    syslog: new Map(),
    snmp: new Map(),
    netflow: new Map()
  };

  shared.userRoleDirectory = buildUserRoleDirectory(nextUsers);

  await Promise.all([
    persistSites(nextSites),
    smartWriteFile(DEVICES_FILE, JSON.stringify(nextDevices, null, 2), 'utf8'),
    persistUsers(nextUsers),
    persistSsoConfig(nextSso),
    persistRuntimeSettings(nextRuntime),
    persistApiTokenSettings(nextApiTokens),
    persistWindowsAgentPackageSettings(nextWindowsPackage),
    persistSslSettings(nextSsl),
    persistLocationSettings(nextLocation),
    persistBackupMeta(nextBackupMeta),
    persistEvents([]),
    smartWriteFile(ERROR_LOG_FILE, '', 'utf8'),
    clearDiagnosticLogEntries(),
    clearTelemetryLogEntries()
  ]);

  setConfigIntegrityState('bootstrap', 'ok', 'Factory reset baseline active');
  console.warn(`Factory reset baseline applied by ${actor} at ${resetAt}`);

  return {
    resetAt,
    actor,
    mode: 'deployment',
    users: nextUsers.map((user) => user.email),
    sites: nextSites.length,
    devices: nextDevices.length,
    events: 0
  };
}

module.exports = {
  runExecFile,
  runExecFileWithOptions,
  buildLinuxAgentDebPackage,
  splitNonEmptyLines,
  normalizeToolsTerminalLines,
  parseToolsTerminalTokens,
  sanitizeToolsTerminalHostToken,
  formatToolsTerminalMbps,
  toolsTerminalDefaultHost,
  getCollectorAgentPresence,
  setCollectorAgentPresence,
  collectorSiteById,
  pruneCollectorAgentSessions,
  ensureCollectorAgentQueue,
  removeCollectorAgentQueuedCommand,
  dequeueCollectorAgentCommandForPoll,
  shellQuoteArg,
  collectorResultHasUnsupportedCommand,
  collectorManualUpdateLines,
  resolveCollectorCommandWaiter,
  rejectCollectorCommandWaiter,
  queueCollectorAgentCommand,
  touchCollectorAgentSession,
  revokeCollectorAgentSiteSessions,
  clearCollectorAgentSiteRuntime,
  issueCollectorAgentSession,
  getCollectorAgentSession,
  toolsTerminalRecentAgeLabel,
  toolsTerminalDiagnosticsLines,
  toolsTerminalStatusLines,
  toolsTerminalHelpLines,
  runToolsTerminalExecCandidates,
  toolsTerminalLinesFromExec,
  runCollectorAgentTerminalCommand,
  runToolsTerminalCommand,
  runCollectorTerminalCommand,
  factoryResetBaselineUsers,
  performFactoryResetForDeployment,

  __test: {
    getCollectorAgentPresence,
    collectorResultHasUnsupportedCommand,
  },
};
