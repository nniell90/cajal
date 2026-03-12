'use strict';
const os = require('os');
const {
  SYSLOG_UDP_PORT,
  SYSLOG_TCP_PORT,
  NETFLOW_PORT,
  EVENT_RETENTION,
  ERROR_LOG_MAX_BYTES,
  ERROR_LOG_MAX_LINES,
  DIAGNOSTIC_LOG_MAX_BYTES,
  DIAGNOSTIC_LOG_MAX_LINES,
  TELEMETRY_LOG_MAX_BYTES,
  TELEMETRY_LOG_MAX_LINES,
  DATA_RETENTION_MS,
  DATA_RETENTION_DAYS,
  ERROR_LOG_FILE,
  DIAGNOSTIC_LOG_FILE,
  TELEMETRY_LOG_FILE,
  STORAGE_TRACKED_FILES,
  FLOW_TIMEOUT_MS,
  SNMP_POLL_INTERVAL_MS,
  SNMP_TRAP_PORT,
  PORT,
  APP_VERSION,
  STARTED_AT_MS,
} = require('./constants');
const { smartReadFile, smartWriteFile, smartStat, getPoolStats, getConfigIntegrityReport } = require('./storage');
const { clearDiagnosticLogEntries, clearTelemetryLogEntries, logDiagnostic } = require('./logging');
const { parseIsoTimestampMs, pruneEventsByPolicy, sameEventList, persistEvents } = require('./events');
const { runExecFile, splitNonEmptyLines } = require('./agent');
const shared = require('./shared');

// ── Firewall check helpers ────────────────────────────────────────────────────
function parsePortNumber(value, fallback = 0) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  const port = Math.floor(n);
  if (port < 1 || port > 65535) return fallback;
  return port;
}

function parseUfwActive(statusVerbose = '') {
  const raw = String(statusVerbose || '').toLowerCase();
  if (!raw.includes('status:')) return null;
  if (raw.includes('status: active')) return true;
  if (raw.includes('status: inactive')) return false;
  return null;
}

function ssHasListener(rawLines = [], port = 0) {
  const needle = `:${Number(port)}`;
  return rawLines.some((line) => line.includes(needle));
}

function inferAppListenerOpen(requirement = {}) {
  const protocol = String(requirement?.protocol || '').trim().toLowerCase();
  const transport = String(requirement?.transport || '').trim().toLowerCase();
  const port = Number(requirement?.port || 0);
  if (!Number.isFinite(port) || port <= 0) return false;
  if (protocol === 'netflow') return transport === 'udp' && port === Number(NETFLOW_PORT);
  if (protocol === 'syslog') {
    if (transport === 'udp') return port === Number(SYSLOG_UDP_PORT);
    if (transport === 'tcp') return port === Number(SYSLOG_TCP_PORT);
  }
  return false;
}

function ufwAllowsSource(lines = [], transport = 'udp', port = 0, sourceIp = '') {
  const proto = String(transport || 'udp').toLowerCase();
  const src = String(sourceIp || '').trim().toLowerCase();
  const target = `${Number(port)}/${proto}`;
  for (const line of lines) {
    const row = String(line || '').toLowerCase();
    if (!row.includes('allow')) continue;
    if (!row.includes(target)) continue;
    if (!src) return true;
    if (row.includes(src)) return true;
    if (row.includes('anywhere')) return true;
    if (row.includes('any')) return true;
  }
  return false;
}

function summarizeChecks(checks = []) {
  const out = { pass: 0, warn: 0, fail: 0, unknown: 0 };
  for (const check of checks) {
    const status = String(check?.status || '').toLowerCase();
    if (status === 'pass') out.pass += 1;
    else if (status === 'warn') out.warn += 1;
    else if (status === 'unknown') out.unknown += 1;
    else out.fail += 1;
  }
  return out;
}

function evaluateFirewallUfwRuleStatus({
  status = 'pass',
  notes = [],
  ufwAvailable = false,
  ufwAccessDenied = false,
  ufwActive = null,
  ufwAllowed = null,
  sourceIp = '',
  transport = 'udp',
  port = 0
} = {}) {
  const nextNotes = Array.isArray(notes) ? notes.slice() : [];
  let nextStatus = String(status || '').toLowerCase() || 'pass';
  if (nextStatus !== 'pass' && nextStatus !== 'warn' && nextStatus !== 'fail' && nextStatus !== 'unknown') nextStatus = 'fail';

  if (!ufwAvailable) {
    nextNotes.push('UFW command unavailable (rule validation skipped)');
    return { status: nextStatus, notes: nextNotes };
  }

  if (ufwAccessDenied) {
    if (nextStatus !== 'fail') nextStatus = 'unknown';
    nextNotes.push('UFW access denied (rule validation skipped)');
    return { status: nextStatus, notes: nextNotes };
  }

  if (ufwActive === false) {
    nextNotes.push('UFW inactive (rule validation skipped)');
    return { status: nextStatus, notes: nextNotes };
  }

  if (ufwActive === true) {
    if (ufwAllowed) {
      nextNotes.push(`UFW allows ${sourceIp || 'source'} -> ${Number(port)}/${String(transport || 'udp')}`);
      return { status: nextStatus, notes: nextNotes };
    }
    nextNotes.push(`Missing UFW allow rule for ${sourceIp || 'source'} -> ${Number(port)}/${String(transport || 'udp')}`);
    return { status: 'fail', notes: nextNotes };
  }

  if (nextStatus !== 'fail') nextStatus = 'unknown';
  nextNotes.push('Unable to determine UFW status');
  return { status: nextStatus, notes: nextNotes };
}

async function buildFirewallCheck(state) {
  const [ufwVerbose, ufwNumbered, ssUdp, ssTcp] = await Promise.all([
    runExecFile('ufw', ['status', 'verbose'], 8000),
    runExecFile('ufw', ['status', 'numbered'], 8000),
    runExecFile('ss', ['-lunp'], 8000),
    runExecFile('ss', ['-ltnp'], 8000)
  ]);

  const ufwAvailable = !(ufwVerbose?.err && ufwVerbose.err.code === 'ENOENT');
  const ssAvailable = !(
    (ssUdp?.err && ssUdp.err.code === 'ENOENT') ||
    (ssTcp?.err && ssTcp.err.code === 'ENOENT')
  );
  const ufwStatusText = String(ufwVerbose?.stdout || ufwVerbose?.stderr || '').trim();
  const ufwRuleText = String(ufwNumbered?.stdout || ufwNumbered?.stderr || '').trim();
  const ufwAccessDenied = (() => {
    if (!ufwAvailable) return false;
    const combined = `${ufwStatusText}\n${ufwRuleText}`.toLowerCase();
    return (
      combined.includes('you need to be root') ||
      combined.includes('permission denied') ||
      combined.includes('operation not permitted')
    );
  })();
  const ufwActive = ufwAvailable && !ufwAccessDenied ? parseUfwActive(ufwStatusText) : null;
  const ufwRules = ufwAccessDenied ? [] : splitNonEmptyLines(ufwRuleText);
  const udpLines = splitNonEmptyLines(ssUdp?.stdout || '');
  const tcpLines = splitNonEmptyLines(ssTcp?.stdout || '');

  const requirements = [];
  for (const site of state.sites) {
    const syslogCfg = site.monitorConfig?.syslog || {};
    if (syslogCfg.enabled) {
      const transport = String(syslogCfg.protocol || 'udp').toLowerCase() === 'tcp' ? 'tcp' : 'udp';
      const fallbackPort = transport === 'tcp' ? SYSLOG_TCP_PORT : SYSLOG_UDP_PORT;
      requirements.push({
        siteId: site.id,
        siteName: site.name,
        protocol: 'syslog',
        transport,
        sourceIp: String(syslogCfg.sourceIp || '').trim(),
        port: parsePortNumber(syslogCfg.port, fallbackPort)
      });
    }
    const netflowCfg = site.monitorConfig?.netflow || {};
    if (netflowCfg.enabled) {
      requirements.push({
        siteId: site.id,
        siteName: site.name,
        protocol: 'netflow',
        transport: 'udp',
        sourceIp: String(netflowCfg.sourceIp || '').trim(),
        port: parsePortNumber(netflowCfg.collectorPort, NETFLOW_PORT)
      });
    }
    // SNMP polling is outbound from the server and does not require a local listener.
  }

  const checks = requirements.map((req) => {
    const listeners = req.transport === 'tcp' ? tcpLines : udpLines;
    const listenerOpen = ssAvailable ? ssHasListener(listeners, req.port) : inferAppListenerOpen(req);
    const ufwAllowed = ufwAvailable && !ufwAccessDenied && ufwActive === true
      ? ufwAllowsSource(ufwRules, req.transport, req.port, req.sourceIp)
      : null;
    let status = 'pass';
    const notes = [];
    if (!ssAvailable) {
      if (listenerOpen) {
        notes.push(`ss command unavailable (inferred listener on ${req.port}/${req.transport})`);
      } else {
        if (status !== 'fail') status = 'warn';
        notes.push('ss command unavailable');
      }
    } else if (!listenerOpen) {
      status = 'fail';
      notes.push(`No local ${req.transport.toUpperCase()} listener on ${req.port}`);
    } else {
      notes.push(`Listener open on ${req.port}/${req.transport}`);
    }
    const ufwOutcome = evaluateFirewallUfwRuleStatus({
      status,
      notes,
      ufwAvailable,
      ufwAccessDenied,
      ufwActive,
      ufwAllowed,
      sourceIp: req.sourceIp,
      transport: req.transport,
      port: req.port
    });
    status = ufwOutcome.status;
    notes.length = 0;
    notes.push(...ufwOutcome.notes);
    return {
      ...req,
      listenerOpen,
      ufwAllowed,
      status,
      detail: notes.join(' | ')
    };
  });

  const summary = summarizeChecks(checks);
  const suggestions = [
    `sudo ufw allow proto udp from <source-ip> to any port ${SYSLOG_UDP_PORT}`,
    `sudo ufw allow proto tcp from <source-ip> to any port ${SYSLOG_TCP_PORT}`,
    `sudo ufw allow proto udp from <source-ip> to any port ${NETFLOW_PORT}`
  ];

  return {
    generatedAt: new Date().toISOString(),
    ufw: {
      available: ufwAvailable,
      accessDenied: ufwAccessDenied,
      active: ufwActive,
      statusText: ufwStatusText || (ufwAvailable ? 'No ufw output' : 'ufw command not found'),
      ruleCount: ufwRules.length
    },
    sockets: {
      available: ssAvailable,
      udpLineCount: udpLines.length,
      tcpLineCount: tcpLines.length
    },
    listeners: {
      udpSample: udpLines.slice(0, 50),
      tcpSample: tcpLines.slice(0, 50)
    },
    summary,
    checks,
    suggestions
  };
}

// ── Storage health helpers ────────────────────────────────────────────────────
async function readTrackedStorageFiles() {
  return Promise.all(
    STORAGE_TRACKED_FILES.map(async (row) => {
      try {
        const stat = await smartStat(row.file);
        return {
          name: row.name,
          category: row.category,
          bytes: Number(stat.size || 0),
          mtime: stat.mtime ? stat.mtime.toISOString() : ''
        };
      } catch {
        return {
          name: row.name,
          category: row.category,
          bytes: 0,
          mtime: ''
        };
      }
    })
  );
}

function estimateEventStorageMax(state, currentEventBytes = 0) {
  const eventCount = Math.max(0, Number(state?.events?.length || 0));
  const avgBytesPerEvent = eventCount > 0 && currentEventBytes > 0
    ? Math.max(160, Math.ceil(currentEventBytes / eventCount))
    : 512;
  return {
    eventCount,
    avgBytesPerEvent,
    maxBytes: avgBytesPerEvent * EVENT_RETENTION
  };
}

async function retainRecentJsonLinesFile(filePath, { maxLines = 0, retentionMs = 0 } = {}) {
  let raw = '';
  try {
    raw = await smartReadFile(filePath, 'utf8');
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      return { changed: false, kept: 0, removed: 0 };
    }
    throw err;
  }

  const rows = raw.split('\n').filter(Boolean);
  const cutoffMs = retentionMs > 0 ? Date.now() - retentionMs : 0;
  const retained = rows.filter((line) => {
    if (!cutoffMs) return true;
    try {
      const parsed = JSON.parse(line);
      const tsMs = parseIsoTimestampMs(parsed?.ts);
      if (!tsMs) return true;
      return tsMs >= cutoffMs;
    } catch {
      return true;
    }
  });
  const trimmed = maxLines > 0 ? retained.slice(-maxLines) : retained;
  const changed = trimmed.length !== rows.length;

  if (changed) {
    const body = trimmed.length ? `${trimmed.join('\n')}\n` : '';
    await smartWriteFile(filePath, body, 'utf8');
  }

  return {
    changed,
    kept: trimmed.length,
    removed: Math.max(0, rows.length - trimmed.length)
  };
}

function retainedEventsForPolicy(events = [], { pruneEvents = true, nowMs = Date.now() } = {}) {
  const rows = Array.isArray(events) ? events : [];
  if (!pruneEvents) return rows.slice();
  const safeNow = Number(nowMs);
  return pruneEventsByPolicy(rows, Number.isFinite(safeNow) ? safeNow : Date.now());
}

async function enforceStorageRetention(state, options = {}) {
  const pruneEvents = options.pruneEvents !== false;
  const persistEventsNow = Boolean(options.persistEventsNow);
  if (pruneEvents) {
    const nextEvents = retainedEventsForPolicy(state?.events || [], { pruneEvents: true, nowMs: Date.now() });
    if (!sameEventList(state?.events || [], nextEvents)) {
      state.events = nextEvents;
      if (persistEventsNow) await persistEvents(nextEvents);
      else state.dirtyEvents = true;
    }
  }

  await Promise.all([
    retainRecentJsonLinesFile(ERROR_LOG_FILE, {
      maxLines: ERROR_LOG_MAX_LINES,
      retentionMs: DATA_RETENTION_MS
    }),
    retainRecentJsonLinesFile(DIAGNOSTIC_LOG_FILE, {
      maxLines: DIAGNOSTIC_LOG_MAX_LINES,
      retentionMs: DATA_RETENTION_MS
    }),
    retainRecentJsonLinesFile(TELEMETRY_LOG_FILE, {
      maxLines: TELEMETRY_LOG_MAX_LINES,
      retentionMs: DATA_RETENTION_MS
    })
  ]);
}

async function buildStorageSummary(state, options = {}) {
  if (options.applyRetention) {
    await enforceStorageRetention(state, { persistEventsNow: true });
  }
  const files = await readTrackedStorageFiles();
  const byName = new Map(files.map((row) => [row.name, row]));
  const eventsRow = byName.get('events') || { bytes: 0 };
  const eventsCap = estimateEventStorageMax(state, Number(eventsRow.bytes || 0));
  const maxByName = {
    events: eventsCap.maxBytes,
    errorLog: ERROR_LOG_MAX_BYTES,
    diagnosticsLog: DIAGNOSTIC_LOG_MAX_BYTES,
    telemetryLog: TELEMETRY_LOG_MAX_BYTES
  };

  const filesWithCaps = files.map((row) => ({
    ...row,
    maxBytes: Number(maxByName[row.name] || 0)
  }));

  const currentBytes = filesWithCaps.reduce((sum, row) => sum + Number(row.bytes || 0), 0);
  const currentLogBytes = filesWithCaps
    .filter((row) => row.category === 'log')
    .reduce((sum, row) => sum + Number(row.bytes || 0), 0);
  const fixedBytes = filesWithCaps
    .filter((row) => row.category !== 'log')
    .reduce((sum, row) => sum + Number(row.bytes || 0), 0);
  const estimatedLogMaxBytes = Object.values(maxByName).reduce((sum, value) => sum + Number(value || 0), 0);
  const estimatedMaxBytes = fixedBytes + estimatedLogMaxBytes;
  const estimatedHeadroomBytes = Math.max(0, estimatedMaxBytes - currentBytes);
  const usagePercent = estimatedMaxBytes > 0 ? Math.min(100, Math.round((currentBytes / estimatedMaxBytes) * 1000) / 10) : 0;

  return {
    generatedAt: new Date().toISOString(),
    retentionDays: DATA_RETENTION_DAYS,
    retentionPolicy: `Logs and telemetry are retained for up to ${DATA_RETENTION_DAYS} days, subject to size caps.`,
    currentBytes,
    currentLogBytes,
    estimatedMaxBytes,
    estimatedLogMaxBytes,
    estimatedHeadroomBytes,
    usagePercent,
    eventRetention: {
      maxEntries: EVENT_RETENTION,
      currentEntries: eventsCap.eventCount,
      avgBytesPerEvent: eventsCap.avgBytesPerEvent,
      estimatedMaxBytes: eventsCap.maxBytes
    },
    caps: {
      errorLogMaxBytes: ERROR_LOG_MAX_BYTES,
      diagnosticsLogMaxBytes: DIAGNOSTIC_LOG_MAX_BYTES,
      telemetryLogMaxBytes: TELEMETRY_LOG_MAX_BYTES
    },
    files: filesWithCaps
  };
}

async function purgeStorageLogs(state) {
  state.events = [];
  state.eventThrottle = new Map();
  state.dirtyEvents = false;
  await Promise.all([
    persistEvents([]),
    smartWriteFile(ERROR_LOG_FILE, '', 'utf8'),
    clearDiagnosticLogEntries(),
    clearTelemetryLogEntries()
  ]);
  return buildStorageSummary(state);
}

// ── Diagnostic check summary ──────────────────────────────────────────────────
function summarizeDiagnosticChecks(protocol, checks = []) {
  const summary = {
    protocol: String(protocol || '').trim().toLowerCase(),
    passed: 0,
    warnings: 0,
    failed: 0,
    ok: true
  };
  for (const check of checks) {
    const status = String(check?.status || '').toLowerCase();
    if (status === 'pass') summary.passed += 1;
    else if (status === 'warn') summary.warnings += 1;
    else summary.failed += 1;
  }
  summary.ok = summary.failed === 0;
  summary.message = `${summary.passed} pass, ${summary.warnings} warn, ${summary.failed} fail`;
  return summary;
}

function toPortNumber(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  const port = Math.floor(n);
  if (port < 1 || port > 65535) return 0;
  return port;
}

function parsePingLatencyMs(stdout = '') {
  const match = String(stdout || '').match(/=\s*([\d.]+)\/([\d.]+)\/([\d.]+)\/([\d.]+)/);
  if (!match) return null;
  const avg = Number(match[2]);
  return Number.isFinite(avg) ? avg : null;
}

async function runPingProbe(host, timeoutMs = 8000) {
  const target = String(host || '').trim();
  if (!target) {
    return { status: 'fail', detail: 'Host is required' };
  }
  const result = await runExecFile('ping', ['-c', '1', '-W', '1', target], timeoutMs);
  if (result.err) {
    if (result.err.code === 'ENOENT') {
      return { status: 'warn', detail: 'ping command is not available on server' };
    }
    const detail = String(result.stderr || result.err.message || 'Ping failed').trim();
    return { status: 'fail', detail };
  }
  const latency = parsePingLatencyMs(result.stdout);
  return {
    status: 'pass',
    detail: latency == null ? 'Reachable' : `Reachable (${latency.toFixed(1)} ms)`
  };
}

function getLocalHostSet() {
  const out = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);
  let interfaces = {};
  try {
    interfaces = os.networkInterfaces() || {};
  } catch {
    interfaces = {};
  }
  for (const rows of Object.values(interfaces || {})) {
    for (const row of rows || []) {
      if (!row || !row.address) continue;
      out.add(String(row.address).trim().toLowerCase());
    }
  }
  return out;
}

function getServerHostInfo() {
  const hostname = String(os.hostname() || '').trim();
  const ipv4 = [];
  const ipv6 = [];
  let interfaces = {};
  try {
    interfaces = os.networkInterfaces() || {};
  } catch {
    interfaces = {};
  }
  for (const rows of Object.values(interfaces || {})) {
    for (const row of rows || []) {
      const address = String(row?.address || '').trim();
      if (!address || row?.internal) continue;
      if (row.family === 'IPv4') {
        ipv4.push(address);
      } else if (row.family === 'IPv6') {
        const lowered = address.toLowerCase();
        if (lowered.startsWith('fe80:')) continue;
        ipv6.push(address);
      }
    }
  }
  const uniq = (values = []) => [...new Set(values.map((v) => String(v || '').trim()).filter(Boolean))];
  const ipv4List = uniq(ipv4);
  const ipv6List = uniq(ipv6);
  return {
    hostname,
    primaryIp: ipv4List[0] || ipv6List[0] || '',
    ipv4: ipv4List,
    ipv6: ipv6List
  };
}

function healthStatusFromChecks(checks = []) {
  const summary = summarizeChecks(checks);
  if (summary.fail > 0) return 'fail';
  if (summary.warn > 0 || summary.unknown > 0) return 'degraded';
  return 'ok';
}

function healthHttpStatusForState(status = 'ok') {
  return String(status || '').trim().toLowerCase() === 'fail' ? 503 : 200;
}

async function runDatabaseHealthCheck() {
  const out = {
    status: 'fail',
    detail: '',
    latencyMs: null
  };
  if (shared.storageBackendActive !== 'postgres') {
    out.detail = `Unsupported storage backend "${shared.storageBackendActive || 'unknown'}"`;
    return out;
  }
  if (!shared.pgPool || typeof shared.pgPool.query !== 'function') {
    out.detail = 'PostgreSQL pool is not ready';
    return out;
  }
  const startedAt = Date.now();
  try {
    await shared.pgPool.query('SELECT 1');
    out.latencyMs = Math.max(0, Date.now() - startedAt);
    out.status = 'pass';
    out.detail = `PostgreSQL query ok (${out.latencyMs} ms)`;
    return out;
  } catch (err) {
    out.latencyMs = Math.max(0, Date.now() - startedAt);
    out.detail = String(err?.message || err || 'PostgreSQL query failed').trim() || 'PostgreSQL query failed';
    return out;
  }
}

async function buildPublicHealthPayload(state, options = {}) {
  const detailed = Boolean(options?.detailed);
  const nowMs = Date.now();
  const checks = [];
  const db = await runDatabaseHealthCheck();
  addDiagnosticCheck(checks, 'database', db.status, db.detail);

  let storageSummary = null;
  let storageStatus = 'pass';
  let storageDetail = '';
  try {
    storageSummary = await buildStorageSummary(state);
    const usage = Number(storageSummary?.usagePercent || 0);
    storageStatus = usage >= 95 ? 'warn' : 'pass';
    storageDetail = `Storage usage ${Number.isFinite(usage) ? usage.toFixed(1) : '0.0'}%`;
  } catch (err) {
    storageStatus = 'fail';
    storageDetail = `Storage summary failed: ${String(err?.message || err || 'unknown error')}`;
  }
  addDiagnosticCheck(checks, 'storage', storageStatus, storageDetail);

  const dependency = state?.dependencies?.smtp || {};
  let dependencyStatus = 'pass';
  let dependencyDetail = String(dependency.detail || '').trim() || 'Teams webhook dependency ready';
  if (!dependency.available) {
    dependencyStatus = 'warn';
    if (!dependencyDetail) dependencyDetail = 'Teams webhook dependency not configured';
  } else if (dependency.probeOk === false) {
    dependencyStatus = 'warn';
    if (!dependencyDetail) dependencyDetail = 'Teams webhook dependency check warning';
  }
  addDiagnosticCheck(checks, 'teams_webhook', dependencyStatus, dependencyDetail);

  const configIntegrity = getConfigIntegrityReport();
  let configStatus = 'pass';
  let configDetail = 'All tracked config stores healthy';
  if (!configIntegrity.healthy) {
    configStatus = 'warn';
    const impacted = configIntegrity.entries
      .filter((row) => row.status !== 'ok')
      .map((row) => row.name);
    configDetail = impacted.length
      ? `Config integrity warnings: ${impacted.join(', ')}`
      : 'Config integrity warnings detected';
  }
  addDiagnosticCheck(checks, 'config_integrity', configStatus, configDetail);

  const listeners = {
    httpPort: PORT,
    syslogUdpPort: SYSLOG_UDP_PORT,
    syslogTcpPort: SYSLOG_TCP_PORT,
    netflowUdpPort: NETFLOW_PORT
  };
  const invalidListenerKeys = Object.entries(listeners)
    .filter(([, port]) => !Number.isFinite(Number(port)) || Number(port) < 1 || Number(port) > 65535)
    .map(([key]) => key);
  addDiagnosticCheck(
    checks,
    'listeners',
    invalidListenerKeys.length ? 'fail' : 'pass',
    invalidListenerKeys.length
      ? `Invalid listener ports: ${invalidListenerKeys.join(', ')}`
      : `http=${PORT} syslog=${SYSLOG_UDP_PORT}/${SYSLOG_TCP_PORT} netflow=${NETFLOW_PORT}`
  );

  const mem = process.memoryUsage();
  const heapUsageRatio = mem.heapTotal > 0 ? (mem.heapUsed / mem.heapTotal) : 0;
  addDiagnosticCheck(
    checks,
    'process_memory',
    heapUsageRatio >= 0.95 ? 'warn' : 'pass',
    `heapUsed=${mem.heapUsed} heapTotal=${mem.heapTotal} (${(heapUsageRatio * 100).toFixed(1)}%)`
  );

  const pool = getPoolStats();
  addDiagnosticCheck(
    checks,
    'db_pool',
    pool.waiting > 0 && pool.total > 0 && pool.waiting >= pool.total ? 'warn' : 'pass',
    `total=${pool.total} idle=${pool.idle} waiting=${pool.waiting}`
  );

  const status = healthStatusFromChecks(checks);
  const summary = summarizeChecks(checks);
  const payload = {
    ok: status === 'ok',
    status,
    timestamp: new Date(nowMs).toISOString(),
    version: APP_VERSION,
    startedAt: new Date(STARTED_AT_MS).toISOString(),
    uptimeSec: Math.max(0, Math.floor(process.uptime())),
    checks,
    summary: {
      pass: summary.pass,
      warn: summary.warn,
      fail: summary.fail,
      unknown: summary.unknown
    },
    storageBackend: shared.storageBackendActive,
    database: {
      backend: shared.storageBackendActive,
      status: db.status,
      detail: db.detail,
      latencyMs: db.latencyMs,
      pool: getPoolStats()
    },
    storage: storageSummary
      ? {
        usagePercent: Number(storageSummary.usagePercent || 0),
        currentBytes: Number(storageSummary.currentBytes || 0),
        estimatedMaxBytes: Number(storageSummary.estimatedMaxBytes || 0),
        retentionDays: Number(storageSummary.retentionDays || DATA_RETENTION_DAYS),
        filesTracked: Array.isArray(storageSummary.files) ? storageSummary.files.length : 0
      }
      : {
        usagePercent: 0,
        currentBytes: 0,
        estimatedMaxBytes: 0,
        retentionDays: DATA_RETENTION_DAYS,
        filesTracked: 0
      },
    dependencies: {
      teamsWebhook: {
        available: Boolean(dependency.available),
        mode: String(dependency.mode || 'teams'),
        probeOk: dependency.probeOk !== false,
        detail: dependencyDetail
      }
    },
    configIntegrity,
    setupRequired: (state?.users || []).every((u) => !u.localAuth?.passwordHash || !u.localAuth?.passwordSalt),
    snmpTrapPort: SNMP_TRAP_PORT
  };
  if (detailed) {
    payload.listeners = listeners;
    payload.process = {
      pid: process.pid,
      node: process.version,
      platform: process.platform,
      arch: process.arch,
      rssBytes: mem.rss,
      heapUsedBytes: mem.heapUsed,
      heapTotalBytes: mem.heapTotal
    };
    payload.host = getServerHostInfo();
  }
  return payload;
}

function isLocalHostValue(value) {
  const host = String(value || '').trim().toLowerCase();
  if (!host) return false;
  return getLocalHostSet().has(host);
}

function addDiagnosticCheck(checks, id, status, detail) {
  const normalized = String(status || 'fail').trim().toLowerCase();
  const finalStatus = normalized === 'pass' || normalized === 'warn' || normalized === 'fail' ? normalized : 'fail';
  checks.push({
    id: String(id || '').trim() || 'check',
    status: finalStatus,
    ok: finalStatus === 'pass',
    detail: String(detail || '').trim()
  });
}

async function runMonitorDiagnostics(state, site, protocol, config = {}, options = {}) {
  const { recentFlowCheck, runSnmpGet, formatSysUpTimeTicks } = require('./monitoring');
  const { mergeConfig } = require('./sites');
  const checks = [];
  const protocolName = String(protocol || '').trim().toLowerCase();
  const cfg = mergeConfig(site?.monitorConfig?.[protocolName] || {}, config || {});
  const runLiveProbe = Boolean(options.runLiveProbe);
  const runtimeSettings = shared.runtimeSettings;

  addDiagnosticCheck(checks, 'monitor_enabled', cfg.enabled ? 'pass' : 'warn', cfg.enabled ? 'Monitor is enabled' : 'Monitor is disabled');

  if (protocolName === 'syslog') {
    const sourceIp = String(cfg.sourceIp || '').trim();
    const server = String(cfg.server || '').trim();
    const transport = String(cfg.protocol || 'udp').trim().toLowerCase();
    const port = toPortNumber(cfg.port || SYSLOG_UDP_PORT);
    const expected = transport === 'tcp' ? SYSLOG_TCP_PORT : SYSLOG_UDP_PORT;
    const conflict = state.sites.find((row) => {
      if (!row || row.id === site.id) return false;
      const rowCfg = row.monitorConfig?.syslog || {};
      return Boolean(rowCfg.enabled) && String(rowCfg.sourceIp || '').trim() === sourceIp;
    });

    addDiagnosticCheck(checks, 'source_ip_present', sourceIp ? 'pass' : 'fail', sourceIp ? `Source IP ${sourceIp}` : 'Source IP is required');
    addDiagnosticCheck(checks, 'server_present', server ? 'pass' : 'fail', server ? `Server ${server}` : 'Syslog server field is required');
    addDiagnosticCheck(checks, 'transport_valid', ['udp', 'tcp'].includes(transport) ? 'pass' : 'fail', `Transport ${transport || 'n/a'}`);
    addDiagnosticCheck(checks, 'port_valid', port ? 'pass' : 'fail', port ? `Port ${port}` : `Invalid port "${cfg.port || ''}"`);
    addDiagnosticCheck(
      checks,
      'collector_port_alignment',
      port === expected ? 'pass' : 'warn',
      `Configured ${port || 'n/a'}, listener ${expected}/${transport.toUpperCase()}`
    );
    addDiagnosticCheck(
      checks,
      'server_points_to_cajal',
      server ? (isLocalHostValue(server) ? 'pass' : 'warn') : 'fail',
      server ? (isLocalHostValue(server) ? 'Syslog server points to this Cajal host' : 'Syslog server does not match this host') : 'Server missing'
    );
    if (sourceIp) {
      const ping = await runPingProbe(sourceIp);
      addDiagnosticCheck(checks, 'source_reachable', ping.status, ping.detail);
    }
    if (sourceIp) {
      addDiagnosticCheck(
        checks,
        'source_conflict',
        conflict ? 'warn' : 'pass',
        conflict ? `Source IP also assigned to ${conflict.name}` : 'Source IP uniquely mapped'
      );
    }
    const flow = recentFlowCheck(state, site, 'syslog');
    addDiagnosticCheck(checks, 'recent_ingest', flow.status, flow.detail);
  } else if (protocolName === 'netflow') {
    const sourceIp = String(cfg.sourceIp || '').trim();
    const collectorIp = String(cfg.collectorIp || '').trim();
    const collectorPort = toPortNumber(cfg.collectorPort || NETFLOW_PORT);
    const templateCount = [...(state.netflowTemplates?.keys() || [])].filter((key) => String(key).startsWith(`${site.id}:`)).length;
    const conflict = state.sites.find((row) => {
      if (!row || row.id === site.id) return false;
      const rowCfg = row.monitorConfig?.netflow || {};
      return Boolean(rowCfg.enabled) && String(rowCfg.sourceIp || '').trim() === sourceIp;
    });

    addDiagnosticCheck(checks, 'source_ip_present', sourceIp ? 'pass' : 'fail', sourceIp ? `Source IP ${sourceIp}` : 'Source IP is required');
    addDiagnosticCheck(checks, 'collector_ip_present', collectorIp ? 'pass' : 'fail', collectorIp ? `Collector ${collectorIp}` : 'Collector IP is required');
    addDiagnosticCheck(checks, 'collector_port_valid', collectorPort ? 'pass' : 'fail', collectorPort ? `Collector port ${collectorPort}` : `Invalid collector port "${cfg.collectorPort || ''}"`);
    addDiagnosticCheck(
      checks,
      'collector_port_alignment',
      collectorPort === NETFLOW_PORT ? 'pass' : 'warn',
      `Configured ${collectorPort || 'n/a'}, listener ${NETFLOW_PORT}/UDP`
    );
    addDiagnosticCheck(
      checks,
      'collector_points_to_cajal',
      collectorIp ? (isLocalHostValue(collectorIp) ? 'pass' : 'warn') : 'fail',
      collectorIp ? (isLocalHostValue(collectorIp) ? 'Collector points to this Cajal host' : 'Collector IP does not match this host') : 'Collector IP missing'
    );
    if (sourceIp) {
      const ping = await runPingProbe(sourceIp);
      addDiagnosticCheck(checks, 'source_reachable', ping.status, ping.detail);
      addDiagnosticCheck(
        checks,
        'source_conflict',
        conflict ? 'warn' : 'pass',
        conflict ? `Source IP also assigned to ${conflict.name}` : 'Source IP uniquely mapped'
      );
    }
    const flow = recentFlowCheck(state, site, 'netflow');
    addDiagnosticCheck(checks, 'recent_ingest', flow.status, flow.detail);
    addDiagnosticCheck(checks, 'template_state', templateCount > 0 ? 'pass' : 'warn',
      templateCount > 0
        ? `${templateCount} exporter template map(s) loaded`
        : 'No NetFlow/IPFIX templates seen yet — device must send template sets before data sets (v9/IPFIX). For v5, check exporter is sending to this host\'s IP on the configured port.');
    const hasFlowData = Array.isArray(site?.metrics?.netflow?.topTalkers) && site.metrics.netflow.topTalkers.length > 0;
    if (templateCount > 0) {
      addDiagnosticCheck(checks, 'flow_data', hasFlowData ? 'pass' : 'warn',
        hasFlowData ? `Flow data present (${site.metrics.netflow.topTalkers.length} top talker(s))` : 'Templates loaded but no flow records yet — check device has active traffic and flow-export is configured');
    }
  } else if (protocolName === 'snmp') {
    const targetHost = String(cfg.targetHost || '').trim();
    const version = String(cfg.version || '2c').trim();
    const dependency = state.dependencies?.snmpget || { available: true, detail: '' };
    addDiagnosticCheck(checks, 'target_host_present', targetHost ? 'pass' : 'fail', targetHost ? `Target ${targetHost}` : 'Target host is required');
    addDiagnosticCheck(checks, 'version_valid', ['1', '2c', '3'].includes(version) ? 'pass' : 'fail', `Version ${version || 'n/a'}`);
    if (version === '3') {
      addDiagnosticCheck(checks, 'credentials', String(cfg.authUser || '').trim() ? 'pass' : 'fail', String(cfg.authUser || '').trim() ? `Auth user ${cfg.authUser}` : 'SNMPv3 authUser is required');
    } else {
      addDiagnosticCheck(
        checks,
        'credentials',
        String(cfg.communityString || '').trim() ? 'pass' : 'fail',
        String(cfg.communityString || '').trim() ? 'Community string provided' : 'Community string is required for v1/v2c'
      );
    }
    addDiagnosticCheck(
      checks,
      'snmp_cli_dependency',
      dependency.available ? 'pass' : 'fail',
      dependency.available ? `${dependency.path || 'snmpget'} ${dependency.detail || ''}`.trim() : dependency.detail || 'snmpget not installed'
    );
    if (targetHost) {
      const ping = await runPingProbe(targetHost);
      addDiagnosticCheck(checks, 'target_reachable', ping.status, ping.detail);
    }
    const flow = recentFlowCheck(
      state,
      site,
      'snmp',
      Math.max(
        Number(runtimeSettings?.flowTimeoutMs || FLOW_TIMEOUT_MS) || FLOW_TIMEOUT_MS,
        Number(runtimeSettings?.snmpPollIntervalMs || SNMP_POLL_INTERVAL_MS) * 2
      )
    );
    addDiagnosticCheck(checks, 'recent_poll', flow.status, flow.detail);
    const ifCount = Number(site?.metrics?.snmp?.interfaceCount ?? -1);
    if (ifCount >= 0) {
      addDiagnosticCheck(checks, 'interface_data', ifCount > 0 ? 'pass' : 'warn',
        ifCount > 0 ? `${ifCount} interface(s) in IF-MIB table` : 'No interfaces returned — community string may lack IF-MIB (1.3.6.1.2.1.2) read access, or device does not expose interface table');
    }
    const blockingFailure = checks.some((item) => item.status === 'fail');
    if (runLiveProbe && !blockingFailure && cfg.enabled) {
      try {
        const startedAt = Date.now();
        const ticks = await runSnmpGet(cfg);
        const durationMs = Date.now() - startedAt;
        addDiagnosticCheck(checks, 'live_probe', 'pass', `SNMP live probe ok (${formatSysUpTimeTicks(ticks)} in ${durationMs} ms)`);
      } catch (err) {
        addDiagnosticCheck(checks, 'live_probe', 'fail', String(err?.message || err || 'SNMP live probe failed'));
      }
    }
  } else {
    addDiagnosticCheck(checks, 'protocol', 'fail', `Unknown protocol "${protocolName}"`);
  }

  const summary = summarizeDiagnosticChecks(protocolName, checks);
  logDiagnostic(state, {
    level: summary.ok ? 'info' : 'warn',
    scope: 'monitor.diagnostics',
    protocol: protocolName,
    siteId: site.id,
    siteName: site.name,
    sourceIp: String(cfg.sourceIp || cfg.targetHost || '').trim(),
    action: 'diagnostics_run',
    message: `${protocolName.toUpperCase()} diagnostics for ${site.name}: ${summary.message}`,
    detail: `enabled=${Boolean(cfg.enabled)} runLiveProbe=${runLiveProbe}`,
    context: { checks }
  });

  return {
    ok: summary.ok,
    summary,
    checks,
    protocol: protocolName,
    siteId: site.id,
    siteName: site.name,
    ranAt: new Date().toISOString()
  };
}

module.exports = {
  parsePortNumber,
  parseUfwActive,
  ssHasListener,
  inferAppListenerOpen,
  ufwAllowsSource,
  summarizeChecks,
  evaluateFirewallUfwRuleStatus,
  buildFirewallCheck,
  readTrackedStorageFiles,
  estimateEventStorageMax,
  retainRecentJsonLinesFile,
  retainedEventsForPolicy,
  enforceStorageRetention,
  buildStorageSummary,
  purgeStorageLogs,
  summarizeDiagnosticChecks,
  toPortNumber,
  parsePingLatencyMs,
  runPingProbe,
  getLocalHostSet,
  getServerHostInfo,
  healthStatusFromChecks,
  healthHttpStatusForState,
  runDatabaseHealthCheck,
  buildPublicHealthPayload,
  isLocalHostValue,
  addDiagnosticCheck,
  runMonitorDiagnostics,
};
