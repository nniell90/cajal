'use strict';
const { execFile } = require('child_process');
const net = require('net');
const dgram = require('dgram');
const {
  FLOW_TIMEOUT_MS,
  SYSLOG_FLOW_TIMEOUT_MIN_MS,
  NETFLOW_FLOW_TIMEOUT_MIN_MS,
  SNMP_POLL_INTERVAL_MS,
  PING_INTERVAL_MS,
  NETFLOW_TOP_WINDOW_MS,
  WAN_TEST_SLOT_INTERVAL_MS,
  WAN_TEST_SLOT_LABEL_BY_HOUR,
  WAN_TEST_HISTORY,
  SYSLOG_UDP_PORT,
  SYSLOG_TCP_PORT,
  NETFLOW_PORT,
  LOCATION_PING_MONITOR_MAX,
  SYSLOG_EVENT_THROTTLE_MS,
  DEFAULT_TEAMS_WEBHOOK_URL,
  DEFAULT_TEAMS_WEBHOOK_TIMEOUT_MS,
  PUBLIC_SERVICE_TARGETS,
  WEBHOOK_ROUTE_MAP,
  normalizeTeamsWebhookUrl,
  normalizeTeamsWebhookTimeoutMs,
  UPTIME_SAMPLE_INTERVAL_MS,
  LOCATION_PING_MONITOR_POLL_INTERVAL_MS,
  WAN_PUBLIC_IP_POLL_INTERVAL_MS,
  WAN_TEST_RECOVERY_INTERVAL_MS,
  TELEMETRY_NETFLOW_RECORDS_PER_PACKET,
  NETFLOW_EVENT_THROTTLE_MS,
  SNMP_OK_EVENT_THROTTLE_MS,
  SNMP_ERROR_EVENT_THROTTLE_MS,
  PUBLIC_SERVICE_POLL_INTERVAL_MS,
} = require('./constants');
const shared = require('./shared');
const { logEvent, logEventThrottled, logSiteEvent, logSiteEventThrottled, locationNameForSite } = require('./events');
const { logDiagnostic, logDiagnosticThrottled, logSystemError, logTelemetry, truncateTelemetryText } = require('./logging');
const { runExecFile, splitNonEmptyLines, getCollectorAgentPresence, runCollectorAgentTerminalCommand } = require('./agent');
const { markSiteDirty, normalizeHeartbeatTarget, isLinkMarkedNone, resolveSiteGatewayIp, applyFlowStatus, formatSysUpTimeTicks } = require('./sites');
const { normalizeRole, dispatchWebhookRouteNotification, reconcileSiteStatus, notifyCollectorWanFailover } = require('./notifications');
const { sanitizeLocationSettings } = require('./settings');
const { SMTP_TRANSPORT_CONFIG, validateSmtpTransportConfig, smtpTransportLabel, runSmtpConnectionProbe } = require('./smtp');
const { formatPacketPreview, parseLinesFromBuffer, parseAnyNetflow } = require('./telemetry');

// ── Protocol flow timeout ─────────────────────────────────────────────────────
function protocolFlowTimeoutMs(protocol = '') {
  const runtimeSettings = shared.runtimeSettings;
  const protocolName = String(protocol || '').trim().toLowerCase();
  const baseTimeoutMs = Math.max(1000, Number(runtimeSettings?.flowTimeoutMs || FLOW_TIMEOUT_MS) || FLOW_TIMEOUT_MS);
  if (protocolName === 'netflow') {
    return Math.max(baseTimeoutMs, NETFLOW_FLOW_TIMEOUT_MIN_MS, 6 * 60 * 1000);
  }
  if (protocolName === 'snmp') {
    return Math.max(baseTimeoutMs, Number(runtimeSettings?.snmpPollIntervalMs || SNMP_POLL_INTERVAL_MS) * 2);
  }
  if (protocolName === 'syslog') {
    return Math.max(baseTimeoutMs, SYSLOG_FLOW_TIMEOUT_MIN_MS);
  }
  return baseTimeoutMs;
}

function recentFlowCheck(state, site, protocol, staleMs = null) {
  const protocolName = String(protocol || '').trim().toLowerCase();
  const protocolTimeoutMs = protocolFlowTimeoutMs(protocolName);
  const hasOverride = staleMs != null && Number.isFinite(Number(staleMs));
  const effectiveStaleMs = hasOverride ? Number(staleMs) : protocolTimeoutMs;
  const ts = Number(state?.lastSeen?.[protocol]?.get(site.id) || 0);
  if (!ts) return { status: 'warn', detail: 'No recent ingest recorded yet' };
  const ageMs = Date.now() - ts;
  if (ageMs > effectiveStaleMs) {
    return { status: 'warn', detail: `Last seen ${Math.floor(ageMs / 1000)}s ago (stale)` };
  }
  return { status: 'pass', detail: `Last seen ${Math.floor(ageMs / 1000)}s ago` };
}

// ── Site matching ─────────────────────────────────────────────────────────────
function matchSiteBySourceIp(state, protocol, sourceIp) {
  return state.sites.find((site) => {
    const cfg = site.monitorConfig?.[protocol] || {};
    if (!cfg.enabled) return false;
    if (!cfg.sourceIp) return false;
    return cfg.sourceIp === sourceIp;
  });
}

// ── Netflow ───────────────────────────────────────────────────────────────────
function markNetflowSeen(state, site, seenAt = Date.now()) {
  if (!state?.lastSeen?.netflow || !site?.id) return;
  const ts = Number(seenAt);
  state.lastSeen.netflow.set(site.id, Number.isFinite(ts) && ts > 0 ? ts : Date.now());
}

function refreshNetflowTopTalkers(state, site, now) {
  const talks = state.netflowTalkers.get(site.id) || new Map();
  const cutoff = now - NETFLOW_TOP_WINDOW_MS;
  const ranked = [];
  for (const [ip, series] of talks.entries()) {
    const recent = series.filter((s) => s.ts >= cutoff);
    if (!recent.length) {
      talks.delete(ip);
      continue;
    }
    talks.set(ip, recent);
    const upBytes = recent.reduce((sum, item) => sum + Number(item.upBytes ?? item.bytes ?? 0), 0);
    const downBytes = recent.reduce((sum, item) => sum + Number(item.downBytes ?? 0), 0);
    const totalBytes = upBytes + downBytes;
    const oldestTs = recent.reduce((min, item) => {
      const ts = Number(item?.ts);
      return Number.isFinite(ts) ? Math.min(min, ts) : min;
    }, now);
    const newestTs = recent.reduce((max, item) => {
      const ts = Number(item?.ts);
      return Number.isFinite(ts) ? Math.max(max, ts) : max;
    }, oldestTs);
    const observedWindowMs = Math.max(1000, newestTs - oldestTs);
    const effectiveWindowMs = Math.max(60 * 1000, Math.min(NETFLOW_TOP_WINDOW_MS, observedWindowMs));
    const upMbps = (upBytes * 8) / (effectiveWindowMs / 1000) / 1000000;
    const downMbps = (downBytes * 8) / (effectiveWindowMs / 1000) / 1000000;
    const mbps = (totalBytes * 8) / (effectiveWindowMs / 1000) / 1000000;
    ranked.push({
      ip,
      downMbps: Number(downMbps.toFixed(6)),
      upMbps: Number(upMbps.toFixed(6)),
      mbps: Number(mbps.toFixed(6)),
      totalMb: Number(((totalBytes * 8) / 1000000).toFixed(2))
    });
  }
  state.netflowTalkers.set(site.id, talks);
  ranked.sort((a, b) => b.mbps - a.mbps);
  site.metrics = site.metrics || {};
  site.metrics.netflow = site.metrics.netflow || {};
  site.metrics.netflow.topTalkers = ranked.slice(0, 3);
}

// ── Syslog metrics ────────────────────────────────────────────────────────────
function updateSyslogMetrics(state, site, now, sourceIp = '') {
  state.lastSeen.syslog.set(site.id, now);
  const key = site.id;
  const window = state.syslogWindows.get(key) || { startedAt: now, count: 0 };
  if (now - window.startedAt > 1000) {
    window.startedAt = now;
    window.count = 0;
  }
  window.count += 1;
  state.syslogWindows.set(key, window);
  site.metrics = site.metrics || {};
  site.metrics.syslog = site.metrics.syslog || {};
  site.metrics.syslog.eventsPerSecond = window.count;
  site.metrics.syslog.totalIngested = Number(site.metrics.syslog.totalIngested || 0) + 1;
  site.metrics.syslog.lastIngestAt = new Date(now).toISOString();
  site.metrics.syslog.lastError = '';
  site.metrics.syslog.lastErrorAt = '';
  logSiteEventThrottled(state, site, `syslog:${site.id}`, SYSLOG_EVENT_THROTTLE_MS, {
    classId: 320,
    source: 'syslog',
    actor: 'collector',
    action: 'syslog_ingest',
    message: `Syslog ingest for ${site.name}`,
    detail: `eps=${window.count}${sourceIp ? ` src=${sourceIp}` : ''}`
  });
  markSiteDirty(state);
}

function logSyslogStreamEvent(state, site, {
  sourceIp = '',
  transport = 'udp',
  message = '',
  packetLen = 0
} = {}) {
  const text = truncateTelemetryText(String(message || '').trim() || '[binary syslog payload]', 420);
  if (!text) return;
  const src = String(sourceIp || '').trim() || 'unknown';
  const mode = String(transport || 'udp').trim().toLowerCase() === 'tcp' ? 'tcp' : 'udp';
  const len = Math.max(0, Number(packetLen || 0));
  logSiteEvent(state, site, {
    classId: 321,
    source: 'syslog',
    actor: 'collector',
    action: 'syslog_stream',
    message: text,
    detail: `src=${src} transport=${mode} len=${len}`
  });
}

function decaySyslogMetrics(state) {
  const now = Date.now();
  let changed = false;
  for (const site of state.sites) {
    const win = state.syslogWindows.get(site.id);
    site.metrics = site.metrics || {};
    site.metrics.syslog = site.metrics.syslog || {};
    if (!win || (now - win.startedAt > 2000)) {
      if (site.metrics.syslog.eventsPerSecond !== 0) {
        site.metrics.syslog.eventsPerSecond = 0;
        changed = true;
      }
    }
  }
  if (changed) markSiteDirty(state);
}

function configuredSyslogSourceList(state) {
  return state.sites
    .filter((s) => Boolean(s.monitorConfig?.syslog?.enabled))
    .map((s) => `${s.name}:${String(s.monitorConfig?.syslog?.sourceIp || '').trim()}`)
    .filter(Boolean)
    .slice(0, 20);
}

function handleUnmatchedSyslogPacket(state, {
  sourceIp = '',
  transport = 'udp',
  preview = '',
  firstMessage = '',
  packetLen = 0
} = {}) {
  const mode = String(transport || 'udp').toLowerCase() === 'tcp' ? 'tcp' : 'udp';
  const len = Math.max(0, Number(packetLen || 0));
  const src = String(sourceIp || '').trim();
  logTelemetry(state, {
    protocol: 'syslog',
    sourceIp: src,
    transport: mode,
    action: 'packet_unmatched',
    message: firstMessage || preview || '[binary syslog payload]',
    detail: `len=${len}`
  });
  const context = { preview };
  if (mode === 'udp') context.configured = configuredSyslogSourceList(state);
  logDiagnosticThrottled(state, `syslog:unmatched:${mode}:${src}`, 10000, {
    level: 'warn',
    scope: `collector.syslog.${mode}`,
    protocol: 'syslog',
    sourceIp: src,
    action: 'packet_unmatched',
    message: `Syslog ${mode.toUpperCase()} packet unmatched for source ${src || 'unknown'}`,
    detail: `len=${len}`,
    context
  });
}

function handleMatchedSyslogPacket(state, site, {
  sourceIp = '',
  transport = 'udp',
  preview = '',
  lines = [],
  packetLen = 0
} = {}) {
  const mode = String(transport || 'udp').toLowerCase() === 'tcp' ? 'tcp' : 'udp';
  const len = Math.max(0, Number(packetLen || 0));
  const src = String(sourceIp || '').trim();
  const rows = Array.isArray(lines) && lines.length ? lines : [preview || '[binary syslog payload]'];
  updateSyslogMetrics(state, site, Date.now(), src);
  for (const row of rows) {
    logSyslogStreamEvent(state, site, {
      sourceIp: src,
      transport: mode,
      message: row,
      packetLen: len
    });
    logTelemetry(state, {
      protocol: 'syslog',
      siteId: site.id,
      siteName: site.name,
      sourceIp: src,
      transport: mode,
      action: 'ingest',
      message: row,
      detail: `len=${len}`
    });
  }
  logDiagnosticThrottled(state, `syslog:ingest:${mode}:${site.id}`, 10000, {
    level: 'debug',
    scope: `collector.syslog.${mode}`,
    protocol: 'syslog',
    siteId: site.id,
    siteName: site.name,
    sourceIp: src,
    action: 'packet_ingest',
    message: `Syslog ${mode.toUpperCase()} ingested for ${site.name}`,
    detail: `len=${len}`,
    context: { preview }
  });
}

// ── SNMP / Ping ───────────────────────────────────────────────────────────────
const fs = require('fs');
const os = require('os');
const path = require('path');

/**
 * Build the shared SNMP execution context (args, exec options, temp config,
 * cleanup callback) used by both snmpget and snmpwalk.
 *
 * @param {object} config       SNMP credential / target config
 * @param {object} opts
 * @param {string[]} opts.trailingArgs  Args appended after the version/credential flags
 * @param {string[]} [opts.extraFlags]  Extra CLI flags inserted before trailingArgs (e.g. ['-Oqn'])
 * @param {object}   [opts.execOverrides] Extra properties merged into execOpts (e.g. { maxBuffer })
 * @returns {{ args: string[], execOpts: object, tmpConfPath: string, cleanup: () => void }}
 * @throws {Error} if required fields are missing
 */
function buildSnmpExecContext(config, { trailingArgs, extraFlags = [], execOverrides = {} } = {}) {
  const host = config.targetHost;
  if (!host) throw new Error('targetHost missing');

  let tmpConfPath = '';
  let args;
  const execOpts = { timeout: 12000, ...execOverrides };

  if (config.version === '3') {
    if (!config.authUser) throw new Error('SNMPv3 authUser missing');
    const privProto = /^AES/i.test(String(config.privProtocol || '')) ? 'AES' : 'DES';
    const authProto = /^MD5/i.test(String(config.authProtocol || '')) ? 'MD5' : 'SHA';
    const confLines = [
      `defSecurityName ${config.authUser}`,
      `defAuthType ${authProto}`,
      `defAuthPassphrase ${config.authPassword || ''}`,
    ];
    if (config.privPassword) {
      confLines.push(`defSecurityLevel authPriv`);
      confLines.push(`defPrivType ${privProto}`);
      confLines.push(`defPrivPassphrase ${config.privPassword}`);
      args = ['-v3', '-l', 'authPriv', ...extraFlags, ...trailingArgs];
    } else {
      confLines.push(`defSecurityLevel authNoPriv`);
      args = ['-v3', '-l', 'authNoPriv', ...extraFlags, ...trailingArgs];
    }
    tmpConfPath = path.join(os.tmpdir(), `.cajal-snmp-${Date.now()}-${Math.random().toString(36).slice(2)}`);
    fs.mkdirSync(tmpConfPath, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(tmpConfPath, 'snmp.conf'), confLines.join('\n'), { mode: 0o600 });
    execOpts.env = { ...process.env, SNMPCONFPATH: tmpConfPath };
  } else if (config.version === '1') {
    args = ['-v1', '-c', config.communityString || '', ...extraFlags, ...trailingArgs];
  } else {
    args = ['-v2c', '-c', config.communityString || '', ...extraFlags, ...trailingArgs];
  }

  const cleanup = () => {
    if (tmpConfPath) {
      try { fs.rmSync(tmpConfPath, { recursive: true, force: true }); } catch (_) {}
    }
  };

  return { args, execOpts, tmpConfPath, cleanup };
}

function runSnmpGet(config) {
  return new Promise((resolve, reject) => {
    let ctx;
    try {
      ctx = buildSnmpExecContext(config, {
        trailingArgs: [config.targetHost, '1.3.6.1.2.1.1.3.0'],
      });
    } catch (e) {
      return reject(e);
    }

    execFile('snmpget', ctx.args, ctx.execOpts, (err, stdout, stderr) => {
      ctx.cleanup();
      if (err) return reject(new Error(stderr.trim() || err.message));
      // Device responded but OID not supported — treat uptime as unavailable
      if (/No Such Object|No Such Instance|noSuchObject|noSuchInstance/i.test(stdout)) return resolve(null);
      // Try parenthesised timeticks: "Timeticks: (12345) 0:02:03.45"
      const matchParen = stdout.match(/\((\d+)\)/);
      if (matchParen) return resolve(Number(matchParen[1]));
      // Fallback: bare timeticks: "Timeticks: 12345"
      const matchBare = stdout.match(/Timeticks:\s*(\d+)/i);
      if (matchBare) return resolve(Number(matchBare[1]));
      return reject(new Error(`Unexpected snmpget output: ${stdout.trim().slice(0, 120)}`));
    });
  });
}

function runSnmpWalk(config, oid) {
  return new Promise((resolve, reject) => {
    let ctx;
    try {
      ctx = buildSnmpExecContext(config, {
        trailingArgs: [config.targetHost, oid],
        extraFlags: ['-Oqn'],
        execOverrides: { timeout: 15000, maxBuffer: 512 * 1024 },
      });
    } catch (e) {
      return reject(e);
    }

    execFile('snmpwalk', ctx.args, ctx.execOpts, (err, stdout, stderr) => {
      ctx.cleanup();
      if (err) return reject(new Error(stderr.trim() || err.message));
      resolve(stdout);
    });
  });
}

const IFTABLE_OID = '1.3.6.1.2.1.2.2.1';
const IF_DESCR     = '.1.3.6.1.2.1.2.2.1.2.';
const IF_SPEED     = '.1.3.6.1.2.1.2.2.1.5.';
const IF_OPER      = '.1.3.6.1.2.1.2.2.1.8.';
const IF_IN_OCT    = '.1.3.6.1.2.1.2.2.1.10.';
const IF_OUT_OCT   = '.1.3.6.1.2.1.2.2.1.16.';

function parseIfTableWalk(stdout) {
  const interfaces = new Map(); // ifIndex -> { ifDescr, ifSpeed, ifOperStatus, ifInOctets, ifOutOctets }
  for (const line of stdout.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const spaceIdx = trimmed.indexOf(' ');
    if (spaceIdx < 0) continue;
    const oid = trimmed.substring(0, spaceIdx);
    const val = trimmed.substring(spaceIdx + 1).trim();

    let idx;
    if (oid.startsWith(IF_DESCR)) {
      idx = Number(oid.substring(IF_DESCR.length));
      if (!interfaces.has(idx)) interfaces.set(idx, { ifIndex: idx });
      interfaces.get(idx).ifDescr = val.replace(/^"|"$/g, '');
    } else if (oid.startsWith(IF_SPEED)) {
      idx = Number(oid.substring(IF_SPEED.length));
      if (!interfaces.has(idx)) interfaces.set(idx, { ifIndex: idx });
      interfaces.get(idx).ifSpeed = Number(val) || 0;
    } else if (oid.startsWith(IF_OPER)) {
      idx = Number(oid.substring(IF_OPER.length));
      if (!interfaces.has(idx)) interfaces.set(idx, { ifIndex: idx });
      interfaces.get(idx).ifOperStatus = Number(val) === 1 ? 'up' : 'down';
    } else if (oid.startsWith(IF_IN_OCT)) {
      idx = Number(oid.substring(IF_IN_OCT.length));
      if (!interfaces.has(idx)) interfaces.set(idx, { ifIndex: idx });
      interfaces.get(idx).ifInOctets = Number(val) || 0;
    } else if (oid.startsWith(IF_OUT_OCT)) {
      idx = Number(oid.substring(IF_OUT_OCT.length));
      if (!interfaces.has(idx)) interfaces.set(idx, { ifIndex: idx });
      interfaces.get(idx).ifOutOctets = Number(val) || 0;
    }
  }
  return [...interfaces.values()].map((iface) => ({
    ifIndex: iface.ifIndex || 0,
    ifDescr: iface.ifDescr || `if${iface.ifIndex}`,
    ifSpeed: iface.ifSpeed || 0,
    ifOperStatus: iface.ifOperStatus || 'down',
    ifInOctets: iface.ifInOctets || 0,
    ifOutOctets: iface.ifOutOctets || 0
  }));
}

// Compute bandwidth deltas from two consecutive polls
function computeInterfaceDeltas(current, previous, elapsedMs) {
  if (!previous || !previous.length || elapsedMs <= 0) return current.map((iface) => ({ ...iface, inMbps: 0, outMbps: 0, totalMbps: 0, utilization: 0 }));
  const prevMap = new Map(previous.map((p) => [p.ifIndex, p]));
  const elapsedSec = elapsedMs / 1000;
  return current.map((iface) => {
    const prev = prevMap.get(iface.ifIndex);
    if (!prev) return { ...iface, inMbps: 0, outMbps: 0, totalMbps: 0, utilization: 0 };
    // Handle 32-bit counter wrap (max ~4.29 GB)
    let inDelta = iface.ifInOctets - prev.ifInOctets;
    let outDelta = iface.ifOutOctets - prev.ifOutOctets;
    if (inDelta < 0) inDelta += 4294967296;
    if (outDelta < 0) outDelta += 4294967296;
    const inMbps = Number(((inDelta * 8) / (elapsedSec * 1000000)).toFixed(3));
    const outMbps = Number(((outDelta * 8) / (elapsedSec * 1000000)).toFixed(3));
    const totalMbps = Number((inMbps + outMbps).toFixed(3));
    const utilization = iface.ifSpeed > 0 ? Number((((inDelta + outDelta) * 8 * 100) / (elapsedSec * iface.ifSpeed)).toFixed(1)) : 0;
    return { ...iface, inMbps, outMbps, totalMbps, utilization: Math.min(utilization, 100) };
  });
}

function runPing(host) {
  return new Promise((resolve) => {
    if (!host) return resolve(false);
    execFile('ping', ['-c', '1', '-W', '1', host], { timeout: 6000 }, (err) => {
      resolve(!err);
    });
  });
}

function runPingStats(host) {
  return new Promise((resolve) => {
    if (!host) return resolve({ ok: false, latencyMs: null });
    execFile('ping', ['-c', '3', '-W', '1', host], { timeout: 9000 }, (err, stdout = '') => {
      if (err) return resolve({ ok: false, latencyMs: null });
      const match = stdout.match(/=\s*([\d.]+)\/([\d.]+)\/([\d.]+)\/([\d.]+)/);
      if (!match) return resolve({ ok: true, latencyMs: null });
      resolve({ ok: true, latencyMs: Number(match[2]) });
    });
  });
}

// ── Uptime tracking ───────────────────────────────────────────────────────────
function appendUptimeSample(site, isUp, now, samplesKey = 'uptimeSamples') {
  site.metrics = site.metrics || {};
  const samples = Array.isArray(site.metrics[samplesKey]) ? site.metrics[samplesKey] : [];
  samples.push({ ts: now, up: isUp ? 1 : 0 });
  const cutoff = now - 14 * 24 * 60 * 60 * 1000;
  site.metrics[samplesKey] = samples.filter((s) => Number(s.ts) >= cutoff).slice(-5000);
}

function currentHeartbeatFreshWindowMs() {
  const runtimeSettings = shared.runtimeSettings;
  const configuredFlowTimeout = Number(runtimeSettings?.flowTimeoutMs || FLOW_TIMEOUT_MS);
  const configuredPingInterval = Number(runtimeSettings?.pingIntervalMs || PING_INTERVAL_MS);
  const flowTimeoutMs = Number.isFinite(configuredFlowTimeout) && configuredFlowTimeout > 0
    ? configuredFlowTimeout
    : FLOW_TIMEOUT_MS;
  const pingIntervalMs = Number.isFinite(configuredPingInterval) && configuredPingInterval > 0
    ? configuredPingInterval
    : PING_INTERVAL_MS;
  return Math.max(60 * 1000, flowTimeoutMs, pingIntervalMs * 2);
}

function deriveUptime14d(site, now, samplesKey = 'uptimeSamples', outKey = 'uptime14d', fallbackKey = 'uptime14d') {
  site.metrics = site.metrics || {};
  const samples = Array.isArray(site.metrics[samplesKey]) ? site.metrics[samplesKey] : [];
  const fallback = Array.isArray(site.metrics[fallbackKey]) ? site.metrics[fallbackKey].slice(-14) : [];
  const dayMs = 24 * 60 * 60 * 1000;
  const oldestDay = new Date(now - 13 * dayMs);
  oldestDay.setHours(0, 0, 0, 0);
  const rangeStart = oldestDay.getTime();
  const rangeEnd = rangeStart + 14 * dayMs;
  const counts = new Array(14).fill(0);
  const ups = new Array(14).fill(0);

  for (const sample of samples) {
    const ts = Number(sample?.ts);
    if (!Number.isFinite(ts) || ts < rangeStart || ts >= rangeEnd) continue;
    const index = Math.floor((ts - rangeStart) / dayMs);
    if (index < 0 || index > 13) continue;
    counts[index] += 1;
    ups[index] += sample?.up ? 1 : 0;
  }

  const out = [];
  for (let i = 0; i < 14; i += 1) {
    if (!counts[i]) {
      out.push(Number(fallback[i] ?? 100));
      continue;
    }
    out.push(Number(((ups[i] / counts[i]) * 100).toFixed(2)));
  }
  site.metrics[outKey] = out;
}

// ── WAN test slots ────────────────────────────────────────────────────────────
function wanTestSlotHourFromTimestamp(ts = Date.now()) {
  const nowMs = Number(ts);
  const date = new Date(Number.isFinite(nowMs) ? nowMs : Date.now());
  return Math.floor(Math.max(0, Math.min(23, date.getHours())) / 4) * 4;
}

function wanTestSlotLabelFromTimestamp(ts = Date.now()) {
  const slotHour = wanTestSlotHourFromTimestamp(ts);
  return WAN_TEST_SLOT_LABEL_BY_HOUR[slotHour] || `${slotHour}:00`;
}

function nextWanTestSlotTimestamp(nowTs = Date.now()) {
  const nowMs = Number(nowTs);
  const now = Number.isFinite(nowMs) ? nowMs : Date.now();
  const next = new Date(now);
  next.setMinutes(0, 0, 0);
  const floorHour = Math.floor(next.getHours() / 4) * 4;
  next.setHours(floorHour, 0, 0, 0);
  if (next.getTime() < now) {
    next.setTime(next.getTime() + WAN_TEST_SLOT_INTERVAL_MS);
  }
  return next.getTime();
}

function appendWanTest(site, result, now) {
  site.metrics = site.metrics || {};
  const list = Array.isArray(site.metrics.wanTests) ? site.metrics.wanTests : [];
  const slotHourRaw = Number(result?.slotHour);
  const slotHour = Number.isFinite(slotHourRaw)
    ? Math.max(0, Math.min(20, Math.floor(slotHourRaw / 4) * 4))
    : wanTestSlotHourFromTimestamp(now);
  const fallbackSlotLabel = WAN_TEST_SLOT_LABEL_BY_HOUR[slotHour] || wanTestSlotLabelFromTimestamp(now);
  const slotLabel = String(result?.slotLabel || '').trim() || fallbackSlotLabel;
  const slotLabelUpper = String(slotLabel || '').trim().toUpperCase();
  const filtered = list.filter((row) => {
    const existingSlotHourRaw = Number(row?.slotHour);
    if (Number.isFinite(existingSlotHourRaw)) {
      const existingSlotHour = Math.max(0, Math.min(20, Math.floor(existingSlotHourRaw / 4) * 4));
      return existingSlotHour !== slotHour;
    }
    const existingSlotLabel = String(row?.slotLabel || '').trim().toUpperCase();
    return existingSlotLabel !== slotLabelUpper;
  });
  filtered.unshift({
    timestamp: new Date(now).toISOString(),
    downloadMbps: result.downloadMbps == null ? 'n/a' : result.downloadMbps,
    uploadMbps: result.uploadMbps == null ? 'n/a' : result.uploadMbps,
    latencyMs: result.latencyMs == null ? 'n/a' : Number(result.latencyMs.toFixed ? result.latencyMs.toFixed(1) : result.latencyMs),
    publicIp: String(result?.publicIp || '').trim(),
    slotHour,
    slotLabel
  });
  site.metrics.wanTests = filtered.slice(0, WAN_TEST_HISTORY);
}

// ── Speedtest / public IP normalization ───────────────────────────────────────
function extractSpeedtestMetricsFromLines(lines = []) {
  const rows = Array.isArray(lines) ? lines : [];
  let downloadMbps = null;
  let uploadMbps = null;
  let latencyMs = null;
  let publicIp = '';
  let target = '';

  for (const line of rows) {
    const raw = String(line || '').trim();
    const lower = raw.toLowerCase();

    // Target line: "Speed test snapshot for target <host>"
    const targetMatch = lower.match(/^speed test snapshot for target\s+(.+)$/);
    if (targetMatch) {
      target = raw.slice(raw.toLowerCase().indexOf('target ') + 7).trim();
      continue;
    }

    // Metrics line: "down=X Mbps up=X Mbps latency=X ms" (space separated tokens)
    const downMatch = lower.match(/(?:^|\s)down=([\d.]+)\s*mbps/);
    const upMatch = lower.match(/(?:^|\s)up=([\d.]+)\s*mbps/);
    const latencyMatch = lower.match(/(?:^|\s)latency=([\d.]+)\s*ms/);

    if (downMatch) {
      const val = Number(downMatch[1]);
      if (Number.isFinite(val) && val >= 0) downloadMbps = val;
    }
    if (upMatch) {
      const val = Number(upMatch[1]);
      if (Number.isFinite(val) && val >= 0) uploadMbps = val;
    }
    if (latencyMatch) {
      const val = Number(latencyMatch[1]);
      if (Number.isFinite(val) && val >= 0) latencyMs = val;
    }

    // Public IP line: "public_ip=X" or "publicip=X" or "ip=X"
    const ipMatch = raw.match(/^(?:public_ip|publicip|ip)=(.+)$/i);
    if (ipMatch) {
      const rawIp = ipMatch[1].trim();
      if (net.isIP(rawIp)) publicIp = rawIp;
    }

    // Target as key=value: "target=X"
    const targetKv = raw.match(/^target=(.+)$/i);
    if (targetKv && !target) {
      target = targetKv[1].trim();
    }
  }

  return { downloadMbps, uploadMbps, latencyMs, publicIp, target };
}

function extractPublicIpFromLines(lines = []) {
  const rows = Array.isArray(lines) ? lines : [];
  for (const line of rows) {
    const row = String(line || '').trim();
    // Format: "public_ip=X" or "publicip=X" or "ip=X"
    const ipKv = row.match(/^(?:public_ip|publicip|ip)=(.+)$/i);
    if (ipKv) {
      const rawIp = ipKv[1].trim();
      if (net.isIP(rawIp)) return rawIp;
    }
    // Plain IP on its own line
    if (net.isIP(row)) return row;
  }
  return '';
}

function normalizeCollectorSpeedtestMetrics(result = {}) {
  const lines = Array.isArray(result?.lines) ? result.lines : [];
  const parsed = extractSpeedtestMetricsFromLines(lines);

  // Read from metrics.speedtest (primary) or metrics (fallback) or parsed lines
  const inputMetrics = result?.metrics && typeof result.metrics === 'object' ? result.metrics : {};
  const speed = inputMetrics?.speedtest && typeof inputMetrics.speedtest === 'object' ? inputMetrics.speedtest : {};

  const downloadMbpsRaw = parsed.downloadMbps != null ? parsed.downloadMbps
    : (speed.downloadMbps != null ? Number(speed.downloadMbps) : null);
  const uploadMbpsRaw = parsed.uploadMbps != null ? parsed.uploadMbps
    : (speed.uploadMbps != null ? Number(speed.uploadMbps) : null);
  const latencyMsRaw = parsed.latencyMs != null ? parsed.latencyMs
    : (speed.latencyMs != null ? Number(speed.latencyMs) : null);
  const publicIpRaw = parsed.publicIp
    || String(speed.publicIp || '').trim()
    || extractPublicIpFromLines(lines);
  const target = parsed.target || String(speed.target || '').trim();

  return {
    downloadMbps: (downloadMbpsRaw != null && Number.isFinite(downloadMbpsRaw)) ? downloadMbpsRaw : null,
    uploadMbps: (uploadMbpsRaw != null && Number.isFinite(uploadMbpsRaw)) ? uploadMbpsRaw : null,
    latencyMs: (latencyMsRaw != null && Number.isFinite(latencyMsRaw)) ? latencyMsRaw : null,
    publicIp: net.isIP(publicIpRaw) ? publicIpRaw : '',
    target
  };
}

function normalizeCollectorPublicIpMetrics(result = {}) {
  const lines = Array.isArray(result?.lines) ? result.lines : [];
  const inputMetrics = result?.metrics && typeof result.metrics === 'object' ? result.metrics : {};
  const speed = inputMetrics?.speedtest && typeof inputMetrics.speedtest === 'object' ? inputMetrics.speedtest : {};
  const speedPublicIp = String(speed.publicIp || '').trim();
  const rawPublicIp = String(inputMetrics.publicIp || '').trim();
  const metricsPublicIp = net.isIP(rawPublicIp) ? rawPublicIp : '';
  const speedMetricPublicIp = net.isIP(speedPublicIp) ? speedPublicIp : '';
  const fromLines = extractPublicIpFromLines(lines);
  return {
    publicIp: metricsPublicIp || speedMetricPublicIp || fromLines || ''
  };
}

// ── Site status ───────────────────────────────────────────────────────────────
function deriveSiteStatus(state, site) {
  const hb = state.pingState.get(site.id);
  const configuredProtocols = ['syslog', 'snmp', 'netflow'].filter((protocol) => Boolean(site.monitorConfig?.[protocol]?.enabled));
  if (hb === false) return 'down';
  if (hb === true) {
    if (!configuredProtocols.length) return 'up';
    const flowingCount = configuredProtocols.filter((protocol) => site.telemetry?.[protocol] === true).length;
    if (flowingCount === configuredProtocols.length) return 'up';
    return 'warn';
  }
  return String(site.firewall?.status || 'down').trim().toLowerCase();
}

// ── Dependency detection ──────────────────────────────────────────────────────
async function detectSnmpgetDependency() {
  const version = await runExecFile('snmpget', ['--version'], 4000);
  if (!version.err) {
    const which = await runExecFile('which', ['snmpget'], 3000);
    const pathValue = which.err ? 'snmpget' : which.stdout.trim();
    return {
      available: true,
      path: pathValue || 'snmpget',
      detail: (version.stdout || version.stderr || '').split('\n')[0].trim()
    };
  }
  const which = await runExecFile('which', ['snmpget'], 3000);
  const detail = (version.stderr || version.err?.message || 'snmpget not found').trim();
  return {
    available: false,
    path: which.err ? '' : which.stdout.trim(),
    detail
  };
}

async function detectSmtpDependency(config) {
  const smtpConfig = config !== undefined ? config : SMTP_TRANSPORT_CONFIG;
  const validation = validateSmtpTransportConfig(smtpConfig);
  if (!validation.ok) {
    return {
      available: false,
      path: smtpTransportLabel(smtpConfig),
      detail: validation.detail,
      probeOk: false,
      mode: 'smtp',
      host: smtpConfig.host,
      port: smtpConfig.port,
      secure: smtpConfig.secure,
      starttls: smtpConfig.starttls,
      authEnabled: Boolean(smtpConfig.user)
    };
  }
  const probe = await runSmtpConnectionProbe(smtpConfig);
  const authText = smtpConfig.user ? `auth user ${smtpConfig.user}` : 'no auth';
  const tlsText = smtpConfig.secure ? 'implicit TLS' : `STARTTLS ${smtpConfig.starttls}`;
  const baseDetail = `${tlsText}; ${authText}`;
  return {
    available: true,
    path: smtpTransportLabel(smtpConfig),
    detail: probe.ok
      ? `${baseDetail}; ${probe.detail || 'connection probe ok'}`
      : `${baseDetail}; ${probe.detail || 'connection probe failed'}`,
    probeOk: probe.ok,
    mode: 'smtp',
    host: smtpConfig.host,
    port: smtpConfig.port,
    secure: smtpConfig.secure,
    starttls: smtpConfig.starttls,
    authEnabled: Boolean(smtpConfig.user)
  };
}

async function detectSendmailDependency() {
  const which = await runExecFile('which', ['sendmail'], 3000);
  if (which.err) {
    return {
      available: false,
      path: '',
      detail: String(which.stderr || which.err?.message || 'sendmail not found').trim(),
      probeOk: false,
      mode: 'sendmail',
      host: '',
      port: 0,
      secure: false,
      starttls: 'off',
      authEnabled: false
    };
  }

  const pathValue = String(which.stdout || '').trim() || 'sendmail';
  const probe = await runExecFile(pathValue, ['-d0.1', '-bv', 'postmaster'], 5000);
  const probeDetail = splitNonEmptyLines(`${probe.stdout}\n${probe.stderr}`)[0] || '';
  return {
    available: true,
    path: pathValue,
    detail: probeDetail || 'sendmail available',
    probeOk: !probe.err,
    mode: 'sendmail',
    host: '',
    port: 0,
    secure: false,
    starttls: 'off',
    authEnabled: false
  };
}

// ── Webhook helpers ───────────────────────────────────────────────────────────
function effectiveTeamsWebhookConfig(config) {
  const cfg = config !== undefined ? config : shared.runtimeSettings;
  const fromRuntime = normalizeTeamsWebhookUrl(cfg?.teamsWebhookUrl || '');
  const fromDefault = normalizeTeamsWebhookUrl(DEFAULT_TEAMS_WEBHOOK_URL);
  const url = fromRuntime || fromDefault;
  const timeoutMs = normalizeTeamsWebhookTimeoutMs(
    cfg?.teamsWebhookTimeoutMs,
    DEFAULT_TEAMS_WEBHOOK_TIMEOUT_MS
  );
  return { url, timeoutMs };
}

function buildWebhookRouteTestPayload(routeId = '') {
  const id = String(routeId || '').trim().toLowerCase();
  const route = WEBHOOK_ROUTE_MAP.get(id);
  const ts = new Date().toISOString();
  const label = String(route?.label || id || 'Webhook Route').trim();
  const signal = String(route?.signal || 'warn').trim().toLowerCase();
  const signalLabel = signal === 'offline' ? 'OFFLINE' : (signal === 'restore' ? 'RESTORE' : 'WARN');
  return {
    title: `[CAJAL TEST] ${label}`,
    group: id || 'webhook_route_test',
    message: `Sample ${signalLabel} webhook alert.\nRoute: ${id || 'unknown'}\nLabel: ${label}\nTimestamp: ${ts}`
  };
}

function collectorLatestWanPublicIp(site = null) {
  const direct = String(site?.metrics?.wanDetectedPublicIp || '').trim();
  if (net.isIP(direct)) return direct;
  const wanTests = Array.isArray(site?.metrics?.wanTests) ? site.metrics.wanTests : [];
  for (const row of wanTests) {
    const ip = String(row?.publicIp || '').trim();
    if (net.isIP(ip)) return ip;
  }
  return '';
}

function buildWebhookTemplateContextForStatus({
  site = null,
  previousStatus = '',
  nextStatus = '',
  locationName = '',
  reason = '',
  detail = '',
  timestamp = '',
  routeId = '',
  routeLabel = '',
  section = '',
  signal = ''
} = {}) {
  const ts = String(timestamp || new Date().toISOString());
  const prev = String(previousStatus || 'unknown').trim();
  const next = String(nextStatus || 'unknown').trim();
  const wanPublicIpCurrent = collectorLatestWanPublicIp(site) || 'N/A';
  return {
    status: next.toUpperCase(),
    statusLower: next.toLowerCase(),
    previousStatus: prev.toUpperCase(),
    previousStatusLower: prev.toLowerCase(),
    siteName: String(site?.name || '').trim() || 'Unknown site',
    siteRole: normalizeRole(site?.role || ''),
    firewallName: String(site?.firewall?.name || '').trim() || 'Unknown firewall',
    wanIp: String(site?.firewall?.wanIp || '').trim() || 'N/A',
    wanIp2: String(site?.firewall?.wanIp2 || '').trim() || 'N/A',
    wanPublicIpCurrent,
    wanPublicIp: wanPublicIpCurrent,
    locationName: String(locationName || locationNameForSite(site) || '').trim() || 'Unknown location',
    reason: String(reason || '').trim(),
    detail: String(detail || '').trim(),
    timestamp: ts,
    routeId: String(routeId || '').trim(),
    routeLabel: String(routeLabel || '').trim(),
    section: String(section || '').trim(),
    signal: String(signal || '').trim()
  };
}

function buildWebhookTemplateContextForRouteTest(routeId = '') {
  const id = String(routeId || '').trim().toLowerCase();
  const route = WEBHOOK_ROUTE_MAP.get(id);
  const signal = String(route?.signal || 'warn').trim().toLowerCase();
  const previousStatus = signal === 'restore' ? 'down' : 'up';
  const nextStatus = signal === 'offline' ? 'down' : (signal === 'restore' ? 'up' : 'warn');
  const context = buildWebhookTemplateContextForStatus({
    site: {
      name: 'Example Site',
      role: route?.section === 'collectors' ? 'collector' : (route?.section === 'other' ? 'other' : 'firewall'),
      firewall: { name: 'Example Firewall', wanIp: '203.0.113.10', wanIp2: '198.51.100.10' },
      metrics: { wanDetectedPublicIp: '198.51.100.10' }
    },
    previousStatus,
    nextStatus,
    locationName: 'Sample Location',
    reason: 'route_test',
    detail: `Simulated ${String(route?.label || id || 'webhook route').trim()} notification`,
    timestamp: new Date().toISOString(),
    routeId: id,
    routeLabel: String(route?.label || '').trim(),
    section: String(route?.section || '').trim(),
    signal
  });
  if (id === 'collector_wan_failover') {
    context.wanPublicIpPrevious = '203.0.113.10';
    context.wanPublicIpCurrent = '198.51.100.10';
    context.wanPublicIp = context.wanPublicIpCurrent;
  }
  return context;
}

// ── System dependency signal ──────────────────────────────────────────────────
function systemDependencySignal(state) {
  const dep = state?.dependencies?.smtp || {};
  if (!dep.available) return 'offline';
  if (dep.probeOk === false) return 'warn';
  return 'restore';
}

// ── Public service / location ping state ──────────────────────────────────────
function initialPublicServiceState() {
  const runtimeSettings = shared.runtimeSettings;
  const internalDnsTarget = String(runtimeSettings?.internalDnsTarget || '').trim();
  return [...PUBLIC_SERVICE_TARGETS, { id: 'internal-dns', label: 'Internal DNS', target: internalDnsTarget }].map((row) => ({
    id: row.id,
    label: row.label,
    target: row.target,
    status: 'unknown',
    latencyMs: null,
    lastCheckedAt: '',
    lastError: ''
  }));
}

function locationPingMonitorDefinitions(settings) {
  const locationSettings = settings !== undefined ? settings : shared.locationSettings;
  const normalized = sanitizeLocationSettings(locationSettings);
  const defs = [];
  for (const section of normalized.sections || []) {
    const sectionId = String(section?.id || '').trim().toLowerCase();
    const sectionName = String(section?.name || sectionId || 'Location').trim() || 'Location';
    const monitors = Array.isArray(section?.pingMonitors) ? section.pingMonitors : [];
    for (const monitor of monitors.slice(0, Math.max(1, LOCATION_PING_MONITOR_MAX || 5))) {
      const monitorId = String(monitor?.id || '').trim().toLowerCase();
      const target = String(monitor?.target || '').trim();
      const label = String(monitor?.label || target || monitorId || 'Ping').trim() || 'Ping';
      if (!monitorId || !target) continue;
      defs.push({ sectionId, sectionName, monitorId, label, target });
    }
  }
  return defs;
}

function locationPingMonitorStateKey(sectionId = '', monitorId = '') {
  return `${String(sectionId || '').trim().toLowerCase()}:${String(monitorId || '').trim().toLowerCase()}`;
}

function initialLocationPingMonitorState(settings) {
  const locationSettings = settings !== undefined ? settings : shared.locationSettings;
  return locationPingMonitorDefinitions(locationSettings).map((row) => ({
    sectionId: row.sectionId,
    sectionName: row.sectionName,
    monitorId: row.monitorId,
    label: row.label,
    target: row.target,
    status: 'unknown',
    latencyMs: null,
    lastCheckedAt: '',
    lastError: ''
  }));
}

// ── Teams / mail dependency detection ────────────────────────────────────────
async function detectTeamsDependency() {
  const runtimeSettings = shared.runtimeSettings;
  const { url: webhook } = effectiveTeamsWebhookConfig(runtimeSettings);
  if (!webhook) {
    return {
      available: false,
      path: '',
      detail: 'Teams webhook is not configured in Settings or CAJAL_TEAMS_WEBHOOK_URL',
      probeOk: false,
      mode: 'teams',
      host: '',
      port: 0,
      secure: true,
      starttls: 'off',
      authEnabled: false
    };
  }
  let host = '';
  let port = 0;
  let secure = true;
  try {
    const parsed = new URL(webhook);
    host = String(parsed.host || '').trim();
    secure = parsed.protocol === 'https:';
    port = Number(parsed.port || (secure ? 443 : 80));
  } catch {
    // keep defaults
  }
  return {
    available: true,
    path: host || 'teams-webhook',
    detail: 'Teams webhook configured',
    probeOk: true,
    mode: 'teams',
    host,
    port: Number.isFinite(port) ? port : 0,
    secure,
    starttls: 'off',
    authEnabled: false
  };
}

async function detectMailDependency() {
  return detectTeamsDependency();
}

// ── Syslog / NetFlow collectors ───────────────────────────────────────────────
function startSyslogCollectors(state) {
  const udp = dgram.createSocket('udp4');
  udp.on('message', (msg, rinfo) => {
    const sourceIp = String(rinfo.address || '').trim();
    const preview = formatPacketPreview(msg);
    const lines = parseLinesFromBuffer(msg);
    const site = matchSiteBySourceIp(state, 'syslog', sourceIp);
    if (!site) {
      handleUnmatchedSyslogPacket(state, {
        sourceIp,
        transport: 'udp',
        preview,
        firstMessage: lines[0],
        packetLen: msg.length
      });
      return;
    }
    handleMatchedSyslogPacket(state, site, {
      sourceIp,
      transport: 'udp',
      preview,
      lines,
      packetLen: msg.length
    });
  });
  udp.on('error', (err) => logSystemError('syslog.udp', err));
  udp.bind(SYSLOG_UDP_PORT, () => {
    console.log(`Syslog UDP listening on ${SYSLOG_UDP_PORT}`);
  });

  const tcp = net.createServer((socket) => {
    const remoteIp = String(socket.remoteAddress || '').replace('::ffff:', '').trim();
    let tcpBuffer = Buffer.alloc(0);
    socket.on('error', (err) => {
      logDiagnosticThrottled(state, `syslog.tcp.socket:${remoteIp}`, 10000, {
        level: 'warn',
        scope: 'syslog.tcp.socket',
        protocol: 'syslog',
        transport: 'tcp',
        action: 'socket_error',
        message: `TCP syslog socket error from ${remoteIp}: ${err?.message || err}`,
        sourceIp: remoteIp
      });
    });
    socket.setTimeout(120000);
    socket.on('timeout', () => socket.destroy());
    socket.on('data', (chunk) => {
      tcpBuffer = Buffer.concat([tcpBuffer, chunk]);
      // Process complete newline-delimited syslog messages from the buffer
      let nlIndex;
      while ((nlIndex = tcpBuffer.indexOf(10)) !== -1) { // 10 = '\n'
        const messageBytes = tcpBuffer.subarray(0, nlIndex);
        tcpBuffer = tcpBuffer.subarray(nlIndex + 1);
        if (!messageBytes.length) continue;
        const sourceIp = String(socket.remoteAddress || '').replace('::ffff:', '').trim();
        const preview = formatPacketPreview(messageBytes);
        const lines = parseLinesFromBuffer(messageBytes);
        const site = matchSiteBySourceIp(state, 'syslog', sourceIp);
        if (!site) {
          handleUnmatchedSyslogPacket(state, {
            sourceIp,
            transport: 'tcp',
            preview,
            firstMessage: lines[0],
            packetLen: messageBytes.length
          });
          continue;
        }
        handleMatchedSyslogPacket(state, site, {
          sourceIp,
          transport: 'tcp',
          preview,
          lines,
          packetLen: messageBytes.length
        });
      }
      // Prevent unbounded buffer growth from malformed streams
      if (tcpBuffer.length > 64 * 1024) {
        tcpBuffer = tcpBuffer.subarray(tcpBuffer.length - 32 * 1024);
      }
    });
    socket.on('close', () => {
      // Flush any remaining data in the buffer on connection close
      if (tcpBuffer.length > 0) {
        const sourceIp = String(socket.remoteAddress || '').replace('::ffff:', '').trim();
        const preview = formatPacketPreview(tcpBuffer);
        const lines = parseLinesFromBuffer(tcpBuffer);
        const site = matchSiteBySourceIp(state, 'syslog', sourceIp);
        if (site) {
          handleMatchedSyslogPacket(state, site, { sourceIp, transport: 'tcp', preview, lines, packetLen: tcpBuffer.length });
        }
        tcpBuffer = Buffer.alloc(0);
      }
    });
  });
  tcp.on('error', (err) => logSystemError('syslog.tcp', err));
  tcp.listen(SYSLOG_TCP_PORT, () => {
    console.log(`Syslog TCP listening on ${SYSLOG_TCP_PORT}`);
  });

  setInterval(() => {
    decaySyslogMetrics(state);
  }, 1000);
}

function startNetflowCollector(state) {
  const socket = dgram.createSocket('udp4');
  socket.on('message', (msg, rinfo) => {
    const sourceIp = String(rinfo.address || '').trim();
    const version = msg.length >= 2 ? msg.readUInt16BE(0) : 0;
    const site = matchSiteBySourceIp(state, 'netflow', sourceIp);
    if (!site) {
      const enabledSites = state.sites
        .filter((s) => Boolean(s.monitorConfig?.netflow?.enabled))
        .map((s) => `${s.name}:${String(s.monitorConfig?.netflow?.sourceIp || '').trim()}`)
        .filter(Boolean);
      logTelemetry(state, {
        protocol: 'netflow',
        sourceIp,
        transport: 'udp',
        action: 'packet_unmatched',
        message: `NetFlow/IPFIX packet from ${sourceIp || 'unknown'}`,
        detail: `len=${msg.length} version=${version || 'unknown'}`
      });
      logDiagnosticThrottled(state, `netflow:unmatched:${sourceIp}:${version}`, 10000, {
        level: 'warn',
        scope: 'collector.netflow.udp',
        protocol: 'netflow',
        sourceIp,
        action: 'packet_unmatched',
        message: `NetFlow packet unmatched for source ${sourceIp || 'unknown'}`,
        detail: `len=${msg.length} version=${version || 'unknown'}`,
        context: { configured: enabledSites.slice(0, 20) }
      });
      return;
    }

    const cfg = site.monitorConfig?.netflow || {};
    const exporter = cfg.sourceIp || sourceIp;
    const templateKey = `${site.id}:${exporter}`;
    const templateMap = state.netflowTemplates.get(templateKey) || new Map();
    state.netflowTemplates.set(templateKey, templateMap);
    const now = Date.now();
    markNetflowSeen(state, site, now);

    const records = parseAnyNetflow(msg, templateMap);
    if (!records || !records.length) {
      site.metrics = site.metrics || {};
      site.metrics.netflow = site.metrics.netflow || {};
      const nextError = `No usable records (v${version || 'unknown'}, templates=${templateMap.size})`;
      if (site.metrics.netflow.lastError !== nextError) {
        site.metrics.netflow.lastError = nextError;
        site.metrics.netflow.lastErrorAt = new Date().toISOString();
        markSiteDirty(state);
      }
      logTelemetry(state, {
        protocol: 'netflow',
        siteId: site.id,
        siteName: site.name,
        sourceIp,
        transport: 'udp',
        action: 'packet_no_records',
        message: `NetFlow/IPFIX packet had no usable records for ${site.name}`,
        detail: `len=${msg.length} version=${version || 'unknown'} templates=${templateMap.size}`
      });
      logDiagnosticThrottled(state, `netflow:no_records:${site.id}:${version}`, 10000, {
        level: 'warn',
        scope: 'collector.netflow.udp',
        protocol: 'netflow',
        siteId: site.id,
        siteName: site.name,
        sourceIp,
        action: 'packet_no_records',
        message: `NetFlow/IPFIX packet produced no records for ${site.name}`,
        detail: `len=${msg.length} version=${version || 'unknown'} templates=${templateMap.size}`,
        context: {
          hint:
            version === 10
              ? 'IPFIX templates may not have arrived yet; exporter must send template sets before data sets.'
              : version === 9
                ? 'NetFlow v9 templates may not have arrived yet.'
                : version === 5
                  ? 'NetFlow v5 packet had no usable records.'
                  : 'Unsupported flow version.'
        }
      });
      return;
    }

    const talkers = state.netflowTalkers.get(site.id) || new Map();
    for (const rec of records) {
      const bytes = Math.max(0, Number(rec.bytes || 0));
      if (bytes <= 0) continue;
      const srcEvents = talkers.get(rec.srcAddr) || [];
      srcEvents.push({ ts: now, upBytes: bytes, downBytes: 0 });
      talkers.set(rec.srcAddr, srcEvents);
      const dstEvents = talkers.get(rec.dstAddr) || [];
      dstEvents.push({ ts: now, upBytes: 0, downBytes: bytes });
      talkers.set(rec.dstAddr, dstEvents);
    }
    state.netflowTalkers.set(site.id, talkers);
    refreshNetflowTopTalkers(state, site, now);
    site.metrics = site.metrics || {};
    site.metrics.netflow = site.metrics.netflow || {};
    if (site.metrics.netflow.lastError) {
      site.metrics.netflow.lastError = '';
      site.metrics.netflow.lastErrorAt = '';
    }
    const top = site.metrics?.netflow?.topTalkers?.[0];
    const sample = records.slice(0, Math.max(1, Math.min(TELEMETRY_NETFLOW_RECORDS_PER_PACKET, 500))).map((rec) => ({
      src: rec.srcAddr,
      dst: rec.dstAddr,
      bytes: rec.bytes
    }));
    logTelemetry(state, {
      protocol: 'netflow',
      siteId: site.id,
      siteName: site.name,
      sourceIp,
      transport: 'udp',
      action: 'ingest',
      message: `NetFlow/IPFIX ingest for ${site.name}`,
      detail: `records=${records.length} version=${version || 'unknown'} templates=${templateMap.size}${top ? ` top=${top.ip}:${top.mbps}Mbps` : ''}`,
      context: { sample }
    });
    logSiteEventThrottled(state, site, `netflow:${site.id}`, NETFLOW_EVENT_THROTTLE_MS, {
      classId: 321,
      source: 'netflow',
      actor: 'collector',
      action: 'netflow_ingest',
      message: `NetFlow ingest for ${site.name}`,
      detail: `records=${records.length} exporter=${exporter}${top ? ` top=${top.ip}:${top.mbps}Mbps` : ''}`
    });
    logDiagnosticThrottled(state, `netflow:ingest:${site.id}`, 10000, {
      level: 'debug',
      scope: 'collector.netflow.udp',
      protocol: 'netflow',
      siteId: site.id,
      siteName: site.name,
      sourceIp,
      action: 'packet_ingest',
      message: `NetFlow ingest for ${site.name}`,
      detail: `records=${records.length} version=${version || 'unknown'} templates=${templateMap.size}${top ? ` top=${top.ip}:${top.mbps}Mbps` : ''}`
    });
    markSiteDirty(state);
  });

  socket.on('error', (err) => logSystemError('netflow.collector', err));
  socket.bind(NETFLOW_PORT, () => {
    console.log(`NetFlow collector listening on ${NETFLOW_PORT}`);
  });
}

// ── Location ping monitors ────────────────────────────────────────────────────
async function pollLocationPingMonitors(state) {
  const locationSettings = shared.locationSettings;
  const defs = locationPingMonitorDefinitions(locationSettings);
  const previousByKey = new Map(
    (Array.isArray(state.locationPingMonitors) ? state.locationPingMonitors : [])
      .map((row) => [locationPingMonitorStateKey(row?.sectionId, row?.monitorId), String(row?.status || '').toLowerCase()])
      .filter(([key]) => Boolean(key))
  );
  const checks = await Promise.all(defs.map(async (row) => {
    const nowIso = new Date().toISOString();
    const target = String(row.target || '').trim();
    let latencyMs = null;
    let status = 'unknown';
    let lastError = '';
    if (target) {
      const startedAt = Date.now();
      const ok = await runPing(target);
      latencyMs = ok ? Math.max(1, Date.now() - startedAt) : null;
      status = ok ? 'up' : 'down';
      lastError = ok ? '' : 'No ping response';
    } else {
      status = 'unknown';
      lastError = 'Target not configured';
    }
    const key = locationPingMonitorStateKey(row.sectionId, row.monitorId);
    const previous = previousByKey.get(key);
    if (previous && previous !== status) {
      logEvent(state, {
        classId: 323,
        source: 'service',
        actor: 'collector',
        action: 'location_ping_monitor_state_change',
        message: `${row.sectionName} / ${row.label} ${status === 'up' ? 'reachable' : 'unreachable'}`,
        detail: `target=${target}${latencyMs != null ? ` latencyMs=${latencyMs}` : ''}`
      });
    }
    return {
      sectionId: row.sectionId,
      sectionName: row.sectionName,
      monitorId: row.monitorId,
      label: row.label,
      target,
      status,
      latencyMs,
      lastCheckedAt: nowIso,
      lastError
    };
  }));
  state.locationPingMonitors = checks;
}

async function pollPublicServices(state) {
  const runtimeSettings = shared.runtimeSettings;
  const nowIso = new Date().toISOString();
  const previousById = new Map(
    (Array.isArray(state.publicServices) ? state.publicServices : [])
      .map((row) => [String(row?.id || ''), String(row?.status || '').toLowerCase()])
      .filter(([id]) => Boolean(id))
  );
  const checks = [];
  const internalDnsTarget = String(runtimeSettings?.internalDnsTarget || '').trim();
  const serviceTargets = [...PUBLIC_SERVICE_TARGETS, { id: 'internal-dns', label: 'Internal DNS', target: internalDnsTarget }];
  for (const row of serviceTargets) {
    const target = String(row.target || '').trim();
    let latencyMs = null;
    let status = 'unknown';
    let lastError = '';
    if (target) {
      const startedAt = Date.now();
      const ok = await runPing(target);
      latencyMs = ok ? Math.max(1, Date.now() - startedAt) : null;
      status = ok ? 'up' : 'down';
      lastError = ok ? '' : 'No ping response';
    } else {
      status = 'unknown';
      lastError = 'Target not configured';
    }
    const previous = previousById.get(row.id);
    if (previous && previous !== status) {
      logEvent(state, {
        classId: 323,
        source: 'service',
        actor: 'collector',
        action: 'public_service_state_change',
        message: `${row.label} ${status === 'up' ? 'reachable' : 'unreachable'}`,
        detail: `target=${target || 'n/a'}${latencyMs != null ? ` latencyMs=${latencyMs}` : ''}`
      });
      const routeId = status === 'up' ? 'other_public_service_restore' : (status === 'down' ? 'other_public_service_offline' : '');
      if (routeId) {
        const routeMeta = WEBHOOK_ROUTE_MAP.get(routeId);
        const detail = `target=${target || 'n/a'}${latencyMs != null ? ` latencyMs=${latencyMs}` : ''}`;
        const context = buildWebhookTemplateContextForStatus({
          site: { name: row.label, role: 'other', firewall: { name: 'Public Service', wanIp: 'N/A', wanIp2: 'N/A' } },
          previousStatus: previous,
          nextStatus: status,
          locationName: 'System',
          reason: 'public_service_state_change',
          detail,
          timestamp: nowIso,
          routeId,
          routeLabel: routeMeta?.label || '',
          section: routeMeta?.section || '',
          signal: routeMeta?.signal || ''
        });
        context.serviceTarget = target || 'n/a';
        context.serviceLabel = row.label;
        const body = [
          `${row.label} is now ${status === 'up' ? 'reachable' : 'unreachable'}.`,
          `Previous status: ${String(previous || 'unknown').toUpperCase()}`,
          `Target: ${target || 'n/a'}`,
          `Latency: ${latencyMs != null ? `${latencyMs} ms` : 'n/a'}`,
          `Timestamp: ${nowIso}`
        ].join('\n');
        dispatchWebhookRouteNotification(state, {
          routeId,
          title: `[CAJAL SERVICE] ${row.label} ${status === 'up' ? 'RESTORED' : 'OFFLINE'}`,
          defaultMessage: body,
          context,
          source: 'service',
          actor: 'collector',
          action: 'public_service_state_change',
          respectSilence: true
        });
      }
    }
    checks.push({
      id: row.id,
      label: row.label,
      target,
      status,
      latencyMs,
      lastCheckedAt: nowIso,
      lastError
    });
  }
  state.publicServices = checks;
}

function startPublicServicePoller(state) {
  const poll = async () => {
    try {
      await pollPublicServices(state);
    } catch (err) {
      logSystemError('poller.public_services', err);
      if (!Array.isArray(state.publicServices) || !state.publicServices.length) {
        state.publicServices = initialPublicServiceState();
      }
    }
  };
  poll().catch((err) => logSystemError('poller.public_services.initial', err));
  setInterval(() => {
    poll().catch((err) => logSystemError('poller.public_services.interval', err));
  }, Math.max(15000, Number(PUBLIC_SERVICE_POLL_INTERVAL_MS) || 60000));
}

function startLocationPingMonitorPoller(state) {
  const locationSettings = shared.locationSettings;
  const poll = async () => {
    try {
      await pollLocationPingMonitors(state);
    } catch (err) {
      logSystemError('poller.location_ping_monitors', err);
      if (!Array.isArray(state.locationPingMonitors)) {
        state.locationPingMonitors = initialLocationPingMonitorState(locationSettings);
      }
    }
  };
  poll().catch((err) => logSystemError('poller.location_ping_monitors.initial', err));
  setInterval(() => {
    poll().catch((err) => logSystemError('poller.location_ping_monitors.interval', err));
  }, Math.max(15000, Number(LOCATION_PING_MONITOR_POLL_INTERVAL_MS) || 60000));
}

// ── Collector WAN probes ──────────────────────────────────────────────────────
async function runCollectorWanPublicIpProbe(state, site) {
  const presence = getCollectorAgentPresence(state, site?.id);
  if (!presence || !presence.connected) {
    return {
      ok: false,
      reason: 'agent_offline',
      source: 'none',
      publicIp: ''
    };
  }

  const { sanitizeToolsTerminalHostToken, collectorResultHasUnsupportedCommand } = require('./agent');
  const probe = await runCollectorAgentTerminalCommand(state, site, 'publicip');
  const parsed = normalizeCollectorPublicIpMetrics(probe);
  if (parsed.publicIp) {
    return {
      ok: Boolean(probe?.ok) || true,
      reason: 'agent_data',
      source: 'publicip',
      publicIp: parsed.publicIp
    };
  }
  if (!collectorResultHasUnsupportedCommand(probe, 'publicip')) {
    return {
      ok: false,
      reason: probe?.ok ? 'agent_no_public_ip' : 'agent_probe_failed',
      source: 'publicip',
      publicIp: ''
    };
  }

  const target = sanitizeToolsTerminalHostToken(site?.firewall?.wanIp) || '8.8.8.8';
  const fallback = await runCollectorAgentTerminalCommand(state, site, `speedtest ${target}`);
  const fallbackParsed = normalizeCollectorSpeedtestMetrics(fallback);
  return {
    ok: Boolean(fallback?.ok) || Boolean(fallbackParsed.publicIp),
    reason: fallbackParsed.publicIp ? 'agent_data_fallback' : (fallback?.ok ? 'agent_no_public_ip_fallback' : 'agent_probe_failed_fallback'),
    source: 'speedtest_fallback',
    publicIp: fallbackParsed.publicIp || ''
  };
}

async function runScheduledCollectorWanSpeedtest(state, site, target = '') {
  const { sanitizeToolsTerminalHostToken } = require('./agent');
  const safeTarget = sanitizeToolsTerminalHostToken(target || '8.8.8.8') || '8.8.8.8';
  const presence = getCollectorAgentPresence(state, site?.id);
  if (!presence || !presence.connected) {
    return {
      ok: false,
      reason: 'agent_offline',
      target: safeTarget,
      downloadMbps: null,
      uploadMbps: null,
      latencyMs: null
    };
  }
  const result = await runCollectorAgentTerminalCommand(state, site, `speedtest ${safeTarget}`);
  const parsed = normalizeCollectorSpeedtestMetrics(result);
  const hasData = parsed.downloadMbps != null || parsed.uploadMbps != null || parsed.latencyMs != null;
  return {
    ok: Boolean(result?.ok) || hasData,
    reason: hasData ? 'agent_data' : 'agent_no_data',
    target: parsed.target || safeTarget,
    downloadMbps: parsed.downloadMbps,
    uploadMbps: parsed.uploadMbps,
    latencyMs: parsed.latencyMs,
    publicIp: parsed.publicIp || ''
  };
}

// ── Ping poller ───────────────────────────────────────────────────────────────
function startPingPoller(state) {
  const poll = async () => {
    for (const site of state.sites) {
      site.heartbeatTarget = normalizeHeartbeatTarget(site.heartbeatTarget);
      site.heartbeatTarget2 = normalizeHeartbeatTarget(site.heartbeatTarget2 || 'wan2');
      const wan1Raw = String(site.firewall?.wanIp || '').trim();
      const wan2Raw = String(site.firewall?.wanIp2 || '').trim();
      const wan1Disabled = isLinkMarkedNone(wan1Raw) || isLinkMarkedNone(site.isp1);
      const wan2Disabled = isLinkMarkedNone(wan2Raw) || isLinkMarkedNone(site.isp2);
      const wanTargets = [
        { slot: 'wan1', host: wan1Disabled ? '' : wan1Raw, disabled: wan1Disabled },
        { slot: 'wan2', host: wan2Disabled ? '' : wan2Raw, disabled: wan2Disabled }
      ];

      let anyOk = false;
      for (const target of wanTargets) {
        const key = `${site.id}:${target.slot}`;
        if (target.disabled || !target.host) {
          state.wanPingState.set(key, null);
          continue;
        }
        const ok = await runPing(target.host);
        anyOk = anyOk || ok;
        const prev = state.wanPingState.get(key);
        if (prev !== undefined && prev !== ok) {
          logSiteEvent(state, site, {
            classId: 325,
            source: 'ping',
            actor: 'collector',
            action: 'wan_ping_state_change',
            message: `${site.name} ${target.slot.toUpperCase()} ${ok ? 'reachable' : 'unreachable'}`,
            detail: `target=${target.host}`
          });
        }
        state.wanPingState.set(key, ok);
        logSiteEventThrottled(state, site, `ping:${site.id}:${target.slot}`, 5 * 60 * 1000, {
          classId: 325,
          source: 'ping',
          actor: 'collector',
          action: 'wan_ping_poll',
          message: `${site.name} ${target.slot.toUpperCase()} ping ${ok ? 'ok' : 'failed'}`,
          detail: `target=${target.host}`
        });
      }

      const gatewayRaw = resolveSiteGatewayIp(state, site);
      const gatewayDisabled = isLinkMarkedNone(gatewayRaw);
      const gatewayKey = `${site.id}:gateway`;
      if (gatewayDisabled || !gatewayRaw) {
        state.wanPingState.set(gatewayKey, null);
        state.wanPingState.set(`${site.id}:internal`, null);
      } else {
        const gatewayOk = await runPing(gatewayRaw);
        const prevGateway = state.wanPingState.get(gatewayKey);
        if (prevGateway !== undefined && prevGateway !== gatewayOk) {
          logSiteEvent(state, site, {
            classId: 325,
            source: 'ping',
            actor: 'collector',
            action: 'gateway_ping_state_change',
            message: `${site.name} GATEWAY ${gatewayOk ? 'reachable' : 'unreachable'}`,
            detail: `target=${gatewayRaw}`
          });
        }
        state.wanPingState.set(gatewayKey, gatewayOk);
        // Keep backward-compatibility with historical "internal" slot naming.
        state.wanPingState.set(`${site.id}:internal`, gatewayOk);
        logSiteEventThrottled(state, site, `ping:${site.id}:gateway`, 5 * 60 * 1000, {
          classId: 325,
          source: 'ping',
          actor: 'collector',
          action: 'wan_ping_poll',
          message: `${site.name} GATEWAY ping ${gatewayOk ? 'ok' : 'failed'}`,
          detail: `target=${gatewayRaw}`
        });
      }

      const targetHosts = {
        wan1: String(site.firewall?.wanIp || '').trim(),
        wan2: String(site.firewall?.wanIp2 || '').trim(),
        gateway: gatewayRaw,
        // Keep legacy "internal" target value compatibility by mapping to gateway.
        internal: gatewayRaw
      };
      const selected = site.heartbeatTarget;
      const selected2 = site.heartbeatTarget2;
      const evaluateTarget = async (slot) => {
        const targetSlot = normalizeHeartbeatTarget(slot);
        if (targetSlot === 'wan1' || targetSlot === 'wan2') {
          return state.wanPingState.get(`${site.id}:${targetSlot}`) === true;
        }
        if (targetSlot === 'gateway' || targetSlot === 'internal') {
          return state.wanPingState.get(`${site.id}:gateway`) === true;
        }
        return false;
      };

      const ok = await evaluateTarget(selected);
      const ok2 = await evaluateTarget(selected2);
      site.metrics = site.metrics || {};
      site.metrics.heartbeat = site.metrics.heartbeat || {};
      const heartbeatMetrics = site.metrics.heartbeat;
      const failedTargets = [];
      const targetHost1 = targetHosts[normalizeHeartbeatTarget(selected)] || 'n/a';
      const targetHost2 = targetHosts[normalizeHeartbeatTarget(selected2)] || 'n/a';
      if (!ok) failedTargets.push(`Target 1 failed (${normalizeHeartbeatTarget(selected)}:${targetHost1})`);
      if (!ok2) failedTargets.push(`Target 2 failed (${normalizeHeartbeatTarget(selected2)}:${targetHost2})`);
      if (failedTargets.length) {
        const nextError = failedTargets.join(' | ');
        if (heartbeatMetrics.lastError !== nextError) {
          heartbeatMetrics.lastError = nextError;
          heartbeatMetrics.lastErrorAt = new Date().toISOString();
          markSiteDirty(state);
        }
      } else if (heartbeatMetrics.lastError) {
        heartbeatMetrics.lastError = '';
        heartbeatMetrics.lastErrorAt = '';
        markSiteDirty(state);
      }

      const prevSite = state.pingState.get(site.id);
      if (prevSite !== undefined && prevSite !== ok) {
        logSiteEvent(state, site, {
          classId: 323,
          source: 'ping',
          actor: 'collector',
          action: 'ping_state_change',
          message: `${site.name} ping ${ok ? 'reachable' : 'unreachable'}`
        });
        reconcileSiteStatus(
          state,
          site,
          'heartbeat_ping_change',
          `ping ${prevSite ? 'reachable' : 'unreachable'} -> ${ok ? 'reachable' : 'unreachable'}`
        );
      }
      state.pingState.set(site.id, ok);
      if (ok) {
        state.lastSeen.ping.set(site.id, Date.now());
      }
      if (ok2) {
        state.lastSeen.pingSecondary?.set(site.id, Date.now());
      }
      reconcileSiteStatus(state, site, 'heartbeat_ping_refresh');
    }
  };
  const loop = async (isInitial = false) => {
    try {
      await poll();
    } catch (err) {
      logSystemError(isInitial ? 'poller.ping.initial' : 'poller.ping.interval', err);
    } finally {
      const runtimeSettings = shared.runtimeSettings;
      const nextMs = Math.max(1000, Number(runtimeSettings?.pingIntervalMs || PING_INTERVAL_MS) || PING_INTERVAL_MS);
      setTimeout(() => {
        loop(false).catch((loopErr) => logSystemError('poller.ping.loop', loopErr));
      }, nextMs);
    }
  };
  loop(true).catch((err) => logSystemError('poller.ping.bootstrap', err));
}

// ── Uptime sampler ────────────────────────────────────────────────────────────
function startUptimeSampler(state) {
  const sample = () => {
    const now = Date.now();
    const freshnessWindowMs = currentHeartbeatFreshWindowMs();
    for (const site of state.sites) {
      const pingTs = state.lastSeen.ping.get(site.id) || 0;
      const pingTsSecondary = state.lastSeen.pingSecondary?.get(site.id) || 0;
      const isUp = pingTs > 0 && now - pingTs <= freshnessWindowMs;
      const isUpSecondary = pingTsSecondary > 0 && now - pingTsSecondary <= freshnessWindowMs;
      appendUptimeSample(site, isUp, now, 'uptimeSamples');
      appendUptimeSample(site, isUpSecondary, now, 'uptimeSamplesSecondary');
      deriveUptime14d(site, now, 'uptimeSamples', 'uptime14d', 'uptime14d');
      deriveUptime14d(site, now, 'uptimeSamplesSecondary', 'uptime14dSecondary', 'uptime14dSecondary');
    }
    markSiteDirty(state);
  };

  sample();
  setInterval(sample, UPTIME_SAMPLE_INTERVAL_MS);
}

// ── Collector WAN public IP poller ────────────────────────────────────────────
function seedCollectorWanPublicIpState(state) {
  if (!state.notificationState || typeof state.notificationState !== 'object') {
    state.notificationState = { systemDependencySignal: '', collectorWanPublicIp: {} };
  }
  if (!state.notificationState.collectorWanPublicIp || typeof state.notificationState.collectorWanPublicIp !== 'object') {
    state.notificationState.collectorWanPublicIp = {};
  }
  for (const site of state.sites || []) {
    if (normalizeRole(site?.role) !== 'collector') continue;
    const siteId = String(site?.id || '').trim();
    if (!siteId) continue;
    const ip = collectorLatestWanPublicIp(site);
    if (!ip) continue;
    state.notificationState.collectorWanPublicIp[siteId] = ip;
    site.metrics = site.metrics || {};
    if (String(site.metrics.wanDetectedPublicIp || '').trim() !== ip) {
      site.metrics.wanDetectedPublicIp = ip;
      markSiteDirty(state);
    }
  }
}

function startCollectorWanPublicIpPoller(state) {
  seedCollectorWanPublicIpState(state);
  const poll = async (reason = 'scheduled') => {
    const collectorSites = state.sites.filter((site) => normalizeRole(site?.role) === 'collector');
    for (const site of collectorSites) {
      const siteId = String(site?.id || '').trim();
      if (!siteId) continue;
      const probe = await runCollectorWanPublicIpProbe(state, site);
      const nextPublicIp = String(probe?.publicIp || '').trim();
      if (!nextPublicIp || !net.isIP(nextPublicIp)) continue;

      site.metrics = site.metrics || {};
      const previousKnown = String(site.metrics.wanDetectedPublicIp || '').trim();
      const previousStateKnown = String(state.notificationState?.collectorWanPublicIp?.[siteId] || '').trim();
      const previousPublicIp = previousKnown || previousStateKnown;

      if (previousKnown !== nextPublicIp) {
        site.metrics.wanDetectedPublicIp = nextPublicIp;
        markSiteDirty(state);
      }
      if (!state.notificationState.collectorWanPublicIp || typeof state.notificationState.collectorWanPublicIp !== 'object') {
        state.notificationState.collectorWanPublicIp = {};
      }
      state.notificationState.collectorWanPublicIp[siteId] = nextPublicIp;

      if (previousPublicIp && previousPublicIp !== nextPublicIp) {
        logSiteEvent(state, site, {
          classId: 324,
          source: 'collector',
          actor: 'collector-agent',
          action: 'collector_wan_public_ip_change',
          message: `${site.name} WAN public IP changed`,
          detail: `previous=${previousPublicIp} current=${nextPublicIp} source=${probe.source || 'publicip'} reason=${reason}:${probe.reason || 'unknown'}`
        });
        notifyCollectorWanFailover(state, site, previousPublicIp, nextPublicIp, probe.source || 'publicip');
      }
    }
  };

  poll('bootstrap').catch((err) => logSystemError('poller.collector_wan_public_ip.initial', err));
  setInterval(() => {
    poll('scheduled').catch((err) => logSystemError('poller.collector_wan_public_ip.interval', err));
  }, WAN_PUBLIC_IP_POLL_INTERVAL_MS);
}

// ── WAN test poller ───────────────────────────────────────────────────────────
function startWanTestPoller(state) {
  const { sanitizeToolsTerminalHostToken } = require('./agent');
  const siteNeedsWanPublicIp = (site) => {
    if (normalizeRole(site?.role) !== 'collector') return false;
    const rows = Array.isArray(site?.metrics?.wanTests) ? site.metrics.wanTests : [];
    if (rows.length < 1) return true;
    const latest = rows[0] && typeof rows[0] === 'object' ? rows[0] : null;
    return String(latest?.publicIp || '').trim().length < 1;
  };

  const poll = async (reason = 'scheduled') => {
    const now = Date.now();
    const slotHour = wanTestSlotHourFromTimestamp(now);
    const slotLabel = wanTestSlotLabelFromTimestamp(now);
    const collectorSites = state.sites.filter((site) => normalizeRole(site?.role) === 'collector');
    for (const site of collectorSites) {
      const target = sanitizeToolsTerminalHostToken(site.monitorConfig?.snmp?.targetHost)
        || sanitizeToolsTerminalHostToken(site.firewall?.wanIp)
        || '8.8.8.8';
      const speed = await runScheduledCollectorWanSpeedtest(state, site, target);
      const sample = {
        downloadMbps: speed.downloadMbps,
        uploadMbps: speed.uploadMbps,
        latencyMs: speed.latencyMs,
        publicIp: speed.publicIp || '',
        slotHour,
        slotLabel
      };
      appendWanTest(
        site,
        sample,
        now
      );
      logEvent(state, {
        classId: speed.ok ? 324 : 424,
        source: 'wan',
        actor: 'collector',
        action: speed.ok ? 'wan_speed_test' : 'wan_speed_test_unavailable',
        message: speed.ok
          ? `WAN speed test completed for ${site.name}`
          : `WAN speed test unavailable for ${site.name}`,
        detail: `slot=${slotLabel} down=${sample.downloadMbps ?? 'n/a'} up=${sample.uploadMbps ?? 'n/a'} latency=${sample.latencyMs ?? 'n/a'} publicIp=${sample.publicIp || 'n/a'} target=${speed.target || target} reason=${reason}:${speed.reason}`
      });
    }
    markSiteDirty(state);
  };

  const runAndReschedule = () => {
    const nextTs = nextWanTestSlotTimestamp(Date.now());
    const baseDelayMs = Math.max(250, nextTs - Date.now());
    const needsPublicIpRecovery = state.sites.some((site) => siteNeedsWanPublicIp(site));
    const delayMs = needsPublicIpRecovery
      ? Math.min(baseDelayMs, WAN_TEST_RECOVERY_INTERVAL_MS)
      : baseDelayMs;
    setTimeout(() => {
      poll('scheduled')
        .catch((err) => logSystemError('poller.wan.interval', err))
        .finally(() => {
          runAndReschedule();
        });
    }, delayMs);
  };

  const shouldBootstrap = state.sites.some((site) => siteNeedsWanPublicIp(site));
  if (shouldBootstrap) {
    poll('bootstrap').catch((err) => logSystemError('poller.wan.initial', err));
  }
  runAndReschedule();
}

// ── SNMP poller ───────────────────────────────────────────────────────────────
function startSnmpPoller(state) {
  const poll = async () => {
    const snmpDependency = state.dependencies?.snmpget || { available: true };
    if (!snmpDependency.available) {
      let changed = false;
      for (const site of state.sites) {
        const cfg = site.monitorConfig?.snmp || {};
        if (!cfg.enabled) {
          site.telemetry.snmp = false;
          continue;
        }
        site.telemetry.snmp = false;
        site.metrics = site.metrics || {};
        site.metrics.snmp = site.metrics.snmp || {};
        const message = `SNMP disabled: snmpget unavailable (${snmpDependency.detail || 'install net-snmp'})`;
        if (site.metrics.snmp.lastPoll !== message) {
          site.metrics.snmp.lastPoll = message;
          changed = true;
        }
      }
      if (changed) markSiteDirty(state);
      logEventThrottled(state, 'snmp:dependency:missing', 10 * 60 * 1000, {
        classId: 422,
        source: 'snmp',
        actor: 'cajal',
        action: 'snmp_dependency_missing',
        message: 'SNMP polling disabled: snmpget not available on server',
        detail: snmpDependency.detail || 'install net-snmp / snmp package'
      });
      logDiagnosticThrottled(state, 'snmp:dependency:missing', 60 * 1000, {
        level: 'error',
        scope: 'poller.snmp',
        protocol: 'snmp',
        action: 'dependency_missing',
        message: 'SNMP polling disabled: snmpget not available',
        detail: snmpDependency.detail || 'install net-snmp / snmp package'
      });
      logTelemetry(state, {
        protocol: 'snmp',
        transport: 'poller',
        action: 'dependency_missing',
        message: 'SNMP dependency missing',
        detail: snmpDependency.detail || 'install net-snmp / snmp package'
      });
      applyFlowStatus(state);
      return;
    }

    for (const site of state.sites) {
      const cfg = site.monitorConfig?.snmp || {};
      if (!cfg.enabled) {
        site.telemetry.snmp = false;
        continue;
      }

      try {
        const startedAt = Date.now();
        const ticks = await runSnmpGet(cfg);
        const responseMs = Date.now() - startedAt;
        site.metrics = site.metrics || {};
        site.metrics.snmp = site.metrics.snmp || {};
        site.metrics.snmp.uptime = ticks !== null ? formatSysUpTimeTicks(ticks) : 'N/A';
        site.metrics.snmp.lastPoll = new Date().toLocaleTimeString();
        site.metrics.snmp.responseMs = responseMs;
        site.metrics.snmp.successCount = Number(site.metrics.snmp.successCount || 0) + 1;
        site.metrics.snmp.lastSuccessAt = new Date().toISOString();
        site.metrics.snmp.lastError = '';
        state.lastSeen.snmp.set(site.id, Date.now());
        logSiteEventThrottled(state, site, `snmp-ok:${site.id}`, SNMP_OK_EVENT_THROTTLE_MS, {
          classId: 322,
          source: 'snmp',
          actor: 'collector',
          action: 'snmp_poll_ok',
          message: `SNMP poll ok for ${site.name}`,
          detail: `uptime=${site.metrics.snmp.uptime}`
        });
        logDiagnostic(state, {
          level: 'info',
          scope: 'poller.snmp',
          protocol: 'snmp',
          siteId: site.id,
          siteName: site.name,
          sourceIp: String(cfg.targetHost || '').trim(),
          action: 'poll_ok',
          message: `SNMP poll ok for ${site.name}`,
          detail: `uptime=${site.metrics.snmp.uptime} responseMs=${responseMs}`
        });
        logTelemetry(state, {
          protocol: 'snmp',
          siteId: site.id,
          siteName: site.name,
          sourceIp: String(cfg.targetHost || '').trim(),
          transport: 'poller',
          action: 'poll_ok',
          message: `SNMP poll ok for ${site.name}`,
          detail: `uptime=${site.metrics.snmp.uptime} responseMs=${responseMs}`
        });

        // ── Interface table poll ───────────────────────────────────────
        try {
          const walkStart = Date.now();
          const walkOutput = await runSnmpWalk(cfg, IFTABLE_OID);
          const raw = parseIfTableWalk(walkOutput);
          const now = Date.now();
          const prevSnapshot = state._ifTableSnapshots?.get(site.id);
          const elapsed = prevSnapshot ? now - prevSnapshot.ts : 0;
          const withDeltas = computeInterfaceDeltas(raw, prevSnapshot?.interfaces, elapsed);
          // Sort by total bandwidth descending
          withDeltas.sort((a, b) => b.totalMbps - a.totalMbps);
          if (!state._ifTableSnapshots) state._ifTableSnapshots = new Map();
          state._ifTableSnapshots.set(site.id, { ts: now, interfaces: raw });
          site.metrics.snmp.interfaces = withDeltas;
          site.metrics.snmp.interfaceCount = raw.length;
          site.metrics.snmp.interfacePollMs = Date.now() - walkStart;
          site.metrics.snmp.lastInterfacePoll = new Date().toISOString();
        } catch (ifErr) {
          // Interface walk failure is non-fatal — uptime poll already succeeded
          site.metrics.snmp.interfaces = site.metrics.snmp.interfaces || [];
          logDiagnostic(state, {
            level: 'warn',
            scope: 'poller.snmp.iftable',
            protocol: 'snmp',
            siteId: site.id,
            siteName: site.name,
            sourceIp: String(cfg.targetHost || '').trim(),
            action: 'iftable_error',
            message: `Interface table walk failed for ${site.name}`,
            detail: String(ifErr?.message || ifErr || 'Unknown error')
          });
        }

        markSiteDirty(state);
      } catch (err) {
        site.metrics = site.metrics || {};
        site.metrics.snmp = site.metrics.snmp || {};
        site.metrics.snmp.lastPoll = `Error: ${err.message}`;
        site.metrics.snmp.failureCount = Number(site.metrics.snmp.failureCount || 0) + 1;
        site.metrics.snmp.lastErrorAt = new Date().toISOString();
        site.metrics.snmp.lastError = String(err.message || 'Unknown error');
        logSiteEventThrottled(state, site, `snmp-err:${site.id}`, SNMP_ERROR_EVENT_THROTTLE_MS, {
          classId: 422,
          source: 'snmp',
          actor: 'collector',
          action: 'snmp_poll_error',
          message: `SNMP poll failed for ${site.name}`,
          detail: err.message
        });
        logDiagnostic(state, {
          level: 'warn',
          scope: 'poller.snmp',
          protocol: 'snmp',
          siteId: site.id,
          siteName: site.name,
          sourceIp: String(cfg.targetHost || '').trim(),
          action: 'poll_error',
          message: `SNMP poll failed for ${site.name}`,
          detail: String(err?.message || err || 'Unknown SNMP error')
        });
        logTelemetry(state, {
          protocol: 'snmp',
          siteId: site.id,
          siteName: site.name,
          sourceIp: String(cfg.targetHost || '').trim(),
          transport: 'poller',
          action: 'poll_error',
          message: `SNMP poll failed for ${site.name}`,
          detail: String(err?.message || err || 'Unknown SNMP error')
        });
        markSiteDirty(state);
      }
    }

    applyFlowStatus(state);
  };

  const loop = async (isInitial = false) => {
    try {
      await poll();
    } catch (err) {
      logSystemError(isInitial ? 'poller.snmp.initial' : 'poller.snmp.interval', err);
    } finally {
      setTimeout(() => {
        loop(false).catch((loopErr) => logSystemError('poller.snmp.loop', loopErr));
      }, SNMP_POLL_INTERVAL_MS);
    }
  };
  loop(true).catch((err) => logSystemError('poller.snmp.bootstrap', err));
}

// ── SNMP OID probe — tries a set of known walk tables, reports what works ─────
const SNMP_OID_PROBE_TARGETS = [
  { label: 'System Group',          oid: '1.3.6.1.2.1.1' },
  { label: 'ifTable (interfaces)',  oid: '1.3.6.1.2.1.2.2.1' },
  { label: 'ifXTable (extended)',   oid: '1.3.6.1.2.1.31.1.1.1' },
  { label: 'IP Address Table',      oid: '1.3.6.1.2.1.4.20.1' },
  { label: 'Meraki Enterprise MIB', oid: '1.3.6.1.4.1.29671' },
  { label: 'hrSystem (host)',       oid: '1.3.6.1.2.1.25.1' },
  { label: 'TCP/UDP Stats',         oid: '1.3.6.1.2.1.6' },
];

async function runSnmpOidProbe(config) {
  const results = [];
  for (const target of SNMP_OID_PROBE_TARGETS) {
    const startedAt = Date.now();
    try {
      const output = await runSnmpWalk(config, target.oid);
      const lines = output.trim().split('\n').filter(Boolean);
      results.push({
        label: target.label,
        oid: target.oid,
        status: lines.length > 0 ? 'ok' : 'empty',
        rows: lines.length,
        sample: lines.slice(0, 3).join('\n'),
        durationMs: Date.now() - startedAt,
      });
    } catch (err) {
      results.push({
        label: target.label,
        oid: target.oid,
        status: 'error',
        rows: 0,
        sample: String(err?.message || err || 'failed').slice(0, 120),
        durationMs: Date.now() - startedAt,
      });
    }
  }
  return results;
}

module.exports = {
  protocolFlowTimeoutMs,
  recentFlowCheck,
  matchSiteBySourceIp,
  markNetflowSeen,
  refreshNetflowTopTalkers,
  updateSyslogMetrics,
  logSyslogStreamEvent,
  decaySyslogMetrics,
  configuredSyslogSourceList,
  handleUnmatchedSyslogPacket,
  handleMatchedSyslogPacket,
  runSnmpGet,
  runSnmpWalk,
  runSnmpOidProbe,
  formatSysUpTimeTicks,
  parseIfTableWalk,
  computeInterfaceDeltas,
  runPing,
  runPingStats,
  appendUptimeSample,
  currentHeartbeatFreshWindowMs,
  deriveUptime14d,
  wanTestSlotHourFromTimestamp,
  wanTestSlotLabelFromTimestamp,
  nextWanTestSlotTimestamp,
  appendWanTest,
  extractSpeedtestMetricsFromLines,
  extractPublicIpFromLines,
  normalizeCollectorSpeedtestMetrics,
  normalizeCollectorPublicIpMetrics,
  deriveSiteStatus,
  detectSnmpgetDependency,
  detectSmtpDependency,
  detectSendmailDependency,
  effectiveTeamsWebhookConfig,
  buildWebhookRouteTestPayload,
  collectorLatestWanPublicIp,
  buildWebhookTemplateContextForStatus,
  buildWebhookTemplateContextForRouteTest,
  systemDependencySignal,
  initialPublicServiceState,
  locationPingMonitorDefinitions,
  locationPingMonitorStateKey,
  initialLocationPingMonitorState,
  detectTeamsDependency,
  detectMailDependency,
  startSyslogCollectors,
  startNetflowCollector,
  pollLocationPingMonitors,
  pollPublicServices,
  startPublicServicePoller,
  startLocationPingMonitorPoller,
  runCollectorWanPublicIpProbe,
  runScheduledCollectorWanSpeedtest,
  startPingPoller,
  startUptimeSampler,
  seedCollectorWanPublicIpState,
  startCollectorWanPublicIpPoller,
  startWanTestPoller,
  startSnmpPoller,
};
