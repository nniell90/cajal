'use strict';
const {
  DATA_DIR,
  ERROR_LOG_FILE,
  ERROR_LOG_MAX_BYTES,
  ERROR_LOG_MAX_LINES,
  DIAGNOSTIC_LOG_FILE,
  DIAGNOSTIC_LOG_MAX_BYTES,
  DIAGNOSTIC_LOG_MAX_LINES,
  TELEMETRY_LOG_FILE,
  TELEMETRY_LOG_MAX_BYTES,
  TELEMETRY_LOG_MAX_LINES,
  TELEMETRY_MESSAGE_MAX_BYTES,
} = require('./constants');

// ── Queue state owned by this module ─────────────────────────────────────────
let errorLogWriteQueue = Promise.resolve();
let diagnosticLogWriteQueue = Promise.resolve();
let telemetryLogWriteQueue = Promise.resolve();

// Storage backend injected at startup (set via setStorageBackend)
let storage = null;

function setStorageBackend(backend) {
  storage = backend;
}

// ── Pure helpers ──────────────────────────────────────────────────────────────
function isSensitiveLogKey(key = '') {
  const k = String(key || '').toLowerCase();
  return (
    k.includes('password') ||
    k.includes('secret') ||
    k.includes('token') ||
    k.includes('cookie') ||
    k.includes('auth') ||
    k.includes('community') ||
    k.includes('privatekey') ||
    k.includes('cert') ||
    k.includes('pem')
  );
}

function redactSecretsInText(value = '') {
  let text = String(value || '');
  if (!text) return '';
  text = text.replace(/\b(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}\b/gi, '$1[redacted]');
  text = text.replace(/\b(cajal_[A-Za-z0-9_-]{8,})\b/g, '[redacted-token]');
  text = text.replace(/\b([A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{8,})\b/g, '[redacted-jwt]');
  text = text.replace(/([?&](?:token|apikey|api_key|access_token|refresh_token|password|secret)=)[^&\s]+/gi, '$1[redacted]');
  text = text.replace(/((?:password|secret|token|apikey|api_key)\s*[:=]\s*)(['"]?)[^'"\s,;]+(\2)/gi, '$1[redacted]');
  return text;
}

function redactForLogs(value, depth = 0) {
  if (depth > 5) return '[max-depth]';
  if (value == null) return value;
  if (typeof value === 'string') {
    const redacted = redactSecretsInText(value);
    return redacted.length > 5000 ? `${redacted.slice(0, 5000)}…[truncated]` : redacted;
  }
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.slice(0, 50).map((item) => redactForLogs(item, depth + 1));
  if (typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      out[key] = isSensitiveLogKey(key) ? '[redacted]' : redactForLogs(item, depth + 1);
    }
    return out;
  }
  return String(value);
}

function normalizeError(err) {
  if (err instanceof Error) {
    const redactedMessage = redactSecretsInText(err.message || 'Unknown error');
    const redactedStack = redactSecretsInText(err.stack || '');
    return {
      name: err.name || 'Error',
      message: redactedMessage || 'Unknown error',
      stack: redactedStack,
      code: err.code || ''
    };
  }
  return {
    name: 'Error',
    message: redactSecretsInText(typeof err === 'string' ? err : JSON.stringify(redactForLogs(err))),
    stack: '',
    code: ''
  };
}

function logJson(level = 'info', scope = 'app', message = '', data = {}) {
  const entry = JSON.stringify({
    ts: new Date().toISOString(),
    level: String(level),
    scope: String(scope),
    message: String(message),
    ...data
  });
  if (level === 'error' || level === 'warn') {
    process.stderr.write(`${entry}\n`);
  } else {
    process.stdout.write(`${entry}\n`);
  }
}

// ── Error log ─────────────────────────────────────────────────────────────────
async function appendErrorLogEntry(entry) {
  const fsp = require('fs').promises;
  await fsp.mkdir(DATA_DIR, { recursive: true });
  try {
    const stat = await storage.smartStat(ERROR_LOG_FILE);
    if (stat.size > ERROR_LOG_MAX_BYTES) {
      const raw = await storage.smartReadFile(ERROR_LOG_FILE, 'utf8');
      const rows = raw.split('\n').filter(Boolean);
      const keep = rows.slice(-Math.max(50, ERROR_LOG_MAX_LINES));
      await storage.smartWriteFile(ERROR_LOG_FILE, `${keep.join('\n')}${keep.length ? '\n' : ''}`, 'utf8');
    }
  } catch {
    // file missing is expected on first run
  }
  await storage.smartAppendFile(ERROR_LOG_FILE, `${JSON.stringify(entry)}\n`, 'utf8');
}

function queueErrorLogEntry(entry) {
  errorLogWriteQueue = errorLogWriteQueue.then(() => appendErrorLogEntry(entry)).catch((err) => {
    const fallback = normalizeError(err);
    logJson('error', 'error_log.write', `Failed to write error log: ${fallback.message}`);
  });
}

function logSystemError(scope, err, context = {}) {
  const normalized = normalizeError(err);
  const entry = {
    ts: new Date().toISOString(),
    scope: String(scope || 'unknown'),
    pid: process.pid,
    message: normalized.message,
    name: normalized.name,
    code: normalized.code || '',
    stack: normalized.stack || '',
    context: redactForLogs(context)
  };
  const head = `[ERROR] ${entry.ts} ${entry.scope}: ${entry.message}`;
  if (entry.stack) {
    console.error(`${head}\n${entry.stack}`);
  } else {
    console.error(head);
  }
  if (entry.context && Object.keys(entry.context).length) {
    console.error(`Error context: ${JSON.stringify(entry.context)}`);
  }
  queueErrorLogEntry(entry);
  return entry;
}

async function readErrorLogEntries(limit = 200) {
  const max = Math.max(1, Math.min(1000, Number(limit) || 200));
  try {
    const raw = await storage.smartReadFile(ERROR_LOG_FILE, 'utf8');
    const rows = raw.split('\n').filter(Boolean).slice(-max);
    const entries = [];
    for (const row of rows.reverse()) {
      try {
        entries.push(JSON.parse(row));
      } catch {
        entries.push({ ts: new Date().toISOString(), scope: 'error-log-parse', message: row, stack: '' });
      }
    }
    return entries;
  } catch {
    return [];
  }
}

// ── Diagnostic log ────────────────────────────────────────────────────────────
async function appendDiagnosticLogEntry(entry) {
  const fsp = require('fs').promises;
  await fsp.mkdir(DATA_DIR, { recursive: true });
  try {
    const stat = await storage.smartStat(DIAGNOSTIC_LOG_FILE);
    if (stat.size > DIAGNOSTIC_LOG_MAX_BYTES) {
      const raw = await storage.smartReadFile(DIAGNOSTIC_LOG_FILE, 'utf8');
      const rows = raw.split('\n').filter(Boolean);
      const keep = rows.slice(-Math.max(100, DIAGNOSTIC_LOG_MAX_LINES));
      await storage.smartWriteFile(DIAGNOSTIC_LOG_FILE, `${keep.join('\n')}${keep.length ? '\n' : ''}`, 'utf8');
    }
  } catch {
    // file missing is expected on first run
  }
  await storage.smartAppendFile(DIAGNOSTIC_LOG_FILE, `${JSON.stringify(entry)}\n`, 'utf8');
}

function queueDiagnosticLogEntry(entry) {
  diagnosticLogWriteQueue = diagnosticLogWriteQueue.then(() => appendDiagnosticLogEntry(entry)).catch((err) => {
    const fallback = normalizeError(err);
    console.error(`Failed to write diagnostics log: ${fallback.message}`);
  });
}

function normalizeDiagnosticLevel(level = 'info') {
  const value = String(level || 'info').trim().toLowerCase();
  if (value === 'error' || value === 'warn' || value === 'debug' || value === 'info') return value;
  return 'info';
}

function logDiagnostic(state, entry = {}) {
  const payload = {
    ts: new Date().toISOString(),
    level: normalizeDiagnosticLevel(entry.level || 'info'),
    scope: String(entry.scope || 'system'),
    protocol: String(entry.protocol || '').trim().toLowerCase(),
    siteId: String(entry.siteId || '').trim(),
    siteName: String(entry.siteName || '').trim(),
    sourceIp: String(entry.sourceIp || '').trim(),
    action: String(entry.action || '').trim(),
    message: String(entry.message || '').trim(),
    detail: String(entry.detail || '').trim(),
    context: redactForLogs(entry.context || {})
  };
  queueDiagnosticLogEntry(payload);
  return payload;
}

function logDiagnosticThrottled(state, key, minIntervalMs, entry = {}) {
  const throttleKey = String(key || '').trim();
  if (!throttleKey) return logDiagnostic(state, entry);
  const map = state?.diagnosticThrottle;
  if (!map || typeof map.get !== 'function') return logDiagnostic(state, entry);
  const now = Date.now();
  const last = Number(map.get(throttleKey) || 0);
  if (last && now - last < Number(minIntervalMs || 0)) return null;
  map.set(throttleKey, now);
  return logDiagnostic(state, entry);
}

async function readDiagnosticLogEntries(limit = 250, filters = {}) {
  const max = Math.max(1, Math.min(2000, Number(limit) || 250));
  const filterProtocol = String(filters.protocol || '').trim().toLowerCase();
  const filterSite = String(filters.siteId || '').trim().toLowerCase();
  const filterLevel = normalizeDiagnosticLevel(filters.level || '');
  const useLevel = Boolean(String(filters.level || '').trim());
  try {
    const raw = await storage.smartReadFile(DIAGNOSTIC_LOG_FILE, 'utf8');
    const rows = raw.split('\n').filter(Boolean);
    const out = [];
    for (let i = rows.length - 1; i >= 0 && out.length < max; i -= 1) {
      let parsed;
      try {
        parsed = JSON.parse(rows[i]);
      } catch {
        parsed = { ts: new Date().toISOString(), level: 'warn', scope: 'diagnostics-log-parse', message: rows[i] };
      }
      if (filterProtocol && String(parsed.protocol || '').toLowerCase() !== filterProtocol) continue;
      if (filterSite) {
        const siteId = String(parsed.siteId || '').toLowerCase();
        const siteName = String(parsed.siteName || '').toLowerCase();
        if (!siteId.includes(filterSite) && !siteName.includes(filterSite)) continue;
      }
      if (useLevel && String(parsed.level || '').toLowerCase() !== filterLevel) continue;
      out.push(parsed);
    }
    return out;
  } catch {
    return [];
  }
}

async function clearDiagnosticLogEntries() {
  await storage.smartWriteFile(DIAGNOSTIC_LOG_FILE, '', 'utf8');
}

// ── Telemetry log ─────────────────────────────────────────────────────────────
function truncateTelemetryText(value = '', maxBytes = TELEMETRY_MESSAGE_MAX_BYTES) {
  const input = String(value || '');
  if (!input) return '';
  const raw = Buffer.from(input, 'utf8');
  if (raw.length <= maxBytes) return input;
  return `${raw.subarray(0, maxBytes).toString('utf8')}...[truncated]`;
}

async function appendTelemetryLogEntry(entry) {
  const fsp = require('fs').promises;
  await fsp.mkdir(DATA_DIR, { recursive: true });
  try {
    const stat = await storage.smartStat(TELEMETRY_LOG_FILE);
    if (stat.size > TELEMETRY_LOG_MAX_BYTES) {
      const raw = await storage.smartReadFile(TELEMETRY_LOG_FILE, 'utf8');
      const rows = raw.split('\n').filter(Boolean);
      const keep = rows.slice(-Math.max(1000, TELEMETRY_LOG_MAX_LINES));
      await storage.smartWriteFile(TELEMETRY_LOG_FILE, `${keep.join('\n')}${keep.length ? '\n' : ''}`, 'utf8');
    }
  } catch {
    // file missing is expected on first run
  }
  await storage.smartAppendFile(TELEMETRY_LOG_FILE, `${JSON.stringify(entry)}\n`, 'utf8');
}

function queueTelemetryLogEntry(entry) {
  telemetryLogWriteQueue = telemetryLogWriteQueue.then(() => appendTelemetryLogEntry(entry)).catch((err) => {
    const fallback = normalizeError(err);
    console.error(`Failed to write telemetry log: ${fallback.message}`);
  });
}

function logTelemetry(state, entry = {}) {
  const payload = {
    ts: new Date().toISOString(),
    protocol: String(entry.protocol || '').trim().toLowerCase(),
    siteId: String(entry.siteId || '').trim(),
    siteName: String(entry.siteName || '').trim(),
    sourceIp: String(entry.sourceIp || '').trim(),
    transport: String(entry.transport || '').trim().toLowerCase(),
    action: String(entry.action || '').trim(),
    message: truncateTelemetryText(entry.message || ''),
    detail: truncateTelemetryText(entry.detail || '', Math.max(2048, Math.floor(TELEMETRY_MESSAGE_MAX_BYTES / 2))),
    context: entry.context && typeof entry.context === 'object' ? entry.context : {}
  };
  queueTelemetryLogEntry(payload);
  return payload;
}

async function readTelemetryLogEntries(limit = 500, filters = {}) {
  const max = Math.max(1, Math.min(5000, Number(limit) || 500));
  const filterProtocol = String(filters.protocol || '').trim().toLowerCase();
  const filterSite = String(filters.siteId || '').trim().toLowerCase();
  const filterQuery = String(filters.q || '').trim().toLowerCase();
  try {
    const raw = await storage.smartReadFileTail(TELEMETRY_LOG_FILE, 5 * 1024 * 1024, 'utf8');
    const rows = raw.split('\n').filter(Boolean);
    const out = [];
    for (let i = rows.length - 1; i >= 0 && out.length < max; i -= 1) {
      let parsed;
      try {
        parsed = JSON.parse(rows[i]);
      } catch {
        parsed = { ts: new Date().toISOString(), protocol: 'unknown', message: rows[i], detail: '' };
      }
      if (filterProtocol && String(parsed.protocol || '').toLowerCase() !== filterProtocol) continue;
      if (filterSite) {
        const siteId = String(parsed.siteId || '').toLowerCase();
        const siteName = String(parsed.siteName || '').toLowerCase();
        if (!siteId.includes(filterSite) && !siteName.includes(filterSite)) continue;
      }
      if (filterQuery) {
        const hay = `${parsed.message || ''} ${parsed.detail || ''} ${parsed.sourceIp || ''} ${parsed.siteName || ''}`.toLowerCase();
        if (!hay.includes(filterQuery)) continue;
      }
      out.push(parsed);
    }
    return out;
  } catch {
    return [];
  }
}

async function clearTelemetryLogEntries() {
  await storage.smartWriteFile(TELEMETRY_LOG_FILE, '', 'utf8');
}

module.exports = {
  setStorageBackend,
  isSensitiveLogKey,
  redactSecretsInText,
  redactForLogs,
  normalizeError,
  logJson,
  appendErrorLogEntry,
  queueErrorLogEntry,
  logSystemError,
  readErrorLogEntries,
  appendDiagnosticLogEntry,
  queueDiagnosticLogEntry,
  normalizeDiagnosticLevel,
  logDiagnostic,
  logDiagnosticThrottled,
  readDiagnosticLogEntries,
  clearDiagnosticLogEntries,
  truncateTelemetryText,
  appendTelemetryLogEntry,
  queueTelemetryLogEntry,
  logTelemetry,
  readTelemetryLogEntries,
  clearTelemetryLogEntries,
};
