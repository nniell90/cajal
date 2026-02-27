'use strict';
const crypto = require('crypto');
const shared = require('./shared');
const {
  DATA_RETENTION_MS,
  EVENT_RETENTION,
  EVENTS_FILE,
  USERS_FILE,
} = require('./constants');
const { smartWriteFile } = require('./storage');
const { AsyncMutex } = require('./mutex');
const _persistMutex = new AsyncMutex();
const { logJson } = require('./logging');
const { normalizeUserEntry, buildUserRoleDirectory } = require('./auth');

// ── Timestamp helpers ─────────────────────────────────────────────────────────
function parseIsoTimestampMs(value = '') {
  const ts = Date.parse(String(value || ''));
  return Number.isFinite(ts) ? ts : 0;
}

// ── Event retention ───────────────────────────────────────────────────────────
function pruneEventsByPolicy(events = [], nowMs = Date.now()) {
  const rows = Array.isArray(events) ? events : [];
  const cutoffMs = nowMs - DATA_RETENTION_MS;
  const retained = rows.filter((row) => {
    const ts = parseIsoTimestampMs(row?.ts);
    if (!ts) return true;
    return ts >= cutoffMs;
  });
  return retained.slice(0, EVENT_RETENTION);
}

function sameEventList(a = [], b = []) {
  if (!Array.isArray(a) || !Array.isArray(b)) return false;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    const left = a[i] || {};
    const right = b[i] || {};
    if (String(left.id || '') !== String(right.id || '')) return false;
    if (String(left.ts || '') !== String(right.ts || '')) return false;
  }
  return true;
}

// ── Event persistence ─────────────────────────────────────────────────────────
async function persistEvents(events) {
  return _persistMutex.run(async () => {
    const rows = Array.isArray(events) ? events : [];
    await smartWriteFile(EVENTS_FILE, JSON.stringify(rows), 'utf8');
  });
}

// ── Event creation ────────────────────────────────────────────────────────────
function createEvent({
  classId = 999,
  source = 'system',
  actor = 'system',
  action = 'event',
  message = '',
  detail = '',
  location = '',
  device = ''
}) {
  return {
    id: `evt-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
    ts: new Date().toISOString(),
    classId: Number(classId) || 999,
    source: String(source || 'system').trim().toLowerCase(),
    actor: String(actor || 'system').trim() || 'system',
    action: String(action || 'event').trim(),
    message: String(message || '').trim() || 'event',
    detail: String(detail || '').trim(),
    location: String(location || '').trim(),
    device: String(device || '').trim()
  };
}

function logEvent(state, entry) {
  const event = createEvent(entry || {});
  state.events.unshift(event);
  if (state.events.length > EVENT_RETENTION) state.events.length = EVENT_RETENTION;
  state.dirtyEvents = true;
}

function actorName(user) {
  if (!user || !user.authenticated) return 'anonymous';
  return String(user.email || user.displayName || 'authenticated-user');
}

// ── Security audit events ─────────────────────────────────────────────────────
function logSecurityAuditEvent(state, {
  key = '',
  minIntervalMs = 0,
  actor = 'anonymous',
  action = 'security_event',
  message = 'Security event',
  detail = '',
  source = 'security',
  classId = 402,
  location = '',
  device = ''
} = {}) {
  if (!state || typeof state !== 'object') return;
  const event = {
    classId,
    source,
    actor,
    action,
    message,
    detail,
    location,
    device
  };
  if (key && Number(minIntervalMs) > 0) {
    logEventThrottled(state, key, Number(minIntervalMs), event);
    return;
  }
  logEvent(state, event);
}

// ── User last login ───────────────────────────────────────────────────────────
async function markUserLastLogin(state, email) {
  const target = String(email || '').trim().toLowerCase();
  if (!target) return;
  const idx = state.users.findIndex((u) => u.email === target);
  if (idx < 0) return;
  const current = normalizeUserEntry(state.users[idx], state.users[idx]);
  current.lastLoginAt = new Date().toISOString();
  state.users[idx] = current;
  const normalized = state.users.map((u) => normalizeUserEntry(u, u)).filter((u) => u.email);
  await smartWriteFile(USERS_FILE, JSON.stringify(normalized), 'utf8');
  shared.userRoleDirectory = buildUserRoleDirectory(state.users);
}

function resolveLocalUserByIdentifier(users = [], identifier = '') {
  const loginId = String(identifier || '').trim().toLowerCase();
  if (!loginId) return null;
  const exact = users.find((u) => u.email === loginId);
  if (exact) return exact;
  if (loginId.includes('@')) return null;
  const matches = users.filter((u) => String(u.email || '').split('@')[0].toLowerCase() === loginId);
  if (matches.length === 1) return matches[0];
  return null;
}

// ── Throttled event logging ───────────────────────────────────────────────────
function logEventThrottled(state, key, minIntervalMs, entry) {
  const now = Date.now();
  const window = state.eventThrottle.get(key) || { lastAt: 0, suppressed: 0 };
  if (now - window.lastAt < minIntervalMs) {
    window.suppressed += 1;
    state.eventThrottle.set(key, window);
    return;
  }
  let detail = String(entry?.detail || '');
  if (window.suppressed > 0) {
    detail = `${detail}${detail ? ' | ' : ''}suppressed=${window.suppressed}`;
  }
  state.eventThrottle.set(key, { lastAt: now, suppressed: 0 });
  logEvent(state, { ...entry, detail });
}

// ── Site event helpers ────────────────────────────────────────────────────────
function locationNameForSite(site) {
  const category = String(site?.category || '').trim().toLowerCase();
  const sections = shared.locationSettings?.sections || [];
  const section = sections.find((s) => String(s.id || '').trim().toLowerCase() === category);
  return section?.name || category || 'Unknown Location';
}

function logSiteEvent(state, site, entry = {}) {
  logEvent(state, {
    ...(entry || {}),
    location: locationNameForSite(site),
    device: String(site?.name || site?.id || '').trim()
  });
}

function logSiteEventThrottled(state, site, key, minIntervalMs, entry = {}) {
  logEventThrottled(state, key, minIntervalMs, {
    ...(entry || {}),
    location: locationNameForSite(site),
    device: String(site?.name || site?.id || '').trim()
  });
}


module.exports = {
  parseIsoTimestampMs,
  pruneEventsByPolicy,
  sameEventList,
  persistEvents,
  createEvent,
  logEvent,
  actorName,
  logSecurityAuditEvent,
  markUserLastLogin,
  resolveLocalUserByIdentifier,
  logEventThrottled,
  logSiteEvent,
  logSiteEventThrottled,
  locationNameForSite,

  __test: {
    parseIsoTimestampMs,
    pruneEventsByPolicy,
    logEventThrottled,
    logSecurityAuditEvent,
  },
};
