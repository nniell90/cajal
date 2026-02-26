'use strict';
const {
  LOGIN_ACCOUNT_FAILURE_THRESHOLD,
  LOGIN_ACCOUNT_FAILURE_WINDOW_MS,
  LOGIN_ACCOUNT_LOCK_MS,
} = require('./constants');
const { sendJson } = require('./http');
const { logSecurityAuditEvent } = require('./events');

// ── Owned state ───────────────────────────────────────────────────────────────
const rateLimitBuckets = new Map();
const loginAccountFailures = new Map();

// ── Helpers ───────────────────────────────────────────────────────────────────
function normalizeLoginIdentifier(value = '') {
  return String(value || '').trim().toLowerCase().slice(0, 320);
}

// ── Rate limiter ──────────────────────────────────────────────────────────────
function consumeRateLimitToken(key = '', max = 10, windowMs = 60_000, now = Date.now()) {
  const bucketKey = String(key || '').trim();
  const limit = Math.max(1, Math.floor(Number(max) || 1));
  const durationMs = Math.max(1000, Math.floor(Number(windowMs) || 1000));
  if (!bucketKey) {
    return {
      allowed: true,
      limit,
      remaining: limit,
      resetAtMs: now + durationMs,
      retryAfterSec: 0
    };
  }
  let bucket = rateLimitBuckets.get(bucketKey);
  if (!bucket || !Number.isFinite(bucket.resetAtMs) || now >= bucket.resetAtMs) {
    bucket = { count: 0, resetAtMs: now + durationMs };
  }
  bucket.count += 1;
  rateLimitBuckets.set(bucketKey, bucket);
  const allowed = bucket.count <= limit;
  const retryAfterSec = allowed ? 0 : Math.max(1, Math.ceil((bucket.resetAtMs - now) / 1000));
  return {
    allowed,
    limit,
    remaining: Math.max(0, limit - bucket.count),
    resetAtMs: bucket.resetAtMs,
    retryAfterSec
  };
}

function pruneRateLimitBuckets(now = Date.now()) {
  for (const [key, bucket] of rateLimitBuckets.entries()) {
    if (!bucket || now >= Number(bucket.resetAtMs || 0)) rateLimitBuckets.delete(key);
  }
}

// ── Login account failure tracking ───────────────────────────────────────────
function getLoginAccountLockState(loginId = '', now = Date.now()) {
  const id = normalizeLoginIdentifier(loginId);
  if (!id) return { locked: false, retryAfterSec: 0, failures: 0 };
  let row = loginAccountFailures.get(id);
  if (!row) return { locked: false, retryAfterSec: 0, failures: 0 };
  if (Number.isFinite(row.lockedUntilMs) && row.lockedUntilMs > now) {
    return {
      locked: true,
      retryAfterSec: Math.max(1, Math.ceil((row.lockedUntilMs - now) / 1000)),
      failures: Number(row.failures || 0)
    };
  }
  if (!Number.isFinite(row.windowStartedAtMs) || now - row.windowStartedAtMs > LOGIN_ACCOUNT_FAILURE_WINDOW_MS) {
    loginAccountFailures.delete(id);
    return { locked: false, retryAfterSec: 0, failures: 0 };
  }
  return { locked: false, retryAfterSec: 0, failures: Number(row.failures || 0) };
}

function recordLoginAccountFailure(loginId = '', now = Date.now()) {
  const id = normalizeLoginIdentifier(loginId);
  if (!id) return { locked: false, retryAfterSec: 0, failures: 0 };
  if (loginAccountFailures.size > 10000) {
    for (const [key, value] of loginAccountFailures.entries()) {
      const stale = !value
        || (!Number.isFinite(value.lockedUntilMs) || value.lockedUntilMs <= now)
        && (!Number.isFinite(value.windowStartedAtMs) || now - value.windowStartedAtMs > LOGIN_ACCOUNT_FAILURE_WINDOW_MS);
      if (stale) loginAccountFailures.delete(key);
    }
  }
  let row = loginAccountFailures.get(id);
  if (!row || !Number.isFinite(row.windowStartedAtMs) || now - row.windowStartedAtMs > LOGIN_ACCOUNT_FAILURE_WINDOW_MS) {
    row = { failures: 0, windowStartedAtMs: now, lockedUntilMs: 0 };
  }
  if (Number.isFinite(row.lockedUntilMs) && row.lockedUntilMs > now) {
    loginAccountFailures.set(id, row);
    return {
      locked: true,
      retryAfterSec: Math.max(1, Math.ceil((row.lockedUntilMs - now) / 1000)),
      failures: Number(row.failures || 0)
    };
  }
  row.failures = Number(row.failures || 0) + 1;
  if (row.failures >= LOGIN_ACCOUNT_FAILURE_THRESHOLD) {
    row.lockedUntilMs = now + LOGIN_ACCOUNT_LOCK_MS;
    row.failures = 0;
  }
  loginAccountFailures.set(id, row);
  if (row.lockedUntilMs > now) {
    return {
      locked: true,
      retryAfterSec: Math.max(1, Math.ceil((row.lockedUntilMs - now) / 1000)),
      failures: Number(row.failures || 0)
    };
  }
  return { locked: false, retryAfterSec: 0, failures: Number(row.failures || 0) };
}

function clearLoginAccountFailures(loginId = '') {
  const id = normalizeLoginIdentifier(loginId);
  if (!id) return;
  loginAccountFailures.delete(id);
}

function sendRateLimitResponse(res, result, message = 'Too many requests') {
  const retryAfterSec = Math.max(1, Number(result?.retryAfterSec || 1));
  const limit = Math.max(1, Number(result?.limit || 1));
  const remaining = Math.max(0, Number(result?.remaining || 0));
  const resetEpochSec = Math.max(1, Math.floor(Number(result?.resetAtMs || Date.now()) / 1000));
  res.setHeader('Retry-After', String(retryAfterSec));
  res.setHeader('X-RateLimit-Limit', String(limit));
  res.setHeader('X-RateLimit-Remaining', String(remaining));
  res.setHeader('X-RateLimit-Reset', String(resetEpochSec));
  return sendJson(res, 429, {
    error: String(message || 'Too many requests'),
    code: 'rate_limited',
    retryAfterSec
  });
}

function enforceRateLimitOrSend(res, {
  key = '',
  max = 10,
  windowMs = 60_000,
  message = 'Too many requests',
  state = null,
  actor = 'anonymous',
  action = 'rate_limit_blocked',
  detail = '',
  source = 'security',
  classId = 402
} = {}) {
  const result = consumeRateLimitToken(key, max, windowMs);
  if (result.allowed) return true;
  if (state && typeof state === 'object') {
    logSecurityAuditEvent(state, {
      key: `security:rate-limit:${key}`,
      minIntervalMs: 30 * 1000,
      actor,
      action,
      message: String(message || 'Too many requests'),
      detail: `${detail}${detail ? ' | ' : ''}retryAfterSec=${result.retryAfterSec}`,
      source,
      classId
    });
  }
  sendRateLimitResponse(res, result, message);
  return false;
}

module.exports = {
  // Exported Maps (by reference — consumers can clear/iterate them)
  rateLimitBuckets,
  loginAccountFailures,
  // Functions
  normalizeLoginIdentifier,
  consumeRateLimitToken,
  pruneRateLimitBuckets,
  getLoginAccountLockState,
  recordLoginAccountFailure,
  clearLoginAccountFailures,
  sendRateLimitResponse,
  enforceRateLimitOrSend,
};
