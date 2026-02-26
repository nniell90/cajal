'use strict';
const { URL } = require('url');
const {
  SESSION_TTL_MS,
  SESSION_IDLE_TTL_MS,
  SESSION_RENEW_INTERVAL_MS,
  FORCE_SECURE_COOKIES,
} = require('./constants');

// ── Owned state ───────────────────────────────────────────────────────────────
const sessions = new Map();

// ── Cookie / request helpers ──────────────────────────────────────────────────
function parseCookies(req) {
  const raw = req.headers.cookie || '';
  const out = {};
  for (const token of raw.split(';')) {
    const [key, ...rest] = token.trim().split('=');
    if (!key) continue;
    out[key] = decodeURIComponent(rest.join('=') || '');
  }
  return out;
}

function requestIsHttps(req, url = null) {
  if (FORCE_SECURE_COOKIES) return true;
  const forwardedProto = String(req?.headers?.['x-forwarded-proto'] || '').split(',')[0].trim().toLowerCase();
  if (forwardedProto === 'https') return true;
  if (String(url?.protocol || '').trim().toLowerCase() === 'https:') return true;
  return Boolean(req?.socket?.encrypted);
}

// ── Session cookies ───────────────────────────────────────────────────────────
function issueSessionCookie(res, sid, options = {}) {
  const maxAgeSec = Math.max(1, Math.floor(SESSION_TTL_MS / 1000));
  const expiresAt = new Date(Date.now() + (maxAgeSec * 1000)).toUTCString();
  const secure = Boolean(options.secure);
  const parts = [
    `cajal_sid=${encodeURIComponent(sid)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${maxAgeSec}`,
    `Expires=${expiresAt}`
  ];
  if (secure) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

function clearSessionCookie(res, options = {}) {
  const secure = Boolean(options.secure);
  const parts = [
    'cajal_sid=',
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    'Max-Age=0',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT'
  ];
  if (secure) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}

// ── Session expiry ────────────────────────────────────────────────────────────
function sessionIsExpired(session = null, now = Date.now()) {
  if (!session || typeof session !== 'object') return true;
  const createdAt = Number(session.createdAt || 0);
  const lastSeenAt = Number(session.lastSeenAt || createdAt || 0);
  if (!Number.isFinite(createdAt) || createdAt <= 0) return true;
  if (now - createdAt > SESSION_TTL_MS) return true;
  if (SESSION_IDLE_TTL_MS > 0 && (!Number.isFinite(lastSeenAt) || now - lastSeenAt > SESSION_IDLE_TTL_MS)) return true;
  return false;
}

// ── Security headers ──────────────────────────────────────────────────────────
function requestOriginFromHeaders(req, url) {
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  const protocol = forwardedProto || (url?.protocol ? url.protocol.replace(/:$/, '') : 'http');
  const host = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
  if (!host) return '';
  return `${protocol}://${host}`;
}

function applySecurityHeaders(req, res, url) {
  if (!res.hasHeader('X-Frame-Options')) res.setHeader('X-Frame-Options', 'DENY');
  if (!res.hasHeader('X-Content-Type-Options')) res.setHeader('X-Content-Type-Options', 'nosniff');
  if (!res.hasHeader('Referrer-Policy')) res.setHeader('Referrer-Policy', 'no-referrer');
  if (!res.hasHeader('Permissions-Policy')) {
    res.setHeader('Permissions-Policy', 'accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()');
  }
  if (!res.hasHeader('Content-Security-Policy')) {
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; connect-src 'self'; img-src 'self' data: https:; script-src 'self'; style-src 'self'; font-src 'self' data:"
    );
  }
  if (requestIsHttps(req, url) && !res.hasHeader('Strict-Transport-Security')) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
}

// ── CSRF validation ───────────────────────────────────────────────────────────
function normalizeOriginHeaderValue(value = '') {
  const raw = String(value || '').trim();
  if (!raw) return '';
  try {
    const parsed = new URL(raw);
    return `${parsed.protocol}//${parsed.host}`.toLowerCase();
  } catch {
    return '';
  }
}

function csrfRequiredForRequest(user, req, url) {
  const provider = String(user?.provider || '').trim().toLowerCase();
  if (!user?.authenticated) return false;
  if (provider !== 'local' && provider !== 'entra') return false;
  const method = String(req?.method || '').trim().toUpperCase();
  if (!url?.pathname?.startsWith('/api/')) return false;
  if (method === 'GET' && url.pathname === '/api/auth/logout') return true;
  return method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
}

function csrfOriginMatchesHost(req, url) {
  const expectedOrigin = String(requestOriginFromHeaders(req, url) || '').trim().toLowerCase();
  if (!expectedOrigin) return false;
  const originHeader = normalizeOriginHeaderValue(req?.headers?.origin);
  if (originHeader) return originHeader === expectedOrigin;
  const refererHeader = normalizeOriginHeaderValue(req?.headers?.referer);
  if (refererHeader) return refererHeader === expectedOrigin;
  const fetchSite = String(req?.headers?.['sec-fetch-site'] || '').trim().toLowerCase();
  if (fetchSite === 'same-origin' || fetchSite === 'same-site' || fetchSite === 'none') return true;
  return false;
}

function validateCsrfRequest(user, req, url) {
  if (!csrfRequiredForRequest(user, req, url)) return { ok: true };
  if (csrfOriginMatchesHost(req, url)) return { ok: true };
  return {
    ok: false,
    error: 'CSRF validation failed: Origin/Referer mismatch',
    code: 'csrf_invalid'
  };
}

module.exports = {
  // Owned state
  sessions,
  // Cookie / request helpers
  parseCookies,
  requestIsHttps,
  // Session cookies
  issueSessionCookie,
  clearSessionCookie,
  // Session expiry
  sessionIsExpired,
  // Security headers
  requestOriginFromHeaders,
  applySecurityHeaders,
  // CSRF validation
  normalizeOriginHeaderValue,
  csrfRequiredForRequest,
  csrfOriginMatchesHost,
  validateCsrfRequest,
};
