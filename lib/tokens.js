'use strict';
const net = require('net');
const {
  API_TOKEN_MAX_IP_ALLOWLIST,
  API_TOKEN_MAX_COUNT,
  API_TOKEN_MAX_LIFETIME_MS,
  API_TOKEN_MAX_LIFETIME_DAYS,
} = require('./constants');

// ── Helpers shared in this module ─────────────────────────────────────────────
function normalizeAccessRole(role) {
  const value = String(role || '').trim().toLowerCase();
  if (value === 'admin' || value === 'monitor') return value;
  return 'monitor';
}

function normalizeApiTokenRole(role) {
  const value = String(role || '').trim().toLowerCase();
  if (value === 'admin' || value === 'monitor') return value;
  return 'monitor';
}

const API_TOKEN_SCOPE_SET = new Set(['read', 'write', 'settings', 'agents', 'security']);
const API_TOKEN_ROLE_SCOPE_MAP = Object.freeze({
  monitor: ['read'],
  admin: ['read', 'write', 'settings', 'agents', 'security']
});

function normalizeApiTokenScope(scope = '') {
  const value = String(scope || '').trim().toLowerCase();
  if (!API_TOKEN_SCOPE_SET.has(value)) return '';
  return value;
}

function parseApiTokenScopeList(value) {
  if (Array.isArray(value)) {
    return value.map((item) => String(item || '').trim()).filter(Boolean);
  }
  if (typeof value === 'string') {
    return value
      .split(/[,\n]/g)
      .map((item) => String(item || '').trim())
      .filter(Boolean);
  }
  return [];
}

function normalizeApiTokenScopes(inputScopes, role = 'monitor', fallbackScopes = null) {
  const normalizedRole = normalizeApiTokenRole(role);
  const allowedForRole = new Set(API_TOKEN_ROLE_SCOPE_MAP[normalizedRole] || API_TOKEN_ROLE_SCOPE_MAP.monitor);
  const requested = parseApiTokenScopeList(inputScopes);
  let scopes = requested
    .map((item) => normalizeApiTokenScope(item))
    .filter(Boolean);
  if (!scopes.length && fallbackScopes) {
    scopes = parseApiTokenScopeList(fallbackScopes)
      .map((item) => normalizeApiTokenScope(item))
      .filter(Boolean);
  }
  if (!scopes.length) scopes = [...allowedForRole];
  const uniq = [];
  const seen = new Set();
  for (const scope of scopes) {
    if (!allowedForRole.has(scope)) continue;
    if (seen.has(scope)) continue;
    seen.add(scope);
    uniq.push(scope);
  }
  if (!uniq.length) return [...allowedForRole];
  return uniq;
}

function requiredApiTokenScopeForRequest(method = '', pathname = '') {
  const normalizedMethod = String(method || 'GET').trim().toUpperCase();
  const normalizedPath = String(pathname || '/').trim();
  if (!normalizedPath.startsWith('/api/')) return 'read';
  if (normalizedPath === '/api/health' || normalizedPath === '/api/auth/me') return 'read';
  if (/^\/api\/settings\/api\/tokens(?:\/|$)/.test(normalizedPath)) return 'security';
  if (/^\/api\/agent(?:\/|$)/.test(normalizedPath) || /\/collector\//.test(normalizedPath)) return 'agents';
  if (/^\/api\/settings(?:\/|$)/.test(normalizedPath) || /^\/api\/backup(?:\/|$)/.test(normalizedPath)) return 'settings';
  if (normalizedMethod === 'GET' || normalizedMethod === 'HEAD' || normalizedMethod === 'OPTIONS') return 'read';
  return 'write';
}

function apiTokenHasScope(tokenScopes = [], requiredScope = 'read') {
  const required = normalizeApiTokenScope(requiredScope) || 'read';
  const granted = new Set(normalizeApiTokenScopes(tokenScopes, 'admin', tokenScopes));
  return granted.has(required);
}

function normalizeApiTokenName(name = '') {
  const text = String(name || '').trim().replace(/\s+/g, ' ');
  return text.slice(0, 80);
}

// ── IP allowlist ──────────────────────────────────────────────────────────────
function normalizeRemoteIpForMatch(remoteIp = '') {
  const raw = String(remoteIp || '').trim().toLowerCase();
  if (!raw) return '';
  if (raw.startsWith('::ffff:')) {
    const mapped = raw.slice(7);
    if (net.isIP(mapped) === 4) return mapped;
  }
  return raw;
}

function parseApiTokenIpAllowlist(input = [], fallback = null) {
  const rows = Array.isArray(input)
    ? input
    : (typeof input === 'string'
      ? input.split(/[,\n]/g)
      : (fallback != null ? parseApiTokenIpAllowlist(fallback, null) : []));
  return rows
    .map((row) => String(row || '').trim().toLowerCase())
    .filter(Boolean);
}

function normalizeApiTokenIpAllowlist(input = [], fallback = null) {
  const rows = parseApiTokenIpAllowlist(input, fallback);
  const seen = new Set();
  const out = [];
  for (const entry of rows) {
    if (out.length >= API_TOKEN_MAX_IP_ALLOWLIST) break;
    if (seen.has(entry)) continue;
    seen.add(entry);
    out.push(entry);
  }
  return out;
}

function validateApiTokenAllowlistEntry(entry = '') {
  const value = String(entry || '').trim().toLowerCase();
  if (!value) return { ok: false, code: 'invalid_api_token_ip_allowlist', error: 'IP allowlist entry is empty' };
  if (!value.includes('/')) {
    const kind = net.isIP(value);
    if (!kind) return { ok: false, code: 'invalid_api_token_ip_allowlist', error: `Invalid IP allowlist entry: ${value}` };
    return { ok: true };
  }
  const [baseRaw, prefixRaw] = value.split('/');
  const base = String(baseRaw || '').trim();
  const prefix = Number(prefixRaw);
  const kind = net.isIP(base);
  if (!kind || !Number.isFinite(prefix)) {
    return { ok: false, code: 'invalid_api_token_ip_allowlist', error: `Invalid CIDR allowlist entry: ${value}` };
  }
  const maxPrefix = kind === 4 ? 32 : 128;
  const normalizedPrefix = Math.floor(prefix);
  if (normalizedPrefix < 0 || normalizedPrefix > maxPrefix) {
    return { ok: false, code: 'invalid_api_token_ip_allowlist', error: `Invalid CIDR prefix for ${base}: ${prefixRaw}` };
  }
  return { ok: true };
}

function apiTokenAllowlistContainsIp(allowlist = [], remoteIp = '') {
  const ip = normalizeRemoteIpForMatch(remoteIp);
  const entries = normalizeApiTokenIpAllowlist(allowlist);
  if (!entries.length) return true;
  if (!ip || !net.isIP(ip)) return false;
  const blockList = new net.BlockList();
  for (const entry of entries) {
    const validation = validateApiTokenAllowlistEntry(entry);
    if (!validation.ok) continue;
    if (!entry.includes('/')) {
      const kind = net.isIP(entry);
      blockList.addAddress(entry, kind === 4 ? 'ipv4' : 'ipv6');
      continue;
    }
    const [baseRaw, prefixRaw] = entry.split('/');
    const base = String(baseRaw || '').trim();
    const prefix = Math.floor(Number(prefixRaw));
    const kind = net.isIP(base);
    blockList.addSubnet(base, prefix, kind === 4 ? 'ipv4' : 'ipv6');
  }
  const type = net.isIP(ip);
  if (!type) return false;
  return blockList.check(ip, type === 4 ? 'ipv4' : 'ipv6');
}

// ── Token record normalization ────────────────────────────────────────────────
function parseCollectorAgentInstallTimestampMs(value = '') {
  if (value == null) return 0;
  const numeric = Number(value);
  if (Number.isFinite(numeric) && numeric > 0) {
    const ms = numeric < 1000000000000 ? numeric * 1000 : numeric;
    return Math.floor(ms);
  }
  const text = String(value || '').trim();
  if (!text) return 0;
  const parsed = Date.parse(text);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function normalizeApiTokenRecord(input = {}, existing = {}) {
  const source = input && typeof input === 'object' ? input : {};
  const fallback = existing && typeof existing === 'object' ? existing : {};
  const createdAtMs = parseCollectorAgentInstallTimestampMs(source.createdAt ?? fallback.createdAt ?? '');
  const lastUsedAtMs = parseCollectorAgentInstallTimestampMs(source.lastUsedAt ?? fallback.lastUsedAt ?? '');
  const expiresAtMs = parseCollectorAgentInstallTimestampMs(source.expiresAt ?? fallback.expiresAt ?? '');
  const revokedAtMs = parseCollectorAgentInstallTimestampMs(source.revokedAt ?? fallback.revokedAt ?? '');
  const allowlistRaw = normalizeApiTokenIpAllowlist(source.ipAllowlist, fallback.ipAllowlist);
  const ipAllowlist = [];
  for (const entry of allowlistRaw) {
    const validation = validateApiTokenAllowlistEntry(entry);
    if (!validation.ok) continue;
    ipAllowlist.push(entry);
    if (ipAllowlist.length >= API_TOKEN_MAX_IP_ALLOWLIST) break;
  }
  return {
    id: String(source.id ?? fallback.id ?? '').trim().slice(0, 80),
    name: normalizeApiTokenName(source.name ?? fallback.name ?? ''),
    role: normalizeApiTokenRole(source.role ?? fallback.role),
    scopes: normalizeApiTokenScopes(source.scopes, source.role ?? fallback.role, fallback.scopes),
    ipAllowlist,
    tokenHash: String(source.tokenHash ?? fallback.tokenHash ?? '').trim().toLowerCase().slice(0, 128),
    tokenPrefix: String(source.tokenPrefix ?? fallback.tokenPrefix ?? '').trim().slice(0, 24),
    createdAt: createdAtMs > 0 ? new Date(createdAtMs).toISOString() : '',
    createdBy: String(source.createdBy ?? fallback.createdBy ?? '').trim().slice(0, 160),
    lastUsedAt: lastUsedAtMs > 0 ? new Date(lastUsedAtMs).toISOString() : '',
    expiresAt: expiresAtMs > 0 ? new Date(expiresAtMs).toISOString() : '',
    revokedAt: revokedAtMs > 0 ? new Date(revokedAtMs).toISOString() : ''
  };
}

function sanitizeApiTokenSettings(config = {}) {
  const rows = Array.isArray(config?.tokens) ? config.tokens : [];
  const seenIds = new Set();
  const out = [];
  for (const row of rows) {
    const normalized = normalizeApiTokenRecord(row, {});
    if (!normalized.id || !normalized.tokenHash || !normalized.expiresAt) continue;
    if (seenIds.has(normalized.id)) continue;
    seenIds.add(normalized.id);
    out.push(normalized);
    if (out.length >= API_TOKEN_MAX_COUNT) break;
  }
  return { tokens: out };
}

function apiTokenStatus(token = {}, now = Date.now()) {
  const revokedAtMs = parseCollectorAgentInstallTimestampMs(token?.revokedAt || '');
  if (revokedAtMs > 0) return 'revoked';
  const expiresAtMs = parseCollectorAgentInstallTimestampMs(token?.expiresAt || '');
  if (!(Number.isFinite(expiresAtMs) && expiresAtMs > 0)) return 'expired';
  if (expiresAtMs > 0 && now >= expiresAtMs) return 'expired';
  return 'active';
}

function isApiTokenActive(token = {}, now = Date.now()) {
  return apiTokenStatus(token, now) === 'active';
}

function apiTokenForClient(token = {}) {
  const normalized = normalizeApiTokenRecord(token, token);
  return {
    id: normalized.id,
    name: normalized.name || normalized.id,
    role: normalizeApiTokenRole(normalized.role),
    tokenPrefix: normalized.tokenPrefix,
    createdAt: normalized.createdAt,
    createdBy: normalized.createdBy,
    lastUsedAt: normalized.lastUsedAt,
    expiresAt: normalized.expiresAt,
    revokedAt: normalized.revokedAt,
    scopes: normalized.scopes,
    ipAllowlist: normalized.ipAllowlist,
    status: apiTokenStatus(normalized)
  };
}

function validateApiTokenCreateInput(body = {}, { now = Date.now(), actorRole = 'admin' } = {}) {
  const role = normalizeApiTokenRole(body?.role || 'monitor');
  const actor = normalizeAccessRole(actorRole);
  if (role === 'admin' && actor !== 'admin') {
    return { ok: false, error: 'Only admins can create admin API tokens', code: 'api_token_role_forbidden' };
  }
  const hasExpiresAt = Object.prototype.hasOwnProperty.call(body || {}, 'expiresAt');
  const rawExpiresAt = String(body?.expiresAt || '').trim();
  if (!hasExpiresAt || !rawExpiresAt) {
    return { ok: false, error: 'expiresAt is required for API tokens', code: 'api_token_expires_required', field: 'expiresAt' };
  }
  const expiresAtMs = parseCollectorAgentInstallTimestampMs(rawExpiresAt);
  if (!(Number.isFinite(expiresAtMs) && expiresAtMs > now)) {
    return { ok: false, error: 'expiresAt must be a valid future timestamp', code: 'api_token_expires_invalid', field: 'expiresAt' };
  }
  if ((expiresAtMs - now) > API_TOKEN_MAX_LIFETIME_MS) {
    return {
      ok: false,
      error: `expiresAt exceeds max lifetime (${API_TOKEN_MAX_LIFETIME_DAYS} days)`,
      code: 'api_token_expires_too_long',
      field: 'expiresAt'
    };
  }
  const requestedScopes = parseApiTokenScopeList(body?.scopes);
  const normalizedScopes = normalizeApiTokenScopes(requestedScopes, role, null);
  const requestedUnknownScopes = requestedScopes
    .map((item) => String(item || '').trim().toLowerCase())
    .filter((item) => item && !API_TOKEN_SCOPE_SET.has(item));
  if (requestedUnknownScopes.length) {
    return {
      ok: false,
      error: `Unsupported token scopes: ${[...new Set(requestedUnknownScopes)].join(', ')}`,
      code: 'api_token_scope_invalid',
      field: 'scopes'
    };
  }
  const disallowedRequestedScopes = requestedScopes
    .map((item) => normalizeApiTokenScope(item))
    .filter(Boolean)
    .filter((scope) => !normalizedScopes.includes(scope));
  if (disallowedRequestedScopes.length) {
    return {
      ok: false,
      error: `Requested scopes exceed allowed role scope for role ${role}: ${[...new Set(disallowedRequestedScopes)].join(', ')}`,
      code: 'api_token_scope_forbidden',
      field: 'scopes'
    };
  }
  const normalizedAllowlist = normalizeApiTokenIpAllowlist(body?.ipAllowlist, null);
  if (API_TOKEN_MAX_IP_ALLOWLIST <= 0 && normalizedAllowlist.length) {
    return { ok: false, error: 'IP allowlist is disabled by server policy', code: 'api_token_ip_allowlist_disabled', field: 'ipAllowlist' };
  }
  for (const entry of normalizedAllowlist) {
    const validation = validateApiTokenAllowlistEntry(entry);
    if (!validation.ok) {
      return {
        ok: false,
        error: validation.error,
        code: validation.code,
        field: 'ipAllowlist'
      };
    }
  }
  return {
    ok: true,
    role,
    scopes: normalizedScopes,
    expiresAt: new Date(expiresAtMs).toISOString(),
    ipAllowlist: normalizedAllowlist
  };
}

function buildApiTokenHashIndex(tokens = []) {
  const index = new Map();
  for (const row of Array.isArray(tokens) ? tokens : []) {
    const normalized = normalizeApiTokenRecord(row, row);
    if (!normalized.tokenHash) continue;
    index.set(normalized.tokenHash, row);
  }
  return index;
}

module.exports = {
  normalizeAccessRole,
  normalizeApiTokenRole,
  API_TOKEN_SCOPE_SET,
  API_TOKEN_ROLE_SCOPE_MAP,
  normalizeApiTokenScope,
  parseApiTokenScopeList,
  normalizeApiTokenScopes,
  requiredApiTokenScopeForRequest,
  apiTokenHasScope,
  normalizeApiTokenName,
  normalizeRemoteIpForMatch,
  parseApiTokenIpAllowlist,
  normalizeApiTokenIpAllowlist,
  validateApiTokenAllowlistEntry,
  apiTokenAllowlistContainsIp,
  parseCollectorAgentInstallTimestampMs,
  normalizeApiTokenRecord,
  sanitizeApiTokenSettings,
  apiTokenStatus,
  isApiTokenActive,
  apiTokenForClient,
  validateApiTokenCreateInput,
  buildApiTokenHashIndex,
};
