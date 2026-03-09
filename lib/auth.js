'use strict';
const crypto = require('crypto');
const QRCode = require('qrcode');
const shared = require('./shared');
const {
  PASSWORD_HASH_ITERATIONS,
  LOCAL_TOTP_ENABLED,
  LOCAL_SETUP_TTL_MS,
  SESSION_RENEW_INTERVAL_MS,
  ADMIN_USERS,
  MONITOR_USERS,
  MASK,
  COLLECTOR_AGENT_INSTALL_TIE_EPSILON_MS,
} = require('./constants');
const {
  encryptJson,
  decryptJson,
  generateTotpSecret,
  hashApiToken,
} = require('./crypto');
const {
  sessions,
  issueSessionCookie,
  sessionIsExpired,
  requestIsHttps,
  parseCookies,
} = require('./session');
const {
  redisPersistSession,
  redisDeleteSession,
} = require('./storage');
const {
  normalizeAccessRole,
  normalizeApiTokenRole,
  normalizeApiTokenScopes,
  normalizeApiTokenIpAllowlist,
  normalizeRemoteIpForMatch,
  isApiTokenActive,
  apiTokenStatus,
  apiTokenAllowlistContainsIp,
  parseCollectorAgentInstallTimestampMs,
  sanitizeApiTokenSettings,
  buildApiTokenHashIndex,
} = require('./tokens');

// ── API token state ───────────────────────────────────────────────────────────
function saveApiTokenSettingsToState(state, config = {}) {
  if (!state || typeof state !== 'object') return [];
  const sanitized = sanitizeApiTokenSettings(config || {});
  state.apiTokens = Array.isArray(sanitized.tokens) ? sanitized.tokens : [];
  state.apiTokenByHash = buildApiTokenHashIndex(state.apiTokens);
  state.apiTokensDirty = true;
  return state.apiTokens;
}

// ── SSO / Entra ───────────────────────────────────────────────────────────────
function entraConfigured() {
  const cfg = shared.ssoRuntimeConfig;
  return Boolean(cfg.tenantId && cfg.clientId && cfg.clientSecret);
}

function ssoConfigForClient() {
  const cfg = shared.ssoRuntimeConfig;
  return {
    tenantId: cfg.tenantId || '',
    clientId: cfg.clientId || '',
    clientSecret: cfg.clientSecret ? MASK : '',
    redirectUri: cfg.redirectUri || '',
    scope: cfg.scope || ''
  };
}

// ── Session helpers ───────────────────────────────────────────────────────────
function getSessionById(sid = '', now = Date.now()) {
  const sessionId = String(sid || '').trim();
  if (!sessionId) return null;
  const session = sessions.get(sessionId);
  if (!sessionIsExpired(session, now)) return { sid: sessionId, session };
  sessions.delete(sessionId);
  redisDeleteSession(sessionId);
  return null;
}

function sessionFromCookies(cookies = {}, now = Date.now()) {
  const sid = String(cookies?.cajal_sid || '').trim();
  return getSessionById(sid, now);
}

function touchSessionActivity(res, sid = '', session = {}, options = {}) {
  const now = Number(options.now || Date.now());
  const sessionId = String(sid || '').trim();
  if (!sessionId || !session || typeof session !== 'object') return;
  const previousSeen = Number(session.lastSeenAt || 0);
  session.lastSeenAt = now;
  sessions.set(sessionId, session);
  redisPersistSession(sessionId, session);
  if (res && (!previousSeen || (now - previousSeen) >= SESSION_RENEW_INTERVAL_MS)) {
    issueSessionCookie(res, sessionId, { secure: Boolean(options.secure) });
  }
}

// ── JWT / role mapping ────────────────────────────────────────────────────────
function decodeJwtPayload(token) {
  const parts = String(token || '').split('.');
  if (parts.length < 2) return {};
  try {
    const payload = Buffer.from(parts[1], 'base64url').toString('utf8');
    return JSON.parse(payload);
  } catch {
    return {};
  }
}

function mapUserRole(claims) {
  const rawRoles = Array.isArray(claims.roles) ? claims.roles : [];
  const lowered = rawRoles.map((v) => String(v).toLowerCase());
  if (lowered.includes('admin')) return 'admin';
  if (lowered.includes('monitor')) return 'monitor';

  const email = String(claims.preferred_username || claims.email || '').toLowerCase();
  if (email && shared.userRoleDirectory.has(email)) {
    return normalizeAccessRole(shared.userRoleDirectory.get(email).role);
  }
  if (ADMIN_USERS.has(email)) return 'admin';
  if (MONITOR_USERS.has(email)) return 'monitor';
  return 'monitor';
}

function getUserFromRequest(req, state = null, cookies = null, options = {}) {
  const guest = { authenticated: false, displayName: 'Guest', email: '', role: 'monitor', provider: 'none' };
  if (req && typeof req === 'object') req.__authIssue = null;
  const authHeader = String(req?.headers?.authorization || '').trim();
  const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);
  if (bearerMatch) {
    const rawToken = String(bearerMatch[1] || '').trim();
    if (!rawToken) {
      if (req && typeof req === 'object') req.__authIssue = { type: 'api_token_missing', detail: 'Bearer token was empty' };
      return guest;
    }
    const tokenHash = hashApiToken(rawToken);
    const tokenRecord = state?.apiTokenByHash?.get(tokenHash);
    const now = Date.now();
    if (!tokenRecord) {
      if (req && typeof req === 'object') req.__authIssue = { type: 'api_token_invalid', detail: 'Bearer token hash not recognized' };
      return guest;
    }
    if (!isApiTokenActive(tokenRecord, now)) {
      if (req && typeof req === 'object') {
        req.__authIssue = {
          type: 'api_token_inactive',
          detail: `API token ${tokenRecord.id || 'unknown'} is ${apiTokenStatus(tokenRecord, now)}`
        };
      }
      return guest;
    }
    const remoteIp = normalizeRemoteIpForMatch(options?.remoteIp || req?.socket?.remoteAddress || '');
    if (!apiTokenAllowlistContainsIp(tokenRecord.ipAllowlist, remoteIp)) {
      if (req && typeof req === 'object') {
        req.__authIssue = {
          type: 'api_token_ip_blocked',
          detail: `remoteIp=${remoteIp || 'unknown'} not allowed by token allowlist`
        };
      }
      return guest;
    }
    const lastUsedMs = parseCollectorAgentInstallTimestampMs(tokenRecord.lastUsedAt || '');
    if (now - lastUsedMs >= 30 * 1000) {
      tokenRecord.lastUsedAt = new Date(now).toISOString();
      if (state && typeof state === 'object') state.apiTokensDirty = true;
    }
    const scopes = normalizeApiTokenScopes(tokenRecord.scopes, tokenRecord.role, tokenRecord.scopes);
    return {
      authenticated: true,
      displayName: tokenRecord.name || `API ${tokenRecord.id}`,
      email: `api-token:${tokenRecord.id}`,
      role: normalizeApiTokenRole(tokenRecord.role),
      provider: 'api-token',
      tokenId: tokenRecord.id,
      scopes,
      ipAllowlist: normalizeApiTokenIpAllowlist(tokenRecord.ipAllowlist, tokenRecord.ipAllowlist)
    };
  }
  const parsedCookies = cookies && typeof cookies === 'object' ? cookies : parseCookies(req);
  const sessionRecord = sessionFromCookies(parsedCookies);
  if (!sessionRecord) {
    return guest;
  }
  const session = sessionRecord.session;
  const email = String(session.user?.email || '').toLowerCase();
  if (email && shared.userRoleDirectory.has(email)) {
    const override = shared.userRoleDirectory.get(email);
    session.user.role = normalizeAccessRole(override.role);
    if (override.displayName) session.user.displayName = override.displayName;
  }
  return { ...session.user, role: normalizeAccessRole(session.user.role) };
}

// ── User normalization ────────────────────────────────────────────────────────
function normalizeUserEntry(input = {}, existing = {}) {
  const email = String(input.email || existing.email || '').trim().toLowerCase();
  const displayName = String(input.displayName || existing.displayName || '').trim() || email;
  const role = normalizeAccessRole(input.role ?? existing.role);
  const lastLoginAt = String(input.lastLoginAt ?? existing.lastLoginAt ?? '').trim();
  const sourceLocal = input.localAuth && typeof input.localAuth === 'object' ? input.localAuth : {};
  const existingLocal = existing.localAuth && typeof existing.localAuth === 'object' ? existing.localAuth : {};
  const localAuth = {
    passwordHash: String(sourceLocal.passwordHash ?? existingLocal.passwordHash ?? '').trim(),
    passwordSalt: String(sourceLocal.passwordSalt ?? existingLocal.passwordSalt ?? '').trim(),
    passwordIterations: Number(sourceLocal.passwordIterations ?? existingLocal.passwordIterations ?? PASSWORD_HASH_ITERATIONS),
    passwordChangedAt: String(sourceLocal.passwordChangedAt ?? existingLocal.passwordChangedAt ?? ''),
    totpSecretEncrypted: sourceLocal.totpSecretEncrypted ?? existingLocal.totpSecretEncrypted ?? null,
    totpEnabled: Boolean(sourceLocal.totpEnabled ?? existingLocal.totpEnabled ?? false),
    totpChangedAt: String(sourceLocal.totpChangedAt ?? existingLocal.totpChangedAt ?? '')
  };
  if (!Number.isFinite(localAuth.passwordIterations) || localAuth.passwordIterations < 1000) {
    localAuth.passwordIterations = PASSWORD_HASH_ITERATIONS;
  }
  return { email, displayName, role, lastLoginAt, localAuth };
}

function sanitizeUserForClient(user = {}) {
  const normalized = normalizeUserEntry(user, user);
  const totpState = resolveTotpSecretState(normalized.localAuth || {});
  return {
    email: normalized.email,
    displayName: normalized.displayName,
    role: normalized.role,
    lastLoginAt: normalized.lastLoginAt || null,
    localAuth: {
      passwordSet: Boolean(normalized.localAuth.passwordHash && normalized.localAuth.passwordSalt),
      totpEnabled: totpState.state === 'verify',
      totpState: totpState.state,
      passwordChangedAt: normalized.localAuth.passwordChangedAt || null,
      totpChangedAt: normalized.localAuth.totpChangedAt || null
    }
  };
}

// ── Password helpers ──────────────────────────────────────────────────────────
function hashPassword(password, salt = crypto.randomBytes(16).toString('base64'), iterations = PASSWORD_HASH_ITERATIONS) {
  const hash = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256').toString('base64');
  return { hash, salt, iterations };
}

function verifyPassword(password, localAuth = {}) {
  if (!localAuth.passwordHash || !localAuth.passwordSalt) return false;
  const computed = hashPassword(password, localAuth.passwordSalt, localAuth.passwordIterations || PASSWORD_HASH_ITERATIONS);
  const expected = Buffer.from(localAuth.passwordHash, 'base64');
  const actual = Buffer.from(computed.hash, 'base64');
  if (expected.length !== actual.length) return false;
  return crypto.timingSafeEqual(expected, actual);
}

// ── Collector agent auth helpers ──────────────────────────────────────────────
function normalizeCollectorAgentAuth(input = {}, existing = {}) {
  const source = input && typeof input === 'object' ? input : {};
  const fallback = existing && typeof existing === 'object' ? existing : {};
  const out = {
    passwordHash: String(source.passwordHash ?? fallback.passwordHash ?? '').trim(),
    passwordSalt: String(source.passwordSalt ?? fallback.passwordSalt ?? '').trim(),
    passwordIterations: Number(source.passwordIterations ?? fallback.passwordIterations ?? PASSWORD_HASH_ITERATIONS),
    passwordChangedAt: String(source.passwordChangedAt ?? fallback.passwordChangedAt ?? '').trim()
  };
  if (!Number.isFinite(out.passwordIterations) || out.passwordIterations < 1000) {
    out.passwordIterations = PASSWORD_HASH_ITERATIONS;
  }
  return out;
}

function normalizeCollectorAgentInstallIdentity(input = {}, existing = {}) {
  const source = input && typeof input === 'object' ? input : {};
  const fallback = existing && typeof existing === 'object' ? existing : {};
  const installIdRaw = source.installId ?? source.install_id ?? fallback.installId ?? '';
  const installedAtRaw = source.installedAt ?? source.installed_at ?? source.installedAtMs ?? source.installed_at_ms ?? fallback.installedAt ?? fallback.installedAtMs ?? '';
  const lockedAtRaw = source.lockedAt ?? source.locked_at ?? fallback.lockedAt ?? '';
  const installedAtMs = parseCollectorAgentInstallTimestampMs(installedAtRaw);
  const lockedAtMs = parseCollectorAgentInstallTimestampMs(lockedAtRaw);
  return {
    installId: String(installIdRaw || '').trim().slice(0, 128),
    installedAt: installedAtMs > 0 ? new Date(installedAtMs).toISOString() : '',
    installedAtMs,
    lockedAt: lockedAtMs > 0 ? new Date(lockedAtMs).toISOString() : ''
  };
}

function evaluateCollectorAgentInstallRegistration(site = {}, incomingInstall = {}) {
  const current = normalizeCollectorAgentInstallIdentity(site?.collector?.agentInstallLock || {}, {});
  const incoming = normalizeCollectorAgentInstallIdentity(incomingInstall, {});
  const currentTs = Number(current.installedAtMs || 0);
  const incomingTs = Number(incoming.installedAtMs || 0);

  if (currentTs <= 0) {
    return { allowed: true, reason: 'no_install_lock', current, incoming };
  }
  if (incomingTs <= 0) {
    return { allowed: false, reason: 'missing_install_metadata', current, incoming };
  }
  if (incomingTs + COLLECTOR_AGENT_INSTALL_TIE_EPSILON_MS < currentTs) {
    return { allowed: false, reason: 'older_install', current, incoming };
  }
  if (incomingTs > currentTs + COLLECTOR_AGENT_INSTALL_TIE_EPSILON_MS) {
    return { allowed: true, reason: 'newer_install', current, incoming };
  }

  const currentId = String(current.installId || '').trim();
  const incomingId = String(incoming.installId || '').trim();
  if (currentId && incomingId && currentId !== incomingId) {
    return { allowed: false, reason: 'install_id_mismatch', current, incoming };
  }
  if (currentId && !incomingId) {
    return { allowed: false, reason: 'missing_install_id', current, incoming };
  }
  return { allowed: true, reason: 'same_install', current, incoming };
}

function updateCollectorAgentInstallLock(site = {}, incomingInstall = {}, now = Date.now()) {
  const incoming = normalizeCollectorAgentInstallIdentity(incomingInstall, {});
  if (!incoming.installId && Number(incoming.installedAtMs || 0) <= 0) return false;
  site.collector = site.collector || {};
  const current = normalizeCollectorAgentInstallIdentity(site.collector.agentInstallLock || {}, {});
  const next = {
    ...incoming,
    lockedAt: new Date(Number.isFinite(Number(now)) ? Number(now) : Date.now()).toISOString()
  };
  const changed = (
    String(current.installId || '') !== String(next.installId || '')
    || Number(current.installedAtMs || 0) !== Number(next.installedAtMs || 0)
    || String(current.installedAt || '') !== String(next.installedAt || '')
  );
  if (changed) {
    site.collector.agentInstallLock = next;
  }
  return changed;
}

function collectorAgentPasswordConfigured(site = {}) {
  const auth = normalizeCollectorAgentAuth(site?.collector?.agentAuth || {}, {});
  return Boolean(auth.passwordHash && auth.passwordSalt);
}

// ── TOTP helpers ──────────────────────────────────────────────────────────────
async function makeTotpPayload(email, secret, setupToken = '') {
  const issuer = 'Cajal ICBM';
  const label = `${issuer}:${email}`;
  const otpauthUrl = `otpauth://totp/${encodeURIComponent(label)}?secret=${encodeURIComponent(
    secret
  )}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
  let qrUrl = setupToken ? `/api/auth/local/totp-qr?setupToken=${encodeURIComponent(setupToken)}` : '';
  if (!qrUrl) {
    try {
      qrUrl = await QRCode.toDataURL(otpauthUrl, {
        errorCorrectionLevel: 'M',
        margin: 1,
        width: 220
      });
    } catch {
      qrUrl = '';
    }
  }
  return {
    secret,
    otpauthUrl,
    qrUrl
  };
}

// ── Setup tokens ──────────────────────────────────────────────────────────────
function createSetupToken(email, stage, secret = '') {
  const token = crypto.randomBytes(24).toString('hex');
  shared.localSetupState.set(token, { email, stage, secret, createdAt: Date.now() });
  return token;
}

function consumeSetupToken(token, requiredStage) {
  const entry = shared.localSetupState.get(token);
  if (!entry) return null;
  if (Date.now() - entry.createdAt > LOCAL_SETUP_TTL_MS) {
    shared.localSetupState.delete(token);
    return null;
  }
  if (requiredStage && entry.stage !== requiredStage) return null;
  shared.localSetupState.delete(token);
  return entry;
}

function peekSetupToken(token, requiredStage) {
  const entry = shared.localSetupState.get(token);
  if (!entry) return null;
  if (Date.now() - entry.createdAt > LOCAL_SETUP_TTL_MS) {
    shared.localSetupState.delete(token);
    return null;
  }
  if (requiredStage && entry.stage !== requiredStage) return null;
  return entry;
}

// ── TOTP secret state ─────────────────────────────────────────────────────────
function decryptTotpSecret(localAuth = {}) {
  if (!localAuth.totpSecretEncrypted) return '';
  try {
    const payload = decryptJson(localAuth.totpSecretEncrypted);
    if (typeof payload === 'string') return payload;
    if (payload && typeof payload.secret === 'string') return payload.secret;
  } catch {
    return '';
  }
  return '';
}

function resolveTotpSecretState(localAuth = {}) {
  const totpEnabled = Boolean(localAuth?.totpEnabled);
  const hasEncryptedSecret = Boolean(localAuth?.totpSecretEncrypted);
  const secret = decryptTotpSecret(localAuth);
  const hasSecret = Boolean(secret);

  if (totpEnabled && !hasSecret) {
    return {
      state: 'invalid',
      reason: 'enabled_without_decryptable_secret',
      secret: ''
    };
  }
  if (!totpEnabled || !hasEncryptedSecret || !hasSecret) {
    return {
      state: 'enroll',
      reason: 'enrollment_required',
      secret: ''
    };
  }
  return {
    state: 'verify',
    reason: 'secret_ready',
    secret
  };
}

function localTotpMfaEnabled() {
  const rt = shared.runtimeSettings;
  if (rt && Object.prototype.hasOwnProperty.call(rt, 'localTotpEnabled')) {
    return Boolean(rt.localTotpEnabled);
  }
  return LOCAL_TOTP_ENABLED;
}

// ── Session issuance ──────────────────────────────────────────────────────────
function issueLocalSession(req, res, user) {
  const cookies = parseCookies(req);
  const previousSid = String(cookies.cajal_sid || '').trim();
  if (previousSid) {
    sessions.delete(previousSid);
    redisDeleteSession(previousSid);
  }
  const now = Date.now();
  const sid = crypto.randomBytes(24).toString('hex');
  const newSession = {
    createdAt: now,
    lastSeenAt: now,
    user: {
      authenticated: true,
      displayName: user.displayName,
      email: user.email,
      role: user.role,
      provider: 'local'
    }
  };
  sessions.set(sid, newSession);
  redisPersistSession(sid, newSession);
  issueSessionCookie(res, sid, { secure: requestIsHttps(req) });
}

// ── Default local users ───────────────────────────────────────────────────────
function ensureDefaultLocalUsers(users = []) {
  let changed = false;
  let admin = users.find((u) => u.email === 'admin');
  if (!admin) {
    const legacy = users.find((u) => u.email === 'admim');
    if (legacy) {
      admin = normalizeUserEntry({ ...legacy, email: 'admin' }, legacy);
      const idx = users.findIndex((u) => u.email === 'admim');
      if (idx >= 0) users.splice(idx, 1);
      users.push(admin);
      changed = true;
    } else {
      admin = normalizeUserEntry({ email: 'admin', displayName: 'Local Admin', role: 'admin' }, {});
      users.push(admin);
      changed = true;
    }
  }

  return changed;
}

// ── User role directory ───────────────────────────────────────────────────────
function buildUserRoleDirectory(users = []) {
  const map = new Map();
  for (const row of users) {
    const u = normalizeUserEntry(row);
    if (!u.email) continue;
    map.set(u.email, { displayName: u.displayName, role: u.role });
  }
  return map;
}

module.exports = {
  saveApiTokenSettingsToState,
  entraConfigured,
  ssoConfigForClient,
  getSessionById,
  sessionFromCookies,
  touchSessionActivity,
  decodeJwtPayload,
  mapUserRole,
  getUserFromRequest,
  normalizeUserEntry,
  sanitizeUserForClient,
  hashPassword,
  verifyPassword,
  normalizeCollectorAgentAuth,
  normalizeCollectorAgentInstallIdentity,
  evaluateCollectorAgentInstallRegistration,
  updateCollectorAgentInstallLock,
  collectorAgentPasswordConfigured,
  makeTotpPayload,
  createSetupToken,
  consumeSetupToken,
  peekSetupToken,
  decryptTotpSecret,
  resolveTotpSecretState,
  localTotpMfaEnabled,
  issueLocalSession,
  ensureDefaultLocalUsers,
  buildUserRoleDirectory,
};
