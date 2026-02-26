const test = require('node:test');
const assert = require('node:assert/strict');

const { __test: core } = require('../server.js');

function makeJsonRes() {
  const headers = new Map();
  return {
    statusCode: 0,
    body: '',
    hasHeader: (key) => headers.has(String(key || '').toLowerCase()),
    getHeader: (key) => headers.get(String(key || '').toLowerCase()),
    setHeader: (key, value) => {
      headers.set(String(key || '').toLowerCase(), String(value));
    },
    writeHead: function writeHead(statusCode, nextHeaders = {}) {
      this.statusCode = Number(statusCode) || 0;
      for (const [key, value] of Object.entries(nextHeaders || {})) {
        headers.set(String(key || '').toLowerCase(), String(value));
      }
    },
    end: function end(chunk = '') {
      const text = Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk || '');
      this.body = `${this.body}${text}`;
    },
    json: function json() {
      return this.body ? JSON.parse(this.body) : {};
    }
  };
}

function makeAuditState() {
  return {
    events: [],
    dirtyEvents: false,
    eventThrottle: new Map()
  };
}

test.afterEach(() => {
  core.resetSecurityStateForTests();
});

test('request validation rejects malformed POST/PATCH/DELETE payloads with stable JSON 400 errors', () => {
  assert.throws(
    () => core.validateRequestPayload('not-an-object'),
    (err) => err instanceof core.RequestValidationError && err.code === 'invalid_payload_type'
  );
  assert.throws(
    () => core.validateRequestPayload({ constructor: { polluted: true } }),
    (err) => err instanceof core.RequestValidationError && err.code === 'invalid_request_key' && err.field === 'constructor'
  );
  assert.throws(
    () => core.validateRequestPayload({ safe: true, extra: true }, { allowedKeys: ['safe'] }),
    (err) => err instanceof core.RequestValidationError && err.code === 'invalid_payload_field' && err.field === 'extra'
  );
  const payload = core.badRequestPayload(new core.RequestValidationError('Unsupported payload field: extra', 'invalid_payload_field', 'extra'));
  assert.deepEqual(payload, {
    error: 'Unsupported payload field: extra',
    code: 'invalid_payload_field',
    field: 'extra'
  });
});

test('login endpoint rate-limit helper returns 429 JSON after threshold and logs security event', () => {
  const state = makeAuditState();
  const key = 'login:198.51.100.10';
  const first = makeJsonRes();
  const second = makeJsonRes();

  const allowed = core.enforceRateLimitOrSend(first, {
    key,
    max: 1,
    windowMs: 60_000,
    message: 'Too many login attempts. Please wait and retry.',
    state,
    actor: 'anonymous',
    action: 'login_rate_limited',
    detail: 'POST /api/auth/local/login ip=198.51.100.10',
    source: 'auth'
  });
  const blocked = core.enforceRateLimitOrSend(second, {
    key,
    max: 1,
    windowMs: 60_000,
    message: 'Too many login attempts. Please wait and retry.',
    state,
    actor: 'anonymous',
    action: 'login_rate_limited',
    detail: 'POST /api/auth/local/login ip=198.51.100.10',
    source: 'auth'
  });

  assert.equal(allowed, true);
  assert.equal(blocked, false);
  assert.equal(second.statusCode, 429);
  assert.equal(second.json().code, 'rate_limited');
  assert.match(second.json().error, /too many login attempts/i);
  assert.ok(Number(second.getHeader('retry-after')) >= 1);
  assert.equal(state.events.length, 1);
  assert.equal(state.events[0].action, 'login_rate_limited');
});

test('API token create/revoke rate-limit helper returns 429 JSON after threshold', () => {
  const state = makeAuditState();
  const createKey = 'api-token-mutate:create:203.0.113.9:admin@cajal.local';
  const revokeKey = 'api-token-mutate:revoke:203.0.113.9:admin@cajal.local';

  assert.equal(core.enforceRateLimitOrSend(makeJsonRes(), {
    key: createKey,
    max: 1,
    windowMs: 60_000,
    message: 'Too many API token create requests. Please wait and retry.',
    state,
    actor: 'admin@cajal.local',
    action: 'api_token_create_rate_limited'
  }), true);
  const createBlocked = makeJsonRes();
  assert.equal(core.enforceRateLimitOrSend(createBlocked, {
    key: createKey,
    max: 1,
    windowMs: 60_000,
    message: 'Too many API token create requests. Please wait and retry.',
    state,
    actor: 'admin@cajal.local',
    action: 'api_token_create_rate_limited'
  }), false);
  assert.equal(createBlocked.statusCode, 429);
  assert.equal(createBlocked.json().code, 'rate_limited');

  assert.equal(core.enforceRateLimitOrSend(makeJsonRes(), {
    key: revokeKey,
    max: 1,
    windowMs: 60_000,
    message: 'Too many API token revoke requests. Please wait and retry.',
    state,
    actor: 'admin@cajal.local',
    action: 'api_token_revoke_rate_limited'
  }), true);
  const revokeBlocked = makeJsonRes();
  assert.equal(core.enforceRateLimitOrSend(revokeBlocked, {
    key: revokeKey,
    max: 1,
    windowMs: 60_000,
    message: 'Too many API token revoke requests. Please wait and retry.',
    state,
    actor: 'admin@cajal.local',
    action: 'api_token_revoke_rate_limited'
  }), false);
  assert.equal(revokeBlocked.statusCode, 429);
  assert.equal(revokeBlocked.json().code, 'rate_limited');

  const actions = new Set(state.events.map((event) => event.action));
  assert.equal(actions.has('api_token_create_rate_limited'), true);
  assert.equal(actions.has('api_token_revoke_rate_limited'), true);
});

test('state-changing cookie-auth requests enforce CSRF token checks', () => {
  const user = { authenticated: true, provider: 'local' };
  const url = new URL('https://app.example.com/api/sites');
  const goodReq = {
    method: 'POST',
    headers: {
      host: 'app.example.com',
      origin: 'https://app.example.com',
      'x-forwarded-proto': 'https'
    }
  };
  const badReq = {
    method: 'POST',
    headers: {
      host: 'app.example.com',
      origin: 'https://evil.example.com',
      'x-forwarded-proto': 'https'
    }
  };

  assert.equal(core.csrfRequiredForRequest(user, { method: 'GET' }, url), false);
  assert.equal(core.csrfRequiredForRequest(user, { method: 'POST' }, url), true);
  assert.equal(core.validateCsrfRequest(user, goodReq, url).ok, true);
  assert.equal(core.validateCsrfRequest(user, badReq, url).ok, false);
  assert.equal(core.validateCsrfRequest({ authenticated: true, provider: 'api-token' }, badReq, url).ok, true);
});

test('responses include security hardening headers', () => {
  const res = makeJsonRes();
  const req = {
    headers: {
      host: 'app.example.com',
      'x-forwarded-proto': 'https'
    },
    socket: { encrypted: false }
  };
  core.applySecurityHeaders(req, res, new URL('https://app.example.com/'));

  assert.ok(res.getHeader('content-security-policy'));
  assert.match(res.getHeader('content-security-policy'), /script-src 'self'/);
  assert.doesNotMatch(res.getHeader('content-security-policy'), /script-src[^;]*'unsafe-inline'/);
  assert.ok(res.getHeader('strict-transport-security'));
  assert.equal(res.getHeader('x-frame-options'), 'DENY');
  assert.equal(res.getHeader('x-content-type-options'), 'nosniff');
  assert.equal(res.getHeader('referrer-policy'), 'no-referrer');
});

test('account login lockout engages after repeated failures and can be cleared', () => {
  const id = 'admin';
  for (let i = 0; i < 8; i += 1) {
    core.recordLoginAccountFailure(id);
  }
  const locked = core.getLoginAccountLockState(id);
  assert.equal(locked.locked, true);
  assert.ok(locked.retryAfterSec >= 1);

  core.clearLoginAccountFailures(id);
  const cleared = core.getLoginAccountLockState(id);
  assert.equal(cleared.locked, false);
});

test('TOTP secret state marks enabled-but-undecryptable records invalid', () => {
  const invalid = core.resolveTotpSecretState({
    totpEnabled: true,
    totpSecretEncrypted: { iv: 'bad', tag: 'bad', data: 'bad' }
  });
  assert.equal(invalid.state, 'invalid');

  const enroll = core.resolveTotpSecretState({
    totpEnabled: false,
    totpSecretEncrypted: null
  });
  assert.equal(enroll.state, 'enroll');
});

test('session cookie flags and session TTL enforcement stay hardened', () => {
  const res = makeJsonRes();
  core.issueSessionCookie(res, 'sid test', { secure: true });
  const cookie = res.getHeader('set-cookie') || '';
  assert.match(cookie, /^cajal_sid=sid%20test;/);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
  assert.match(cookie, /Secure/);
  const maxAgeMatch = cookie.match(/Max-Age=(\d+)/);
  assert.ok(maxAgeMatch);
  assert.equal(Number(maxAgeMatch[1]), Math.floor(core.constants.SESSION_TTL_MS / 1000));

  const now = Date.parse('2026-02-25T12:00:00.000Z');
  assert.equal(core.sessionIsExpired({
    createdAt: now - 1000,
    lastSeenAt: now - 1000
  }, now), false);
  assert.equal(core.sessionIsExpired({
    createdAt: now - core.constants.SESSION_TTL_MS - 1,
    lastSeenAt: now - 1000
  }, now), true);
});

test('API token policy requires expiration and enforces role scope constraints', () => {
  const now = Date.parse('2026-02-25T12:00:00.000Z');
  const oneHourFromNowIso = new Date(now + (60 * 60 * 1000)).toISOString();

  const missingExpiry = core.validateApiTokenCreateInput({ role: 'monitor' }, { now, actorRole: 'admin' });
  assert.equal(missingExpiry.ok, false);
  assert.equal(missingExpiry.code, 'api_token_expires_required');

  const tooLong = core.validateApiTokenCreateInput({
    role: 'monitor',
    expiresAt: new Date(now + (365 * 24 * 60 * 60 * 1000)).toISOString()
  }, { now, actorRole: 'admin' });
  assert.equal(tooLong.ok, false);
  assert.equal(tooLong.code, 'api_token_expires_too_long');

  const monitorAdminToken = core.validateApiTokenCreateInput({
    role: 'admin',
    expiresAt: oneHourFromNowIso
  }, { now, actorRole: 'monitor' });
  assert.equal(monitorAdminToken.ok, false);
  assert.equal(monitorAdminToken.code, 'api_token_role_forbidden');

  const monitorWriteScope = core.validateApiTokenCreateInput({
    role: 'monitor',
    expiresAt: oneHourFromNowIso,
    scopes: ['write']
  }, { now, actorRole: 'admin' });
  assert.equal(monitorWriteScope.ok, false);
  assert.equal(monitorWriteScope.code, 'api_token_scope_forbidden');

  const invalidAllowlist = core.validateApiTokenCreateInput({
    role: 'admin',
    expiresAt: oneHourFromNowIso,
    scopes: ['read', 'security'],
    ipAllowlist: ['not-an-ip']
  }, { now, actorRole: 'admin' });
  assert.equal(invalidAllowlist.ok, false);
  assert.equal(invalidAllowlist.code, 'invalid_api_token_ip_allowlist');

  const valid = core.validateApiTokenCreateInput({
    role: 'admin',
    expiresAt: oneHourFromNowIso,
    scopes: ['read', 'security'],
    ipAllowlist: ['10.0.0.1', '192.168.0.0/24']
  }, { now, actorRole: 'admin' });
  assert.equal(valid.ok, true);
  assert.deepEqual(valid.scopes, ['read', 'security']);
  assert.deepEqual(valid.ipAllowlist, ['10.0.0.1', '192.168.0.0/24']);
});

test('/api/health returns robust JSON with status mapping (ok/degraded/fail) and component checks', async () => {
  const payload = await core.buildPublicHealthPayload({
    events: [],
    dependencies: {
      smtp: {
        available: true,
        probeOk: true,
        detail: 'Teams webhook configured',
        mode: 'teams'
      }
    }
  });
  assert.ok(['ok', 'degraded', 'fail'].includes(payload.status));
  assert.equal(payload.ok, payload.status === 'ok');
  assert.equal(typeof payload.timestamp, 'string');
  assert.equal(typeof payload.version, 'string');
  assert.ok(Array.isArray(payload.checks));
  assert.ok(payload.checks.length >= 4);
  assert.equal(typeof payload.summary.pass, 'number');
  assert.equal(typeof payload.summary.warn, 'number');
  assert.equal(typeof payload.summary.fail, 'number');
  assert.equal(typeof payload.database.status, 'string');
  assert.equal(typeof payload.dependencies.teamsWebhook.available, 'boolean');
  assert.equal(Object.prototype.hasOwnProperty.call(payload, 'host'), false);
  assert.equal(Object.prototype.hasOwnProperty.call(payload, 'listeners'), false);
  assert.equal(Object.prototype.hasOwnProperty.call(payload, 'process'), false);
  const detailed = await core.buildPublicHealthPayload({
    events: [],
    dependencies: {
      smtp: {
        available: true,
        probeOk: true,
        detail: 'Teams webhook configured',
        mode: 'teams'
      }
    }
  }, { detailed: true });
  assert.equal(Object.prototype.hasOwnProperty.call(detailed, 'host'), true);
  assert.equal(Object.prototype.hasOwnProperty.call(detailed, 'listeners'), true);
  assert.equal(Object.prototype.hasOwnProperty.call(detailed, 'process'), true);
  assert.equal(core.healthHttpStatusForState(payload.status), payload.status === 'fail' ? 503 : 200);
  assert.equal(core.healthHttpStatusForState('fail'), 503);
  assert.equal(core.healthHttpStatusForState('degraded'), 200);
  assert.equal(core.healthHttpStatusForState('ok'), 200);
});

test('security-relevant actions emit structured audit events with throttling support', () => {
  const state = makeAuditState();

  core.logSecurityAuditEvent(state, {
    actor: 'admin@cajal.local',
    action: 'auth_token_rejected',
    message: 'Authentication token rejected',
    detail: 'Bearer token hash not recognized',
    source: 'auth',
    classId: 402
  });
  assert.equal(state.events.length, 1);
  assert.equal(state.events[0].source, 'auth');
  assert.equal(state.events[0].action, 'auth_token_rejected');

  const key = 'security:api-token-scope:tok-1:security:/api/settings';
  core.logSecurityAuditEvent(state, {
    key,
    minIntervalMs: 60_000,
    actor: 'api-token:tok-1',
    action: 'api_token_scope_blocked',
    message: 'API token scope denied request',
    detail: 'requiredScope=security method=POST path=/api/settings'
  });
  core.logSecurityAuditEvent(state, {
    key,
    minIntervalMs: 60_000,
    actor: 'api-token:tok-1',
    action: 'api_token_scope_blocked',
    message: 'API token scope denied request',
    detail: 'requiredScope=security method=POST path=/api/settings'
  });
  assert.equal(state.events.length, 2);

  state.eventThrottle.set(key, { lastAt: Date.now() - 61_000, suppressed: 1 });
  core.logSecurityAuditEvent(state, {
    key,
    minIntervalMs: 60_000,
    actor: 'api-token:tok-1',
    action: 'api_token_scope_blocked',
    message: 'API token scope denied request',
    detail: 'requiredScope=security method=POST path=/api/settings'
  });
  assert.equal(state.events.length, 3);
  assert.match(state.events[0].detail, /suppressed=1/);
});

test('system update/apply endpoint enforces 1-per-5-minute rate limit per admin identity', () => {
  const state = makeAuditState();
  const key = 'update-apply:203.0.113.5:admin@cajal.local';
  const FIVE_MINUTES = 5 * 60 * 1000;

  const first = makeJsonRes();
  const allowed = core.enforceRateLimitOrSend(first, {
    key,
    max: 1,
    windowMs: FIVE_MINUTES,
    message: 'Update already triggered. Please wait 5 minutes before trying again.',
    state,
    actor: 'admin@cajal.local',
    action: 'system_update_rate_limited',
    detail: 'POST /api/system/update/apply ip=203.0.113.5'
  });

  const second = makeJsonRes();
  const blocked = core.enforceRateLimitOrSend(second, {
    key,
    max: 1,
    windowMs: FIVE_MINUTES,
    message: 'Update already triggered. Please wait 5 minutes before trying again.',
    state,
    actor: 'admin@cajal.local',
    action: 'system_update_rate_limited',
    detail: 'POST /api/system/update/apply ip=203.0.113.5'
  });

  assert.equal(allowed, true);
  assert.equal(blocked, false);
  assert.equal(second.statusCode, 429);
  assert.equal(second.json().code, 'rate_limited');
  assert.match(second.json().error, /wait 5 minutes/i);
  assert.ok(Number(second.getHeader('retry-after')) >= 1);
  assert.equal(state.events.length, 1);
  assert.equal(state.events[0].action, 'system_update_rate_limited');
});

test('diagnostics and error outputs redact secrets, tokens, and password-like values', () => {
  const text = 'Bearer abcdefghijklmnop token=supersecret password=hunter2 cajal_abcdefghijklmnopqrstuvwxyz';
  const redactedText = core.redactSecretsInText(text);
  assert.equal(/supersecret/.test(redactedText), false);
  assert.equal(/hunter2/.test(redactedText), false);
  assert.equal(/abcdefghijklmnopqrstuvwxyz/.test(redactedText), false);
  assert.match(redactedText, /\[redacted/);

  const redactedObject = core.redactForLogs({
    password: 's3cr3t',
    nested: {
      url: 'https://api.example.com/notify?token=abcd1234',
      auth: 'Bearer qwertyuiopasdfghjkl'
    }
  });
  assert.equal(redactedObject.password, '[redacted]');
  assert.match(redactedObject.nested.url, /\[redacted\]/);
  assert.equal(redactedObject.nested.auth, '[redacted]');

  const normalized = core.normalizeError(new Error('request failed with password=topsecret and Bearer topsecretbearer'));
  assert.equal(/topsecret/.test(normalized.message), false);
  assert.equal(/topsecretbearer/.test(normalized.message), false);
});
