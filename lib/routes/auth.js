'use strict';
const crypto = require('crypto');
const QRCode = require('qrcode');

const { sendJson, sendServerError, ensureAllowed, readRequestBody, badRequestPayload } = require('../http');
const {
  enforceRateLimitOrSend,
  getLoginAccountLockState,
  recordLoginAccountFailure,
  clearLoginAccountFailures,
} = require('../ratelimit');
const {
  sessions,
  parseCookies,
  requestIsHttps,
  issueSessionCookie,
  clearSessionCookie,
  requestOriginFromHeaders,
} = require('../session');
const {
  logEvent,
  actorName,
  logSecurityAuditEvent,
  logEventThrottled,
  markUserLastLogin,
  resolveLocalUserByIdentifier,
} = require('../events');
const {
  entraConfigured,
  ssoConfigForClient,
  decodeJwtPayload,
  verifyJwt,
  mapUserRole,
  normalizeUserEntry,
  hashPassword,
  verifyPassword,
  makeTotpPayload,
  createSetupToken,
  consumeSetupToken,
  peekSetupToken,
  decryptTotpSecret,
  resolveTotpSecretState,
  localTotpMfaEnabled,
  issueLocalSession,
  buildUserRoleDirectory,
} = require('../auth');
const { generateTotpSecret, verifyTotp, encryptJson } = require('../crypto');
const { persistUsers } = require('../sites');
const { getAlertSilenceState } = require('../notifications');
const { getConfigIntegrityReport, redisDeleteSession } = require('../storage');
const shared = require('../shared');
const {
  PUBLIC_STATUS_RATE_LIMIT_MAX,
  PUBLIC_STATUS_RATE_LIMIT_WINDOW_MS,
  LOGIN_RATE_LIMIT_MAX,
  LOGIN_RATE_LIMIT_WINDOW_MS,
  STARTED_AT_MS,
  ENTRA_TENANT_ID,
  ENTRA_CLIENT_ID,
  ENTRA_CLIENT_SECRET,
  ENTRA_REDIRECT_URI,
  ENTRA_SCOPE,
  FORCE_SECURE_COOKIES,
  LOCAL_TOTP_ENABLED,
  ADMIN_USERS,
  MONITOR_USERS,
  PASSWORD_HASH_ITERATIONS,
} = require('../constants');

// TOTP replay prevention: tracks the last accepted TOTP step per user.
// Keyed by email, value is the TOTP time-step counter (Math.floor(epoch/30)).
// In-memory map provides fast path; persisted to user.localAuth.totpLastUsedStep
// so replay prevention survives server restarts.
const totpLastUsedStep = new Map();

function pruneTotpLastUsedStep() {
  const currentStep = Math.floor(Date.now() / 1000 / 30);
  for (const [email, step] of totpLastUsedStep) {
    // Remove entries older than 5 minutes (10 steps)
    if (currentStep - step > 10) totpLastUsedStep.delete(email);
  }
}

function handleAuth({ req, res, url, state, requestUser, requestContext }) {
  const requestCookies = parseCookies(req);
  const requestSecure = requestIsHttps(req, url);

  if (req.method === 'GET' && url.pathname === '/api/auth/me') {
    const runtimePayload = {
      globalDataRefreshMs: shared.runtimeSettings.globalDataRefreshMs,
      globalClockTimeZone: shared.runtimeSettings.globalClockTimeZone,
      globalClockHourMode: shared.runtimeSettings.globalClockHourMode
    };
    if (requestUser?.authenticated) {
      runtimePayload.internalDnsTarget = shared.runtimeSettings.internalDnsTarget || '';
      runtimePayload.localTotpEnabled = Boolean(shared.runtimeSettings.localTotpEnabled);
    }

    if (!requestUser?.authenticated) {
      sendJson(res, 200, {
        user: { authenticated: false, displayName: 'Guest', email: '', role: 'monitor', provider: 'none' },
        config: {
          enabled: entraConfigured(),
          provider: 'entra'
        },
        runtime: runtimePayload,
        alerting: {
          silenced: false,
          silencedUntil: '',
          silenceRemainingSec: 0
        },
        system: {
          nowMs: Date.now(),
          startedAt: '',
          uptimeSec: 0,
          dependencies: {}
        }
      });
      return true;
    }

    const silence = getAlertSilenceState(state);
    const configIntegrity = getConfigIntegrityReport();
    sendJson(res, 200, {
      user: requestUser,
      config: {
        enabled: entraConfigured(),
        provider: 'entra',
        tenantId: shared.ssoRuntimeConfig.tenantId || '',
        clientId: shared.ssoRuntimeConfig.clientId || '',
        redirectUri: shared.ssoRuntimeConfig.redirectUri || '',
        scope: shared.ssoRuntimeConfig.scope || ''
      },
      runtime: runtimePayload,
      alerting: {
        silenced: silence.active,
        silencedUntil: silence.untilMs ? new Date(silence.untilMs).toISOString() : '',
        silenceRemainingSec: silence.remainingSec
      },
      system: {
        nowMs: Date.now(),
        startedAt: new Date(STARTED_AT_MS).toISOString(),
        uptimeSec: Math.max(0, Math.floor(process.uptime())),
        dependencies: {
          snmpget: {
            available: Boolean(state.dependencies?.snmpget?.available),
            path: state.dependencies?.snmpget?.path || '',
            detail: state.dependencies?.snmpget?.detail || ''
          },
          smtp: {
            available: Boolean(state.dependencies?.smtp?.available),
            path: state.dependencies?.smtp?.path || '',
            detail: state.dependencies?.smtp?.detail || '',
            probeOk: state.dependencies?.smtp?.probeOk !== false,
            mode: state.dependencies?.smtp?.mode || ''
          },
          teams: {
            available: Boolean(state.dependencies?.smtp?.available),
            path: state.dependencies?.smtp?.path || '',
            detail: state.dependencies?.smtp?.detail || '',
            probeOk: state.dependencies?.smtp?.probeOk !== false
          }
        },
        configIntegrity
      }
    });
    return true;
  }

  if (req.method === 'POST' && url.pathname === '/api/auth/local/login') {
    if (
      !enforceRateLimitOrSend(res, {
        key: `login:${requestContext.remoteIp || 'unknown'}`,
        max: LOGIN_RATE_LIMIT_MAX,
        windowMs: LOGIN_RATE_LIMIT_WINDOW_MS,
        message: 'Too many login attempts. Please wait and retry.',
        state,
        actor: actorName(requestUser),
        action: 'login_rate_limited',
        detail: `${requestContext.method} ${requestContext.path} ip=${requestContext.remoteIp || 'unknown'}`,
        source: 'auth'
      })
    ) return true;
    readRequestBody(req, {
      allowedKeys: ['email', 'username', 'password', 'totp']
    })
      .then(async (body) => {
        const loginId = String(body.email || body.username || '').trim().toLowerCase();
        const loginAccountState = getLoginAccountLockState(loginId);
        if (loginAccountState.locked) {
          res.setHeader('Retry-After', String(loginAccountState.retryAfterSec));
          logEventThrottled(state, `auth:login_account_locked:${loginId || 'unknown'}`, 30 * 1000, {
            classId: 402,
            source: 'auth',
            actor: loginId || 'unknown-user',
            action: 'login_account_locked',
            message: 'Local login blocked by account lockout',
            detail: `retryAfterSec=${loginAccountState.retryAfterSec}`
          });
          return sendJson(res, 429, { error: 'Too many login attempts. Please wait and retry.', code: 'login_account_locked' });
        }
        const password = String(body.password || '');
        const totp = String(body.totp || '');
        const user = resolveLocalUserByIdentifier(state.users, loginId);
        if (!user) {
          recordLoginAccountFailure(loginId);
          logEvent(state, {
            classId: 402,
            source: 'auth',
            actor: loginId || 'unknown-user',
            action: 'login_failed',
            message: 'Local login failed',
            detail: 'Unknown username'
          });
          // Return identical shape to prevent account enumeration
          const dummyToken = crypto.randomBytes(24).toString('hex');
          return sendJson(res, 200, { next: 'set_password', setupToken: dummyToken });
        }
        const email = user.email;

        if (!verifyPassword(password, user.localAuth || {})) {
          const hasPassword = Boolean(user.localAuth?.passwordHash && user.localAuth?.passwordSalt);
          if (!hasPassword) {
            const setupToken = createSetupToken(email, 'set_password');
            return sendJson(res, 200, { next: 'set_password', setupToken });
          }
          const lock = recordLoginAccountFailure(loginId || email);
          if (lock.locked) {
            res.setHeader('Retry-After', String(lock.retryAfterSec));
            logEvent(state, {
              classId: 402,
              source: 'auth',
              actor: email,
              action: 'login_account_locked',
              message: 'Local login account lockout triggered',
              detail: `retryAfterSec=${lock.retryAfterSec}`
            });
            return sendJson(res, 429, { error: 'Too many login attempts. Please wait and retry.', code: 'login_account_locked' });
          }
          logEvent(state, {
            classId: 402,
            source: 'auth',
            actor: email,
            action: 'login_failed',
            message: 'Local login failed',
            detail: 'Bad password'
          });
          return sendJson(res, 401, { error: 'Invalid username or password' });
        }

        if (!localTotpMfaEnabled()) {
          clearLoginAccountFailures(loginId || email);
          clearLoginAccountFailures(email);
          issueLocalSession(req, res, user);
          await markUserLastLogin(state, email);
          logEvent(state, {
            classId: 401,
            source: 'auth',
            actor: email,
            action: 'login_success',
            message: 'Local login successful',
            detail: 'Password login'
          });
          return sendJson(res, 200, { ok: true });
        }

        const totpState = resolveTotpSecretState(user.localAuth || {});
        if (totpState.state === 'invalid') {
          logEvent(state, {
            classId: 422,
            source: 'auth',
            actor: email,
            action: 'totp_secret_unavailable',
            message: 'Stored TOTP secret is unavailable; re-enrollment required',
            detail: 'Ensure CAJAL_CONFIG_KEY is stable across restarts or reset local TOTP for this user'
          });
          return sendJson(res, 409, {
            error: 'Stored TOTP enrollment is unavailable. Ask an admin to reset local auth (or reset your own TOTP from My Security), then enroll again.',
            code: 'totp_secret_unavailable'
          });
        }
        if (totpState.state === 'enroll') {
          const enrollmentSecret = generateTotpSecret();
          const setupToken = createSetupToken(email, 'enroll_totp', enrollmentSecret);
          const totpPayload = await makeTotpPayload(email, enrollmentSecret, setupToken);
          return sendJson(res, 200, {
            next: 'enroll_totp',
            setupToken,
            ...totpPayload
          });
        }

        if (!totp) {
          return sendJson(res, 200, { next: 'verify_totp' });
        }
        const totpStep = Math.floor(Date.now() / 1000 / 30);
        const lastUsedStep = Number(user.localAuth?.totpLastUsedStep || 0);
        if (lastUsedStep === totpStep || totpLastUsedStep.get(email) === totpStep) {
          return sendJson(res, 401, { error: 'TOTP code already used. Wait for the next code.' });
        }
        if (!verifyTotp(totpState.secret, totp)) {
          const lock = recordLoginAccountFailure(loginId || email);
          if (lock.locked) {
            res.setHeader('Retry-After', String(lock.retryAfterSec));
            logEvent(state, {
              classId: 402,
              source: 'auth',
              actor: email,
              action: 'login_account_locked',
              message: 'Local login account lockout triggered',
              detail: `retryAfterSec=${lock.retryAfterSec}`
            });
            return sendJson(res, 429, { error: 'Too many login attempts. Please wait and retry.', code: 'login_account_locked' });
          }
          logEvent(state, {
            classId: 402,
            source: 'auth',
            actor: email,
            action: 'totp_failed',
            message: 'TOTP verification failed'
          });
          return sendJson(res, 401, { error: 'Invalid TOTP code' });
        }

        totpLastUsedStep.set(email, totpStep);
        user.localAuth = user.localAuth || {};
        user.localAuth.totpLastUsedStep = totpStep;
        await persistUsers(state.users);
        clearLoginAccountFailures(loginId || email);
        clearLoginAccountFailures(email);
        issueLocalSession(req, res, user);
        await markUserLastLogin(state, email);
        logEvent(state, {
          classId: 401,
          source: 'auth',
          actor: email,
          action: 'login_success',
          message: 'Local login successful',
          detail: 'Password + TOTP'
        });
        return sendJson(res, 200, { ok: true });
      })
      .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    return true;
  }

  if (req.method === 'POST' && url.pathname === '/api/auth/local/setup-password') {
    if (
      !enforceRateLimitOrSend(res, {
        key: `setup:${requestContext.remoteIp || 'unknown'}`,
        max: LOGIN_RATE_LIMIT_MAX,
        windowMs: LOGIN_RATE_LIMIT_WINDOW_MS,
        message: 'Too many setup attempts. Please wait and retry.',
        state,
        actor: actorName(requestUser),
        action: 'setup_rate_limited',
        detail: `${requestContext.method} ${requestContext.path} ip=${requestContext.remoteIp || 'unknown'}`,
        source: 'auth'
      })
    ) return true;
    return readRequestBody(req, {
      allowedKeys: ['setupToken', 'password']
    })
      .then(async (body) => {
        const setupToken = String(body.setupToken || '');
        const password = String(body.password || '');
        if (password.length < 10) return sendJson(res, 400, { error: 'Password must be at least 10 characters' });
        const setup = consumeSetupToken(setupToken, 'set_password');
        if (!setup) return sendJson(res, 400, { error: 'Invalid or expired setup token' });
        const user = state.users.find((u) => u.email === setup.email);
        if (!user) return sendJson(res, 404, { error: 'User not found' });

        const hashed = hashPassword(password);
        user.localAuth = user.localAuth || {};
        user.localAuth.passwordHash = hashed.hash;
        user.localAuth.passwordSalt = hashed.salt;
        user.localAuth.passwordIterations = hashed.iterations;
        user.localAuth.passwordChangedAt = new Date().toISOString();

        await persistUsers(state.users);
        shared.userRoleDirectory = buildUserRoleDirectory(state.users);
        logEvent(state, {
          classId: 102,
          source: 'users',
          actor: actorName(requestUser),
          action: 'local_password_set',
          message: `Local password set for ${user.email}`
        });

        if (!localTotpMfaEnabled()) {
          shared.localSetupState.delete(setupToken);
          clearLoginAccountFailures(setup.email);
          issueLocalSession(req, res, user);
          await markUserLastLogin(state, user.email);
          logEvent(state, {
            classId: 401,
            source: 'auth',
            actor: user.email,
            action: 'login_success',
            message: 'Local login successful',
            detail: 'Password setup complete'
          });
          return sendJson(res, 200, { ok: true });
        }

        const enrollmentSecret = generateTotpSecret();
        setup.stage = 'enroll_totp';
        setup.secret = enrollmentSecret;
        setup.createdAt = Date.now();
        shared.localSetupState.set(setupToken, setup);
        const totpPayload = await makeTotpPayload(user.email, enrollmentSecret, setupToken);
        return sendJson(res, 200, {
          next: 'enroll_totp',
          setupToken,
          ...totpPayload
        });
      })
      .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    return true;
  }

  if (req.method === 'GET' && url.pathname === '/api/auth/local/totp-qr') {
    const setupToken = String(url.searchParams.get('setupToken') || '');
    const setup = peekSetupToken(setupToken, 'enroll_totp');
    if (!setup) return sendJson(res, 404, { error: 'Invalid or expired setup token' }), true;
    const user = state.users.find((u) => u.email === setup.email);
    if (!user) return sendJson(res, 404, { error: 'User not found' }), true;
    const orgName = (shared.locationSettings?.companyName || '').trim();
    const issuer = orgName && orgName !== 'My Organization' ? `Cajal – ${orgName}` : 'Cajal ICBM';
    const label = `${issuer}:${setup.email}`;
    const otpauthUrl = `otpauth://totp/${encodeURIComponent(label)}?secret=${encodeURIComponent(
      setup.secret
    )}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
    QRCode.toString(otpauthUrl, { type: 'svg', margin: 1, width: 220 })
      .then((svg) => {
        res.writeHead(200, {
          'Content-Type': 'image/svg+xml; charset=utf-8',
          'Cache-Control': 'no-store',
          'Content-Length': Buffer.byteLength(svg)
        });
        res.end(svg);
      })
      .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.auth.local.totp_qr' }, `QR generation failed: ${err?.message || 'Unknown error'}`));
    return true;
  }

  if (req.method === 'POST' && url.pathname === '/api/auth/local/verify-totp') {
    if (!localTotpMfaEnabled()) { sendJson(res, 400, { error: 'TOTP verification is disabled' }); return true; }
    if (
      !enforceRateLimitOrSend(res, {
        key: `setup:${requestContext.remoteIp || 'unknown'}`,
        max: LOGIN_RATE_LIMIT_MAX,
        windowMs: LOGIN_RATE_LIMIT_WINDOW_MS,
        message: 'Too many setup attempts. Please wait and retry.',
        state,
        actor: actorName(requestUser),
        action: 'setup_rate_limited',
        detail: `${requestContext.method} ${requestContext.path} ip=${requestContext.remoteIp || 'unknown'}`,
        source: 'auth'
      })
    ) return true;
    return readRequestBody(req, {
      allowedKeys: ['setupToken', 'totp']
    })
      .then(async (body) => {
        const setupToken = String(body.setupToken || '');
        const totp = String(body.totp || '');
        const setup = consumeSetupToken(setupToken, 'enroll_totp');
        if (!setup) return sendJson(res, 400, { error: 'Invalid or expired setup token' });
        if (!verifyTotp(setup.secret, totp)) return sendJson(res, 401, { error: 'Invalid TOTP code' });
        const user = state.users.find((u) => u.email === setup.email);
        if (!user) return sendJson(res, 404, { error: 'User not found' });

        user.localAuth = user.localAuth || {};
        user.localAuth.totpSecretEncrypted = encryptJson({ secret: setup.secret });
        user.localAuth.totpEnabled = true;
        user.localAuth.totpChangedAt = new Date().toISOString();
        shared.localSetupState.delete(setupToken);

        await persistUsers(state.users);
        shared.userRoleDirectory = buildUserRoleDirectory(state.users);
        clearLoginAccountFailures(user.email);
        issueLocalSession(req, res, user);
        await markUserLastLogin(state, user.email);
        logEvent(state, {
          classId: 103,
          source: 'auth',
          actor: user.email,
          action: 'totp_enrolled',
          message: 'TOTP enrollment completed'
        });
        return sendJson(res, 200, { ok: true });
      })
      .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    return true;
  }

  if (req.method === 'POST' && url.pathname === '/api/auth/local/reset-totp') {
    if (!requestUser?.authenticated) { sendJson(res, 401, { error: 'Authentication required' }); return true; }
    const email = String(requestUser.email || '').trim().toLowerCase();
    if (!email) { sendJson(res, 400, { error: 'Cannot resolve current user' }); return true; }
    const idx = state.users.findIndex((u) => u.email === email);
    if (idx < 0) { sendJson(res, 404, { error: 'Local user not found' }); return true; }
    const current = normalizeUserEntry(state.users[idx], state.users[idx]);
    current.localAuth = current.localAuth || {};
    current.localAuth.totpSecretEncrypted = null;
    current.localAuth.totpEnabled = false;
    current.localAuth.totpChangedAt = '';
    state.users[idx] = current;
    persistUsers(state.users)
      .then(() => {
        shared.userRoleDirectory = buildUserRoleDirectory(state.users);
        logEvent(state, {
          classId: 101,
          source: 'users',
          actor: actorName(requestUser),
          action: 'self_totp_reset',
          message: `User reset own TOTP: ${email}`
        });
        return sendJson(res, 200, { ok: true });
      })
      .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.auth.local.reset_totp' }));
    return true;
  }

  if (req.method === 'GET' && url.pathname === '/api/auth/login') {
    if (!entraConfigured()) {
      res.writeHead(302, { Location: '/' });
      res.end();
      return true;
    }
    // Prune expired OAuth state entries (10-minute TTL)
    const pruneNow = Date.now();
    for (const [k, v] of shared.oauthState) {
      if (pruneNow - (typeof v === 'number' ? v : Number(v?.createdAt || 0)) > 600000) shared.oauthState.delete(k);
    }
    const stateToken = crypto.randomBytes(24).toString('hex');
    shared.oauthState.set(stateToken, pruneNow);
    const authUrl = new URL(
      `https://login.microsoftonline.com/${encodeURIComponent(shared.ssoRuntimeConfig.tenantId)}/oauth2/v2.0/authorize`
    );
    authUrl.searchParams.set('client_id', shared.ssoRuntimeConfig.clientId);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('redirect_uri', shared.ssoRuntimeConfig.redirectUri);
    authUrl.searchParams.set('response_mode', 'query');
    authUrl.searchParams.set('scope', shared.ssoRuntimeConfig.scope);
    authUrl.searchParams.set('state', stateToken);
    res.writeHead(302, { Location: authUrl.toString() });
    res.end();
    return true;
  }

  if (req.method === 'GET' && url.pathname === '/api/auth/callback') {
    const stateToken = url.searchParams.get('state') || '';
    const code = url.searchParams.get('code') || '';
    if (!stateToken || !shared.oauthState.has(stateToken)) { sendJson(res, 400, { error: 'Invalid OAuth state' }); return true; }
    shared.oauthState.delete(stateToken);
    if (!code) { sendJson(res, 400, { error: 'Authorization code missing' }); return true; }

    const tokenUrl = `https://login.microsoftonline.com/${encodeURIComponent(shared.ssoRuntimeConfig.tenantId)}/oauth2/v2.0/token`;
    const body = new URLSearchParams();
    body.set('client_id', shared.ssoRuntimeConfig.clientId);
    body.set('client_secret', shared.ssoRuntimeConfig.clientSecret);
    body.set('grant_type', 'authorization_code');
    body.set('code', code);
    body.set('redirect_uri', shared.ssoRuntimeConfig.redirectUri);
    body.set('scope', shared.ssoRuntimeConfig.scope);

    const abortCtl = new AbortController();
    const fetchTimer = setTimeout(() => abortCtl.abort(), 10000);
    fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      signal: abortCtl.signal
    })
      .then((r) => r.json().then((payload) => ({ ok: r.ok, payload })))
      .then(async ({ ok, payload }) => {
        if (!ok || !payload.id_token) {
          const detail = 'SSO token exchange failed';
          return sendJson(res, 401, { error: detail });
        }

        const tenantId = String(shared.ssoRuntimeConfig?.tenantId || '').trim();
        const { verified, claims } = await verifyJwt(payload.id_token, tenantId);
        if (!verified) {
          logEvent(state, { classId: 402, source: 'auth', actor: 'entra', action: 'jwt_verify_failed', message: 'SSO id_token signature verification failed' });
          return sendJson(res, 401, { error: 'SSO token signature verification failed' });
        }
        const email = String(claims.preferred_username || claims.email || '');
        const displayName = String(claims.name || email || 'User');
        const role = mapUserRole(claims);
        const previousSid = String(requestCookies.cajal_sid || '').trim();
        if (previousSid) sessions.delete(previousSid);
        const now = Date.now();
        const sid = crypto.randomBytes(24).toString('hex');
        sessions.set(sid, {
          createdAt: now,
          lastSeenAt: now,
          user: { authenticated: true, displayName, email, role, provider: 'entra' }
        });
        await markUserLastLogin(state, email);
        issueSessionCookie(res, sid, { secure: requestSecure });
        logEvent(state, {
          classId: 401,
          source: 'auth',
          actor: email || 'entra-user',
          action: 'login_success',
          message: 'Entra login successful'
        });
        res.writeHead(302, { Location: '/' });
        return res.end();
      })
      .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.auth.oauth.callback' }, `OAuth callback failed: ${err?.message || 'Unknown error'}`))
      .finally(() => clearTimeout(fetchTimer));
    return true;
  }

  if ((req.method === 'POST' || req.method === 'GET') && url.pathname === '/api/auth/logout') {
    if (
      !enforceRateLimitOrSend(res, {
        key: `logout:${requestContext.remoteIp || 'unknown'}`,
        max: 20,
        windowMs: 60000,
        message: 'Too many logout requests. Please wait.',
        state,
        actor: actorName(requestUser),
        action: 'logout_rate_limited',
      })
    ) return true;
    if (requestCookies.cajal_sid) {
      sessions.delete(requestCookies.cajal_sid);
      redisDeleteSession(requestCookies.cajal_sid);
    }
    clearSessionCookie(res, { secure: requestSecure });
    logEvent(state, {
      classId: 401,
      source: 'auth',
      actor: actorName(requestUser),
      action: 'logout',
      message: 'User logged out'
    });
    if (req.method === 'GET') {
      res.writeHead(302, { Location: '/login.html' });
      res.end();
      return true;
    }
    sendJson(res, 200, { ok: true });
    return true;
  }

  if (req.method === 'GET' && url.pathname === '/login.html') {
    if (requestUser?.authenticated) {
      res.writeHead(302, { Location: '/' });
      res.end();
      return true;
    }
    return false; // Let static file server handle it
  }

  return false;
}

module.exports = { handleAuth, pruneTotpLastUsedStep };
