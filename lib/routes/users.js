'use strict';
const { sendJson, sendServerError, ensureAllowed, readRequestBody, badRequestPayload } = require('../http');
const { logEvent, actorName } = require('../events');
const { normalizeUserEntry, sanitizeUserForClient, buildUserRoleDirectory } = require('../auth');
const { persistUsers } = require('../sites');
const shared = require('../shared');
const { PASSWORD_HASH_ITERATIONS } = require('../constants');

function handleUsers({ req, res, url, state, requestUser, requestContext }) {
  if (req.method === 'GET' && url.pathname === '/api/users') {
    if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
    return sendJson(res, 200, state.users.map((u) => sanitizeUserForClient(u)));
  }

  if (req.method === 'POST' && url.pathname === '/api/users') {
    if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
    return readRequestBody(req, {
      allowedKeys: ['email', 'displayName', 'role', 'lastLoginAt', 'localAuth']
    })
      .then(async (body) => {
        // Strip any pre-computed auth fields — hashes/secrets must only be set
        // by the server's own cryptographic flows, never by API callers.
        if (body?.localAuth && typeof body.localAuth === 'object') {
          const { passwordHash, passwordSalt, totpSecretEncrypted, totpEnabled, ...safeLocalAuth } = body.localAuth;
          body = { ...body, localAuth: safeLocalAuth };
        }
        const user = normalizeUserEntry(body || {}, {});
        if (!user.email) return sendJson(res, 400, { error: 'email is required' });
        const idx = state.users.findIndex((u) => u.email === user.email);
        if (idx >= 0) {
          state.users[idx] = normalizeUserEntry({ ...state.users[idx], ...user }, state.users[idx]);
          logEvent(state, {
            classId: 101,
            source: 'users',
            actor: actorName(requestUser),
            action: 'user_update',
            message: `User updated: ${user.email}`
          });
        } else {
          state.users.push(user);
          logEvent(state, {
            classId: 101,
            source: 'users',
            actor: actorName(requestUser),
            action: 'user_create',
            message: `User added: ${user.email}`
          });
        }
        await persistUsers(state.users);
        shared.userRoleDirectory = buildUserRoleDirectory(state.users);
        const saved = state.users.find((u) => u.email === user.email) || user;
        return sendJson(res, 200, { user: sanitizeUserForClient(saved) });
      })
      .catch((err) => sendJson(res, 400, badRequestPayload(err)));
  }

  if (req.method === 'PATCH' && /^\/api\/users\/[^/]+$/.test(url.pathname)) {
    if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
    const match = url.pathname.match(/^\/api\/users\/([^/]+)$/);
    const email = decodeURIComponent(match?.[1] || '').trim().toLowerCase();
    if (!email) return sendJson(res, 400, { error: 'Invalid user path' });
    return readRequestBody(req, {
      allowedKeys: ['displayName', 'role']
    })
      .then(async (body) => {
        const idx = state.users.findIndex((u) => u.email === email);
        if (idx < 0) return sendJson(res, 404, { error: 'User not found' });
        const current = normalizeUserEntry(state.users[idx], state.users[idx]);
        const next = normalizeUserEntry({
          email,
          displayName: body.displayName ?? current.displayName,
          role: body.role ?? current.role
        }, current);
        state.users[idx] = next;
        await persistUsers(state.users);
        shared.userRoleDirectory = buildUserRoleDirectory(state.users);
        logEvent(state, {
          classId: 101,
          source: 'users',
          actor: actorName(requestUser),
          action: 'user_role_update',
          message: `User role/profile updated: ${email}`,
          detail: `role=${next.role}`
        });
        return sendJson(res, 200, { user: sanitizeUserForClient(next) });
      })
      .catch((err) => sendJson(res, 400, badRequestPayload(err)));
  }

  if (req.method === 'DELETE' && /^\/api\/users\/[^/]+$/.test(url.pathname)) {
    if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
    const match = url.pathname.match(/^\/api\/users\/([^/]+)$/);
    const email = decodeURIComponent(match?.[1] || '').trim().toLowerCase();
    if (!email) return sendJson(res, 400, { error: 'Invalid user path' });
    if (String(requestUser.email || '').trim().toLowerCase() === email) {
      return sendJson(res, 400, { error: 'You cannot delete your own account' });
    }
    const idx = state.users.findIndex((u) => u.email === email);
    if (idx < 0) return sendJson(res, 404, { error: 'User not found' });
    state.users.splice(idx, 1);
    return persistUsers(state.users)
      .then(() => {
        shared.userRoleDirectory = buildUserRoleDirectory(state.users);
        logEvent(state, {
          classId: 101,
          source: 'users',
          actor: actorName(requestUser),
          action: 'user_delete',
          message: `User deleted: ${email}`
        });
        return sendJson(res, 200, { ok: true, email });
      })
      .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.users.delete' }));
  }

  if (req.method === 'POST' && /^\/api\/users\/[^/]+\/reset-local$/.test(url.pathname)) {
    if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
    const match = url.pathname.match(/^\/api\/users\/([^/]+)\/reset-local$/);
    const email = decodeURIComponent(match?.[1] || '').trim().toLowerCase();
    if (!email) return sendJson(res, 400, { error: 'Invalid user path' });
    return readRequestBody(req, {
      allowedKeys: ['password', 'totp']
    })
      .then(async (body) => {
        const idx = state.users.findIndex((u) => u.email === email);
        if (idx < 0) return sendJson(res, 404, { error: 'User not found' });
        const resetPassword = Boolean(body?.password);
        const resetTotp = Boolean(body?.totp);
        if (!resetPassword && !resetTotp) {
          return sendJson(res, 400, { error: 'Specify password and/or totp reset' });
        }
        const current = normalizeUserEntry(state.users[idx], state.users[idx]);
        current.localAuth = current.localAuth || {};
        if (resetPassword) {
          current.localAuth.passwordHash = '';
          current.localAuth.passwordSalt = '';
          current.localAuth.passwordIterations = PASSWORD_HASH_ITERATIONS;
          current.localAuth.passwordChangedAt = '';
        }
        if (resetTotp) {
          current.localAuth.totpSecretEncrypted = null;
          current.localAuth.totpEnabled = false;
          current.localAuth.totpChangedAt = '';
        }
        state.users[idx] = current;
        await persistUsers(state.users);
        shared.userRoleDirectory = buildUserRoleDirectory(state.users);
        logEvent(state, {
          classId: 101,
          source: 'users',
          actor: actorName(requestUser),
          action: 'user_local_reset',
          message: `Local auth reset: ${email}`,
          detail: `password=${resetPassword} totp=${resetTotp}`
        });
        return sendJson(res, 200, { user: sanitizeUserForClient(current) });
      })
      .catch((err) => sendJson(res, 400, badRequestPayload(err)));
  }

  return false;
}

module.exports = { handleUsers };
