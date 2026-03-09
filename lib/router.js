'use strict';
const fs = require('fs');
const path = require('path');

const {
  API_TOKEN_RATE_LIMIT_MAX,
  API_TOKEN_RATE_LIMIT_WINDOW_MS,
  PUBLIC_DIR,
} = require('./constants');

const {
  sendJson,
  sendServerError,
} = require('./http');

const {
  enforceRateLimitOrSend,
} = require('./ratelimit');

const {
  parseCookies,
  requestIsHttps,
  applySecurityHeaders,
  validateCsrfRequest,
} = require('./session');

const {
  requiredApiTokenScopeForRequest,
  apiTokenHasScope,
} = require('./tokens');

const {
  getUserFromRequest,
  sessionFromCookies,
  touchSessionActivity,
} = require('./auth');

const {
  actorName,
  logSecurityAuditEvent,
} = require('./events');

// ── Route modules ────────────────────────────────────────────────────────────
const { handleAuth } = require('./routes/auth');
const { handleEvents } = require('./routes/events');
const { handleSettings } = require('./routes/settings');
const { handleSystem } = require('./routes/system');
const { handleBackup } = require('./routes/backup');
const { handleAgent } = require('./routes/agent');
const { handleHealth } = require('./routes/health');
const { handleSites } = require('./routes/sites');
const { handleUsers } = require('./routes/users');
const { handleDevices } = require('./routes/devices');

const routeHandlers = [
  handleAuth,
  handleEvents,
  handleSettings,
  handleSystem,
  handleBackup,
  handleAgent,
  handleHealth,
  handleSites,
  handleUsers,
  handleDevices,
];

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml'
};

function createHttpHandler(state) {
  return (req, res) => {
    req.setTimeout(60000, () => {
      if (!res.headersSent) sendJson(res, 408, { error: 'Request timeout', code: 'request_timeout' });
      req.destroy();
    });

    let url = new URL(req.url, `http://${req.headers.host}`);
    // API versioning: /api/v1/* → /api/* (backward-compatible alias)
    if (url.pathname.startsWith('/api/v1/')) {
      url = new URL(req.url.replace('/api/v1/', '/api/'), `http://${req.headers.host}`);
    }
    res.setHeader('X-API-Version', 'v1');
    const requestCookies = parseCookies(req);
    const remoteIpRaw = String(req.socket?.remoteAddress || '').replace('::ffff:', '');
    const requestUser = getUserFromRequest(req, state, requestCookies, {
      remoteIp: remoteIpRaw,
      method: req.method,
      path: url.pathname
    });
    const requestSecure = requestIsHttps(req, url);
    const sessionRecord = sessionFromCookies(requestCookies);
    if (
      sessionRecord
      && (requestUser?.provider === 'local' || requestUser?.provider === 'entra')
      && requestUser?.authenticated
    ) {
      touchSessionActivity(res, sessionRecord.sid, sessionRecord.session, { secure: requestSecure });
    }
    const requestContext = {
      method: req.method,
      path: url.pathname,
      query: Object.fromEntries(url.searchParams.entries()),
      remoteIp: remoteIpRaw,
      actor: String(requestUser?.email || requestUser?.displayName || 'anonymous')
    };
    try {
      applySecurityHeaders(req, res, url);
      if (req.__authIssue && url.pathname.startsWith('/api/')) {
        const issue = req.__authIssue;
        logSecurityAuditEvent(state, {
          key: `security:auth-issue:${issue.type}:${requestContext.remoteIp || 'unknown'}`,
          minIntervalMs: 60 * 1000,
          actor: 'anonymous',
          action: 'auth_token_rejected',
          message: `Authentication token rejected (${issue.type})`,
          detail: String(issue.detail || '').trim(),
          source: 'auth',
          classId: 402,
          location: requestContext.path
        });
      }
      const csrf = validateCsrfRequest(requestUser, req, url);
      if (!csrf.ok) {
        logSecurityAuditEvent(state, {
          key: `security:csrf:${requestContext.remoteIp || 'unknown'}:${requestContext.path}`,
          minIntervalMs: 30 * 1000,
          actor: actorName(requestUser),
          action: 'csrf_blocked',
          message: 'CSRF request blocked',
          detail: `${requestContext.method} ${requestContext.path} from ${requestContext.remoteIp || 'unknown'}`,
          source: 'security',
          classId: 402
        });
        return sendJson(res, 403, { error: csrf.error, code: csrf.code });
      }
      if (requestUser?.provider === 'api-token') {
        const requiredScope = requiredApiTokenScopeForRequest(req.method, url.pathname);
        if (!apiTokenHasScope(requestUser?.scopes, requiredScope)) {
          logSecurityAuditEvent(state, {
            key: `security:api-token-scope:${requestUser.tokenId || 'unknown'}:${requiredScope}:${requestContext.path}`,
            minIntervalMs: 30 * 1000,
            actor: actorName(requestUser),
            action: 'api_token_scope_blocked',
            message: 'API token scope denied request',
            detail: `requiredScope=${requiredScope} method=${requestContext.method} path=${requestContext.path}`,
            source: 'security',
            classId: 402
          });
          return sendJson(res, 403, {
            error: `API token is missing required scope: ${requiredScope}`,
            code: 'api_token_scope_forbidden'
          });
        }
      }

    // Per-token rate limit: cap all authenticated API-token requests
    if (requestUser?.provider === 'api-token' && requestUser?.tokenId) {
      if (
        !enforceRateLimitOrSend(res, {
          key: `api-token-req:${requestUser.tokenId}`,
          max: API_TOKEN_RATE_LIMIT_MAX,
          windowMs: API_TOKEN_RATE_LIMIT_WINDOW_MS,
          message: 'API token request rate limit exceeded. Please wait and retry.',
          state,
          actor: actorName(requestUser),
          action: 'api_token_rate_limited',
          detail: `${requestContext.method} ${requestContext.path}`,
          source: 'security'
        })
      ) return;
    }

    // ── Route dispatch ─────────────────────────────────────────────────────────
    const ctx = { req, res, url, state, requestUser, requestContext };
    for (const handler of routeHandlers) {
      const result = handler(ctx);
      if (result !== false) return;
    }

    // ── Static file fallback ───────────────────────────────────────────────────
    const cleanPath = url.pathname === '/' ? '/index.html' : url.pathname;
    const safePath = path.normalize(cleanPath).replace(/^([.][.][/\\])+/, '');
    const fullPath = path.resolve(PUBLIC_DIR, safePath);

    if (!fullPath.startsWith(PUBLIC_DIR)) return sendJson(res, 403, { error: 'Forbidden' });

    fs.stat(fullPath, (statErr, stats) => {
      if (statErr || !stats.isFile()) return sendJson(res, 404, { error: 'Not found' });
      const ext = path.extname(fullPath);
      const type = MIME_TYPES[ext] || 'application/octet-stream';
      const etag = `"${stats.size.toString(36)}-${Math.floor(stats.mtimeMs).toString(36)}"`;
      const isHtml = ext === '.html' || ext === '.htm';
      const cacheControl = isHtml ? 'no-cache' : 'public, max-age=3600';

      if (req.headers['if-none-match'] === etag) {
        res.writeHead(304, { ETag: etag, 'Cache-Control': cacheControl });
        return res.end();
      }

      fs.readFile(fullPath, (err, content) => {
        if (err) return sendJson(res, 404, { error: 'Not found' });
        res.writeHead(200, {
          'Content-Type': type,
          'Content-Length': content.length,
          ETag: etag,
          'Cache-Control': cacheControl
        });
        res.end(content);
      });
    });
    } catch (err) {
      return sendServerError(res, err, { ...requestContext, scope: 'http.request.unhandled' });
    }

  };
}

module.exports = { createHttpHandler };
