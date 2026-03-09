'use strict';
const { sendJson, sendServerError, ensureAllowed } = require('../http');
const { enforceRateLimitOrSend } = require('../ratelimit');
const { logEvent, actorName, logSecurityAuditEvent } = require('../events');
const { readTelemetryLogEntries, clearTelemetryLogEntries } = require('../logging');
const {
  APP_VERSION,
  GITHUB_REPO,
  UPDATE_IMAGE,
  WATCHTOWER_URL,
  WATCHTOWER_TOKEN,
} = require('../constants');

function semverNewer(latest, current) {
  const a = String(latest || '').split('.').map(Number);
  const b = String(current || '').split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((a[i] || 0) > (b[i] || 0)) return true;
    if ((a[i] || 0) < (b[i] || 0)) return false;
  }
  return false;
}

function handleSystem({ req, res, url, state, requestUser, requestContext }) {
    // ── Version check + update (Watchtower) ─────────────────────────────────────
    if (req.method === 'GET' && url.pathname === '/api/system/version/check') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      if (!GITHUB_REPO) return sendJson(res, 200, { configured: false, current: APP_VERSION });
      const cache = state._versionCheckCache;
      const ONE_HOUR = 60 * 60 * 1000;
      if (cache && cache.fetchedAt && (Date.now() - cache.fetchedAt) < ONE_HOUR) {
        return sendJson(res, 200, cache.value);
      }
      const watchtowerReady = Boolean(WATCHTOWER_URL && WATCHTOWER_TOKEN);
      return new Promise((resolve) => {
        const https = require('https');
        // Use GHCR tags API (public, works with private repos) to find latest version
        const IMAGE_NAME = String(UPDATE_IMAGE || 'ghcr.io/nniell90/cajal').replace(/^ghcr\.io\//, '').replace(/:.*$/, '');
        const tokenUrl = `https://ghcr.io/token?scope=repository:${IMAGE_NAME}:pull`;
        const tokenReq = https.request(tokenUrl, (tokenRes) => {
          let tokenBody = '';
          tokenRes.on('data', (chunk) => { tokenBody += chunk; });
          tokenRes.on('end', () => {
            try {
              const ghcrToken = JSON.parse(tokenBody).token;
              const tagsOpts = {
                hostname: 'ghcr.io',
                path: `/v2/${IMAGE_NAME}/tags/list`,
                method: 'GET',
                headers: { 'Authorization': `Bearer ${ghcrToken}` }
              };
              const tagsReq = https.request(tagsOpts, (tagsRes) => {
                let tagsBody = '';
                tagsRes.on('data', (chunk) => { tagsBody += chunk; });
                tagsRes.on('end', () => {
                  try {
                    const tags = JSON.parse(tagsBody).tags || [];
                    // Filter to semver tags (n.n.n), find highest
                    const semverTags = tags.filter((t) => /^\d+\.\d+\.\d+$/.test(t));
                    semverTags.sort((a, b) => {
                      const pa = a.split('.').map(Number), pb = b.split('.').map(Number);
                      for (let i = 0; i < 3; i++) { if (pa[i] !== pb[i]) return pb[i] - pa[i]; }
                      return 0;
                    });
                    const latest = semverTags[0] || '';
                    const current = APP_VERSION;
                    const updateAvailable = latest && latest !== current && semverNewer(latest, current);
                    const result = {
                      configured: true,
                      watchtowerReady,
                      current,
                      latest: latest || current,
                      updateAvailable,
                      releaseUrl: `https://github.com/${GITHUB_REPO}/releases/tag/v${latest}`,
                      releaseName: latest ? `v${latest}` : '',
                      publishedAt: '',
                      image: UPDATE_IMAGE || ''
                    };
                    state._versionCheckCache = { value: result, fetchedAt: Date.now() };
                    resolve(sendJson(res, 200, result));
                  } catch {
                    resolve(sendJson(res, 502, { error: 'Failed to parse GHCR tags response' }));
                  }
                });
              });
              tagsReq.on('error', (err) => resolve(sendJson(res, 502, { error: `GHCR API unreachable: ${err?.message || err}` })));
              tagsReq.setTimeout(8000, () => { tagsReq.destroy(); resolve(sendJson(res, 504, { error: 'GHCR API timeout' })); });
              tagsReq.end();
            } catch {
              resolve(sendJson(res, 502, { error: 'Failed to obtain GHCR token' }));
            }
          });
        });
        tokenReq.on('error', (err) => resolve(sendJson(res, 502, { error: `GHCR token request failed: ${err?.message || err}` })));
        tokenReq.setTimeout(8000, () => { tokenReq.destroy(); resolve(sendJson(res, 504, { error: 'GHCR token timeout' })); });
        tokenReq.end();
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/system/update/apply') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      if (
        !enforceRateLimitOrSend(res, {
          key: `update-apply:${requestContext.remoteIp || 'unknown'}:${String(requestUser?.email || '').toLowerCase()}`,
          max: 1,
          windowMs: 5 * 60 * 1000,
          message: 'Update already triggered. Please wait 5 minutes before trying again.',
          state,
          actor: actorName(requestUser),
          action: 'system_update_rate_limited',
          detail: `${requestContext.method} ${requestContext.path} ip=${requestContext.remoteIp || 'unknown'}`
        })
      ) return;
      if (!WATCHTOWER_URL || !WATCHTOWER_TOKEN) {
        return sendJson(res, 503, { error: 'Watchtower is not configured (CAJAL_WATCHTOWER_URL and CAJAL_WATCHTOWER_TOKEN required)' });
      }
      return new Promise((resolve) => {
        const http = require('http');
        const wtUrl = new URL(`${WATCHTOWER_URL}/v1/update`);
        const opts = {
          hostname: wtUrl.hostname,
          port: wtUrl.port || 80,
          path: wtUrl.pathname,
          method: 'POST',
          headers: { 'Authorization': `Bearer ${WATCHTOWER_TOKEN}` }
        };
        const req2 = http.request(opts, (r) => {
          r.resume();
          r.on('end', () => {
            if (r.statusCode >= 200 && r.statusCode < 300) {
              logSecurityAuditEvent(state, {
                actor: actorName(requestUser),
                action: 'system_update_triggered',
                message: 'System update triggered via Watchtower',
                detail: WATCHTOWER_URL,
                source: 'system',
                classId: 101
              });
              logEvent(state, {
                classId: 101,
                source: 'system',
                actor: actorName(requestUser),
                action: 'system_update_triggered',
                message: 'Self-update triggered via Watchtower',
                detail: `image=${UPDATE_IMAGE || 'configured image'}`
              });
              state._versionCheckCache = null;
              resolve(sendJson(res, 200, { ok: true, message: 'Update triggered. The container will restart shortly.' }));
            } else {
              resolve(sendJson(res, 502, { error: `Watchtower returned HTTP ${r.statusCode}` }));
            }
          });
        });
        req2.on('error', (err) => {
          resolve(sendJson(res, 502, { error: `Watchtower unreachable: ${err?.message || err}` }));
        });
        req2.setTimeout(10000, () => { req2.destroy(); resolve(sendJson(res, 504, { error: 'Watchtower timeout' })); });
        req2.end();
      });
    }

    if (req.method === 'GET' && url.pathname === '/api/telemetry/raw') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      const limit = Math.max(1, Math.min(5000, Number(url.searchParams.get('limit') || 500)));
      const protocol = String(url.searchParams.get('protocol') || '').trim().toLowerCase();
      const siteId = String(url.searchParams.get('siteId') || '').trim();
      const q = String(url.searchParams.get('q') || '').trim();
      return readTelemetryLogEntries(limit, { protocol, siteId, q })
        .then((entries) => sendJson(res, 200, { entries }))
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.telemetry.raw' }));
    }

    if (req.method === 'DELETE' && url.pathname === '/api/telemetry/raw') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return clearTelemetryLogEntries()
        .then(() => sendJson(res, 200, { ok: true }))
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.telemetry.raw.clear' }));
    }

    return false;
}

module.exports = { handleSystem, semverNewer };
