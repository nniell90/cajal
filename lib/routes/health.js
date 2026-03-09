'use strict';
const { sendJson, ensureAllowed } = require('../http');
const { enforceRateLimitOrSend } = require('../ratelimit');
const { actorName } = require('../events');
const { summarize, applyFlowStatus } = require('../sites');
const { getPoolStats } = require('../storage');
const { healthHttpStatusForState, buildPublicHealthPayload } = require('../health');
const shared = require('../shared');
const {
  PUBLIC_STATUS_RATE_LIMIT_MAX,
  PUBLIC_STATUS_RATE_LIMIT_WINDOW_MS,
} = require('../constants');

function handleHealth({ req, res, url, state, requestUser, requestContext }) {
  if (req.method === 'GET' && url.pathname === '/metrics') {
    if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
    const pool = getPoolStats();
    const uptime = Math.floor(process.uptime());
    const mem = process.memoryUsage();
    const lines = [
      '# HELP cajal_uptime_seconds Process uptime in seconds',
      '# TYPE cajal_uptime_seconds gauge',
      `cajal_uptime_seconds ${uptime}`,
      '# HELP cajal_requests_total Total HTTP requests handled',
      '# TYPE cajal_requests_total counter',
      `cajal_requests_total ${shared.prometheusMetrics.requestsTotal}`,
      ...['2xx', '3xx', '4xx', '5xx'].map((b) => `cajal_requests_by_status{status="${b}"} ${shared.prometheusMetrics.requestsByStatus.get(b) || 0}`),
      '# HELP cajal_events_stored Events currently in memory',
      '# TYPE cajal_events_stored gauge',
      `cajal_events_stored ${state.events.length}`,
      '# HELP cajal_sites_total Sites configured',
      '# TYPE cajal_sites_total gauge',
      `cajal_sites_total ${state.sites.length}`,
      '# HELP cajal_db_pool_connections Database pool connection counts',
      '# TYPE cajal_db_pool_connections gauge',
      `cajal_db_pool_connections{state="total"} ${pool.total}`,
      `cajal_db_pool_connections{state="idle"} ${pool.idle}`,
      `cajal_db_pool_connections{state="waiting"} ${pool.waiting}`,
      '# HELP cajal_heap_used_bytes Process heap used bytes',
      '# TYPE cajal_heap_used_bytes gauge',
      `cajal_heap_used_bytes ${mem.heapUsed}`,
      '# HELP cajal_heap_total_bytes Process heap total bytes',
      '# TYPE cajal_heap_total_bytes gauge',
      `cajal_heap_total_bytes ${mem.heapTotal}`,
      ''
    ].join('\n');
    res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4; charset=utf-8' });
    return res.end(lines);
  }

  if (req.method === 'GET' && url.pathname === '/api/health') {
    if (
      !enforceRateLimitOrSend(res, {
        key: `status:health:${requestContext.remoteIp || 'unknown'}`,
        max: PUBLIC_STATUS_RATE_LIMIT_MAX,
        windowMs: PUBLIC_STATUS_RATE_LIMIT_WINDOW_MS,
        message: 'Too many health status requests. Please wait and retry.',
        state,
        actor: actorName(requestUser),
        action: 'health_status_rate_limited',
        detail: `${requestContext.method} ${requestContext.path} ip=${requestContext.remoteIp || 'unknown'}`,
        source: 'security'
      })
    ) return;
    const detailedHealth = Boolean(requestUser?.authenticated && ensureAllowed(requestUser, ['admin']));
    return buildPublicHealthPayload(state, { detailed: detailedHealth })
      .then((payload) => sendJson(res, healthHttpStatusForState(payload.status), payload))
      .catch((err) => sendJson(res, 503, {
        ok: false,
        status: 'fail',
        timestamp: new Date().toISOString(),
        error: String(err?.message || err || 'Health check failed'),
        code: 'health_check_failed'
      }));
  }

  if (req.method === 'GET' && url.pathname === '/api/healthz') {
    return sendJson(res, 200, { ok: true, timestamp: new Date().toISOString() });
  }

  if (req.method === 'GET' && url.pathname === '/api/summary') {
    if (!requestUser?.authenticated) return sendJson(res, 401, { error: 'Authentication required' });
    return sendJson(res, 200, summarize(state.devices, state.alerts));
  }

  if (req.method === 'GET' && url.pathname === '/api/public-services') {
    if (!requestUser?.authenticated) return sendJson(res, 401, { error: 'Authentication required' });
    return sendJson(res, 200, {
      services: Array.isArray(state.publicServices) ? state.publicServices : []
    });
  }

  if (req.method === 'GET' && url.pathname === '/api/location-monitors') {
    if (!requestUser?.authenticated) return sendJson(res, 401, { error: 'Authentication required' });
    return sendJson(res, 200, {
      monitors: Array.isArray(state.locationPingMonitors) ? state.locationPingMonitors : []
    });
  }

  return false;
}

module.exports = { handleHealth };
