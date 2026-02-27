'use strict';
const { sendJson, ensureAllowed } = require('../http');
const { logEvent, actorName } = require('../events');

function handleEvents({ req, res, url, state, requestUser, requestContext }) {
  if (req.method === 'GET' && url.pathname === '/api/events') {
    if (!requestUser?.authenticated) return sendJson(res, 401, { error: 'Authentication required' });
    const limit = Math.max(1, Math.min(5000, Number(url.searchParams.get('limit') || 200)));
    const since = String(url.searchParams.get('since') || '');
    const classId = Number(url.searchParams.get('class') || 0);
    const source = String(url.searchParams.get('source') || '').trim().toLowerCase();
    let rows = state.events.slice();
    if (since) rows = rows.filter((e) => e.ts > since);
    if (classId) rows = rows.filter((e) => Number(e.classId) === classId);
    if (source) rows = rows.filter((e) => String(e.source || '').toLowerCase() === source);
    return sendJson(res, 200, { events: rows.slice(0, limit) });
  }

  if (req.method === 'GET' && url.pathname === '/api/events/export') {
    if (!requestUser?.authenticated) return sendJson(res, 401, { error: 'Authentication required' });
    const format = String(url.searchParams.get('format') || 'json').toLowerCase();
    const since = String(url.searchParams.get('since') || '');
    let rows = state.events.slice();
    if (since) rows = rows.filter((e) => e.ts > since);
    const dateTag = new Date().toISOString().slice(0, 10);
    if (format === 'csv') {
      const csvEsc = (v) => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`;
      const header = 'ts,classId,source,actor,action,message,detail\n';
      const body = rows.map((e) => [e.ts, e.classId, e.source, e.actor, e.action, e.message, e.detail || ''].map(csvEsc).join(',')).join('\n');
      res.writeHead(200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': `attachment; filename="cajal-events-${dateTag}.csv"`
      });
      return res.end(header + body);
    }
    const out = JSON.stringify({ exportedAt: new Date().toISOString(), count: rows.length, events: rows }, null, 2);
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': `attachment; filename="cajal-events-${dateTag}.json"`
    });
    return res.end(out);
  }

  if (req.method === 'POST' && url.pathname === '/api/events/manual-refresh') {
    if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
    logEvent(state, {
      classId: 301,
      source: 'runtime',
      actor: actorName(requestUser),
      action: 'manual_global_refresh',
      message: 'Manual global refresh triggered from header control'
    });
    return sendJson(res, 200, { ok: true, ts: new Date().toISOString() });
  }

  if (req.method === 'GET' && url.pathname === '/api/audit') {
    if (!requestUser?.authenticated) return sendJson(res, 401, { error: 'Authentication required' });
    const limit = Math.max(1, Math.min(1000, Number(url.searchParams.get('limit') || 200)));
    const allowedClasses = new Set([101, 201, 202, 203, 204, 205]);
    const allowedSources = new Set(['settings', 'users', 'sites', 'devices', 'notifications', 'syslog', 'snmp', 'netflow']);
    const rows = state.events.filter((e) => {
      const classId = Number(e.classId) || 0;
      if (!allowedClasses.has(classId)) return false;
      if (!allowedSources.has(String(e.source || '').toLowerCase())) return false;
      return true;
    });
    return sendJson(res, 200, { events: rows.slice(0, limit) });
  }

  return false;
}

module.exports = { handleEvents };
