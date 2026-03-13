'use strict';
const { sendJson, sendServerError, ensureAllowed, readRequestBody, badRequestPayload } = require('../http');
const { logEvent, actorName } = require('../events');
const { smartWriteFile } = require('../storage');
const { getAlertSilenceState, isAlertingSilenced, dispatchWebhookRouteNotification } = require('../notifications');
const { buildWebhookTemplateContextForStatus } = require('../monitoring');
const net = require('net');
const {
  DEVICES_FILE,
  ALERT_SILENCE_DURATION_MS,
  WEBHOOK_ROUTE_MAP,
} = require('../constants');

function handleDevices({ req, res, url, state, requestUser, requestContext }) {
  if (req.method === 'GET' && url.pathname === '/api/devices') {
    if (!requestUser?.authenticated) return sendJson(res, 401, { error: 'Authentication required' });
    const siteId = url.searchParams.get('siteId');
    const devices = siteId ? state.devices.filter((d) => d.siteId === siteId) : state.devices;
    return sendJson(res, 200, devices);
  }

  if (req.method === 'POST' && url.pathname === '/api/devices') {
    if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
    return readRequestBody(req, {
      allowedKeys: ['name', 'ip', 'type', 'siteId']
    })
      .then(async (body) => {
        if (!body.name || !body.ip || !body.type || !body.siteId) {
          return sendJson(res, 400, { error: 'name, ip, type, and siteId are required' });
        }
        if (!state.sites.find((s) => s.id === body.siteId)) {
          return sendJson(res, 404, { error: 'siteId does not match any existing site' });
        }
        if (!net.isIP(body.ip)) {
          return sendJson(res, 400, { error: 'ip must be a valid IPv4 or IPv6 address' });
        }

        const newDevice = {
          id: `dev-${Date.now()}`,
          name: body.name,
          ip: body.ip,
          type: body.type,
          siteId: body.siteId,
          status: 'up',
          cpu: 0,
          memory: 0,
          lastSeen: new Date().toISOString()
        };

        state.devices.push(newDevice);
        await smartWriteFile(DEVICES_FILE, JSON.stringify(state.devices, null, 2), 'utf8');
        logEvent(state, {
          classId: 205,
          source: 'devices',
          actor: actorName(requestUser),
          action: 'device_add',
          message: `Device added: ${newDevice.name}`,
          detail: `site=${newDevice.siteId} ip=${newDevice.ip}`
        });
        return sendJson(res, 201, newDevice);
      })
      .catch((err) => sendJson(res, 400, badRequestPayload(err)));
  }

  if (req.method === 'GET' && url.pathname === '/api/alerts') {
    if (!requestUser?.authenticated) return sendJson(res, 401, { error: 'Authentication required' });
    return sendJson(res, 200, state.alerts);
  }

  if (req.method === 'GET' && url.pathname === '/api/alerts/silence') {
    if (!requestUser?.authenticated) return sendJson(res, 401, { error: 'Authentication required' });
    const silence = getAlertSilenceState(state);
    return sendJson(res, 200, {
      silenced: silence.active,
      silencedUntil: silence.untilMs ? new Date(silence.untilMs).toISOString() : '',
      silenceRemainingSec: silence.remainingSec
    });
  }

  if (req.method === 'POST' && url.pathname === '/api/alerts/silence/toggle') {
    if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
    const current = getAlertSilenceState(state);
    if (current.active) {
      state.alertSilenceUntilMs = 0;
      logEvent(state, {
        classId: 101,
        source: 'notifications',
        actor: actorName(requestUser),
        action: 'alerts_unsilenced_manual',
        message: 'Global alert silence manually disabled'
      });
      const routeId = 'system_alerts_resumed';
      const timestamp = new Date().toISOString();
      const context = buildWebhookTemplateContextForStatus({
        site: { name: 'Cajal System', role: 'other', firewall: { name: 'N/A', wanIp: 'N/A', wanIp2: 'N/A' } },
        previousStatus: 'warn',
        nextStatus: 'up',
        locationName: 'System',
        reason: 'alerts_unsilenced_manual',
        detail: 'Global alert silence manually disabled',
        timestamp,
        routeId,
        routeLabel: WEBHOOK_ROUTE_MAP.get(routeId)?.label || 'System Alerts Resumed',
        section: 'system',
        signal: 'restore'
      });
      dispatchWebhookRouteNotification(state, {
        routeId,
        title: '[CAJAL SYSTEM] Alerting Resumed',
        defaultMessage: `Global alert silence manually disabled.\nTimestamp: ${timestamp}`,
        context,
        source: 'notifications',
        actor: actorName(requestUser),
        action: 'alerts_unsilenced_manual',
        respectSilence: false
      });
    } else {
      state.alertSilenceUntilMs = Date.now() + ALERT_SILENCE_DURATION_MS;
      logEvent(state, {
        classId: 101,
        source: 'notifications',
        actor: actorName(requestUser),
        action: 'alerts_silenced_manual',
        message: `Global alerts silenced for ${Math.round(ALERT_SILENCE_DURATION_MS / 60000)} minutes`
      });
      const routeId = 'system_alerts_silenced';
      const timestamp = new Date().toISOString();
      const minutes = Math.round(ALERT_SILENCE_DURATION_MS / 60000);
      const context = buildWebhookTemplateContextForStatus({
        site: { name: 'Cajal System', role: 'other', firewall: { name: 'N/A', wanIp: 'N/A', wanIp2: 'N/A' } },
        previousStatus: 'up',
        nextStatus: 'warn',
        locationName: 'System',
        reason: 'alerts_silenced_manual',
        detail: `Global alerts silenced for ${minutes} minutes`,
        timestamp,
        routeId,
        routeLabel: WEBHOOK_ROUTE_MAP.get(routeId)?.label || 'System Alerts Silenced',
        section: 'system',
        signal: 'warn'
      });
      dispatchWebhookRouteNotification(state, {
        routeId,
        title: '[CAJAL SYSTEM] Alerting Silenced',
        defaultMessage: `Global alerts silenced for ${minutes} minutes.\nTimestamp: ${timestamp}`,
        context,
        source: 'notifications',
        actor: actorName(requestUser),
        action: 'alerts_silenced_manual',
        respectSilence: false
      });
    }
    const silence = getAlertSilenceState(state);
    return sendJson(res, 200, {
      silenced: silence.active,
      silencedUntil: silence.untilMs ? new Date(silence.untilMs).toISOString() : '',
      silenceRemainingSec: silence.remainingSec
    });
  }

  if (req.method === 'GET' && url.pathname === '/api/topology') {
    if (!requestUser?.authenticated) return sendJson(res, 401, { error: 'Authentication required' });
    return sendJson(res, 200, {
      nodes: state.devices.map((d) => ({ id: d.id, label: d.name, status: d.status, type: d.type })),
      edges: state.links
    });
  }

  return false;
}

module.exports = { handleDevices };
