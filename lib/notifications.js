'use strict';
const crypto = require('crypto');
const shared = require('./shared');
const {
  WEBHOOK_ROUTE_IDS,
  WEBHOOK_ROUTE_MAP,
  WEBHOOK_ROUTE_CATALOG,
  WEBHOOK_SECTION_CATALOG,
  defaultRuntimeSettings,
  normalizeWebhookRoutingRules,
  normalizeWebhookSectionModes,
  normalizeWebhookRoutingMessages,
} = require('./constants');
const {
  logEvent,
  logEventThrottled,
  logSiteEvent,
  logSiteEventThrottled,
  locationNameForSite,
} = require('./events');

// ── Internal helpers ──────────────────────────────────────────────────────────
function normalizeRole(role) {
  const value = String(role || '').trim().toLowerCase();
  return ['firewall', 'collector', 'other'].includes(value) ? value : 'firewall';
}

function sanitizeMailHeaderValue(value = '') {
  return String(value || '').replace(/[\r\n]+/g, ' ').trim();
}

// ── Webhook routing runtime accessors ────────────────────────────────────────
function webhookRoutingForRuntime(config = shared.runtimeSettings) {
  return normalizeWebhookRoutingRules(config?.webhookRouting, defaultRuntimeSettings.webhookRouting);
}

function webhookSectionModesForRuntime(config = shared.runtimeSettings) {
  return normalizeWebhookSectionModes(config?.webhookSectionModes, defaultRuntimeSettings.webhookSectionModes);
}

function webhookRoutingMessagesForRuntime(config = shared.runtimeSettings) {
  return normalizeWebhookRoutingMessages(config?.webhookRoutingMessages, defaultRuntimeSettings.webhookRoutingMessages);
}

function webhookPayloadGroupForRuntime(config = shared.runtimeSettings) {
  return sanitizeMailHeaderValue(String(config?.teamsPayloadGroup || '').trim() || 'cajal').slice(0, 128) || 'cajal';
}

function isWebhookRouteEnabled(routeId = '', config = shared.runtimeSettings) {
  const id = String(routeId || '').trim().toLowerCase();
  if (!id || !WEBHOOK_ROUTE_IDS.has(id)) return true;
  const routes = webhookRoutingForRuntime(config);
  if (routes[id] === false) return false;
  const route = WEBHOOK_ROUTE_MAP.get(id);
  if (!route) return true;
  const sectionModes = webhookSectionModesForRuntime(config);
  const mode = String(sectionModes[route.section] || 'warn').trim().toLowerCase();
  const signal = String(route.signal || 'warn').trim().toLowerCase();
  if (mode === 'never') return false;
  if (mode === 'offline') return signal === 'offline';
  if (mode === 'restore') return signal === 'restore';
  return signal === 'warn' || signal === 'offline' || signal === 'restore';
}

function webhookRouteMessageForRuntime(routeId = '', config = shared.runtimeSettings) {
  const id = String(routeId || '').trim().toLowerCase();
  if (!id || !WEBHOOK_ROUTE_IDS.has(id)) return '';
  const messages = webhookRoutingMessagesForRuntime(config);
  return String(messages[id] || '').trim();
}

function renderWebhookMessageTemplate(template = '', context = {}) {
  const source = String(template || '');
  if (!source.trim()) return '';
  return source.replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, (_match, rawKey) => {
    const key = String(rawKey || '').trim();
    if (!key) return '';
    if (!Object.prototype.hasOwnProperty.call(context, key)) return '';
    const value = context[key];
    if (value === undefined || value === null) return '';
    return String(value);
  }).trim();
}

function webhookRoutePrefixForSite(site = null) {
  const role = normalizeRole(site?.role);
  if (role === 'collector') return 'collector_status';
  if (role === 'other') return 'other_status';
  return 'firewall_status';
}

function webhookRouteForStatusTransition(site = null, previousStatus = '', nextStatus = '') {
  const prev = String(previousStatus || '').trim().toLowerCase();
  const next = String(nextStatus || '').trim().toLowerCase();
  const prefix = webhookRoutePrefixForSite(site);
  if (next === 'down') return `${prefix}_offline`;
  if (next === 'warn') return `${prefix}_warn`;
  if (next === 'up' && (prev === 'down' || prev === 'warn')) return `${prefix}_restore`;
  return '';
}

function webhookRouteForSiteTest(site = null) {
  const role = normalizeRole(site?.role);
  if (role === 'collector') return 'collector_test_notify';
  if (role === 'other') return 'other_test_notify';
  return 'firewall_test_notify';
}

function webhookRouteSignalThemeColor(signal = '') {
  const normalized = String(signal || '').trim().toLowerCase();
  if (normalized === 'offline') return 'C62828';
  if (normalized === 'restore') return '2E7D32';
  return 'ED7D31';
}

function webhookRouteCatalogForClient() {
  return WEBHOOK_ROUTE_CATALOG.map((route) => ({
    id: route.id,
    section: route.section,
    signal: route.signal,
    label: route.label,
    description: route.description
  }));
}

function webhookSectionCatalogForClient() {
  return WEBHOOK_SECTION_CATALOG.map((section) => ({
    id: section.id,
    label: section.label
  }));
}

// ── Teams webhook retry helpers ───────────────────────────────────────────────
const {
  TEAMS_WEBHOOK_MAX_ATTEMPTS,
  TEAMS_WEBHOOK_RETRY_BASE_MS,
} = require('./constants');

function teamsWebhookRetryableStatus(status = 0) {
  const code = Number(status);
  if (!Number.isFinite(code)) return false;
  return code === 408 || code === 425 || code === 429 || code === 500 || code === 502 || code === 503 || code === 504;
}

function teamsWebhookRetryDelayMs(attempt = 1, baseMs = TEAMS_WEBHOOK_RETRY_BASE_MS) {
  const index = Math.max(1, Math.floor(Number(attempt) || 1));
  const seed = Math.max(50, Math.min(10000, Math.floor(Number(baseMs) || TEAMS_WEBHOOK_RETRY_BASE_MS)));
  return Math.min(15000, seed * (2 ** (index - 1)));
}

function teamsWebhookRetryableError(err) {
  if (!err) return false;
  if (teamsWebhookRetryableStatus(err.statusCode || err.status)) return true;
  const code = String(err.code || err?.cause?.code || '').trim().toUpperCase();
  if (['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'EAI_AGAIN', 'ENOTFOUND', 'EPIPE', 'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT'].includes(code)) {
    return true;
  }
  const name = String(err.name || '').trim();
  if (name === 'AbortError') return true;
  return false;
}

function sleepMs(ms = 0) {
  const delay = Math.max(0, Math.min(30000, Math.floor(Number(ms) || 0)));
  if (delay <= 0) return Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, delay));
}

async function postTeamsWebhookWithRetry(webhook, payload, timeoutMs) {
  let lastErr = null;
  for (let attempt = 1; attempt <= TEAMS_WEBHOOK_MAX_ATTEMPTS; attempt += 1) {
    let timer = null;
    try {
      const controller = new AbortController();
      timer = setTimeout(() => controller.abort(), timeoutMs);
      const response = await fetch(webhook, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload),
        signal: controller.signal
      });
      if (response.ok) return;
      const detail = String(await response.text().catch(() => '') || '').trim();
      const failure = new Error(`Teams webhook returned ${response.status}${detail ? `: ${detail}` : ''}`);
      failure.statusCode = response.status;
      lastErr = failure;
      if (!teamsWebhookRetryableStatus(response.status) || attempt >= TEAMS_WEBHOOK_MAX_ATTEMPTS) throw failure;
    } catch (err) {
      lastErr = err;
      if (!teamsWebhookRetryableError(err) || attempt >= TEAMS_WEBHOOK_MAX_ATTEMPTS) throw err;
    } finally {
      if (timer) clearTimeout(timer);
    }
    await sleepMs(teamsWebhookRetryDelayMs(attempt));
  }
  throw new Error(String(lastErr?.message || lastErr || 'Teams webhook send failed'));
}

async function sendTeamsNotification({ title = '', group = '', text = '', message = '', summary = '', themeColor = '0076D7' } = {}) {
  const { effectiveTeamsWebhookConfig } = require('./monitoring');
  const { url: webhook, timeoutMs } = effectiveTeamsWebhookConfig(shared.runtimeSettings);
  if (!webhook) {
    throw new Error('Teams webhook is not configured (set it in Settings or CAJAL_TEAMS_WEBHOOK_URL)');
  }
  const cleanTitle = sanitizeMailHeaderValue(title || summary || 'CAJAL Notification');
  const cleanGroup = sanitizeMailHeaderValue(group || 'cajal');
  const cleanSummary = sanitizeMailHeaderValue(summary || title || 'CAJAL Notification');
  const cleanMessage = String(message || text || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n').trim();
  const renderedMessage = cleanMessage || cleanSummary;
  const powerAutomatePayload = {
    title: cleanTitle,
    group: cleanGroup,
    message: renderedMessage
  };
  const escapeTeamsHtml = (value = '') => String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
  const htmlText = renderedMessage
    ? renderedMessage.split('\n').map((line) => escapeTeamsHtml(line)).join('<br>')
    : escapeTeamsHtml(cleanSummary);
  const cardPayload = {
    '@type': 'MessageCard',
    '@context': 'http://schema.org/extensions',
    summary: cleanSummary,
    themeColor: String(themeColor || '0076D7'),
    title: cleanTitle,
    text: htmlText
  };
  const fallbackPayload = {
    text: `${cleanTitle}\n${renderedMessage}`
  };
  const payloads = [powerAutomatePayload, cardPayload, fallbackPayload];
  let lastErr = null;
  for (const payload of payloads) {
    try {
      await postTeamsWebhookWithRetry(webhook, payload, timeoutMs);
      return;
    } catch (err) {
      lastErr = err;
    }
  }
  throw new Error(String(lastErr?.message || lastErr || 'Teams webhook send failed'));
}

function getAlertSilenceState(state) {
  const now = Date.now();
  const untilMs = Number(state?.alertSilenceUntilMs || 0);
  const active = untilMs > now;
  if (!active && state && state.alertSilenceUntilMs) {
    state.alertSilenceUntilMs = 0;
    logEventThrottled(state, 'alerts:silence_expired', 60 * 1000, {
      classId: 301,
      source: 'notifications',
      actor: 'cajal',
      action: 'alerts_unsilenced_auto',
      message: 'Global alert silence expired; alerting resumed'
    });
    const routeId = 'system_alerts_resumed';
    const timestamp = new Date().toISOString();
    const { buildWebhookTemplateContextForStatus } = require('./monitoring');
    const context = buildWebhookTemplateContextForStatus({
      site: { name: 'Cajal System', role: 'other', firewall: { name: 'N/A', wanIp: 'N/A', wanIp2: 'N/A' } },
      previousStatus: 'warn',
      nextStatus: 'up',
      locationName: 'System',
      reason: 'alerts_unsilenced_auto',
      detail: 'Global alert silence expired; alerting resumed',
      timestamp,
      routeId,
      routeLabel: WEBHOOK_ROUTE_MAP.get(routeId)?.label || 'System Alerts Resumed',
      section: 'system',
      signal: 'restore'
    });
    dispatchWebhookRouteNotification(state, {
      routeId,
      title: '[CAJAL SYSTEM] Alerting Resumed',
      defaultMessage: `Global alert silence expired.\nTimestamp: ${timestamp}`,
      context,
      source: 'notifications',
      actor: 'cajal',
      action: 'alerts_unsilenced_auto',
      respectSilence: false
    });
  }
  return {
    active,
    untilMs: active ? untilMs : 0,
    remainingSec: active ? Math.max(0, Math.ceil((untilMs - now) / 1000)) : 0
  };
}

function isAlertingSilenced(state) {
  return getAlertSilenceState(state).active;
}

function dispatchWebhookRouteNotification(state, {
  routeId = '',
  title = '',
  defaultMessage = '',
  context = {},
  themeColor = '',
  source = 'notifications',
  actor = 'collector',
  action = 'webhook_route_notify',
  respectSilence = true
} = {}) {
  const id = String(routeId || '').trim().toLowerCase();
  if (!id || !WEBHOOK_ROUTE_IDS.has(id)) return;
  if (respectSilence && isAlertingSilenced(state)) return;
  if (!isWebhookRouteEnabled(id, shared.runtimeSettings)) return;
  const route = WEBHOOK_ROUTE_MAP.get(id);
  const routeMessage = webhookRouteMessageForRuntime(id, shared.runtimeSettings);
  const payloadMessage = renderWebhookMessageTemplate(routeMessage, context) || String(defaultMessage || '').trim() || title;
  const payloadGroup = webhookPayloadGroupForRuntime(shared.runtimeSettings);
  const color = String(themeColor || webhookRouteSignalThemeColor(route?.signal)).trim() || '0076D7';
  sendTeamsNotification({
    title,
    group: payloadGroup || id,
    summary: title,
    message: payloadMessage,
    text: payloadMessage,
    themeColor: color
  })
    .catch((err) => {
      logEvent(state, {
        classId: 401,
        source,
        actor,
        action: `${action}_failed`,
        message: `Webhook route notification failed for ${id}`,
        detail: String(err?.message || err || 'unknown error')
      });
    });
}

function notifyCollectorAgentState(state, site, routeId, previousStatus, nextStatus, reason = '', detail = '', agentInfo = {}) {
  if (!site || !routeId) return;
  const routeMeta = WEBHOOK_ROUTE_MAP.get(routeId);
  const timestamp = new Date().toISOString();
  const { buildWebhookTemplateContextForStatus } = require('./monitoring');
  const context = buildWebhookTemplateContextForStatus({
    site,
    previousStatus,
    nextStatus,
    locationName: locationNameForSite(site),
    reason: reason || routeId,
    detail: detail || 'n/a',
    timestamp,
    routeId,
    routeLabel: routeMeta?.label || '',
    section: routeMeta?.section || '',
    signal: routeMeta?.signal || ''
  });
  context.agentHost = String(agentInfo?.hostname || '').trim() || 'unknown';
  context.agentRemoteIp = String(agentInfo?.remoteIp || '').trim() || 'unknown';
  context.agentLocalIp = String(agentInfo?.localIp || '').trim() || 'unknown';
  const message = [
    `${site.name} collector agent ${nextStatus === 'up' ? 'online' : 'offline'}.`,
    `Location: ${locationNameForSite(site)}`,
    `Host: ${context.agentHost}`,
    `Remote IP: ${context.agentRemoteIp}`,
    `Local IP: ${context.agentLocalIp}`,
    `Reason: ${reason || routeId}`,
    `Detail: ${detail || 'n/a'}`,
    `Timestamp: ${timestamp}`
  ].join('\n');
  dispatchWebhookRouteNotification(state, {
    routeId,
    title: `[CAJAL COLLECTOR] ${site.name} agent ${nextStatus === 'up' ? 'ONLINE' : 'OFFLINE'}`,
    defaultMessage: message,
    context,
    source: 'collector',
    actor: 'collector-agent',
    action: routeId,
    respectSilence: true
  });
}

function notifyCollectorWanFailover(state, site, previousPublicIp = '', nextPublicIp = '', probeSource = 'publicip') {
  if (!site) return;
  const notificationsEnabled = Boolean(site?.notifications?.enabled);
  if (!notificationsEnabled) return;
  const routeId = 'collector_wan_failover';
  if (!isWebhookRouteEnabled(routeId, shared.runtimeSettings)) return;
  const routeMeta = WEBHOOK_ROUTE_MAP.get(routeId);
  const timestamp = new Date().toISOString();
  const previousIp = String(previousPublicIp || '').trim();
  const nextIp = String(nextPublicIp || '').trim();
  const detail = `publicIp ${previousIp || 'unknown'} -> ${nextIp || 'unknown'} source=${probeSource}`;
  const { buildWebhookTemplateContextForStatus } = require('./monitoring');
  const context = buildWebhookTemplateContextForStatus({
    site,
    previousStatus: 'up',
    nextStatus: 'warn',
    locationName: locationNameForSite(site),
    reason: 'collector_wan_public_ip_changed',
    detail,
    timestamp,
    routeId,
    routeLabel: routeMeta?.label || '',
    section: routeMeta?.section || '',
    signal: routeMeta?.signal || ''
  });
  context.wanPublicIpPrevious = previousIp || 'N/A';
  context.wanPublicIpCurrent = nextIp || 'N/A';
  context.wanPublicIp = context.wanPublicIpCurrent;

  const message = [
    `Collector WAN public IP changed for ${site.name}.`,
    `Location: ${locationNameForSite(site)}`,
    `Previous Public IP: ${context.wanPublicIpPrevious}`,
    `Current Public IP: ${context.wanPublicIpCurrent}`,
    `Source: ${probeSource}`,
    `Timestamp: ${timestamp}`
  ].join('\n');
  dispatchWebhookRouteNotification(state, {
    routeId,
    title: `[CAJAL FAILOVER] ${site.name} WAN IP changed`,
    defaultMessage: message,
    context,
    source: 'collector',
    actor: 'collector-agent',
    action: 'collector_wan_failover',
    respectSilence: true
  });
}

function updateSystemDependencyNotificationState(state, reason = 'dependency_check') {
  const { systemDependencySignal, buildWebhookTemplateContextForStatus } = require('./monitoring');
  const nextSignal = systemDependencySignal(state);
  const previousSignal = String(state?.notificationState?.systemDependencySignal || '').trim().toLowerCase();
  if (!state.notificationState) state.notificationState = { systemDependencySignal: nextSignal, collectorWanPublicIp: {} };
  if (nextSignal === previousSignal) return;
  state.notificationState.systemDependencySignal = nextSignal;
  if (!previousSignal) return;
  const routeId = nextSignal === 'offline'
    ? 'system_dependency_offline'
    : (nextSignal === 'warn' ? 'system_dependency_warn' : 'system_dependency_restore');
  const title = `[CAJAL SYSTEM] Dependency ${nextSignal.toUpperCase()}`;
  const timestamp = new Date().toISOString();
  const detail = String(state?.dependencies?.smtp?.detail || 'n/a').trim();
  const context = buildWebhookTemplateContextForStatus({
    site: { name: 'Cajal System', role: 'other', firewall: { name: 'N/A', wanIp: 'N/A', wanIp2: 'N/A' } },
    previousStatus: previousSignal || 'unknown',
    nextStatus: nextSignal === 'offline' ? 'down' : (nextSignal === 'warn' ? 'warn' : 'up'),
    locationName: 'System',
    reason,
    detail,
    timestamp,
    routeId,
    routeLabel: WEBHOOK_ROUTE_MAP.get(routeId)?.label || 'System Dependency',
    section: 'system',
    signal: nextSignal
  });
  const message = [
    `System dependency state changed: ${previousSignal || 'unknown'} -> ${nextSignal}.`,
    `Reason: ${reason}`,
    `Detail: ${detail}`,
    `Timestamp: ${timestamp}`
  ].join('\n');
  dispatchWebhookRouteNotification(state, {
    routeId,
    title,
    defaultMessage: message,
    context,
    source: 'system',
    actor: 'cajal',
    action: 'system_dependency',
    respectSilence: false
  });
}

function dispatchStatusNotification(state, site, previousStatus, nextStatus, reason = '', detail = '') {
  if (isAlertingSilenced(state)) {
    logSiteEventThrottled(state, site, `notifications:silenced:${site.id}`, 60 * 1000, {
      classId: 301,
      source: 'notifications',
      actor: 'collector',
      action: 'status_notify_silenced',
      message: `Status notification suppressed for ${site.name}`,
      detail: `reason=${reason || 'status_change'}`
    });
    return;
  }
  const notifications = site.notifications || {};
  if (!notifications.enabled) return;
  const routeId = webhookRouteForStatusTransition(site, previousStatus, nextStatus);
  if (routeId && !isWebhookRouteEnabled(routeId, shared.runtimeSettings)) {
    logSiteEventThrottled(state, site, `notifications:route_off:${site.id}:${routeId}`, 60 * 1000, {
      classId: 301,
      source: 'notifications',
      actor: 'collector',
      action: 'status_notify_route_disabled',
      message: `Status notification route disabled for ${site.name}`,
      detail: `route=${routeId} reason=${reason || 'status_change'}`
    });
    return;
  }

  const locationName = locationNameForSite(site);
  const statusUpper = String(nextStatus || 'unknown').toUpperCase();
  const prevUpper = String(previousStatus || 'unknown').toUpperCase();
  const subject = `[CAJAL STATUS] ${locationName} / ${site.name} ${prevUpper} -> ${statusUpper}`;
  const eventTimestamp = new Date().toISOString();
  const body = [
    'Cajal status change detected.',
    `Location: ${locationName}`,
    `Device: ${site.name}`,
    `Firewall: ${site.firewall?.name || 'Unknown firewall'}`,
    `Status: ${prevUpper} -> ${statusUpper}`,
    `Reason: ${reason || 'status recompute'}`,
    `Detail: ${detail || 'n/a'}`,
    `WAN IP 1: ${site.firewall?.wanIp || 'N/A'}`,
    `WAN IP 2: ${site.firewall?.wanIp2 || 'N/A'}`,
    `Timestamp: ${eventTimestamp}`
  ].join('\n');
  const payloadGroup = webhookPayloadGroupForRuntime(shared.runtimeSettings);
  const configuredRouteMessage = webhookRouteMessageForRuntime(routeId, shared.runtimeSettings);
  const routeMeta = WEBHOOK_ROUTE_MAP.get(routeId);
  const { buildWebhookTemplateContextForStatus } = require('./monitoring');
  const messageContext = buildWebhookTemplateContextForStatus({
    site,
    previousStatus,
    nextStatus,
    locationName,
    reason,
    detail,
    timestamp: eventTimestamp,
    routeId,
    routeLabel: routeMeta?.label || '',
    section: routeMeta?.section || '',
    signal: routeMeta?.signal || ''
  });
  const payloadMessage = renderWebhookMessageTemplate(configuredRouteMessage, messageContext) || body;

  const themeColor = webhookRouteSignalThemeColor(routeMeta?.signal || (nextStatus === 'down' ? 'offline' : (nextStatus === 'warn' ? 'warn' : 'restore')));
  sendTeamsNotification({ title: subject, group: payloadGroup || locationName, summary: subject, text: payloadMessage, message: payloadMessage, themeColor })
    .then(() => {
      logSiteEvent(state, site, {
        classId: 301,
        source: 'notifications',
        actor: 'collector',
        action: 'status_notify_sent',
        message: `${locationName} / ${site.name} status Teams notification sent (${prevUpper} -> ${statusUpper})`,
        detail: `channel=teams reason=${reason || 'status_change'}`
      });
    })
    .catch((err) => {
      logSiteEvent(state, site, {
        classId: 401,
        source: 'notifications',
        actor: 'collector',
        action: 'status_notify_failed',
        message: `${locationName} / ${site.name} status Teams notification failed (${prevUpper} -> ${statusUpper})`,
        detail: `${err.message} | channel=teams reason=${reason || 'status_change'}`
      });
    });
}

function reconcileSiteStatus(state, site, reason = '', detail = '') {
  const { deriveSiteStatus } = require('./monitoring');
  const { markSiteDirty } = require('./sites');
  site.firewall = site.firewall || {};
  const previousStatus = String(site.firewall.status || 'down').trim().toLowerCase();
  const nextStatus = deriveSiteStatus(state, site);
  if (previousStatus === nextStatus) return;

  site.firewall.status = nextStatus;
  markSiteDirty(state);

  const locationName = locationNameForSite(site);
  logSiteEvent(state, site, {
    classId: 303,
    source: 'status',
    actor: 'collector',
    action: 'site_status_change',
    message: `${locationName} / ${site.name} status ${previousStatus.toUpperCase()} -> ${nextStatus.toUpperCase()}`,
    detail: `${reason || 'status_recompute'}${detail ? ` | ${detail}` : ''}`
  });

  if (!isAlertingSilenced(state) && (nextStatus === 'down' || nextStatus === 'warn' || previousStatus === 'down' || previousStatus === 'warn')) {
    state.alerts.unshift({
      id: `status-alert-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`,
      severity: nextStatus === 'down' ? 'critical' : 'warning',
      title: `${locationName} / ${site.name} ${previousStatus.toUpperCase()} -> ${nextStatus.toUpperCase()}`,
      deviceId: state.devices.find((d) => d.siteId === site.id && d.type === 'Firewall')?.id || null,
      createdAt: new Date().toISOString()
    });
    if (state.alerts.length > 100) state.alerts.length = 100;
  } else if (isAlertingSilenced(state)) {
    logSiteEventThrottled(state, site, `alerts:silenced:${site.id}`, 60 * 1000, {
      classId: 301,
      source: 'notifications',
      actor: 'collector',
      action: 'status_alert_silenced',
      message: `Alert creation suppressed for ${site.name}`,
      detail: `${previousStatus.toUpperCase()} -> ${nextStatus.toUpperCase()}`
    });
  }

  dispatchStatusNotification(state, site, previousStatus, nextStatus, reason, detail);
}

async function dispatchTestNotification(site) {
  const notificationsEnabled = Boolean(site?.notifications?.enabled);
  if (!notificationsEnabled) {
    return { sent: false, simulated: true, detail: 'Notifications are disabled for this site' };
  }
  const routeId = webhookRouteForSiteTest(site);
  if (!isWebhookRouteEnabled(routeId, shared.runtimeSettings)) {
    return {
      sent: false,
      simulated: true,
      detail: `Webhook route ${routeId} is disabled in Settings.`
    };
  }

  const routeMeta = WEBHOOK_ROUTE_MAP.get(routeId);
  const subject = `[CAJAL TEST] ${site.name} ${routeMeta?.label || 'Test Notify'}`;
  const body = [
    'This is a test Teams notification generated by Cajal.',
    `Site: ${site.name}`,
    `Role: ${normalizeRole(site?.role)}`,
    `Firewall: ${site.firewall?.name || 'Unknown firewall'}`,
    `WAN IP: ${site.firewall?.wanIp || 'N/A'}`,
    `Timestamp: ${new Date().toISOString()}`,
    '',
    'No real outage occurred. This was a test notify action.'
  ].join('\n');
  const payloadGroup = webhookPayloadGroupForRuntime(shared.runtimeSettings);
  const configuredRouteMessage = webhookRouteMessageForRuntime(routeId, shared.runtimeSettings);
  const { buildWebhookTemplateContextForStatus } = require('./monitoring');
  const messageContext = buildWebhookTemplateContextForStatus({
    site,
    previousStatus: 'up',
    nextStatus: routeMeta?.signal === 'offline' ? 'down' : (routeMeta?.signal === 'restore' ? 'up' : 'warn'),
    locationName: locationNameForSite(site),
    reason: routeId,
    detail: 'No real outage occurred. This was a test notify action.',
    timestamp: new Date().toISOString(),
    routeId,
    routeLabel: routeMeta?.label || '',
    section: routeMeta?.section || '',
    signal: routeMeta?.signal || ''
  });
  const payloadMessage = renderWebhookMessageTemplate(configuredRouteMessage, messageContext) || body;

  try {
    await sendTeamsNotification({ title: subject, group: payloadGroup || routeId, summary: subject, text: payloadMessage, message: payloadMessage, themeColor: '0076D7' });
    return { sent: true, simulated: false, detail: 'Teams notification posted.' };
  } catch (err) {
    return {
      sent: false,
      simulated: false,
      detail: `Teams notification failed: ${err.message}`
    };
  }
}

module.exports = {
  normalizeRole,
  webhookRoutingForRuntime,
  webhookSectionModesForRuntime,
  webhookRoutingMessagesForRuntime,
  webhookPayloadGroupForRuntime,
  isWebhookRouteEnabled,
  webhookRouteMessageForRuntime,
  renderWebhookMessageTemplate,
  webhookRoutePrefixForSite,
  webhookRouteForStatusTransition,
  webhookRouteForSiteTest,
  webhookRouteSignalThemeColor,
  webhookRouteCatalogForClient,
  webhookSectionCatalogForClient,
  teamsWebhookRetryableStatus,
  teamsWebhookRetryDelayMs,
  teamsWebhookRetryableError,
  sleepMs,
  postTeamsWebhookWithRetry,
  sendTeamsNotification,
  getAlertSilenceState,
  isAlertingSilenced,
  dispatchWebhookRouteNotification,
  notifyCollectorAgentState,
  notifyCollectorWanFailover,
  updateSystemDependencyNotificationState,
  dispatchStatusNotification,
  reconcileSiteStatus,
  dispatchTestNotification,
};
