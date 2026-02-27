'use strict';
const shared = require('./shared');
const {
  SYSLOG_UDP_PORT,
  SYSLOG_TCP_PORT,
  NETFLOW_PORT,
  PASSWORD_HASH_ITERATIONS,
  SITES_FILE,
  USERS_FILE,
  EVENTS_FILE,
  SENSITIVE_FIELDS,
  MASK,
  SITE_MONITOR_CONFIG_DECRYPT_FAILED,
  SITE_MONITOR_CONFIG_ENCRYPTED_FALLBACK,
} = require('./constants');
const { encryptJson, decryptJson } = require('./crypto');
const { smartReadFile, smartWriteFile } = require('./storage');
const {
  normalizeUserEntry,
  normalizeCollectorAgentAuth,
  normalizeCollectorAgentInstallIdentity,
} = require('./auth');
const { persistEvents } = require('./events');
const { normalizeRole } = require('./notifications');
const { AsyncMutex } = require('./mutex');
const _persistMutex = new AsyncMutex();

// ── Site ID helpers ───────────────────────────────────────────────────────────
function makeSiteId(name = 'location') {
  const base = String(name)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 24) || 'location';
  return `site-${base}-${Date.now().toString(36)}`;
}

function makeSectionId(name = 'location') {
  const base = String(name)
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 24) || 'location';
  return `loc-${base}`;
}

// ── Site template ─────────────────────────────────────────────────────────────
function createSiteTemplate(name, category) {
  const nowIso = new Date().toISOString();
  const locationSettings = shared.locationSettings;
  const safeCategory = String(category || locationSettings?.sections?.[0]?.id || 'internal').trim().toLowerCase() || 'internal';
  return {
    id: makeSiteId(name),
    name,
    model: '',
    timezone: 'America/Chicago',
    category: safeCategory,
    internalIp: '',
    dhcpScope: '',
    heartbeatTarget: 'wan1',
    heartbeatTarget2: 'wan2',
    isp1: '',
    isp2: '',
    role: 'firewall',
    collector: {
      ip: 'collector.local',
      localIp: '',
      terminalHost: 'collector.local',
      agentConnected: false,
      agentInstallLock: {
        installId: '',
        installedAt: '',
        installedAtMs: 0,
        lockedAt: ''
      },
      agentAuth: {
        passwordHash: '',
        passwordSalt: '',
        passwordIterations: PASSWORD_HASH_ITERATIONS,
        passwordChangedAt: ''
      }
    },
    firewall: { name: `${name} Firewall`, status: 'down', wanIp: '', wanIp2: '' },
    telemetry: { syslog: false, snmp: false, netflow: false },
    notifications: {
      enabled: false,
      recipients: [],
      lastChanged: nowIso,
      lastChangedBy: 'system'
    },
    monitorConfig: {
      syslog: {
        enabled: false,
        sourceIp: '',
        server: 'collector.local',
        port: String(SYSLOG_UDP_PORT),
        protocol: 'udp',
        authToken: '',
        lastChanged: nowIso,
        lastChangedBy: 'system'
      },
      snmp: {
        enabled: false,
        targetHost: '',
        version: '2c',
        communityString: '',
        authUser: '',
        authPassword: '',
        lastChanged: nowIso,
        lastChangedBy: 'system'
      },
      netflow: {
        enabled: false,
        sourceIp: '',
        collectorIp: 'collector.local',
        collectorPort: String(NETFLOW_PORT),
        exporterId: '',
        sharedSecret: '',
        lastChanged: nowIso,
        lastChangedBy: 'system'
      }
    },
    metrics: {
      uptime14d: [],
      uptime14dSecondary: [],
      heartbeat: { lastError: '', lastErrorAt: '' },
      snmp: { uptime: 'Unknown', lastPoll: 'Never', successCount: 0, failureCount: 0, lastSuccessAt: '', lastErrorAt: '', lastError: '', responseMs: 0 },
      syslog: { eventsPerSecond: 0, totalIngested: 0, lastIngestAt: '', lastError: '', lastErrorAt: '' },
      netflow: { topTalkers: [], lastError: '', lastErrorAt: '' },
      wanTests: []
    }
  };
}

// ── Site seed builder ─────────────────────────────────────────────────────────
function siteFromSeed(seed = []) {
  const [
    id, name, description, category,
    firewallName, firewallStatus, wanIp,
    notificationsEnabled, notificationRecipients, notificationsLastChanged,
    syslogSeed, snmpSeed, netflowSeed,
    uptime14d, snmpUptime, wanRecent, wanPrior
  ] = seed;
  const [syslogEnabled = false, syslogProtocol = 'udp', syslogAuthToken = '', syslogLastChanged = ''] = Array.isArray(syslogSeed) ? syslogSeed : [];
  const [snmpEnabled = false, snmpTargetHost = '', snmpCommunity = '', snmpLastChanged = ''] = Array.isArray(snmpSeed) ? snmpSeed : [];
  const [netflowEnabled = false, netflowExporterId = '', netflowSharedSecret = '', netflowLastChanged = ''] = Array.isArray(netflowSeed) ? netflowSeed : [];
  const [wanRecentTs = '10 min ago', wanRecentDown = 0, wanRecentUp = 0, wanRecentLatency = 0] = Array.isArray(wanRecent) ? wanRecent : [];
  const [wanPriorTs = '40 min ago', wanPriorDown = 0, wanPriorUp = 0, wanPriorLatency = 0] = Array.isArray(wanPrior) ? wanPrior : [];
  const normalizedProto = String(syslogProtocol || '').toLowerCase() === 'tcp' ? 'tcp' : 'udp';
  return {
    id: String(id || ''),
    name: String(name || ''),
    description: String(description || ''),
    timezone: 'America/Chicago',
    category: String(category || 'internal'),
    firewall: {
      name: String(firewallName || ''),
      status: String(firewallStatus || 'down'),
      wanIp: String(wanIp || '')
    },
    telemetry: { syslog: false, snmp: false, netflow: false },
    notifications: {
      enabled: Boolean(notificationsEnabled),
      recipients: Array.isArray(notificationRecipients) ? notificationRecipients.map((value) => String(value || '')) : [],
      lastChanged: String(notificationsLastChanged || '')
    },
    monitorConfig: {
      syslog: {
        enabled: Boolean(syslogEnabled),
        sourceIp: '',
        server: 'collector.local',
        port: String(normalizedProto === 'tcp' ? SYSLOG_TCP_PORT : SYSLOG_UDP_PORT),
        protocol: normalizedProto,
        authToken: String(syslogAuthToken || ''),
        lastChanged: String(syslogLastChanged || '')
      },
      snmp: {
        enabled: Boolean(snmpEnabled),
        targetHost: String(snmpTargetHost || ''),
        version: '2c',
        communityString: String(snmpCommunity || ''),
        authUser: '',
        authPassword: '',
        lastChanged: String(snmpLastChanged || '')
      },
      netflow: {
        enabled: Boolean(netflowEnabled),
        sourceIp: '',
        collectorIp: 'collector.local',
        collectorPort: String(NETFLOW_PORT),
        exporterId: String(netflowExporterId || ''),
        sharedSecret: String(netflowSharedSecret || ''),
        lastChanged: String(netflowLastChanged || '')
      }
    },
    metrics: {
      uptime14d: Array.isArray(uptime14d) ? uptime14d : [],
      snmp: { uptime: String(snmpUptime || 'Unknown'), lastPoll: 'Never' },
      syslog: { eventsPerSecond: 0 },
      netflow: { topTalkers: [] },
      wanTests: [
        { timestamp: wanRecentTs, downloadMbps: wanRecentDown, uploadMbps: wanRecentUp, latencyMs: wanRecentLatency },
        { timestamp: wanPriorTs, downloadMbps: wanPriorDown, uploadMbps: wanPriorUp, latencyMs: wanPriorLatency }
      ]
    }
  };
}

// ── Import normalization ───────────────────────────────────────────────────────
function normalizeImportedSite(rawSite, index, validSectionIds = new Set(['internal', 'customer'])) {
  const fallbackName = `Imported Device ${index + 1}`;
  const name = String(rawSite?.name || fallbackName).trim() || fallbackName;
  const incomingCategory = String(rawSite?.category || '').trim().toLowerCase();
  const category = validSectionIds.has(incomingCategory) ? incomingCategory : (validSectionIds.values().next().value || 'internal');
  const base = createSiteTemplate(name, category);
  const merged = {
    ...base,
    ...(rawSite || {}),
    id: String(rawSite?.id || base.id).trim() || base.id,
    name,
    category,
    model: String(rawSite?.model || base.model || '').trim(),
    internalIp: String(rawSite?.internalIp || base.internalIp || '').trim(),
    dhcpScope: String(rawSite?.dhcpScope || base.dhcpScope || '').trim(),
    isp1: String(rawSite?.isp1 || base.isp1 || '').trim(),
    isp2: String(rawSite?.isp2 || base.isp2 || '').trim(),
    heartbeatTarget: normalizeHeartbeatTarget(rawSite?.heartbeatTarget || base.heartbeatTarget),
    heartbeatTarget2: normalizeHeartbeatTarget(rawSite?.heartbeatTarget2 || base.heartbeatTarget2),
    role: normalizeRole(rawSite?.role || base.role)
  };
  merged.firewall = { ...base.firewall, ...(rawSite?.firewall || {}) };
  merged.collector = { ...base.collector, ...(rawSite?.collector || {}) };
  merged.collector.agentAuth = normalizeCollectorAgentAuth(merged.collector.agentAuth, base.collector.agentAuth);
  merged.collector.agentInstallLock = normalizeCollectorAgentInstallIdentity(
    merged.collector.agentInstallLock,
    base.collector.agentInstallLock
  );
  merged.collector.agentConnected = false;
  merged.collector.terminalHost = String(merged.collector.terminalHost || merged.collector.ip || '').trim();
  merged.collector.localIp = String(merged.collector.localIp || '').trim();
  delete merged.collector.os;
  merged.telemetry = { ...base.telemetry, ...(rawSite?.telemetry || {}) };
  merged.notifications = { ...base.notifications, ...(rawSite?.notifications || {}) };
  if (!Array.isArray(merged.notifications.recipients)) merged.notifications.recipients = [];
  merged.monitorConfig = {
    syslog: { ...base.monitorConfig.syslog, ...(rawSite?.monitorConfig?.syslog || {}) },
    snmp: { ...base.monitorConfig.snmp, ...(rawSite?.monitorConfig?.snmp || {}) },
    netflow: { ...base.monitorConfig.netflow, ...(rawSite?.monitorConfig?.netflow || {}) }
  };
  merged.metrics = {
    ...base.metrics,
    ...(rawSite?.metrics || {}),
    snmp: { ...base.metrics.snmp, ...(rawSite?.metrics?.snmp || {}) },
    syslog: { ...base.metrics.syslog, ...(rawSite?.metrics?.syslog || {}) },
    netflow: { ...base.metrics.netflow, ...(rawSite?.metrics?.netflow || {}) },
    wanTests: Array.isArray(rawSite?.metrics?.wanTests) ? rawSite.metrics.wanTests : base.metrics.wanTests,
    uptime14d: Array.isArray(rawSite?.metrics?.uptime14d) ? rawSite.metrics.uptime14d : base.metrics.uptime14d,
    uptime14dSecondary: Array.isArray(rawSite?.metrics?.uptime14dSecondary) ? rawSite.metrics.uptime14dSecondary : base.metrics.uptime14dSecondary
  };
  return merged;
}

// ── Utility ───────────────────────────────────────────────────────────────────
function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

// ── Sites persistence ─────────────────────────────────────────────────────────
async function loadSites() {
  const raw = await smartReadFile(SITES_FILE, 'utf8');
  const rows = JSON.parse(raw);
  return rows.map((site) => {
    const hydrated = { ...site };
    if (site.monitorConfigEncrypted) {
      try {
        hydrated.monitorConfig = decryptJson(site.monitorConfigEncrypted);
      } catch {
        hydrated.monitorConfig = {};
        hydrated[SITE_MONITOR_CONFIG_DECRYPT_FAILED] = true;
        hydrated[SITE_MONITOR_CONFIG_ENCRYPTED_FALLBACK] = clone(site.monitorConfigEncrypted);
        console.warn(`Monitor config decrypt failed for site ${site.id || 'unknown'}; using defaults.`);
      }
      delete hydrated.monitorConfigEncrypted;
    }
    if (!hydrated.internalIp) hydrated.internalIp = '';
    if (!hydrated.dhcpScope) hydrated.dhcpScope = '';
    if (!hydrated.model) hydrated.model = '';
    if (!hydrated.isp1) hydrated.isp1 = '';
    if (!hydrated.isp2) hydrated.isp2 = '';
    hydrated.firewall = hydrated.firewall || {};
    if (!hydrated.firewall.wanIp2) hydrated.firewall.wanIp2 = '';
    if (!hydrated.monitorConfig) hydrated.monitorConfig = {};
    hydrated.collector = hydrated.collector || {};
    if (!hydrated.collector.ip) hydrated.collector.ip = hydrated.monitorConfig?.netflow?.collectorIp || 'collector.local';
    if (!hydrated.collector.localIp) hydrated.collector.localIp = '';
    delete hydrated.collector.os;
    if (!hydrated.collector.terminalHost) hydrated.collector.terminalHost = hydrated.collector.ip || '';
    hydrated.collector.terminalHost = String(hydrated.collector.terminalHost || '').trim();
    hydrated.collector.localIp = String(hydrated.collector.localIp || '').trim();
    hydrated.collector.agentInstallLock = normalizeCollectorAgentInstallIdentity(
      hydrated.collector.agentInstallLock,
      {}
    );
    hydrated.collector.agentAuth = normalizeCollectorAgentAuth(hydrated.collector.agentAuth, {});
    hydrated.collector.agentConnected = false;
    if (!hydrated.telemetry) hydrated.telemetry = { syslog: false, snmp: false, netflow: false };
    if (!hydrated.notifications) hydrated.notifications = { enabled: false, recipients: [], lastChanged: null };
    if (!Array.isArray(hydrated.notifications.recipients)) hydrated.notifications.recipients = [];
    if (!hydrated.metrics) hydrated.metrics = {};
    if (!hydrated.role) hydrated.role = 'firewall';
    hydrated.heartbeatTarget = normalizeHeartbeatTarget(hydrated.heartbeatTarget);
    hydrated.heartbeatTarget2 = normalizeHeartbeatTarget(hydrated.heartbeatTarget2 || 'wan2');
    return hydrated;
  });
}

function toDiskSite(site) {
  if (site?.[SITE_MONITOR_CONFIG_DECRYPT_FAILED] && site?.[SITE_MONITOR_CONFIG_ENCRYPTED_FALLBACK]) {
    const copy = clone(site);
    if (copy.collector && typeof copy.collector === 'object') delete copy.collector.os;
    copy.monitorConfigEncrypted = clone(site[SITE_MONITOR_CONFIG_ENCRYPTED_FALLBACK]);
    delete copy.monitorConfig;
    return copy;
  }
  const copy = clone(site);
  if (copy.collector && typeof copy.collector === 'object') delete copy.collector.os;
  copy.monitorConfigEncrypted = encryptJson(copy.monitorConfig || {});
  delete copy.monitorConfig;
  return copy;
}

async function persistSites(sites) {
  return _persistMutex.run(async () => {
    const toStore = sites.map(toDiskSite);
    await smartWriteFile(SITES_FILE, JSON.stringify(toStore), 'utf8');
  });
}

// ── Users persistence ─────────────────────────────────────────────────────────
async function loadUsers() {
  const raw = await smartReadFile(USERS_FILE, 'utf8');
  const rows = JSON.parse(raw);
  return (Array.isArray(rows) ? rows : []).map((u) => normalizeUserEntry(u, u)).filter((u) => u.email);
}

async function persistUsers(users) {
  return _persistMutex.run(async () => {
    const normalized = users.map((u) => normalizeUserEntry(u, u)).filter((u) => u.email);
    await smartWriteFile(USERS_FILE, JSON.stringify(normalized), 'utf8');
  });
}

// ── Events load ───────────────────────────────────────────────────────────────
async function loadEvents() {
  const raw = await smartReadFile(EVENTS_FILE, 'utf8');
  const rows = JSON.parse(raw || '[]');
  return Array.isArray(rows) ? rows : [];
}

// ── Site client helpers ───────────────────────────────────────────────────────
function sanitizeSiteForClient(site) {
  const copy = clone(site);
  copy.monitorConfig = copy.monitorConfig || {};

  for (const protocol of ['syslog', 'snmp', 'netflow']) {
    const cfg = copy.monitorConfig[protocol] || {};
    for (const [key, value] of Object.entries(cfg)) {
      if (SENSITIVE_FIELDS.has(key) && value) {
        cfg[key] = MASK;
      }
    }
    copy.monitorConfig[protocol] = cfg;
  }

  copy.collector = copy.collector || {};
  const collectorAuth = normalizeCollectorAgentAuth(copy.collector.agentAuth, {});
  copy.collector.agentPasswordSet = Boolean(collectorAuth.passwordHash && collectorAuth.passwordSalt);
  delete copy.collector.agentAuth;
  delete copy.collector.agentInstallLock;
  delete copy.collector.os;

  return copy;
}

function normalizeHeartbeatTarget(value) {
  const v = String(value || '').trim().toLowerCase();
  return ['wan1', 'wan2', 'gateway', 'internal'].includes(v) ? v : 'wan1';
}

function isLinkMarkedNone(value) {
  const v = String(value || '').trim().toLowerCase();
  return !v || v === 'none';
}

function resolveSiteGatewayIp(state, site) {
  const fallback = String(site?.internalIp || '').trim();
  if (!site || normalizeRole(site?.role) !== 'collector') return fallback;
  const category = String(site?.category || '').trim().toLowerCase();
  const rows = Array.isArray(state?.sites) ? state.sites : [];
  const byCategory = rows.find((row) => (
    row
    && String(row.id || '') !== String(site.id || '')
    && normalizeRole(row.role) === 'firewall'
    && String(row.category || '').trim().toLowerCase() === category
    && String(row.internalIp || '').trim()
  ));
  if (byCategory) return String(byCategory.internalIp || '').trim();
  const anyFirewall = rows.find((row) => (
    row
    && String(row.id || '') !== String(site.id || '')
    && normalizeRole(row.role) === 'firewall'
    && String(row.internalIp || '').trim()
  ));
  if (anyFirewall) return String(anyFirewall.internalIp || '').trim();
  return fallback;
}

// ── Summary helper ────────────────────────────────────────────────────────────
function summarize(devices, alerts) {
  const summary = {
    totalDevices: devices.length,
    up: 0,
    warn: 0,
    down: 0,
    criticalAlerts: alerts.filter((a) => a.severity === 'critical').length
  };

  for (const d of devices) {
    if (d.status === 'up') summary.up += 1;
    if (d.status === 'warn') summary.warn += 1;
    if (d.status === 'down') summary.down += 1;
  }

  return summary;
}

// ── SNMP uptime formatter ─────────────────────────────────────────────────────
function formatSysUpTimeTicks(ticks) {
  const totalSeconds = Math.floor(ticks / 100);
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  return `${days}d ${String(hours).padStart(2, '0')}h ${String(minutes).padStart(2, '0')}m`;
}

// ── Config merge helper ───────────────────────────────────────────────────────
function mergeConfig(existing, incoming) {
  const next = { ...existing };
  for (const [key, value] of Object.entries(incoming || {})) {
    if (SENSITIVE_FIELDS.has(key)) {
      if (!value || value === MASK) continue;
      next[key] = value;
      continue;
    }
    next[key] = value;
  }
  return next;
}

// ── Change actor backfill ─────────────────────────────────────────────────────
function backfillSiteChangeActorsFromEvents(sites = [], events = []) {
  const rows = Array.isArray(sites) ? sites : [];
  const eventRows = Array.isArray(events) ? events : [];
  let changed = false;
  const siteByDevice = new Map();
  const fallbackActorTokens = new Set(['', 'system', 'unknown', 'anonymous', 'authenticated-user']);
  for (const site of rows) {
    const nameKey = String(site?.name || '').trim().toLowerCase();
    const idKey = String(site?.id || '').trim().toLowerCase();
    if (nameKey) siteByDevice.set(nameKey, site);
    if (idKey) siteByDevice.set(idKey, site);
  }

  const findActorFromEvents = (site, classId, source, targetMs = NaN) => {
    const siteName = String(site?.name || '').trim().toLowerCase();
    const siteId = String(site?.id || '').trim().toLowerCase();
    let best = '';
    let bestDelta = Number.POSITIVE_INFINITY;
    for (const evt of eventRows) {
      if (Number(evt?.classId || 0) !== classId) continue;
      if (String(evt?.source || '').trim().toLowerCase() !== source) continue;
      const deviceKey = String(evt?.device || '').trim().toLowerCase();
      if (deviceKey && deviceKey !== siteName && deviceKey !== siteId) continue;
      const actor = String(evt?.actor || '').trim();
      if (!actor || fallbackActorTokens.has(actor.toLowerCase())) continue;
      if (!Number.isFinite(targetMs)) return actor;
      const evtMs = Date.parse(String(evt?.ts || ''));
      if (!Number.isFinite(evtMs)) return actor;
      const delta = Math.abs(evtMs - targetMs);
      if (delta < bestDelta) {
        best = actor;
        bestDelta = delta;
      }
    }
    if (best && bestDelta <= 24 * 60 * 60 * 1000) return best;
    return best || '';
  };

  for (const site of rows) {
    site.notifications = site.notifications || { enabled: false, recipients: [], lastChanged: null };
    const notificationsChangedAtMs = Date.parse(String(site.notifications.lastChanged || ''));
    const notifCurrentActor = String(site.notifications.lastChangedBy || '').trim();
    const notifNeedsUpdate = fallbackActorTokens.has(notifCurrentActor.toLowerCase());
    const notifActorFromEvents = findActorFromEvents(site, 204, 'notifications', notificationsChangedAtMs);
    if (notifNeedsUpdate && notifActorFromEvents) {
      site.notifications.lastChangedBy = notifActorFromEvents;
      changed = true;
    } else if (!notifCurrentActor) {
      site.notifications.lastChangedBy = 'system';
      changed = true;
    }

    site.monitorConfig = site.monitorConfig || {};
    for (const protocol of ['syslog', 'snmp', 'netflow']) {
      site.monitorConfig[protocol] = site.monitorConfig[protocol] || {};
      const cfg = site.monitorConfig[protocol];
      const currentActor = String(cfg.lastChangedBy || '').trim();
      const needsUpdate = fallbackActorTokens.has(currentActor.toLowerCase());
      const changedAtMs = Date.parse(String(cfg.lastChanged || ''));
      const actorFromEvents = findActorFromEvents(site, 203, protocol, changedAtMs);
      if (needsUpdate && actorFromEvents) {
        cfg.lastChangedBy = actorFromEvents;
        changed = true;
      } else if (!currentActor) {
        site.monitorConfig[protocol].lastChangedBy = 'system';
        changed = true;
      }
    }
  }

  return changed;
}

// ── Site dirty state ──────────────────────────────────────────────────────────
function markSiteDirty(state) {
  state.dirtySites = true;
}

function siteHasMonitorConfigDecryptFailure(site) {
  return Boolean(site?.[SITE_MONITOR_CONFIG_DECRYPT_FAILED]);
}

function clearMonitorConfigDecryptFailure(site) {
  if (!site) return;
  site[SITE_MONITOR_CONFIG_DECRYPT_FAILED] = false;
  delete site[SITE_MONITOR_CONFIG_ENCRYPTED_FALLBACK];
}

// ── Flush dirty state ─────────────────────────────────────────────────────────
async function flushDirtyState(state, options = {}) {
  const forceSites = Boolean(options.forceSites);
  const forceEvents = Boolean(options.forceEvents);
  const forceApiTokens = Boolean(options.forceApiTokens);
  if (forceSites || state.dirtySites) {
    await persistSites(state.sites);
    state.dirtySites = false;
  }
  if (forceEvents || state.dirtyEvents) {
    await persistEvents(state.events);
    state.dirtyEvents = false;
  }
  if (forceApiTokens || state.apiTokensDirty) {
    // Lazy require to avoid circular dependency with lib/settings.js
    const { persistApiTokenSettings } = require('./settings');
    await persistApiTokenSettings({ tokens: state.apiTokens });
    state.apiTokensDirty = false;
  }
}

function decorateSiteForClient(site, state) {
  const { deriveUptime14d, currentHeartbeatFreshWindowMs } = require('./monitoring');
  const { getCollectorAgentPresence } = require('./agent');
  const { collectorAgentPasswordConfigured } = require('./auth');
  const { LINUX_AGENT_DEB_VERSION } = require('./constants');
  const clean = sanitizeSiteForClient(site);
  deriveUptime14d(clean, Date.now());
  deriveUptime14d(clean, Date.now(), 'uptimeSamplesSecondary', 'uptime14dSecondary', 'uptime14dSecondary');
  clean.collector = clean.collector || {};
  const presence = getCollectorAgentPresence(state, clean.id);
  const nextAgentVersion = String(LINUX_AGENT_DEB_VERSION || '').trim();
  const currentAgentVersion = String(presence?.version || '').trim();
  clean.collector.agentConnected = Boolean(presence?.connected);
  clean.collector.agentLastSeenAt = presence?.lastSeenAt ? new Date(presence.lastSeenAt).toISOString() : '';
  clean.collector.agentRemoteIp = String(presence?.remoteIp || '').trim();
  clean.collector.localIp = String(presence?.localIp || clean.collector.localIp || '').trim();
  clean.collector.agentPlatform = String(presence?.platform || '').trim();
  clean.collector.agentVersion = currentAgentVersion;
  clean.collector.nextAgentVersion = nextAgentVersion;
  clean.collector.updateAvailable = Boolean(currentAgentVersion && nextAgentVersion && currentAgentVersion !== nextAgentVersion);
  if (presence?.hostname) clean.collector.terminalHost = presence.hostname;
  clean.collector.agentPasswordSet = collectorAgentPasswordConfigured(site);
  clean.gatewayIp = resolveSiteGatewayIp(state, site);
  clean.heartbeatTarget = normalizeHeartbeatTarget(clean.heartbeatTarget);
  clean.heartbeatTarget2 = normalizeHeartbeatTarget(clean.heartbeatTarget2 || 'wan2');
  const wan1Disabled = isLinkMarkedNone(clean.firewall?.wanIp) || isLinkMarkedNone(clean.isp1);
  const wan2Disabled = isLinkMarkedNone(clean.firewall?.wanIp2) || isLinkMarkedNone(clean.isp2);
  const gatewayDisabled = isLinkMarkedNone(clean.gatewayIp);
  const wan1State = state.wanPingState.get(`${site.id}:wan1`);
  const wan2State = state.wanPingState.get(`${site.id}:wan2`);
  const gatewayState = state.wanPingState.get(`${site.id}:gateway`);
  clean.wanPing = {
    wan1: wan1Disabled ? 'off' : wan1State === true ? 'up' : wan1State === false ? 'down' : 'unknown',
    wan2: wan2Disabled ? 'off' : wan2State === true ? 'up' : wan2State === false ? 'down' : 'unknown',
    gateway: gatewayDisabled ? 'off' : gatewayState === true ? 'up' : gatewayState === false ? 'down' : 'unknown',
    // Keep legacy target value compatibility for saved "internal" heartbeat target selections.
    internal: gatewayDisabled ? 'off' : gatewayState === true ? 'up' : gatewayState === false ? 'down' : 'unknown'
  };
  const now = Date.now();
  const freshnessWindowMs = currentHeartbeatFreshWindowMs();
  const pingTs = state.lastSeen.ping.get(site.id) || 0;
  const pingTs2 = state.lastSeen.pingSecondary?.get(site.id) || 0;
  if (!pingTs && !pingTs2) {
    clean.heartbeat = { method: 'none', lastSeenAt: null, lastSeenAt2: null, ageSec: null, staleInSec: null };
    return clean;
  }

  const ageSec = pingTs ? Math.max(0, Math.floor((now - pingTs) / 1000)) : null;
  const staleInSec = pingTs ? Math.max(0, Math.floor((freshnessWindowMs - (now - pingTs)) / 1000)) : null;
  clean.heartbeat = {
    method: 'ping',
    lastSeenAt: pingTs ? new Date(pingTs).toISOString() : null,
    lastSeenAt2: pingTs2 ? new Date(pingTs2).toISOString() : null,
    ageSec,
    staleInSec
  };
  return clean;
}

function applyFlowStatus(state) {
  const { protocolFlowTimeoutMs, recentFlowCheck, deriveSiteStatus } = require('./monitoring');
  const { reconcileSiteStatus } = require('./notifications');
  const { logSiteEvent } = require('./events');
  const now = Date.now();
  for (const site of state.sites) {
    for (const protocol of ['syslog', 'snmp', 'netflow']) {
      const cfg = site.monitorConfig?.[protocol] || {};
      const enabled = Boolean(cfg.enabled);
      if (!enabled) {
        site.telemetry[protocol] = false;
        continue;
      }
      const last = state.lastSeen[protocol].get(site.id) || 0;
      const timeoutMs = protocolFlowTimeoutMs(protocol);
      const isUp = now - last <= timeoutMs;
      site.telemetry[protocol] = isUp;
      const key = `${site.id}:${protocol}`;
      const prev = state.flowState.get(key);
      if (prev !== undefined && prev !== isUp) {
        logSiteEvent(state, site, {
          classId: 302,
          source: protocol,
          actor: 'collector',
          action: 'flow_state_change',
          message: `${site.name} ${protocol.toUpperCase()} ${isUp ? 'flowing' : 'stopped'}`
        });
        reconcileSiteStatus(
          state,
          site,
          `${protocol}_flow_state_change`,
          `${protocol} ${prev ? 'flowing' : 'stopped'} -> ${isUp ? 'flowing' : 'stopped'}`
        );
      }
      state.flowState.set(key, isUp);
    }
    reconcileSiteStatus(state, site, 'flow_status_refresh');
  }
}

module.exports = {
  makeSiteId,
  makeSectionId,
  createSiteTemplate,
  siteFromSeed,
  normalizeImportedSite,
  clone,
  loadSites,
  toDiskSite,
  persistSites,
  loadUsers,
  persistUsers,
  loadEvents,
  sanitizeSiteForClient,
  normalizeHeartbeatTarget,
  isLinkMarkedNone,
  resolveSiteGatewayIp,
  summarize,
  formatSysUpTimeTicks,
  mergeConfig,
  backfillSiteChangeActorsFromEvents,
  markSiteDirty,
  siteHasMonitorConfigDecryptFailure,
  clearMonitorConfigDecryptFailure,
  flushDirtyState,
  decorateSiteForClient,
  applyFlowStatus,

  __test: {
    normalizeHeartbeatTarget,
    resolveSiteGatewayIp,
    formatSysUpTimeTicks,
    backfillSiteChangeActorsFromEvents,
    mergeConfig,
  },
};
