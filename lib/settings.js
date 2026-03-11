'use strict';
const crypto = require('crypto');
const shared = require('./shared');
const {
  PORT,
  MASK,
  LOCATION_PING_MONITOR_MAX,
  ENTRA_TENANT_ID,
  ENTRA_CLIENT_ID,
  ENTRA_CLIENT_SECRET,
  ENTRA_REDIRECT_URI,
  ENTRA_SCOPE,
  SSO_FILE,
  SSL_FILE,
  RUNTIME_FILE,
  API_TOKENS_FILE,
  LOCATION_SETTINGS_FILE,
  BACKUP_META_FILE,
  LDAP_FILE,
  defaultRuntimeSettings,
  defaultSslSettings,
  defaultLocationSettings,
  defaultBackupMeta,
  defaultApiTokenSettings,
  normalizeTeamsWebhookUrl,
  normalizeTeamsWebhookTimeoutMs,
  normalizeWebhookRoutingRules,
  normalizeWebhookSectionModes,
  normalizeWebhookRoutingMessages,
} = require('./constants');
const { encryptJson, decryptJson } = require('./crypto');
const { smartReadFile, smartWriteFile, setConfigIntegrityState } = require('./storage');
const { sanitizeMailHeaderValue } = require('./smtp');
const { sanitizeApiTokenSettings } = require('./tokens');
const { makeSectionId } = require('./sites');

// ── Default SSO config ────────────────────────────────────────────────────────
const defaultSsoConfig = {
  tenantId: ENTRA_TENANT_ID,
  clientId: ENTRA_CLIENT_ID,
  clientSecret: ENTRA_CLIENT_SECRET,
  redirectUri: ENTRA_REDIRECT_URI,
  scope: ENTRA_SCOPE
};

// ── SSO config ────────────────────────────────────────────────────────────────
async function loadSsoConfig() {
  try {
    const raw = await smartReadFile(SSO_FILE, 'utf8');
    const parsed = JSON.parse(raw || '{}');
    const config = parsed?.encrypted && parsed?.blob ? decryptJson(parsed.blob) : parsed;
    const normalized = {
      tenantId: String(config.tenantId || ''),
      clientId: String(config.clientId || ''),
      clientSecret: String(config.clientSecret || ''),
      redirectUri: String(config.redirectUri || `http://localhost:${PORT}/api/auth/callback`),
      scope: String(config.scope || 'openid profile email')
    };
    setConfigIntegrityState('sso', 'ok', 'Loaded successfully');
    return normalized;
  } catch (err) {
    const detail = String(err?.message || err || 'SSO config decrypt/load failed').trim() || 'SSO config decrypt/load failed';
    console.warn(`SSO config decrypt failed; using defaults. (${detail})`);
    setConfigIntegrityState('sso', 'fail', detail);
    return { ...defaultSsoConfig };
  }
}

async function persistSsoConfig(config) {
  const payload = {
    encrypted: true,
    blob: encryptJson(config)
  };
  await smartWriteFile(SSO_FILE, JSON.stringify(payload, null, 2), 'utf8');
  setConfigIntegrityState('sso', 'ok', 'Saved successfully');
}

// ── Runtime settings ──────────────────────────────────────────────────────────
function sanitizeRuntimeSettings(config = {}) {
  const readNumber = (value, fallback, min = 1, max = 2147483647) => {
    const n = Number(value);
    if (!Number.isFinite(n)) return fallback;
    const v = Math.floor(n);
    return Math.max(min, Math.min(max, v));
  };
  const readBoolean = (value, fallback = false) => {
    if (typeof value === 'boolean') return value;
    if (value == null) return Boolean(fallback);
    const normalized = String(value).trim().toLowerCase();
    if (['1', 'true', 'yes', 'on', 'enabled'].includes(normalized)) return true;
    if (['0', 'false', 'no', 'off', 'disabled'].includes(normalized)) return false;
    return Boolean(fallback);
  };
  const sanitizeTimeZone = (value, fallback) => {
    const tz = String(value || '').trim();
    if (!tz) return fallback;
    try {
      new Intl.DateTimeFormat('en-US', { timeZone: tz }).format(new Date());
      return tz;
    } catch {
      return fallback;
    }
  };
  const sanitizeHourMode = (value, fallback) => {
    const mode = String(value || '').trim().toLowerCase();
    if (mode === '12h' || mode === '24h') return mode;
    return fallback;
  };
  const sanitizeHostTarget = (value, fallback = '') => {
    const raw = String(value ?? '').trim();
    if (!raw) return '';
    if (raw.length > 255) return fallback;
    if (!/^[A-Za-z0-9._:-]+$/.test(raw)) return fallback;
    return raw;
  };
  const sanitizeTeamsWebhookUrl = (value, fallback = '') => {
    const normalized = normalizeTeamsWebhookUrl(value || '');
    if (normalized) return normalized;
    if (value === '' || value == null) return '';
    return normalizeTeamsWebhookUrl(fallback || '') || '';
  };
  const sanitizeGroup = (value, fallback = 'cajal') => {
    const raw = String(value ?? '').trim();
    const clean = sanitizeMailHeaderValue(raw || fallback || 'cajal').slice(0, 128);
    return clean || 'cajal';
  };
  return {
    syslogUdpPort: readNumber(config.syslogUdpPort, defaultRuntimeSettings.syslogUdpPort, 1, 65535),
    syslogTcpPort: readNumber(config.syslogTcpPort, defaultRuntimeSettings.syslogTcpPort, 1, 65535),
    netflowPort: readNumber(config.netflowPort, defaultRuntimeSettings.netflowPort, 1, 65535),
    snmpPollIntervalMs: readNumber(config.snmpPollIntervalMs, defaultRuntimeSettings.snmpPollIntervalMs, 1000),
    flowTimeoutMs: readNumber(config.flowTimeoutMs, defaultRuntimeSettings.flowTimeoutMs, 1000),
    pingIntervalMs: readNumber(config.pingIntervalMs, defaultRuntimeSettings.pingIntervalMs, 1000),
    globalDataRefreshMs: readNumber(config.globalDataRefreshMs, defaultRuntimeSettings.globalDataRefreshMs, 10000),
    globalClockTimeZone: sanitizeTimeZone(config.globalClockTimeZone, defaultRuntimeSettings.globalClockTimeZone),
    globalClockHourMode: sanitizeHourMode(config.globalClockHourMode, defaultRuntimeSettings.globalClockHourMode),
    localTotpEnabled: readBoolean(config.localTotpEnabled, defaultRuntimeSettings.localTotpEnabled),
    wanTestIntervalMs: readNumber(config.wanTestIntervalMs, defaultRuntimeSettings.wanTestIntervalMs, 1000),
    internalDnsTarget: sanitizeHostTarget(
      config.internalDnsTarget,
      defaultRuntimeSettings.internalDnsTarget
    ),
    teamsWebhookUrl: sanitizeTeamsWebhookUrl(config.teamsWebhookUrl, defaultRuntimeSettings.teamsWebhookUrl),
    teamsWebhookTimeoutMs: normalizeTeamsWebhookTimeoutMs(
      config.teamsWebhookTimeoutMs,
      defaultRuntimeSettings.teamsWebhookTimeoutMs
    ),
    teamsPayloadGroup: sanitizeGroup(config.teamsPayloadGroup, defaultRuntimeSettings.teamsPayloadGroup),
    webhookRouting: normalizeWebhookRoutingRules(config.webhookRouting, defaultRuntimeSettings.webhookRouting),
    webhookSectionModes: normalizeWebhookSectionModes(
      config.webhookSectionModes,
      defaultRuntimeSettings.webhookSectionModes
    ),
    webhookRoutingMessages: normalizeWebhookRoutingMessages(
      config.webhookRoutingMessages,
      defaultRuntimeSettings.webhookRoutingMessages
    ),
    setupWizardCompleted: readBoolean(config.setupWizardCompleted, false)
  };
}

async function loadRuntimeSettings() {
  try {
    const raw = await smartReadFile(RUNTIME_FILE, 'utf8');
    const parsed = JSON.parse(raw || '{}');
    const config = parsed?.encrypted && parsed?.blob ? decryptJson(parsed.blob) : parsed;
    const normalized = sanitizeRuntimeSettings({ ...defaultRuntimeSettings, ...(config || {}) });
    setConfigIntegrityState('runtime', 'ok', 'Loaded successfully');
    return normalized;
  } catch (err) {
    const detail = String(err?.message || err || 'Runtime settings decrypt/load failed').trim() || 'Runtime settings decrypt/load failed';
    console.warn(`Runtime settings decrypt failed; using defaults. (${detail})`);
    setConfigIntegrityState('runtime', 'fail', detail);
    return { ...defaultRuntimeSettings };
  }
}

async function persistRuntimeSettings(config) {
  const payload = {
    encrypted: true,
    blob: encryptJson(sanitizeRuntimeSettings(config))
  };
  await smartWriteFile(RUNTIME_FILE, JSON.stringify(payload, null, 2), 'utf8');
  setConfigIntegrityState('runtime', 'ok', 'Saved successfully');
}

// ── API token settings ────────────────────────────────────────────────────────
async function loadApiTokenSettings() {
  try {
    const raw = await smartReadFile(API_TOKENS_FILE, 'utf8');
    const parsed = JSON.parse(raw || '{}');
    const config = parsed?.encrypted && parsed?.blob ? decryptJson(parsed.blob) : parsed;
    const normalized = sanitizeApiTokenSettings(config || {});
    setConfigIntegrityState('apiTokens', 'ok', 'Loaded successfully');
    return normalized;
  } catch (err) {
    const detail = String(err?.message || err || 'API token settings decrypt/load failed').trim() || 'API token settings decrypt/load failed';
    console.warn(`API token settings decrypt failed; using defaults. (${detail})`);
    setConfigIntegrityState('apiTokens', 'fail', detail);
    return { ...defaultApiTokenSettings };
  }
}

async function persistApiTokenSettings(config = {}) {
  const payload = {
    encrypted: true,
    blob: encryptJson(sanitizeApiTokenSettings(config))
  };
  await smartWriteFile(API_TOKENS_FILE, JSON.stringify(payload, null, 2), 'utf8');
  setConfigIntegrityState('apiTokens', 'ok', 'Saved successfully');
}

// ── Windows agent exe detection ──────────────────────────────────────────────
function isWindowsExeBuffer(payload = null) {
  return Buffer.isBuffer(payload) && payload.length >= 2 && payload[0] === 0x4d && payload[1] === 0x5a;
}

// ── SSL settings ──────────────────────────────────────────────────────────────
function sanitizeSslSettings(config = {}) {
  return {
    certPem: String(config.certPem || '').trim(),
    keyPem: String(config.keyPem || '').trim(),
    caPem: String(config.caPem || '').trim()
  };
}

function sslConfigForClient() {
  const sslRuntimeConfig = shared.sslRuntimeConfig;
  return {
    certPem: sslRuntimeConfig.certPem ? MASK : '',
    keyPem: sslRuntimeConfig.keyPem ? MASK : '',
    caPem: sslRuntimeConfig.caPem ? MASK : '',
    hasCert: Boolean(sslRuntimeConfig.certPem),
    hasKey: Boolean(sslRuntimeConfig.keyPem),
    hasCa: Boolean(sslRuntimeConfig.caPem)
  };
}

async function loadSslSettings() {
  try {
    const raw = await smartReadFile(SSL_FILE, 'utf8');
    const parsed = JSON.parse(raw || '{}');
    const config = parsed?.encrypted && parsed?.blob ? decryptJson(parsed.blob) : parsed;
    const normalized = sanitizeSslSettings(config || {});
    setConfigIntegrityState('ssl', 'ok', 'Loaded successfully');
    return normalized;
  } catch (err) {
    const detail = String(err?.message || err || 'SSL settings decrypt/load failed').trim() || 'SSL settings decrypt/load failed';
    console.warn(`SSL settings decrypt failed; using empty defaults. (${detail})`);
    setConfigIntegrityState('ssl', 'fail', detail);
    return { ...defaultSslSettings };
  }
}

async function persistSslSettings(config) {
  const payload = {
    encrypted: true,
    blob: encryptJson(sanitizeSslSettings(config))
  };
  await smartWriteFile(SSL_FILE, JSON.stringify(payload, null, 2), 'utf8');
  setConfigIntegrityState('ssl', 'ok', 'Saved successfully');
}

// ── Location settings ─────────────────────────────────────────────────────────
function sanitizeLocationSettings(config = {}) {
  const clean = (value, fallback) => {
    const next = String(value ?? fallback ?? '').trim();
    return next.slice(0, 64) || fallback;
  };
  const cleanTarget = (value, fallback = '') => {
    const raw = String(value ?? fallback ?? '').trim();
    if (!raw) return '';
    const clipped = raw.slice(0, 255);
    if (!/^[A-Za-z0-9._:-]+$/.test(clipped)) return '';
    return clipped;
  };
  const cleanMonitorId = (value = '', seed = '') => {
    const raw = String(value || '').trim().toLowerCase().replace(/[^a-z0-9-]/g, '').slice(0, 24);
    if (raw) return raw;
    const hash = crypto.createHash('sha1').update(String(seed || 'monitor')).digest('hex').slice(0, 10);
    return `pm-${hash}`;
  };
  const cleanPingMonitors = (rows = []) => {
    const out = [];
    const seen = new Set();
    for (const row of Array.isArray(rows) ? rows : []) {
      if (out.length >= Math.max(1, LOCATION_PING_MONITOR_MAX || 5)) break;
      const target = cleanTarget(row?.target, '');
      if (!target) continue;
      const labelRaw = String(row?.label || target).trim().slice(0, 48) || target;
      const id = cleanMonitorId(row?.id || '', `${labelRaw}|${target}`);
      if (seen.has(id)) continue;
      seen.add(id);
      out.push({ id, label: labelRaw, target });
    }
    return out;
  };
  const rawSections = Array.isArray(config.sections) ? config.sections : [];
  const baseSections = rawSections
    .map((row) => {
      const name = clean(row?.name, '');
      const rawId = String(row?.id || '').trim().toLowerCase();
      const id = (rawId || makeSectionId(name)).replace(/[^a-z0-9-]/g, '').slice(0, 32);
      const address = clean(row?.address, '').slice(0, 96);
      const pingMonitors = cleanPingMonitors(row?.pingMonitors || []);
      if (!name || !id) return null;
      return { id, name, address, pingMonitors };
    })
    .filter(Boolean);

  const sectionMap = new Map();
  for (const section of baseSections) {
    if (!sectionMap.has(section.id)) sectionMap.set(section.id, section);
  }

  const sections = Array.from(sectionMap.values());
  if (!sections.length) {
    sections.push({ id: 'internal', name: clean(config.internalName, defaultLocationSettings.internalName), address: '', pingMonitors: [] });
    const customerFallback = clean(config.customerName, defaultLocationSettings.customerName);
    if (customerFallback) {
      sections.push({ id: 'customer', name: customerFallback, address: '', pingMonitors: [] });
    }
  }

  const requestedInternal = clean(config.internalName, sections[0]?.name || defaultLocationSettings.internalName);
  const requestedCustomer = clean(config.customerName, sections[1]?.name || defaultLocationSettings.customerName);
  if (sections[0]) sections[0].name = requestedInternal;
  if (sections[1]) sections[1].name = requestedCustomer;
  sections.forEach((section) => {
    if (typeof section.address !== 'string') section.address = '';
    section.address = clean(section.address, '').slice(0, 96);
    section.pingMonitors = cleanPingMonitors(section.pingMonitors || []);
  });

  const internalSection = sections[0] || { id: 'internal', name: defaultLocationSettings.internalName };
  const customerSection = sections[1];
  return {
    companyName: clean(config.companyName, defaultLocationSettings.companyName),
    internalName: requestedInternal || internalSection.name || defaultLocationSettings.internalName,
    customerName: customerSection ? (requestedCustomer || customerSection.name || '') : '',
    sections
  };
}

async function loadLocationSettings() {
  try {
    const raw = await smartReadFile(LOCATION_SETTINGS_FILE, 'utf8');
    const parsed = JSON.parse(raw || '{}');
    return sanitizeLocationSettings(parsed);
  } catch {
    return { ...defaultLocationSettings };
  }
}

async function persistLocationSettings(config) {
  await smartWriteFile(LOCATION_SETTINGS_FILE, JSON.stringify(sanitizeLocationSettings(config), null, 2), 'utf8');
}

// ── Backup meta ───────────────────────────────────────────────────────────────
function sanitizeBackupMeta(config = {}) {
  return {
    lastBackupAt: String(config.lastBackupAt || '').trim(),
    lastBackupBy: String(config.lastBackupBy || '').trim(),
    lastRestoreAt: String(config.lastRestoreAt || '').trim(),
    lastRestoreBy: String(config.lastRestoreBy || '').trim()
  };
}

async function loadBackupMeta() {
  try {
    const raw = await smartReadFile(BACKUP_META_FILE, 'utf8');
    const parsed = JSON.parse(raw || '{}');
    return sanitizeBackupMeta(parsed);
  } catch {
    return { ...defaultBackupMeta };
  }
}

async function persistBackupMeta(config = {}) {
  await smartWriteFile(BACKUP_META_FILE, JSON.stringify(sanitizeBackupMeta(config), null, 2), 'utf8');
}

// ── LDAP config ──────────────────────────────────────────────────────────────
const defaultLdapConfig = {
  serverUrl: '',
  port: 389,
  baseDn: '',
  adminGroup: '',
  monitorGroup: '',
  bindDn: '',
  bindPassword: ''
};

function sanitizeLdapConfig(config = {}) {
  return {
    serverUrl: String(config.serverUrl || '').trim().slice(0, 255),
    port: Math.max(1, Math.min(65535, Number(config.port) || 389)),
    baseDn: String(config.baseDn || '').trim().slice(0, 512),
    adminGroup: String(config.adminGroup || '').trim().slice(0, 255),
    monitorGroup: String(config.monitorGroup || '').trim().slice(0, 255),
    bindDn: String(config.bindDn || '').trim().slice(0, 512),
    bindPassword: String(config.bindPassword || '')
  };
}

async function loadLdapConfig() {
  try {
    const raw = await smartReadFile(LDAP_FILE, 'utf8');
    const parsed = JSON.parse(raw || '{}');
    const config = parsed?.encrypted && parsed?.blob ? decryptJson(parsed.blob) : parsed;
    const normalized = sanitizeLdapConfig(config || {});
    setConfigIntegrityState('ldap', 'ok', 'Loaded successfully');
    return normalized;
  } catch (err) {
    const detail = String(err?.message || err || 'LDAP config decrypt/load failed').trim() || 'LDAP config decrypt/load failed';
    setConfigIntegrityState('ldap', 'fail', detail);
    return { ...defaultLdapConfig };
  }
}

async function persistLdapConfig(config) {
  const payload = {
    encrypted: true,
    blob: encryptJson(sanitizeLdapConfig(config))
  };
  await smartWriteFile(LDAP_FILE, JSON.stringify(payload, null, 2), 'utf8');
  setConfigIntegrityState('ldap', 'ok', 'Saved successfully');
}

function ldapConfigForClient() {
  const cfg = shared.ldapRuntimeConfig;
  return {
    serverUrl: cfg.serverUrl || '',
    port: cfg.port || 389,
    baseDn: cfg.baseDn || '',
    adminGroup: cfg.adminGroup || '',
    monitorGroup: cfg.monitorGroup || '',
    bindDn: cfg.bindDn || '',
    bindPassword: cfg.bindPassword ? MASK : ''
  };
}

module.exports = {
  defaultSsoConfig,
  loadSsoConfig,
  persistSsoConfig,
  sanitizeRuntimeSettings,
  loadRuntimeSettings,
  persistRuntimeSettings,
  loadApiTokenSettings,
  persistApiTokenSettings,
  isWindowsExeBuffer,
  sanitizeSslSettings,
  sslConfigForClient,
  loadSslSettings,
  persistSslSettings,
  sanitizeLocationSettings,
  loadLocationSettings,
  persistLocationSettings,
  sanitizeBackupMeta,
  loadBackupMeta,
  persistBackupMeta,
  defaultLdapConfig,
  sanitizeLdapConfig,
  loadLdapConfig,
  persistLdapConfig,
  ldapConfigForClient,
};
