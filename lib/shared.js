'use strict';
const {
  defaultRuntimeSettings,
  defaultSslSettings,
  defaultLocationSettings,
  defaultBackupMeta,
  CONFIG_INTEGRITY_KEYS,
  ENTRA_TENANT_ID,
  ENTRA_CLIENT_ID,
  ENTRA_CLIENT_SECRET,
  ENTRA_REDIRECT_URI,
  ENTRA_SCOPE,
} = require('./constants');

// ── Maps (exported by reference — same object always) ─────────────────────────
const sessions = new Map();
const rateLimitBuckets = new Map();
const loginAccountFailures = new Map();
const oauthState = new Map();
const localSetupState = new Map();
const prometheusMetrics = { requestsTotal: 0, requestsByStatus: new Map() };

// ── Default SSO config (computed here since it depends on ENTRA_ constants) ───
const defaultSsoConfig = {
  tenantId: ENTRA_TENANT_ID,
  clientId: ENTRA_CLIENT_ID,
  clientSecret: ENTRA_CLIENT_SECRET,
  redirectUri: ENTRA_REDIRECT_URI,
  scope: ENTRA_SCOPE
};

// ── Config integrity ──────────────────────────────────────────────────────────
function defaultConfigIntegrityState() {
  const out = {};
  for (const key of CONFIG_INTEGRITY_KEYS) {
    out[key] = { status: 'ok', detail: '', updatedAt: '' };
  }
  return out;
}

// ── Mutable `let` state (exported via getters/setters) ───────────────────────
let userRoleDirectory = new Map();
let ssoRuntimeConfig = { ...defaultSsoConfig };
let runtimeSettings = { ...defaultRuntimeSettings };
let sslRuntimeConfig = { ...defaultSslSettings };
let locationSettings = { ...defaultLocationSettings };
let backupMeta = { ...defaultBackupMeta };
let errorLogWriteQueue = Promise.resolve();
let diagnosticLogWriteQueue = Promise.resolve();
let telemetryLogWriteQueue = Promise.resolve();
let pgPool = null;
let redisClient = null;
let configIntegrityState = defaultConfigIntegrityState();
let linuxAgentDebCache = {
  scriptMtimeMs: 0,
  setupScriptMtimeMs: 0,
  connectTestScriptMtimeMs: 0,
  fileName: '',
  body: null
};
let storageBackendActive = 'file';

module.exports = {
  // Maps (same reference)
  sessions,
  rateLimitBuckets,
  loginAccountFailures,
  oauthState,
  localSetupState,
  prometheusMetrics,

  // Default configs
  defaultSsoConfig,
  defaultConfigIntegrityState,

  // Mutable lets via getters/setters
  get userRoleDirectory() { return userRoleDirectory; },
  set userRoleDirectory(v) { userRoleDirectory = v; },

  get ssoRuntimeConfig() { return ssoRuntimeConfig; },
  set ssoRuntimeConfig(v) { ssoRuntimeConfig = v; },

  get runtimeSettings() { return runtimeSettings; },
  set runtimeSettings(v) { runtimeSettings = v; },

  get sslRuntimeConfig() { return sslRuntimeConfig; },
  set sslRuntimeConfig(v) { sslRuntimeConfig = v; },

  get locationSettings() { return locationSettings; },
  set locationSettings(v) { locationSettings = v; },

  get backupMeta() { return backupMeta; },
  set backupMeta(v) { backupMeta = v; },

  get errorLogWriteQueue() { return errorLogWriteQueue; },
  set errorLogWriteQueue(v) { errorLogWriteQueue = v; },

  get diagnosticLogWriteQueue() { return diagnosticLogWriteQueue; },
  set diagnosticLogWriteQueue(v) { diagnosticLogWriteQueue = v; },

  get telemetryLogWriteQueue() { return telemetryLogWriteQueue; },
  set telemetryLogWriteQueue(v) { telemetryLogWriteQueue = v; },

  get pgPool() { return pgPool; },
  set pgPool(v) { pgPool = v; },

  get redisClient() { return redisClient; },
  set redisClient(v) { redisClient = v; },

  get configIntegrityState() { return configIntegrityState; },
  set configIntegrityState(v) { configIntegrityState = v; },

  get linuxAgentDebCache() { return linuxAgentDebCache; },
  set linuxAgentDebCache(v) { linuxAgentDebCache = v; },

  get storageBackendActive() { return storageBackendActive; },
  set storageBackendActive(v) { storageBackendActive = v; },
};
