const http = require('http');
const https = require('https');
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { URL } = require('url');
const crypto = require('crypto');
const readline = require('readline');
const dgram = require('dgram');
const net = require('net');
const tls = require('tls');
const os = require('os');
const { execFile, spawn } = require('child_process');
const QRCode = require('qrcode');

// ── Load constants (also loads .env file) ────────────────────────────────────
const {
  APP_VERSION,
  loadEnvFile,
  parseBooleanFlag,
  normalizeSmtpStarttlsMode,
  normalizeSmtpTransportConfig,
  smtpConfigEnabled,
  smtpTransportLabel,
  sanitizeMailAddress,
  resolveMailFrom,
  normalizeTeamsWebhookUrl,
  teamsWebhookEnabled,
  normalizeTeamsWebhookTimeoutMs,
  defaultWebhookRoutingRules,
  defaultWebhookSectionModes,
  defaultWebhookRoutingMessages,
  normalizeWebhookRoutingRules,
  normalizeWebhookRoutingMessages,
  normalizeWebhookSectionModes,
  PORT,
  HTTPS_PORT,
  SYSLOG_UDP_PORT,
  SYSLOG_TCP_PORT,
  NETFLOW_PORT,
  FLOW_TIMEOUT_MS,
  SYSLOG_FLOW_TIMEOUT_MIN_MS,
  NETFLOW_FLOW_TIMEOUT_MIN_MS,
  SNMP_POLL_INTERVAL_MS,
  PING_INTERVAL_MS,
  GLOBAL_DATA_REFRESH_MS,
  NETFLOW_TOP_WINDOW_MS,
  UPTIME_SAMPLE_INTERVAL_MS,
  WAN_TEST_INTERVAL_MS,
  LOCATION_PING_MONITOR_MAX,
  LOCATION_PING_MONITOR_POLL_INTERVAL_MS,
  WAN_TEST_SLOT_INTERVAL_MS,
  WAN_PUBLIC_IP_POLL_INTERVAL_MS,
  WAN_TEST_RECOVERY_INTERVAL_MS,
  WAN_TEST_SLOT_LABEL_BY_HOUR,
  GLOBAL_CLOCK_TIMEZONE,
  GLOBAL_CLOCK_HOUR_MODE,
  ALERT_SILENCE_DURATION_MS,
  WAN_TEST_HISTORY,
  SESSION_TTL_MS,
  SESSION_IDLE_TTL_MS,
  SESSION_RENEW_INTERVAL_MS,
  FORCE_SECURE_COOKIES,
  LOGIN_RATE_LIMIT_MAX,
  LOGIN_RATE_LIMIT_WINDOW_MS,
  LOGIN_ACCOUNT_FAILURE_THRESHOLD,
  LOGIN_ACCOUNT_FAILURE_WINDOW_MS,
  LOGIN_ACCOUNT_LOCK_MS,
  PUBLIC_STATUS_RATE_LIMIT_MAX,
  PUBLIC_STATUS_RATE_LIMIT_WINDOW_MS,
  API_TOKEN_RATE_LIMIT_MAX,
  API_TOKEN_RATE_LIMIT_WINDOW_MS,
  WEBHOOK_TEST_RATE_LIMIT_MAX,
  WEBHOOK_TEST_RATE_LIMIT_WINDOW_MS,
  LOCAL_SETUP_TTL_MS,
  PASSWORD_HASH_ITERATIONS,
  LOCAL_TOTP_ENABLED,
  MIN_CONFIG_KEY_LENGTH,
  API_TOKEN_MAX_COUNT,
  API_TOKEN_MAX_LIFETIME_DAYS,
  API_TOKEN_MAX_LIFETIME_MS,
  API_TOKEN_MAX_IP_ALLOWLIST,
  EVENT_RETENTION,
  SITES_PERSIST_INTERVAL_MS,
  EVENTS_PERSIST_INTERVAL_MS,
  BACKUP_KDF_ITERATIONS,
  ERROR_LOG_MAX_BYTES,
  ERROR_LOG_MAX_LINES,
  DIAGNOSTIC_LOG_MAX_BYTES,
  DIAGNOSTIC_LOG_MAX_LINES,
  TELEMETRY_LOG_MAX_BYTES,
  TELEMETRY_LOG_MAX_LINES,
  TELEMETRY_MESSAGE_MAX_BYTES,
  DATA_RETENTION_DAYS,
  DATA_RETENTION_MS,
  TELEMETRY_NETFLOW_RECORDS_PER_PACKET,
  SYSLOG_EVENT_THROTTLE_MS,
  NETFLOW_EVENT_THROTTLE_MS,
  SNMP_OK_EVENT_THROTTLE_MS,
  SNMP_ERROR_EVENT_THROTTLE_MS,
  TOOLS_TERMINAL_TIMEOUT_MS,
  TOOLS_TERMINAL_MAX_LINES,
  COLLECTOR_AGENT_SESSION_TTL_MS,
  COLLECTOR_AGENT_COMMAND_TIMEOUT_MS,
  COLLECTOR_AGENT_COMMAND_LEASE_MS,
  COLLECTOR_AGENT_POLL_INTERVAL_MS,
  COLLECTOR_AGENT_INSTALL_TIE_EPSILON_MS,
  PUBLIC_SERVICE_POLL_INTERVAL_MS,
  SMTP_TRANSPORT_CONFIG,
  MAIL_FROM,
  DEFAULT_TEAMS_WEBHOOK_URL,
  DEFAULT_TEAMS_WEBHOOK_TIMEOUT_MS,
  TEAMS_WEBHOOK_MAX_ATTEMPTS,
  TEAMS_WEBHOOK_RETRY_BASE_MS,
  WINDOWS_AGENT_PACKAGE_MAX_BYTES,
  DATABASE_POOL_MAX,
  DATABASE_POOL_IDLE_TIMEOUT_MS,
  DATABASE_POOL_CONNECTION_TIMEOUT_MS,
  DATABASE_STATEMENT_TIMEOUT_MS,
  DATABASE_QUERY_TIMEOUT_MS,
  STARTED_AT_MS,
  PUBLIC_SERVICE_TARGETS,
  ENTRA_TENANT_ID,
  ENTRA_CLIENT_ID,
  ENTRA_CLIENT_SECRET,
  ENTRA_REDIRECT_URI,
  ENTRA_SCOPE,
  ADMIN_USERS,
  MONITOR_USERS,
  PUBLIC_DIR,
  DATA_DIR,
  README_PATH,
  REQUESTED_STORAGE_BACKEND,
  DATABASE_URL,
  DATABASE_SSL_MODE,
  SITES_FILE,
  DEVICES_FILE,
  USERS_FILE,
  SSO_FILE,
  EVENTS_FILE,
  ERROR_LOG_FILE,
  DIAGNOSTIC_LOG_FILE,
  TELEMETRY_LOG_FILE,
  SSL_FILE,
  RUNTIME_FILE,
  LOCATION_SETTINGS_FILE,
  BACKUP_META_FILE,
  API_TOKENS_FILE,
  WINDOWS_AGENT_PACKAGE_FILE,
  LINUX_AGENT_SCRIPT_FILE,
  WINDOWS_AGENT_SCRIPT_FILE,
  WINDOWS_AGENT_EXE_FILE,
  WINDOWS_AGENT_SCRIPT_FILENAME,
  WINDOWS_AGENT_DOWNLOAD_FILENAME,
  LINUX_AGENT_SETUP_SCRIPT_FILE,
  LINUX_AGENT_CONNECT_TEST_SCRIPT_FILE,
  LINUX_AGENT_DEB_PACKAGE_NAME,
  LINUX_AGENT_DEB_VERSION,
  LINUX_AGENT_SERVICE_NAME,
  LINUX_AGENT_DEB_ARCH,
  CONFIG_INTEGRITY_KEYS,
  WEBHOOK_SECTION_CATALOG,
  WEBHOOK_SECTION_MODE_VALUES,
  WEBHOOK_ROUTE_CATALOG,
  WEBHOOK_ROUTE_IDS,
  WEBHOOK_ROUTE_MAP,
  WEBHOOK_ROUTE_DEFAULT_MESSAGES,
  SENSITIVE_FIELDS,
  MASK,
  SITE_MONITOR_CONFIG_DECRYPT_FAILED,
  SITE_MONITOR_CONFIG_ENCRYPTED_FALLBACK,
  defaultRuntimeSettings,
  defaultSslSettings,
  defaultLocationSettings,
  defaultBackupMeta,
  defaultApiTokenSettings,
  defaultWindowsAgentPackageSettings,
  STORAGE_TRACKED_FILES,
  STORAGE_TRACKED_FILE_KEYS,
} = require('./lib/constants');

const {
  validateConfigKeyStrength,
  deriveCryptoKey,
  getCryptoKey,
  getPreviousCryptoKey,
  encryptJson,
  decryptJsonWithKey,
  decryptJson,
  deriveBackupKey,
  encryptBackupPayload,
  decryptBackupPayload,
  validateBackupImportPayload,
  BASE32_ALPHABET,
  base32Encode,
  base32Decode,
  generateTotpSecret,
  totpAt,
  verifyTotp,
  hashApiToken,
} = require('./lib/crypto');
const { AsyncMutex } = require('./lib/mutex');

const {
  rateLimitBuckets,
  loginAccountFailures,
  normalizeLoginIdentifier,
  consumeRateLimitToken,
  pruneRateLimitBuckets,
  getLoginAccountLockState,
  recordLoginAccountFailure,
  clearLoginAccountFailures,
  sendRateLimitResponse,
  enforceRateLimitOrSend,
} = require('./lib/ratelimit');

const {
  sessions,
  parseCookies,
  requestIsHttps,
  issueSessionCookie,
  clearSessionCookie,
  sessionIsExpired,
  requestOriginFromHeaders,
  applySecurityHeaders,
  normalizeOriginHeaderValue,
  csrfRequiredForRequest,
  csrfOriginMatchesHost,
  validateCsrfRequest,
} = require('./lib/session');

const {
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
} = require('./lib/notifications');

const shared = require('./lib/shared');

const {
  sanitizeMailHeaderValue,
  buildPlainTextEmailMessage,
  smtpDotStuffMessage,
  parseSmtpResponseLine,
  smtpCapabilitiesFromResponse,
  createSmtpLineReader,
  readSmtpResponse,
  smtpWriteLine,
  smtpCommand,
  connectSmtpSocket,
  runSmtpConnectionProbe,
  smtpAuthenticate,
  sendMailWithSmtp,
  sendMailWithSendmail,
  sendMailWithTransport,
  validateSmtpTransportConfig,
} = require('./lib/smtp');

const {
  normalizeAccessRole,
  normalizeApiTokenRole,
  API_TOKEN_SCOPE_SET,
  normalizeApiTokenScope,
  parseApiTokenScopeList,
  normalizeApiTokenScopes,
  requiredApiTokenScopeForRequest,
  apiTokenHasScope,
  normalizeApiTokenName,
  normalizeRemoteIpForMatch,
  parseApiTokenIpAllowlist,
  normalizeApiTokenIpAllowlist,
  validateApiTokenAllowlistEntry,
  apiTokenAllowlistContainsIp,
  parseCollectorAgentInstallTimestampMs,
  normalizeApiTokenRecord,
  sanitizeApiTokenSettings,
  apiTokenStatus,
  isApiTokenActive,
  apiTokenForClient,
  validateApiTokenCreateInput,
  buildApiTokenHashIndex,
} = require('./lib/tokens');

const {
  setStorageBackend: setLoggingStorageBackend,
  isSensitiveLogKey,
  redactSecretsInText,
  redactForLogs,
  normalizeError,
  logJson,
  appendErrorLogEntry,
  queueErrorLogEntry,
  logSystemError,
  readErrorLogEntries,
  appendDiagnosticLogEntry,
  queueDiagnosticLogEntry,
  normalizeDiagnosticLevel,
  logDiagnostic,
  logDiagnosticThrottled,
  readDiagnosticLogEntries,
  clearDiagnosticLogEntries,
  truncateTelemetryText,
  appendTelemetryLogEntry,
  queueTelemetryLogEntry,
  logTelemetry,
  readTelemetryLogEntries,
  clearTelemetryLogEntries,
} = require('./lib/logging');

const {
  getPoolStats,
  incrementRequestMetric,
  initRedisIfConfigured,
  redisSessionKey,
  redisPersistSession,
  redisDeleteSession,
  redisRestoreSessions,
  normalizeConfigIntegrityStatus,
  setConfigIntegrityState,
  getConfigIntegrityReport,
  trackedStoreKeyForFile,
  isTrackedDataFile,
  createEnoentError,
  parseReadEncodingArg,
  normalizeStorageBody,
  readStoreBodyFromPostgres,
  writeStoreBodyToPostgres,
  appendStoreBodyToPostgres,
  hasStoreKeyInPostgres,
  statStoreBodyFromPostgres,
  smartReadFile,
  smartWriteFile,
  smartAppendFile,
  smartStat,
  smartFileExists,
  resolvePostgresSslConfig,
  buildPostgresPoolConfig,
  migrateExistingFilesToPostgresStore,
  initStorageBackend,
  closeStorageBackend,
} = require('./lib/storage');

// Inject storage backend into lib/logging.js (must come after smart* functions are defined)
setLoggingStorageBackend({ smartReadFile, smartWriteFile, smartAppendFile, smartStat });

const {
  sendJson,
  sendServerError,
  RequestValidationError,
  isPlainObject,
  walkPayloadForUnsafeKeys,
  normalizeAllowedPayloadKeys,
  validateRequestPayload,
  badRequestPayload,
  readRequestBody,
  ensureAllowed,
} = require('./lib/http');

const {
  saveApiTokenSettingsToState,
  entraConfigured,
  ssoConfigForClient,
  getSessionById,
  sessionFromCookies,
  touchSessionActivity,
  decodeJwtPayload,
  mapUserRole,
  getUserFromRequest,
  normalizeUserEntry,
  sanitizeUserForClient,
  hashPassword,
  verifyPassword,
  normalizeCollectorAgentAuth,
  normalizeCollectorAgentInstallIdentity,
  evaluateCollectorAgentInstallRegistration,
  updateCollectorAgentInstallLock,
  collectorAgentPasswordConfigured,
  makeTotpPayload,
  createSetupToken,
  consumeSetupToken,
  peekSetupToken,
  decryptTotpSecret,
  resolveTotpSecretState,
  localTotpMfaEnabled,
  issueLocalSession,
  ensureDefaultLocalUsers,
  buildUserRoleDirectory,
} = require('./lib/auth');

const {
  parseIsoTimestampMs,
  pruneEventsByPolicy,
  sameEventList,
  persistEvents,
  createEvent,
  logEvent,
  actorName,
  logSecurityAuditEvent,
  markUserLastLogin,
  resolveLocalUserByIdentifier,
  logEventThrottled,
  logSiteEvent,
  logSiteEventThrottled,
  locationNameForSite,
} = require('./lib/events');

const {
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
} = require('./lib/sites');

const {
  defaultSsoConfig,
  loadSsoConfig,
  persistSsoConfig,
  sanitizeRuntimeSettings,
  loadRuntimeSettings,
  persistRuntimeSettings,
  loadApiTokenSettings,
  persistApiTokenSettings,
  sanitizeWindowsAgentPackageFileName,
  normalizeWindowsAgentPackageBase64,
  isWindowsExeBuffer,
  decodeWindowsAgentPackageBuffer,
  normalizeWindowsAgentPackageSettings,
  windowsAgentPackageForClient,
  loadWindowsAgentPackageSettings,
  persistWindowsAgentPackageSettings,
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
} = require('./lib/settings');

const {
  parseLinesFromBuffer,
  formatPacketPreview,
  normalizeNetflowUsageIp,
  addNetflowUsage,
  buildNetflowTroublemakersReport,
  parseNetflowV5,
  readUnsignedBE,
  parseIPv4,
  parseTemplateFlowSet,
  parseDataWithTemplate,
  parseNetflowV9,
  parseIPFIX,
  parseAnyNetflow,
} = require('./lib/telemetry');

const {
  runExecFile,
  runExecFileWithOptions,
  buildLinuxAgentDebPackage,
  splitNonEmptyLines,
  normalizeToolsTerminalLines,
  parseToolsTerminalTokens,
  sanitizeToolsTerminalHostToken,
  formatToolsTerminalMbps,
  toolsTerminalDefaultHost,
  getCollectorAgentPresence,
  setCollectorAgentPresence,
  collectorSiteById,
  pruneCollectorAgentSessions,
  ensureCollectorAgentQueue,
  removeCollectorAgentQueuedCommand,
  dequeueCollectorAgentCommandForPoll,
  shellQuoteArg,
  collectorResultHasUnsupportedCommand,
  collectorManualUpdateLines,
  resolveCollectorCommandWaiter,
  rejectCollectorCommandWaiter,
  queueCollectorAgentCommand,
  touchCollectorAgentSession,
  revokeCollectorAgentSiteSessions,
  clearCollectorAgentSiteRuntime,
  issueCollectorAgentSession,
  getCollectorAgentSession,
  toolsTerminalRecentAgeLabel,
  toolsTerminalDiagnosticsLines,
  toolsTerminalStatusLines,
  toolsTerminalHelpLines,
  runToolsTerminalExecCandidates,
  toolsTerminalLinesFromExec,
  runCollectorAgentTerminalCommand,
  runToolsTerminalCommand,
  runCollectorTerminalCommand,
  factoryResetBaselineUsers,
  performFactoryResetForDeployment,
} = require('./lib/agent');

const {
  parsePortNumber,
  parseUfwActive,
  ssHasListener,
  inferAppListenerOpen,
  ufwAllowsSource,
  summarizeChecks,
  evaluateFirewallUfwRuleStatus,
  buildFirewallCheck,
  readTrackedStorageFiles,
  estimateEventStorageMax,
  retainRecentJsonLinesFile,
  retainedEventsForPolicy,
  enforceStorageRetention,
  buildStorageSummary,
  purgeStorageLogs,
  summarizeDiagnosticChecks,
  toPortNumber,
  parsePingLatencyMs,
  runPingProbe,
  getLocalHostSet,
  getServerHostInfo,
  healthStatusFromChecks,
  healthHttpStatusForState,
  runDatabaseHealthCheck,
  buildPublicHealthPayload,
  isLocalHostValue,
  addDiagnosticCheck,
  runMonitorDiagnostics,
} = require('./lib/health');

const {
  protocolFlowTimeoutMs,
  recentFlowCheck,
  matchSiteBySourceIp,
  markNetflowSeen,
  refreshNetflowTopTalkers,
  updateSyslogMetrics,
  logSyslogStreamEvent,
  decaySyslogMetrics,
  configuredSyslogSourceList,
  handleUnmatchedSyslogPacket,
  handleMatchedSyslogPacket,
  runSnmpGet,
  runPing,
  runPingStats,
  appendUptimeSample,
  currentHeartbeatFreshWindowMs,
  deriveUptime14d,
  wanTestSlotHourFromTimestamp,
  wanTestSlotLabelFromTimestamp,
  nextWanTestSlotTimestamp,
  appendWanTest,
  extractSpeedtestMetricsFromLines,
  extractPublicIpFromLines,
  normalizeCollectorSpeedtestMetrics,
  normalizeCollectorPublicIpMetrics,
  deriveSiteStatus,
  detectSnmpgetDependency,
  detectSmtpDependency,
  detectSendmailDependency,
  effectiveTeamsWebhookConfig,
  buildWebhookRouteTestPayload,
  collectorLatestWanPublicIp,
  buildWebhookTemplateContextForStatus,
  buildWebhookTemplateContextForRouteTest,
  systemDependencySignal,
  initialPublicServiceState,
  locationPingMonitorDefinitions,
  locationPingMonitorStateKey,
  initialLocationPingMonitorState,
  detectTeamsDependency,
  detectMailDependency,
  startSyslogCollectors,
  startNetflowCollector,
  pollLocationPingMonitors,
  pollPublicServices,
  startPublicServicePoller,
  startLocationPingMonitorPoller,
  runCollectorWanPublicIpProbe,
  runScheduledCollectorWanSpeedtest,
  startPingPoller,
  startUptimeSampler,
  seedCollectorWanPublicIpState,
  startCollectorWanPublicIpPoller,
  startWanTestPoller,
  startSnmpPoller,
} = require('./lib/monitoring');

const { createHttpHandler } = require('./lib/router');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml'
};


const defaultSiteSeeds = [
  ['site-hq', 'HQ', 'Primary office edge and core connectivity.', 'internal', 'HQ Edge Firewall', 'up', '203.0.113.12', true, ['noc@cajal.local', 'infra@cajal.local'], '2026-02-12T14:05:00.000Z', [true, 'udp', 'syslog-hq-token', '2026-02-18T15:20:00.000Z'], [true, '10.0.0.1', 'public-hq', '2026-02-16T17:10:00.000Z'], [true, 'HQ-FW-01', 'netflow-hq-secret', '2026-02-19T12:45:00.000Z'], [100, 100, 99.96, 100, 99.92, 100, 99.98, 99.95, 100, 100, 99.9, 99.97, 100, 100], '67d 04h', ['10 min ago', 942, 901, 4], ['40 min ago', 934, 887, 5]],
  ['site-lab', 'Engineering Lab', 'R&D environment with test workloads and branch uplink.', 'internal', 'Lab Firewall', 'warn', '203.0.113.36', true, ['labops@cajal.local'], '2026-02-11T09:20:00.000Z', [true, 'tcp', 'syslog-lab-token', '2026-02-15T10:35:00.000Z'], [true, '10.0.50.1', 'public-lab', '2026-02-14T09:05:00.000Z'], [false, 'LAB-FW-01', 'netflow-lab-secret', '2026-02-13T18:50:00.000Z'], [99.2, 98.9, 99.1, 98.7, 98.4, 97.8, 98.2, 99.0, 98.6, 99.1, 98.8, 98.3, 98.9, 99.0], '11d 18h', ['8 min ago', 516, 201, 12], ['38 min ago', 492, 193, 14]]
];

const defaultData = {
  sites: defaultSiteSeeds.map(siteFromSeed),
  devices: [
    {
      id: 'fw-001',
      name: 'Edge Firewall',
      type: 'Firewall',
      siteId: 'site-hq',
      ip: '10.0.0.1',
      status: 'up',
      cpu: 46,
      memory: 61,
      lastSeen: new Date().toISOString()
    },
    {
      id: 'col-001',
      name: 'HQ Collector',
      type: 'Collector',
      siteId: 'site-hq',
      ip: '10.0.0.10',
      status: 'up',
      cpu: 12,
      memory: 34,
      lastSeen: new Date().toISOString()
    },
    {
      id: 'col-002',
      name: 'WIN11-HOST',
      type: 'Collector',
      siteId: 'site-hq',
      ip: '10.0.0.11',
      status: 'up',
      cpu: 8,
      memory: 28,
      lastSeen: new Date().toISOString()
    }
  ]
};

const defaultUsers = [
  { email: 'admin', displayName: 'Local Admin', role: 'admin' },
  { email: 'monitor@cajal.local', displayName: 'Local Monitor', role: 'monitor' }
];

if (!shared.ssoRuntimeConfig) shared.ssoRuntimeConfig = { ...defaultSsoConfig };
if (!shared.runtimeSettings) shared.runtimeSettings = { ...defaultRuntimeSettings };
if (!shared.sslRuntimeConfig) shared.sslRuntimeConfig = { ...defaultSslSettings };
if (!shared.locationSettings) shared.locationSettings = { ...defaultLocationSettings };
if (!shared.backupMeta) shared.backupMeta = { ...defaultBackupMeta };






async function ensureDataFiles() {
  await fsp.mkdir(DATA_DIR, { recursive: true });
  const seededKeys = [];
  const hasSites = await smartFileExists(SITES_FILE);
  const hasDevices = await smartFileExists(DEVICES_FILE);
  const hasUsers = await smartFileExists(USERS_FILE);
  const hasSso = await smartFileExists(SSO_FILE);
  const hasSsl = await smartFileExists(SSL_FILE);
  const hasRuntime = await smartFileExists(RUNTIME_FILE);
  const hasApiTokens = await smartFileExists(API_TOKENS_FILE);
  const hasWindowsAgentPackage = await smartFileExists(WINDOWS_AGENT_PACKAGE_FILE);
  const hasLocationSettings = await smartFileExists(LOCATION_SETTINGS_FILE);
  const hasEvents = await smartFileExists(EVENTS_FILE);
  const hasErrorLog = await smartFileExists(ERROR_LOG_FILE);
  const hasDiagnosticLog = await smartFileExists(DIAGNOSTIC_LOG_FILE);
  const hasTelemetryLog = await smartFileExists(TELEMETRY_LOG_FILE);
  const hasBackupMeta = await smartFileExists(BACKUP_META_FILE);

  if (!hasSites || !hasDevices) {
    const initial = {
      sites: clone(defaultData.sites),
      devices: clone(defaultData.devices)
    };
    await persistSites(initial.sites);
    await smartWriteFile(DEVICES_FILE, JSON.stringify(initial.devices, null, 2), 'utf8');
    if (!hasSites) seededKeys.push('sites');
    if (!hasDevices) seededKeys.push('devices');
  }

  if (!hasUsers) {
    await smartWriteFile(USERS_FILE, JSON.stringify(defaultUsers, null, 2), 'utf8');
    seededKeys.push('users');
  }
  if (!hasSso) {
    await persistSsoConfig(defaultSsoConfig);
    seededKeys.push('sso');
  }
  if (!hasSsl) {
    await persistSslSettings(defaultSslSettings);
    seededKeys.push('ssl');
  }
  if (!hasRuntime) {
    await persistRuntimeSettings(defaultRuntimeSettings);
    seededKeys.push('runtime');
  }
  if (!hasApiTokens) {
    await persistApiTokenSettings(defaultApiTokenSettings);
    seededKeys.push('apiTokens');
  }
  if (!hasWindowsAgentPackage) {
    await persistWindowsAgentPackageSettings(defaultWindowsAgentPackageSettings);
    seededKeys.push('windowsAgentPackage');
  }
  if (!hasLocationSettings) {
    await smartWriteFile(LOCATION_SETTINGS_FILE, JSON.stringify(defaultLocationSettings, null, 2), 'utf8');
    seededKeys.push('locationSettings');
  }
  if (!hasEvents) {
    await smartWriteFile(EVENTS_FILE, JSON.stringify([], null, 2), 'utf8');
    seededKeys.push('events');
  }
  if (!hasErrorLog) {
    await smartWriteFile(ERROR_LOG_FILE, '', 'utf8');
    seededKeys.push('errorLog');
  }
  if (!hasDiagnosticLog) {
    await smartWriteFile(DIAGNOSTIC_LOG_FILE, '', 'utf8');
    seededKeys.push('diagnosticsLog');
  }
  if (!hasTelemetryLog) {
    await smartWriteFile(TELEMETRY_LOG_FILE, '', 'utf8');
    seededKeys.push('telemetryLog');
  }
  if (!hasBackupMeta) {
    await persistBackupMeta(defaultBackupMeta);
    seededKeys.push('backupMeta');
  }
  return [...new Set(seededKeys)];
}









async function loadState() {
  const seededDataKeys = await ensureDataFiles();
  if (seededDataKeys.length) {
    setConfigIntegrityState('bootstrap', 'warn', `Auto-seeded missing tracked data keys: ${seededDataKeys.join(', ')}`);
  } else {
    setConfigIntegrityState('bootstrap', 'ok', 'All tracked data keys were present');
  }
  const sites = await loadSites();
  const devices = JSON.parse(await smartReadFile(DEVICES_FILE, 'utf8'));
  const users = await loadUsers();
  const loadedEvents = await loadEvents();
  const events = Array.isArray(loadedEvents) ? loadedEvents : [];
  const changeActorBackfilled = backfillSiteChangeActorsFromEvents(sites, events);
  let dirtySites = false;
  if (changeActorBackfilled) {
    try {
      await persistSites(sites);
    } catch (err) {
      dirtySites = true;
      console.warn(`Change actor backfill persist failed: ${err?.message || err}`);
    }
  }
  const usersChanged = ensureDefaultLocalUsers(users);
  if (usersChanged) await persistUsers(users);
  shared.ssoRuntimeConfig = await loadSsoConfig();
  shared.runtimeSettings = await loadRuntimeSettings();
  const apiTokenSettings = await loadApiTokenSettings();
  shared.sslRuntimeConfig = await loadSslSettings();
  shared.locationSettings = await loadLocationSettings();
  shared.backupMeta = await loadBackupMeta();
  shared.userRoleDirectory = buildUserRoleDirectory(users);
  return {
    sites,
    devices,
    users,
    backupMeta: shared.backupMeta,
    links: [],
    alerts: [],
    events,
    apiTokens: Array.isArray(apiTokenSettings?.tokens) ? apiTokenSettings.tokens : [],
    apiTokenByHash: buildApiTokenHashIndex(apiTokenSettings?.tokens),
    apiTokensDirty: false,
    dirtySites,
    dirtyEvents: false,
    syslogWindows: new Map(),
    netflowTalkers: new Map(),
    netflowTemplates: new Map(),
    flowState: new Map(),
    pingState: new Map(),
    wanPingState: new Map(),
    alertSilenceUntilMs: 0,
    eventThrottle: new Map(),
    diagnosticThrottle: new Map(),
    agentSessions: new Map(),
    agentBySite: new Map(),
    agentCommandQueue: new Map(),
    agentPending: new Map(),
    publicServices: initialPublicServiceState(),
    locationPingMonitors: initialLocationPingMonitorState(shared.locationSettings),
    startupBootstrapSeededKeys: seededDataKeys,
    notificationState: {
      systemDependencySignal: '',
      collectorWanPublicIp: {}
    },
    dependencies: {
      snmpget: { available: true, path: '', detail: '' },
      smtp: { available: false, path: '', detail: '', probeOk: false, mode: 'teams', host: '', port: 0, secure: true, starttls: 'off', authEnabled: false }
    },
    lastSeen: {
      ping: new Map(),
      pingSecondary: new Map(),
      syslog: new Map(),
      snmp: new Map(),
      netflow: new Map()
    },
    stateMutex: new AsyncMutex()
  };
}















function persistLoop(state) {
  setInterval(() => {
    if (!state.dirtySites) return;
    flushDirtyState(state, { forceSites: true })
      .catch((err) => {
        logSystemError('persist.sites', err, { dirtySites: state.dirtySites });
      });
  }, SITES_PERSIST_INTERVAL_MS);

  setInterval(() => {
    if (!state.dirtyEvents) return;
    flushDirtyState(state, { forceEvents: true })
      .catch((err) => {
        logSystemError('persist.events', err, { dirtyEvents: state.dirtyEvents });
      });
  }, EVENTS_PERSIST_INTERVAL_MS);

  setInterval(() => {
    if (!state.apiTokensDirty) return;
    flushDirtyState(state, { forceApiTokens: true })
      .catch((err) => {
        logSystemError('persist.api_tokens', err, { apiTokensDirty: state.apiTokensDirty });
      });
  }, SITES_PERSIST_INTERVAL_MS);
}

function installShutdownHandlers(state, ...servers) {
  let shuttingDown = false;
  const handleSignal = (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`${signal} received; flushing state to storage before exit...`);
    flushDirtyState(state, { forceSites: true, forceEvents: true, forceApiTokens: true })
      .catch((err) => {
        logSystemError('shutdown.flush', err, { signal });
      })
      .then(() => closeStorageBackend().catch((err) => logSystemError('shutdown.storage.close', err, { signal })))
      .finally(() => {
        const toClose = servers.filter((s) => s && typeof s.close === 'function');
        if (!toClose.length) { process.exit(0); }
        const fallbackExit = setTimeout(() => process.exit(0), 1500);
        fallbackExit.unref?.();
        let remaining = toClose.length;
        const done = () => { if (--remaining === 0) { clearTimeout(fallbackExit); process.exit(0); } };
        toClose.forEach((s) => s.close(done));
      });
  };

  process.on('SIGINT', () => handleSignal('SIGINT'));
  process.on('SIGTERM', () => handleSignal('SIGTERM'));
}

async function main() {
  getCryptoKey();
  await initStorageBackend();
  const state = await loadState();
  if (Array.isArray(state.startupBootstrapSeededKeys) && state.startupBootstrapSeededKeys.length) {
    const seededDetail = state.startupBootstrapSeededKeys.join(', ');
    logEvent(state, {
      classId: 422,
      source: 'system',
      actor: 'cajal',
      action: 'tracked_store_auto_seeded',
      message: `Missing tracked data keys were auto-seeded: ${state.startupBootstrapSeededKeys.length}`,
      detail: seededDetail
    });
    console.warn(`Auto-seeded missing tracked data keys: ${seededDetail}`);
  }
  const configIntegrity = getConfigIntegrityReport();
  if (!configIntegrity.healthy) {
    const failing = configIntegrity.entries.filter((row) => row.status !== 'ok');
    const detail = failing.map((row) => `${row.name}:${row.status}${row.detail ? `(${row.detail})` : ''}`).join(', ');
    logEvent(state, {
      classId: 422,
      source: 'system',
      actor: 'cajal',
      action: 'config_integrity_warning',
      message: 'Configuration integrity warnings detected on startup',
      detail
    });
    console.warn(`Configuration integrity warning(s): ${detail}`);
  }
  const monitorDecryptFailures = state.sites.filter((site) => siteHasMonitorConfigDecryptFailure(site));
  if (monitorDecryptFailures.length) {
    const affected = monitorDecryptFailures.map((site) => site.name || site.id).join(', ');
    logEvent(state, {
      classId: 422,
      source: 'system',
      actor: 'cajal',
      action: 'monitor_config_decrypt_failed',
      message: `Monitor config decrypt failed for ${monitorDecryptFailures.length} site(s)`,
      detail: affected
    });
    console.warn(`Monitor config decrypt failed for ${monitorDecryptFailures.length} site(s): ${affected}`);
  }
  await enforceStorageRetention(state, { persistEventsNow: true, pruneEvents: false });
  await initRedisIfConfigured();
  await redisRestoreSessions(sessions);
  state.dependencies.snmpget = await detectSnmpgetDependency();
  state.dependencies.smtp = await detectMailDependency();
  if (!state.dependencies.snmpget.available) {
    logEvent(state, {
      classId: 422,
      source: 'snmp',
      actor: 'cajal',
      action: 'startup_dependency_check',
      message: 'SNMP dependency missing: snmpget not found',
      detail: state.dependencies.snmpget.detail || 'install net-snmp / snmp package'
    });
  } else {
    logEvent(state, {
      classId: 322,
      source: 'snmp',
      actor: 'cajal',
      action: 'startup_dependency_check',
      message: 'SNMP dependency ready',
      detail: `${state.dependencies.snmpget.path || 'snmpget'} ${state.dependencies.snmpget.detail || ''}`.trim()
    });
  }
  if (!state.dependencies.smtp.available) {
    logEvent(state, {
      classId: 422,
      source: 'notifications',
      actor: 'cajal',
      action: 'startup_dependency_check',
      message: 'Teams notification dependency missing',
      detail: state.dependencies.smtp.detail || 'Configure Teams webhook in Settings or set CAJAL_TEAMS_WEBHOOK_URL'
    });
  } else {
    logEvent(state, {
      classId: state.dependencies.smtp.probeOk ? 322 : 402,
      source: 'notifications',
      actor: 'cajal',
      action: 'startup_dependency_check',
      message: state.dependencies.smtp.probeOk ? 'Teams notification dependency ready' : 'Teams notification dependency detected with warning',
      detail: `${state.dependencies.smtp.mode || 'teams'} ${state.dependencies.smtp.path || ''} ${state.dependencies.smtp.detail || ''}`.trim()
    });
  }
  if (!state.notificationState) state.notificationState = { systemDependencySignal: '', collectorWanPublicIp: {} };
  state.notificationState.systemDependencySignal = systemDependencySignal(state);

  persistLoop(state);
  startSyslogCollectors(state);
  startNetflowCollector(state);
  startSnmpPoller(state);
  startPingPoller(state);
  startPublicServicePoller(state);
  startLocationPingMonitorPoller(state);
  startUptimeSampler(state);
  startCollectorWanPublicIpPoller(state);
  startWanTestPoller(state);
  logEvent(state, {
    classId: 210,
    source: 'system',
    actor: 'cajal',
    action: 'startup_collectors',
    message: 'Telemetry collectors started',
    detail: `storage=${shared.storageBackendActive} syslog=${SYSLOG_UDP_PORT}/${SYSLOG_TCP_PORT} netflow=${NETFLOW_PORT} snmpPollMs=${SNMP_POLL_INTERVAL_MS}`
  });

  setInterval(() => {
    applyFlowStatus(state);
  }, 5000);

  setInterval(() => {
    enforceStorageRetention(state, { persistEventsNow: true })
      .catch((err) => logSystemError('retention.enforce.interval', err));
  }, 10 * 60 * 1000);

  setInterval(() => {
    const now = Date.now();
    for (const [sid, session] of sessions.entries()) {
      if (sessionIsExpired(session, now)) sessions.delete(sid);
    }
    pruneRateLimitBuckets(now);
    for (const [stateToken, createdAt] of shared.oauthState.entries()) {
      if (now - createdAt > 10 * 60 * 1000) shared.oauthState.delete(stateToken);
    }
    for (const [token, setup] of shared.localSetupState.entries()) {
      if (!setup || now - setup.createdAt > LOCAL_SETUP_TTL_MS) shared.localSetupState.delete(token);
    }
    pruneCollectorAgentSessions(state, now);

    // ── Prune flow Maps for deleted sites ──────────────────────────────────────
    const activeSiteIds = new Set(state.sites.map((s) => s.id));
    for (const key of state.syslogWindows.keys()) {
      if (!activeSiteIds.has(key)) state.syslogWindows.delete(key);
    }
    for (const key of state.pingState.keys()) {
      if (!activeSiteIds.has(key)) state.pingState.delete(key);
    }
    for (const key of state.flowState.keys()) {
      const siteId = key.split(':')[0];
      if (!activeSiteIds.has(siteId)) state.flowState.delete(key);
    }
    const netflowCutoff = now - NETFLOW_TOP_WINDOW_MS;
    for (const [siteId, talkers] of state.netflowTalkers.entries()) {
      if (!activeSiteIds.has(siteId)) {
        state.netflowTalkers.delete(siteId);
        continue;
      }
      for (const [ip, series] of talkers.entries()) {
        const recent = series.filter((s) => s.ts >= netflowCutoff);
        if (!recent.length) talkers.delete(ip);
        else talkers.set(ip, recent);
      }
    }
    for (const protocol of ['ping', 'pingSecondary', 'syslog', 'snmp', 'netflow']) {
      const map = state.lastSeen[protocol];
      if (!map) continue;
      for (const key of map.keys()) {
        if (!activeSiteIds.has(key)) map.delete(key);
      }
    }
  }, 60000);

  const { certPem, keyPem, caPem } = shared.sslRuntimeConfig;
  const telemetryLine = `Telemetry listeners: syslog udp:${SYSLOG_UDP_PORT}, syslog tcp:${SYSLOG_TCP_PORT}, netflow udp:${NETFLOW_PORT}`;

  if (certPem && keyPem) {
    // ── HTTPS mode: TLS server + plain-HTTP redirect ─────────────────────────
    const tlsOptions = { cert: certPem, key: keyPem, ...(caPem ? { ca: caPem } : {}) };
    const httpsServer = https.createServer(tlsOptions, createHttpHandler(state));
    httpsServer.requestTimeout = 30000;
    httpsServer.headersTimeout = 10000;
    httpsServer.keepAliveTimeout = 5000;

    const redirectServer = http.createServer((req, res) => {
      const host = String(req.headers.host || '').replace(/:\d+$/, '');
      const portSuffix = HTTPS_PORT === 443 ? '' : `:${HTTPS_PORT}`;
      res.writeHead(301, { 'Location': `https://${host}${portSuffix}${req.url}` });
      res.end();
    });

    installShutdownHandlers(state, httpsServer, redirectServer);

    redirectServer.listen(PORT, () => {
      console.log(`Cajal HTTP redirect: http://localhost:${PORT} → https://localhost:${HTTPS_PORT}`);
    });
    httpsServer.listen(HTTPS_PORT, () => {
      console.log(`Cajal running at https://localhost:${HTTPS_PORT}`);
      console.log(`Storage backend active: ${shared.storageBackendActive}`);
      console.log(telemetryLine);
    });
  } else {
    // ── HTTP mode: no SSL cert configured yet ────────────────────────────────
    const server = http.createServer(createHttpHandler(state));
    server.requestTimeout = 30000;
    server.headersTimeout = 10000;
    server.keepAliveTimeout = 5000;
    installShutdownHandlers(state, server);
    server.listen(PORT, () => {
      console.log(`Cajal running at http://localhost:${PORT} (no SSL cert configured)`);
      console.log(`Storage backend active: ${shared.storageBackendActive}`);
      console.log(telemetryLine);
      if (!FORCE_SECURE_COOKIES) {
        console.log('WARNING: CAJAL_FORCE_SECURE_COOKIES is not enabled. Set CAJAL_FORCE_SECURE_COOKIES=1 if behind an HTTPS reverse proxy.');
      }
    });
  }
}

function setRuntimeSettingsForTests(next = {}) {
  shared.runtimeSettings = { ...shared.runtimeSettings, ...(next || {}) };
  return { ...shared.runtimeSettings };
}

function resetRuntimeSettingsForTests() {
  shared.runtimeSettings = { ...defaultRuntimeSettings };
  return { ...shared.runtimeSettings };
}

function resetConfigIntegrityStateForTests() {
  shared.configIntegrityState = shared.defaultConfigIntegrityState();
  return getConfigIntegrityReport();
}

function resetSecurityStateForTests() {
  rateLimitBuckets.clear();
  loginAccountFailures.clear();
  resetConfigIntegrityStateForTests();
}

module.exports = {
  __test: {
    parseLinesFromBuffer,
    formatPacketPreview,
    matchSiteBySourceIp,
    markNetflowSeen,
    updateSyslogMetrics,
    decaySyslogMetrics,
    formatSysUpTimeTicks,
    parseNetflowV5,
    parseNetflowV9,
    parseIPFIX,
    parseAnyNetflow,
    refreshNetflowTopTalkers,
    normalizeHeartbeatTarget,
    resolveSiteGatewayIp,
    currentHeartbeatFreshWindowMs,
    protocolFlowTimeoutMs,
    deriveSiteStatus,
    applyFlowStatus,
    evaluateFirewallUfwRuleStatus,
    retainedEventsForPolicy,
    getCollectorAgentPresence,
    issueCollectorAgentSession,
    ensureCollectorAgentQueue,
    dequeueCollectorAgentCommandForPoll,
    collectorResultHasUnsupportedCommand,
    collectorManualUpdateLines,
    parseCollectorAgentInstallTimestampMs,
    normalizeCollectorAgentInstallIdentity,
    evaluateCollectorAgentInstallRegistration,
    extractSpeedtestMetricsFromLines,
    extractPublicIpFromLines,
    normalizeCollectorSpeedtestMetrics,
    normalizeCollectorPublicIpMetrics,
    wanTestSlotHourFromTimestamp,
    wanTestSlotLabelFromTimestamp,
    nextWanTestSlotTimestamp,
    normalizeSmtpStarttlsMode,
    normalizeSmtpTransportConfig,
    sanitizeRuntimeSettings,
    localTotpMfaEnabled,
    resolveTotpSecretState,
    normalizeTeamsWebhookUrl,
    teamsWebhookRetryableStatus,
    teamsWebhookRetryDelayMs,
    teamsWebhookRetryableError,
    normalizeApiTokenRole,
    normalizeApiTokenName,
    parseApiTokenScopeList,
    normalizeApiTokenScopes,
    requiredApiTokenScopeForRequest,
    apiTokenHasScope,
    normalizeApiTokenIpAllowlist,
    validateApiTokenAllowlistEntry,
    apiTokenAllowlistContainsIp,
    normalizeApiTokenRecord,
    sanitizeApiTokenSettings,
    apiTokenStatus,
    isApiTokenActive,
    validateApiTokenCreateInput,
    hashApiToken,
    enforceStorageRetention,
    pruneEventsByPolicy,
    validateConfigKeyStrength,
    ensureDefaultLocalUsers,
    factoryResetBaselineUsers,
    sanitizeUserForClient,
    setConfigIntegrityState,
    getConfigIntegrityReport,
    validateSmtpTransportConfig,
    smtpConfigEnabled,
    smtpTransportLabel,
    resolveMailFrom,
    sanitizeMailHeaderValue,
    sanitizeMailAddress,
    buildPlainTextEmailMessage,
    smtpDotStuffMessage,
    parseSmtpResponseLine,
    smtpCapabilitiesFromResponse,
    normalizeWindowsAgentPackageBase64,
    sanitizeWindowsAgentPackageFileName,
    normalizeWindowsAgentPackageSettings,
    windowsAgentPackageForClient,
    isWindowsExeBuffer,
    shellQuoteArg,
    normalizeToolsTerminalLines,
    summarizeChecks,
    RequestValidationError,
    validateRequestPayload,
    badRequestPayload,
    redactSecretsInText,
    redactForLogs,
    normalizeError,
    buildPostgresPoolConfig,
    applySecurityHeaders,
    csrfRequiredForRequest,
    csrfOriginMatchesHost,
    validateCsrfRequest,
    consumeRateLimitToken,
    enforceRateLimitOrSend,
    getLoginAccountLockState,
    recordLoginAccountFailure,
    clearLoginAccountFailures,
    pruneRateLimitBuckets,
    issueSessionCookie,
    clearSessionCookie,
    sessionIsExpired,
    requestIsHttps,
    logSecurityAuditEvent,
    healthStatusFromChecks,
    healthHttpStatusForState,
    buildPublicHealthPayload,
    encryptBackupPayload,
    decryptBackupPayload,
    validateBackupImportPayload,
    generateTotpSecret,
    totpAt,
    verifyTotp,
    createSetupToken,
    consumeSetupToken,
    peekSetupToken,
    webhookRoutePrefixForSite,
    webhookRouteForStatusTransition,
    renderWebhookMessageTemplate,
    isWebhookRouteEnabled,
    deriveSiteStatus,
    setRuntimeSettingsForTests,
    resetRuntimeSettingsForTests,
    resetConfigIntegrityStateForTests,
    resetSecurityStateForTests,
    constants: {
      COLLECTOR_AGENT_SESSION_TTL_MS,
      COLLECTOR_AGENT_COMMAND_LEASE_MS,
      FLOW_TIMEOUT_MS,
      PING_INTERVAL_MS,
      SNMP_POLL_INTERVAL_MS,
      SYSLOG_FLOW_TIMEOUT_MIN_MS,
      NETFLOW_FLOW_TIMEOUT_MIN_MS,
      NETFLOW_TOP_WINDOW_MS,
      SESSION_TTL_MS,
      SESSION_IDLE_TTL_MS
    }
  }
};

if (require.main === module) {
  main().catch((err) => {
    logSystemError('startup.main', err);
    closeStorageBackend()
      .catch(() => {})
      .finally(() => process.exit(1));
  });

  process.on('unhandledRejection', (reason) => {
    logSystemError('process.unhandledRejection', reason);
  });

  process.on('uncaughtException', (err) => {
    logSystemError('process.uncaughtException', err);
    closeStorageBackend()
      .catch(() => {})
      .finally(() => process.exit(1));
  });
}
