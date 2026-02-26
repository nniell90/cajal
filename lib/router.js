'use strict';
const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const { URL } = require('url');
const crypto = require('crypto');
const QRCode = require('qrcode');

const {
  APP_VERSION,
  PORT,
  SYSLOG_UDP_PORT,
  SYSLOG_TCP_PORT,
  NETFLOW_PORT,
  FLOW_TIMEOUT_MS,
  GLOBAL_DATA_REFRESH_MS,
  ALERT_SILENCE_DURATION_MS,
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
  DATA_RETENTION_DAYS,
  DATA_RETENTION_MS,
  COLLECTOR_AGENT_SESSION_TTL_MS,
  COLLECTOR_AGENT_COMMAND_TIMEOUT_MS,
  COLLECTOR_AGENT_COMMAND_LEASE_MS,
  COLLECTOR_AGENT_POLL_INTERVAL_MS,
  COLLECTOR_AGENT_INSTALL_TIE_EPSILON_MS,
  MAIL_FROM,
  DEFAULT_TEAMS_WEBHOOK_URL,
  DEFAULT_TEAMS_WEBHOOK_TIMEOUT_MS,
  TEAMS_WEBHOOK_MAX_ATTEMPTS,
  TEAMS_WEBHOOK_RETRY_BASE_MS,
  WINDOWS_AGENT_PACKAGE_MAX_BYTES,
  STARTED_AT_MS,
  ENTRA_TENANT_ID,
  ENTRA_CLIENT_ID,
  ENTRA_CLIENT_SECRET,
  ENTRA_REDIRECT_URI,
  ENTRA_SCOPE,
  GITHUB_REPO,
  UPDATE_IMAGE,
  WATCHTOWER_URL,
  WATCHTOWER_TOKEN,
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
  LOCATION_PING_MONITOR_MAX,
} = require('./constants');

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
} = require('./crypto');

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
} = require('./ratelimit');

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
} = require('./session');

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
} = require('./notifications');

const shared = require('./shared');

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
} = require('./smtp');

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
} = require('./tokens');

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
} = require('./logging');

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
} = require('./storage');

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
} = require('./http');

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
} = require('./auth');

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
} = require('./events');

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
} = require('./sites');

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
} = require('./settings');

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
} = require('./telemetry');

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
} = require('./agent');

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
} = require('./health');

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
} = require('./monitoring');

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml'
};

function createHttpHandler(state) {
  return (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
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

    if (req.method === 'GET' && url.pathname === '/api/auth/me') {
      if (
        !enforceRateLimitOrSend(res, {
          key: `status:auth_me:${requestContext.remoteIp || 'unknown'}`,
          max: PUBLIC_STATUS_RATE_LIMIT_MAX,
          windowMs: PUBLIC_STATUS_RATE_LIMIT_WINDOW_MS,
          message: 'Too many auth status requests. Please wait and retry.',
          state,
          actor: actorName(requestUser),
          action: 'auth_status_rate_limited',
          detail: `${requestContext.method} ${requestContext.path} ip=${requestContext.remoteIp || 'unknown'}`,
          source: 'security'
        })
      ) return;

      const runtimePayload = {
        globalDataRefreshMs: shared.runtimeSettings.globalDataRefreshMs,
        globalClockTimeZone: shared.runtimeSettings.globalClockTimeZone,
        globalClockHourMode: shared.runtimeSettings.globalClockHourMode
      };
      if (requestUser?.authenticated) {
        runtimePayload.internalDnsTarget = shared.runtimeSettings.internalDnsTarget || '';
        runtimePayload.localTotpEnabled = Boolean(shared.runtimeSettings.localTotpEnabled);
      }

      if (!requestUser?.authenticated) {
        return sendJson(res, 200, {
          user: { authenticated: false, displayName: 'Guest', email: '', role: 'monitor', provider: 'none' },
          config: {
            enabled: entraConfigured(),
            provider: 'entra'
          },
          runtime: runtimePayload,
          alerting: {
            silenced: false,
            silencedUntil: '',
            silenceRemainingSec: 0
          },
          system: {
            nowMs: Date.now(),
            startedAt: '',
            uptimeSec: 0,
            dependencies: {}
          }
        });
      }

      const silence = getAlertSilenceState(state);
      const configIntegrity = getConfigIntegrityReport();
      return sendJson(res, 200, {
        user: requestUser,
        config: {
          enabled: entraConfigured(),
          provider: 'entra',
          tenantId: shared.ssoRuntimeConfig.tenantId || '',
          clientId: shared.ssoRuntimeConfig.clientId || '',
          redirectUri: shared.ssoRuntimeConfig.redirectUri || '',
          scope: shared.ssoRuntimeConfig.scope || ''
        },
        runtime: runtimePayload,
        alerting: {
          silenced: silence.active,
          silencedUntil: silence.untilMs ? new Date(silence.untilMs).toISOString() : '',
          silenceRemainingSec: silence.remainingSec
        },
        system: {
          nowMs: Date.now(),
          startedAt: new Date(STARTED_AT_MS).toISOString(),
          uptimeSec: Math.max(0, Math.floor(process.uptime())),
          dependencies: {
            snmpget: {
              available: Boolean(state.dependencies?.snmpget?.available),
              path: state.dependencies?.snmpget?.path || '',
              detail: state.dependencies?.snmpget?.detail || ''
            },
            smtp: {
              available: Boolean(state.dependencies?.smtp?.available),
              path: state.dependencies?.smtp?.path || '',
              detail: state.dependencies?.smtp?.detail || '',
              probeOk: state.dependencies?.smtp?.probeOk !== false,
              mode: state.dependencies?.smtp?.mode || ''
            },
            teams: {
              available: Boolean(state.dependencies?.smtp?.available),
              path: state.dependencies?.smtp?.path || '',
              detail: state.dependencies?.smtp?.detail || '',
              probeOk: state.dependencies?.smtp?.probeOk !== false
            }
          },
          configIntegrity
        }
      });
    }

    if (req.method === 'GET' && url.pathname === '/api/help/readme') {
      return fsp.readFile(README_PATH, 'utf8')
        .then((content) => sendJson(res, 200, { content }))
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.help.readme' }, `Failed to load README: ${err.message}`));
    }

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

    if (req.method === 'GET' && url.pathname === '/api/settings/sso') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return sendJson(res, 200, ssoConfigForClient());
    }

    if (req.method === 'PATCH' && url.pathname === '/api/settings/sso') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return readRequestBody(req, {
        allowedKeys: ['tenantId', 'clientId', 'redirectUri', 'scope', 'clientSecret']
      })
        .then(async (body) => {
          const next = { ...shared.ssoRuntimeConfig };
          if (typeof body.tenantId === 'string') next.tenantId = body.tenantId.trim();
          if (typeof body.clientId === 'string') next.clientId = body.clientId.trim();
          if (typeof body.redirectUri === 'string') next.redirectUri = body.redirectUri.trim();
          if (typeof body.scope === 'string') next.scope = body.scope.trim();
          if (typeof body.clientSecret === 'string') {
            const secret = body.clientSecret.trim();
            if (secret && secret !== MASK) next.clientSecret = secret;
            if (!secret) next.clientSecret = '';
          }
          shared.ssoRuntimeConfig = next;
          await persistSsoConfig(shared.ssoRuntimeConfig);
          logEvent(state, {
            classId: 101,
            source: 'settings',
            actor: actorName(requestUser),
            action: 'sso_update',
            message: 'SSO configuration updated'
          });
          logSecurityAuditEvent(state, {
            actor: actorName(requestUser),
            action: 'sso_update',
            message: 'Security configuration updated: SSO',
            detail: 'SSO tenant/client/redirect settings changed',
            source: 'security',
            classId: 101
          });
          return sendJson(res, 200, ssoConfigForClient());
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'GET' && url.pathname === '/api/settings/runtime') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return sendJson(res, 200, sanitizeRuntimeSettings(shared.runtimeSettings));
    }

    if (req.method === 'PATCH' && url.pathname === '/api/settings/runtime') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return readRequestBody(req, {
        allowedKeys: Object.keys(defaultRuntimeSettings)
      })
        .then(async (body) => {
          shared.runtimeSettings = sanitizeRuntimeSettings({ ...shared.runtimeSettings, ...(body || {}) });
          await persistRuntimeSettings(shared.runtimeSettings);
          state.dependencies.smtp = await detectMailDependency();
          updateSystemDependencyNotificationState(state, 'runtime_settings_update');
          await pollPublicServices(state).catch((err) => logSystemError('runtime.public_services.refresh', err));
          logEvent(state, {
            classId: 101,
            source: 'settings',
            actor: actorName(requestUser),
            action: 'runtime_update',
            message: 'Advanced runtime settings updated'
          });
          logSecurityAuditEvent(state, {
            actor: actorName(requestUser),
            action: 'runtime_update',
            message: 'Security/runtime settings updated',
            detail: 'Runtime configuration changed',
            source: 'security',
            classId: 101
          });
          return sendJson(res, 200, shared.runtimeSettings);
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'GET' && url.pathname === '/api/settings/api/tokens') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      const rows = (Array.isArray(state.apiTokens) ? state.apiTokens : []).map((row) => apiTokenForClient(row));
      return sendJson(res, 200, {
        limit: API_TOKEN_MAX_COUNT,
        tokens: rows
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/settings/api/tokens') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      if (
        !enforceRateLimitOrSend(res, {
          key: `api-token-mutate:create:${requestContext.remoteIp || 'unknown'}:${String(requestUser?.email || '').toLowerCase()}`,
          max: API_TOKEN_RATE_LIMIT_MAX,
          windowMs: API_TOKEN_RATE_LIMIT_WINDOW_MS,
          message: 'Too many API token create requests. Please wait and retry.',
          state,
          actor: actorName(requestUser),
          action: 'api_token_create_rate_limited',
          detail: `${requestContext.method} ${requestContext.path} ip=${requestContext.remoteIp || 'unknown'}`
        })
      ) return;
      return readRequestBody(req, {
        allowedKeys: ['name', 'role', 'expiresAt', 'scopes', 'ipAllowlist']
      })
        .then(async (body) => {
          const now = Date.now();
          const activeCount = (Array.isArray(state.apiTokens) ? state.apiTokens : []).filter((row) => isApiTokenActive(row, now)).length;
          if (activeCount >= API_TOKEN_MAX_COUNT) {
            return sendJson(res, 400, { error: `API token limit reached (${API_TOKEN_MAX_COUNT})` });
          }
          const policy = validateApiTokenCreateInput(body, {
            now,
            actorRole: normalizeAccessRole(requestUser?.role)
          });
          if (!policy.ok) {
            return sendJson(res, 400, {
              error: policy.error,
              code: policy.code || 'invalid_api_token_policy',
              field: policy.field || ''
            });
          }
          const name = normalizeApiTokenName(body?.name || '');
          const role = policy.role;
          const scopes = policy.scopes;
          const ipAllowlist = policy.ipAllowlist;
          const expiresAt = policy.expiresAt;

          const plainToken = `cajal_${crypto.randomBytes(24).toString('base64url')}`;
          const createdAt = new Date(now).toISOString();
          const createdBy = actorName(requestUser);
          const tokenRecord = normalizeApiTokenRecord({
            id: `tok_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`,
            name,
            role,
            tokenHash: hashApiToken(plainToken),
            tokenPrefix: plainToken.slice(0, 14),
            createdAt,
            createdBy,
            lastUsedAt: '',
            expiresAt,
            scopes,
            ipAllowlist,
            revokedAt: ''
          });
          saveApiTokenSettingsToState(state, {
            tokens: [tokenRecord, ...(Array.isArray(state.apiTokens) ? state.apiTokens : [])]
          });
          await persistApiTokenSettings({ tokens: state.apiTokens });
          state.apiTokensDirty = false;
          logEvent(state, {
            classId: 101,
            source: 'settings',
            actor: createdBy,
            action: 'api_token_create',
            message: `API token created: ${tokenRecord.name || tokenRecord.id}`,
            detail: `tokenId=${tokenRecord.id} role=${tokenRecord.role} scopes=${tokenRecord.scopes.join(',')} allowlist=${tokenRecord.ipAllowlist.length}`
          });
          logSecurityAuditEvent(state, {
            actor: createdBy,
            action: 'api_token_create',
            message: `Security token created: ${tokenRecord.name || tokenRecord.id}`,
            detail: `tokenId=${tokenRecord.id} role=${tokenRecord.role} scopes=${tokenRecord.scopes.join(',')} allowlist=${tokenRecord.ipAllowlist.length}`,
            source: 'security',
            classId: 101
          });
          return sendJson(res, 201, {
            limit: API_TOKEN_MAX_COUNT,
            token: plainToken,
            tokenRecord: apiTokenForClient(tokenRecord),
            tokens: state.apiTokens.map((row) => apiTokenForClient(row))
          });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'DELETE' && /^\/api\/settings\/api\/tokens\/[^/]+$/.test(url.pathname)) {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      if (
        !enforceRateLimitOrSend(res, {
          key: `api-token-mutate:revoke:${requestContext.remoteIp || 'unknown'}:${String(requestUser?.email || '').toLowerCase()}`,
          max: API_TOKEN_RATE_LIMIT_MAX,
          windowMs: API_TOKEN_RATE_LIMIT_WINDOW_MS,
          message: 'Too many API token revoke requests. Please wait and retry.',
          state,
          actor: actorName(requestUser),
          action: 'api_token_revoke_rate_limited',
          detail: `${requestContext.method} ${requestContext.path} ip=${requestContext.remoteIp || 'unknown'}`
        })
      ) return;
      const match = url.pathname.match(/^\/api\/settings\/api\/tokens\/([^/]+)$/);
      const tokenId = decodeURIComponent(match?.[1] || '').trim();
      if (!tokenId) return sendJson(res, 400, { error: 'Invalid token id' });
      const idx = (Array.isArray(state.apiTokens) ? state.apiTokens : []).findIndex((row) => String(row?.id || '') === tokenId);
      if (idx < 0) return sendJson(res, 404, { error: 'Token not found' });

      const current = normalizeApiTokenRecord(state.apiTokens[idx], state.apiTokens[idx]);
      if (!current.revokedAt) {
        const updated = normalizeApiTokenRecord({
          ...current,
          revokedAt: new Date().toISOString()
        }, current);
        const nextRows = state.apiTokens.slice();
        nextRows[idx] = updated;
        saveApiTokenSettingsToState(state, { tokens: nextRows });
        return persistApiTokenSettings({ tokens: state.apiTokens })
          .then(() => {
            state.apiTokensDirty = false;
            logEvent(state, {
              classId: 101,
              source: 'settings',
              actor: actorName(requestUser),
              action: 'api_token_revoke',
              message: `API token revoked: ${updated.name || updated.id}`,
              detail: `tokenId=${updated.id}`
            });
            logSecurityAuditEvent(state, {
              actor: actorName(requestUser),
              action: 'api_token_revoke',
              message: `Security token revoked: ${updated.name || updated.id}`,
              detail: `tokenId=${updated.id}`,
              source: 'security',
              classId: 101
            });
            return sendJson(res, 200, {
              ok: true,
              limit: API_TOKEN_MAX_COUNT,
              tokens: state.apiTokens.map((row) => apiTokenForClient(row))
            });
          })
          .catch((err) => sendJson(res, 400, badRequestPayload(err)));
      }

      return sendJson(res, 200, {
        ok: true,
        limit: API_TOKEN_MAX_COUNT,
        tokens: state.apiTokens.map((row) => apiTokenForClient(row))
      });
    }

    if (req.method === 'GET' && url.pathname === '/api/settings/agent/windows-package') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return (async () => {
        const uploaded = windowsAgentPackageForClient(await loadWindowsAgentPackageSettings());
        let bundled = {
          available: false,
          fileName: 'cajal-windows-agent.exe',
          sizeBytes: 0,
          updatedAt: ''
        };
        try {
          const stat = await smartStat(WINDOWS_AGENT_EXE_FILE);
          bundled = {
            available: Number(stat?.size || 0) > 0,
            fileName: 'cajal-windows-agent.exe',
            sizeBytes: Number(stat?.size || 0),
            updatedAt: Number(stat?.mtimeMs || 0) > 0 ? new Date(Number(stat.mtimeMs)).toISOString() : ''
          };
        } catch {
          bundled = {
            available: false,
            fileName: 'cajal-windows-agent.exe',
            sizeBytes: 0,
            updatedAt: ''
          };
        }
        return sendJson(res, 200, {
          maxBytes: WINDOWS_AGENT_PACKAGE_MAX_BYTES,
          uploaded,
          bundled
        });
      })().catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'POST' && url.pathname === '/api/settings/agent/windows-package') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return readRequestBody(req, {
        maxBytes: Math.max(2 * 1024 * 1024, Math.ceil(WINDOWS_AGENT_PACKAGE_MAX_BYTES * 1.45)),
        allowedKeys: ['fileDataBase64', 'dataBase64', 'fileName']
      })
        .then(async (body) => {
          const normalizedBase64 = normalizeWindowsAgentPackageBase64(body?.fileDataBase64 || body?.dataBase64 || '');
          if (!normalizedBase64) return sendJson(res, 400, { error: 'fileDataBase64 is required' });
          let payload = null;
          try {
            payload = Buffer.from(normalizedBase64, 'base64');
          } catch {
            payload = null;
          }
          if (!payload?.length) return sendJson(res, 400, { error: 'Decoded package is empty or invalid base64' });
          if (payload.length > WINDOWS_AGENT_PACKAGE_MAX_BYTES) {
            return sendJson(res, 400, { error: `Windows package exceeds max size (${WINDOWS_AGENT_PACKAGE_MAX_BYTES} bytes)` });
          }
          if (!isWindowsExeBuffer(payload)) {
            return sendJson(res, 400, { error: 'Uploaded package is not a valid Windows executable (.exe)' });
          }
          const fileName = sanitizeWindowsAgentPackageFileName(body?.fileName || 'cajal-windows-agent.exe');
          const uploadedAt = new Date().toISOString();
          const record = normalizeWindowsAgentPackageSettings({
            fileName,
            sizeBytes: payload.length,
            uploadedAt,
            sha256: crypto.createHash('sha256').update(payload).digest('hex'),
            dataBase64: payload.toString('base64')
          });
          await persistWindowsAgentPackageSettings(record);
          logEvent(state, {
            classId: 101,
            source: 'settings',
            actor: actorName(requestUser),
            action: 'windows_agent_package_upload',
            message: 'Windows agent executable package uploaded',
            detail: `file=${record.fileName} size=${record.sizeBytes}`
          });
          return sendJson(res, 200, {
            ok: true,
            maxBytes: WINDOWS_AGENT_PACKAGE_MAX_BYTES,
            uploaded: windowsAgentPackageForClient(record)
          });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'DELETE' && url.pathname === '/api/settings/agent/windows-package') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return persistWindowsAgentPackageSettings(defaultWindowsAgentPackageSettings)
        .then(() => {
          logEvent(state, {
            classId: 101,
            source: 'settings',
            actor: actorName(requestUser),
            action: 'windows_agent_package_delete',
            message: 'Uploaded Windows agent executable package removed'
          });
          return sendJson(res, 200, {
            ok: true,
            maxBytes: WINDOWS_AGENT_PACKAGE_MAX_BYTES,
            uploaded: windowsAgentPackageForClient(defaultWindowsAgentPackageSettings)
          });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'GET' && url.pathname === '/api/settings/webhook-routing') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return sendJson(res, 200, {
        sections: webhookSectionCatalogForClient(),
        routes: webhookRoutingForRuntime(shared.runtimeSettings),
        sectionModes: webhookSectionModesForRuntime(shared.runtimeSettings),
        messages: webhookRoutingMessagesForRuntime(shared.runtimeSettings),
        catalog: webhookRouteCatalogForClient()
      });
    }

    if (req.method === 'PATCH' && url.pathname === '/api/settings/webhook-routing') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return readRequestBody(req, {
        allowedKeys: ['routes', 'sectionModes', 'messages']
      })
        .then(async (body) => {
          const patch = (body && typeof body.routes === 'object' && body.routes) ? body.routes : {};
          const sectionModePatch = (body && typeof body.sectionModes === 'object' && body.sectionModes) ? body.sectionModes : {};
          const messagePatch = (body && typeof body.messages === 'object' && body.messages) ? body.messages : {};
          const merged = normalizeWebhookRoutingRules({
            ...webhookRoutingForRuntime(shared.runtimeSettings),
            ...patch
          }, defaultRuntimeSettings.webhookRouting);
          const mergedSectionModes = normalizeWebhookSectionModes({
            ...webhookSectionModesForRuntime(shared.runtimeSettings),
            ...sectionModePatch
          }, defaultRuntimeSettings.webhookSectionModes);
          const mergedMessages = normalizeWebhookRoutingMessages({
            ...webhookRoutingMessagesForRuntime(shared.runtimeSettings),
            ...messagePatch
          }, defaultRuntimeSettings.webhookRoutingMessages);
          shared.runtimeSettings = sanitizeRuntimeSettings({
            ...shared.runtimeSettings,
            webhookRouting: merged,
            webhookSectionModes: mergedSectionModes,
            webhookRoutingMessages: mergedMessages
          });
          await persistRuntimeSettings(shared.runtimeSettings);
          logEvent(state, {
            classId: 101,
            source: 'settings',
            actor: actorName(requestUser),
            action: 'webhook_routing_update',
            message: 'Webhook routing settings updated'
          });
          return sendJson(res, 200, {
            sections: webhookSectionCatalogForClient(),
            routes: webhookRoutingForRuntime(shared.runtimeSettings),
            sectionModes: webhookSectionModesForRuntime(shared.runtimeSettings),
            messages: webhookRoutingMessagesForRuntime(shared.runtimeSettings),
            catalog: webhookRouteCatalogForClient()
          });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'POST' && url.pathname === '/api/settings/webhook-routing/test') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      if (
        !enforceRateLimitOrSend(res, {
          key: `webhook-test:route:${requestContext.remoteIp || 'unknown'}:${String(requestUser?.email || '').toLowerCase()}`,
          max: WEBHOOK_TEST_RATE_LIMIT_MAX,
          windowMs: WEBHOOK_TEST_RATE_LIMIT_WINDOW_MS,
          message: 'Too many webhook test requests. Please wait and retry.',
          state,
          actor: actorName(requestUser),
          action: 'webhook_route_test_rate_limited',
          detail: `${requestContext.method} ${requestContext.path} ip=${requestContext.remoteIp || 'unknown'}`
        })
      ) return;
      return readRequestBody(req, {
        allowedKeys: ['routeId', 'message']
      })
        .then(async (body) => {
          const routeId = String(body?.routeId || '').trim().toLowerCase();
          if (!WEBHOOK_ROUTE_IDS.has(routeId)) {
            return sendJson(res, 400, { error: 'Invalid routeId' });
          }
          const payload = buildWebhookRouteTestPayload(routeId);
          const configuredRouteMessage = webhookRouteMessageForRuntime(routeId, shared.runtimeSettings);
          const messageOverride = String(body?.message || '').trim();
          const group = webhookPayloadGroupForRuntime(shared.runtimeSettings);
          const templateContext = buildWebhookTemplateContextForRouteTest(routeId);
          const messageTemplate = messageOverride || configuredRouteMessage || payload.message;
          const message = renderWebhookMessageTemplate(messageTemplate, templateContext) || payload.message;
          await sendTeamsNotification({
            title: payload.title,
            group,
            message,
            summary: payload.title,
            themeColor: '0076D7'
          });
          logEvent(state, {
            classId: 301,
            source: 'notifications',
            actor: actorName(requestUser),
            action: 'webhook_route_test',
            message: `Webhook route test sent for ${routeId}`
          });
          return sendJson(res, 200, {
            sent: true,
            routeId,
            group,
            detail: `Webhook test posted for ${routeId}.`
          });
        })
        .catch((err) => {
          const payload = badRequestPayload(err, 'Webhook route test failed');
          return sendJson(res, 400, { sent: false, ...payload });
        });
    }

    if (req.method === 'POST' && url.pathname === '/api/settings/teams/test') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      if (
        !enforceRateLimitOrSend(res, {
          key: `webhook-test:teams:${requestContext.remoteIp || 'unknown'}:${String(requestUser?.email || '').toLowerCase()}`,
          max: WEBHOOK_TEST_RATE_LIMIT_MAX,
          windowMs: WEBHOOK_TEST_RATE_LIMIT_WINDOW_MS,
          message: 'Too many Teams test requests. Please wait and retry.',
          state,
          actor: actorName(requestUser),
          action: 'teams_test_rate_limited',
          detail: `${requestContext.method} ${requestContext.path} ip=${requestContext.remoteIp || 'unknown'}`
        })
      ) return;
      return readRequestBody(req, {
        allowedKeys: ['title', 'group', 'message']
      })
        .then(async (body) => {
          const subject = String(body?.title || '').trim() || '[CAJAL TEST] Power Automate webhook';
          const group = String(body?.group || '').trim() || webhookPayloadGroupForRuntime(shared.runtimeSettings);
          const message = String(body?.message || '').trim() || `This is a test webhook payload from CAJAL.\nTimestamp: ${new Date().toISOString()}`;
          await sendTeamsNotification({
            title: subject,
            group,
            message,
            summary: subject,
            themeColor: '0076D7'
          });
          logEvent(state, {
            classId: 301,
            source: 'notifications',
            actor: actorName(requestUser),
            action: 'teams_settings_test',
            message: 'Teams notification test sent from Settings'
          });
          state.dependencies.smtp = await detectMailDependency();
          updateSystemDependencyNotificationState(state, 'teams_settings_test');
          return sendJson(res, 200, { sent: true, detail: 'Teams notification posted.' });
        })
        .catch((err) => {
          const payload = badRequestPayload(err, 'Teams test failed');
          return sendJson(res, 400, { sent: false, ...payload });
        });
    }

    if (req.method === 'GET' && url.pathname === '/api/settings/ssl') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return sendJson(res, 200, sslConfigForClient());
    }

    if (req.method === 'PATCH' && url.pathname === '/api/settings/ssl') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return readRequestBody(req, {
        allowedKeys: ['certPem', 'keyPem', 'caPem']
      })
        .then(async (body) => {
          const next = { ...shared.sslRuntimeConfig };
          const updateField = (key) => {
            if (typeof body[key] !== 'string') return;
            const value = body[key].trim();
            if (!value || value === MASK) return;
            next[key] = value;
          };
          updateField('certPem');
          updateField('keyPem');
          updateField('caPem');
          shared.sslRuntimeConfig = sanitizeSslSettings(next);
          await persistSslSettings(shared.sslRuntimeConfig);
          logEvent(state, {
            classId: 101,
            source: 'settings',
            actor: actorName(requestUser),
            action: 'ssl_update',
            message: 'SSL certificate settings updated'
          });
          logSecurityAuditEvent(state, {
            actor: actorName(requestUser),
            action: 'ssl_update',
            message: 'Security configuration updated: SSL',
            detail: 'TLS certificate/key settings changed',
            source: 'security',
            classId: 101
          });
          return sendJson(res, 200, sslConfigForClient());
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    // ── Version check + update (Watchtower) ─────────────────────────────────────
    if (req.method === 'GET' && url.pathname === '/api/system/version/check') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      if (!GITHUB_REPO) return sendJson(res, 200, { configured: false, current: APP_VERSION });
      const cache = state._versionCheckCache;
      const ONE_HOUR = 60 * 60 * 1000;
      if (cache && cache.fetchedAt && (Date.now() - cache.fetchedAt) < ONE_HOUR) {
        return sendJson(res, 200, cache.value);
      }
      return new Promise((resolve) => {
        const https = require('https');
        const opts = {
          hostname: 'api.github.com',
          path: `/repos/${GITHUB_REPO}/releases/latest`,
          method: 'GET',
          headers: { 'User-Agent': 'Cajal-ICBM', 'Accept': 'application/vnd.github+json' }
        };
        const req2 = https.request(opts, (r) => {
          let body = '';
          r.on('data', (chunk) => { body += chunk; });
          r.on('end', () => {
            try {
              const data = JSON.parse(body);
              const latest = String(data?.tag_name || '').replace(/^v/, '');
              const current = APP_VERSION;
              const updateAvailable = latest && latest !== current;
              const result = {
                configured: true,
                current,
                latest: latest || current,
                updateAvailable,
                releaseUrl: String(data?.html_url || ''),
                releaseName: String(data?.name || data?.tag_name || ''),
                publishedAt: String(data?.published_at || ''),
                image: UPDATE_IMAGE || ''
              };
              state._versionCheckCache = { value: result, fetchedAt: Date.now() };
              resolve(sendJson(res, 200, result));
            } catch {
              resolve(sendJson(res, 502, { error: 'Failed to parse GitHub releases response' }));
            }
          });
        });
        req2.on('error', (err) => {
          resolve(sendJson(res, 502, { error: `GitHub API unreachable: ${err.message}` }));
        });
        req2.setTimeout(8000, () => { req2.destroy(); resolve(sendJson(res, 504, { error: 'GitHub API timeout' })); });
        req2.end();
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
              resolve(sendJson(res, 200, { ok: true, message: 'Update triggered. The container will restart shortly.' }));
            } else {
              resolve(sendJson(res, 502, { error: `Watchtower returned HTTP ${r.statusCode}` }));
            }
          });
        });
        req2.on('error', (err) => {
          resolve(sendJson(res, 502, { error: `Watchtower unreachable: ${err.message}` }));
        });
        req2.setTimeout(10000, () => { req2.destroy(); resolve(sendJson(res, 504, { error: 'Watchtower timeout' })); });
        req2.end();
      });
    }

    if (req.method === 'GET' && url.pathname === '/api/settings/locations') {
      return sendJson(res, 200, sanitizeLocationSettings(shared.locationSettings));
    }

    if (req.method === 'GET' && url.pathname === '/api/settings/error-logs') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      const limit = Math.max(1, Math.min(1000, Number(url.searchParams.get('limit') || 250)));
      return readErrorLogEntries(limit)
        .then((entries) => sendJson(res, 200, { entries }))
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.settings.error_logs' }));
    }

    if (req.method === 'GET' && url.pathname === '/api/settings/diagnostics-logs') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      const limit = Math.max(1, Math.min(2000, Number(url.searchParams.get('limit') || 250)));
      const protocol = String(url.searchParams.get('protocol') || '').trim().toLowerCase();
      const siteId = String(url.searchParams.get('siteId') || '').trim();
      const level = String(url.searchParams.get('level') || '').trim().toLowerCase();
      return readDiagnosticLogEntries(limit, { protocol, siteId, level })
        .then((entries) => sendJson(res, 200, { entries }))
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.settings.diagnostics_logs' }));
    }

    if (req.method === 'DELETE' && url.pathname === '/api/settings/diagnostics-logs') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return clearDiagnosticLogEntries()
        .then(() => sendJson(res, 200, { ok: true }))
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.settings.diagnostics_logs.clear' }));
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

    if (req.method === 'GET' && url.pathname === '/api/settings/storage') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return buildStorageSummary(state)
        .then((payload) => sendJson(res, 200, payload))
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.settings.storage' }));
    }

    if (req.method === 'POST' && url.pathname === '/api/settings/storage/purge-logs') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return buildStorageSummary(state)
        .then((before) => purgeStorageLogs(state).then((after) => ({ before, after })))
        .then(({ before, after }) => sendJson(res, 200, {
          ok: true,
          purgedAt: new Date().toISOString(),
          before,
          after
        }))
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.settings.storage.purge_logs' }));
    }

    if (req.method === 'POST' && url.pathname === '/api/settings/factory-reset') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return readRequestBody(req, {
        allowedKeys: ['confirmText', 'mode']
      })
        .then(async (body) => {
          const confirmText = String(body?.confirmText || '').trim().toUpperCase();
          const mode = String(body?.mode || 'deployment').trim().toLowerCase();
          if (confirmText !== 'FACTORY RESET') {
            return sendJson(res, 400, {
              error: 'Factory reset confirmation phrase is required (type: FACTORY RESET).'
            });
          }
          if (mode !== 'deployment') {
            return sendJson(res, 400, {
              error: 'Unsupported factory reset mode.'
            });
          }
          const summary = await performFactoryResetForDeployment(state, { actor: actorName(requestUser) });
          clearSessionCookie(res, { secure: requestSecure });
          return sendJson(res, 200, {
            ok: true,
            detail: 'Factory reset complete. Baseline deployment state is ready.',
            redirect: '/login.html',
            summary
          });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'GET' && url.pathname === '/api/settings/firewall-check') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return buildFirewallCheck(state)
        .then((payload) => sendJson(res, 200, payload))
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.settings.firewall_check' }));
    }

    if (req.method === 'GET' && url.pathname === '/api/settings/system-health') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return Promise.all(
        [
          ['sites', SITES_FILE],
          ['devices', DEVICES_FILE],
          ['users', USERS_FILE],
          ['events', EVENTS_FILE],
          ['errorLog', ERROR_LOG_FILE],
          ['diagnosticsLog', DIAGNOSTIC_LOG_FILE],
          ['telemetryLog', TELEMETRY_LOG_FILE],
          ['runtime', RUNTIME_FILE],
          ['apiTokens', API_TOKENS_FILE],
          ['locationSettings', LOCATION_SETTINGS_FILE],
          ['backupMeta', BACKUP_META_FILE]
        ].map(async ([name, file]) => {
          try {
            const stat = await smartStat(file);
            return { name, bytes: stat.size, mtime: stat.mtime.toISOString() };
          } catch {
            return { name, bytes: 0, mtime: '' };
          }
        })
      )
        .then((fileStats) => {
          const enabledByProtocol = { syslog: 0, snmp: 0, netflow: 0 };
          const activeByProtocol = { syslog: 0, snmp: 0, netflow: 0 };
          let notifyEnabledSites = 0;
          for (const site of state.sites) {
            for (const protocol of ['syslog', 'snmp', 'netflow']) {
              if (site.monitorConfig?.[protocol]?.enabled) enabledByProtocol[protocol] += 1;
              if (site.telemetry?.[protocol] === true) activeByProtocol[protocol] += 1;
            }
            const notifications = site.notifications || {};
            if (notifications.enabled) {
              notifyEnabledSites += 1;
            }
          }
          const mem = process.memoryUsage();
          const configIntegrity = getConfigIntegrityReport();
          const teamsDependency = {
            available: Boolean(state.dependencies?.smtp?.available),
            path: state.dependencies?.smtp?.path || '',
            detail: state.dependencies?.smtp?.detail || '',
            probeOk: state.dependencies?.smtp?.probeOk !== false,
            mode: state.dependencies?.smtp?.mode || '',
            host: state.dependencies?.smtp?.host || '',
            port: Number(state.dependencies?.smtp?.port || 0),
            secure: Boolean(state.dependencies?.smtp?.secure),
            starttls: state.dependencies?.smtp?.starttls || 'off',
            authEnabled: Boolean(state.dependencies?.smtp?.authEnabled),
            enabledSites: notifyEnabledSites,
            recipients: 0
          };
          return sendJson(res, 200, {
            snmpCli: {
              available: Boolean(state.dependencies?.snmpget?.available),
              path: state.dependencies?.snmpget?.path || '',
              detail: state.dependencies?.snmpget?.detail || ''
            },
            teams: teamsDependency,
            smtp: teamsDependency,
            backup: sanitizeBackupMeta(state.backupMeta || backupMeta || defaultBackupMeta),
            process: {
              pid: process.pid,
              node: process.version,
              platform: process.platform,
              arch: process.arch,
              storageBackend: shared.storageBackendActive,
              startedAt: new Date(STARTED_AT_MS).toISOString(),
              uptimeSec: Math.max(0, Math.floor(process.uptime())),
              rssBytes: mem.rss,
              heapUsedBytes: mem.heapUsed,
              heapTotalBytes: mem.heapTotal
            },
            host: getServerHostInfo(),
            runtime: sanitizeRuntimeSettings(shared.runtimeSettings),
            telemetry: {
              sites: state.sites.length,
              devices: state.devices.length,
              alerts: state.alerts.length,
              events: state.events.length,
              enabledByProtocol,
              activeByProtocol
            },
            listeners: {
              syslogUdpPort: SYSLOG_UDP_PORT,
              syslogTcpPort: SYSLOG_TCP_PORT,
              netflowPort: NETFLOW_PORT
            },
            alerting: {
              ...getAlertSilenceState(state)
            },
            configIntegrity,
            storage: fileStats
          });
        })
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.settings.system_health' }));
    }

    if (req.method === 'PATCH' && url.pathname === '/api/settings/locations') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return readRequestBody(req, {
        allowedKeys: ['companyName', 'internalName', 'customerName', 'sections']
      })
        .then(async (body) => {
          shared.locationSettings = sanitizeLocationSettings({ ...shared.locationSettings, ...(body || {}) });
          await persistLocationSettings(shared.locationSettings);
          pollLocationPingMonitors(state).catch((err) => logSystemError('poller.location_ping_monitors.settings_locations_patch', err));
          logEvent(state, {
            classId: 101,
            source: 'settings',
            actor: actorName(requestUser),
            action: 'location_labels_update',
            message: 'Location section labels updated'
          });
          return sendJson(res, 200, shared.locationSettings);
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'POST' && url.pathname === '/api/settings/locations/sections') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return readRequestBody(req, {
        allowedKeys: ['name']
      })
        .then(async (body) => {
          const name = String(body?.name || '').trim();
          if (!name) return sendJson(res, 400, { error: 'name is required' });
          const settings = sanitizeLocationSettings(shared.locationSettings);
          const baseId = makeSectionId(name);
          let nextId = baseId;
          let idx = 2;
          while (settings.sections.some((s) => s.id === nextId)) {
            nextId = `${baseId}-${idx}`;
            idx += 1;
          }
          settings.sections.push({ id: nextId, name: name.slice(0, 64), address: '', pingMonitors: [] });
          shared.locationSettings = sanitizeLocationSettings(settings);
          await persistLocationSettings(shared.locationSettings);
          pollLocationPingMonitors(state).catch((err) => logSystemError('poller.location_ping_monitors.settings_locations_add_section', err));
          logEvent(state, {
            classId: 101,
            source: 'settings',
            actor: actorName(requestUser),
            action: 'location_section_add',
            message: `Location section added: ${name}`,
            detail: `sectionId=${nextId}`
          });
          return sendJson(res, 201, shared.locationSettings);
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'PATCH' && /^\/api\/settings\/locations\/sections\/[^/]+$/.test(url.pathname)) {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      const match = url.pathname.match(/^\/api\/settings\/locations\/sections\/([^/]+)$/);
      const sectionId = decodeURIComponent(match?.[1] || '').trim().toLowerCase();
      if (!sectionId) return sendJson(res, 400, { error: 'Invalid section path' });
      return readRequestBody(req, {
        allowedKeys: ['name', 'address', 'pingMonitors']
      })
        .then(async (body) => {
          const settings = sanitizeLocationSettings(shared.locationSettings);
          const idx = settings.sections.findIndex((s) => s.id === sectionId);
          if (idx < 0) return sendJson(res, 404, { error: 'Section not found' });
          if (typeof body.name === 'string') settings.sections[idx].name = body.name.trim().slice(0, 64);
          if (typeof body.address === 'string') settings.sections[idx].address = body.address.trim().slice(0, 96);
          if (Object.prototype.hasOwnProperty.call(body || {}, 'pingMonitors')) {
            if (!Array.isArray(body.pingMonitors)) {
              return sendJson(res, 400, { error: 'pingMonitors must be an array' });
            }
            settings.sections[idx].pingMonitors = body.pingMonitors;
          }
          shared.locationSettings = sanitizeLocationSettings(settings);
          await persistLocationSettings(shared.locationSettings);
          pollLocationPingMonitors(state).catch((err) => logSystemError('poller.location_ping_monitors.settings_locations_patch_section', err));
          logEvent(state, {
            classId: 101,
            source: 'settings',
            actor: actorName(requestUser),
            action: 'location_section_update',
            message: `Location section updated: ${sectionId}`
          });
          return sendJson(res, 200, shared.locationSettings);
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'DELETE' && /^\/api\/settings\/locations\/sections\/[^/]+$/.test(url.pathname)) {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      const match = url.pathname.match(/^\/api\/settings\/locations\/sections\/([^/]+)$/);
      const sectionId = decodeURIComponent(match?.[1] || '').trim().toLowerCase();
      if (!sectionId) return sendJson(res, 400, { error: 'Invalid section path' });

      const settings = sanitizeLocationSettings(shared.locationSettings);
      if (settings.sections.length <= 1) {
        return sendJson(res, 400, { error: 'At least one location section is required' });
      }
      const idx = settings.sections.findIndex((s) => s.id === sectionId);
      if (idx < 0) return sendJson(res, 404, { error: 'Section not found' });
      const removed = settings.sections[idx];

      const deletedSiteIds = new Set(
        state.sites
          .filter((s) => String(s.category || '').trim().toLowerCase() === sectionId)
          .map((s) => s.id)
      );
      const siteCount = deletedSiteIds.size;
      const deviceCount = state.devices.filter((d) => deletedSiteIds.has(d.siteId)).length;

      settings.sections.splice(idx, 1);
      shared.locationSettings = sanitizeLocationSettings(settings);
      state.sites = state.sites.filter((s) => String(s.category || '').trim().toLowerCase() !== sectionId);
      state.devices = state.devices.filter((d) => !deletedSiteIds.has(d.siteId));
      state.links = state.links.filter((l) => !deletedSiteIds.has(l.source) && !deletedSiteIds.has(l.target));
      markSiteDirty(state);
      return persistSites(state.sites)
        .then(() => smartWriteFile(DEVICES_FILE, JSON.stringify(state.devices, null, 2), 'utf8'))
        .then(() => persistLocationSettings(shared.locationSettings))
        .then(() => {
          pollLocationPingMonitors(state).catch((err) => logSystemError('poller.location_ping_monitors.settings_locations_delete_section', err));
          state.dirtySites = false;
          logEvent(state, {
            classId: 101,
            source: 'settings',
            actor: actorName(requestUser),
            action: 'location_section_delete',
            message: `Location section deleted: ${removed.name}`,
            detail: `sectionId=${sectionId} sites=${siteCount} devices=${deviceCount}`
          });
          return sendJson(res, 200, {
            ok: true,
            sectionId,
            removedName: removed.name,
            deletedSites: siteCount,
            deletedDevices: deviceCount,
            locationSettings: shared.locationSettings
          });
        })
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.settings.locations.delete_section' }));
    }

    if (req.method === 'POST' && url.pathname === '/api/backup/export') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return readRequestBody(req, {
        allowedKeys: ['password']
      })
        .then(async (body) => {
          const password = String(body?.password || '');
          if (!password) return sendJson(res, 400, { error: 'Backup password is required' });
          const backupData = {
            version: 1,
            exportedAt: new Date().toISOString(),
            locationSettings: sanitizeLocationSettings(shared.locationSettings),
            sites: clone(state.sites),
            devices: clone(state.devices)
          };
          const backup = encryptBackupPayload(backupData, password);
          const dateTag = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
          state.backupMeta = {
            ...sanitizeBackupMeta(state.backupMeta || shared.backupMeta || defaultBackupMeta),
            lastBackupAt: new Date().toISOString(),
            lastBackupBy: actorName(requestUser)
          };
          shared.backupMeta = { ...state.backupMeta };
          await persistBackupMeta(state.backupMeta);
          logEvent(state, {
            classId: 101,
            source: 'backup',
            actor: actorName(requestUser),
            action: 'backup_export',
            message: 'Configuration backup exported'
          });
          return sendJson(res, 200, { filename: `cajal-backup-${dateTag}.cajalbak`, backup });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'POST' && url.pathname === '/api/backup/export/incremental') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return readRequestBody(req, { allowedKeys: ['password'] })
        .then(async (body) => {
          const password = String(body?.password || '');
          if (!password) return sendJson(res, 400, { error: 'Backup password is required' });
          const sinceTs = state.backupMeta?.lastBackupAt || null;
          const sinceMs = sinceTs ? Date.parse(sinceTs) : 0;
          const filterSince = (arr) => sinceMs > 0
            ? arr.filter((item) => !item.updatedAt || Date.parse(item.updatedAt) >= sinceMs)
            : arr;
          const backupData = {
            version: 1,
            type: 'incremental',
            exportedAt: new Date().toISOString(),
            incrementalSince: sinceTs || null,
            locationSettings: sanitizeLocationSettings(shared.locationSettings),
            sites: filterSince(clone(state.sites)),
            devices: filterSince(clone(state.devices))
          };
          const backup = encryptBackupPayload(backupData, password);
          const dateTag = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
          state.backupMeta = {
            ...sanitizeBackupMeta(state.backupMeta || shared.backupMeta || defaultBackupMeta),
            lastBackupAt: new Date().toISOString(),
            lastBackupBy: actorName(requestUser)
          };
          shared.backupMeta = { ...state.backupMeta };
          await persistBackupMeta(state.backupMeta);
          logEvent(state, {
            classId: 101,
            source: 'backup',
            actor: actorName(requestUser),
            action: 'backup_export_incremental',
            message: `Incremental backup exported (since ${sinceTs || 'beginning'})`
          });
          return sendJson(res, 200, {
            filename: `cajal-backup-incremental-${dateTag}.cajalbak`,
            incrementalSince: sinceTs,
            sitesIncluded: backupData.sites.length,
            devicesIncluded: backupData.devices.length,
            backup
          });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'POST' && url.pathname === '/api/backup/import') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return readRequestBody(req, {
        allowedKeys: ['password', 'backup']
      })
        .then(async (body) => {
          const password = String(body?.password || '');
          if (!password) return sendJson(res, 400, { error: 'Backup password is required' });
          const decrypted = decryptBackupPayload(body?.backup, password);
          try { validateBackupImportPayload(decrypted); } catch (validationErr) { return sendJson(res, 400, { error: validationErr.message }); }
          const importedLocationSettings = sanitizeLocationSettings(decrypted?.locationSettings || {});
          const validSectionIds = new Set((importedLocationSettings.sections || []).map((s) => s.id));
          const importedSitesRaw = Array.isArray(decrypted?.sites) ? decrypted.sites : [];
          const importedDevicesRaw = Array.isArray(decrypted?.devices) ? decrypted.devices : [];
          if (!importedSitesRaw.length) return sendJson(res, 400, { error: 'Backup has no sites/devices payload' });

          const importedSites = importedSitesRaw.map((site, idx) => normalizeImportedSite(site, idx, validSectionIds));
          const siteIds = new Set(importedSites.map((s) => s.id));
          const importedDevices = importedDevicesRaw
            .map((d, idx) => ({
              id: String(d?.id || `dev-${Date.now()}-${idx}`).trim(),
              name: String(d?.name || `Device ${idx + 1}`).trim(),
              type: String(d?.type || 'Firewall').trim(),
              siteId: String(d?.siteId || '').trim(),
              ip: String(d?.ip || '').trim(),
              status: String(d?.status || 'down').trim().toLowerCase(),
              cpu: Number(d?.cpu) || 0,
              memory: Number(d?.memory) || 0,
              lastSeen: String(d?.lastSeen || new Date().toISOString())
            }))
            .filter((d) => d.siteId && siteIds.has(d.siteId));

          state.sites = importedSites;
          state.devices = importedDevices;
          shared.locationSettings = importedLocationSettings;
          state.links = [];
          state.alerts = [];
          state.syslogWindows = new Map();
          state.netflowTalkers = new Map();
          state.netflowTemplates = new Map();
          state.flowState = new Map();
          state.pingState = new Map();
          state.wanPingState = new Map();
          state.diagnosticThrottle = new Map();
          state.lastSeen = { ping: new Map(), pingSecondary: new Map(), syslog: new Map(), snmp: new Map(), netflow: new Map() };
          state.backupMeta = {
            ...sanitizeBackupMeta(state.backupMeta || shared.backupMeta || defaultBackupMeta),
            lastRestoreAt: new Date().toISOString(),
            lastRestoreBy: actorName(requestUser)
          };
          shared.backupMeta = { ...state.backupMeta };
          markSiteDirty(state);
          await persistSites(state.sites);
          await smartWriteFile(DEVICES_FILE, JSON.stringify(state.devices, null, 2), 'utf8');
          await persistLocationSettings(shared.locationSettings);
          await persistBackupMeta(state.backupMeta);
          state.dirtySites = false;
          logEvent(state, {
            classId: 101,
            source: 'backup',
            actor: actorName(requestUser),
            action: 'backup_import',
            message: `Configuration backup imported (${state.sites.length} sites)`
          });
          return sendJson(res, 200, {
            ok: true,
            sites: state.sites.length,
            devices: state.devices.length
          });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'POST' && url.pathname === '/api/auth/local/login') {
      if (
        !enforceRateLimitOrSend(res, {
          key: `login:${requestContext.remoteIp || 'unknown'}`,
          max: LOGIN_RATE_LIMIT_MAX,
          windowMs: LOGIN_RATE_LIMIT_WINDOW_MS,
          message: 'Too many login attempts. Please wait and retry.',
          state,
          actor: actorName(requestUser),
          action: 'login_rate_limited',
          detail: `${requestContext.method} ${requestContext.path} ip=${requestContext.remoteIp || 'unknown'}`,
          source: 'auth'
        })
      ) return;
      return readRequestBody(req, {
        allowedKeys: ['email', 'username', 'password', 'totp']
      })
        .then(async (body) => {
          const loginId = String(body.email || body.username || '').trim().toLowerCase();
          const loginAccountState = getLoginAccountLockState(loginId);
          if (loginAccountState.locked) {
            res.setHeader('Retry-After', String(loginAccountState.retryAfterSec));
            logEventThrottled(state, `auth:login_account_locked:${loginId || 'unknown'}`, 30 * 1000, {
              classId: 402,
              source: 'auth',
              actor: loginId || 'unknown-user',
              action: 'login_account_locked',
              message: 'Local login blocked by account lockout',
              detail: `retryAfterSec=${loginAccountState.retryAfterSec}`
            });
            return sendJson(res, 429, { error: 'Too many login attempts. Please wait and retry.', code: 'login_account_locked' });
          }
          const password = String(body.password || '');
          const totp = String(body.totp || '');
          const user = resolveLocalUserByIdentifier(state.users, loginId);
          if (!user) {
            recordLoginAccountFailure(loginId);
            logEvent(state, {
              classId: 402,
              source: 'auth',
              actor: loginId || 'unknown-user',
              action: 'login_failed',
              message: 'Local login failed',
              detail: 'Unknown username'
            });
            return sendJson(res, 401, { error: 'Invalid username or password' });
          }
          const email = user.email;

          if (!verifyPassword(password, user.localAuth || {})) {
            const hasPassword = Boolean(user.localAuth?.passwordHash && user.localAuth?.passwordSalt);
            if (!hasPassword) {
              const setupToken = createSetupToken(email, 'set_password');
              return sendJson(res, 200, { next: 'set_password', setupToken });
            }
            const lock = recordLoginAccountFailure(loginId || email);
            if (lock.locked) {
              res.setHeader('Retry-After', String(lock.retryAfterSec));
              logEvent(state, {
                classId: 402,
                source: 'auth',
                actor: email,
                action: 'login_account_locked',
                message: 'Local login account lockout triggered',
                detail: `retryAfterSec=${lock.retryAfterSec}`
              });
              return sendJson(res, 429, { error: 'Too many login attempts. Please wait and retry.', code: 'login_account_locked' });
            }
            logEvent(state, {
              classId: 402,
              source: 'auth',
              actor: email,
              action: 'login_failed',
              message: 'Local login failed',
              detail: 'Bad password'
            });
            return sendJson(res, 401, { error: 'Invalid username or password' });
          }

          if (!localTotpMfaEnabled()) {
            clearLoginAccountFailures(loginId || email);
            clearLoginAccountFailures(email);
            issueLocalSession(req, res, user);
            await markUserLastLogin(state, email);
            logEvent(state, {
              classId: 401,
              source: 'auth',
              actor: email,
              action: 'login_success',
              message: 'Local login successful',
              detail: 'Password login'
            });
            return sendJson(res, 200, { ok: true });
          }

          const totpState = resolveTotpSecretState(user.localAuth || {});
          if (totpState.state === 'invalid') {
            logEvent(state, {
              classId: 422,
              source: 'auth',
              actor: email,
              action: 'totp_secret_unavailable',
              message: 'Stored TOTP secret is unavailable; re-enrollment required',
              detail: 'Ensure CAJAL_CONFIG_KEY is stable across restarts or reset local TOTP for this user'
            });
            return sendJson(res, 409, {
              error: 'Stored TOTP enrollment is unavailable. Ask an admin to reset local auth (or reset your own TOTP from My Security), then enroll again.',
              code: 'totp_secret_unavailable'
            });
          }
          if (totpState.state === 'enroll') {
            const enrollmentSecret = generateTotpSecret();
            const setupToken = createSetupToken(email, 'enroll_totp', enrollmentSecret);
            const totpPayload = await makeTotpPayload(email, enrollmentSecret, setupToken);
            return sendJson(res, 200, {
              next: 'enroll_totp',
              setupToken,
              ...totpPayload
            });
          }

          if (!totp) {
            return sendJson(res, 200, { next: 'verify_totp' });
          }
          if (!verifyTotp(totpState.secret, totp)) {
            const lock = recordLoginAccountFailure(loginId || email);
            if (lock.locked) {
              res.setHeader('Retry-After', String(lock.retryAfterSec));
              logEvent(state, {
                classId: 402,
                source: 'auth',
                actor: email,
                action: 'login_account_locked',
                message: 'Local login account lockout triggered',
                detail: `retryAfterSec=${lock.retryAfterSec}`
              });
              return sendJson(res, 429, { error: 'Too many login attempts. Please wait and retry.', code: 'login_account_locked' });
            }
            logEvent(state, {
              classId: 402,
              source: 'auth',
              actor: email,
              action: 'totp_failed',
              message: 'TOTP verification failed'
            });
            return sendJson(res, 401, { error: 'Invalid TOTP code' });
          }

          clearLoginAccountFailures(loginId || email);
          clearLoginAccountFailures(email);
          issueLocalSession(req, res, user);
          await markUserLastLogin(state, email);
          logEvent(state, {
            classId: 401,
            source: 'auth',
            actor: email,
            action: 'login_success',
            message: 'Local login successful',
            detail: 'Password + TOTP'
          });
          return sendJson(res, 200, { ok: true });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'POST' && url.pathname === '/api/auth/local/setup-password') {
      return readRequestBody(req, {
        allowedKeys: ['setupToken', 'password']
      })
        .then(async (body) => {
          const setupToken = String(body.setupToken || '');
          const password = String(body.password || '');
          if (password.length < 10) return sendJson(res, 400, { error: 'Password must be at least 10 characters' });
          const setup = consumeSetupToken(setupToken, 'set_password');
          if (!setup) return sendJson(res, 400, { error: 'Invalid or expired setup token' });
          const user = state.users.find((u) => u.email === setup.email);
          if (!user) return sendJson(res, 404, { error: 'User not found' });

          const hashed = hashPassword(password);
          user.localAuth = user.localAuth || {};
          user.localAuth.passwordHash = hashed.hash;
          user.localAuth.passwordSalt = hashed.salt;
          user.localAuth.passwordIterations = hashed.iterations;
          user.localAuth.passwordChangedAt = new Date().toISOString();

          await persistUsers(state.users);
          shared.userRoleDirectory = buildUserRoleDirectory(state.users);
          logEvent(state, {
            classId: 102,
            source: 'users',
            actor: actorName(requestUser),
            action: 'local_password_set',
            message: `Local password set for ${user.email}`
          });

          if (!localTotpMfaEnabled()) {
            shared.localSetupState.delete(setupToken);
            clearLoginAccountFailures(setup.email);
            issueLocalSession(req, res, user);
            await markUserLastLogin(state, user.email);
            logEvent(state, {
              classId: 401,
              source: 'auth',
              actor: user.email,
              action: 'login_success',
              message: 'Local login successful',
              detail: 'Password setup complete'
            });
            return sendJson(res, 200, { ok: true });
          }

          const enrollmentSecret = generateTotpSecret();
          setup.stage = 'enroll_totp';
          setup.secret = enrollmentSecret;
          setup.createdAt = Date.now();
          shared.localSetupState.set(setupToken, setup);
          const totpPayload = await makeTotpPayload(user.email, enrollmentSecret, setupToken);
          return sendJson(res, 200, {
            next: 'enroll_totp',
            setupToken,
            ...totpPayload
          });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'GET' && url.pathname === '/api/auth/local/totp-qr') {
      const setupToken = String(url.searchParams.get('setupToken') || '');
      const setup = peekSetupToken(setupToken, 'enroll_totp');
      if (!setup) return sendJson(res, 404, { error: 'Invalid or expired setup token' });
      const user = state.users.find((u) => u.email === setup.email);
      if (!user) return sendJson(res, 404, { error: 'User not found' });
      const issuer = 'Cajal ICBM';
      const label = `${issuer}:${setup.email}`;
      const otpauthUrl = `otpauth://totp/${encodeURIComponent(label)}?secret=${encodeURIComponent(
        setup.secret
      )}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
      return QRCode.toString(otpauthUrl, { type: 'svg', margin: 1, width: 220 })
        .then((svg) => {
          res.writeHead(200, {
            'Content-Type': 'image/svg+xml; charset=utf-8',
            'Cache-Control': 'no-store',
            'Content-Length': Buffer.byteLength(svg)
          });
          res.end(svg);
        })
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.auth.local.totp_qr' }, `QR generation failed: ${err.message}`));
    }

    if (req.method === 'POST' && url.pathname === '/api/auth/local/verify-totp') {
      if (!localTotpMfaEnabled()) return sendJson(res, 400, { error: 'TOTP verification is disabled' });
      return readRequestBody(req, {
        allowedKeys: ['setupToken', 'totp']
      })
        .then(async (body) => {
          const setupToken = String(body.setupToken || '');
          const totp = String(body.totp || '');
          const setup = consumeSetupToken(setupToken, 'enroll_totp');
          if (!setup) return sendJson(res, 400, { error: 'Invalid or expired setup token' });
          if (!verifyTotp(setup.secret, totp)) return sendJson(res, 401, { error: 'Invalid TOTP code' });
          const user = state.users.find((u) => u.email === setup.email);
          if (!user) return sendJson(res, 404, { error: 'User not found' });

          user.localAuth = user.localAuth || {};
          user.localAuth.totpSecretEncrypted = encryptJson({ secret: setup.secret });
          user.localAuth.totpEnabled = true;
          user.localAuth.totpChangedAt = new Date().toISOString();
          shared.localSetupState.delete(setupToken);

          await persistUsers(state.users);
          shared.userRoleDirectory = buildUserRoleDirectory(state.users);
          clearLoginAccountFailures(user.email);
          issueLocalSession(req, res, user);
          await markUserLastLogin(state, user.email);
          logEvent(state, {
            classId: 103,
            source: 'auth',
            actor: user.email,
            action: 'totp_enrolled',
            message: 'TOTP enrollment completed'
          });
          return sendJson(res, 200, { ok: true });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'POST' && url.pathname === '/api/auth/local/reset-totp') {
      if (!requestUser?.authenticated) return sendJson(res, 401, { error: 'Authentication required' });
      const email = String(requestUser.email || '').trim().toLowerCase();
      if (!email) return sendJson(res, 400, { error: 'Cannot resolve current user' });
      const idx = state.users.findIndex((u) => u.email === email);
      if (idx < 0) return sendJson(res, 404, { error: 'Local user not found' });
      const current = normalizeUserEntry(state.users[idx], state.users[idx]);
      current.localAuth = current.localAuth || {};
      current.localAuth.totpSecretEncrypted = null;
      current.localAuth.totpEnabled = false;
      current.localAuth.totpChangedAt = '';
      state.users[idx] = current;
      return persistUsers(state.users)
        .then(() => {
          shared.userRoleDirectory = buildUserRoleDirectory(state.users);
          logEvent(state, {
            classId: 101,
            source: 'users',
            actor: actorName(requestUser),
            action: 'self_totp_reset',
            message: `User reset own TOTP: ${email}`
          });
          return sendJson(res, 200, { ok: true });
        })
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.auth.local.reset_totp' }));
    }

    if (req.method === 'GET' && url.pathname === '/api/auth/login') {
      if (!entraConfigured()) {
        res.writeHead(302, { Location: '/' });
        return res.end();
      }
      const stateToken = crypto.randomBytes(24).toString('hex');
      shared.oauthState.set(stateToken, Date.now());
      const authUrl = new URL(
        `https://login.microsoftonline.com/${encodeURIComponent(shared.ssoRuntimeConfig.tenantId)}/oauth2/v2.0/authorize`
      );
      authUrl.searchParams.set('client_id', shared.ssoRuntimeConfig.clientId);
      authUrl.searchParams.set('response_type', 'code');
      authUrl.searchParams.set('redirect_uri', shared.ssoRuntimeConfig.redirectUri);
      authUrl.searchParams.set('response_mode', 'query');
      authUrl.searchParams.set('scope', shared.ssoRuntimeConfig.scope);
      authUrl.searchParams.set('state', stateToken);
      res.writeHead(302, { Location: authUrl.toString() });
      return res.end();
    }

    if (req.method === 'GET' && url.pathname === '/api/auth/callback') {
      const stateToken = url.searchParams.get('state') || '';
      const code = url.searchParams.get('code') || '';
      if (!stateToken || !shared.oauthState.has(stateToken)) return sendJson(res, 400, { error: 'Invalid OAuth state' });
      shared.oauthState.delete(stateToken);
      if (!code) return sendJson(res, 400, { error: 'Authorization code missing' });

      const tokenUrl = `https://login.microsoftonline.com/${encodeURIComponent(shared.ssoRuntimeConfig.tenantId)}/oauth2/v2.0/token`;
      const body = new URLSearchParams();
      body.set('client_id', shared.ssoRuntimeConfig.clientId);
      body.set('client_secret', shared.ssoRuntimeConfig.clientSecret);
      body.set('grant_type', 'authorization_code');
      body.set('code', code);
      body.set('redirect_uri', shared.ssoRuntimeConfig.redirectUri);
      body.set('scope', shared.ssoRuntimeConfig.scope);

      return fetch(tokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body
      })
        .then((r) => r.json().then((payload) => ({ ok: r.ok, payload })))
        .then(async ({ ok, payload }) => {
          if (!ok || !payload.id_token) {
            const detail = payload.error_description || payload.error || 'Token exchange failed';
            return sendJson(res, 401, { error: detail });
          }

          const claims = decodeJwtPayload(payload.id_token);
          const email = String(claims.preferred_username || claims.email || '');
          const displayName = String(claims.name || email || 'User');
          const role = mapUserRole(claims);
          const previousSid = String(requestCookies.cajal_sid || '').trim();
          if (previousSid) sessions.delete(previousSid);
          const now = Date.now();
          const sid = crypto.randomBytes(24).toString('hex');
          sessions.set(sid, {
            createdAt: now,
            lastSeenAt: now,
            user: { authenticated: true, displayName, email, role, provider: 'entra' }
          });
          await markUserLastLogin(state, email);
          issueSessionCookie(res, sid, { secure: requestSecure });
          logEvent(state, {
            classId: 401,
            source: 'auth',
            actor: email || 'entra-user',
            action: 'login_success',
            message: 'Entra login successful'
          });
          res.writeHead(302, { Location: '/' });
          return res.end();
        })
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.auth.oauth.callback' }, `OAuth callback failed: ${err.message}`));
    }

    if ((req.method === 'POST' || req.method === 'GET') && url.pathname === '/api/auth/logout') {
      if (requestCookies.cajal_sid) {
        sessions.delete(requestCookies.cajal_sid);
        redisDeleteSession(requestCookies.cajal_sid);
      }
      clearSessionCookie(res, { secure: requestSecure });
      logEvent(state, {
        classId: 401,
        source: 'auth',
        actor: actorName(requestUser),
        action: 'logout',
        message: 'User logged out'
      });
      if (req.method === 'GET') {
        res.writeHead(302, { Location: '/login.html' });
        return res.end();
      }
      return sendJson(res, 200, { ok: true });
    }

    if (req.method === 'GET' && url.pathname === '/api/agent/linux/download') {
      const format = String(url.searchParams.get('format') || '').trim().toLowerCase();
      if (format === 'deb') {
        return buildLinuxAgentDebPackage()
          .then((pkg) => {
            const body = pkg?.body;
            const filename = String(pkg?.fileName || `${LINUX_AGENT_DEB_PACKAGE_NAME}_${LINUX_AGENT_DEB_VERSION}_${LINUX_AGENT_DEB_ARCH}.deb`);
            if (!body?.length) return sendJson(res, 500, { error: 'Linux agent package build produced empty output' });
            res.writeHead(200, {
              'Content-Type': 'application/vnd.debian.binary-package',
              'Content-Disposition': `attachment; filename="${filename}"`,
              'Content-Length': body.length,
              'X-Content-SHA256': crypto.createHash('sha256').update(body).digest('hex')
            });
            return res.end(body);
          })
          .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.agent.linux.download.deb' }, `Failed to build Linux agent .deb: ${err.message}`));
      }

      return smartReadFile(LINUX_AGENT_SCRIPT_FILE, 'utf8')
        .then((script) => {
          const filename = 'cajal-linux-agent.py';
          const body = String(script || '');
          res.writeHead(200, {
            'Content-Type': 'text/x-python; charset=utf-8',
            'Content-Disposition': `attachment; filename="${filename}"`,
            'Content-Length': Buffer.byteLength(body),
            'X-Content-SHA256': crypto.createHash('sha256').update(Buffer.from(body)).digest('hex')
          });
          return res.end(body);
        })
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.agent.linux.download' }, `Failed to load Linux agent script: ${err.message}`));
    }

    if (req.method === 'GET' && url.pathname === '/api/agent/windows/download') {
      const requestedFormat = String(url.searchParams.get('format') || '').trim().toLowerCase();
      if (requestedFormat === 'exe') {
        return (async () => {
          let payload = null;
          let fileName = 'cajal-windows-agent.exe';
          try {
            const bundled = await smartReadFile(WINDOWS_AGENT_EXE_FILE);
            const bundledPayload = Buffer.isBuffer(bundled) ? bundled : Buffer.from(bundled);
            if (bundledPayload.length > 0 && isWindowsExeBuffer(bundledPayload)) {
              payload = bundledPayload;
            }
          } catch (err) {
            if (String(err?.code || '').trim().toUpperCase() !== 'ENOENT') {
              throw err;
            }
          }

          if (!payload) {
            const uploadedPackage = await loadWindowsAgentPackageSettings();
            const uploadedPayload = decodeWindowsAgentPackageBuffer(uploadedPackage);
            if (uploadedPayload?.length) {
              payload = uploadedPayload;
              fileName = sanitizeWindowsAgentPackageFileName(uploadedPackage.fileName || fileName);
            }
          }

          if (!payload?.length) {
            return sendJson(res, 404, {
              error: 'Windows .exe package not available on this server. Upload one in Settings > API or download ?format=ps1 instead.'
            });
          }

          res.writeHead(200, {
            'Content-Type': 'application/octet-stream',
            'Content-Disposition': `attachment; filename="${fileName}"`,
            'Content-Length': payload.length,
            'X-Content-SHA256': crypto.createHash('sha256').update(payload).digest('hex')
          });
          return res.end(payload);
        })()
          .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.agent.windows.download.exe' }, `Failed to load Windows agent executable: ${err.message}`));
      }

      return smartReadFile(WINDOWS_AGENT_SCRIPT_FILE, 'utf8')
        .then((script) => {
          const body = String(script || '');
          res.writeHead(200, {
            'Content-Type': 'text/plain; charset=utf-8',
            'Content-Disposition': `attachment; filename="${WINDOWS_AGENT_SCRIPT_FILENAME}"`,
            'Content-Length': Buffer.byteLength(body),
            'X-Content-SHA256': crypto.createHash('sha256').update(Buffer.from(body)).digest('hex')
          });
          return res.end(body);
        })
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.agent.windows.download.ps1' }, `Failed to load Windows agent script: ${err.message}`));
    }

    if (req.method === 'GET' && url.pathname === '/api/agent/collectors') {
      const collectors = state.sites
        .filter((site) => normalizeRole(site?.role) === 'collector')
        .map((site) => ({
          id: String(site?.id || '').trim(),
          name: String(site?.name || site?.id || '').trim() || 'Collector',
          role: 'collector',
          agentPasswordSet: collectorAgentPasswordConfigured(site)
        }))
        .filter((row) => row.id)
        .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));
      return sendJson(res, 200, {
        ok: true,
        serverTime: new Date().toISOString(),
        collectors
      });
    }

    if (req.method === 'POST' && url.pathname === '/api/agent/register') {
      return readRequestBody(req, {
        allowedKeys: ['siteId', 'password', 'agent']
      })
        .then((body) => {
          const siteId = String(body?.siteId || '').trim();
          const password = String(body?.password || '');
          const agent = body?.agent && typeof body.agent === 'object' ? body.agent : {};
          if (!siteId || !password) return sendJson(res, 400, { error: 'siteId and password are required' });
          const site = state.sites.find((row) => row.id === siteId);
          if (!site) return sendJson(res, 404, { error: 'Site not found' });
          if (normalizeRole(site.role) !== 'collector') return sendJson(res, 409, { error: 'Site role is not collector' });
          if (!collectorAgentPasswordConfigured(site)) {
            return sendJson(res, 409, { error: 'Collector agent password is not configured for this site' });
          }
          const auth = normalizeCollectorAgentAuth(site.collector?.agentAuth || {}, {});
          if (!verifyPassword(password, auth)) {
            return sendJson(res, 401, { error: 'Collector agent authentication failed' });
          }
          const installCheck = evaluateCollectorAgentInstallRegistration(site, {
            installId: agent?.installId ?? agent?.install_id,
            installedAt: agent?.installedAt ?? agent?.installed_at ?? agent?.installedAtMs ?? agent?.installed_at_ms
          });
          if (!installCheck.allowed) {
            return sendJson(res, 409, {
              error: 'A newer collector agent install is already active for this site. Re-run cajal-agent-setup on the intended host.'
            });
          }

          const remoteIp = String(req.socket?.remoteAddress || '').replace('::ffff:', '');
          const session = issueCollectorAgentSession(state, site, agent, remoteIp);
          const installLockUpdated = updateCollectorAgentInstallLock(site, installCheck.incoming, Date.now());
          if (installLockUpdated) markSiteDirty(state);
          const installDetail = installCheck.incoming?.installedAt
            ? ` installAt=${installCheck.incoming.installedAt}${installCheck.incoming.installId ? ` installId=${installCheck.incoming.installId}` : ''}`
            : '';
          logSiteEvent(state, site, {
            classId: 323,
            source: 'collector',
            actor: 'collector-agent',
            action: 'agent_register',
            message: `Collector agent registered for ${site.name}`,
            detail: `host=${session?.hostname || 'unknown'} ip=${remoteIp || 'unknown'}${installDetail}`
          });
          notifyCollectorAgentState(
            state,
            site,
            'collector_agent_online',
            'down',
            'up',
            'collector_agent_register',
            'Collector agent registered successfully.',
            session
          );
          return sendJson(res, 200, {
            ok: true,
            token: session.token,
            siteId,
            pollIntervalMs: COLLECTOR_AGENT_POLL_INTERVAL_MS,
            sessionTtlMs: COLLECTOR_AGENT_SESSION_TTL_MS
          });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'POST' && url.pathname === '/api/agent/poll') {
      return readRequestBody(req, {
        allowedKeys: ['token']
      })
        .then((body) => {
          const token = String(body?.token || '').trim();
          const session = getCollectorAgentSession(state, token);
          if (!session) return sendJson(res, 401, { error: 'Invalid or expired agent session' });
          touchCollectorAgentSession(state, session);
          const site = state.sites.find((row) => row.id === session.siteId);
          if (!site) return sendJson(res, 404, { error: 'Site not found' });
          const command = dequeueCollectorAgentCommandForPoll(state, session.siteId);
          return sendJson(res, 200, {
            ok: true,
            pollIntervalMs: COLLECTOR_AGENT_POLL_INTERVAL_MS,
            command: command
              ? {
                id: command.id,
                command: command.command,
                issuedAt: new Date().toISOString()
              }
              : null
          });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'POST' && url.pathname === '/api/agent/result') {
      return readRequestBody(req, {
        allowedKeys: ['token', 'commandId', 'ok', 'exitCode', 'lines', 'output', 'message', 'metrics']
      })
        .then((body) => {
          const token = String(body?.token || '').trim();
          const commandId = String(body?.commandId || '').trim();
          const ok = Boolean(body?.ok);
          const exitCodeRaw = Number(body?.exitCode);
          const exitCode = Number.isFinite(exitCodeRaw) ? exitCodeRaw : (ok ? 0 : 1);
          const linesRaw = Array.isArray(body?.lines) ? body.lines : [body?.output || body?.message || ''];
          const lines = normalizeToolsTerminalLines(linesRaw);
          const session = getCollectorAgentSession(state, token);
          if (!session) return sendJson(res, 401, { error: 'Invalid or expired agent session' });
          touchCollectorAgentSession(state, session);
          if (!commandId) return sendJson(res, 400, { error: 'commandId is required' });

          const inputMetrics = body?.metrics && typeof body.metrics === 'object' ? body.metrics : {};
          const speed = inputMetrics.speedtest && typeof inputMetrics.speedtest === 'object' ? inputMetrics.speedtest : null;
          const metrics = {};
          const directPublicIpRaw = String(inputMetrics.publicIp || '').trim();
          if (net.isIP(directPublicIpRaw)) metrics.publicIp = directPublicIpRaw;
          if (speed) {
            const down = Number(speed.downloadMbps);
            const up = Number(speed.uploadMbps);
            const latency = Number(speed.latencyMs);
            const publicIpRaw = String(speed.publicIp || '').trim();
            metrics.speedtest = {
              downloadMbps: Number.isFinite(down) ? down : null,
              uploadMbps: Number.isFinite(up) ? up : null,
              latencyMs: Number.isFinite(latency) ? latency : null,
              target: String(speed.target || '').trim(),
              publicIp: net.isIP(publicIpRaw) ? publicIpRaw : ''
            };
          }

          const resolved = resolveCollectorCommandWaiter(state, session.siteId, commandId, {
            ok,
            exitCode,
            lines,
            metrics
          });
          if (!resolved) {
            return sendJson(res, 404, { error: 'Unknown or expired command id' });
          }
          return sendJson(res, 200, { ok: true });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    const publicPaths = new Set(['/login.html', '/login.js', '/styles.css']);
    const publicApis = new Set(['/api/auth/me', '/api/auth/local/login', '/api/health']);
    if (!requestUser.authenticated) {
      if (publicPaths.has(url.pathname) || publicApis.has(url.pathname)) {
        // allow
      } else if (url.pathname.startsWith('/api/')) {
        return sendJson(res, 401, { error: 'Authentication required' });
      } else {
        res.writeHead(302, { Location: '/login.html' });
        return res.end();
      }
    } else if (req.method === 'GET' && url.pathname === '/login.html') {
      res.writeHead(302, { Location: '/' });
      return res.end();
    }

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

    if (req.method === 'GET' && url.pathname === '/api/summary') {
      return sendJson(res, 200, summarize(state.devices, state.alerts));
    }

    if (req.method === 'GET' && url.pathname === '/api/public-services') {
      return sendJson(res, 200, {
        services: Array.isArray(state.publicServices) ? state.publicServices : []
      });
    }

    if (req.method === 'GET' && url.pathname === '/api/location-monitors') {
      return sendJson(res, 200, {
        monitors: Array.isArray(state.locationPingMonitors) ? state.locationPingMonitors : []
      });
    }

    if (req.method === 'GET' && url.pathname === '/api/sites') {
      applyFlowStatus(state);
      return sendJson(res, 200, state.sites.map((site) => decorateSiteForClient(site, state)));
    }

    if (req.method === 'POST' && url.pathname === '/api/sites') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return readRequestBody(req, {
        allowedKeys: ['name', 'category']
      })
        .then(async (body) => {
          const name = String(body.name || '').trim();
          if (!name) return sendJson(res, 400, { error: 'name is required' });
          const sections = sanitizeLocationSettings(shared.locationSettings).sections;
          const defaultCategory = sections[0]?.id || 'internal';
          const category = String(body.category || defaultCategory).trim().toLowerCase();
          if (!sections.some((s) => s.id === category)) {
            return sendJson(res, 400, { error: 'category must match an existing location section' });
          }
          const site = createSiteTemplate(name, category);
          state.sites.push(site);
          markSiteDirty(state);
          await persistSites(state.sites);
          state.dirtySites = false;
          logEvent(state, {
            classId: 201,
            source: 'sites',
            actor: actorName(requestUser),
            action: 'site_create',
            message: `Location created: ${site.name}`,
            detail: `category=${site.category}`
          });
          applyFlowStatus(state);
          return sendJson(res, 201, { site: decorateSiteForClient(site, state) });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'DELETE' && /^\/api\/sites\/[^/]+$/.test(url.pathname)) {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      const match = url.pathname.match(/^\/api\/sites\/([^/]+)$/);
      const siteId = decodeURIComponent(match?.[1] || '').trim();
      if (!siteId) return sendJson(res, 400, { error: 'Invalid site path' });
      const idx = state.sites.findIndex((s) => s.id === siteId);
      if (idx < 0) return sendJson(res, 404, { error: 'Site not found' });
      const [removed] = state.sites.splice(idx, 1);
      state.devices = state.devices.filter((d) => d.siteId !== siteId);
      clearCollectorAgentSiteRuntime(state, siteId, 'Site removed');
      markSiteDirty(state);
      return persistSites(state.sites)
        .then(() => smartWriteFile(DEVICES_FILE, JSON.stringify(state.devices, null, 2), 'utf8'))
        .then(() => {
          state.dirtySites = false;
          logEvent(state, {
            classId: 201,
            source: 'sites',
            actor: actorName(requestUser),
            action: 'site_delete',
            message: `Location deleted: ${removed.name}`,
            detail: `siteId=${removed.id}`
          });
          return sendJson(res, 200, { ok: true, siteId });
        })
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.sites.delete' }));
    }

    if (req.method === 'GET' && url.pathname === '/api/users') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return sendJson(res, 200, state.users.map((u) => sanitizeUserForClient(u)));
    }

    if (req.method === 'POST' && url.pathname === '/api/users') {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      return readRequestBody(req, {
        allowedKeys: ['email', 'displayName', 'role', 'lastLoginAt', 'localAuth']
      })
        .then(async (body) => {
          const user = normalizeUserEntry(body || {}, {});
          if (!user.email) return sendJson(res, 400, { error: 'email is required' });
          const idx = state.users.findIndex((u) => u.email === user.email);
          if (idx >= 0) {
            state.users[idx] = normalizeUserEntry({ ...state.users[idx], ...user }, state.users[idx]);
            logEvent(state, {
              classId: 101,
              source: 'users',
              actor: actorName(requestUser),
              action: 'user_update',
              message: `User updated: ${user.email}`
            });
          } else {
            state.users.push(user);
            logEvent(state, {
              classId: 101,
              source: 'users',
              actor: actorName(requestUser),
              action: 'user_create',
              message: `User added: ${user.email}`
            });
          }
          await persistUsers(state.users);
          shared.userRoleDirectory = buildUserRoleDirectory(state.users);
          const saved = state.users.find((u) => u.email === user.email) || user;
          return sendJson(res, 200, { user: sanitizeUserForClient(saved) });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'PATCH' && /^\/api\/users\/[^/]+$/.test(url.pathname)) {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      const match = url.pathname.match(/^\/api\/users\/([^/]+)$/);
      const email = decodeURIComponent(match?.[1] || '').trim().toLowerCase();
      if (!email) return sendJson(res, 400, { error: 'Invalid user path' });
      return readRequestBody(req, {
        allowedKeys: ['displayName', 'role']
      })
        .then(async (body) => {
          const idx = state.users.findIndex((u) => u.email === email);
          if (idx < 0) return sendJson(res, 404, { error: 'User not found' });
          const current = normalizeUserEntry(state.users[idx], state.users[idx]);
          const next = normalizeUserEntry({
            email,
            displayName: body.displayName ?? current.displayName,
            role: body.role ?? current.role
          }, current);
          state.users[idx] = next;
          await persistUsers(state.users);
          shared.userRoleDirectory = buildUserRoleDirectory(state.users);
          logEvent(state, {
            classId: 101,
            source: 'users',
            actor: actorName(requestUser),
            action: 'user_role_update',
            message: `User role/profile updated: ${email}`,
            detail: `role=${next.role}`
          });
          return sendJson(res, 200, { user: sanitizeUserForClient(next) });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'DELETE' && /^\/api\/users\/[^/]+$/.test(url.pathname)) {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      const match = url.pathname.match(/^\/api\/users\/([^/]+)$/);
      const email = decodeURIComponent(match?.[1] || '').trim().toLowerCase();
      if (!email) return sendJson(res, 400, { error: 'Invalid user path' });
      if (String(requestUser.email || '').trim().toLowerCase() === email) {
        return sendJson(res, 400, { error: 'You cannot delete your own account' });
      }
      const idx = state.users.findIndex((u) => u.email === email);
      if (idx < 0) return sendJson(res, 404, { error: 'User not found' });
      state.users.splice(idx, 1);
      return persistUsers(state.users)
        .then(() => {
          shared.userRoleDirectory = buildUserRoleDirectory(state.users);
          logEvent(state, {
            classId: 101,
            source: 'users',
            actor: actorName(requestUser),
            action: 'user_delete',
            message: `User deleted: ${email}`
          });
          return sendJson(res, 200, { ok: true, email });
        })
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.users.delete' }));
    }

    if (req.method === 'POST' && /^\/api\/users\/[^/]+\/reset-local$/.test(url.pathname)) {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      const match = url.pathname.match(/^\/api\/users\/([^/]+)\/reset-local$/);
      const email = decodeURIComponent(match?.[1] || '').trim().toLowerCase();
      if (!email) return sendJson(res, 400, { error: 'Invalid user path' });
      return readRequestBody(req, {
        allowedKeys: ['password', 'totp']
      })
        .then(async (body) => {
          const idx = state.users.findIndex((u) => u.email === email);
          if (idx < 0) return sendJson(res, 404, { error: 'User not found' });
          const resetPassword = Boolean(body?.password);
          const resetTotp = Boolean(body?.totp);
          if (!resetPassword && !resetTotp) {
            return sendJson(res, 400, { error: 'Specify password and/or totp reset' });
          }
          const current = normalizeUserEntry(state.users[idx], state.users[idx]);
          current.localAuth = current.localAuth || {};
          if (resetPassword) {
            current.localAuth.passwordHash = '';
            current.localAuth.passwordSalt = '';
            current.localAuth.passwordIterations = PASSWORD_HASH_ITERATIONS;
            current.localAuth.passwordChangedAt = '';
          }
          if (resetTotp) {
            current.localAuth.totpSecretEncrypted = null;
            current.localAuth.totpEnabled = false;
            current.localAuth.totpChangedAt = '';
          }
          state.users[idx] = current;
          await persistUsers(state.users);
          shared.userRoleDirectory = buildUserRoleDirectory(state.users);
          logEvent(state, {
            classId: 101,
            source: 'users',
            actor: actorName(requestUser),
            action: 'user_local_reset',
            message: `Local auth reset: ${email}`,
            detail: `password=${resetPassword} totp=${resetTotp}`
          });
          return sendJson(res, 200, { user: sanitizeUserForClient(current) });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'PATCH' && /^\/api\/sites\/[^/]+\/meta$/.test(url.pathname)) {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      const match = url.pathname.match(/^\/api\/sites\/([^/]+)\/meta$/);
      const siteId = match?.[1];
      if (!siteId) return sendJson(res, 400, { error: 'Invalid site meta path' });

      const site = state.sites.find((s) => s.id === siteId);
      if (!site) return sendJson(res, 404, { error: 'Site not found' });

      return readRequestBody(req, {
        allowedKeys: [
          'name',
          'model',
          'internalIp',
          'dhcpScope',
          'isp1',
          'isp2',
          'role',
          'firewallName',
          'wanIp',
          'wanIp2',
          'heartbeatTarget',
          'heartbeatTarget2'
        ]
      })
        .then((body) => {
          const previousRole = normalizeRole(site.role);
          if (typeof body.name === 'string') site.name = body.name.trim() || site.name;
          if (typeof body.model === 'string') site.model = body.model.trim();
          if (typeof body.internalIp === 'string') site.internalIp = body.internalIp.trim();
          if (typeof body.dhcpScope === 'string') site.dhcpScope = body.dhcpScope.trim();
          if (typeof body.isp1 === 'string') site.isp1 = body.isp1.trim();
          if (typeof body.isp2 === 'string') site.isp2 = body.isp2.trim();
          if (typeof body.role === 'string') {
            const role = body.role.trim().toLowerCase();
            if (['firewall', 'collector', 'other'].includes(role)) site.role = role;
          }
          const nextRole = normalizeRole(site.role);
          if (previousRole !== nextRole && nextRole !== 'collector') {
            clearCollectorAgentSiteRuntime(state, site.id, 'Site role changed from collector');
          }
          site.collector = site.collector || {};
          site.collector.agentAuth = normalizeCollectorAgentAuth(site.collector.agentAuth, {});
          if (typeof body.firewallName === 'string') {
            site.firewall = site.firewall || {};
            site.firewall.name = body.firewallName.trim() || site.firewall.name;
          }
          if (typeof body.wanIp === 'string') {
            site.firewall = site.firewall || {};
            site.firewall.wanIp = body.wanIp.trim();
          }
          if (typeof body.wanIp2 === 'string') {
            site.firewall = site.firewall || {};
            site.firewall.wanIp2 = body.wanIp2.trim();
          }
          if (typeof body.heartbeatTarget === 'string') {
            site.heartbeatTarget = normalizeHeartbeatTarget(body.heartbeatTarget);
          }
          if (typeof body.heartbeatTarget2 === 'string') {
            site.heartbeatTarget2 = normalizeHeartbeatTarget(body.heartbeatTarget2);
          }

          markSiteDirty(state);
          logSiteEvent(state, site, {
            classId: 202,
            source: 'sites',
            actor: actorName(requestUser),
            action: 'site_meta_update',
            message: `Site details updated: ${site.name}`
          });
          return sendJson(res, 200, { siteId, site: decorateSiteForClient(site, state) });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'POST' && /^\/api\/sites\/[^/]+\/collector\/agent\/password$/.test(url.pathname)) {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      const match = url.pathname.match(/^\/api\/sites\/([^/]+)\/collector\/agent\/password$/);
      const siteId = match?.[1];
      if (!siteId) return sendJson(res, 400, { error: 'Invalid collector agent password path' });
      const site = state.sites.find((s) => s.id === siteId);
      if (!site) return sendJson(res, 404, { error: 'Site not found' });
      if (normalizeRole(site.role) !== 'collector') return sendJson(res, 409, { error: 'Site role must be collector' });

      return readRequestBody(req, {
        allowedKeys: ['password']
      })
        .then((body) => {
          const password = String(body?.password || '');
          if (password.length < 8) return sendJson(res, 400, { error: 'Password must be at least 8 characters' });
          if (password.length > 256) return sendJson(res, 400, { error: 'Password is too long' });
          const hashed = hashPassword(password);
          site.collector = site.collector || {};
          site.collector.agentAuth = normalizeCollectorAgentAuth({
            passwordHash: hashed.hash,
            passwordSalt: hashed.salt,
            passwordIterations: hashed.iterations,
            passwordChangedAt: new Date().toISOString()
          }, site.collector.agentAuth || {});
          clearCollectorAgentSiteRuntime(state, site.id, 'Collector agent password changed');
          markSiteDirty(state);
          logSiteEvent(state, site, {
            classId: 203,
            source: 'collector',
            actor: actorName(requestUser),
            action: 'collector_agent_password_update',
            message: `Collector agent password updated for ${site.name}`
          });
          const origin = requestOriginFromHeaders(req, url) || `http://localhost:${PORT}`;
          const linuxDownloadUrl = `${origin}/api/agent/linux/download?format=deb`;
          const windowsDownloadUrl = `${origin}/api/agent/windows/download?format=ps1`;
          const windowsDownloadUrlExe = `${origin}/api/agent/windows/download?format=exe`;
          const setupPrefillCommand = `sudo cajal-agent-setup --server ${shellQuoteArg(origin)} --site ${shellQuoteArg(site.id)}`;
          const quickEnroll = [
            `curl -fsSL ${linuxDownloadUrl} -o ${LINUX_AGENT_DEB_PACKAGE_NAME}.deb`,
            `sudo dpkg -i ./${LINUX_AGENT_DEB_PACKAGE_NAME}.deb || sudo apt-get -f install -y`,
            setupPrefillCommand,
            'sudo cajal-connect-test',
            `sudo systemctl enable --now ${LINUX_AGENT_SERVICE_NAME}`
          ];
          const windowsQuickEnroll = [
            `powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -UseBasicParsing '${windowsDownloadUrlExe}' -OutFile 'cajal-windows-agent.exe'"`,
            `powershell -NoProfile -ExecutionPolicy Bypass -Command "& .\\cajal-windows-agent.exe -Server '${origin}' -Site '${site.id}' -Password '<agent-password>'"`,
            `Fallback script if .exe is unavailable: Invoke-WebRequest -UseBasicParsing '${windowsDownloadUrl}' -OutFile '${WINDOWS_AGENT_DOWNLOAD_FILENAME}'`,
            `Fallback run: powershell -NoProfile -ExecutionPolicy Bypass -File .\\${WINDOWS_AGENT_DOWNLOAD_FILENAME} -Server '${origin}' -Site '${site.id}' -Password '<agent-password>'`,
            'Optional (run at startup): register this command in Task Scheduler as SYSTEM with highest privileges.',
            `Windows download endpoints: exe=${windowsDownloadUrlExe} ps1=${windowsDownloadUrl}`
          ];
          return sendJson(res, 200, {
            ok: true,
            siteId: site.id,
            agentPasswordSet: true,
            linux: {
              downloadUrl: linuxDownloadUrl,
              setupPrefillCommand,
              quickEnroll,
              installSteps: [
                ...quickEnroll,
                'Installer can open a local setup window; use it if preferred.',
                'Run connectivity diagnostics: cajal-connect-test',
                `sudo systemctl status ${LINUX_AGENT_SERVICE_NAME} --no-pager`
              ]
            },
            windows: {
              downloadUrl: windowsDownloadUrl,
              exeDownloadUrl: windowsDownloadUrlExe,
              quickEnroll: windowsQuickEnroll,
              installSteps: [
                ...windowsQuickEnroll,
                "Use the same password you set in this dialog for -Password.",
                'Verify registration in UI: collector should show Agent Status Connected.'
              ]
            }
          });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'POST' && /^\/api\/sites\/[^/]+\/collector\/agent\/update$/.test(url.pathname)) {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      const match = url.pathname.match(/^\/api\/sites\/([^/]+)\/collector\/agent\/update$/);
      const siteId = match?.[1];
      if (!siteId) return sendJson(res, 400, { error: 'Invalid collector agent update path' });
      const site = state.sites.find((s) => s.id === siteId);
      if (!site) return sendJson(res, 404, { error: 'Site not found' });
      if (normalizeRole(site.role) !== 'collector') return sendJson(res, 409, { error: 'Site role must be collector' });

      return readRequestBody(req, {
        allowedKeys: ['downloadUrl', 'targetVersion']
      })
        .then(async (body) => {
          const fallbackOrigin = requestOriginFromHeaders(req, url) || `http://localhost:${PORT}`;
          const requestedDownloadUrl = String(body?.downloadUrl || '').trim();
          const downloadUrl = requestedDownloadUrl || `${fallbackOrigin}/api/agent/linux/download?format=deb`;
          if (!/^https?:\/\/[^ "']+/i.test(downloadUrl)) {
            return sendJson(res, 400, { error: 'Update download URL must start with http:// or https://' });
          }
          const targetVersion = String(body?.targetVersion || LINUX_AGENT_DEB_VERSION || '').trim() || String(LINUX_AGENT_DEB_VERSION || '').trim();
          const quotedUrl = shellQuoteArg(downloadUrl);
          const quotedVersion = shellQuoteArg(targetVersion || 'unknown');
          const command = `update ${quotedUrl} ${quotedVersion}`;
          const result = await runCollectorAgentTerminalCommand(state, site, command);
          const unsupportedUpdate = collectorResultHasUnsupportedCommand(result, 'update');
          const manualUpdateSteps = unsupportedUpdate ? collectorManualUpdateLines(downloadUrl, targetVersion) : [];
          const responseLines = unsupportedUpdate
            ? normalizeToolsTerminalLines([...(result.lines || []), ...manualUpdateSteps])
            : normalizeToolsTerminalLines(result.lines || []);
          const effectiveOk = Boolean(result.ok) && !unsupportedUpdate;

          logSiteEvent(state, site, {
            classId: effectiveOk ? 323 : 423,
            source: 'collector',
            actor: actorName(requestUser),
            action: 'collector_agent_update_push',
            message: `Collector agent update ${effectiveOk ? 'queued' : 'failed'} for ${site.name}`,
            detail: `targetVersion=${targetVersion || 'unknown'} downloadUrl=${downloadUrl}${unsupportedUpdate ? ' legacyAgentUnsupported=true' : ''}`
          });

          return sendJson(res, 200, {
            ok: effectiveOk,
            siteId: site.id,
            command,
            currentVersion: String(getCollectorAgentPresence(state, site.id)?.version || '').trim(),
            targetVersion,
            downloadUrl,
            exitCode: Number(result.exitCode || 0),
            legacyAgentUnsupportedUpdate: unsupportedUpdate,
            manualUpdateSteps,
            lines: responseLines
          });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'PATCH' && /^\/api\/sites\/[^/]+\/monitors\/(syslog|snmp|netflow)$/.test(url.pathname)) {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      const match = url.pathname.match(/^\/api\/sites\/([^/]+)\/monitors\/(syslog|snmp|netflow)$/);
      const siteId = match?.[1];
      const protocol = match?.[2];

      if (!siteId || !protocol) return sendJson(res, 400, { error: 'Invalid monitor path' });
      const site = state.sites.find((s) => s.id === siteId);
      if (!site) return sendJson(res, 404, { error: 'Site not found' });
      if (siteHasMonitorConfigDecryptFailure(site)) {
        return sendJson(res, 409, {
          error: 'Monitor config decrypt failed for this site. Verify CAJAL_CONFIG_KEY and restart before editing SNMP/Syslog/NetFlow settings.'
        });
      }

      return readRequestBody(req, {
        allowedKeys: ['config', 'enabled']
      })
        .then(async (body) => {
          const cfg = site.monitorConfig?.[protocol] || {};
          const merged = mergeConfig(cfg, body.config || {});
          const changedBy = actorName(requestUser);
          merged.enabled = typeof body.enabled === 'boolean' ? body.enabled : Boolean(cfg.enabled);
          merged.lastChanged = new Date().toISOString();
          merged.lastChangedBy = changedBy;

          site.monitorConfig = site.monitorConfig || {};
          site.monitorConfig[protocol] = merged;
          clearMonitorConfigDecryptFailure(site);
          if (!merged.enabled) {
            site.telemetry[protocol] = false;
          }

          markSiteDirty(state);
          logSiteEvent(state, site, {
            classId: 203,
            source: protocol,
            actor: changedBy,
            action: 'monitor_update',
            message: `${protocol.toUpperCase()} config updated for ${site.name}`,
            detail: `enabled=${merged.enabled}`
          });
          let diagnostics = null;
          if (merged.enabled) {
            diagnostics = await runMonitorDiagnostics(state, site, protocol, merged, { runLiveProbe: false });
          }
          await flushDirtyState(state, { forceSites: true });
          return sendJson(res, 200, {
            siteId,
            protocol,
            config: sanitizeSiteForClient(site).monitorConfig[protocol],
            diagnostics
          });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'POST' && /^\/api\/sites\/[^/]+\/monitors\/(syslog|snmp|netflow)\/diagnostics$/.test(url.pathname)) {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      const match = url.pathname.match(/^\/api\/sites\/([^/]+)\/monitors\/(syslog|snmp|netflow)\/diagnostics$/);
      const siteId = match?.[1];
      const protocol = match?.[2];
      if (!siteId || !protocol) return sendJson(res, 400, { error: 'Invalid monitor diagnostics path' });
      const site = state.sites.find((s) => s.id === siteId);
      if (!site) return sendJson(res, 404, { error: 'Site not found' });

      return readRequestBody(req, {
        allowedKeys: ['config', 'enabled']
      })
        .then(async (body) => {
          const baseCfg = site.monitorConfig?.[protocol] || {};
          const testCfg = mergeConfig(baseCfg, body?.config || {});
          if (typeof body?.enabled === 'boolean') testCfg.enabled = body.enabled;
          const diagnostics = await runMonitorDiagnostics(state, site, protocol, testCfg, { runLiveProbe: protocol === 'snmp' });
          logSiteEvent(state, site, {
            classId: diagnostics.ok ? 323 : 423,
            source: protocol,
            actor: actorName(requestUser),
            action: 'monitor_diagnostics',
            message: `${protocol.toUpperCase()} diagnostics ${diagnostics.ok ? 'ok' : 'has failures'} for ${site.name}`,
            detail: diagnostics.summary?.message || ''
          });
          return sendJson(res, 200, diagnostics);
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'POST' && /^\/api\/sites\/[^/]+\/monitors\/snmp\/test$/.test(url.pathname)) {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      const match = url.pathname.match(/^\/api\/sites\/([^/]+)\/monitors\/snmp\/test$/);
      const siteId = match?.[1];
      if (!siteId) return sendJson(res, 400, { error: 'Invalid SNMP test path' });
      const site = state.sites.find((s) => s.id === siteId);
      if (!site) return sendJson(res, 404, { error: 'Site not found' });

      return readRequestBody(req, {
        allowedKeys: ['config', 'enabled']
      })
        .then(async (body) => {
          const baseCfg = site.monitorConfig?.snmp || {};
          const testCfg = mergeConfig(baseCfg, body?.config || {});
          if (!String(testCfg.targetHost || '').trim()) {
            return sendJson(res, 400, { error: 'SNMP targetHost is required for test' });
          }
          if (String(testCfg.version || '2c') !== '3' && !String(testCfg.communityString || '').trim()) {
            return sendJson(res, 400, { error: 'SNMP communityString is required for v1/v2c test' });
          }

          const startedAt = Date.now();
          const ticks = await runSnmpGet(testCfg);
          const durationMs = Date.now() - startedAt;
          const uptime = formatSysUpTimeTicks(ticks);
          logSiteEvent(state, site, {
            classId: 322,
            source: 'snmp',
            actor: actorName(requestUser),
            action: 'snmp_test_ok',
            message: `SNMP test succeeded for ${site.name}`,
            detail: `target=${testCfg.targetHost} version=${testCfg.version || '2c'} uptime=${uptime} durationMs=${durationMs}`
          });
          logTelemetry(state, {
            protocol: 'snmp',
            siteId: site.id,
            siteName: site.name,
            sourceIp: String(testCfg.targetHost || '').trim(),
            transport: 'test',
            action: 'test_ok',
            message: `SNMP test succeeded for ${site.name}`,
            detail: `version=${testCfg.version || '2c'} uptime=${uptime} durationMs=${durationMs}`
          });
          const diagnostics = await runMonitorDiagnostics(state, site, 'snmp', testCfg, { runLiveProbe: false });
          return sendJson(res, 200, {
            ok: true,
            uptime,
            ticks,
            durationMs,
            targetHost: String(testCfg.targetHost || ''),
            version: String(testCfg.version || '2c'),
            diagnostics
          });
        })
        .catch((err) => {
          logSiteEvent(state, site, {
            classId: 422,
            source: 'snmp',
            actor: actorName(requestUser),
            action: 'snmp_test_error',
            message: `SNMP test failed for ${site.name}`,
            detail: err.message
          });
          logTelemetry(state, {
            protocol: 'snmp',
            siteId: site.id,
            siteName: site.name,
            sourceIp: String(site.monitorConfig?.snmp?.targetHost || '').trim(),
            transport: 'test',
            action: 'test_error',
            message: `SNMP test failed for ${site.name}`,
            detail: String(err?.message || err || 'Unknown SNMP test error')
          });
          return sendJson(res, 400, badRequestPayload(err));
        });
    }

    if (req.method === 'POST' && /^\/api\/sites\/[^/]+\/monitors\/syslog\/test$/.test(url.pathname)) {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      const match = url.pathname.match(/^\/api\/sites\/([^/]+)\/monitors\/syslog\/test$/);
      const siteId = match?.[1];
      if (!siteId) return sendJson(res, 400, { error: 'Invalid SYSLOG test path' });
      const site = state.sites.find((s) => s.id === siteId);
      if (!site) return sendJson(res, 404, { error: 'Site not found' });

      return readRequestBody(req, {
        allowedKeys: ['config', 'enabled']
      })
        .then(async (body) => {
          const baseCfg = site.monitorConfig?.syslog || {};
          const testCfg = mergeConfig(baseCfg, body?.config || {});
          const sourceIp = String(testCfg.sourceIp || '').trim();
          if (!sourceIp) return sendJson(res, 400, { error: 'SYSLOG sourceIp is required for test' });

          // Synthetic ingest validates Cajal's event/metrics pipeline without requiring a live device packet.
          updateSyslogMetrics(state, site, Date.now(), sourceIp);
          site.telemetry = site.telemetry || {};
          site.telemetry.syslog = true;
          logSiteEvent(state, site, {
            classId: 320,
            source: 'syslog',
            actor: actorName(requestUser),
            action: 'syslog_test_ok',
            message: `SYSLOG test succeeded for ${site.name}`,
            detail: `sourceIp=${sourceIp} transport=${String(testCfg.protocol || 'udp')} port=${String(testCfg.port || SYSLOG_UDP_PORT)}`
          });
          logTelemetry(state, {
            protocol: 'syslog',
            siteId: site.id,
            siteName: site.name,
            sourceIp,
            transport: String(testCfg.protocol || 'udp'),
            action: 'test_ok',
            message: `SYSLOG test succeeded for ${site.name}`,
            detail: `port=${String(testCfg.port || SYSLOG_UDP_PORT)}`
          });
          const diagnostics = await runMonitorDiagnostics(state, site, 'syslog', testCfg, { runLiveProbe: false });
          return sendJson(res, 200, {
            ok: true,
            sourceIp,
            transport: String(testCfg.protocol || 'udp'),
            port: String(testCfg.port || SYSLOG_UDP_PORT),
            eventsPerSecond: Number(site.metrics?.syslog?.eventsPerSecond || 0),
            diagnostics
          });
        })
        .catch((err) => {
          site.metrics = site.metrics || {};
          site.metrics.syslog = site.metrics.syslog || {};
          site.metrics.syslog.lastError = String(err?.message || err || 'Unknown SYSLOG test error');
          site.metrics.syslog.lastErrorAt = new Date().toISOString();
          markSiteDirty(state);
          logSiteEvent(state, site, {
            classId: 422,
            source: 'syslog',
            actor: actorName(requestUser),
            action: 'syslog_test_error',
            message: `SYSLOG test failed for ${site.name}`,
            detail: err.message
          });
          logTelemetry(state, {
            protocol: 'syslog',
            siteId: site.id,
            siteName: site.name,
            sourceIp: String(site.monitorConfig?.syslog?.sourceIp || '').trim(),
            transport: 'test',
            action: 'test_error',
            message: `SYSLOG test failed for ${site.name}`,
            detail: String(err?.message || err || 'Unknown SYSLOG test error')
          });
          return sendJson(res, 400, badRequestPayload(err));
        });
    }

    if (req.method === 'POST' && /^\/api\/sites\/[^/]+\/monitors\/netflow\/test$/.test(url.pathname)) {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      const match = url.pathname.match(/^\/api\/sites\/([^/]+)\/monitors\/netflow\/test$/);
      const siteId = match?.[1];
      if (!siteId) return sendJson(res, 400, { error: 'Invalid NETFLOW test path' });
      const site = state.sites.find((s) => s.id === siteId);
      if (!site) return sendJson(res, 404, { error: 'Site not found' });

      return readRequestBody(req, {
        allowedKeys: ['config', 'enabled']
      })
        .then(async (body) => {
          const baseCfg = site.monitorConfig?.netflow || {};
          const testCfg = mergeConfig(baseCfg, body?.config || {});
          const sourceIp = String(testCfg.sourceIp || '').trim();
          if (!sourceIp) return sendJson(res, 400, { error: 'NETFLOW sourceIp is required for test' });

          const now = Date.now();
          state.lastSeen.netflow.set(site.id, now);
          site.telemetry = site.telemetry || {};
          site.telemetry.netflow = true;
          site.metrics = site.metrics || {};
          site.metrics.netflow = site.metrics.netflow || {};
          site.metrics.netflow.lastError = '';
          site.metrics.netflow.lastErrorAt = '';
          const talkers = state.netflowTalkers.get(site.id) || new Map();
          const sampleHost = `test-${sourceIp}`;
          const events = talkers.get(sampleHost) || [];
          events.push({ ts: now, upBytes: 150000, downBytes: 100000 });
          talkers.set(sampleHost, events);
          state.netflowTalkers.set(site.id, talkers);
          refreshNetflowTopTalkers(state, site, now);
          markSiteDirty(state);
          logSiteEvent(state, site, {
            classId: 321,
            source: 'netflow',
            actor: actorName(requestUser),
            action: 'netflow_test_ok',
            message: `NETFLOW test succeeded for ${site.name}`,
            detail: `sourceIp=${sourceIp} collectorIp=${String(testCfg.collectorIp || '')} collectorPort=${String(testCfg.collectorPort || '')}`
          });
          logTelemetry(state, {
            protocol: 'netflow',
            siteId: site.id,
            siteName: site.name,
            sourceIp,
            transport: 'test',
            action: 'test_ok',
            message: `NETFLOW test succeeded for ${site.name}`,
            detail: `collectorIp=${String(testCfg.collectorIp || '')} collectorPort=${String(testCfg.collectorPort || '')}`
          });
          const diagnostics = await runMonitorDiagnostics(state, site, 'netflow', testCfg, { runLiveProbe: false });
          return sendJson(res, 200, {
            ok: true,
            sourceIp,
            topTalkers: site.metrics?.netflow?.topTalkers || [],
            diagnostics
          });
        })
        .catch((err) => {
          site.metrics = site.metrics || {};
          site.metrics.netflow = site.metrics.netflow || {};
          site.metrics.netflow.lastError = String(err?.message || err || 'Unknown NETFLOW test error');
          site.metrics.netflow.lastErrorAt = new Date().toISOString();
          markSiteDirty(state);
          logSiteEvent(state, site, {
            classId: 422,
            source: 'netflow',
            actor: actorName(requestUser),
            action: 'netflow_test_error',
            message: `NETFLOW test failed for ${site.name}`,
            detail: err.message
          });
          logTelemetry(state, {
            protocol: 'netflow',
            siteId: site.id,
            siteName: site.name,
            sourceIp: String(site.monitorConfig?.netflow?.sourceIp || '').trim(),
            transport: 'test',
            action: 'test_error',
            message: `NETFLOW test failed for ${site.name}`,
            detail: String(err?.message || err || 'Unknown NETFLOW test error')
          });
          return sendJson(res, 400, badRequestPayload(err));
        });
    }

    if (req.method === 'GET' && /^\/api\/sites\/[^/]+\/netflow\/troublemakers$/.test(url.pathname)) {
      const match = url.pathname.match(/^\/api\/sites\/([^/]+)\/netflow\/troublemakers$/);
      const siteId = match?.[1];
      if (!siteId) return sendJson(res, 400, { error: 'Invalid NETFLOW troublemakers path' });
      const site = state.sites.find((s) => s.id === siteId);
      if (!site) return sendJson(res, 404, { error: 'Site not found' });

      const days = Math.max(1, Math.min(30, Number(url.searchParams.get('days') || 7)));
      return buildNetflowTroublemakersReport(state, site, { days, topPercent: 0.1 })
        .then((report) => sendJson(res, 200, report))
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.sites.netflow.troublemakers', siteId }));
    }

    if (req.method === 'POST' && /^\/api\/sites\/[^/]+\/collector\/terminal$/.test(url.pathname)) {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      const match = url.pathname.match(/^\/api\/sites\/([^/]+)\/collector\/terminal$/);
      const siteId = match?.[1];
      if (!siteId) return sendJson(res, 400, { error: 'Invalid collector terminal path' });
      const site = state.sites.find((s) => s.id === siteId);
      if (!site) return sendJson(res, 404, { error: 'Site not found' });
      if (normalizeRole(site?.role) !== 'collector') return sendJson(res, 409, { error: 'Site role is not collector' });

      return readRequestBody(req, {
        allowedKeys: ['command']
      })
        .then(async (body) => {
          const command = String(body?.command || '').trim();
          const result = await runCollectorTerminalCommand(state, site, command);
          const tokens = parseToolsTerminalTokens(command);
          const cmdName = String(tokens[0] || '').toLowerCase();
          const unsupportedUpdate = cmdName === 'update' && collectorResultHasUnsupportedCommand(result, 'update');
          let manualUpdateSteps = [];
          let responseLines = normalizeToolsTerminalLines(result.lines || []);
          if (unsupportedUpdate) {
            const fallbackOrigin = requestOriginFromHeaders(req, url) || `http://localhost:${PORT}`;
            const requestedDownloadUrl = String(tokens[1] || '').trim();
            const downloadUrl = /^https?:\/\/[^ "'\t\r\n]+$/i.test(requestedDownloadUrl)
              ? requestedDownloadUrl
              : `${fallbackOrigin}/api/agent/linux/download?format=deb`;
            const targetVersion = String(tokens[2] || LINUX_AGENT_DEB_VERSION || '').trim()
              || String(LINUX_AGENT_DEB_VERSION || '').trim();
            manualUpdateSteps = collectorManualUpdateLines(downloadUrl, targetVersion);
            responseLines = normalizeToolsTerminalLines([...responseLines, ...manualUpdateSteps]);
          }
          const clippedCmd = command.length > 140 ? `${command.slice(0, 140)}...` : command;
          logSiteEvent(state, site, {
            classId: result.ok ? 323 : 423,
            source: 'collector',
            actor: actorName(requestUser),
            action: 'collector_terminal_command',
            message: `Collector terminal command ${result.ok ? 'ok' : 'failed'} for ${site.name}`,
            detail: `cmd=${clippedCmd || 'none'} exitCode=${Number(result.exitCode || 0)}`
          });
          return sendJson(res, 200, {
            ok: Boolean(result.ok),
            command,
            exitCode: Number(result.exitCode || 0),
            legacyAgentUnsupportedUpdate: unsupportedUpdate,
            manualUpdateSteps,
            lines: responseLines
          });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'POST' && /^\/api\/sites\/[^/]+\/tools\/terminal$/.test(url.pathname)) {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      const match = url.pathname.match(/^\/api\/sites\/([^/]+)\/tools\/terminal$/);
      const siteId = match?.[1];
      if (!siteId) return sendJson(res, 400, { error: 'Invalid tools terminal path' });
      const site = state.sites.find((s) => s.id === siteId);
      if (!site) return sendJson(res, 404, { error: 'Site not found' });

      return readRequestBody(req, {
        allowedKeys: ['command']
      })
        .then(async (body) => {
          const command = String(body?.command || '').trim();
          const result = await runToolsTerminalCommand(state, site, command);
          const clippedCmd = command.length > 140 ? `${command.slice(0, 140)}...` : command;
          logSiteEvent(state, site, {
            classId: result.ok ? 323 : 423,
            source: 'tools',
            actor: actorName(requestUser),
            action: 'tools_terminal_command',
            message: `Tools terminal command ${result.ok ? 'ok' : 'failed'} for ${site.name}`,
            detail: `cmd=${clippedCmd || 'none'} exitCode=${Number(result.exitCode || 0)}`
          });
          return sendJson(res, 200, {
            ok: Boolean(result.ok),
            command,
            exitCode: Number(result.exitCode || 0),
            lines: normalizeToolsTerminalLines(result.lines || [])
          });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'PATCH' && /^\/api\/sites\/[^/]+\/notifications$/.test(url.pathname)) {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      const match = url.pathname.match(/^\/api\/sites\/([^/]+)\/notifications$/);
      const siteId = match?.[1];
      if (!siteId) return sendJson(res, 400, { error: 'Invalid notifications path' });

      const site = state.sites.find((s) => s.id === siteId);
      if (!site) return sendJson(res, 404, { error: 'Site not found' });

      return readRequestBody(req, {
        allowedKeys: ['enabled', 'recipients']
      })
        .then((body) => {
          const changedBy = actorName(requestUser);
          site.notifications = site.notifications || { enabled: false, recipients: [], lastChanged: null };
          if (typeof body.enabled === 'boolean') {
            site.notifications.enabled = body.enabled;
          }
          if (Array.isArray(body.recipients)) {
            site.notifications.recipients = body.recipients.map((v) => String(v).trim()).filter(Boolean);
          }
          site.notifications.lastChanged = new Date().toISOString();
          site.notifications.lastChangedBy = changedBy;
          markSiteDirty(state);
          logSiteEvent(state, site, {
            classId: 204,
            source: 'notifications',
            actor: changedBy,
            action: 'notification_update',
            message: `Notification settings updated for ${site.name}`,
            detail: `enabled=${site.notifications.enabled} targets=${site.notifications.recipients.length}`
          });
          return sendJson(res, 200, { siteId, notifications: site.notifications });
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'POST' && /^\/api\/sites\/[^/]+\/test-notify$/.test(url.pathname)) {
      if (!ensureAllowed(requestUser, ['admin'])) return sendJson(res, 403, { error: 'Forbidden' });
      if (
        !enforceRateLimitOrSend(res, {
          key: `webhook-test:site:${requestContext.remoteIp || 'unknown'}:${String(requestUser?.email || '').toLowerCase()}`,
          max: WEBHOOK_TEST_RATE_LIMIT_MAX,
          windowMs: WEBHOOK_TEST_RATE_LIMIT_WINDOW_MS,
          message: 'Too many site test notifications. Please wait and retry.',
          state,
          actor: actorName(requestUser),
          action: 'site_test_notify_rate_limited',
          detail: `${requestContext.method} ${requestContext.path} ip=${requestContext.remoteIp || 'unknown'}`
        })
      ) return;
      const match = url.pathname.match(/^\/api\/sites\/([^/]+)\/test-notify$/);
      const siteId = match?.[1];
      if (!siteId) return sendJson(res, 400, { error: 'Invalid test notify path' });

      const site = state.sites.find((s) => s.id === siteId);
      if (!site) return sendJson(res, 404, { error: 'Site not found' });

      if (isAlertingSilenced(state)) {
        return sendJson(res, 200, {
          sent: false,
          simulated: true,
          detail: 'Global alert silence is active; test notification suppressed'
        });
      }

      return dispatchTestNotification(site)
        .then((result) => {
          const alert = {
            id: `test-alert-${Date.now()}`,
            severity: 'critical',
            title: `[TEST] ${site.name} firewall down notification`,
            deviceId: state.devices.find((d) => d.siteId === site.id && d.type === 'Firewall')?.id || null,
            createdAt: new Date().toISOString()
          };
          state.alerts.unshift(alert);
          if (state.alerts.length > 100) state.alerts.length = 100;
          logSiteEvent(state, site, {
            classId: 301,
            source: 'notifications',
            actor: actorName(requestUser),
            action: 'test_notify',
            message: `Test notification triggered for ${site.name}`,
            detail: result.detail || ''
          });
          return sendJson(res, 200, result);
        })
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.sites.test_notify' }));
    }

    if (req.method === 'GET' && url.pathname === '/api/devices') {
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

          const newDevice = {
            id: `dev-${Date.now()}`,
            name: body.name,
            ip: body.ip,
            type: body.type,
            siteId: body.siteId,
            status: 'up',
            cpu: 10,
            memory: 20,
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
          sendJson(res, 201, newDevice);
        })
        .catch((err) => sendJson(res, 400, badRequestPayload(err)));
    }

    if (req.method === 'GET' && url.pathname === '/api/alerts') {
      return sendJson(res, 200, state.alerts);
    }

    if (req.method === 'GET' && url.pathname === '/api/alerts/silence') {
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
      return sendJson(res, 200, {
        nodes: state.devices.map((d) => ({ id: d.id, label: d.name, status: d.status, type: d.type })),
        edges: state.links
      });
    }

    const cleanPath = url.pathname === '/' ? '/index.html' : url.pathname;
    const safePath = path.normalize(cleanPath).replace(/^([.][.][/\\])+/, '');
    const fullPath = path.join(PUBLIC_DIR, safePath);

    if (!fullPath.startsWith(PUBLIC_DIR)) return sendJson(res, 403, { error: 'Forbidden' });

    fs.readFile(fullPath, (err, content) => {
      if (err) return sendJson(res, 404, { error: 'Not found' });
      const ext = path.extname(fullPath);
      const type = MIME_TYPES[ext] || 'application/octet-stream';
      res.writeHead(200, { 'Content-Type': type, 'Content-Length': content.length });
      res.end(content);
    });
    } catch (err) {
      return sendServerError(res, err, { ...requestContext, scope: 'http.request.unhandled' });
    }

  };
}

module.exports = { createHttpHandler };
