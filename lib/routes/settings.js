'use strict';
const fs = require('fs');
const fsp = fs.promises;
const crypto = require('crypto');

const { sendJson, sendServerError, ensureAllowed, readRequestBody, badRequestPayload } = require('../http');
const {
  README_PATH,
  MASK,
  SENSITIVE_FIELDS,
  defaultRuntimeSettings,
  defaultBackupMeta,
  defaultWindowsAgentPackageSettings,
  WINDOWS_AGENT_PACKAGE_MAX_BYTES,
  WINDOWS_AGENT_EXE_FILE,
  API_TOKEN_MAX_COUNT,
  API_TOKEN_RATE_LIMIT_MAX,
  API_TOKEN_RATE_LIMIT_WINDOW_MS,
  WEBHOOK_TEST_RATE_LIMIT_MAX,
  WEBHOOK_TEST_RATE_LIMIT_WINDOW_MS,
  WEBHOOK_ROUTE_IDS,
  SITES_FILE,
  DEVICES_FILE,
  USERS_FILE,
  EVENTS_FILE,
  ERROR_LOG_FILE,
  DIAGNOSTIC_LOG_FILE,
  TELEMETRY_LOG_FILE,
  RUNTIME_FILE,
  API_TOKENS_FILE,
  LOCATION_SETTINGS_FILE,
  BACKUP_META_FILE,
  SYSLOG_UDP_PORT,
  SYSLOG_TCP_PORT,
  NETFLOW_PORT,
  STARTED_AT_MS,
  LOCATION_PING_MONITOR_MAX,
  normalizeWebhookRoutingRules,
  normalizeWebhookSectionModes,
  normalizeWebhookRoutingMessages,
} = require('../constants');

const { enforceRateLimitOrSend } = require('../ratelimit');
const { clearSessionCookie, requestIsHttps } = require('../session');
const {
  getAlertSilenceState,
  sendTeamsNotification,
  webhookPayloadGroupForRuntime,
  webhookRouteMessageForRuntime,
  renderWebhookMessageTemplate,
  updateSystemDependencyNotificationState,
  webhookRoutingForRuntime,
  webhookSectionModesForRuntime,
  webhookRoutingMessagesForRuntime,
  webhookRouteCatalogForClient,
  webhookSectionCatalogForClient,
} = require('../notifications');

const { logEvent, actorName, logSecurityAuditEvent } = require('../events');

const {
  makeSectionId,
  persistSites,
  clone,
  markSiteDirty,
} = require('../sites');

const {
  ssoConfigForClient,
  persistSsoConfig,
  sanitizeRuntimeSettings,
  persistRuntimeSettings,
  loadWindowsAgentPackageSettings,
  persistWindowsAgentPackageSettings,
  sanitizeWindowsAgentPackageFileName,
  normalizeWindowsAgentPackageBase64,
  isWindowsExeBuffer,
  normalizeWindowsAgentPackageSettings,
  windowsAgentPackageForClient,
  sanitizeSslSettings,
  sslConfigForClient,
  persistSslSettings,
  sanitizeLocationSettings,
  persistLocationSettings,
  sanitizeBackupMeta,
} = require('../settings');

const {
  normalizeAccessRole,
  normalizeApiTokenRole,
  normalizeApiTokenName,
  normalizeApiTokenRecord,
  isApiTokenActive,
  apiTokenForClient,
  validateApiTokenCreateInput,
} = require('../tokens');

const { saveApiTokenSettingsToState } = require('../auth');
const { persistApiTokenSettings } = require('../settings');
const { hashApiToken } = require('../crypto');

const { readErrorLogEntries, readDiagnosticLogEntries, clearDiagnosticLogEntries, logSystemError } = require('../logging');
const { smartStat, smartWriteFile, getConfigIntegrityReport } = require('../storage');
const { buildFirewallCheck, buildStorageSummary, purgeStorageLogs, getServerHostInfo } = require('../health');
const { detectMailDependency, pollPublicServices, pollLocationPingMonitors, buildWebhookRouteTestPayload, buildWebhookTemplateContextForRouteTest } = require('../monitoring');
const { performFactoryResetForDeployment } = require('../agent');
const shared = require('../shared');

function handleSettings({ req, res, url, state, requestUser, requestContext }) {
  if (req.method === 'GET' && url.pathname === '/api/help/readme') {
    return fsp.readFile(README_PATH, 'utf8')
      .then((content) => sendJson(res, 200, { content }))
      .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.help.readme' }, `Failed to load README: ${err.message}`));
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

  if (req.method === 'GET' && url.pathname === '/api/settings/locations') {
    if (!requestUser?.authenticated) return sendJson(res, 401, { error: 'Authentication required' });
    return sendJson(res, 200, sanitizeLocationSettings(shared.locationSettings));
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
        const requestSecure = requestIsHttps(req, url);
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
          backup: sanitizeBackupMeta(state.backupMeta || shared.backupMeta || defaultBackupMeta),
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

  return false;
}

module.exports = { handleSettings };
