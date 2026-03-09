'use strict';
const { sendJson, sendServerError, ensureAllowed, readRequestBody, badRequestPayload } = require('../http');
const { enforceRateLimitOrSend } = require('../ratelimit');
const { requestOriginFromHeaders } = require('../session');
const { logEvent, actorName, logSiteEvent } = require('../events');
const {
  applyFlowStatus,
  decorateSiteForClient,
  createSiteTemplate,
  sanitizeSiteForClient,
  normalizeHeartbeatTarget,
  formatSysUpTimeTicks,
  mergeConfig,
  markSiteDirty,
  siteHasMonitorConfigDecryptFailure,
  clearMonitorConfigDecryptFailure,
  flushDirtyState,
  persistSites,
} = require('../sites');
const { normalizeCollectorAgentAuth, hashPassword } = require('../auth');
const {
  clearCollectorAgentSiteRuntime,
  getCollectorAgentPresence,
  shellQuoteArg,
  normalizeToolsTerminalLines,
  parseToolsTerminalTokens,
  collectorResultHasUnsupportedCommand,
  collectorManualUpdateLines,
  runCollectorAgentTerminalCommand,
  runToolsTerminalCommand,
  runCollectorTerminalCommand,
} = require('../agent');
const { runSnmpGet, updateSyslogMetrics, refreshNetflowTopTalkers } = require('../monitoring');
const { runMonitorDiagnostics } = require('../health');
const { normalizeRole, isAlertingSilenced, dispatchTestNotification } = require('../notifications');
const { logTelemetry } = require('../logging');
const { smartWriteFile } = require('../storage');
const { buildNetflowTroublemakersReport } = require('../telemetry');
const { sanitizeLocationSettings } = require('../settings');
const shared = require('../shared');
const {
  PORT,
  SYSLOG_UDP_PORT,
  DEVICES_FILE,
  WEBHOOK_TEST_RATE_LIMIT_MAX,
  WEBHOOK_TEST_RATE_LIMIT_WINDOW_MS,
  LINUX_AGENT_DEB_PACKAGE_NAME,
  LINUX_AGENT_DEB_VERSION,
  LINUX_AGENT_SERVICE_NAME,
  WINDOWS_AGENT_DOWNLOAD_FILENAME,
} = require('../constants');

function handleSites({ req, res, url, state, requestUser, requestContext }) {
  if (req.method === 'GET' && url.pathname === '/api/sites') {
    if (!requestUser?.authenticated) return sendJson(res, 401, { error: 'Authentication required' });
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
    if (!requestUser?.authenticated) return sendJson(res, 401, { error: 'Authentication required' });
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

  return false;
}

module.exports = { handleSites };
