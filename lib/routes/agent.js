'use strict';
const crypto = require('crypto');
const net = require('net');
const { sendJson, sendServerError, ensureAllowed, readRequestBody, badRequestPayload } = require('../http');
const { enforceRateLimitOrSend } = require('../ratelimit');
const { logEvent, logSiteEvent, actorName } = require('../events');
const { normalizeRole, decorateSiteForClient, markSiteDirty, persistSites } = require('../sites');
const {
  normalizeCollectorAgentAuth,
  collectorAgentPasswordConfigured,
  normalizeCollectorAgentInstallIdentity,
  evaluateCollectorAgentInstallRegistration,
  updateCollectorAgentInstallLock,
  verifyPassword,
} = require('../auth');
const {
  buildLinuxAgentDebPackage,
  normalizeToolsTerminalLines,
  getCollectorAgentPresence,
  setCollectorAgentPresence,
  collectorSiteById,
  issueCollectorAgentSession,
  getCollectorAgentSession,
  touchCollectorAgentSession,
  dequeueCollectorAgentCommandForPoll,
  resolveCollectorCommandWaiter,
} = require('../agent');
const { notifyCollectorAgentState } = require('../notifications');
const { smartReadFile, smartStat } = require('../storage');
const {
  isWindowsExeBuffer,
} = require('../settings');
const shared = require('../shared');
const {
  APP_VERSION,
  PORT,
  LINUX_AGENT_SCRIPT_FILE,
  LINUX_AGENT_DEB_PACKAGE_NAME,
  LINUX_AGENT_DEB_VERSION,
  LINUX_AGENT_DEB_ARCH,
  WINDOWS_AGENT_SCRIPT_FILE,
  WINDOWS_AGENT_EXE_FILE,
  WINDOWS_AGENT_SCRIPT_FILENAME,
  WINDOWS_AGENT_DOWNLOAD_FILENAME,
  COLLECTOR_AGENT_POLL_INTERVAL_MS,
  COLLECTOR_AGENT_SESSION_TTL_MS,
} = require('../constants');

function handleAgent({ req, res, url, state, requestUser, requestContext }) {
    if (req.method === 'GET' && url.pathname === '/api/agent/linux/download') {
      if (!requestUser?.authenticated) return sendJson(res, 401, { error: 'Authentication required' });
      req.setTimeout(300000); // 5 min for .deb build
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
          .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.agent.linux.download.deb' }));
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
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.agent.linux.download' }));
    }

    if (req.method === 'GET' && url.pathname === '/api/agent/windows/download') {
      if (!requestUser?.authenticated) return sendJson(res, 401, { error: 'Authentication required' });
      const requestedFormat = String(url.searchParams.get('format') || '').trim().toLowerCase();

      // Serve .ps1 only when explicitly requested
      if (requestedFormat === 'ps1') {
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
          .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.agent.windows.download.ps1' }));
      }

      // Default: serve bundled .exe
      return (async () => {
        let payload = null;
        const fileName = 'cajal-windows-agent.exe';
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

        if (!payload?.length) {
          return sendJson(res, 404, {
            error: 'Windows .exe agent not available on this server. Use ?format=ps1 for the PowerShell script.'
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
        .catch((err) => sendServerError(res, err, { ...requestContext, scope: 'api.agent.windows.download.exe' }));
    }

    if (req.method === 'GET' && url.pathname === '/api/agent/collectors') {
      if (!requestUser?.authenticated) return sendJson(res, 401, { error: 'Authentication required' });
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
      const remoteIpForLimit = String(req.socket?.remoteAddress || '').replace('::ffff:', '');
      if (!enforceRateLimitOrSend(res, {
        key: `agent-register:${remoteIpForLimit}`,
        max: 10,
        windowMs: 60000,
        message: 'Too many agent registration attempts. Please wait and retry.',
        state,
        actor: remoteIpForLimit || 'unknown',
        action: 'agent_register_rate_limited',
        detail: `POST /api/agent/register from ${remoteIpForLimit}`,
        source: 'security'
      })) return;
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

    return false;
}

module.exports = { handleAgent };
