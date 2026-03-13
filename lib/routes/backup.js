'use strict';
const { sendJson, ensureAllowed, readRequestBody, badRequestPayload } = require('../http');
const { logEvent, actorName } = require('../events');
const { encryptBackupPayload, decryptBackupPayload, validateBackupImportPayload } = require('../crypto');
const { clone, sanitizeLocationSettings, normalizeImportedSite, persistSites, markSiteDirty } = require('../sites');
const { sanitizeBackupMeta, persistBackupMeta, persistLocationSettings } = require('../settings');
const { smartWriteFile } = require('../storage');
const shared = require('../shared');
const { defaultBackupMeta, DEVICES_FILE } = require('../constants');

function handleBackup({ req, res, url, state, requestUser, requestContext }) {
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
      req.setTimeout(300000); // 5 min for backup import
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

          const SAFE_ID_RE = /^[a-zA-Z0-9_-]+$/;
          const importedSites = importedSitesRaw
            .map((site, idx) => normalizeImportedSite(site, idx, validSectionIds))
            .filter((site) => SAFE_ID_RE.test(site.id));
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
            .filter((d) => d.siteId && siteIds.has(d.siteId) && SAFE_ID_RE.test(d.id));

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

    return false;
}

module.exports = { handleBackup };
