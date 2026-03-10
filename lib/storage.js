'use strict';
const fs = require('fs');
const fsp = fs.promises;
const shared = require('./shared');
const { sessionIsExpired } = require('./session');
const { logJson } = require('./logging');
const {
  SESSION_TTL_MS,
  DATABASE_URL,
  DATABASE_SSL_MODE,
  DATABASE_POOL_MAX,
  DATABASE_POOL_IDLE_TIMEOUT_MS,
  DATABASE_POOL_CONNECTION_TIMEOUT_MS,
  DATABASE_STATEMENT_TIMEOUT_MS,
  DATABASE_QUERY_TIMEOUT_MS,
  STORAGE_TRACKED_FILES,
  STORAGE_TRACKED_FILE_KEYS,
  CONFIG_INTEGRITY_KEYS,
  REQUESTED_STORAGE_BACKEND,
} = require('./constants');

// ── Pool stats ────────────────────────────────────────────────────────────────
function getPoolStats() {
  const pgPool = shared.pgPool;
  if (!pgPool) return { total: 0, idle: 0, waiting: 0 };
  return {
    total: pgPool.totalCount,
    idle: pgPool.idleCount,
    waiting: pgPool.waitingCount
  };
}

// ── Prometheus metrics ────────────────────────────────────────────────────────
function incrementRequestMetric(statusCode) {
  shared.prometheusMetrics.requestsTotal += 1;
  const bucket = statusCode >= 500 ? '5xx' : statusCode >= 400 ? '4xx' : statusCode >= 300 ? '3xx' : '2xx';
  shared.prometheusMetrics.requestsByStatus.set(
    bucket,
    (shared.prometheusMetrics.requestsByStatus.get(bucket) || 0) + 1
  );
}

// ── Optional Redis-backed distributed state ───────────────────────────────────
async function initRedisIfConfigured() {
  const redisUrl = String(process.env.CAJAL_REDIS_URL || '').trim();
  if (!redisUrl) return false;
  let redis;
  try {
    redis = require('redis');
  } catch {
    logJson('warn', 'redis.init', 'CAJAL_REDIS_URL is set but the "redis" npm package is not installed. Run: npm install redis');
    return false;
  }
  try {
    const client = redis.createClient({ url: redisUrl });
    client.on('error', (err) => logJson('error', 'redis.client', `Redis client error: ${String(err?.message || err)}`));
    await client.connect();
    shared.redisClient = client;
    logJson('info', 'redis.init', 'Redis connected', { url: redisUrl.replace(/:[^:@]*@/, ':***@') });
    return true;
  } catch (err) {
    logJson('warn', 'redis.init', `Redis connection failed, falling back to in-memory state: ${String(err?.message || err)}`);
    return false;
  }
}

function redisSessionKey(sid) { return `cajal:session:${String(sid || '')}`; }

function redisPersistSession(sid, session) {
  const redisClient = shared.redisClient;
  if (!redisClient) return;
  const ageMs = Date.now() - Number(session?.createdAt || 0);
  const ttlMs = Math.max(1000, SESSION_TTL_MS - ageMs);
  redisClient.set(redisSessionKey(sid), JSON.stringify(session), { PX: ttlMs }).catch((err) => logJson('warn', 'redis.persist', `Redis session persist failed: ${String(err?.message || err)}`));
}

function redisDeleteSession(sid) {
  const redisClient = shared.redisClient;
  if (!redisClient) return;
  redisClient.del(redisSessionKey(sid)).catch((err) => logJson('warn', 'redis.delete', `Redis session delete failed: ${String(err?.message || err)}`));
}

async function redisRestoreSessions(sessionMap) {
  const redisClient = shared.redisClient;
  if (!redisClient) return 0;
  try {
    const keys = await redisClient.keys('cajal:session:*');
    let restored = 0;
    const now = Date.now();
    await Promise.all(keys.map(async (key) => {
      try {
        const raw = await redisClient.get(key);
        if (!raw) return;
        const session = JSON.parse(raw);
        if (sessionIsExpired(session, now)) return;
        const sid = key.slice('cajal:session:'.length);
        sessionMap.set(sid, session);
        restored += 1;
      } catch (err) { logJson('warn', 'redis.restore.entry', `Skipped corrupt session entry: ${String(err?.message || err)}`); }
    }));
    if (restored > 0) logJson('info', 'redis.restore', `Restored ${restored} sessions from Redis`);
    return restored;
  } catch (err) {
    logJson('warn', 'redis.restore', `Session restore from Redis failed: ${String(err?.message || err)}`);
    return 0;
  }
}

// ── Config integrity ──────────────────────────────────────────────────────────
function normalizeConfigIntegrityStatus(status = 'ok') {
  const normalized = String(status || '').trim().toLowerCase();
  if (normalized === 'warn' || normalized === 'warning') return 'warn';
  if (normalized === 'fail' || normalized === 'error') return 'fail';
  return 'ok';
}

function setConfigIntegrityState(key, status = 'ok', detail = '') {
  const configIntegrityState = shared.configIntegrityState;
  const configKey = String(key || '').trim();
  if (!configKey) return;
  if (!Object.prototype.hasOwnProperty.call(configIntegrityState, configKey)) {
    configIntegrityState[configKey] = { status: 'ok', detail: '', updatedAt: '' };
  }
  const nextStatus = normalizeConfigIntegrityStatus(status);
  const nextDetail = String(detail || '').trim();
  configIntegrityState[configKey] = {
    status: nextStatus,
    detail: nextDetail,
    updatedAt: new Date().toISOString()
  };
}

function getConfigIntegrityReport() {
  const configIntegrityState = shared.configIntegrityState;
  const entries = Object.entries(configIntegrityState)
    .map(([name, value]) => ({
      name,
      status: normalizeConfigIntegrityStatus(value?.status || 'ok'),
      detail: String(value?.detail || '').trim(),
      updatedAt: String(value?.updatedAt || '').trim()
    }))
    .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }));
  const summary = {
    ok: entries.filter((row) => row.status === 'ok').length,
    warn: entries.filter((row) => row.status === 'warn').length,
    fail: entries.filter((row) => row.status === 'fail').length
  };
  return {
    summary,
    entries,
    healthy: summary.warn === 0 && summary.fail === 0
  };
}

// ── Storage key helpers ───────────────────────────────────────────────────────
function trackedStoreKeyForFile(filePath) {
  return STORAGE_TRACKED_FILE_KEYS.get(filePath) || '';
}

function isTrackedDataFile(filePath) {
  return STORAGE_TRACKED_FILE_KEYS.has(filePath);
}

function createEnoentError(filePath) {
  const err = new Error(`ENOENT: no such file or store key, open '${filePath}'`);
  err.code = 'ENOENT';
  return err;
}

function parseReadEncodingArg(options) {
  if (!options) return '';
  if (typeof options === 'string') return options;
  if (options && typeof options === 'object' && typeof options.encoding === 'string') return options.encoding;
  return '';
}

function normalizeStorageBody(data, options) {
  if (Buffer.isBuffer(data)) {
    const enc = parseReadEncodingArg(options) || 'utf8';
    return data.toString(enc);
  }
  return String(data ?? '');
}

// ── Postgres store operations ─────────────────────────────────────────────────
async function readStoreBodyFromPostgres(key) {
  const result = await shared.pgPool.query('SELECT body FROM cajal_store WHERE key = $1', [key]);
  if (!result.rowCount) return null;
  return String(result.rows[0]?.body ?? '');
}

async function writeStoreBodyToPostgres(key, body) {
  await shared.pgPool.query(
    `INSERT INTO cajal_store (key, body, updated_at)
     VALUES ($1, $2, NOW())
     ON CONFLICT (key) DO UPDATE
       SET body = EXCLUDED.body, updated_at = NOW()
       WHERE cajal_store.body IS DISTINCT FROM EXCLUDED.body`,
    [key, String(body ?? '')]
  );
}

async function appendStoreBodyToPostgres(key, chunk) {
  await shared.pgPool.query(
    `INSERT INTO cajal_store (key, body, updated_at)
     VALUES ($1, $2, NOW())
     ON CONFLICT (key) DO UPDATE SET body = cajal_store.body || EXCLUDED.body, updated_at = NOW()`,
    [key, String(chunk ?? '')]
  );
}

async function hasStoreKeyInPostgres(key) {
  const result = await shared.pgPool.query('SELECT 1 FROM cajal_store WHERE key = $1', [key]);
  return result.rowCount > 0;
}

async function statStoreBodyFromPostgres(key, filePath) {
  const result = await shared.pgPool.query(
    'SELECT OCTET_LENGTH(body) AS size, updated_at FROM cajal_store WHERE key = $1',
    [key]
  );
  if (!result.rowCount) throw createEnoentError(filePath);
  const row = result.rows[0] || {};
  const updatedAt = row.updated_at ? new Date(row.updated_at) : new Date();
  return {
    size: Number(row.size || 0),
    mtime: updatedAt,
    mtimeMs: updatedAt.getTime()
  };
}

// ── Smart file operations ─────────────────────────────────────────────────────
async function smartReadFile(filePath, ...args) {
  if (shared.storageBackendActive === 'postgres' && isTrackedDataFile(filePath)) {
    const key = trackedStoreKeyForFile(filePath);
    const body = await readStoreBodyFromPostgres(key);
    if (body == null) throw createEnoentError(filePath);
    const encoding = parseReadEncodingArg(args[0]);
    if (!encoding) return Buffer.from(body, 'utf8');
    if (encoding.toLowerCase() === 'utf8' || encoding.toLowerCase() === 'utf-8') return body;
    return Buffer.from(body, 'utf8').toString(encoding);
  }
  return fsp.readFile(filePath, ...args);
}

async function smartWriteFile(filePath, data, ...args) {
  if (shared.storageBackendActive === 'postgres' && isTrackedDataFile(filePath)) {
    const key = trackedStoreKeyForFile(filePath);
    const body = normalizeStorageBody(data, args[0]);
    await writeStoreBodyToPostgres(key, body);
    return;
  }
  return fsp.writeFile(filePath, data, ...args);
}

async function smartAppendFile(filePath, data, ...args) {
  if (shared.storageBackendActive === 'postgres' && isTrackedDataFile(filePath)) {
    const key = trackedStoreKeyForFile(filePath);
    const chunk = normalizeStorageBody(data, args[0]);
    await appendStoreBodyToPostgres(key, chunk);
    return;
  }
  return fsp.appendFile(filePath, data, ...args);
}

async function smartStat(filePath, ...args) {
  if (shared.storageBackendActive === 'postgres' && isTrackedDataFile(filePath)) {
    const key = trackedStoreKeyForFile(filePath);
    return statStoreBodyFromPostgres(key, filePath);
  }
  return fsp.stat(filePath, ...args);
}

async function smartReadFileTail(filePath, maxBytes = 5 * 1024 * 1024, encoding = 'utf8') {
  if (shared.storageBackendActive === 'postgres' && isTrackedDataFile(filePath)) {
    return smartReadFile(filePath, encoding);
  }
  const stats = await fsp.stat(filePath);
  if (stats.size <= maxBytes) {
    return fsp.readFile(filePath, encoding);
  }
  return new Promise((resolve, reject) => {
    const chunks = [];
    const stream = fs.createReadStream(filePath, {
      start: stats.size - maxBytes,
      encoding
    });
    stream.on('data', (chunk) => chunks.push(chunk));
    stream.on('end', () => {
      let result = chunks.join('');
      const nl = result.indexOf('\n');
      if (nl >= 0) result = result.slice(nl + 1);
      resolve(result);
    });
    stream.on('error', reject);
  });
}

async function smartFileExists(filePath) {
  if (shared.storageBackendActive === 'postgres' && isTrackedDataFile(filePath)) {
    const key = trackedStoreKeyForFile(filePath);
    return hasStoreKeyInPostgres(key);
  }
  return fs.existsSync(filePath);
}

// ── Postgres pool config ──────────────────────────────────────────────────────
function resolvePostgresSslConfig() {
  if (DATABASE_SSL_MODE === 'disable') return undefined;
  // 'prefer': try SSL but allow fallback — safe for local Postgres without certs
  if (DATABASE_SSL_MODE === 'prefer' || !DATABASE_SSL_MODE) return { rejectUnauthorized: false };
  // 'require': enforce SSL but accept any cert (self-signed OK, no third-party CA needed)
  if (DATABASE_SSL_MODE === 'require') return { rejectUnauthorized: false };
  // 'verify-ca' / 'verify-full': full cert chain validation (production external DB)
  if (DATABASE_SSL_MODE === 'verify-ca' || DATABASE_SSL_MODE === 'verify-full') return { rejectUnauthorized: true };
  if (DATABASE_SSL_MODE === 'true' || DATABASE_SSL_MODE === '1') return { rejectUnauthorized: false };
  return { rejectUnauthorized: false };
}

function buildPostgresPoolConfig() {
  return {
    connectionString: DATABASE_URL,
    ssl: resolvePostgresSslConfig(),
    max: DATABASE_POOL_MAX,
    idleTimeoutMillis: DATABASE_POOL_IDLE_TIMEOUT_MS,
    connectionTimeoutMillis: DATABASE_POOL_CONNECTION_TIMEOUT_MS,
    statement_timeout: DATABASE_STATEMENT_TIMEOUT_MS,
    query_timeout: DATABASE_QUERY_TIMEOUT_MS,
    application_name: 'cajal-app'
  };
}

// ── Storage backend lifecycle ─────────────────────────────────────────────────
async function migrateExistingFilesToPostgresStore() {
  for (const row of STORAGE_TRACKED_FILES) {
    const hasKey = await hasStoreKeyInPostgres(row.name);
    if (hasKey) continue;
    if (!fs.existsSync(row.file)) continue;
    try {
      const body = await fsp.readFile(row.file, 'utf8');
      await writeStoreBodyToPostgres(row.name, body);
    } catch (err) {
      console.warn(`Postgres migration skipped for ${row.name}: ${err?.message || err}`);
    }
  }
}

// ── Schema versioning ──────────────────────────────────────────────────────────
const SCHEMA_MIGRATIONS = [
  {
    version: 1,
    description: 'Initial cajal_store table',
    up: `CREATE TABLE IF NOT EXISTS cajal_store (
      key TEXT PRIMARY KEY,
      body TEXT NOT NULL DEFAULT '',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`
  },
  {
    version: 2,
    description: 'Add schema_migrations tracking table',
    up: null // handled by bootstrap below
  },
  {
    version: 3,
    description: 'Add updated_at index for data retention purging',
    up: `CREATE INDEX IF NOT EXISTS idx_cajal_store_updated_at ON cajal_store (updated_at)`
  },
  {
    version: 4,
    description: 'Agent sessions table for persistence across restarts',
    up: `CREATE TABLE IF NOT EXISTS cajal_agent_sessions (
      token TEXT PRIMARY KEY,
      session_id TEXT NOT NULL,
      site_id TEXT NOT NULL,
      created_at BIGINT NOT NULL,
      last_seen_at BIGINT NOT NULL,
      expires_at BIGINT NOT NULL,
      hostname TEXT NOT NULL DEFAULT '',
      local_ip TEXT NOT NULL DEFAULT '',
      platform TEXT NOT NULL DEFAULT '',
      version TEXT NOT NULL DEFAULT '',
      remote_ip TEXT NOT NULL DEFAULT ''
    )`
  },
];

const CURRENT_SCHEMA_VERSION = SCHEMA_MIGRATIONS.length;

async function ensureMigrationsTable(pool) {
  await pool.query(
    `CREATE TABLE IF NOT EXISTS cajal_schema_migrations (
      version INTEGER PRIMARY KEY,
      description TEXT NOT NULL DEFAULT '',
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`
  );
}

async function getAppliedSchemaVersion(pool) {
  const result = await pool.query('SELECT COALESCE(MAX(version), 0) AS ver FROM cajal_schema_migrations');
  return Number(result.rows[0]?.ver || 0);
}

async function runSchemaMigrations(pool) {
  await ensureMigrationsTable(pool);
  const appliedVersion = await getAppliedSchemaVersion(pool);

  for (const migration of SCHEMA_MIGRATIONS) {
    if (migration.version <= appliedVersion) continue;
    if (migration.up) {
      await pool.query(migration.up);
    }
    await pool.query(
      'INSERT INTO cajal_schema_migrations (version, description) VALUES ($1, $2) ON CONFLICT (version) DO NOTHING',
      [migration.version, migration.description]
    );
    console.log(`Schema migration v${migration.version}: ${migration.description}`);
  }
}

// ── Data retention purging at DB level ────────────────────────────────────────
async function purgeStaleDbRows(retentionDays = 90) {
  if (!shared.pgPool) return { deleted: 0 };
  // Only purge log rows (jsonl files), not config files
  const logKeys = ['error-log', 'diagnostics-log', 'telemetry-log'];
  const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
  let totalDeleted = 0;
  for (const key of logKeys) {
    try {
      const body = await readStoreBodyFromPostgres(key);
      if (!body) continue;
      const lines = body.split('\n').filter(Boolean);
      const retained = lines.filter((line) => {
        try {
          const parsed = JSON.parse(line);
          return !parsed.ts || parsed.ts >= cutoff;
        } catch { return true; }
      });
      const removed = lines.length - retained.length;
      if (removed > 0) {
        await writeStoreBodyToPostgres(key, retained.join('\n') + (retained.length ? '\n' : ''));
        totalDeleted += removed;
      }
    } catch { /* skip on error */ }
  }
  return { deleted: totalDeleted };
}

// ── Connection retry ──────────────────────────────────────────────────────────
async function connectWithRetry(pool, maxRetries = 5, baseDelayMs = 1000) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      await pool.query('SELECT 1');
      return;
    } catch (err) {
      if (attempt === maxRetries) throw err;
      const delayMs = baseDelayMs * Math.pow(2, attempt - 1);
      console.warn(`Postgres connection attempt ${attempt}/${maxRetries} failed: ${err?.message || err}. Retrying in ${delayMs}ms...`);
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
}

async function initStorageBackend() {
  if (REQUESTED_STORAGE_BACKEND && REQUESTED_STORAGE_BACKEND !== 'postgres') {
    throw new Error('File storage backend is no longer supported. Use PostgreSQL (CAJAL_STORAGE_BACKEND=postgres).');
  }
  if (!DATABASE_URL) {
    throw new Error('CAJAL_DATABASE_URL is required. File storage backend is no longer supported.');
  }
  let PoolCtor = null;
  try {
    ({ Pool: PoolCtor } = require('pg'));
  } catch (err) {
    throw new Error(`Postgres backend requested but pg dependency is missing: ${err?.message || err}`);
  }
  shared.pgPool = new PoolCtor(buildPostgresPoolConfig());
  await connectWithRetry(shared.pgPool);
  // Ensure base table exists (migration v1 handles CREATE IF NOT EXISTS)
  await shared.pgPool.query(
    `CREATE TABLE IF NOT EXISTS cajal_store (
      key TEXT PRIMARY KEY,
      body TEXT NOT NULL DEFAULT '',
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )`
  );
  await runSchemaMigrations(shared.pgPool);
  await migrateExistingFilesToPostgresStore();
  shared.storageBackendActive = 'postgres';
  console.log(`Storage backend: postgres (schema v${CURRENT_SCHEMA_VERSION})`);
}

// ── Agent session persistence ─────────────────────────────────────────────────
async function persistAgentSession(session) {
  if (!shared.pgPool) return;
  try {
    await shared.pgPool.query(
      `INSERT INTO cajal_agent_sessions (token, session_id, site_id, created_at, last_seen_at, expires_at, hostname, local_ip, platform, version, remote_ip)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       ON CONFLICT (token) DO UPDATE SET
         last_seen_at = EXCLUDED.last_seen_at,
         expires_at = EXCLUDED.expires_at`,
      [
        session.token, session.sessionId, session.siteId,
        session.createdAt, session.lastSeenAt, session.expiresAt,
        session.hostname || '', session.localIp || '', session.platform || '',
        session.version || '', session.remoteIp || ''
      ]
    );
  } catch (err) {
    logJson('warn', 'storage.agent-session.persist', `Agent session persist failed: ${err?.message || err}`);
  }
}

async function deleteAgentSessionsByToken(tokens) {
  if (!shared.pgPool || !tokens?.length) return;
  try {
    await shared.pgPool.query(
      'DELETE FROM cajal_agent_sessions WHERE token = ANY($1)',
      [tokens]
    );
  } catch (err) {
    logJson('warn', 'storage.agent-session.delete', `Agent session delete failed: ${err?.message || err}`);
  }
}

async function deleteAgentSessionsBySite(siteId) {
  if (!shared.pgPool || !siteId) return;
  try {
    await shared.pgPool.query(
      'DELETE FROM cajal_agent_sessions WHERE site_id = $1',
      [siteId]
    );
  } catch (err) {
    logJson('warn', 'storage.agent-session.delete-site', `Agent session delete by site failed: ${err?.message || err}`);
  }
}

async function restoreAgentSessions(sessionMap, agentBySite, now = Date.now()) {
  if (!shared.pgPool) return 0;
  try {
    const result = await shared.pgPool.query(
      'SELECT * FROM cajal_agent_sessions WHERE expires_at > $1',
      [now]
    );
    let restored = 0;
    const expiredTokens = [];
    for (const row of result.rows) {
      const session = {
        token: row.token,
        sessionId: row.session_id,
        siteId: row.site_id,
        createdAt: Number(row.created_at),
        lastSeenAt: Number(row.last_seen_at),
        expiresAt: Number(row.expires_at),
        hostname: row.hostname || '',
        localIp: row.local_ip || '',
        platform: row.platform || '',
        version: row.version || '',
        remoteIp: row.remote_ip || ''
      };
      if (session.expiresAt <= now) {
        expiredTokens.push(session.token);
        continue;
      }
      sessionMap.set(session.token, session);
      agentBySite.set(session.siteId, session);
      restored++;
    }
    if (expiredTokens.length) {
      deleteAgentSessionsByToken(expiredTokens).catch(() => {});
    }
    // Clean up any remaining expired rows
    await shared.pgPool.query('DELETE FROM cajal_agent_sessions WHERE expires_at <= $1', [now]).catch(() => {});
    if (restored > 0) logJson('info', 'storage.agent-session.restore', `Restored ${restored} agent sessions from Postgres`);
    return restored;
  } catch (err) {
    logJson('warn', 'storage.agent-session.restore', `Agent session restore failed: ${err?.message || err}`);
    return 0;
  }
}

async function closeStorageBackend() {
  if (!shared.pgPool) return;
  await shared.pgPool.end();
  shared.pgPool = null;
}

module.exports = {
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
  smartReadFileTail,
  smartFileExists,
  resolvePostgresSslConfig,
  buildPostgresPoolConfig,
  migrateExistingFilesToPostgresStore,
  initStorageBackend,
  closeStorageBackend,
  purgeStaleDbRows,
  connectWithRetry,
  runSchemaMigrations,
  persistAgentSession,
  deleteAgentSessionsByToken,
  deleteAgentSessionsBySite,
  restoreAgentSessions,
  CURRENT_SCHEMA_VERSION,

  __test: {
    buildPostgresPoolConfig,
    resolvePostgresSslConfig,
    setConfigIntegrityState,
    getConfigIntegrityReport,
    SCHEMA_MIGRATIONS,
    CURRENT_SCHEMA_VERSION,
    connectWithRetry,
    purgeStaleDbRows,
  },
};
