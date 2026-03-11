const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.resolve(__dirname, '..');

function readFile(relativePath) {
  return fs.readFileSync(path.join(ROOT, relativePath), 'utf8');
}

test('header keeps version + patch notes affordance wired to help anchor', () => {
  const html = readFile('public/index.html');
  assert.match(html, /class="version-label-inline">Version</);
  assert.match(html, /class="version-patch-badge" data-help-section="patch-notes">Patch Notes</);
});

test('audit trail panel exposes explicit close control', () => {
  const html = readFile('public/index.html');
  assert.match(html, /id="auditRefreshBtn"/);
  assert.match(html, /id="auditCloseBtn"/);
});

test('help doc includes stable patch-notes anchor', () => {
  const readme = readFile('README.md');
  assert.match(readme, /^## Patch Notes \{#patch-notes\}/m);
});

test('settings include dedicated API section with token controls', () => {
  const html = readFile('public/index.html');
  assert.match(html, /id="apiAccessPanel"/);
  assert.match(html, /<span>API Tokens<\/span>/);
  assert.match(html, /id="apiTokenForm"/);
  assert.match(html, /id="apiTokenList"/);
});

test('api section does not include windows agent upload controls', () => {
  const html = readFile('public/index.html');
  assert.ok(!html.includes('windowsAgentPackageForm'), 'Upload form should be removed');
  assert.ok(!html.includes('windowsAgentPackageUploadBtn'), 'Upload button should be removed');
});

test('agent setup dialog submit button updates text for platform', () => {
  const js = readFile('public/app.js');
  // askLinuxAgentSetup must update the submit button text with the platform label
  const fnStart = js.indexOf('function askLinuxAgentSetup');
  assert.ok(fnStart >= 0, 'askLinuxAgentSetup function not found');
  const fnBody = js.slice(fnStart, fnStart + 800);
  assert.ok(fnBody.includes('linuxAgentSubmit') && fnBody.includes('Download') && fnBody.includes('platform'),
    'submit button must be updated with platform label');
});

// ── Security hardening regression tests ──────────────────────────────────────

test('setup-password and verify-totp endpoints are rate-limited', () => {
  const auth = readFile('lib/routes/auth.js');
  const setupStart = auth.indexOf("url.pathname === '/api/auth/local/setup-password'");
  assert.ok(setupStart >= 0, 'setup-password route not found');
  const setupBlock = auth.slice(setupStart, setupStart + 800);
  assert.ok(setupBlock.includes('enforceRateLimitOrSend'), 'setup-password must be rate-limited');

  const totpStart = auth.indexOf("url.pathname === '/api/auth/local/verify-totp'");
  assert.ok(totpStart >= 0, 'verify-totp route not found');
  const totpBlock = auth.slice(totpStart, totpStart + 800);
  assert.ok(totpBlock.includes('enforceRateLimitOrSend'), 'verify-totp must be rate-limited');
});

test('login returns identical response shape for unknown users (anti-enumeration)', () => {
  const auth = readFile('lib/routes/auth.js');
  const loginBlock = auth.slice(
    auth.indexOf("resolveLocalUserByIdentifier(state.users, loginId)"),
    auth.indexOf("resolveLocalUserByIdentifier(state.users, loginId)") + 600
  );
  // Unknown user path must return set_password (same as no-password user)
  assert.ok(loginBlock.includes("next: 'set_password'"), 'unknown user must return set_password shape');
  assert.ok(loginBlock.includes('dummyToken'), 'unknown user must use dummy token');
});

test('TOTP replay prevention is persisted to user record', () => {
  const auth = readFile('lib/routes/auth.js');
  assert.match(auth, /totpLastUsedStep/, 'must reference totpLastUsedStep');
  assert.match(auth, /user\.localAuth\.totpLastUsedStep/, 'must persist step to user.localAuth');
  assert.match(auth, /persistUsers/, 'must call persistUsers after storing step');
});

test('config key derivation uses HKDF', () => {
  const cryptoFile = readFile('lib/crypto.js');
  assert.match(cryptoFile, /hkdfSync/, 'must use HKDF for key derivation');
  assert.match(cryptoFile, /deriveCryptoKeyLegacy/, 'must keep legacy SHA256 for backward compat');
  assert.match(cryptoFile, /deriveCryptoKeyHkdf/, 'must have HKDF derivation function');
});

test('backup password minimum is 16 characters', () => {
  const cryptoFile = readFile('lib/crypto.js');
  assert.match(cryptoFile, /pass\.length < 16/, 'backup password minimum must be 16');
});

test('login registration dialog keeps staged auth controls and disables native form blocking', () => {
  const html = readFile('public/login.html');
  assert.match(html, /id="registerForm"[^>]*novalidate/);
  assert.match(html, /id="registerPasswordWrap"/);
  assert.match(html, /id="registerTotpWrap"/);
  assert.match(html, /id="registerQrWrap"/);
});

test('router enforces rate limit on update/apply before calling Watchtower', () => {
  const system = readFile('lib/routes/system.js');
  // enforceRateLimitOrSend must appear before the Watchtower http.request call within the update/apply block
  const applyStart = system.indexOf("url.pathname === '/api/system/update/apply'");
  assert.ok(applyStart >= 0, 'update/apply route not found in system routes');
  const applyBlock = system.slice(applyStart, applyStart + 800);
  const rateLimitPos = applyBlock.indexOf('enforceRateLimitOrSend');
  const watchtowerPos = applyBlock.indexOf('WATCHTOWER_URL');
  assert.ok(rateLimitPos >= 0, 'enforceRateLimitOrSend not found in update/apply block');
  assert.ok(rateLimitPos < watchtowerPos, 'rate limit check must precede Watchtower call');
});

test('dead welcome dialog code has been removed', () => {
  const html = readFile('public/index.html');
  assert.ok(!html.includes('id="welcomeDialog"'), 'welcomeDialog should be removed');
  const js = readFile('public/app.js');
  assert.ok(!js.includes('function maybeShowWelcomeDialog'), 'maybeShowWelcomeDialog should be removed');
});

test('system health panel includes version check section placeholder', () => {
  const html = readFile('public/index.html');
  assert.match(html, /id="versionCheckSection"/);
});

test('app.js includes version check functions', () => {
  const js = readFile('public/app.js');
  assert.match(js, /function checkForUpdates/);
  assert.match(js, /function applyUpdate/);
  assert.match(js, /function renderVersionCheckSection/);
  assert.match(js, /function updateTopbarVersion/);
});

test('applyUpdate uses in-app askActionConfirm before triggering restart', () => {
  const js = readFile('public/app.js');
  const fnStart = js.indexOf('async function applyUpdate');
  assert.ok(fnStart >= 0, 'applyUpdate function not found');
  const fnBody = js.slice(fnStart, fnStart + 500);
  // Must use in-app dialog, not native confirm()
  assert.ok(!fnBody.includes('window.confirm(') && !fnBody.includes('\n  if (!confirm('), 'applyUpdate must not use native confirm()');
  const confirmPos = fnBody.indexOf('askActionConfirm(');
  const progressPos = fnBody.indexOf('updateInProgress = true');
  assert.ok(confirmPos >= 0, 'askActionConfirm() not found in applyUpdate');
  assert.ok(confirmPos < progressPos, 'askActionConfirm() must come before setting updateInProgress');
});

test('factory reset does not use native window.prompt', () => {
  const js = readFile('public/app.js');
  const fnStart = js.indexOf('async function triggerFactoryResetForDeployment');
  assert.ok(fnStart >= 0, 'triggerFactoryResetForDeployment function not found');
  const fnBody = js.slice(fnStart, fnStart + 800);
  assert.ok(!fnBody.includes('window.prompt('), 'factory reset must not use window.prompt()');
  assert.ok(fnBody.includes('typeToConfirm'), 'factory reset must use typeToConfirm in-app dialog');
});

test('dead setup wizard code has been removed', () => {
  const html = readFile('public/index.html');
  assert.ok(!html.includes('id="setupWizardDialog"'), 'setupWizardDialog should be removed');
  const js = readFile('public/app.js');
  assert.ok(!js.includes('function maybeShowSetupWizard'), 'maybeShowSetupWizard should be removed');
});

// ── Install / update flow regression tests ─────────────────────────────────

test('docker-compose.yml uses image pull (not build) for remote installs', () => {
  const yml = readFile('docker-compose.yml');
  assert.match(yml, /image:\s*ghcr\.io\/nniell90\/cajal/);
  assert.ok(!yml.includes('build: .'), 'docker-compose.yml should not use build: . — remote users cannot build from source');
});

test('docker-compose.yml watchtower token default matches cajal service default', () => {
  const yml = readFile('docker-compose.yml');
  const cajalToken = yml.match(/CAJAL_WATCHTOWER_TOKEN:\s*\$\{CAJAL_WATCHTOWER_TOKEN:-(.*?)\}/);
  const wtToken = yml.match(/WATCHTOWER_HTTP_API_TOKEN:\s*\$\{CAJAL_WATCHTOWER_TOKEN:-(.*?)\}/);
  assert.ok(cajalToken, 'cajal service must reference CAJAL_WATCHTOWER_TOKEN');
  assert.ok(wtToken, 'watchtower service must reference CAJAL_WATCHTOWER_TOKEN');
  assert.equal(cajalToken[1], wtToken[1], 'token fallback defaults must match between cajal and watchtower services');
});

test('docker-compose.yml includes watchtower and socket-proxy services', () => {
  const yml = readFile('docker-compose.yml');
  assert.match(yml, /cajal-watchtower/);
  assert.match(yml, /cajal-socket-proxy/);
  assert.match(yml, /containrrr\/watchtower/);
  assert.match(yml, /tecnativa\/docker-socket-proxy/);
});

test('docker-compose.yml cajal service has watchtower label', () => {
  const yml = readFile('docker-compose.yml');
  assert.match(yml, /com\.centurylinklabs\.watchtower\.enable=true/);
});

test('docker-reload.sh reads CAJAL_DB_USER and CAJAL_DB_NAME from .env', () => {
  const sh = readFile('docker-reload.sh');
  assert.match(sh, /CAJAL_DB_USER/, 'should reference CAJAL_DB_USER');
  assert.match(sh, /CAJAL_DB_NAME/, 'should reference CAJAL_DB_NAME');
  assert.ok(!sh.includes('-e POSTGRES_DB=cajal'), 'should not hardcode POSTGRES_DB=cajal');
  assert.ok(!sh.includes('-e POSTGRES_USER=cajal'), 'should not hardcode POSTGRES_USER=cajal');
});

test('docker-reload.sh DATABASE_URL uses dynamic user and db name', () => {
  const sh = readFile('docker-reload.sh');
  const urlLine = sh.split('\n').find(l => l.includes('CAJAL_DATABASE_URL='));
  assert.ok(urlLine, 'DATABASE_URL assignment must exist');
  assert.match(urlLine, /\$\{?db_user\}?/, 'DATABASE_URL must use db_user variable');
  assert.match(urlLine, /\$\{?db_name\}?/, 'DATABASE_URL must use db_name variable');
});

test('version check endpoint returns watchtowerReady flag', () => {
  const system = readFile('lib/routes/system.js');
  const checkBlock = system.slice(
    system.indexOf("url.pathname === '/api/system/version/check'"),
    system.indexOf("url.pathname === '/api/system/update/apply'")
  );
  assert.match(checkBlock, /watchtowerReady/, 'version check response must include watchtowerReady');
  assert.match(checkBlock, /Boolean\(WATCHTOWER_URL && WATCHTOWER_TOKEN\)/, 'watchtowerReady must check both URL and TOKEN');
});

test('update/apply clears version check cache on success', () => {
  const system = readFile('lib/routes/system.js');
  const applyStart = system.indexOf("url.pathname === '/api/system/update/apply'");
  const applyBlock = system.slice(applyStart, applyStart + 2500);
  assert.match(applyBlock, /_versionCheckCache\s*=\s*null/, 'must clear version cache after successful update');
});

test('app.js shows manual update command when watchtowerReady is false', () => {
  const js = readFile('public/app.js');
  assert.match(js, /watchtowerReady\s*===\s*false/, 'must check watchtowerReady flag');
  assert.match(js, /docker compose pull/, 'must show manual docker compose command');
});

test('app.js reloads admin sections after login via reloadAfterLogin', () => {
  const js = readFile('public/app.js');
  assert.match(js, /async function reloadAfterLogin/, 'reloadAfterLogin must exist');
  assert.match(js, /async function loadAdminSections/, 'loadAdminSections must exist');
  const reloadFn = js.slice(js.indexOf('async function reloadAfterLogin'), js.indexOf('async function reloadAfterLogin') + 300);
  assert.match(reloadFn, /loadAdminSections/, 'reloadAfterLogin must call loadAdminSections');
  assert.match(reloadFn, /loadAuthState/, 'reloadAfterLogin must call loadAuthState');
});

test('constants.js has sensible defaults for update config', () => {
  const constants = readFile('lib/constants.js');
  assert.match(constants, /GITHUB_REPO.*'nniell90\/cajal'/, 'GITHUB_REPO default');
  assert.match(constants, /UPDATE_IMAGE.*'ghcr\.io\/nniell90\/cajal:latest'/, 'UPDATE_IMAGE default');
  assert.match(constants, /WATCHTOWER_URL.*'http:\/\/127\.0\.0\.1:8080'/, 'WATCHTOWER_URL default');
});

test('.env.example documents auto-generation behavior', () => {
  const env = readFile('.env.example');
  assert.match(env, /auto-generat/i, 'must mention auto-generation');
  assert.match(env, /docker-reload\.sh/, 'must reference docker-reload.sh');
  assert.match(env, /Default:.*nniell90\/cajal/i, 'must document GITHUB_REPO default');
});

test('SNMP poller uses recursive setTimeout for backpressure (not setInterval)', () => {
  const monitoring = readFile('lib/monitoring.js');
  const fnIdx = monitoring.indexOf('function startSnmpPoller');
  assert.ok(fnIdx > 0, 'startSnmpPoller function must exist');
  const snmpSection = monitoring.slice(fnIdx, fnIdx + 8000);
  assert.ok(!snmpSection.includes('setInterval'), 'SNMP poller must not use setInterval (use setTimeout for backpressure)');
  assert.match(snmpSection, /setTimeout/, 'SNMP poller must use setTimeout for backpressure');
});

test('static file serving includes Cache-Control and ETag headers', () => {
  const router = readFile('lib/router.js');
  const staticIdx = router.indexOf('MIME_TYPES[ext]');
  assert.ok(staticIdx > 0, 'static file serving must exist');
  const staticSection = router.slice(staticIdx, staticIdx + 600);
  assert.match(staticSection, /ETag/, 'must set ETag header');
  assert.match(staticSection, /Cache-Control/, 'must set Cache-Control header');
  assert.match(staticSection, /if-none-match/, 'must check If-None-Match for 304');
});

test('telemetry log read uses tail-limited read instead of full file', () => {
  const logging = readFile('lib/logging.js');
  assert.match(logging, /smartReadFileTail/, 'readTelemetryLogEntries must use smartReadFileTail');
});

test('retention cleanup interval is 10 minutes', () => {
  const server = readFile('server.js');
  assert.match(server, /enforceStorageRetention[\s\S]*?10 \* 60 \* 1000/, 'retention interval must be 10 minutes');
});

test('60-second cleanup prunes flow Maps for deleted sites', () => {
  const server = readFile('server.js');
  assert.match(server, /activeSiteIds/, 'cleanup must compute active site IDs');
  assert.match(server, /syslogWindows\.keys/, 'cleanup must prune syslogWindows');
  assert.match(server, /netflowTalkers\.entries/, 'cleanup must prune netflowTalkers');
  assert.match(server, /flowState\.keys/, 'cleanup must prune flowState');
  assert.match(server, /pingState\.keys/, 'cleanup must prune pingState');
});

// ── Architecture regression tests ────────────────────────────────────────────

test('TCP syslog socket has error handler and timeout', () => {
  const monitoring = readFile('lib/monitoring.js');
  const tcpStart = monitoring.indexOf('net.createServer');
  assert.ok(tcpStart >= 0, 'TCP server must exist in monitoring.js');
  const tcpBlock = monitoring.slice(tcpStart, tcpStart + 1200);
  assert.match(tcpBlock, /socket\.on\('error'/, 'individual TCP sockets must have error handlers');
  assert.match(tcpBlock, /socket\.setTimeout/, 'TCP sockets must have a timeout');
  assert.match(tcpBlock, /socket\.on\('timeout'/, 'TCP sockets must handle timeout events');
});

test('HTTP servers have request, headers, and keepAlive timeouts', () => {
  const server = readFile('server.js');
  assert.match(server, /requestTimeout\s*=\s*30000/, 'server must set requestTimeout');
  assert.match(server, /headersTimeout\s*=\s*35000/, 'server must set headersTimeout');
  assert.match(server, /keepAliveTimeout\s*=\s*5000/, 'server must set keepAliveTimeout');
});

test('router applies per-request timeout and API versioning URL rewrite', () => {
  const router = readFile('lib/router.js');
  assert.match(router, /req\.setTimeout\(60000/, 'handler must set 60s per-request timeout');
  assert.match(router, /\/api\/v1\//, 'handler must handle /api/v1/ prefix');
  assert.match(router, /X-API-Version/, 'handler must set X-API-Version header');
});

test('AsyncMutex provides acquire/release/run serialization', () => {
  const mutex = readFile('lib/mutex.js');
  assert.match(mutex, /class AsyncMutex/, 'must define AsyncMutex class');
  assert.match(mutex, /acquire\(\)/, 'must have acquire method');
  assert.match(mutex, /release\(\)/, 'must have release method');
  assert.match(mutex, /async run\(fn\)/, 'must have async run method');
  assert.match(mutex, /this\._queue/, 'must maintain internal queue');
});

test('persist functions use AsyncMutex for write serialization', () => {
  const events = readFile('lib/events.js');
  const sites = readFile('lib/sites.js');
  assert.match(events, /AsyncMutex/, 'events.js must import AsyncMutex');
  assert.match(events, /_persistMutex\.run/, 'persistEvents must use mutex');
  assert.match(sites, /AsyncMutex/, 'sites.js must import AsyncMutex');
  assert.match(sites, /_persistMutex\.run/, 'persistSites must use mutex');
});

test('router.js is a slim dispatcher with route module imports', () => {
  const router = readFile('lib/router.js');
  const routeModules = ['auth', 'events', 'settings', 'system', 'backup', 'agent', 'health', 'sites', 'users', 'devices'];
  for (const mod of routeModules) {
    assert.ok(router.includes(`./routes/${mod}`), `router must import routes/${mod}`);
  }
  assert.match(router, /routeHandlers/, 'router must define routeHandlers array');
  assert.match(router, /for \(const handler of routeHandlers\)/, 'router must dispatch via loop');
  // Router should be under 300 lines (was 3952 before split)
  const lineCount = router.split('\n').length;
  assert.ok(lineCount < 300, `router.js must be under 300 lines (got ${lineCount})`);
});

test('each route module exports a handler function', () => {
  const routeModules = ['auth', 'events', 'settings', 'system', 'backup', 'agent', 'health', 'sites', 'users', 'devices'];
  for (const mod of routeModules) {
    const src = readFile(`lib/routes/${mod}.js`);
    const expectedFn = 'handle' + mod.charAt(0).toUpperCase() + mod.slice(1);
    assert.ok(src.includes(`function ${expectedFn}`), `routes/${mod}.js must define ${expectedFn}`);
    assert.ok(src.includes(`module.exports`), `routes/${mod}.js must export handler`);
  }
});

test('backup import route sets extended timeout', () => {
  const backup = readFile('lib/routes/backup.js');
  const importStart = backup.indexOf("url.pathname === '/api/backup/import'");
  assert.ok(importStart >= 0, 'backup import route must exist');
  const importBlock = backup.slice(importStart, importStart + 400);
  assert.match(importBlock, /req\.setTimeout\(300000\)/, 'backup import must have 5-min timeout');
});

// ── Exhaustive unauthenticated endpoint scan ──────────────────────────────────
// Every GET endpoint that returns site/device/alert/settings data MUST require auth.
// Only allow-listed public endpoints may skip auth.
test('all data GET endpoints require authentication', () => {
  const ALLOWED_PUBLIC_ENDPOINTS = new Set([
    '/api/auth/me',
    '/api/auth/login',
    '/api/auth/callback',
    '/api/auth/local/totp-qr',
    '/api/auth/local/login',
    '/api/auth/local/setup-password',
    '/api/auth/local/verify-totp',
    '/api/health',
    '/api/healthz',
    '/api/help/readme',
    '/api/agent/linux/download',
    '/api/agent/windows/download',
    '/login.html',
  ]);

  const routeFiles = [
    'lib/routes/sites.js',
    'lib/routes/devices.js',
    'lib/routes/health.js',
    'lib/routes/settings.js',
    'lib/routes/events.js',
    'lib/routes/system.js',
    'lib/routes/backup.js',
    'lib/routes/agent.js',
    'lib/routes/users.js',
    'lib/routes/auth.js',
  ];

  const getRoutePattern = /req\.method\s*===?\s*'GET'\s*&&\s*(?:url\.pathname\s*===?\s*'([^']+)'|\/\^(.+?)\$\/\.test\(url\.pathname\))/g;
  const failures = [];

  for (const file of routeFiles) {
    const src = readFile(file);
    let match;
    while ((match = getRoutePattern.exec(src)) !== null) {
      const endpoint = match[1] || match[2];
      if (!endpoint) continue;
      if (ALLOWED_PUBLIC_ENDPOINTS.has(endpoint)) continue;

      // Find the code block between this match and the next ~300 chars
      const blockStart = match.index;
      const block = src.substring(blockStart, blockStart + 400);

      const hasAuth =
        block.includes('requestUser?.authenticated') ||
        block.includes('ensureAllowed(requestUser') ||
        block.includes('Authentication required');

      if (!hasAuth) {
        failures.push(`${file}: GET ${endpoint} missing auth check`);
      }
    }
  }

  assert.deepEqual(failures, [], `Unauthenticated GET endpoints found:\n${failures.join('\n')}`);
});

// ── TCP syslog framing uses newline-delimited buffering ───────────────────────
test('TCP syslog collector uses newline-delimited message framing', () => {
  const monSrc = readFile('lib/monitoring.js');
  const tcpStart = monSrc.indexOf('net.createServer');
  assert.ok(tcpStart >= 0, 'syslog TCP server must exist');
  const tcpBlock = monSrc.substring(tcpStart, tcpStart + 2000);
  assert.ok(tcpBlock.includes('tcpBuffer'), 'TCP syslog must use a buffer for message framing');
  assert.ok(tcpBlock.includes('Buffer.concat'), 'TCP syslog must concatenate chunks');
  assert.ok(tcpBlock.includes('indexOf(10)') || tcpBlock.includes("indexOf('\\n')"), 'TCP syslog must split on newline boundaries');
  assert.ok(tcpBlock.includes('64 * 1024'), 'TCP syslog buffer must have a max size guard');
  assert.ok(tcpBlock.includes("on('close'"), 'TCP syslog must flush remaining buffer on close');
});

// ── Persist mutex wraps flushDirtyState ───────────────────────────────────────
test('persistLoop wraps flushDirtyState with mutex', () => {
  const serverSrc = readFile('server.js');
  assert.ok(serverSrc.includes('persistMutex'), 'server.js must use persistMutex');
  assert.ok(serverSrc.includes("persistMutex.run(() => flushDirtyState"), 'persist calls must be wrapped in mutex.run');
  assert.ok(serverSrc.includes("const persistMutex = new AsyncMutex()"), 'persistMutex must be an AsyncMutex instance');
});

// ── consumeSetupToken actually deletes the token ──────────────────────────────
test('consumeSetupToken removes the token from localSetupState', () => {
  const authSrc = readFile('lib/auth.js');
  const consumeStart = authSrc.indexOf('function consumeSetupToken');
  assert.ok(consumeStart >= 0, 'consumeSetupToken must exist');
  const consumeBlock = authSrc.substring(consumeStart, consumeStart + 400);
  // Must delete the token before returning
  const deleteCount = (consumeBlock.match(/localSetupState\.delete/g) || []).length;
  assert.ok(deleteCount >= 2, 'consumeSetupToken must delete token on expiry AND on successful consume');
});

// ── SNMP credentials not in process args for v3 ──────────────────────────────
test('SNMPv3 credentials use config file instead of CLI args', () => {
  const monSrc = readFile('lib/monitoring.js');
  // The shared SNMP setup lives in buildSnmpExecContext; runSnmpGet/runSnmpWalk delegate to it.
  const helperStart = monSrc.indexOf('function buildSnmpExecContext');
  assert.ok(helperStart >= 0, 'buildSnmpExecContext helper must exist');
  const snmpBlock = monSrc.substring(helperStart, helperStart + 2200);
  assert.ok(snmpBlock.includes('SNMPCONFPATH'), 'SNMPv3 must use SNMPCONFPATH for credentials');
  assert.ok(snmpBlock.includes('snmp.conf'), 'SNMPv3 must write a temporary snmp.conf file');
  assert.ok(snmpBlock.includes('mode: 0o600') || snmpBlock.includes('0o600'), 'snmp.conf must have restricted permissions');
  assert.ok(snmpBlock.includes('rmSync') || snmpBlock.includes('unlinkSync'), 'temporary config must be cleaned up after use');
  // Verify both consumers still exist
  assert.ok(monSrc.includes('function runSnmpGet'), 'runSnmpGet must exist');
  assert.ok(monSrc.includes('function runSnmpWalk'), 'runSnmpWalk must exist');
});

// ── headersTimeout > requestTimeout ──────────────────────────────────────────
test('headersTimeout is greater than requestTimeout on HTTP servers', () => {
  const serverSrc = readFile('server.js');
  const requestTimeoutMatch = serverSrc.match(/\.requestTimeout\s*=\s*(\d+)/);
  const headersTimeoutMatch = serverSrc.match(/\.headersTimeout\s*=\s*(\d+)/);
  assert.ok(requestTimeoutMatch, 'requestTimeout must be set');
  assert.ok(headersTimeoutMatch, 'headersTimeout must be set');
  const requestTimeout = Number(requestTimeoutMatch[1]);
  const headersTimeout = Number(headersTimeoutMatch[1]);
  assert.ok(headersTimeout > requestTimeout,
    `headersTimeout (${headersTimeout}) must be > requestTimeout (${requestTimeout}) per Node.js docs`);
});

// ── /api/healthz unauthenticated endpoint ────────────────────────────────────
test('/api/healthz endpoint exists and does not require auth', () => {
  const healthSrc = readFile('lib/routes/health.js');
  const healthzStart = healthSrc.indexOf("/api/healthz");
  assert.ok(healthzStart >= 0, '/api/healthz endpoint must exist');
  const healthzBlock = healthSrc.substring(healthzStart, healthzStart + 200);
  assert.ok(!healthzBlock.includes('ensureAllowed'), '/api/healthz must not require admin auth');
  assert.ok(!healthzBlock.includes('requestUser?.authenticated'), '/api/healthz must not require user auth');
  assert.ok(healthzBlock.includes('ok: true') || healthzBlock.includes('"ok"'), '/api/healthz must return ok status');
});

// ── totpLastUsedStep pruning ─────────────────────────────────────────────────
test('totpLastUsedStep map has periodic pruning', () => {
  const authSrc = readFile('lib/routes/auth.js');
  assert.ok(authSrc.includes('pruneTotpLastUsedStep'), 'auth.js must export pruneTotpLastUsedStep');
  assert.ok(authSrc.includes('totpLastUsedStep.delete'), 'pruning must delete stale entries');

  const serverSrc = readFile('server.js');
  assert.ok(serverSrc.includes('pruneTotpLastUsedStep'), 'server.js must call pruneTotpLastUsedStep');
});

// ── decaySyslogMetrics only marks dirty when changed ─────────────────────────
test('decaySyslogMetrics only marks dirty when EPS actually changes', () => {
  const monSrc = readFile('lib/monitoring.js');
  const decayStart = monSrc.indexOf('function decaySyslogMetrics');
  assert.ok(decayStart >= 0, 'decaySyslogMetrics must exist');
  const decayBlock = monSrc.substring(decayStart, decayStart + 500);
  assert.ok(decayBlock.includes('let changed = false'), 'must track whether values changed');
  assert.ok(decayBlock.includes('if (changed) markSiteDirty'), 'must only call markSiteDirty when changed');
});

// ── Duplicate MIME_TYPES removed from server.js ──────────────────────────────
test('MIME_TYPES is not duplicated in server.js', () => {
  const serverSrc = readFile('server.js');
  const mimeCount = (serverSrc.match(/const MIME_TYPES/g) || []).length;
  assert.equal(mimeCount, 0, 'server.js should not define MIME_TYPES (defined in router.js only)');
  const routerSrc = readFile('lib/router.js');
  assert.ok(routerSrc.includes('const MIME_TYPES'), 'MIME_TYPES must exist in router.js');
});

// ── Database architecture tests ──────────────────────────────────────────────
test('all Postgres queries use parameterized values (no string concatenation)', () => {
  const storageSrc = readFile('lib/storage.js');
  // Every .query() call should use $1/$2 parameterized syntax
  const queryPattern = /\.query\(\s*[`'"]([^`'"]+)/g;
  let match;
  while ((match = queryPattern.exec(storageSrc)) !== null) {
    const sql = match[1];
    // Skip simple non-parameterized queries (no user input)
    if (/^(SELECT 1|CREATE |INSERT INTO cajal_schema)/.test(sql)) continue;
    // Any query involving cajal_store with WHERE must use $1
    if (sql.includes('cajal_store') && sql.includes('WHERE')) {
      assert.ok(sql.includes('$1'), `Query must use parameterized values: ${sql.slice(0, 60)}`);
    }
  }
});

test('storage.js exports schema versioning functions', () => {
  const storageSrc = readFile('lib/storage.js');
  assert.ok(storageSrc.includes('CURRENT_SCHEMA_VERSION'), 'must export CURRENT_SCHEMA_VERSION');
  assert.ok(storageSrc.includes('runSchemaMigrations'), 'must export runSchemaMigrations');
  assert.ok(storageSrc.includes('connectWithRetry'), 'must export connectWithRetry');
  assert.ok(storageSrc.includes('purgeStaleDbRows'), 'must export purgeStaleDbRows');
});

test('initStorageBackend uses connection retry', () => {
  const storageSrc = readFile('lib/storage.js');
  const initStart = storageSrc.indexOf('async function initStorageBackend');
  assert.ok(initStart >= 0, 'initStorageBackend must exist');
  const initBlock = storageSrc.substring(initStart, initStart + 1500);
  assert.ok(initBlock.includes('connectWithRetry'), 'must use connectWithRetry instead of direct query');
  assert.ok(initBlock.includes('runSchemaMigrations'), 'must run schema migrations on startup');
});

test('.env.example documents DATABASE_SSL auto-detection', () => {
  const envExample = readFile('.env.example');
  assert.ok(envExample.includes('CAJAL_DATABASE_SSL'), 'must document CAJAL_DATABASE_SSL');
  assert.ok(envExample.includes('Auto-detect') || envExample.includes('auto-detect'), 'must mention auto-detection');
});

// ── v1.6.1 regression tests ──────────────────────────────────────────────────

test('fresh install seeds demo sites and empty devices', () => {
  const serverSrc = readFile('server.js');
  assert.match(serverSrc, /defaultData\s*=\s*\{/, 'defaultData must exist');
  assert.ok(serverSrc.includes("'site-hq'") || serverSrc.includes('"site-hq"'), 'defaultData must include Demo Firewall site');
  assert.ok(serverSrc.includes('Demo Collector'), 'defaultData must include Demo Collector site');
  assert.ok(serverSrc.includes('Demo LAN Links'), 'defaultData must include Demo LAN Links site');
  assert.match(serverSrc, /devices:\s*\[\]/, 'defaultData.devices must be empty array');
});

test('TOTP issuer is hardcoded to Cajal ICBM', () => {
  const authSrc = readFile('lib/auth.js');
  const authRoutesSrc = readFile('lib/routes/auth.js');
  assert.ok(authSrc.includes("const issuer = 'Cajal ICBM'"), 'makeTotpPayload must use Cajal ICBM issuer');
  assert.ok(authRoutesSrc.includes("const issuer = 'Cajal ICBM'"), 'QR route must use Cajal ICBM issuer');
});

test('Teams notify section is removed from site cards', () => {
  const appSrc = readFile('public/app.js');
  assert.ok(!appSrc.includes('Teams Notes'), 'Teams Notes label must not appear in card templates');
  assert.ok(!appSrc.includes('notify-readonly'), 'notify-readonly paragraph must not appear');
  assert.ok(!appSrc.includes("Teams ${notifications.enabled"), 'Teams ON/OFF toggle buttons must not appear in templates');
});

test('LAN Link Monitor card exists in app.js', () => {
  const appSrc = readFile('public/app.js');
  assert.ok(appSrc.includes('lanLinkMonitorCard'), 'lanLinkMonitorCard function must exist');
  assert.ok(appSrc.includes('LAN LINK MONITOR'), 'card must have LAN LINK MONITOR heading');
  assert.ok(appSrc.includes('lan-link-card'), 'card must use lan-link-card CSS class');
  assert.ok(appSrc.includes('lan-link-table'), 'card must contain a table');
});

test('LAN Link Monitor card has double-width CSS', () => {
  const cssSrc = readFile('public/styles.css');
  assert.ok(cssSrc.includes('.lan-link-card'), 'lan-link-card class must exist');
  assert.ok(cssSrc.includes('grid-column: span 2'), 'lan-link-card must span 2 columns');
});

test('index.html guards rendering until auth check completes', () => {
  const indexSrc = readFile('public/index.html');
  assert.ok(indexSrc.includes("fetch('/api/auth/me'"), 'must use fetch for auth guard');
  assert.ok(indexSrc.includes("visibility"), 'must hide page until auth verified');
  assert.ok(indexSrc.includes("window.location.replace('/login.html')"), 'must redirect to login.html if unauthenticated');
});

test('dead deleteDeviceDialog has been removed', () => {
  const html = readFile('public/index.html');
  assert.ok(!html.includes('id="deleteDeviceDialog"'), 'deleteDeviceDialog should be removed');
});

test('SNMP interface metrics structure includes interface fields', () => {
  const sitesSrc = readFile('lib/sites.js');
  assert.ok(sitesSrc.includes('interfaces: []'), 'snmp metrics must include interfaces array');
  assert.ok(sitesSrc.includes('interfaceCount:'), 'snmp metrics must include interfaceCount');
  assert.ok(sitesSrc.includes('lastInterfacePoll:'), 'snmp metrics must include lastInterfacePoll');
});

test('SNMP poller calls runSnmpWalk for interface table after successful uptime poll', () => {
  const monSrc = readFile('lib/monitoring.js');
  const pollerIdx = monSrc.indexOf('function startSnmpPoller');
  assert.ok(pollerIdx > 0, 'startSnmpPoller must exist');
  const pollerBlock = monSrc.slice(pollerIdx, pollerIdx + 8000);
  assert.ok(pollerBlock.includes('runSnmpWalk'), 'poller must call runSnmpWalk');
  assert.ok(pollerBlock.includes('parseIfTableWalk'), 'poller must call parseIfTableWalk');
  assert.ok(pollerBlock.includes('computeInterfaceDeltas'), 'poller must compute deltas');
  assert.ok(pollerBlock.includes('_ifTableSnapshots'), 'poller must track snapshots for delta calculation');
});

test('login page does not expose First-Time Setup link', () => {
  const loginHtml = readFile('public/login.html');
  assert.ok(!loginHtml.includes('First-Time Setup'), 'login page must not show First-Time Setup text');
});

// ── QA Review Fixes ──────────────────────────────────────────────────────────

test('error catch blocks use safe err?.message access', () => {
  const sites = readFile('lib/routes/sites.js');
  const auth = readFile('lib/routes/auth.js');
  const system = readFile('lib/routes/system.js');
  // sites.js catch blocks must use safe access
  assert.ok(!sites.match(/detail: err\.message(?!\s*\|\|)/), 'sites.js must not use bare err.message in detail');
  // auth.js must not leak Azure error_description
  assert.ok(!auth.includes('payload.error_description'), 'auth.js must not leak Azure error_description');
  // system.js must use safe access
  assert.ok(!system.match(/\$\{err\.message\}/), 'system.js must not use bare ${err.message}');
});

test('POST /api/devices validates siteId existence and IP format', () => {
  const devices = readFile('lib/routes/devices.js');
  assert.match(devices, /state\.sites\.find/, 'must validate siteId exists in state.sites');
  assert.match(devices, /net\.isIP/, 'must validate IP address format');
});

test('site name has max length validation', () => {
  const sites = readFile('lib/routes/sites.js');
  assert.match(sites, /name\.length > 255/, 'must reject site names over 255 characters');
});

test('POST /api/users returns 201 for new users', () => {
  const users = readFile('lib/routes/users.js');
  assert.match(users, /isNew \? 201 : 200/, 'must return 201 for new users, 200 for updates');
});

test('OAuth fetch has AbortController timeout', () => {
  const auth = readFile('lib/routes/auth.js');
  assert.match(auth, /AbortController/, 'OAuth token exchange must use AbortController');
  assert.match(auth, /signal:\s*abortCtl\.signal/, 'fetch must pass abort signal');
  assert.match(auth, /clearTimeout\(fetchTimer\)/, 'must clean up timeout');
});

test('OAuth state tokens are pruned on new SSO login', () => {
  const auth = readFile('lib/routes/auth.js');
  assert.match(auth, /600000/, 'OAuth state must have 10-minute TTL (600000ms)');
  assert.match(auth, /oauthState\.delete/, 'must prune expired OAuth state entries');
});

test('static file path uses path.resolve for traversal prevention', () => {
  const router = readFile('lib/router.js');
  assert.match(router, /path\.resolve\(PUBLIC_DIR/, 'must use path.resolve instead of path.join for static files');
});

test('CSP does not allow data: URIs', () => {
  const session = readFile('lib/session.js');
  assert.ok(session.includes('Content-Security-Policy'), 'CSP header must exist');
  // Find the CSP value string (spans multiple lines in setHeader call)
  const cspStart = session.indexOf("default-src 'self'");
  assert.ok(cspStart > 0, 'CSP policy string must exist');
  const cspEnd = session.indexOf('"', cspStart);
  const cspValue = session.substring(cspStart, cspEnd);
  assert.ok(!cspValue.includes('data:'), 'CSP must not allow data: URIs');
});

test('submit buttons are disabled during async form operations', () => {
  const app = readFile('public/app.js');
  // Check add device, add user, add location forms
  const deviceForm = app.substring(app.indexOf('addDeviceForm?.addEventListener'), app.indexOf('addDeviceForm?.addEventListener') + 1500);
  assert.match(deviceForm, /submitBtn\.disabled = true/, 'add device form must disable submit button');
  const userForm = app.substring(app.indexOf('addUserForm?.addEventListener'), app.indexOf('addUserForm?.addEventListener') + 800);
  assert.match(userForm, /submitBtn\.disabled = true/, 'add user form must disable submit button');
  const locationForm = app.substring(app.indexOf('addLocationForm?.addEventListener'), app.indexOf('addLocationForm?.addEventListener') + 1500);
  assert.match(locationForm, /submitBtn\.disabled = true/, 'add location form must disable submit button');
});

test('Redis operations log errors instead of silently swallowing', () => {
  const storage = readFile('lib/storage.js');
  const persistStart = storage.indexOf('function redisPersistSession');
  const deleteStart = storage.indexOf('function redisDeleteSession');
  const persistFn = storage.substring(persistStart, deleteStart);
  const deleteFn = storage.substring(deleteStart, deleteStart + 300);
  assert.ok(!persistFn.includes('.catch(() => {})'), 'redisPersistSession must not silently swallow errors');
  assert.ok(persistFn.includes('logJson'), 'redisPersistSession must log Redis errors');
  assert.ok(!deleteFn.includes('.catch(() => {})'), 'redisDeleteSession must not silently swallow errors');
  assert.ok(deleteFn.includes('logJson'), 'redisDeleteSession must log Redis errors');
});

test('Dockerfile runs as non-root user', () => {
  const dockerfile = readFile('Dockerfile');
  assert.match(dockerfile, /USER node/, 'Dockerfile must set USER node');
});

test('docker-compose cajal service has healthcheck', () => {
  const compose = readFile('docker-compose.yml');
  const cajalSection = compose.substring(compose.indexOf('cajal:'));
  assert.match(cajalSection, /healthcheck/, 'cajal service must have healthcheck');
  assert.match(cajalSection, /\/api\/health/, 'healthcheck must hit /api/health endpoint');
});

test('logout endpoint has rate limiting', () => {
  const auth = readFile('lib/routes/auth.js');
  const logoutBlock = auth.substring(auth.indexOf("'/api/auth/logout'"), auth.indexOf("'/api/auth/logout'") + 500);
  assert.match(logoutBlock, /enforceRateLimitOrSend/, 'logout must use rate limiting');
});

test('FW CHECK badge shows N/A when no firewall checks exist', () => {
  const appSrc = readFile('public/app.js');
  assert.ok(appSrc.includes("firewallValue = 'N/A'"), 'must set firewallValue to N/A when payload exists but no checks');
  assert.ok(appSrc.includes("firewallTone = 'up'"), 'must set firewallTone to up when no checks');
  assert.ok(appSrc.includes('firewallPayload && typeof firewallPayload'), 'must check firewallPayload exists before showing N/A');
});

test('LAN Link Monitor card has EDIT button', () => {
  const appSrc = readFile('public/app.js');
  assert.ok(appSrc.includes('lan-link-edit-btn'), 'must render edit button with lan-link-edit-btn class');
  assert.ok(appSrc.includes('activeLanLinkEditorSiteId'), 'must track active LAN link editor state');
  assert.ok(appSrc.includes('lan-link-name-form'), 'must render inline name edit form');
});

test('LAN Link EDIT button has CSS styling', () => {
  const cssSrc = readFile('public/styles.css');
  assert.ok(cssSrc.includes('.lan-link-edit-btn'), 'lan-link-edit-btn class must exist in CSS');
  assert.ok(cssSrc.includes('.lan-link-name-form'), 'lan-link-name-form class must exist in CSS');
});

test('ticker animation uses tuned speed (94s)', () => {
  const cssSrc = readFile('public/styles.css');
  assert.ok(cssSrc.includes('ticker-scroll 94s linear infinite'), 'ticker must use 94s animation duration');
});

test('logout uses in-app confirmation dialog not browser confirm()', () => {
  const appSrc = readFile('public/app.js');
  const start = appSrc.indexOf("authActionBtn?.addEventListener('click'");
  const logoutArea = appSrc.substring(start, start + 800);
  assert.ok(!logoutArea.includes("confirm('Are you sure"), 'must not use browser confirm() for logout');
  assert.ok(logoutArea.includes('askActionConfirm'), 'must use askActionConfirm for logout');
});

test('version check buttons use { once: true } to prevent listener leaks', () => {
  const appSrc = readFile('public/app.js');
  const checkBtn = appSrc.indexOf("getElementById('checkUpdatesBtn')");
  assert.ok(checkBtn > 0, 'checkUpdatesBtn must exist');
  const checkArea = appSrc.substring(checkBtn, checkBtn + 200);
  assert.ok(checkArea.includes('once: true'), 'checkUpdatesBtn must use { once: true }');
  const applyBtn = appSrc.indexOf("getElementById('applyUpdateBtn')");
  if (applyBtn > 0) {
    const applyArea = appSrc.substring(applyBtn, applyBtn + 200);
    assert.ok(applyArea.includes('once: true'), 'applyUpdateBtn must use { once: true }');
  }
});

test('login form disables submit button to prevent double-submit', () => {
  const loginSrc = readFile('public/login.js');
  assert.ok(loginSrc.includes('submitBtn?.disabled') || loginSrc.includes('submitBtn.disabled'), 'login form must check/set disabled on submit button');
  assert.ok(loginSrc.includes("submitBtn) submitBtn.disabled = true"), 'login submit must disable button');
  assert.ok(loginSrc.includes("submitBtn) submitBtn.disabled = false"), 'login submit must re-enable button in finally');
});

test('login.js has no dead registerBtn reference', () => {
  const loginSrc = readFile('public/login.js');
  assert.ok(!loginSrc.includes("getElementById('registerBtn')"), 'registerBtn element reference must be removed (element does not exist)');
});

test('docker-reload.sh creates .db_password file from env', () => {
  const script = readFile('docker-reload.sh');
  assert.ok(script.includes('.db_password'), 'script must reference .db_password file');
  assert.ok(script.includes("printf '%s'") || script.includes('> .db_password'), 'script must write password to .db_password');
  assert.ok(script.includes('chmod 600 .db_password'), 'script must set restrictive permissions on .db_password');
});

test('install.bat creates .db_password file from env', () => {
  const script = readFile('install.bat');
  assert.ok(script.includes('.db_password'), 'install.bat must reference .db_password file');
});

// ── LDAP module tests ─────────────────────────────────────────────────────────

test('LDAP settings HTML section exists in security tab', () => {
  const html = readFile('public/index.html');
  assert.ok(html.includes('id="ldapConfigPanel"'), 'LDAP config panel must exist');
  assert.ok(html.includes('id="ldapConfigForm"'), 'LDAP config form must exist');
  assert.ok(html.includes('id="ldapTestBtn"'), 'LDAP test button must exist');
  assert.ok(html.includes('id="ldapTestDialog"'), 'LDAP test dialog must exist');
  assert.ok(html.includes('name="serverUrl"'), 'DC server URL input must exist');
  assert.ok(html.includes('name="adminGroup"'), 'admin group input must exist');
  assert.ok(html.includes('name="monitorGroup"'), 'monitor group input must exist');
  assert.ok(html.includes('name="bindDn"'), 'bind DN input must exist');
  assert.ok(html.includes('name="bindPassword"'), 'bind password input must exist');
});

test('LDAP settings CSS classes exist', () => {
  const css = readFile('public/styles.css');
  assert.ok(css.includes('.ldap-config-form'), 'ldap-config-form class must exist');
  assert.ok(css.includes('.ldap-test-steps'), 'ldap-test-steps class must exist');
  assert.ok(css.includes('.ldap-step-ok'), 'ldap-step-ok class must exist');
  assert.ok(css.includes('.ldap-step-fail'), 'ldap-step-fail class must exist');
  assert.ok(css.includes('.ldap-user-row'), 'ldap-user-row class must exist');
});

test('LDAP frontend JS has form handler and test button', () => {
  const js = readFile('public/app.js');
  assert.ok(js.includes("ldapConfigForm?.addEventListener('submit'"), 'LDAP form submit handler must exist');
  assert.ok(js.includes("ldapTestBtn?.addEventListener('click'"), 'LDAP test button handler must exist');
  assert.ok(js.includes("ldapTestApprove?.addEventListener('click'"), 'LDAP approve handler must exist');
  assert.ok(js.includes('loadLdapSettings'), 'loadLdapSettings function must exist');
  assert.ok(js.includes('populateLdapForm'), 'populateLdapForm function must exist');
});

test('LDAP backend settings module has config persistence', () => {
  const settings = readFile('lib/settings.js');
  assert.ok(settings.includes('loadLdapConfig'), 'loadLdapConfig must be exported');
  assert.ok(settings.includes('persistLdapConfig'), 'persistLdapConfig must be exported');
  assert.ok(settings.includes('ldapConfigForClient'), 'ldapConfigForClient must be exported');
  assert.ok(settings.includes('LDAP_FILE'), 'LDAP_FILE constant must be imported');
});

test('LDAP routes exist in settings handler', () => {
  const routes = readFile('lib/routes/settings.js');
  assert.ok(routes.includes("/api/settings/ldap'"), 'GET/PATCH /api/settings/ldap route must exist');
  assert.ok(routes.includes("/api/settings/ldap/test'"), 'POST /api/settings/ldap/test route must exist');
  assert.ok(routes.includes("/api/settings/ldap/import'"), 'POST /api/settings/ldap/import route must exist');
});

test('LDAP module exists with test connection function', () => {
  const ldapModule = readFile('lib/ldap.js');
  assert.ok(ldapModule.includes('testLdapConnection'), 'testLdapConnection must be exported');
  assert.ok(ldapModule.includes('tcpPing'), 'tcpPing must exist');
  assert.ok(ldapModule.includes('ldapBind'), 'ldapBind function must exist');
  assert.ok(ldapModule.includes('resolveGroupMembers'), 'resolveGroupMembers must exist');
});

test('LDAP config loaded at server startup', () => {
  const server = readFile('server.js');
  assert.ok(server.includes('loadLdapConfig'), 'server must load LDAP config at startup');
  assert.ok(server.includes('shared.ldapRuntimeConfig'), 'server must set shared.ldapRuntimeConfig');
});

test('LDAP shared state has getter/setter', () => {
  const shared = readFile('lib/shared.js');
  assert.ok(shared.includes('ldapRuntimeConfig'), 'shared module must have ldapRuntimeConfig');
});

test('LDAP file tracked in constants', () => {
  const constants = readFile('lib/constants.js');
  assert.ok(constants.includes('LDAP_FILE'), 'LDAP_FILE must be defined in constants');
  assert.ok(constants.includes("'ldap'"), 'ldap must be in CONFIG_INTEGRITY_KEYS');
});
