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
  assert.match(html, /<span>16\. API<\/span>/);
  assert.match(html, /id="apiTokenForm"/);
  assert.match(html, /id="apiTokenList"/);
});

test('api section includes windows agent exe package controls', () => {
  const html = readFile('public/index.html');
  assert.match(html, /id="windowsAgentPackageForm"/);
  assert.match(html, /id="windowsAgentPackageFile"/);
  assert.match(html, /id="windowsAgentPackageUploadBtn"/);
  assert.match(html, /id="windowsAgentPackageDeleteBtn"/);
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

test('backup password minimum is 12 characters', () => {
  const cryptoFile = readFile('lib/crypto.js');
  assert.match(cryptoFile, /pass\.length < 12/, 'backup password minimum must be 12');
  const html = readFile('public/index.html');
  assert.match(html, /backupPasswordInput.*minlength="12"/, 'backup input must have minlength 12');
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

test('welcome dialog is present with correct structure and dismiss/help controls', () => {
  const html = readFile('public/index.html');
  assert.match(html, /id="welcomeDialog"/);
  assert.match(html, /id="welcomeHelpBtn"/);
  assert.match(html, /id="welcomeDismissBtn"/);
  assert.match(html, /Welcome to Cajal ICBM/);
});

test('system health panel includes version check section placeholder', () => {
  const html = readFile('public/index.html');
  assert.match(html, /id="versionCheckSection"/);
});

test('app.js includes welcome dialog and version check functions', () => {
  const js = readFile('public/app.js');
  assert.match(js, /function maybeShowWelcomeDialog/);
  assert.match(js, /function dismissWelcomeDialog/);
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

test('setup wizard dialog is present with correct structure', () => {
  const html = readFile('public/index.html');
  assert.match(html, /id="setupWizardDialog"/);
  assert.match(html, /id="wizardStep1"/);
  assert.match(html, /id="wizardStep2"/);
  assert.match(html, /id="wizardOrgName"/);
  assert.match(html, /id="wizardStep1Next"/);
  assert.match(html, /id="wizardSkipAll"/);
  assert.match(html, /id="wizardFinish"/);
});

test('app.js includes setup wizard functions and state', () => {
  const js = readFile('public/app.js');
  assert.match(js, /function maybeShowSetupWizard/);
  assert.match(js, /function markWizardComplete/);
  assert.match(js, /setupWizardCompleted/);
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
  assert.match(constants, /WATCHTOWER_URL.*'http:\/\/cajal-watchtower:8080'/, 'WATCHTOWER_URL default');
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
  const snmpSection = monitoring.slice(fnIdx, fnIdx + 6000);
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
  assert.match(server, /headersTimeout\s*=\s*10000/, 'server must set headersTimeout');
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
