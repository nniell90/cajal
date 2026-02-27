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
  assert.match(html, /class="version-label-inline">Version 1\.4</);
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

test('login registration dialog keeps staged auth controls and disables native form blocking', () => {
  const html = readFile('public/login.html');
  assert.match(html, /id="registerForm"[^>]*novalidate/);
  assert.match(html, /id="registerPasswordWrap"/);
  assert.match(html, /id="registerTotpWrap"/);
  assert.match(html, /id="registerQrWrap"/);
});

test('router enforces rate limit on update/apply before calling Watchtower', () => {
  const router = readFile('lib/router.js');
  // enforceRateLimitOrSend must appear before the Watchtower http.request call within the update/apply block
  const applyStart = router.indexOf("url.pathname === '/api/system/update/apply'");
  assert.ok(applyStart >= 0, 'update/apply route not found in router');
  const applyBlock = router.slice(applyStart, applyStart + 800);
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
  const router = readFile('lib/router.js');
  const checkBlock = router.slice(
    router.indexOf("url.pathname === '/api/system/version/check'"),
    router.indexOf("url.pathname === '/api/system/update/apply'")
  );
  assert.match(checkBlock, /watchtowerReady/, 'version check response must include watchtowerReady');
  assert.match(checkBlock, /Boolean\(WATCHTOWER_URL && WATCHTOWER_TOKEN\)/, 'watchtowerReady must check both URL and TOKEN');
});

test('update/apply clears version check cache on success', () => {
  const router = readFile('lib/router.js');
  const applyStart = router.indexOf("url.pathname === '/api/system/update/apply'");
  const applyBlock = router.slice(applyStart, applyStart + 2500);
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
