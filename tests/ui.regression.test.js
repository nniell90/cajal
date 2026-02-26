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
  assert.match(html, /class="version-label-inline">Version 1\.1</);
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

test('applyUpdate requires user confirmation before triggering restart', () => {
  const js = readFile('public/app.js');
  // confirm() call must appear before updateInProgress = true inside applyUpdate
  const fnStart = js.indexOf('async function applyUpdate');
  assert.ok(fnStart >= 0, 'applyUpdate function not found');
  const fnBody = js.slice(fnStart, fnStart + 400);
  const confirmPos = fnBody.indexOf('confirm(');
  const progressPos = fnBody.indexOf('updateInProgress = true');
  assert.ok(confirmPos >= 0, 'confirm() not found in applyUpdate');
  assert.ok(confirmPos < progressPos, 'confirm() must come before setting updateInProgress');
});
