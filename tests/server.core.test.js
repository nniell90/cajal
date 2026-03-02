const test = require('node:test');
const assert = require('node:assert/strict');

const { __test: core } = require('../server.js');

function makeState() {
  return {
    sites: [],
    devices: [],
    alerts: [],
    events: [],
    dirtySites: false,
    dirtyEvents: false,
    eventThrottle: new Map(),
    syslogWindows: new Map(),
    netflowTalkers: new Map(),
    netflowTemplates: new Map(),
    flowState: new Map(),
    pingState: new Map(),
    wanPingState: new Map(),
    alertSilenceUntilMs: 0,
    lastSeen: {
      ping: new Map(),
      pingSecondary: new Map(),
      syslog: new Map(),
      snmp: new Map(),
      netflow: new Map()
    },
    agentSessions: new Map(),
    agentBySite: new Map(),
    agentCommandQueue: new Map(),
    agentPending: new Map()
  };
}

function makeSite(overrides = {}) {
  return {
    id: 'site-1',
    name: 'Test Site',
    category: 'internal',
    firewall: { status: 'up', wanIp: '1.1.1.1', wanIp2: '2.2.2.2' },
    telemetry: { syslog: false, snmp: false, netflow: false },
    monitorConfig: {
      syslog: { enabled: true, sourceIp: '10.0.0.1' },
      snmp: { enabled: true },
      netflow: { enabled: true, sourceIp: '10.0.0.1' }
    },
    notifications: { enabled: false, recipients: [] },
    metrics: {
      syslog: { eventsPerSecond: 0, totalIngested: 0, lastError: '', lastErrorAt: '' },
      netflow: { topTalkers: [], lastError: '', lastErrorAt: '' }
    },
    ...overrides
  };
}

test.afterEach(() => {
  core.resetRuntimeSettingsForTests();
  core.resetSecurityStateForTests();
});

test('syslog line parser strips blanks and null bytes', () => {
  const rows = core.parseLinesFromBuffer(Buffer.from(' first \n\nsecond\0\r\n third  ', 'utf8'));
  assert.deepEqual(rows, ['first', 'second', 'third']);
});

test('syslog source matching respects enabled + sourceIp', () => {
  const state = makeState();
  const site = makeSite();
  state.sites = [site];
  const match = core.matchSiteBySourceIp(state, 'syslog', '10.0.0.1');
  assert.equal(match?.id, site.id);
  assert.equal(core.matchSiteBySourceIp(state, 'syslog', '10.0.0.9'), undefined);
});

test('syslog metrics update increments EPS and ingestion counters', () => {
  const state = makeState();
  const site = makeSite();
  const now = Date.now();

  core.updateSyslogMetrics(state, site, now, '10.0.0.1');
  core.updateSyslogMetrics(state, site, now + 200, '10.0.0.1');

  assert.equal(state.lastSeen.syslog.get(site.id), now + 200);
  assert.equal(site.metrics.syslog.eventsPerSecond, 2);
  assert.equal(site.metrics.syslog.totalIngested, 2);
  assert.equal(state.dirtySites, true);
});

test('markNetflowSeen records a netflow timestamp for matched packet traffic', () => {
  const state = makeState();
  const site = makeSite({ id: 'site-nf-seen' });
  const now = Date.now();

  core.markNetflowSeen(state, site, now);

  assert.equal(state.lastSeen.netflow.get(site.id), now);
});

test('syslog metrics decay resets stale EPS to zero', () => {
  const state = makeState();
  const site = makeSite();
  state.sites = [site];
  site.metrics.syslog.eventsPerSecond = 5;

  core.decaySyslogMetrics(state);

  assert.equal(site.metrics.syslog.eventsPerSecond, 0);
  assert.equal(state.dirtySites, true);
});

test('netflow v5 parser extracts src/dst/bytes records', () => {
  const buf = Buffer.alloc(24 + 48);
  buf.writeUInt16BE(5, 0);
  buf.writeUInt16BE(1, 2);
  const off = 24;
  buf[off + 0] = 10;
  buf[off + 1] = 0;
  buf[off + 2] = 0;
  buf[off + 3] = 1;
  buf[off + 4] = 10;
  buf[off + 5] = 0;
  buf[off + 6] = 0;
  buf[off + 7] = 2;
  buf.writeUInt32BE(12345, off + 20);

  const rows = core.parseNetflowV5(buf);
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0], { srcAddr: '10.0.0.1', dstAddr: '10.0.0.2', bytes: 12345 });
});

test('netflow v9 parser loads template and parses data set', () => {
  const buf = Buffer.alloc(60);
  buf.writeUInt16BE(9, 0);

  buf.writeUInt16BE(0, 24);
  buf.writeUInt16BE(20, 26);
  buf.writeUInt16BE(256, 28);
  buf.writeUInt16BE(3, 30);
  buf.writeUInt16BE(8, 32);
  buf.writeUInt16BE(4, 34);
  buf.writeUInt16BE(12, 36);
  buf.writeUInt16BE(4, 38);
  buf.writeUInt16BE(1, 40);
  buf.writeUInt16BE(4, 42);

  buf.writeUInt16BE(256, 44);
  buf.writeUInt16BE(16, 46);
  buf[48] = 192;
  buf[49] = 168;
  buf[50] = 1;
  buf[51] = 10;
  buf[52] = 8;
  buf[53] = 8;
  buf[54] = 8;
  buf[55] = 8;
  buf.writeUInt32BE(2048, 56);

  const templates = new Map();
  const rows = core.parseNetflowV9(buf, templates);
  assert.equal(templates.has(256), true);
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0], { srcAddr: '192.168.1.10', dstAddr: '8.8.8.8', bytes: 2048 });
});

test('netflow top talkers ranking derives Mbps fields', () => {
  const state = makeState();
  const site = makeSite({ id: 'site-nf' });
  const now = Date.now();

  state.netflowTalkers.set(site.id, new Map([
    ['10.0.0.1', [{ ts: now - 30_000, upBytes: 800000, downBytes: 0 }]],
    ['10.0.0.2', [{ ts: now - 30_000, upBytes: 200000, downBytes: 0 }]]
  ]));

  core.refreshNetflowTopTalkers(state, site, now);
  assert.equal(site.metrics.netflow.topTalkers.length, 2);
  assert.equal(site.metrics.netflow.topTalkers[0].ip, '10.0.0.1');
  assert.ok(site.metrics.netflow.topTalkers[0].mbps >= site.metrics.netflow.topTalkers[1].mbps);
});

test('snmp uptime tick formatter renders d/h/m', () => {
  assert.equal(core.formatSysUpTimeTicks(9006100), '1d 01h 01m');
});

test('smtp STARTTLS mode normalization maps aliases', () => {
  assert.equal(core.normalizeSmtpStarttlsMode('require'), 'required');
  assert.equal(core.normalizeSmtpStarttlsMode('disabled'), 'off');
  assert.equal(core.normalizeSmtpStarttlsMode(''), 'auto');
});

test('smtp config normalization picks secure/default ports and timeout bounds', () => {
  const secureCfg = core.normalizeSmtpTransportConfig({
    host: 'smtp.example.com',
    secure: 'true',
    timeoutMs: '50'
  });
  assert.equal(secureCfg.port, 465);
  assert.equal(secureCfg.secure, true);
  assert.equal(secureCfg.timeoutMs, 1000);

  const plainCfg = core.normalizeSmtpTransportConfig({
    host: 'smtp.example.com',
    secure: '0',
    port: '2525',
    timeoutMs: '25000'
  });
  assert.equal(plainCfg.port, 2525);
  assert.equal(plainCfg.secure, false);
  assert.equal(plainCfg.timeoutMs, 25000);
});

test('teams webhook normalization enforces https-only webhook URLs', () => {
  const secureUrl = core.normalizeTeamsWebhookUrl('https://example.com/power-automate/webhook');
  assert.ok(secureUrl.startsWith('https://'));
  assert.equal(core.normalizeTeamsWebhookUrl('http://example.com/webhook'), '');
  assert.equal(core.normalizeTeamsWebhookUrl('javascript:alert(1)'), '');
});

test('teams webhook retry helpers classify retryable statuses and errors', () => {
  assert.equal(core.teamsWebhookRetryableStatus(429), true);
  assert.equal(core.teamsWebhookRetryableStatus(503), true);
  assert.equal(core.teamsWebhookRetryableStatus(400), false);
  assert.equal(core.teamsWebhookRetryDelayMs(1, 300), 300);
  assert.equal(core.teamsWebhookRetryDelayMs(3, 300), 1200);
  assert.equal(core.teamsWebhookRetryableError({ statusCode: 504 }), true);
  assert.equal(core.teamsWebhookRetryableError({ name: 'AbortError' }), true);
  assert.equal(core.teamsWebhookRetryableError({ code: 'ECONNREFUSED' }), true);
  assert.equal(core.teamsWebhookRetryableError({ code: 'EINVAL' }), false);
});

test('windows agent package helpers sanitize file names and payload metadata', () => {
  const payload = Buffer.from('MZ-test-agent', 'utf8');
  const normalized = core.normalizeWindowsAgentPackageSettings({
    fileName: '../Collector Agent',
    sizeBytes: payload.length,
    uploadedAt: '2026-02-25T12:00:00.000Z',
    sha256: 'ABCDEF',
    dataBase64: `data:application/octet-stream;base64,${payload.toString('base64')}`
  });
  assert.equal(core.sanitizeWindowsAgentPackageFileName('../Collector Agent'), 'Collector_Agent.exe');
  assert.equal(normalized.fileName, 'Collector_Agent.exe');
  assert.equal(normalized.sizeBytes, payload.length);
  assert.equal(normalized.sha256, 'abcdef');
  assert.equal(core.isWindowsExeBuffer(payload), true);
  assert.equal(core.windowsAgentPackageForClient(normalized).available, true);
});

test('api token sanitization keeps valid rows and enforces role/name normalization', () => {
  const cleaned = core.sanitizeApiTokenSettings({
    tokens: [
      {
        id: 'tok-a',
        name: '  Build Agent   Token  ',
        role: 'ADMIN',
        tokenHash: 'abcdef',
        tokenPrefix: 'cajal_abcd',
        createdAt: '2026-02-25T00:00:00.000Z',
        expiresAt: '2026-03-25T00:00:00.000Z'
      },
      { id: 'tok-missing-hash', role: 'monitor' }
    ]
  });
  assert.equal(cleaned.tokens.length, 1);
  assert.equal(cleaned.tokens[0].id, 'tok-a');
  assert.equal(cleaned.tokens[0].name, 'Build Agent Token');
  assert.equal(cleaned.tokens[0].role, 'admin');
  assert.equal(core.normalizeApiTokenRole('bad-role'), 'monitor');
});

test('api token status helper detects active expired and revoked tokens', () => {
  const now = Date.parse('2026-02-25T12:00:00.000Z');
  const active = { expiresAt: '2026-02-25T12:30:00.000Z', revokedAt: '' };
  const expired = { expiresAt: '2026-02-25T11:59:59.000Z', revokedAt: '' };
  const revoked = { expiresAt: '2026-02-26T12:00:00.000Z', revokedAt: '2026-02-25T12:00:00.000Z' };
  assert.equal(core.apiTokenStatus(active, now), 'active');
  assert.equal(core.apiTokenStatus(expired, now), 'expired');
  assert.equal(core.apiTokenStatus(revoked, now), 'revoked');
  assert.equal(core.isApiTokenActive(active, now), true);
  assert.equal(core.isApiTokenActive(expired, now), false);
});

test('smtp config validation requires host and password for authenticated user', () => {
  const missingHost = core.validateSmtpTransportConfig({
    host: '',
    port: 587,
    user: '',
    pass: ''
  });
  assert.equal(missingHost.ok, false);

  const missingPass = core.validateSmtpTransportConfig({
    host: 'smtp.example.com',
    port: 587,
    user: 'mailer',
    pass: ''
  });
  assert.equal(missingPass.ok, false);
  assert.match(missingPass.detail, /CAJAL_SMTP_PASS/);
});

test('smtp transport label + address sanitization work for headers/envelope', () => {
  const cfg = core.normalizeSmtpTransportConfig({
    host: 'smtp.example.com',
    secure: '1'
  });
  assert.equal(core.smtpConfigEnabled(cfg), true);
  assert.equal(core.smtpTransportLabel(cfg), 'smtps://smtp.example.com:465');
  assert.equal(core.sanitizeMailAddress('Alerts <ops@example.com>\r\n'), 'ops@example.com');
});

test('mail-from resolution prefers explicit value then smtp user then smtp host', () => {
  assert.equal(
    core.resolveMailFrom('alerts@corp.example', { host: 'smtp.example.com', user: 'mailer@example.com' }),
    'alerts@corp.example'
  );
  assert.equal(
    core.resolveMailFrom('', { host: 'smtp.example.com', user: 'mailer@example.com' }),
    'mailer@example.com'
  );
  assert.equal(
    core.resolveMailFrom('', { host: 'relay.example.com', user: '' }),
    'cajal-alerts@relay.example.com'
  );
});

test('smtp header sanitization strips CRLF injection characters', () => {
  assert.equal(
    core.sanitizeMailHeaderValue('Alerts\r\nBCC: stealth@example.com'),
    'Alerts BCC: stealth@example.com'
  );
});

test('smtp dot-stuffing escapes leading dot lines and normalizes CRLF', () => {
  const message = '.first\nsecond\r\n..third';
  assert.equal(core.smtpDotStuffMessage(message), '..first\r\nsecond\r\n...third');
});

test('rate limiter blocks after threshold inside a single window', () => {
  const key = `rate-test-${Date.now()}`;
  const t0 = Date.parse('2026-02-25T00:00:00.000Z');
  const first = core.consumeRateLimitToken(key, 2, 60_000, t0);
  const second = core.consumeRateLimitToken(key, 2, 60_000, t0 + 1000);
  const third = core.consumeRateLimitToken(key, 2, 60_000, t0 + 2000);
  assert.equal(first.allowed, true);
  assert.equal(second.allowed, true);
  assert.equal(third.allowed, false);
  assert.ok(third.retryAfterSec >= 1);
});

test('csrf validation enforces same-origin for cookie-auth state-changing API calls', () => {
  const user = { authenticated: true, provider: 'local' };
  const url = new URL('https://app.example.com/api/sites');
  const goodReq = {
    method: 'POST',
    headers: {
      host: 'app.example.com',
      origin: 'https://app.example.com',
      'x-forwarded-proto': 'https'
    }
  };
  const badReq = {
    method: 'POST',
    headers: {
      host: 'app.example.com',
      origin: 'https://evil.example.com',
      'x-forwarded-proto': 'https'
    }
  };
  assert.equal(core.validateCsrfRequest(user, goodReq, url).ok, true);
  const denied = core.validateCsrfRequest(user, badReq, url);
  assert.equal(denied.ok, false);
  assert.equal(denied.code, 'csrf_invalid');
  assert.equal(core.validateCsrfRequest({ authenticated: true, provider: 'api-token' }, badReq, url).ok, true);
});

test('session expiry checks enforce both idle and absolute TTL', () => {
  const now = Date.parse('2026-02-25T12:00:00.000Z');
  const fresh = { createdAt: now - 1000, lastSeenAt: now - 1000 };
  const staleIdle = {
    createdAt: now - 10_000,
    lastSeenAt: now - core.constants.SESSION_IDLE_TTL_MS - 1
  };
  const staleAbsolute = {
    createdAt: now - core.constants.SESSION_TTL_MS - 1,
    lastSeenAt: now - 1000
  };
  assert.equal(core.sessionIsExpired(fresh, now), false);
  assert.equal(core.sessionIsExpired(staleIdle, now), true);
  assert.equal(core.sessionIsExpired(staleAbsolute, now), true);
});

test('security headers helper applies CSP and transport/browser hardening headers', () => {
  const headers = new Map();
  const res = {
    hasHeader: (key) => headers.has(String(key || '').toLowerCase()),
    setHeader: (key, value) => headers.set(String(key || '').toLowerCase(), String(value))
  };
  const req = {
    headers: {
      host: 'app.example.com',
      'x-forwarded-proto': 'https'
    },
    socket: { encrypted: false }
  };
  const url = new URL('https://app.example.com/');
  core.applySecurityHeaders(req, res, url);
  assert.equal(headers.get('x-frame-options'), 'DENY');
  assert.equal(headers.get('x-content-type-options'), 'nosniff');
  assert.equal(headers.get('referrer-policy'), 'no-referrer');
  assert.match(headers.get('content-security-policy'), /default-src 'self'/);
  assert.match(headers.get('strict-transport-security'), /max-age=31536000/);
});

test('smtp response parsing + capability extraction handle EHLO multiline responses', () => {
  const first = core.parseSmtpResponseLine('250-STARTTLS');
  assert.deepEqual(first, { code: 250, complete: false, text: 'STARTTLS' });
  const last = core.parseSmtpResponseLine('250 AUTH LOGIN PLAIN');
  assert.deepEqual(last, { code: 250, complete: true, text: 'AUTH LOGIN PLAIN' });

  const caps = core.smtpCapabilitiesFromResponse([
    '250-mail.example.com',
    '250-STARTTLS',
    '250-AUTH LOGIN PLAIN XOAUTH2',
    '250 SIZE 35882577'
  ]);
  assert.equal(caps.features.has('STARTTLS'), true);
  assert.equal(caps.features.has('AUTH'), true);
  assert.equal(caps.features.has('SIZE'), true);
  assert.equal(caps.authMethods.has('LOGIN'), true);
  assert.equal(caps.authMethods.has('PLAIN'), true);
  assert.equal(caps.authMethods.has('XOAUTH2'), true);
});

test('plain text email builder sanitizes headers and keeps body text', () => {
  const text = core.buildPlainTextEmailMessage({
    from: 'Cajal Alerts <alerts@example.com>\r\nBCC: hidden@example.com',
    recipients: ['ops@example.com', 'noc@example.com'],
    subject: 'Status update\r\nInjected: bad',
    body: 'line1\r\nline2'
  });
  assert.match(text, /^From: Cajal Alerts <alerts@example.com> BCC: hidden@example.com/m);
  assert.match(text, /^To: ops@example.com, noc@example.com/m);
  assert.match(text, /^Subject: Status update Injected: bad/m);
  assert.match(text, /\n\nline1\nline2\n$/);
});

test('snmp flow timeout respects poll interval multiplier', () => {
  core.setRuntimeSettingsForTests({ flowTimeoutMs: 1000, snmpPollIntervalMs: 60000 });
  assert.equal(core.protocolFlowTimeoutMs('snmp'), 120000);
});

test('runtime settings sanitizer normalizes local TOTP toggle values', () => {
  const baseline = core.sanitizeRuntimeSettings({});
  assert.equal(typeof baseline.localTotpEnabled, 'boolean');
  assert.equal(core.sanitizeRuntimeSettings({ localTotpEnabled: 'on' }).localTotpEnabled, true);
  assert.equal(core.sanitizeRuntimeSettings({ localTotpEnabled: 'off' }).localTotpEnabled, false);
  assert.equal(
    core.sanitizeRuntimeSettings({ localTotpEnabled: 'invalid-value' }).localTotpEnabled,
    baseline.localTotpEnabled
  );
});

test('local TOTP toggle follows runtime settings override', () => {
  core.resetRuntimeSettingsForTests();
  core.setRuntimeSettingsForTests({ localTotpEnabled: false });
  assert.equal(core.localTotpMfaEnabled(), false);

  core.setRuntimeSettingsForTests({ localTotpEnabled: true });
  assert.equal(core.localTotpMfaEnabled(), true);
});

test('default local user bootstrap does not assign a known default password', () => {
  const users = [];
  const changed = core.ensureDefaultLocalUsers(users);
  assert.equal(changed, true);
  const admin = users.find((row) => row.email === 'admin');
  assert.ok(admin);
  assert.equal(Boolean(admin.localAuth?.passwordHash), false);
  assert.equal(Boolean(admin.localAuth?.passwordSalt), false);
});

test('factory reset baseline keeps only bootstrap admin without local auth seed', () => {
  const users = core.factoryResetBaselineUsers();
  assert.equal(Array.isArray(users), true);
  assert.equal(users.length, 1);
  assert.equal(users[0].email, 'admin');
  assert.equal(Boolean(users[0].localAuth?.passwordHash), false);
  assert.equal(Boolean(users[0].localAuth?.totpEnabled), false);
});

test('config key strength validator enforces production-safe minimums', () => {
  assert.equal(core.validateConfigKeyStrength('').ok, false);
  assert.equal(core.validateConfigKeyStrength('short1!A').ok, false);
  assert.equal(core.validateConfigKeyStrength('alllowercasecharacters123').ok, false);
  assert.equal(core.validateConfigKeyStrength('ChangeMePassword123!').ok, false);
  assert.equal(core.validateConfigKeyStrength('Q7x!M2n#V9p$L4t@R8k^H3d%Z1w').ok, true);
});

test('user payload marks TOTP invalid when secret is undecryptable', () => {
  const user = core.sanitizeUserForClient({
    email: 'admin',
    displayName: 'Admin',
    role: 'admin',
    localAuth: {
      totpEnabled: true,
      totpSecretEncrypted: {
        iv: 'bad',
        tag: 'bad',
        data: 'bad'
      }
    }
  });
  assert.equal(user.localAuth.totpEnabled, false);
  assert.equal(user.localAuth.totpState, 'invalid');
});

test('config integrity report exposes non-healthy tracked stores', () => {
  core.resetConfigIntegrityStateForTests();
  core.setConfigIntegrityState('runtime', 'fail', 'decrypt failed');
  const report = core.getConfigIntegrityReport();
  assert.equal(report.healthy, false);
  assert.equal(report.summary.fail >= 1, true);
  const runtime = report.entries.find((row) => row.name === 'runtime');
  assert.ok(runtime);
  assert.equal(runtime.status, 'fail');
});

test('postgres pool config includes explicit production timeouts and sizing', () => {
  const cfg = core.buildPostgresPoolConfig();
  assert.equal(typeof cfg.max, 'number');
  assert.ok(cfg.max >= 2);
  assert.equal(typeof cfg.idleTimeoutMillis, 'number');
  assert.ok(cfg.idleTimeoutMillis >= 1000);
  assert.equal(typeof cfg.connectionTimeoutMillis, 'number');
  assert.ok(cfg.connectionTimeoutMillis >= 500);
  assert.equal(typeof cfg.statement_timeout, 'number');
  assert.ok(cfg.statement_timeout >= 1000);
  assert.equal(typeof cfg.query_timeout, 'number');
  assert.ok(cfg.query_timeout >= 1000);
});

test('heartbeat target normalization defaults invalid values to wan1', () => {
  assert.equal(core.normalizeHeartbeatTarget('internal'), 'internal');
  assert.equal(core.normalizeHeartbeatTarget('gateway'), 'gateway');
  assert.equal(core.normalizeHeartbeatTarget('WAN2'), 'wan2');
  assert.equal(core.normalizeHeartbeatTarget('bad-target'), 'wan1');
});

test('collector gateway resolution defaults to firewall internal IP in same category', () => {
  const state = makeState();
  const firewallSite = makeSite({
    id: 'site-fw',
    role: 'firewall',
    category: 'internal',
    internalIp: '192.168.1.1'
  });
  const collectorSite = makeSite({
    id: 'site-col',
    role: 'collector',
    category: 'internal',
    internalIp: '192.168.1.232'
  });
  state.sites = [collectorSite, firewallSite];
  assert.equal(core.resolveSiteGatewayIp(state, collectorSite), '192.168.1.1');
  assert.equal(core.resolveSiteGatewayIp(state, firewallSite), '192.168.1.1');
});

test('heartbeat freshness window honors minimum and runtime settings', () => {
  core.setRuntimeSettingsForTests({ flowTimeoutMs: 30000, pingIntervalMs: 10000 });
  assert.equal(core.currentHeartbeatFreshWindowMs(), 60000);

  core.setRuntimeSettingsForTests({ flowTimeoutMs: 180000, pingIntervalMs: 20000 });
  assert.equal(core.currentHeartbeatFreshWindowMs(), 180000);
});

test('wan test slot helpers map local timestamps to expected four-hour slots', () => {
  const sampleTs = new Date(2026, 1, 24, 16, 10, 0, 0).getTime();
  assert.equal(core.wanTestSlotHourFromTimestamp(sampleTs), 16);
  assert.equal(core.wanTestSlotLabelFromTimestamp(sampleTs), '4PM');
});

test('wan test next-slot helper snaps to boundaries and advances after boundary passes', () => {
  const inBetweenTs = new Date(2026, 1, 24, 10, 15, 30, 500).getTime();
  const nextTs = core.nextWanTestSlotTimestamp(inBetweenTs);
  const next = new Date(nextTs);
  assert.equal(next.getHours(), 12);
  assert.equal(next.getMinutes(), 0);
  assert.equal(next.getSeconds(), 0);
  assert.equal(next.getMilliseconds(), 0);

  const exactBoundaryTs = new Date(2026, 1, 24, 12, 0, 0, 0).getTime();
  assert.equal(core.nextWanTestSlotTimestamp(exactBoundaryTs), exactBoundaryTs);

  const justAfterBoundaryTs = new Date(2026, 1, 24, 12, 0, 0, 1).getTime();
  const nextAfter = new Date(core.nextWanTestSlotTimestamp(justAfterBoundaryTs));
  assert.equal(nextAfter.getHours(), 16);
  assert.equal(nextAfter.getMinutes(), 0);
});

test('speedtest summary line parser reads down/up/latency tokens', () => {
  const parsed = core.extractSpeedtestMetricsFromLines([
    'Speed test snapshot for target 8.8.8.8',
    'down=230.0 Mbps up=199.6 Mbps latency=9.0 ms'
  ]);
  assert.equal(parsed.downloadMbps, 230.0);
  assert.equal(parsed.uploadMbps, 199.6);
  assert.equal(parsed.latencyMs, 9.0);

  const parsedNa = core.extractSpeedtestMetricsFromLines([
    'down=n/a Mbps up=n/a Mbps latency=10.3 ms'
  ]);
  assert.equal(parsedNa.downloadMbps, null);
  assert.equal(parsedNa.uploadMbps, null);
  assert.equal(parsedNa.latencyMs, 10.3);
});

test('collector speedtest metric normalization falls back to command output lines', () => {
  const fromMetrics = core.normalizeCollectorSpeedtestMetrics({
    metrics: {
      speedtest: {
        target: '1.1.1.1',
        downloadMbps: 500.5,
        uploadMbps: 300.2,
        latencyMs: 7.1,
        publicIp: '203.0.113.10'
      }
    },
    lines: []
  });
  assert.equal(fromMetrics.target, '1.1.1.1');
  assert.equal(fromMetrics.downloadMbps, 500.5);
  assert.equal(fromMetrics.uploadMbps, 300.2);
  assert.equal(fromMetrics.latencyMs, 7.1);
  assert.equal(fromMetrics.publicIp, '203.0.113.10');

  const fromLines = core.normalizeCollectorSpeedtestMetrics({
    metrics: {},
    lines: [
      'Speed test snapshot for target 8.8.4.4',
      'down=210.0 Mbps up=180.0 Mbps latency=11.4 ms',
      'public_ip=198.51.100.44'
    ]
  });
  assert.equal(fromLines.target, '8.8.4.4');
  assert.equal(fromLines.downloadMbps, 210.0);
  assert.equal(fromLines.uploadMbps, 180.0);
  assert.equal(fromLines.latencyMs, 11.4);
  assert.equal(fromLines.publicIp, '198.51.100.44');
});

test('collector public-ip metric normalization supports direct metrics and output lines', () => {
  const fromMetrics = core.normalizeCollectorPublicIpMetrics({
    metrics: {
      publicIp: '203.0.113.88'
    },
    lines: []
  });
  assert.equal(fromMetrics.publicIp, '203.0.113.88');

  const fromSpeedMetric = core.normalizeCollectorPublicIpMetrics({
    metrics: {
      speedtest: {
        publicIp: '198.51.100.44'
      }
    },
    lines: []
  });
  assert.equal(fromSpeedMetric.publicIp, '198.51.100.44');

  const fromLines = core.normalizeCollectorPublicIpMetrics({
    metrics: {},
    lines: ['Collector WAN public IP probe complete.', 'public_ip=203.0.113.20']
  });
  assert.equal(fromLines.publicIp, '203.0.113.20');
});

test('derive site status combines heartbeat + telemetry state', () => {
  const state = makeState();
  const site = makeSite();
  state.pingState.set(site.id, false);
  assert.equal(core.deriveSiteStatus(state, site), 'down');

  state.pingState.set(site.id, true);
  site.monitorConfig = { syslog: { enabled: false }, snmp: { enabled: false }, netflow: { enabled: false } };
  assert.equal(core.deriveSiteStatus(state, site), 'up');

  site.monitorConfig = { syslog: { enabled: true }, snmp: { enabled: true }, netflow: { enabled: false } };
  site.telemetry = { syslog: true, snmp: false, netflow: false };
  assert.equal(core.deriveSiteStatus(state, site), 'warn');
});

test('applyFlowStatus updates protocol telemetry flags from recency', () => {
  const state = makeState();
  const site = makeSite();
  state.sites = [site];
  state.pingState.set(site.id, true);
  const now = Date.now();
  state.lastSeen.syslog.set(site.id, now);
  state.lastSeen.snmp.set(site.id, now);
  state.lastSeen.netflow.set(site.id, now - (core.constants.NETFLOW_FLOW_TIMEOUT_MIN_MS + 1000));

  core.applyFlowStatus(state);

  assert.equal(site.telemetry.syslog, true);
  assert.equal(site.telemetry.snmp, true);
  assert.equal(site.telemetry.netflow, false);
});

test('collector unsupported update detection and fallback command rendering', () => {
  assert.equal(
    core.collectorResultHasUnsupportedCommand({ lines: ['Unsupported agent command: update'] }, 'update'),
    true
  );
  const lines = core.collectorManualUpdateLines('not-a-url', '1.2.3');
  assert.ok(lines.some((line) => line.includes('/api/agent/linux/download?format=deb')));
  assert.ok(lines.some((line) => line.includes('Target agent version: 1.2.3')));
});

test('collector session presence expires after TTL', () => {
  const state = makeState();
  const site = makeSite({ id: 'collector-1' });
  const session = core.issueCollectorAgentSession(state, site, { hostname: 'raspi', version: '1.0.0' }, '10.2.3.4');
  assert.ok(session?.token);

  const present = core.getCollectorAgentPresence(state, site.id, session.lastSeenAt + 1000);
  assert.equal(present?.connected, true);
  assert.equal(present?.hostname, 'raspi');

  const expired = core.getCollectorAgentPresence(
    state,
    site.id,
    session.lastSeenAt + core.constants.COLLECTOR_AGENT_SESSION_TTL_MS + 1
  );
  assert.equal(expired, null);
});

test('collector install registration gate blocks older installs after newer lock', () => {
  const site = makeSite({
    id: 'collector-lock-1',
    role: 'collector',
    collector: {
      agentInstallLock: {
        installId: 'install-newer',
        installedAt: '2026-02-25T10:00:00.000Z',
        installedAtMs: Date.parse('2026-02-25T10:00:00.000Z')
      }
    }
  });

  const older = core.evaluateCollectorAgentInstallRegistration(site, {
    installId: 'install-older',
    installedAt: '2026-02-24T10:00:00.000Z'
  });
  assert.equal(older.allowed, false);
  assert.equal(older.reason, 'older_install');

  const newer = core.evaluateCollectorAgentInstallRegistration(site, {
    installId: 'install-newest',
    installedAt: '2026-02-26T10:00:00.000Z'
  });
  assert.equal(newer.allowed, true);
  assert.equal(newer.reason, 'newer_install');
});

test('collector install registration gate rejects missing metadata when lock exists', () => {
  const site = makeSite({
    id: 'collector-lock-2',
    role: 'collector',
    collector: {
      agentInstallLock: {
        installId: 'install-current',
        installedAt: '2026-02-25T10:00:00.000Z',
        installedAtMs: Date.parse('2026-02-25T10:00:00.000Z')
      }
    }
  });

  const noMetadata = core.evaluateCollectorAgentInstallRegistration(site, {});
  assert.equal(noMetadata.allowed, false);
  assert.equal(noMetadata.reason, 'missing_install_metadata');

  const sameInstall = core.evaluateCollectorAgentInstallRegistration(site, {
    installId: 'install-current',
    installedAt: '2026-02-25T10:00:00.000Z'
  });
  assert.equal(sameInstall.allowed, true);
  assert.equal(sameInstall.reason, 'same_install');
});

test('collector install timestamp parser handles iso and epoch seconds/ms', () => {
  const isoMs = core.parseCollectorAgentInstallTimestampMs('2026-02-25T10:00:00.000Z');
  assert.equal(isoMs, Date.parse('2026-02-25T10:00:00.000Z'));

  const secMs = core.parseCollectorAgentInstallTimestampMs(1730000000);
  assert.equal(secMs, 1730000000 * 1000);

  const rawMs = core.parseCollectorAgentInstallTimestampMs(1730000000000);
  assert.equal(rawMs, 1730000000000);
});

test('firewall ufw evaluation keeps pass when ufw inactive or unavailable', () => {
  const unavailable = core.evaluateFirewallUfwRuleStatus({
    status: 'pass',
    notes: ['Listener open on 5514/udp'],
    ufwAvailable: false,
    ufwActive: null,
    ufwAllowed: null,
    sourceIp: '10.0.0.1',
    transport: 'udp',
    port: 5514
  });
  assert.equal(unavailable.status, 'pass');
  assert.ok(unavailable.notes.some((line) => line.includes('unavailable')));

  const inactive = core.evaluateFirewallUfwRuleStatus({
    status: 'pass',
    notes: ['Listener open on 5514/udp'],
    ufwAvailable: true,
    ufwActive: false,
    ufwAllowed: null,
    sourceIp: '10.0.0.1',
    transport: 'udp',
    port: 5514
  });
  assert.equal(inactive.status, 'pass');
  assert.ok(inactive.notes.some((line) => line.includes('inactive')));
});

test('firewall ufw evaluation marks unknown when ufw access is denied', () => {
  const denied = core.evaluateFirewallUfwRuleStatus({
    status: 'pass',
    notes: ['Listener open on 5514/udp'],
    ufwAvailable: true,
    ufwAccessDenied: true,
    ufwActive: null,
    ufwAllowed: null,
    sourceIp: '10.0.0.1',
    transport: 'udp',
    port: 5514
  });
  assert.equal(denied.status, 'unknown');
  assert.ok(denied.notes.some((line) => line.includes('access denied')));
});

test('firewall ufw evaluation fails on missing allow rule when ufw active', () => {
  const blocked = core.evaluateFirewallUfwRuleStatus({
    status: 'pass',
    notes: ['Listener open on 2055/udp'],
    ufwAvailable: true,
    ufwActive: true,
    ufwAllowed: false,
    sourceIp: '10.0.0.9',
    transport: 'udp',
    port: 2055
  });
  assert.equal(blocked.status, 'fail');
  assert.ok(blocked.notes.some((line) => line.includes('Missing UFW allow rule')));
});

test('firewall check summary includes unknown status buckets', () => {
  const summary = core.summarizeChecks([
    { status: 'pass' },
    { status: 'warn' },
    { status: 'unknown' },
    { status: 'fail' }
  ]);
  assert.deepEqual(summary, { pass: 1, warn: 1, fail: 1, unknown: 1 });
});

test('retained events helper preserves all rows when pruning disabled', () => {
  const staleTs = new Date(Date.now() - 10 * 365 * 24 * 60 * 60 * 1000).toISOString();
  const rows = [
    { id: 'evt-old', ts: staleTs, classId: 101 },
    { id: 'evt-new', ts: new Date().toISOString(), classId: 101 }
  ];
  const kept = core.retainedEventsForPolicy(rows, { pruneEvents: false, nowMs: Date.now() });
  assert.equal(kept.length, 2);

  const pruned = core.retainedEventsForPolicy(rows, { pruneEvents: true, nowMs: Date.now() });
  assert.equal(pruned.some((row) => row.id === 'evt-old'), false);
  assert.equal(pruned.some((row) => row.id === 'evt-new'), true);
});

test('collector command dequeue enforces lease windows', () => {
  const state = makeState();
  const queue = core.ensureCollectorAgentQueue(state, 'collector-1');
  queue.push({ id: 'cmd-1', leaseUntil: 0, attempts: 0, lastIssuedAt: 0 });
  const now = Date.now();

  const first = core.dequeueCollectorAgentCommandForPoll(state, 'collector-1', now);
  assert.equal(first?.id, 'cmd-1');
  assert.equal(first?.attempts, 1);

  const blocked = core.dequeueCollectorAgentCommandForPoll(state, 'collector-1', now);
  assert.equal(blocked, null);

  const afterLease = core.dequeueCollectorAgentCommandForPoll(
    state,
    'collector-1',
    now + core.constants.COLLECTOR_AGENT_COMMAND_LEASE_MS + 1
  );
  assert.equal(afterLease?.id, 'cmd-1');
  assert.equal(afterLease?.attempts, 2);
});

test('api token hash uses SHA-256 and produces a consistent 64-character hex digest', () => {
  // SHA-256 produces 32 bytes = 64 hex characters; SHA-1 would be 40
  const digest = core.hashApiToken('cajal_test-token-value');
  assert.equal(typeof digest, 'string');
  assert.equal(digest.length, 64);
  assert.match(digest, /^[0-9a-f]{64}$/);

  // Same input always produces the same hash
  assert.equal(core.hashApiToken('cajal_test-token-value'), digest);

  // Different tokens produce different hashes
  assert.notEqual(core.hashApiToken('cajal_different-token'), digest);

  // Known SHA-256 digest of the string 'test' — verifies the algorithm, not just the length
  assert.equal(
    core.hashApiToken('test'),
    '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'
  );
});

test('enforceStorageRetention prunes stale events from state and marks dirty', async () => {
  // Events older than DATA_RETENTION_DAYS (default 90) should be removed
  const staleTs = new Date(Date.now() - 100 * 24 * 60 * 60 * 1000).toISOString();
  const freshTs = new Date().toISOString();
  const state = {
    events: [
      { id: 'evt-stale', ts: staleTs, classId: 101 },
      { id: 'evt-fresh', ts: freshTs, classId: 101 }
    ],
    dirtyEvents: false,
    eventThrottle: new Map()
  };

  await core.enforceStorageRetention(state, { persistEventsNow: false });

  assert.equal(state.events.some((e) => e.id === 'evt-stale'), false);
  assert.equal(state.events.some((e) => e.id === 'evt-fresh'), true);
  assert.equal(state.dirtyEvents, true);
});

test('enforceStorageRetention skips event pruning when pruneEvents is false', async () => {
  const staleTs = new Date(Date.now() - 100 * 24 * 60 * 60 * 1000).toISOString();
  const state = {
    events: [{ id: 'evt-stale', ts: staleTs, classId: 101 }],
    dirtyEvents: false,
    eventThrottle: new Map()
  };

  await core.enforceStorageRetention(state, { persistEventsNow: false, pruneEvents: false });

  assert.equal(state.events.length, 1);
  assert.equal(state.dirtyEvents, false);
});

// ── Backup round-trip ──────────────────────────────────────────────────────────

test('encryptBackupPayload + decryptBackupPayload round-trips a payload correctly', () => {
  const payload = { version: 1, sites: [{ id: 'site-1', name: 'HQ' }], devices: [] };
  const password = 'test-password-123';
  const encrypted = core.encryptBackupPayload(payload, password);
  assert.equal(encrypted.format, 'cajal-backup-v1');
  assert.ok(encrypted.kdf && encrypted.cipher, 'encrypted blob has kdf and cipher');
  const decrypted = core.decryptBackupPayload(encrypted, password);
  assert.deepEqual(decrypted, payload);
});

test('decryptBackupPayload throws on wrong password', () => {
  const payload = { version: 1, sites: [{ id: 'site-1' }], devices: [] };
  const encrypted = core.encryptBackupPayload(payload, 'correct-pass-123');
  assert.throws(() => core.decryptBackupPayload(encrypted, 'wrong-password-abc'), /error/i);
});

test('decryptBackupPayload throws on malformed backup blob', () => {
  assert.throws(() => core.decryptBackupPayload({ format: 'unknown' }, 'password'), /invalid backup file format/i);
});

test('encryptBackupPayload rejects passwords shorter than 12 chars', () => {
  assert.throws(() => core.encryptBackupPayload({}, 'short'), /at least 12/i);
});

// ── validateBackupImportPayload ────────────────────────────────────────────────

test('validateBackupImportPayload accepts a valid payload', () => {
  const payload = {
    version: 1,
    sites: [{ id: 'site-1', name: 'HQ' }],
    devices: [{ id: 'dev-1', siteId: 'site-1' }]
  };
  assert.equal(core.validateBackupImportPayload(payload), true);
});

test('validateBackupImportPayload rejects null payload', () => {
  assert.throws(() => core.validateBackupImportPayload(null), /not an object/i);
});

test('validateBackupImportPayload rejects wrong version', () => {
  assert.throws(() => core.validateBackupImportPayload({ version: 2, sites: [{ id: 'x' }], devices: [] }), /unsupported backup version/i);
});

test('validateBackupImportPayload rejects missing sites array', () => {
  assert.throws(() => core.validateBackupImportPayload({ version: 1 }), /sites field/i);
});

test('validateBackupImportPayload rejects empty sites array', () => {
  assert.throws(() => core.validateBackupImportPayload({ version: 1, sites: [], devices: [] }), /no sites/i);
});

test('validateBackupImportPayload rejects site with empty id', () => {
  assert.throws(() => core.validateBackupImportPayload({ version: 1, sites: [{ id: '' }], devices: [] }), /missing or empty id/i);
});

test('validateBackupImportPayload rejects duplicate site ids', () => {
  assert.throws(
    () => core.validateBackupImportPayload({ version: 1, sites: [{ id: 'x' }, { id: 'x' }], devices: [] }),
    /duplicate site id/i
  );
});

test('validateBackupImportPayload rejects missing devices array', () => {
  assert.throws(() => core.validateBackupImportPayload({ version: 1, sites: [{ id: 'x' }] }), /devices field/i);
});

// ── sessionIsExpired idle-timeout path ────────────────────────────────────────

test('sessionIsExpired returns false for a fresh session', () => {
  const now = Date.now();
  const session = { createdAt: now - 1000, lastSeenAt: now - 100 };
  assert.equal(core.sessionIsExpired(session, now), false);
});

test('sessionIsExpired returns true when lastSeenAt exceeds idle TTL', () => {
  const { SESSION_IDLE_TTL_MS } = core.constants;
  const now = Date.now();
  const session = {
    createdAt: now - SESSION_IDLE_TTL_MS - 2000,
    lastSeenAt: now - SESSION_IDLE_TTL_MS - 1000
  };
  assert.equal(core.sessionIsExpired(session, now), true);
});

test('sessionIsExpired returns true when absolute TTL exceeded', () => {
  const { SESSION_TTL_MS } = core.constants;
  const now = Date.now();
  const session = {
    createdAt: now - SESSION_TTL_MS - 1000,
    lastSeenAt: now - 100
  };
  assert.equal(core.sessionIsExpired(session, now), true);
});

test('sessionIsExpired returns true for null session', () => {
  assert.equal(core.sessionIsExpired(null), true);
});

// ── consumeRateLimitToken ─────────────────────────────────────────────────────

test('consumeRateLimitToken allows requests within limit', () => {
  const key = `test-rl-${Date.now()}-allow`;
  const result = core.consumeRateLimitToken(key, 5, 60_000);
  assert.equal(result.allowed, true);
  assert.equal(result.limit, 5);
});

test('consumeRateLimitToken blocks after limit is reached', () => {
  const key = `test-rl-${Date.now()}-block`;
  for (let i = 0; i < 3; i++) core.consumeRateLimitToken(key, 3, 60_000);
  const result = core.consumeRateLimitToken(key, 3, 60_000);
  assert.equal(result.allowed, false);
  assert.ok(result.retryAfterSec > 0);
});

// ── TOTP ──────────────────────────────────────────────────────────────────────

test('generateTotpSecret returns a non-empty base32 string of expected length', () => {
  const secret = core.generateTotpSecret();
  assert.ok(typeof secret === 'string' && secret.length >= 16, `expected base32 string, got: ${secret}`);
  assert.match(secret, /^[A-Z2-7]+=*$/);
});

test('totpAt returns a 6-digit string for any secret and time', () => {
  const secret = core.generateTotpSecret();
  const code = core.totpAt(secret, Math.floor(Date.now() / 1000));
  assert.match(code, /^\d{6}$/);
});

test('verifyTotp accepts the freshly generated TOTP code', () => {
  const secret = core.generateTotpSecret();
  const now = Math.floor(Date.now() / 1000);
  const code = core.totpAt(secret, now);
  assert.equal(core.verifyTotp(secret, code), true);
});

test('verifyTotp rejects a wrong code', () => {
  const secret = core.generateTotpSecret();
  assert.equal(core.verifyTotp(secret, '000000'), false);
});

test('verifyTotp rejects non-numeric input', () => {
  const secret = core.generateTotpSecret();
  assert.equal(core.verifyTotp(secret, 'abcdef'), false);
  assert.equal(core.verifyTotp(secret, ''), false);
});

// ── Webhook routing ───────────────────────────────────────────────────────────

test('webhookRoutePrefixForSite returns firewall_status for firewall role', () => {
  assert.equal(core.webhookRoutePrefixForSite({ role: 'firewall' }), 'firewall_status');
});

test('webhookRoutePrefixForSite returns collector_status for collector role', () => {
  assert.equal(core.webhookRoutePrefixForSite({ role: 'collector' }), 'collector_status');
});

test('webhookRoutePrefixForSite returns other_status for other role', () => {
  assert.equal(core.webhookRoutePrefixForSite({ role: 'other' }), 'other_status');
});

test('webhookRoutePrefixForSite falls back to firewall_status for unknown role', () => {
  assert.equal(core.webhookRoutePrefixForSite({ role: 'generic' }), 'firewall_status');
});

test('webhookRouteForStatusTransition maps down to offline route', () => {
  const site = { role: 'firewall' };
  assert.equal(core.webhookRouteForStatusTransition(site, 'up', 'down'), 'firewall_status_offline');
});

test('webhookRouteForStatusTransition maps warn to warn route', () => {
  const site = { role: 'firewall' };
  assert.equal(core.webhookRouteForStatusTransition(site, 'up', 'warn'), 'firewall_status_warn');
});

test('webhookRouteForStatusTransition maps up-from-down to restore route', () => {
  const site = { role: 'firewall' };
  assert.equal(core.webhookRouteForStatusTransition(site, 'down', 'up'), 'firewall_status_restore');
});

test('webhookRouteForStatusTransition returns empty string for up-from-up', () => {
  const site = { role: 'firewall' };
  assert.equal(core.webhookRouteForStatusTransition(site, 'up', 'up'), '');
});

test('renderWebhookMessageTemplate substitutes known context keys', () => {
  const result = core.renderWebhookMessageTemplate('Hello {{name}}!', { name: 'HQ' });
  assert.equal(result, 'Hello HQ!');
});

test('renderWebhookMessageTemplate returns empty string for missing keys', () => {
  const result = core.renderWebhookMessageTemplate('{{missing}}', {});
  assert.equal(result, '');
});

test('renderWebhookMessageTemplate handles multiple substitutions', () => {
  const result = core.renderWebhookMessageTemplate('{{a}} and {{b}}', { a: 'X', b: 'Y' });
  assert.equal(result, 'X and Y');
});

test('isWebhookRouteEnabled returns true for unknown route id (default allow)', () => {
  assert.equal(core.isWebhookRouteEnabled('nonexistent_route_id_xyz', {}), true);
});

test('isWebhookRouteEnabled returns false when section mode is never', () => {
  // Find a known route id to test section mode suppression
  const config = {
    webhookSectionModes: { firewalls: 'never' }
  };
  // firewall_status_offline is in section 'firewalls'
  assert.equal(core.isWebhookRouteEnabled('firewall_status_offline', config), false);
});

// ── deriveSiteStatus ──────────────────────────────────────────────────────────

test('deriveSiteStatus returns down when heartbeat is false', () => {
  const state = { pingState: new Map([['site-1', false]]) };
  const site = { id: 'site-1', monitorConfig: {}, telemetry: {} };
  assert.equal(core.deriveSiteStatus(state, site), 'down');
});

test('deriveSiteStatus returns up when heartbeat is true and no protocols configured', () => {
  const state = { pingState: new Map([['site-1', true]]) };
  const site = { id: 'site-1', monitorConfig: {}, telemetry: {} };
  assert.equal(core.deriveSiteStatus(state, site), 'up');
});

test('deriveSiteStatus returns warn when heartbeat true but configured protocol not flowing', () => {
  const state = { pingState: new Map([['site-1', true]]) };
  const site = {
    id: 'site-1',
    monitorConfig: { syslog: { enabled: true } },
    telemetry: { syslog: false }
  };
  assert.equal(core.deriveSiteStatus(state, site), 'warn');
});

test('deriveSiteStatus returns up when heartbeat true and all configured protocols flowing', () => {
  const state = { pingState: new Map([['site-1', true]]) };
  const site = {
    id: 'site-1',
    monitorConfig: { syslog: { enabled: true } },
    telemetry: { syslog: true }
  };
  assert.equal(core.deriveSiteStatus(state, site), 'up');
});

test('smartReadFileTail reads only the tail of large files', async () => {
  const fs = require('node:fs');
  const fsp = fs.promises;
  const os = require('node:os');
  const path = require('node:path');
  const { smartReadFileTail } = require('../lib/storage');

  const tmpFile = path.join(os.tmpdir(), `cajal-test-tail-${Date.now()}.log`);
  try {
    const lines = [];
    for (let i = 0; i < 1000; i++) lines.push(JSON.stringify({ i, msg: `line-${i}` }));
    await fsp.writeFile(tmpFile, lines.join('\n') + '\n', 'utf8');

    const stats = await fsp.stat(tmpFile);
    const smallMax = Math.floor(stats.size / 4);
    const tail = await smartReadFileTail(tmpFile, smallMax, 'utf8');

    assert.ok(tail.length < stats.size, 'tail read must be smaller than full file');
    assert.ok(tail.length > 0, 'tail read must return some data');
    const tailLines = tail.split('\n').filter(Boolean);
    assert.ok(tailLines.length < 1000, 'tail must contain fewer lines than the full file');
    assert.ok(tailLines.length > 0, 'tail must contain some lines');
    const lastParsed = JSON.parse(tailLines[tailLines.length - 1]);
    assert.equal(lastParsed.i, 999, 'last line in tail must be the last line written');
  } finally {
    await fsp.unlink(tmpFile).catch(() => {});
  }

  const fullContent = await smartReadFileTail(tmpFile + '.nonexistent', 1024, 'utf8').catch(() => '');
  assert.equal(fullContent, '', 'missing file returns empty on error');
});

test('AsyncMutex serializes concurrent operations and releases on error', async () => {
  const { AsyncMutex } = require('../lib/mutex');
  const mutex = new AsyncMutex();
  const order = [];

  // Test basic serialization: three concurrent tasks must run sequentially
  const p1 = mutex.run(async () => { order.push('a-start'); await new Promise(r => setTimeout(r, 20)); order.push('a-end'); return 'a'; });
  const p2 = mutex.run(async () => { order.push('b-start'); order.push('b-end'); return 'b'; });
  const p3 = mutex.run(async () => { order.push('c-start'); order.push('c-end'); return 'c'; });

  const [r1, r2, r3] = await Promise.all([p1, p2, p3]);
  assert.equal(r1, 'a');
  assert.equal(r2, 'b');
  assert.equal(r3, 'c');
  assert.deepStrictEqual(order, ['a-start', 'a-end', 'b-start', 'b-end', 'c-start', 'c-end'], 'tasks must run sequentially');

  // Test that mutex releases on error
  const errResult = mutex.run(async () => { throw new Error('test-error'); }).catch((e) => e.message);
  const afterResult = mutex.run(async () => 'after-error');
  assert.equal(await errResult, 'test-error', 'error must propagate');
  assert.equal(await afterResult, 'after-error', 'mutex must release after error');
});

// ── First-Time Setup Tests ──────────────────────────────────────────────────

test('bootstrap admin has no password or TOTP — forces first-time setup', () => {
  const users = [];
  core.ensureDefaultLocalUsers(users);
  const admin = users.find((u) => u.email === 'admin');
  assert.ok(admin, 'bootstrap admin must exist');
  assert.equal(admin.role, 'admin');
  assert.equal(Boolean(admin.localAuth?.passwordHash), false, 'no pre-set password hash');
  assert.equal(Boolean(admin.localAuth?.passwordSalt), false, 'no pre-set password salt');
  assert.equal(Boolean(admin.localAuth?.totpEnabled), false, 'TOTP must not be pre-enabled');
  assert.equal(admin.localAuth?.totpSecretEncrypted == null || admin.localAuth?.totpSecretEncrypted === '', true, 'no pre-set TOTP secret');
});

test('bootstrap admin is idempotent — does not duplicate on repeated calls', () => {
  const users = [];
  core.ensureDefaultLocalUsers(users);
  core.ensureDefaultLocalUsers(users);
  core.ensureDefaultLocalUsers(users);
  const admins = users.filter((u) => u.email === 'admin');
  assert.equal(admins.length, 1, 'must have exactly one admin');
});

test('sanitizeUserForClient shows passwordSet=false for bootstrap admin', () => {
  const users = [];
  core.ensureDefaultLocalUsers(users);
  const admin = users.find((u) => u.email === 'admin');
  const sanitized = core.sanitizeUserForClient(admin);
  assert.equal(sanitized.localAuth?.passwordSet, false, 'password must not be set');
  assert.equal(sanitized.localAuth?.totpEnabled, false, 'TOTP must not be enabled');
  // Sensitive fields must not leak
  assert.equal(sanitized.localAuth?.passwordHash, undefined, 'hash must not leak');
  assert.equal(sanitized.localAuth?.passwordSalt, undefined, 'salt must not leak');
  assert.equal(sanitized.localAuth?.totpSecretEncrypted, undefined, 'encrypted secret must not leak');
});

// ── Setup Token Tests ───────────────────────────────────────────────────────

test('createSetupToken returns a hex token that can be consumed', () => {
  const token = core.createSetupToken('admin', 'set_password');
  assert.ok(typeof token === 'string' && token.length >= 24, 'token must be a hex string');
  const entry = core.consumeSetupToken(token, 'set_password');
  assert.ok(entry, 'token must be consumable');
  assert.equal(entry.email, 'admin');
  assert.equal(entry.stage, 'set_password');
});

test('consumeSetupToken returns entry and route handler deletes token after use', () => {
  const token = core.createSetupToken('admin', 'set_password');
  const entry = core.consumeSetupToken(token, 'set_password');
  assert.ok(entry, 'first consume must return entry');
  // Route handlers delete the token from shared.localSetupState after use.
  // Simulate that behavior:
  require('../lib/shared').localSetupState.delete(token);
  const second = core.consumeSetupToken(token, 'set_password');
  assert.equal(second, null, 'deleted token must not be reusable');
});

test('peekSetupToken reads without consuming', () => {
  const token = core.createSetupToken('admin', 'enroll_totp', 'SECRET123');
  const first = core.peekSetupToken(token, 'enroll_totp');
  assert.ok(first, 'peek must return entry');
  assert.equal(first.secret, 'SECRET123');
  const second = core.peekSetupToken(token, 'enroll_totp');
  assert.ok(second, 'peek must not consume — second peek must succeed');
  // Cleanup
  core.consumeSetupToken(token, 'enroll_totp');
});

test('consumeSetupToken rejects wrong stage', () => {
  const token = core.createSetupToken('admin', 'set_password');
  const result = core.consumeSetupToken(token, 'enroll_totp');
  assert.equal(result, null, 'wrong stage must be rejected');
  // Cleanup — token still exists since wrong stage didn't consume it
  core.consumeSetupToken(token, 'set_password');
});

test('consumeSetupToken rejects invalid token', () => {
  const result = core.consumeSetupToken('nonexistent-token', 'set_password');
  assert.equal(result, null);
});

// ── TOTP Tests During Registration ──────────────────────────────────────────

test('generateTotpSecret returns a valid base32 string', () => {
  const secret = core.generateTotpSecret();
  assert.ok(typeof secret === 'string' && secret.length >= 16, 'secret must be a non-empty string');
  assert.match(secret, /^[A-Z2-7]+=*$/, 'secret must be valid base32');
});

test('totpAt generates a 6-digit code for a given secret and time', () => {
  const secret = core.generateTotpSecret();
  const now = Math.floor(Date.now() / 1000);
  const code = core.totpAt(secret, now);
  assert.ok(typeof code === 'string', 'code must be a string');
  assert.match(code, /^\d{6}$/, 'code must be exactly 6 digits');
});

test('verifyTotp accepts a freshly generated TOTP code', () => {
  const secret = core.generateTotpSecret();
  const now = Math.floor(Date.now() / 1000);
  const code = core.totpAt(secret, now);
  assert.equal(core.verifyTotp(secret, code), true, 'fresh code must be accepted');
});

test('verifyTotp rejects an incorrect code', () => {
  const secret = core.generateTotpSecret();
  assert.equal(core.verifyTotp(secret, '000000'), false, 'wrong code must be rejected');
});

test('verifyTotp accepts codes within the time window (±1 step)', () => {
  const secret = core.generateTotpSecret();
  const now = Math.floor(Date.now() / 1000);
  const previousStep = core.totpAt(secret, now - 30);
  const nextStep = core.totpAt(secret, now + 30);
  // At least one adjacent step should be accepted (window tolerance)
  const prevOk = core.verifyTotp(secret, previousStep);
  const nextOk = core.verifyTotp(secret, nextStep);
  assert.ok(prevOk || nextOk, 'adjacent time step codes should be accepted within window');
});

test('TOTP secret can be stored in setup token for registration flow', () => {
  const secret = core.generateTotpSecret();
  const token = core.createSetupToken('admin', 'enroll_totp', secret);
  // Simulate QR code fetch — peek should return the secret
  const entry = core.peekSetupToken(token, 'enroll_totp');
  assert.ok(entry, 'setup token must be valid');
  assert.equal(entry.secret, secret, 'secret must match');
  // Generate and verify TOTP code against the stored secret
  const now = Math.floor(Date.now() / 1000);
  const code = core.totpAt(entry.secret, now);
  assert.equal(core.verifyTotp(entry.secret, code), true, 'TOTP code must verify against stored secret');
  // Consume the token (simulating verify-totp endpoint)
  const consumed = core.consumeSetupToken(token, 'enroll_totp');
  assert.ok(consumed, 'token must be consumable');
  assert.equal(consumed.secret, secret);
});

// ── Dashboard Auth Guard Tests ──────────────────────────────────────────────

test('app.js redirects unauthenticated users to login page', () => {
  const appJs = require('fs').readFileSync(require('path').join(__dirname, '..', 'public', 'app.js'), 'utf8');
  assert.match(appJs, /if\s*\(\s*!authState\?\.user\?\.authenticated\s*\)/, 'auth guard must check authenticated flag');
  assert.match(appJs, /window\.location\.replace\(['"]\/login\.html['"]\)/, 'must redirect to /login.html');
});

test('app.js does not schedule autoRefresh when unauthenticated', () => {
  const appJs = require('fs').readFileSync(require('path').join(__dirname, '..', 'public', 'app.js'), 'utf8');
  // scheduleAutoRefresh must NOT be in a finally block
  const initMatch = appJs.match(/async function initialize\(\)[^]*?^}/m);
  if (initMatch) {
    assert.ok(!initMatch[0].includes('finally'), 'scheduleAutoRefresh must not be in a finally block');
  }
});

test('login.html does not include app.js script', () => {
  const loginHtml = require('fs').readFileSync(require('path').join(__dirname, '..', 'public', 'login.html'), 'utf8');
  assert.ok(!loginHtml.includes('app.js'), 'login.html must not load app.js to prevent redirect loops');
});

test('login.js only redirects when authenticated', () => {
  const loginJs = require('fs').readFileSync(require('path').join(__dirname, '..', 'public', 'login.js'), 'utf8');
  assert.match(loginJs, /state\?\.user\?\.authenticated/, 'login page must check authenticated before redirecting');
});

// ── Semver Comparison Tests ────────────────────────────────────────────────

const { semverNewer } = require('../lib/routes/system');

test('semverNewer returns true when latest is a higher major version', () => {
  assert.equal(semverNewer('2.0.0', '1.9.9'), true);
});

test('semverNewer returns true when latest is a higher minor version', () => {
  assert.equal(semverNewer('1.6.0', '1.5.1'), true);
});

test('semverNewer returns true when latest is a higher patch version', () => {
  assert.equal(semverNewer('1.5.2', '1.5.1'), true);
});

test('semverNewer returns false when versions are equal', () => {
  assert.equal(semverNewer('1.5.1', '1.5.1'), false);
});

test('semverNewer returns false when current is newer', () => {
  assert.equal(semverNewer('1.4.0', '1.5.1'), false);
  assert.equal(semverNewer('1.5.0', '1.5.1'), false);
  assert.equal(semverNewer('0.9.9', '1.0.0'), false);
});

test('semverNewer handles missing or empty versions gracefully', () => {
  assert.equal(semverNewer('', '1.0.0'), false);
  assert.equal(semverNewer(null, '1.0.0'), false);
  assert.equal(semverNewer(undefined, '1.0.0'), false);
  assert.equal(semverNewer('1.0.0', ''), true);
  assert.equal(semverNewer('1.0.0', null), true);
});

test('semverNewer handles partial version strings', () => {
  assert.equal(semverNewer('2', '1.9.9'), true);
  assert.equal(semverNewer('1.5', '1.4.9'), true);
  assert.equal(semverNewer('1', '1.0.0'), false);
});

// ── Account Lockout Expiry Tests ───────────────────────────────────────────

test('account lockout expires after cooldown period', () => {
  const email = 'lockout-expiry-test@example.com';
  core.clearLoginAccountFailures(email);

  // Trigger lockout (8 failures at threshold)
  const baseTime = Date.now();
  let result;
  for (let i = 0; i < 8; i++) {
    result = core.recordLoginAccountFailure(email, baseTime);
  }
  assert.equal(result.locked, true, 'account must be locked after 8 failures');

  // Check still locked immediately
  const stillLocked = core.getLoginAccountLockState(email, baseTime + 1000);
  assert.equal(stillLocked.locked, true, 'must still be locked after 1 second');
  assert.ok(stillLocked.retryAfterSec > 0, 'retryAfterSec must be positive');

  // Check unlocked after 15 minutes + 1 second
  const unlocked = core.getLoginAccountLockState(email, baseTime + 15 * 60 * 1000 + 1000);
  assert.equal(unlocked.locked, false, 'account must unlock after cooldown');

  core.clearLoginAccountFailures(email);
});

test('successful login clears lockout state', () => {
  const email = 'lockout-clear-test@example.com';
  core.clearLoginAccountFailures(email);

  for (let i = 0; i < 8; i++) {
    core.recordLoginAccountFailure(email);
  }
  const locked = core.getLoginAccountLockState(email);
  assert.equal(locked.locked, true);

  core.clearLoginAccountFailures(email);
  const cleared = core.getLoginAccountLockState(email);
  assert.equal(cleared.locked, false, 'lockout must be cleared');
  assert.equal(cleared.failures, 0, 'failure count must be zero');
});

// ── TOTP Replay Prevention Tests ───────────────────────────────────────────

test('verifyTotp rejects non-numeric and short codes', () => {
  const secret = core.generateTotpSecret();
  assert.equal(core.verifyTotp(secret, 'abcdef'), false, 'alphabetic code rejected');
  assert.equal(core.verifyTotp(secret, '12345'), false, '5-digit code rejected');
  assert.equal(core.verifyTotp(secret, '1234567'), false, '7-digit code rejected');
  assert.equal(core.verifyTotp(secret, ''), false, 'empty code rejected');
  assert.equal(core.verifyTotp(secret, null), false, 'null code rejected');
});

test('auth.js implements TOTP replay prevention via totpLastUsedStep', () => {
  const authSrc = require('fs').readFileSync(require('path').join(__dirname, '..', 'lib', 'routes', 'auth.js'), 'utf8');
  // Must check totpLastUsedStep map before accepting TOTP
  assert.ok(authSrc.includes('totpLastUsedStep'), 'auth must track totpLastUsedStep');
  assert.ok(authSrc.includes('TOTP code already used'), 'auth must reject replayed TOTP codes');
  // Must persist step to user record
  assert.ok(authSrc.includes('user.localAuth.totpLastUsedStep'), 'must persist step to user record');
});

// ── Login Response Shape Tests ─────────────────────────────────────────────

test('login route returns set_password for admin without password', () => {
  const authSrc = require('fs').readFileSync(require('path').join(__dirname, '..', 'lib', 'routes', 'auth.js'), 'utf8');
  // When user has no password, login must return { next: 'set_password', setupToken }
  assert.ok(authSrc.includes("next: 'set_password'"), 'must return set_password stage for passwordless users');
  // When user needs TOTP enrollment, must return { next: 'enroll_totp', setupToken, ... }
  assert.ok(authSrc.includes("next: 'enroll_totp'"), 'must return enroll_totp stage');
  // When user has TOTP enabled and password correct but no totp code sent, must return { next: 'verify_totp' }
  assert.ok(authSrc.includes("next: 'verify_totp'"), 'must return verify_totp stage');
});

test('unknown user login returns same shape as passwordless user (anti-enumeration)', () => {
  const authSrc = require('fs').readFileSync(require('path').join(__dirname, '..', 'lib', 'routes', 'auth.js'), 'utf8');
  // Both unknown users and passwordless users must get { next: 'set_password', setupToken: ... }
  // The unknown-user path creates a dummy token to match the response shape
  assert.ok(authSrc.includes('dummyToken') || authSrc.includes('dummy'), 'must use dummy token for unknown users');
});

// ── Password Verification Tests ────────────────────────────────────────────

test('hashPassword and verifyPassword round-trip correctly', () => {
  const { hashPassword, verifyPassword } = require('../lib/auth');
  const result = hashPassword('MySecurePassword123!');
  assert.ok(result.hash, 'hash must exist');
  assert.ok(result.salt, 'salt must exist');
  assert.ok(result.iterations > 0, 'iterations must be positive');

  assert.equal(verifyPassword('MySecurePassword123!', {
    passwordHash: result.hash,
    passwordSalt: result.salt,
    passwordIterations: result.iterations
  }), true, 'correct password must verify');

  assert.equal(verifyPassword('WrongPassword', {
    passwordHash: result.hash,
    passwordSalt: result.salt,
    passwordIterations: result.iterations
  }), false, 'wrong password must fail');
});

test('verifyPassword uses timing-safe comparison', () => {
  const authSrc = require('fs').readFileSync(require('path').join(__dirname, '..', 'lib', 'auth.js'), 'utf8');
  assert.ok(authSrc.includes('timingSafeEqual'), 'password comparison must use crypto.timingSafeEqual');
});

test('verifyPassword returns false when no hash/salt stored', () => {
  const { verifyPassword } = require('../lib/auth');
  assert.equal(verifyPassword('password', {}), false, 'empty localAuth must fail');
  assert.equal(verifyPassword('password', { passwordHash: '', passwordSalt: '' }), false);
  assert.equal(verifyPassword('password', undefined), false);
});

// ── Setup Flow Integration Tests ───────────────────────────────────────────

test('full setup flow: bootstrap → set password → TOTP enroll lifecycle', () => {
  const shared = require('../lib/shared');
  const { hashPassword, ensureDefaultLocalUsers, resolveTotpSecretState } = require('../lib/auth');
  const { encryptJson } = require('../lib/crypto');

  // Step 1: Bootstrap admin — no password, no TOTP
  const users = [];
  ensureDefaultLocalUsers(users);
  const admin = users.find(u => u.email === 'admin');
  assert.ok(admin, 'admin must exist');
  assert.equal(Boolean(admin.localAuth.passwordHash), false);

  // Step 2: Login as admin (no password) → get setup token
  const token1 = core.createSetupToken('admin', 'set_password');
  assert.ok(token1);

  // Step 3: Set password via setup token
  const entry = core.consumeSetupToken(token1, 'set_password');
  assert.ok(entry);
  assert.equal(entry.email, 'admin');
  const hashed = hashPassword('TestPassword123');
  admin.localAuth.passwordHash = hashed.hash;
  admin.localAuth.passwordSalt = hashed.salt;
  admin.localAuth.passwordIterations = hashed.iterations;
  admin.localAuth.passwordChangedAt = new Date().toISOString();

  // Step 4: Check TOTP state — should need enrollment
  const totpState = resolveTotpSecretState(admin.localAuth);
  assert.equal(totpState.state, 'enroll', 'TOTP must require enrollment after password set');

  // Step 5: Create TOTP enrollment token
  const enrollSecret = core.generateTotpSecret();
  const token2 = core.createSetupToken('admin', 'enroll_totp', enrollSecret);

  // Step 6: Verify TOTP code
  const now = Math.floor(Date.now() / 1000);
  const code = core.totpAt(enrollSecret, now);
  assert.equal(core.verifyTotp(enrollSecret, code), true);

  // Step 7: Persist TOTP enrollment
  const enrollEntry = core.consumeSetupToken(token2, 'enroll_totp');
  assert.ok(enrollEntry);
  admin.localAuth.totpSecretEncrypted = encryptJson({ secret: enrollSecret });
  admin.localAuth.totpEnabled = true;
  admin.localAuth.totpChangedAt = new Date().toISOString();

  // Step 8: Verify TOTP state is now 'verify' (enrolled)
  const finalState = resolveTotpSecretState(admin.localAuth);
  assert.equal(finalState.state, 'verify', 'TOTP must be in verify state after enrollment');
  assert.ok(finalState.secret, 'decrypted secret must be recoverable');

  // Cleanup
  shared.localSetupState.delete(token1);
  shared.localSetupState.delete(token2);
});

// ── Login.html Redirect Logic Tests ────────────────────────────────────────

test('auth route only redirects /login.html for authenticated users', () => {
  const authSrc = require('fs').readFileSync(require('path').join(__dirname, '..', 'lib', 'routes', 'auth.js'), 'utf8');
  // Must check requestUser.authenticated before redirecting away from /login.html
  const loginHtmlBlock = authSrc.substring(
    authSrc.indexOf("url.pathname === '/login.html'"),
    authSrc.indexOf("url.pathname === '/login.html'") + 200
  );
  assert.ok(loginHtmlBlock.includes('authenticated'), '/login.html redirect must check authentication status');
  assert.ok(loginHtmlBlock.includes('return false'), 'unauthenticated users must fall through to static file server');
});

test('/api/auth/me does not have rate limiting', () => {
  const authSrc = require('fs').readFileSync(require('path').join(__dirname, '..', 'lib', 'routes', 'auth.js'), 'utf8');
  // Find the /api/auth/me handler block
  const meStart = authSrc.indexOf("url.pathname === '/api/auth/me'");
  const meEnd = authSrc.indexOf("url.pathname === '/api/auth/local/login'");
  const meBlock = authSrc.substring(meStart, meEnd);
  assert.ok(!meBlock.includes('enforceRateLimitOrSend'), '/api/auth/me must not be rate-limited (causes redirect loops)');
});
