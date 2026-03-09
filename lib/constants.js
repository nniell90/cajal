'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const { URL } = require('url');

function loadEnvFile(filePath) {
  if (!fs.existsSync(filePath)) return;
  let raw = '';
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch {
    return;
  }
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const match = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!match) continue;
    const key = match[1];
    if (process.env[key]) continue;
    let value = match[2] || '';
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    process.env[key] = value;
  }
}

loadEnvFile(path.join(__dirname, '..', '.env'));

// ── App version ───────────────────────────────────────────────────────────────
let APP_VERSION = '1.0.0';
try {
  APP_VERSION = String(require('../package.json')?.version || APP_VERSION);
} catch {
  // Keep default version when package.json is unavailable.
}

// ── Helper functions (must be defined before constants that call them) ────────

function parseBooleanFlag(value, fallback = false) {
  const text = String(value ?? '').trim().toLowerCase();
  if (!text) return fallback;
  if (['1', 'true', 'yes', 'on'].includes(text)) return true;
  if (['0', 'false', 'no', 'off'].includes(text)) return false;
  return fallback;
}

function normalizeSmtpStarttlsMode(value = 'auto') {
  const text = String(value ?? '').trim().toLowerCase();
  if (!text) return 'auto';
  if (['required', 'require', 'force'].includes(text)) return 'required';
  if (['off', 'disable', 'disabled', 'false', 'no', '0'].includes(text)) return 'off';
  return 'auto';
}

function normalizeSmtpTransportConfig(input = {}) {
  const secure = parseBooleanFlag(input.secure, false);
  const rawPort = Number(input.port || 0);
  const defaultPort = secure ? 465 : 587;
  const port = Number.isFinite(rawPort) && rawPort > 0 && rawPort <= 65535 ? Math.floor(rawPort) : defaultPort;
  const timeoutRaw = Number(input.timeoutMs || 0);
  const timeoutMs = Number.isFinite(timeoutRaw) && timeoutRaw > 0
    ? Math.max(1000, Math.min(120000, Math.floor(timeoutRaw)))
    : 5000;
  return {
    host: String(input.host || '').trim(),
    port,
    secure,
    starttls: normalizeSmtpStarttlsMode(input.starttls || 'auto'),
    user: String(input.user || '').trim(),
    pass: String(input.pass || ''),
    allowInvalidCert: parseBooleanFlag(input.allowInvalidCert, false),
    timeoutMs,
    heloName: String(input.heloName || os.hostname() || 'localhost').trim() || 'localhost'
  };
}

function smtpConfigEnabled(config = SMTP_TRANSPORT_CONFIG) {
  return Boolean(String(config.host || '').trim());
}

function smtpTransportLabel(config = SMTP_TRANSPORT_CONFIG) {
  const scheme = config.secure ? 'smtps' : 'smtp';
  return `${scheme}://${config.host || 'n/a'}:${config.port || 0}`;
}

function sanitizeMailAddress(value = '') {
  const raw = String(value || '').trim();
  const angleMatch = raw.match(/<([^>]+)>/);
  const candidate = angleMatch ? angleMatch[1] : raw;
  return candidate.replace(/[\r\n<>]/g, '').trim();
}

function resolveMailFrom(rawValue = '', config = SMTP_TRANSPORT_CONFIG) {
  const configured = sanitizeMailAddress(rawValue);
  if (configured && configured.includes('@')) return configured;

  const userAddress = sanitizeMailAddress(config?.user || '');
  if (userAddress && userAddress.includes('@')) return userAddress;

  const hostRaw = String(config?.host || '').trim().toLowerCase();
  const host = hostRaw.split(':')[0].replace(/[^a-z0-9.-]/g, '');
  if (host && host !== 'localhost' && host.includes('.')) {
    return `cajal-alerts@${host}`;
  }
  return 'cajal-alerts@localhost';
}

function normalizeTeamsWebhookUrl(value = '') {
  const raw = String(value || '').trim();
  if (!raw) return '';
  try {
    const parsed = new URL(raw);
    if (parsed.protocol !== 'https:') return '';
    return parsed.toString();
  } catch {
    return '';
  }
}

function teamsWebhookEnabled(url = '') {
  return Boolean(normalizeTeamsWebhookUrl(url));
}

function normalizeTeamsWebhookTimeoutMs(value = 8000, fallback = 8000) {
  const raw = Number(value);
  if (Number.isFinite(raw) && raw >= 1000) {
    return Math.max(1000, Math.min(120000, Math.floor(raw)));
  }
  const fallbackRaw = Number(fallback);
  if (Number.isFinite(fallbackRaw) && fallbackRaw >= 1000) {
    return Math.max(1000, Math.min(120000, Math.floor(fallbackRaw)));
  }
  return 8000;
}

// ── Ports and intervals ───────────────────────────────────────────────────────
const PORT = Number(process.env.PORT || 4000);
const HTTPS_PORT = Number(process.env.CAJAL_HTTPS_PORT || 4443);
const SYSLOG_UDP_PORT = Number(process.env.CAJAL_SYSLOG_UDP_PORT || 5514);
const SYSLOG_TCP_PORT = Number(process.env.CAJAL_SYSLOG_TCP_PORT || 5514);
const NETFLOW_PORT = Number(process.env.CAJAL_NETFLOW_PORT || 2055);
const FLOW_TIMEOUT_MS = Number(process.env.CAJAL_FLOW_TIMEOUT_MS || 120000);
const SYSLOG_FLOW_TIMEOUT_MIN_MS = Number(process.env.CAJAL_SYSLOG_FLOW_TIMEOUT_MIN_MS || 15 * 60 * 1000);
const NETFLOW_FLOW_TIMEOUT_MIN_MS = Number(process.env.CAJAL_NETFLOW_FLOW_TIMEOUT_MIN_MS || 15 * 60 * 1000);
const SNMP_POLL_INTERVAL_MS = Number(process.env.CAJAL_SNMP_POLL_INTERVAL_MS || 60000);
const PING_INTERVAL_MS = Number(process.env.CAJAL_PING_INTERVAL_MS || 45000);
const GLOBAL_DATA_REFRESH_MS = Number(process.env.CAJAL_GLOBAL_REFRESH_MS || 60 * 1000);
const NETFLOW_TOP_WINDOW_MS = Number(process.env.CAJAL_NETFLOW_TOP_WINDOW_MS || 30 * 60 * 1000);
const UPTIME_SAMPLE_INTERVAL_MS = Number(process.env.CAJAL_UPTIME_SAMPLE_INTERVAL_MS || 5 * 60 * 1000);
const WAN_TEST_INTERVAL_MS = Number(process.env.CAJAL_WAN_TEST_INTERVAL_MS || 4 * 60 * 60 * 1000);
const LOCATION_PING_MONITOR_MAX = Number(process.env.CAJAL_LOCATION_PING_MONITOR_MAX || 5);
const LOCATION_PING_MONITOR_POLL_INTERVAL_MS = Number(process.env.CAJAL_LOCATION_PING_MONITOR_POLL_INTERVAL_MS || 60 * 1000);
const WAN_TEST_SLOT_INTERVAL_MS = 4 * 60 * 60 * 1000;
const WAN_PUBLIC_IP_POLL_INTERVAL_MS = Math.max(
  15 * 1000,
  Number(process.env.CAJAL_WAN_PUBLIC_IP_POLL_INTERVAL_MS || 60 * 1000)
);
const WAN_TEST_RECOVERY_INTERVAL_MS = Math.max(
  60 * 1000,
  Number(process.env.CAJAL_WAN_TEST_RECOVERY_INTERVAL_MS || 60 * 1000)
);
const WAN_TEST_SLOT_LABEL_BY_HOUR = Object.freeze({
  0: '12AM',
  4: '4AM',
  8: '8AM',
  12: '12PM',
  16: '4PM',
  20: '8PM'
});
const GLOBAL_CLOCK_TIMEZONE = String(process.env.CAJAL_GLOBAL_CLOCK_TIMEZONE || 'UTC').trim() || 'UTC';
const GLOBAL_CLOCK_HOUR_MODE = String(process.env.CAJAL_GLOBAL_CLOCK_HOUR_MODE || '24h').trim().toLowerCase() === '12h' ? '12h' : '24h';
const ALERT_SILENCE_DURATION_MS = Number(process.env.CAJAL_ALERT_SILENCE_MS || 15 * 60 * 1000);
const WAN_TEST_HISTORY = Number(process.env.CAJAL_WAN_TEST_HISTORY || 6);
const SESSION_TTL_MS = Number(process.env.CAJAL_SESSION_TTL_MS || 8 * 60 * 60 * 1000);
const SESSION_IDLE_TTL_MS = Math.max(
  60 * 1000,
  Math.min(
    SESSION_TTL_MS,
    Number(process.env.CAJAL_SESSION_IDLE_TTL_MS || (30 * 60 * 1000))
  )
);
const SESSION_RENEW_INTERVAL_MS = Math.max(
  30 * 1000,
  Math.min(SESSION_TTL_MS, Number(process.env.CAJAL_SESSION_RENEW_INTERVAL_MS || (5 * 60 * 1000)))
);
const FORCE_SECURE_COOKIES = String(process.env.CAJAL_FORCE_SECURE_COOKIES || '0').trim() !== '0';
const LOGIN_RATE_LIMIT_MAX = Math.max(3, Math.min(200, Number(process.env.CAJAL_LOGIN_RATE_LIMIT_MAX || 20)));
const LOGIN_RATE_LIMIT_WINDOW_MS = Math.max(5 * 1000, Math.min(60 * 60 * 1000, Number(process.env.CAJAL_LOGIN_RATE_LIMIT_WINDOW_MS || (5 * 60 * 1000))));
const LOGIN_ACCOUNT_FAILURE_THRESHOLD = Math.max(3, Math.min(50, Number(process.env.CAJAL_LOGIN_ACCOUNT_FAILURE_THRESHOLD || 8)));
const LOGIN_ACCOUNT_FAILURE_WINDOW_MS = Math.max(30 * 1000, Math.min(24 * 60 * 60 * 1000, Number(process.env.CAJAL_LOGIN_ACCOUNT_FAILURE_WINDOW_MS || (15 * 60 * 1000))));
const LOGIN_ACCOUNT_LOCK_MS = Math.max(30 * 1000, Math.min(24 * 60 * 60 * 1000, Number(process.env.CAJAL_LOGIN_ACCOUNT_LOCK_MS || (15 * 60 * 1000))));
const PUBLIC_STATUS_RATE_LIMIT_MAX = Math.max(30, Math.min(2000, Number(process.env.CAJAL_PUBLIC_STATUS_RATE_LIMIT_MAX || 120)));
const PUBLIC_STATUS_RATE_LIMIT_WINDOW_MS = Math.max(5 * 1000, Math.min(60 * 60 * 1000, Number(process.env.CAJAL_PUBLIC_STATUS_RATE_LIMIT_WINDOW_MS || (60 * 1000))));
const API_TOKEN_RATE_LIMIT_MAX = Math.max(1, Math.min(200, Number(process.env.CAJAL_API_TOKEN_RATE_LIMIT_MAX || 30)));
const API_TOKEN_RATE_LIMIT_WINDOW_MS = Math.max(5 * 1000, Math.min(60 * 60 * 1000, Number(process.env.CAJAL_API_TOKEN_RATE_LIMIT_WINDOW_MS || (10 * 60 * 1000))));
const WEBHOOK_TEST_RATE_LIMIT_MAX = Math.max(1, Math.min(200, Number(process.env.CAJAL_WEBHOOK_TEST_RATE_LIMIT_MAX || 20)));
const WEBHOOK_TEST_RATE_LIMIT_WINDOW_MS = Math.max(5 * 1000, Math.min(60 * 60 * 1000, Number(process.env.CAJAL_WEBHOOK_TEST_RATE_LIMIT_WINDOW_MS || (10 * 60 * 1000))));
const LOCAL_SETUP_TTL_MS = Number(process.env.CAJAL_LOCAL_SETUP_TTL_MS || 10 * 60 * 1000);
const PASSWORD_HASH_ITERATIONS = Number(process.env.CAJAL_PASSWORD_HASH_ITERATIONS || 210000);
const LOCAL_TOTP_ENABLED = String(process.env.CAJAL_LOCAL_TOTP_ENABLED || '1').trim() !== '0';
const MIN_CONFIG_KEY_LENGTH = Math.max(16, Math.min(256, Number(process.env.CAJAL_CONFIG_KEY_MIN_LENGTH || 20) || 20));
const API_TOKEN_MAX_COUNT = Math.max(1, Math.min(500, Math.floor(Number(process.env.CAJAL_API_TOKEN_MAX_COUNT || 200) || 200)));
const API_TOKEN_MAX_LIFETIME_DAYS = Math.max(1, Math.min(3650, Math.floor(Number(process.env.CAJAL_API_TOKEN_MAX_LIFETIME_DAYS || 90) || 90)));
const API_TOKEN_MAX_LIFETIME_MS = API_TOKEN_MAX_LIFETIME_DAYS * 24 * 60 * 60 * 1000;
const API_TOKEN_MAX_IP_ALLOWLIST = Math.max(0, Math.min(128, Math.floor(Number(process.env.CAJAL_API_TOKEN_MAX_IP_ALLOWLIST || 32) || 32)));
const EVENT_RETENTION = Number(process.env.CAJAL_EVENT_RETENTION || 5000);
const SITES_PERSIST_INTERVAL_MS = Number(process.env.CAJAL_SITES_PERSIST_INTERVAL_MS || 15000);
const EVENTS_PERSIST_INTERVAL_MS = Number(process.env.CAJAL_EVENTS_PERSIST_INTERVAL_MS || 10000);
const BACKUP_KDF_ITERATIONS = Number(process.env.CAJAL_BACKUP_KDF_ITERATIONS || 210000);
const ERROR_LOG_MAX_BYTES = Number(process.env.CAJAL_ERROR_LOG_MAX_BYTES || 5 * 1024 * 1024);
const ERROR_LOG_MAX_LINES = Number(process.env.CAJAL_ERROR_LOG_MAX_LINES || 2000);
const DIAGNOSTIC_LOG_MAX_BYTES = Number(process.env.CAJAL_DIAGNOSTIC_LOG_MAX_BYTES || 5 * 1024 * 1024);
const DIAGNOSTIC_LOG_MAX_LINES = Number(process.env.CAJAL_DIAGNOSTIC_LOG_MAX_LINES || 5000);
const TELEMETRY_LOG_MAX_BYTES = Number(process.env.CAJAL_TELEMETRY_LOG_MAX_BYTES || 100 * 1024 * 1024);
const TELEMETRY_LOG_MAX_LINES = Number(process.env.CAJAL_TELEMETRY_LOG_MAX_LINES || 200000);
const TELEMETRY_MESSAGE_MAX_BYTES = Number(process.env.CAJAL_TELEMETRY_MESSAGE_MAX_BYTES || 65535);
const DATA_RETENTION_DAYS = Math.max(1, Math.min(3650, Math.floor(Number(process.env.CAJAL_DATA_RETENTION_DAYS || 90) || 90)));
const DATA_RETENTION_MS = DATA_RETENTION_DAYS * 24 * 60 * 60 * 1000;
const TELEMETRY_NETFLOW_RECORDS_PER_PACKET = Number(process.env.CAJAL_TELEMETRY_NETFLOW_RECORDS_PER_PACKET || 120);
const SYSLOG_EVENT_THROTTLE_MS = Number(process.env.CAJAL_SYSLOG_EVENT_THROTTLE_MS || 10000);
const NETFLOW_EVENT_THROTTLE_MS = Number(process.env.CAJAL_NETFLOW_EVENT_THROTTLE_MS || 10000);
const SNMP_OK_EVENT_THROTTLE_MS = Number(process.env.CAJAL_SNMP_OK_EVENT_THROTTLE_MS || 60000);
const SNMP_ERROR_EVENT_THROTTLE_MS = Number(process.env.CAJAL_SNMP_ERROR_EVENT_THROTTLE_MS || 60000);
const TOOLS_TERMINAL_TIMEOUT_MS = Number(process.env.CAJAL_TOOLS_TERMINAL_TIMEOUT_MS || 12000);
const TOOLS_TERMINAL_MAX_LINES = Number(process.env.CAJAL_TOOLS_TERMINAL_MAX_LINES || 120);
const COLLECTOR_AGENT_SESSION_TTL_MS = Number(process.env.CAJAL_AGENT_SESSION_TTL_MS || 2 * 60 * 1000);
const COLLECTOR_AGENT_COMMAND_TIMEOUT_MS = Number(process.env.CAJAL_AGENT_COMMAND_TIMEOUT_MS || 30 * 1000);
const COLLECTOR_AGENT_COMMAND_LEASE_MS = Number(process.env.CAJAL_AGENT_COMMAND_LEASE_MS || 12 * 1000);
const COLLECTOR_AGENT_POLL_INTERVAL_MS = Number(process.env.CAJAL_AGENT_POLL_INTERVAL_MS || 1500);
const COLLECTOR_AGENT_INSTALL_TIE_EPSILON_MS = Number(process.env.CAJAL_AGENT_INSTALL_TIE_EPSILON_MS || 1000);
const PUBLIC_SERVICE_POLL_INTERVAL_MS = Number(process.env.CAJAL_PUBLIC_SERVICE_POLL_INTERVAL_MS || 60 * 1000);

// ── SMTP / Mail ───────────────────────────────────────────────────────────────
const SMTP_TRANSPORT_CONFIG = normalizeSmtpTransportConfig({
  host: process.env.CAJAL_SMTP_HOST,
  port: process.env.CAJAL_SMTP_PORT,
  secure: process.env.CAJAL_SMTP_SECURE,
  starttls: process.env.CAJAL_SMTP_STARTTLS,
  user: process.env.CAJAL_SMTP_USER,
  pass: process.env.CAJAL_SMTP_PASS,
  timeoutMs: process.env.CAJAL_SMTP_TIMEOUT_MS,
  allowInvalidCert: process.env.CAJAL_SMTP_ALLOW_INVALID_CERT,
  heloName: process.env.CAJAL_SMTP_HELO
});
const MAIL_FROM = resolveMailFrom(process.env.CAJAL_MAIL_FROM, SMTP_TRANSPORT_CONFIG);
const DEFAULT_TEAMS_WEBHOOK_URL = normalizeTeamsWebhookUrl(process.env.CAJAL_TEAMS_WEBHOOK_URL || '');
const DEFAULT_TEAMS_WEBHOOK_TIMEOUT_MS = normalizeTeamsWebhookTimeoutMs(process.env.CAJAL_TEAMS_WEBHOOK_TIMEOUT_MS, 8000);
const TEAMS_WEBHOOK_MAX_ATTEMPTS = Math.max(1, Math.min(6, Number(process.env.CAJAL_TEAMS_WEBHOOK_MAX_ATTEMPTS || 3)));
const TEAMS_WEBHOOK_RETRY_BASE_MS = Math.max(50, Math.min(10000, Number(process.env.CAJAL_TEAMS_WEBHOOK_RETRY_BASE_MS || 350)));

// ── Agent package limits ──────────────────────────────────────────────────────
const WINDOWS_AGENT_PACKAGE_MAX_BYTES = Math.max(1024 * 1024, Math.min(100 * 1024 * 1024, Number(process.env.CAJAL_WINDOWS_AGENT_PACKAGE_MAX_BYTES || (30 * 1024 * 1024))));

// ── Database connection pool ──────────────────────────────────────────────────
const DATABASE_POOL_MAX = Math.max(2, Math.min(128, Number(process.env.CAJAL_DATABASE_POOL_MAX || 20) || 20));
const DATABASE_POOL_IDLE_TIMEOUT_MS = Math.max(1000, Math.min(10 * 60 * 1000, Number(process.env.CAJAL_DATABASE_POOL_IDLE_TIMEOUT_MS || 30000) || 30000));
const DATABASE_POOL_CONNECTION_TIMEOUT_MS = Math.max(500, Math.min(5 * 60 * 1000, Number(process.env.CAJAL_DATABASE_POOL_CONNECTION_TIMEOUT_MS || 10000) || 10000));
const DATABASE_STATEMENT_TIMEOUT_MS = Math.max(1000, Math.min(60 * 60 * 1000, Number(process.env.CAJAL_DATABASE_STATEMENT_TIMEOUT_MS || 30000) || 30000));
const DATABASE_QUERY_TIMEOUT_MS = Math.max(1000, Math.min(60 * 60 * 1000, Number(process.env.CAJAL_DATABASE_QUERY_TIMEOUT_MS || 30000) || 30000));

// ── Misc startup ──────────────────────────────────────────────────────────────
const STARTED_AT_MS = Date.now();

// ── Public service targets ────────────────────────────────────────────────────
const PUBLIC_SERVICE_TARGETS = Object.freeze([
  { id: 'google-dns', label: 'Google DNS', target: '8.8.8.8' },
  { id: 'cloudflare-dns', label: 'Cloudflare', target: '1.1.1.1' },
  { id: 'msft-azure', label: 'MSFT Azure', target: 'azure.microsoft.com' },
  { id: 'msft-office', label: 'MSFT Office', target: 'www.office.com' },
  { id: 'aws', label: 'AWS', target: 'aws.amazon.com' }
]);

// ── Entra SSO ─────────────────────────────────────────────────────────────────
const ENTRA_TENANT_ID = process.env.CAJAL_ENTRA_TENANT_ID || '';
const ENTRA_CLIENT_ID = process.env.CAJAL_ENTRA_CLIENT_ID || '';
const ENTRA_CLIENT_SECRET = process.env.CAJAL_ENTRA_CLIENT_SECRET || '';
const ENTRA_REDIRECT_URI = process.env.CAJAL_ENTRA_REDIRECT_URI || `http://localhost:${PORT}/api/auth/callback`;
const ENTRA_SCOPE = process.env.CAJAL_ENTRA_SCOPE || 'openid profile email';

// ── Self-update (GitHub Releases + Watchtower) ────────────────────────────────
const GITHUB_REPO = String(process.env.CAJAL_GITHUB_REPO || 'nniell90/cajal').trim();
const UPDATE_IMAGE = String(process.env.CAJAL_UPDATE_IMAGE || 'ghcr.io/nniell90/cajal:latest').trim();
const WATCHTOWER_URL = String(process.env.CAJAL_WATCHTOWER_URL || 'http://127.0.0.1:8080').trim().replace(/\/$/, '');
const WATCHTOWER_TOKEN = String(process.env.CAJAL_WATCHTOWER_TOKEN || '').trim();

// ── Users (admin/monitor sets) ────────────────────────────────────────────────
const ADMIN_USERS = new Set(
  String(process.env.CAJAL_ADMIN_USERS || '')
    .split(',')
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean)
);
const MONITOR_USERS = new Set(
  String(process.env.CAJAL_MONITOR_USERS || '')
    .split(',')
    .map((v) => v.trim().toLowerCase())
    .filter(Boolean)
);

// ── Paths ─────────────────────────────────────────────────────────────────────
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const DATA_DIR = path.join(__dirname, '..', 'data');
const README_PATH = path.join(__dirname, '..', 'README.md');
const REQUESTED_STORAGE_BACKEND = String(process.env.CAJAL_STORAGE_BACKEND || 'postgres').trim().toLowerCase();
const DATABASE_URL = String(process.env.CAJAL_DATABASE_URL || '').trim();
const DATABASE_SSL_MODE = (() => {
  const explicit = String(process.env.CAJAL_DATABASE_SSL || '').trim().toLowerCase();
  if (explicit) return explicit;
  // Auto-detect: local connections don't need SSL; remote connections should use it
  const dbUrl = String(process.env.CAJAL_DATABASE_URL || '').toLowerCase();
  const isLocal = /(@localhost[:/]|@127\.0\.0\.1[:/]|@\[::1\][:/])/.test(dbUrl);
  return isLocal ? 'disable' : 'require';
})();
const SITES_FILE = path.join(DATA_DIR, 'sites.json');
const DEVICES_FILE = path.join(DATA_DIR, 'devices.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SSO_FILE = path.join(DATA_DIR, 'sso.json');
const EVENTS_FILE = path.join(DATA_DIR, 'events.json');
const ERROR_LOG_FILE = path.join(DATA_DIR, 'error-log.jsonl');
const DIAGNOSTIC_LOG_FILE = path.join(DATA_DIR, 'diagnostics-log.jsonl');
const TELEMETRY_LOG_FILE = path.join(DATA_DIR, 'telemetry-log.jsonl');
const SSL_FILE = path.join(DATA_DIR, 'ssl.json');
const RUNTIME_FILE = path.join(DATA_DIR, 'runtime.json');
const LOCATION_SETTINGS_FILE = path.join(DATA_DIR, 'location-settings.json');
const BACKUP_META_FILE = path.join(DATA_DIR, 'backup-meta.json');
const API_TOKENS_FILE = path.join(DATA_DIR, 'api-tokens.json');
const WINDOWS_AGENT_PACKAGE_FILE = path.join(DATA_DIR, 'windows-agent-package.json');
const LINUX_AGENT_SCRIPT_FILE = path.join(__dirname, '..', 'agent', 'cajal-linux-agent.py');
const WINDOWS_AGENT_SCRIPT_FILE = path.join(__dirname, '..', 'agent', 'cajal-windows-agent.ps1');
const WINDOWS_AGENT_EXE_FILE = path.join(__dirname, '..', 'agent', 'cajal-windows-agent.exe');
const WINDOWS_AGENT_SCRIPT_FILENAME = 'cajal-windows-agent.ps1';
const WINDOWS_AGENT_DOWNLOAD_FILENAME = WINDOWS_AGENT_SCRIPT_FILENAME;
const LINUX_AGENT_SETUP_SCRIPT_FILE = path.join(__dirname, '..', 'agent', 'cajal-agent-setup.py');
const LINUX_AGENT_CONNECT_TEST_SCRIPT_FILE = path.join(__dirname, '..', 'agent', 'cajal-connect-test.py');
const LINUX_AGENT_DEB_PACKAGE_NAME = 'cajal-agent';
const LINUX_AGENT_DEB_VERSION = String(process.env.CAJAL_AGENT_DEB_VERSION || APP_VERSION || '1.0.0')
  .replace(/[^0-9A-Za-z.+:~-]/g, '-')
  .replace(/^-+/, '') || '1.0.0';
const LINUX_AGENT_SERVICE_NAME = 'cajal-agent';
const LINUX_AGENT_DEB_ARCH = 'all';

// ── Database settings ─────────────────────────────────────────────────────────
const CONFIG_INTEGRITY_KEYS = Object.freeze(['sso', 'runtime', 'apiTokens', 'ssl', 'windowsAgentPackage', 'bootstrap']);

// ── Webhook catalogs ──────────────────────────────────────────────────────────
const WEBHOOK_SECTION_CATALOG = Object.freeze([
  { id: 'firewalls', label: 'FIREWALLS' },
  { id: 'collectors', label: 'COLLECTORS' },
  { id: 'system', label: 'SYSTEM' },
  { id: 'other', label: 'OTHER' }
]);
const WEBHOOK_SECTION_MODE_VALUES = new Set(['warn', 'offline', 'restore', 'never']);

const WEBHOOK_ROUTE_CATALOG = Object.freeze([
  { id: 'firewall_status_offline', section: 'firewalls', signal: 'offline', label: 'Firewall Offline', description: 'Send when a firewall site changes to DOWN.' },
  { id: 'firewall_status_warn', section: 'firewalls', signal: 'warn', label: 'Firewall Warn', description: 'Send when a firewall site changes to WARN.' },
  { id: 'firewall_status_restore', section: 'firewalls', signal: 'restore', label: 'Firewall Restore', description: 'Send when a firewall site recovers to UP.' },
  { id: 'firewall_test_notify', section: 'firewalls', signal: 'warn', label: 'Firewall Test Notify', description: 'Send when Test Notify is triggered for a firewall site.' },

  { id: 'collector_status_offline', section: 'collectors', signal: 'offline', label: 'Collector Offline', description: 'Send when a collector site changes to DOWN.' },
  { id: 'collector_status_warn', section: 'collectors', signal: 'warn', label: 'Collector Warn', description: 'Send when a collector site changes to WARN.' },
  { id: 'collector_status_restore', section: 'collectors', signal: 'restore', label: 'Collector Restore', description: 'Send when a collector site recovers to UP.' },
  { id: 'collector_test_notify', section: 'collectors', signal: 'warn', label: 'Collector Test Notify', description: 'Send when Test Notify is triggered for a collector site.' },
  { id: 'collector_agent_offline', section: 'collectors', signal: 'offline', label: 'Collector Agent Offline', description: 'Send when a collector agent disconnects or expires.' },
  { id: 'collector_agent_online', section: 'collectors', signal: 'restore', label: 'Collector Agent Online', description: 'Send when a collector agent registers successfully.' },
  { id: 'collector_wan_failover', section: 'collectors', signal: 'warn', label: 'Collector WAN Failover', description: 'Send when a collector public WAN IP changes (possible failover).' },

  { id: 'system_dependency_offline', section: 'system', signal: 'offline', label: 'System Dependency Offline', description: 'Send when required system dependency is missing.' },
  { id: 'system_dependency_warn', section: 'system', signal: 'warn', label: 'System Dependency Warn', description: 'Send when dependency checks have warnings.' },
  { id: 'system_dependency_restore', section: 'system', signal: 'restore', label: 'System Dependency Restore', description: 'Send when dependency checks return to healthy.' },
  { id: 'system_alerts_silenced', section: 'system', signal: 'warn', label: 'System Alerts Silenced', description: 'Send when global alert silencing is enabled.' },
  { id: 'system_alerts_resumed', section: 'system', signal: 'restore', label: 'System Alerts Resumed', description: 'Send when global alert silencing ends.' },

  { id: 'other_status_offline', section: 'other', signal: 'offline', label: 'Other Device Offline', description: 'Send when an OTHER-role site changes to DOWN.' },
  { id: 'other_status_warn', section: 'other', signal: 'warn', label: 'Other Device Warn', description: 'Send when an OTHER-role site changes to WARN.' },
  { id: 'other_status_restore', section: 'other', signal: 'restore', label: 'Other Device Restore', description: 'Send when an OTHER-role site recovers to UP.' },
  { id: 'other_test_notify', section: 'other', signal: 'warn', label: 'Other Test Notify', description: 'Send when Test Notify is triggered for an OTHER-role site.' },
  { id: 'other_public_service_offline', section: 'other', signal: 'offline', label: 'Public Service Offline', description: 'Send when a monitored public service becomes unreachable.' },
  { id: 'other_public_service_restore', section: 'other', signal: 'restore', label: 'Public Service Restore', description: 'Send when a monitored public service becomes reachable again.' }
]);
const WEBHOOK_ROUTE_IDS = new Set(WEBHOOK_ROUTE_CATALOG.map((route) => route.id));
const WEBHOOK_ROUTE_MAP = new Map(WEBHOOK_ROUTE_CATALOG.map((route) => [route.id, route]));
const WEBHOOK_ROUTE_DEFAULT_MESSAGES = Object.freeze({
  firewall_status_offline: '[{{status}}] Firewall {{siteName}} at {{locationName}} is DOWN.\nPrevious: {{previousStatus}}\nWAN1: {{wanIp1}} WAN2: {{wanIp2}}\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}',
  firewall_status_warn: '[{{status}}] Firewall {{siteName}} at {{locationName}} is in WARN.\nPrevious: {{previousStatus}}\nWAN1: {{wanIp1}} WAN2: {{wanIp2}}\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}',
  firewall_status_restore: '[{{status}}] Firewall {{siteName}} at {{locationName}} has recovered.\nPrevious: {{previousStatus}}\nWAN1: {{wanIp1}} WAN2: {{wanIp2}}\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}',
  firewall_test_notify: '[TEST] Firewall alert route check for {{siteName}} at {{locationName}}.\nStatus: {{status}} Previous: {{previousStatus}}\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}',

  collector_status_offline: '[{{status}}] Collector {{siteName}} at {{locationName}} is DOWN.\nPrevious: {{previousStatus}}\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}',
  collector_status_warn: '[{{status}}] Collector {{siteName}} at {{locationName}} is in WARN.\nPrevious: {{previousStatus}}\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}',
  collector_status_restore: '[{{status}}] Collector {{siteName}} at {{locationName}} has recovered.\nPrevious: {{previousStatus}}\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}',
  collector_test_notify: '[TEST] Collector alert route check for {{siteName}} at {{locationName}}.\nStatus: {{status}} Previous: {{previousStatus}}\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}',
  collector_agent_offline: '[OFFLINE] Collector agent for {{siteName}} at {{locationName}} is offline.\nHost: {{agentHost}}\nLocal IP: {{agentLocalIp}} Remote IP: {{agentRemoteIp}}\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}',
  collector_agent_online: '[RESTORE] Collector agent for {{siteName}} at {{locationName}} is online.\nHost: {{agentHost}}\nLocal IP: {{agentLocalIp}} Remote IP: {{agentRemoteIp}}\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}',
  collector_wan_failover: '[WARN] Collector {{siteName}} at {{locationName}} detected WAN failover.\nPrevious Public IP: {{wanPublicIpPrevious}}\nCurrent Public IP: {{wanPublicIpCurrent}}\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}',

  system_dependency_offline: '[OFFLINE] System dependency check failed.\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}',
  system_dependency_warn: '[WARN] System dependency check warning.\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}',
  system_dependency_restore: '[RESTORE] System dependency check recovered.\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}',
  system_alerts_silenced: '[WARN] Global alert silence enabled.\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}',
  system_alerts_resumed: '[RESTORE] Global alert silence ended; alerting resumed.\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}',

  other_status_offline: '[{{status}}] Device {{siteName}} at {{locationName}} is DOWN.\nPrevious: {{previousStatus}}\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}',
  other_status_warn: '[{{status}}] Device {{siteName}} at {{locationName}} is in WARN.\nPrevious: {{previousStatus}}\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}',
  other_status_restore: '[{{status}}] Device {{siteName}} at {{locationName}} has recovered.\nPrevious: {{previousStatus}}\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}',
  other_test_notify: '[TEST] OTHER alert route check for {{siteName}} at {{locationName}}.\nStatus: {{status}} Previous: {{previousStatus}}\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}',
  other_public_service_offline: '[OFFLINE] Public service {{serviceLabel}} is unreachable.\nTarget: {{serviceTarget}}\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}',
  other_public_service_restore: '[RESTORE] Public service {{serviceLabel}} is reachable again.\nTarget: {{serviceTarget}}\nReason: {{reason}}\nDetail: {{detail}}\nTime: {{timestamp}}'
});

function defaultWebhookRoutingRules() {
  const out = {};
  for (const route of WEBHOOK_ROUTE_CATALOG) out[route.id] = true;
  return out;
}

function defaultWebhookSectionModes() {
  const out = {};
  for (const section of WEBHOOK_SECTION_CATALOG) out[section.id] = 'warn';
  return out;
}

function defaultWebhookRoutingMessages() {
  const out = {};
  for (const route of WEBHOOK_ROUTE_CATALOG) out[route.id] = String(WEBHOOK_ROUTE_DEFAULT_MESSAGES[route.id] || '').trim().slice(0, 4000);
  return out;
}

function normalizeWebhookRoutingRules(input = {}, fallback = {}) {
  const out = defaultWebhookRoutingRules();
  const applyFrom = (source) => {
    if (!source || typeof source !== 'object') return;
    for (const routeId of Object.keys(out)) {
      if (!Object.prototype.hasOwnProperty.call(source, routeId)) continue;
      out[routeId] = Boolean(source[routeId]);
    }
    // Legacy compatibility from pre-section route IDs.
    if (Object.prototype.hasOwnProperty.call(source, 'status_down')) {
      out.firewall_status_offline = Boolean(source.status_down);
      out.collector_status_offline = Boolean(source.status_down);
      out.other_status_offline = Boolean(source.status_down);
    }
    if (Object.prototype.hasOwnProperty.call(source, 'status_warn')) {
      out.firewall_status_warn = Boolean(source.status_warn);
      out.collector_status_warn = Boolean(source.status_warn);
      out.other_status_warn = Boolean(source.status_warn);
    }
    if (Object.prototype.hasOwnProperty.call(source, 'status_recovery')) {
      out.firewall_status_restore = Boolean(source.status_recovery);
      out.collector_status_restore = Boolean(source.status_recovery);
      out.other_status_restore = Boolean(source.status_recovery);
    }
    if (Object.prototype.hasOwnProperty.call(source, 'site_test_notify')) {
      out.firewall_test_notify = Boolean(source.site_test_notify);
      out.collector_test_notify = Boolean(source.site_test_notify);
      out.other_test_notify = Boolean(source.site_test_notify);
    }
  };
  applyFrom(fallback);
  applyFrom(input);
  return out;
}

function normalizeWebhookRoutingMessages(input = {}, fallback = {}) {
  const out = defaultWebhookRoutingMessages();
  const applyFrom = (source) => {
    if (!source || typeof source !== 'object') return;
    for (const routeId of Object.keys(out)) {
      if (!Object.prototype.hasOwnProperty.call(source, routeId)) continue;
      out[routeId] = String(source[routeId] ?? '').trim().slice(0, 4000);
    }
    // Legacy compatibility from pre-section route IDs.
    if (Object.prototype.hasOwnProperty.call(source, 'status_down')) {
      const msg = String(source.status_down ?? '').trim().slice(0, 4000);
      out.firewall_status_offline = msg;
      out.collector_status_offline = msg;
      out.other_status_offline = msg;
    }
    if (Object.prototype.hasOwnProperty.call(source, 'status_warn')) {
      const msg = String(source.status_warn ?? '').trim().slice(0, 4000);
      out.firewall_status_warn = msg;
      out.collector_status_warn = msg;
      out.other_status_warn = msg;
    }
    if (Object.prototype.hasOwnProperty.call(source, 'status_recovery')) {
      const msg = String(source.status_recovery ?? '').trim().slice(0, 4000);
      out.firewall_status_restore = msg;
      out.collector_status_restore = msg;
      out.other_status_restore = msg;
    }
    if (Object.prototype.hasOwnProperty.call(source, 'site_test_notify')) {
      const msg = String(source.site_test_notify ?? '').trim().slice(0, 4000);
      out.firewall_test_notify = msg;
      out.collector_test_notify = msg;
      out.other_test_notify = msg;
    }
  };
  applyFrom(fallback);
  applyFrom(input);
  const defaults = defaultWebhookRoutingMessages();
  for (const routeId of Object.keys(out)) {
    if (!String(out[routeId] || '').trim()) {
      out[routeId] = defaults[routeId];
    }
  }
  return out;
}

function normalizeWebhookSectionModes(input = {}, fallback = {}) {
  const out = defaultWebhookSectionModes();
  const applyFrom = (source) => {
    if (!source || typeof source !== 'object') return;
    for (const sectionId of Object.keys(out)) {
      if (!Object.prototype.hasOwnProperty.call(source, sectionId)) continue;
      const mode = String(source[sectionId] || '').trim().toLowerCase();
      out[sectionId] = WEBHOOK_SECTION_MODE_VALUES.has(mode) ? mode : out[sectionId];
    }
  };
  applyFrom(fallback);
  applyFrom(input);
  return out;
}

// ── Sensitive fields / symbols ────────────────────────────────────────────────
const SENSITIVE_FIELDS = new Set(['authToken', 'communityString', 'authPassword', 'sharedSecret']);
const MASK = '********';
const SITE_MONITOR_CONFIG_DECRYPT_FAILED = Symbol('siteMonitorConfigDecryptFailed');
const SITE_MONITOR_CONFIG_ENCRYPTED_FALLBACK = Symbol('siteMonitorConfigEncryptedFallback');

// ── Default config objects ────────────────────────────────────────────────────
const defaultRuntimeSettings = {
  syslogUdpPort: SYSLOG_UDP_PORT,
  syslogTcpPort: SYSLOG_TCP_PORT,
  netflowPort: NETFLOW_PORT,
  snmpPollIntervalMs: SNMP_POLL_INTERVAL_MS,
  flowTimeoutMs: FLOW_TIMEOUT_MS,
  pingIntervalMs: PING_INTERVAL_MS,
  globalDataRefreshMs: GLOBAL_DATA_REFRESH_MS,
  globalClockTimeZone: GLOBAL_CLOCK_TIMEZONE,
  globalClockHourMode: GLOBAL_CLOCK_HOUR_MODE,
  localTotpEnabled: LOCAL_TOTP_ENABLED,
  wanTestIntervalMs: WAN_TEST_INTERVAL_MS,
  internalDnsTarget: String(process.env.CAJAL_INTERNAL_DNS_TARGET || '').trim(),
  teamsWebhookUrl: DEFAULT_TEAMS_WEBHOOK_URL,
  teamsWebhookTimeoutMs: DEFAULT_TEAMS_WEBHOOK_TIMEOUT_MS,
  teamsPayloadGroup: String(process.env.CAJAL_TEAMS_PAYLOAD_GROUP || 'cajal').trim() || 'cajal',
  webhookRouting: defaultWebhookRoutingRules(),
  webhookSectionModes: defaultWebhookSectionModes(),
  webhookRoutingMessages: defaultWebhookRoutingMessages(),
  setupWizardCompleted: false
};
const defaultSslSettings = {
  certPem: '',
  keyPem: '',
  caPem: ''
};
const defaultLocationSettings = {
  companyName: 'My Organization',
  internalName: 'Location 1',
  customerName: '',
  sections: [
    { id: 'internal', name: 'Location 1', address: '', pingMonitors: [] }
  ]
};
const defaultBackupMeta = {
  lastBackupAt: '',
  lastBackupBy: '',
  lastRestoreAt: '',
  lastRestoreBy: ''
};
const defaultApiTokenSettings = {
  tokens: []
};
const defaultWindowsAgentPackageSettings = {
  fileName: '',
  sizeBytes: 0,
  uploadedAt: '',
  sha256: '',
  dataBase64: ''
};

// ── Storage tracked files ─────────────────────────────────────────────────────
const STORAGE_TRACKED_FILES = [
  { name: 'sites', file: SITES_FILE, category: 'config' },
  { name: 'devices', file: DEVICES_FILE, category: 'config' },
  { name: 'users', file: USERS_FILE, category: 'config' },
  { name: 'sso', file: SSO_FILE, category: 'config' },
  { name: 'ssl', file: SSL_FILE, category: 'config' },
  { name: 'runtime', file: RUNTIME_FILE, category: 'config' },
  { name: 'apiTokens', file: API_TOKENS_FILE, category: 'config' },
  { name: 'windowsAgentPackage', file: WINDOWS_AGENT_PACKAGE_FILE, category: 'config' },
  { name: 'locationSettings', file: LOCATION_SETTINGS_FILE, category: 'config' },
  { name: 'backupMeta', file: BACKUP_META_FILE, category: 'config' },
  { name: 'events', file: EVENTS_FILE, category: 'log' },
  { name: 'errorLog', file: ERROR_LOG_FILE, category: 'log' },
  { name: 'diagnosticsLog', file: DIAGNOSTIC_LOG_FILE, category: 'log' },
  { name: 'telemetryLog', file: TELEMETRY_LOG_FILE, category: 'log' }
];
const STORAGE_TRACKED_FILE_KEYS = new Map(STORAGE_TRACKED_FILES.map((row) => [row.file, row.name]));

// ── API token scope ───────────────────────────────────────────────────────────
// (Populated after API_TOKEN_SCOPE_SET is defined in server.js — we include it here for reference)
// Note: API_TOKEN_SCOPE_SET is defined in server.js and is not a pure constant (it depends on logic)
// We provide a placeholder here and the real one stays in server.js.

module.exports = {
  APP_VERSION,
  loadEnvFile,
  parseBooleanFlag,
  normalizeSmtpStarttlsMode,
  normalizeSmtpTransportConfig,
  smtpConfigEnabled,
  smtpTransportLabel,
  sanitizeMailAddress,
  resolveMailFrom,
  normalizeTeamsWebhookUrl,
  teamsWebhookEnabled,
  normalizeTeamsWebhookTimeoutMs,
  defaultWebhookRoutingRules,
  defaultWebhookSectionModes,
  defaultWebhookRoutingMessages,
  normalizeWebhookRoutingRules,
  normalizeWebhookRoutingMessages,
  normalizeWebhookSectionModes,
  PORT,
  HTTPS_PORT,
  SYSLOG_UDP_PORT,
  SYSLOG_TCP_PORT,
  NETFLOW_PORT,
  FLOW_TIMEOUT_MS,
  SYSLOG_FLOW_TIMEOUT_MIN_MS,
  NETFLOW_FLOW_TIMEOUT_MIN_MS,
  SNMP_POLL_INTERVAL_MS,
  PING_INTERVAL_MS,
  GLOBAL_DATA_REFRESH_MS,
  NETFLOW_TOP_WINDOW_MS,
  UPTIME_SAMPLE_INTERVAL_MS,
  WAN_TEST_INTERVAL_MS,
  LOCATION_PING_MONITOR_MAX,
  LOCATION_PING_MONITOR_POLL_INTERVAL_MS,
  WAN_TEST_SLOT_INTERVAL_MS,
  WAN_PUBLIC_IP_POLL_INTERVAL_MS,
  WAN_TEST_RECOVERY_INTERVAL_MS,
  WAN_TEST_SLOT_LABEL_BY_HOUR,
  GLOBAL_CLOCK_TIMEZONE,
  GLOBAL_CLOCK_HOUR_MODE,
  ALERT_SILENCE_DURATION_MS,
  WAN_TEST_HISTORY,
  SESSION_TTL_MS,
  SESSION_IDLE_TTL_MS,
  SESSION_RENEW_INTERVAL_MS,
  FORCE_SECURE_COOKIES,
  LOGIN_RATE_LIMIT_MAX,
  LOGIN_RATE_LIMIT_WINDOW_MS,
  LOGIN_ACCOUNT_FAILURE_THRESHOLD,
  LOGIN_ACCOUNT_FAILURE_WINDOW_MS,
  LOGIN_ACCOUNT_LOCK_MS,
  PUBLIC_STATUS_RATE_LIMIT_MAX,
  PUBLIC_STATUS_RATE_LIMIT_WINDOW_MS,
  API_TOKEN_RATE_LIMIT_MAX,
  API_TOKEN_RATE_LIMIT_WINDOW_MS,
  WEBHOOK_TEST_RATE_LIMIT_MAX,
  WEBHOOK_TEST_RATE_LIMIT_WINDOW_MS,
  LOCAL_SETUP_TTL_MS,
  PASSWORD_HASH_ITERATIONS,
  LOCAL_TOTP_ENABLED,
  MIN_CONFIG_KEY_LENGTH,
  API_TOKEN_MAX_COUNT,
  API_TOKEN_MAX_LIFETIME_DAYS,
  API_TOKEN_MAX_LIFETIME_MS,
  API_TOKEN_MAX_IP_ALLOWLIST,
  EVENT_RETENTION,
  SITES_PERSIST_INTERVAL_MS,
  EVENTS_PERSIST_INTERVAL_MS,
  BACKUP_KDF_ITERATIONS,
  ERROR_LOG_MAX_BYTES,
  ERROR_LOG_MAX_LINES,
  DIAGNOSTIC_LOG_MAX_BYTES,
  DIAGNOSTIC_LOG_MAX_LINES,
  TELEMETRY_LOG_MAX_BYTES,
  TELEMETRY_LOG_MAX_LINES,
  TELEMETRY_MESSAGE_MAX_BYTES,
  DATA_RETENTION_DAYS,
  DATA_RETENTION_MS,
  TELEMETRY_NETFLOW_RECORDS_PER_PACKET,
  SYSLOG_EVENT_THROTTLE_MS,
  NETFLOW_EVENT_THROTTLE_MS,
  SNMP_OK_EVENT_THROTTLE_MS,
  SNMP_ERROR_EVENT_THROTTLE_MS,
  TOOLS_TERMINAL_TIMEOUT_MS,
  TOOLS_TERMINAL_MAX_LINES,
  COLLECTOR_AGENT_SESSION_TTL_MS,
  COLLECTOR_AGENT_COMMAND_TIMEOUT_MS,
  COLLECTOR_AGENT_COMMAND_LEASE_MS,
  COLLECTOR_AGENT_POLL_INTERVAL_MS,
  COLLECTOR_AGENT_INSTALL_TIE_EPSILON_MS,
  PUBLIC_SERVICE_POLL_INTERVAL_MS,
  SMTP_TRANSPORT_CONFIG,
  MAIL_FROM,
  DEFAULT_TEAMS_WEBHOOK_URL,
  DEFAULT_TEAMS_WEBHOOK_TIMEOUT_MS,
  TEAMS_WEBHOOK_MAX_ATTEMPTS,
  TEAMS_WEBHOOK_RETRY_BASE_MS,
  WINDOWS_AGENT_PACKAGE_MAX_BYTES,
  DATABASE_POOL_MAX,
  DATABASE_POOL_IDLE_TIMEOUT_MS,
  DATABASE_POOL_CONNECTION_TIMEOUT_MS,
  DATABASE_STATEMENT_TIMEOUT_MS,
  DATABASE_QUERY_TIMEOUT_MS,
  STARTED_AT_MS,
  PUBLIC_SERVICE_TARGETS,
  ENTRA_TENANT_ID,
  ENTRA_CLIENT_ID,
  ENTRA_CLIENT_SECRET,
  ENTRA_REDIRECT_URI,
  ENTRA_SCOPE,
  GITHUB_REPO,
  UPDATE_IMAGE,
  WATCHTOWER_URL,
  WATCHTOWER_TOKEN,
  ADMIN_USERS,
  MONITOR_USERS,
  PUBLIC_DIR,
  DATA_DIR,
  README_PATH,
  REQUESTED_STORAGE_BACKEND,
  DATABASE_URL,
  DATABASE_SSL_MODE,
  SITES_FILE,
  DEVICES_FILE,
  USERS_FILE,
  SSO_FILE,
  EVENTS_FILE,
  ERROR_LOG_FILE,
  DIAGNOSTIC_LOG_FILE,
  TELEMETRY_LOG_FILE,
  SSL_FILE,
  RUNTIME_FILE,
  LOCATION_SETTINGS_FILE,
  BACKUP_META_FILE,
  API_TOKENS_FILE,
  WINDOWS_AGENT_PACKAGE_FILE,
  LINUX_AGENT_SCRIPT_FILE,
  WINDOWS_AGENT_SCRIPT_FILE,
  WINDOWS_AGENT_EXE_FILE,
  WINDOWS_AGENT_SCRIPT_FILENAME,
  WINDOWS_AGENT_DOWNLOAD_FILENAME,
  LINUX_AGENT_SETUP_SCRIPT_FILE,
  LINUX_AGENT_CONNECT_TEST_SCRIPT_FILE,
  LINUX_AGENT_DEB_PACKAGE_NAME,
  LINUX_AGENT_DEB_VERSION,
  LINUX_AGENT_SERVICE_NAME,
  LINUX_AGENT_DEB_ARCH,
  CONFIG_INTEGRITY_KEYS,
  WEBHOOK_SECTION_CATALOG,
  WEBHOOK_SECTION_MODE_VALUES,
  WEBHOOK_ROUTE_CATALOG,
  WEBHOOK_ROUTE_IDS,
  WEBHOOK_ROUTE_MAP,
  WEBHOOK_ROUTE_DEFAULT_MESSAGES,
  SENSITIVE_FIELDS,
  MASK,
  SITE_MONITOR_CONFIG_DECRYPT_FAILED,
  SITE_MONITOR_CONFIG_ENCRYPTED_FALLBACK,
  defaultRuntimeSettings,
  defaultSslSettings,
  defaultLocationSettings,
  defaultBackupMeta,
  defaultApiTokenSettings,
  defaultWindowsAgentPackageSettings,
  STORAGE_TRACKED_FILES,
  STORAGE_TRACKED_FILE_KEYS,
};
