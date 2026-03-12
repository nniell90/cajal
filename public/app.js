const locationPanels = document.getElementById('locationPanels');
const refreshClock = document.getElementById('refreshClock');
const systemClock = document.getElementById('systemClock');
const systemUptime = document.getElementById('systemUptime');
const changeTicker = document.getElementById('changeTicker');
const changeTickerWrap = document.querySelector('.change-ticker');
const topbar = document.querySelector('.topbar');
const settingsBtn = document.getElementById('settingsBtn');
const helpBtn = document.getElementById('helpBtn');
const settingsPanel = document.getElementById('settingsPanel');
const closeSettingsBtn = document.getElementById('closeSettingsBtn');
const ssoStatusLine = document.getElementById('ssoStatusLine');
const systemDepsLine = document.getElementById('systemDepsLine');
const ssoLoginBtn = document.getElementById('ssoLoginBtn');
const ssoConfigPanel = document.getElementById('ssoConfigPanel');
const ssoConfigForm = document.getElementById('ssoConfigForm');
const ssoConfigMsg = document.getElementById('ssoConfigMsg');
const syncNowBtn = document.getElementById('syncNowBtn');
const ldapConfigPanel = document.getElementById('ldapConfigPanel');
const ldapConfigForm = document.getElementById('ldapConfigForm');
const ldapConfigMsg = document.getElementById('ldapConfigMsg');
const ldapStatusLine = document.getElementById('ldapStatusLine');
const ldapTestBtn = document.getElementById('ldapTestBtn');
const ldapTestDialog = document.getElementById('ldapTestDialog');
const ldapTestSteps = document.getElementById('ldapTestSteps');
const ldapTestUserList = document.getElementById('ldapTestUserList');
const ldapTestUserTable = document.getElementById('ldapTestUserTable');
const ldapTestApprove = document.getElementById('ldapTestApprove');
const ldapTestClose = document.getElementById('ldapTestClose');
const userAdminPanel = document.getElementById('userAdminPanel');
const userList = document.getElementById('userList');
const addUserForm = document.getElementById('addUserForm');
const userAdminMsg = document.getElementById('userAdminMsg');
const locationAdminPanel = document.getElementById('locationAdminPanel');
const locationConfigForm = document.getElementById('locationConfigForm');
const locationAdminMsg = document.getElementById('locationAdminMsg');
const locationSectionList = document.getElementById('locationSectionList');
const companyNameDisplay = document.getElementById('companyNameDisplay');
const serverSelfMonitorBadges = document.getElementById('serverSelfMonitorBadges');
const silenceAlertsBtn = document.getElementById('silenceAlertsBtn');
const globalUndoBtn = document.getElementById('globalUndoBtn');
const silenceAlertsCountdown = document.getElementById('silenceAlertsCountdown');
const sslConfigPanel = document.getElementById('sslConfigPanel');
const sslConfigForm = document.getElementById('sslConfigForm');
const sslConfigMsg = document.getElementById('sslConfigMsg');
const teamsConfigPanel = document.getElementById('teamsConfigPanel');
const teamsConfigForm = document.getElementById('teamsConfigForm');
const teamsConfigMsg = document.getElementById('teamsConfigMsg');
const teamsConfigTestBtn = document.getElementById('teamsConfigTestBtn');
const teamsPayloadTitleInput = document.getElementById('teamsPayloadTitle');
const teamsPayloadGroupInput = document.getElementById('teamsPayloadGroup');
const teamsPayloadMessageInput = document.getElementById('teamsPayloadMessage');
const webhookRoutingPanel = document.getElementById('webhookRoutingPanel');
const webhookRoutingContent = document.getElementById('webhookRoutingContent');
const webhookRoutingMsg = document.getElementById('webhookRoutingMsg');
const runtimeConfigPanel = document.getElementById('runtimeConfigPanel');
const runtimeConfigForm = document.getElementById('runtimeConfigForm');
const runtimeConfigMsg = document.getElementById('runtimeConfigMsg');
const factoryResetBtn = document.getElementById('factoryResetBtn');
const clockConfigPanel = document.getElementById('clockConfigPanel');
const clockConfigForm = document.getElementById('clockConfigForm');
const clockConfigMsg = document.getElementById('clockConfigMsg');
const systemHealthPanel = document.getElementById('systemHealthPanel');
const systemHealthContent = document.getElementById('systemHealthContent');
const systemHealthMsg = document.getElementById('systemHealthMsg');
const refreshSystemHealthBtn = document.getElementById('refreshSystemHealthBtn');
const backupPanel = document.getElementById('backupPanel');
const backupNowBtn = document.getElementById('backupNowBtn');
const backupRestoreForm = document.getElementById('backupRestoreForm');
const backupFileInput = document.getElementById('backupFileInput');
const backupMsg = document.getElementById('backupMsg');
const errorLogPanel = document.getElementById('errorLogPanel');
const errorLogLimitInput = document.getElementById('errorLogLimitInput');
const refreshErrorLogBtn = document.getElementById('refreshErrorLogBtn');
const errorLogViewer = document.getElementById('errorLogViewer');
const errorLogMsg = document.getElementById('errorLogMsg');
const diagnosticsPanel = document.getElementById('diagnosticsPanel');
const diagnosticsLogLimitInput = document.getElementById('diagnosticsLogLimitInput');
const diagnosticsProtocolFilter = document.getElementById('diagnosticsProtocolFilter');
const diagnosticsLevelFilter = document.getElementById('diagnosticsLevelFilter');
const diagnosticsSiteFilter = document.getElementById('diagnosticsSiteFilter');
const refreshDiagnosticsBtn = document.getElementById('refreshDiagnosticsBtn');
const clearDiagnosticsBtn = document.getElementById('clearDiagnosticsBtn');
const openDiagnosticsConsoleBtn = document.getElementById('openDiagnosticsConsoleBtn');
const diagnosticsLogViewer = document.getElementById('diagnosticsLogViewer');
const diagnosticsLogMsg = document.getElementById('diagnosticsLogMsg');
const diagnosticConsoleDialog = document.getElementById('diagnosticConsoleDialog');
const diagnosticConsoleClose = document.getElementById('diagnosticConsoleClose');
const diagnosticConsoleOutput = document.getElementById('diagnosticConsoleOutput');
const rawTelemetryPanel = document.getElementById('rawTelemetryPanel');
const rawTelemetryLimitInput = document.getElementById('rawTelemetryLimitInput');
const rawTelemetryProtocolFilter = document.getElementById('rawTelemetryProtocolFilter');
const rawTelemetrySiteFilter = document.getElementById('rawTelemetrySiteFilter');
const rawTelemetrySearchFilter = document.getElementById('rawTelemetrySearchFilter');
const rawTelemetryAutoRefresh = document.getElementById('rawTelemetryAutoRefresh');
const refreshRawTelemetryBtn = document.getElementById('refreshRawTelemetryBtn');
const openRawTelemetryConsoleBtn = document.getElementById('openRawTelemetryConsoleBtn');
const clearRawTelemetryBtn = document.getElementById('clearRawTelemetryBtn');
const rawTelemetryViewer = document.getElementById('rawTelemetryViewer');
const rawTelemetryMsg = document.getElementById('rawTelemetryMsg');
const rawTelemetryConsoleDialog = document.getElementById('rawTelemetryConsoleDialog');
const rawTelemetryConsoleClose = document.getElementById('rawTelemetryConsoleClose');
const rawTelemetryConsoleOutput = document.getElementById('rawTelemetryConsoleOutput');
const netflowTroublemakersDialog = document.getElementById('netflowTroublemakersDialog');
const netflowTroublemakersClose = document.getElementById('netflowTroublemakersClose');
const netflowTroublemakersOutput = document.getElementById('netflowTroublemakersOutput');
const firewallCheckerPanel = document.getElementById('firewallCheckerPanel');
const refreshFirewallCheckerBtn = document.getElementById('refreshFirewallCheckerBtn');
const firewallCheckerViewer = document.getElementById('firewallCheckerViewer');
const firewallCheckerMsg = document.getElementById('firewallCheckerMsg');
const storagePanel = document.getElementById('storagePanel');
const refreshStorageBtn = document.getElementById('refreshStorageBtn');
const purgeStorageLogsBtn = document.getElementById('purgeStorageLogsBtn');
const storageSummaryContent = document.getElementById('storageSummaryContent');
const storageViewer = document.getElementById('storageViewer');
const storageMsg = document.getElementById('storageMsg');
const apiAccessPanel = document.getElementById('apiAccessPanel');
const apiTokenForm = document.getElementById('apiTokenForm');
const apiTokenNameInput = document.getElementById('apiTokenNameInput');
const apiTokenRoleInput = document.getElementById('apiTokenRoleInput');
const apiTokenExpiresInput = document.getElementById('apiTokenExpiresInput');
const apiTokenReveal = document.getElementById('apiTokenReveal');
const apiTokenRevealValue = document.getElementById('apiTokenRevealValue');
const apiTokenCopyBtn = document.getElementById('apiTokenCopyBtn');
const apiTokenList = document.getElementById('apiTokenList');
const apiTokenMsg = document.getElementById('apiTokenMsg');
const mySecurityPanel = document.getElementById('mySecurityPanel');
const mySecurityMsg = document.getElementById('mySecurityMsg');
const resetOwnTotpBtn = document.getElementById('resetOwnTotpBtn');
const topRoleBadge = document.getElementById('topRoleBadge');
const authActionBtn = document.getElementById('authActionBtn');
const addLocationBtn = document.getElementById('addLocationBtn');
const auditTrailBtn = document.getElementById('auditTrailBtn');
const eventViewerBtn = document.getElementById('eventViewerBtn');
const auditPanel = document.getElementById('auditPanel');
const eventPanel = document.getElementById('eventPanel');
const auditTrailList = document.getElementById('auditTrailList');
const eventViewerLog = document.getElementById('eventViewerLog');
const eventSearchInput = document.getElementById('eventSearchInput');
const eventClassFilter = document.getElementById('eventClassFilter');
const eventSourceFilter = document.getElementById('eventSourceFilter');
const eventViewerClose = document.getElementById('eventViewerClose');
const roadmapBtn = document.getElementById('roadmapBtn');
const roadmapDialog = document.getElementById('roadmapDialog');
const roadmapClose = document.getElementById('roadmapClose');
const versionCheckSection = document.getElementById('versionCheckSection');
const auditRefreshBtn = document.getElementById('auditRefreshBtn');
const auditCloseBtn = document.getElementById('auditCloseBtn');
const localAuthDialog = document.getElementById('localAuthDialog');
const localAuthForm = document.getElementById('localAuthForm');
const localAuthTitle = document.getElementById('localAuthTitle');
const localAuthMsg = document.getElementById('localAuthMsg');
const localAuthEmail = document.getElementById('localAuthEmail');
const localAuthPasswordWrap = document.getElementById('localAuthPasswordWrap');
const localAuthPassword = document.getElementById('localAuthPassword');
const localAuthTotpWrap = document.getElementById('localAuthTotpWrap');
const localAuthTotp = document.getElementById('localAuthTotp');
const localAuthQrWrap = document.getElementById('localAuthQrWrap');
const localAuthQrImage = document.getElementById('localAuthQrImage');
const localAuthSecret = document.getElementById('localAuthSecret');
const localAuthSubmit = document.getElementById('localAuthSubmit');
const localAuthCancel = document.getElementById('localAuthCancel');
const addLocationDialog = document.getElementById('addLocationDialog');
const addLocationForm = document.getElementById('addLocationForm');
const addLocationName = document.getElementById('addLocationName');
const addLocationGroup = document.getElementById('addLocationGroup');
const addLocationCancel = document.getElementById('addLocationCancel');
const addDeviceDialog = document.getElementById('addDeviceDialog');
const addDeviceForm = document.getElementById('addDeviceForm');
const addDeviceName = document.getElementById('addDeviceName');
const addDeviceType = document.getElementById('addDeviceType');
const addDeviceMsg = document.getElementById('addDeviceMsg');
const addDeviceCancel = document.getElementById('addDeviceCancel');
const locationPingDialog = document.getElementById('locationPingDialog');
const locationPingForm = document.getElementById('locationPingForm');
const locationPingTitle = document.getElementById('locationPingTitle');
const locationPingMsg = document.getElementById('locationPingMsg');
const locationPingTargetInput = document.getElementById('locationPingTargetInput');
const locationPingNameInput = document.getElementById('locationPingNameInput');
const locationPingSubmit = document.getElementById('locationPingSubmit');
const locationPingDelete = document.getElementById('locationPingDelete');
const locationPingCancel = document.getElementById('locationPingCancel');
const deleteDeviceDialog = document.getElementById('deleteDeviceDialog');
const deleteDeviceForm = document.getElementById('deleteDeviceForm');
const deleteDeviceMsg = document.getElementById('deleteDeviceMsg');
const deleteDeviceCancel = document.getElementById('deleteDeviceCancel');
const deleteUserDialog = document.getElementById('deleteUserDialog');
const deleteUserForm = document.getElementById('deleteUserForm');
const deleteUserMsg = document.getElementById('deleteUserMsg');
const deleteUserCancel = document.getElementById('deleteUserCancel');
const backupPasswordDialog = document.getElementById('backupPasswordDialog');
const backupPasswordForm = document.getElementById('backupPasswordForm');
const backupPasswordInput = document.getElementById('backupPasswordInput');
const backupPasswordTitle = document.getElementById('backupPasswordTitle');
const backupPasswordMsg = document.getElementById('backupPasswordMsg');
const backupPasswordCancel = document.getElementById('backupPasswordCancel');
const confirmActionDialog = document.getElementById('confirmActionDialog');
const confirmActionForm = document.getElementById('confirmActionForm');
const confirmActionTitle = document.getElementById('confirmActionTitle');
const confirmActionMsg = document.getElementById('confirmActionMsg');
const confirmActionConfirm = document.getElementById('confirmActionConfirm');
const confirmActionCancel = document.getElementById('confirmActionCancel');
const confirmTypeToConfirmWrap = document.getElementById('confirmTypeToConfirmWrap');
const confirmTypeToConfirmInput = document.getElementById('confirmTypeToConfirmInput');
const internalDnsDialog = document.getElementById('internalDnsDialog');
const internalDnsForm = document.getElementById('internalDnsForm');
const internalDnsTargetInput = document.getElementById('internalDnsTargetInput');
const internalDnsMsg = document.getElementById('internalDnsMsg');
const internalDnsCancel = document.getElementById('internalDnsCancel');
const linuxAgentDialog = document.getElementById('linuxAgentDialog');
const linuxAgentForm = document.getElementById('linuxAgentForm');
const linuxAgentTitle = document.getElementById('linuxAgentTitle');
const linuxAgentMsg = document.getElementById('linuxAgentMsg');
const linuxAgentServerInput = document.getElementById('linuxAgentServerInput');
const linuxAgentSiteInput = document.getElementById('linuxAgentSiteInput');
const linuxAgentPasswordInput = document.getElementById('linuxAgentPasswordInput');
const linuxAgentConfirmInput = document.getElementById('linuxAgentConfirmInput');
const linuxAgentCancel = document.getElementById('linuxAgentCancel');
const linuxAgentSubmit = document.getElementById('linuxAgentSubmit');
const toast = document.getElementById('toast');
const DEFAULT_AUTO_REFRESH_MS = 60 * 1000;
const SSO_MASK = '********';
const UPTIME_SCALE_OPTIONS = [
  { id: '1h', label: '1 Hour', windowMs: 60 * 60 * 1000, bins: 24, agoLabel: '1h ago' },
  { id: '6h', label: '6 Hours', windowMs: 6 * 60 * 60 * 1000, bins: 24, agoLabel: '6h ago' },
  { id: '12h', label: '12 Hours', windowMs: 12 * 60 * 60 * 1000, bins: 24, agoLabel: '12h ago' },
  { id: '24h', label: '24 Hours', windowMs: 24 * 60 * 60 * 1000, bins: 24, agoLabel: '24h ago' },
  { id: '3d', label: '3 Days', windowMs: 3 * 24 * 60 * 60 * 1000, bins: 36, agoLabel: '3d ago' },
  { id: '7d', label: '7 Days', windowMs: 7 * 24 * 60 * 60 * 1000, bins: 42, agoLabel: '7d ago' },
  { id: '14d', label: '14 Days', windowMs: 14 * 24 * 60 * 60 * 1000, bins: 56, agoLabel: '14d ago' }
];
const DEFAULT_UPTIME_SCALE_ID = '1h';

let sites = [];
let activeEditor = null;
let activeMetaEditorSiteId = null;
let activeLanLinkEditorSiteId = null;
const dirtyMetaSites = new Set();
const uptimeScaleBySite = new Map();
let autoRefreshMs = DEFAULT_AUTO_REFRESH_MS;
let nextAutoRefreshAt = Date.now() + DEFAULT_AUTO_REFRESH_MS;
let nextAutoRefreshAtServerMs = Date.now() + DEFAULT_AUTO_REFRESH_MS;
let autoRefreshTimer = null;
let serverClockOffsetMs = 0;
let globalClockTimeZone = 'UTC';
let globalClockHourMode = '24h';
let snmpTrapPort = 1162;
let authState = {
  user: { authenticated: false, displayName: 'Guest', email: '', role: 'monitor' },
  config: { enabled: false },
  runtime: { globalDataRefreshMs: DEFAULT_AUTO_REFRESH_MS, globalClockTimeZone: 'UTC', globalClockHourMode: '24h', localTotpEnabled: true },
  alerting: { silenced: false, silencedUntil: '', silenceRemainingSec: 0 },
  system: {
    nowMs: Date.now(),
    startedAt: new Date().toISOString(),
    uptimeSec: 0,
    dependencies: { snmpget: { available: true, path: '', detail: '' } }
  }
};
let managedUsers = [];
let ssoConfigState = {};
let ldapConfigState = {};
let ldapTestPendingUsers = [];
let runtimeConfigState = {};
let sslConfigState = {};
let locationSettingsState = {
  companyName: 'My Organization',
  internalName: 'Location 1',
  customerName: '',
  sections: [
    { id: 'internal', name: 'Location 1', address: '', pingMonitors: [] }
  ]
};
let localAuthFlow = { stage: 'login', setupToken: '', email: '' };
let eventsCache = [];
let tickerAuditEvents = [];
let eventPollTimer = null;
let toastTimer = null;
let eventSearchDebounceTimer = null;
let rawTelemetrySearchDebounceTimer = null;
let lastEventFilterSignature = '';
let heartbeatCardRefs = [];
let pendingDeleteDevice = { siteId: '', siteName: '' };
let pendingDeleteUser = { email: '' };
let pendingAddDeviceCategory = '';
let pendingLocationPingMonitorSectionId = '';
let pendingLocationPingMonitorId = '';
let backupPasswordResolve = null;
let backupPasswordSubmitted = false;
let confirmActionResolve = null;
let confirmActionSubmitted = false;
let confirmActionRequiredPhrase = '';
let linuxAgentSetupResolve = null;
let linuxAgentSetupSubmitted = false;
let systemStartedAtMs = Date.now();
let alertSilenceUntilMs = 0;
let diagnosticsRenderCache = 'No diagnostics logs loaded yet.';
let rawTelemetryRenderCache = 'No raw telemetry loaded yet.';
let netflowTroublemakersRenderCache = '<p class="troublemakers-empty">No report loaded yet.</p>';
let rawTelemetryAutoTimer = null;
let refreshClockTickerTimeout = null;
let refreshClockLastLabel = '';
let refreshClockManualButton = null;
let refreshClockCountdownSpan = null;
let refreshClockStaticSpan = null;
let refreshClockInteractiveMode = false;
let manualGlobalRefreshInFlight = false;
let mfaDisabledWarningShown = false;
let uiSecondTickerTimeout = null;
const collectorToolsTerminalBySite = new Map();
const collectorToolsTerminalScrollByKey = new Map();
const collectorToolsPulseCleanupTimers = new WeakMap();
const collectorToolsExpandedSites = new Set();
const collectorDetailsExpandedSites = new Set();
const COLLECTOR_TOOLS_MAX_LINES = 180;
const COLLECTOR_TOOLS_MAX_HISTORY = 120;
const SETTINGS_UNDO_LIMIT = 50;
const TERMINAL_SCOPE_CAJAL = 'cajal-tools';
const TERMINAL_SCOPE_AGENT = 'collector-agent';
const EVENT_VIEWER_FETCH_LIMIT = 2000;
const REFRESH_CLOCK_TICK_MS = 250;
const settingsUndoStack = [];
let settingsUndoInFlight = false;
const TICKER_FALLBACK_ACTORS = new Set(['', 'system', 'unknown', 'anonymous', 'cajal', 'collector', 'collector-agent']);
let publicServiceStatuses = [];
let locationPingMonitorStatuses = [];
let systemHealthSnapshot = null;
let firewallCheckSnapshot = null;
const WEBHOOK_SECTION_ORDER = Object.freeze(['firewalls', 'collectors', 'system', 'other']);
const WEBHOOK_SECTION_LABELS = Object.freeze({
  firewalls: 'FIREWALLS',
  collectors: 'COLLECTORS',
  system: 'SYSTEM',
  other: 'OTHER'
});
const WEBHOOK_SECTION_MODE_VALUES = new Set(['warn', 'offline', 'restore', 'never']);
let webhookRoutingState = { routes: {}, sectionModes: {}, messages: {}, catalog: [], sections: [] };
let apiTokenState = { limit: 0, tokens: [], revealToken: '' };
const TOOLS_TERMINAL_DEFAULT_TOP_LEVEL_COMMANDS = Object.freeze([
  'help',
  'status',
  'snmp',
  'syslog',
  'netflow',
  'listeners',
  'ping',
  'traceroute',
  'dns',
  'clear',
  'cls'
]);
const TOOLS_TERMINAL_DEFAULT_SUBCOMMANDS = Object.freeze({
  help: [],
  status: [],
  snmp: ['poll', 'diag', 'probe'],
  syslog: ['diag'],
  netflow: ['diag', 'top'],
  listeners: [],
  ping: ['<host>'],
  traceroute: ['<host>'],
  dns: ['<hostname>'],
  clear: [],
  cls: []
});
const TOOLS_TERMINAL_COLLECTOR_TOP_LEVEL_COMMANDS = Object.freeze([
  'help',
  'status',
  'doctor',
  'deps',
  'capabilities',
  'update',
  'speedtest',
  'ping',
  'traceroute',
  'tracert',
  'dns',
  'resolve',
  'nslookup',
  'ipconfig',
  'clear',
  'cls'
]);
const TOOLS_TERMINAL_COLLECTOR_SUBCOMMANDS = Object.freeze({
  help: [],
  status: [],
  doctor: [],
  deps: [],
  capabilities: [],
  update: ['<download-url>', '<target-version>'],
  speedtest: [],
  ping: ['<host>'],
  traceroute: ['<host>'],
  tracert: ['<host>'],
  dns: ['resolve', '<hostname>'],
  resolve: ['<hostname>'],
  nslookup: ['<hostname>'],
  ipconfig: ['<interface>'],
  clear: [],
  cls: []
});
const COLLECTOR_TERMINAL_TIME_BADGES = Object.freeze([
  '12AM',
  '4AM',
  '8AM',
  '12PM',
  '4PM',
  '8PM'
]);

function setNotice(message) {
  if (userAdminMsg) userAdminMsg.textContent = String(message || '');
}

function showToast(message) {
  if (!toast) return;
  toast.textContent = String(message || 'Saved');
  toast.hidden = false;
  toast.classList.add('show');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => {
      toast.hidden = true;
    }, 140);
  }, 4000);
}

function normalizeAgentServerUrl(value = '') {
  const raw = String(value || '').trim();
  if (!raw) return '';
  return raw.replace(/\/+$/, '');
}

function shellQuoteArg(value = '') {
  return `'${String(value || '').replace(/'/g, `'\"'\"'`)}'`;
}

function powershellQuoteArg(value = '') {
  return `'${String(value || '').replace(/'/g, "''")}'`;
}

function buildCollectorEnrollCommands({ siteId = '', serverUrl = '', packageFilename = 'cajal-agent.deb' } = {}) {
  const id = String(siteId || '').trim();
  const server = normalizeAgentServerUrl(serverUrl);
  const file = String(packageFilename || 'cajal-agent.deb').trim() || 'cajal-agent.deb';
  const packageEndpoint = '/api/agent/linux/download?format=deb';
  const downloadUrl = server ? `${server}${packageEndpoint}` : packageEndpoint;
  const lines = [
    `curl -fsSL ${downloadUrl} -o ${file}`,
    `sudo dpkg -i ./${file} || sudo apt-get -f install -y`
  ];
  if (server && id) {
    lines.push(`sudo cajal-agent-setup --server ${shellQuoteArg(server)} --site ${shellQuoteArg(id)}`);
  } else {
    lines.push('sudo cajal-agent-setup');
  }
  lines.push('sudo cajal-connect-test');
  lines.push('sudo systemctl enable --now cajal-agent');
  lines.push('sudo systemctl status cajal-agent --no-pager');
  return lines;
}

function buildWindowsCollectorEnrollCommands({
  siteId = '',
  serverUrl = '',
  downloadFilename = 'cajal-windows-agent.ps1',
  downloadFormat = 'ps1'
} = {}) {
  const id = String(siteId || '').trim();
  const server = normalizeAgentServerUrl(serverUrl);
  const format = String(downloadFormat || 'ps1').trim().toLowerCase() === 'exe' ? 'exe' : 'ps1';
  const defaultName = format === 'exe' ? 'cajal-windows-agent.exe' : 'cajal-windows-agent.ps1';
  const file = String(downloadFilename || defaultName).trim() || defaultName;
  const downloadEndpoint = `/api/agent/windows/download?format=${format}`;
  const downloadUrl = server ? `${server}${downloadEndpoint}` : downloadEndpoint;
  const lines = [
    `powershell -NoProfile -ExecutionPolicy Bypass -Command "Invoke-WebRequest -UseBasicParsing ${powershellQuoteArg(downloadUrl)} -OutFile ${powershellQuoteArg(file)}"`
  ];
  const localPath = `.\\${file}`;
  if (format === 'exe') {
    const commandArgs = server && id
      ? `-Server ${powershellQuoteArg(server)} -Site ${powershellQuoteArg(id)} -Password ${powershellQuoteArg('<agent-password>')}`
      : `-Password ${powershellQuoteArg('<agent-password>')}`;
    lines.push(`powershell -NoProfile -ExecutionPolicy Bypass -Command "& ${powershellQuoteArg(localPath)} ${commandArgs}"`);
  } else {
    if (server && id) {
      lines.push(`powershell -NoProfile -ExecutionPolicy Bypass -File ${powershellQuoteArg(localPath)} -Server ${powershellQuoteArg(server)} -Site ${powershellQuoteArg(id)} -Password ${powershellQuoteArg('<agent-password>')}`);
    } else {
      lines.push(`powershell -NoProfile -ExecutionPolicy Bypass -File ${powershellQuoteArg(localPath)} -Password ${powershellQuoteArg('<agent-password>')}`);
    }
  }
  lines.push('Optional: run the command at startup using Task Scheduler (SYSTEM, highest privileges).');
  return lines;
}

function normalizeTerminalScope(value = '') {
  const raw = String(value || '').trim().toLowerCase();
  if (raw === TERMINAL_SCOPE_AGENT) return TERMINAL_SCOPE_AGENT;
  return TERMINAL_SCOPE_CAJAL;
}

function cloneForUndo(value) {
  if (value == null) return value;
  if (typeof structuredClone === 'function') {
    try {
      return structuredClone(value);
    } catch {
      // Fall through to JSON clone.
    }
  }
  try {
    return JSON.parse(JSON.stringify(value));
  } catch {
    return value;
  }
}

function escapeForCssSelector(value = '') {
  const raw = String(value || '');
  if (typeof CSS !== 'undefined' && typeof CSS.escape === 'function') {
    return CSS.escape(raw);
  }
  return raw.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function isElementVisibleForUndoFlash(el) {
  if (!(el instanceof Element)) return false;
  if (el.closest('[hidden]')) return false;
  const style = window.getComputedStyle(el);
  if (style.display === 'none' || style.visibility === 'hidden') return false;
  return el.getClientRects().length > 0;
}

function collectUndoFlashElements(target) {
  if (!target) return [];
  if (Array.isArray(target)) return target.flatMap((item) => collectUndoFlashElements(item));
  if (typeof target === 'function') return collectUndoFlashElements(target());
  if (typeof target === 'string') {
    const selector = String(target).trim();
    if (!selector) return [];
    try {
      return Array.from(document.querySelectorAll(selector));
    } catch {
      return [];
    }
  }
  if (target instanceof Element) return [target];
  return [];
}

function runUndoVisibleFlash(flashTargets = []) {
  const elements = collectUndoFlashElements(flashTargets)
    .filter((el) => isElementVisibleForUndoFlash(el))
    .filter((el, idx, arr) => arr.indexOf(el) === idx);
  if (!elements.length) return;
  elements.forEach((el) => {
    el.classList.remove('undo-visible-flash');
    // Force reflow so repeated undo flashes retrigger animation.
    void el.offsetWidth;
    el.classList.add('undo-visible-flash');
    setTimeout(() => el.classList.remove('undo-visible-flash'), 1650);
  });
}

function siteFlashSelector(siteId = '') {
  const key = String(siteId || '').trim();
  if (!key) return '';
  return `.site-tile[data-site-id="${escapeForCssSelector(key)}"]`;
}

function sectionFlashSelector(sectionId = '') {
  const key = String(sectionId || '').trim().toLowerCase();
  if (!key) return '';
  const escaped = escapeForCssSelector(key);
  return `.panel[data-section-id="${escaped}"], .location-row[data-section-id="${escaped}"]`;
}

function renderGlobalUndoButton() {
  if (!globalUndoBtn) return;
  const count = settingsUndoStack.length;
  globalUndoBtn.textContent = `Undo (${count})`;
  globalUndoBtn.disabled = !canAdmin() || settingsUndoInFlight || count === 0;
}

function clearSettingsUndoStack() {
  if (!settingsUndoStack.length) {
    renderGlobalUndoButton();
    return;
  }
  settingsUndoStack.length = 0;
  renderGlobalUndoButton();
}

function pushSettingsUndo(label = 'Settings change', undoFn = null, options = {}) {
  if (typeof undoFn !== 'function') return;
  const rawTargets = options?.flashTargets;
  const flashTargets = Array.isArray(rawTargets)
    ? rawTargets.filter(Boolean)
    : (rawTargets ? [rawTargets] : []);
  settingsUndoStack.push({
    label: String(label || 'Settings change').trim() || 'Settings change',
    undo: undoFn,
    flashTargets
  });
  if (settingsUndoStack.length > SETTINGS_UNDO_LIMIT) {
    settingsUndoStack.splice(0, settingsUndoStack.length - SETTINGS_UNDO_LIMIT);
  }
  renderGlobalUndoButton();
}

function snapshotSiteForUndo(siteId = '') {
  const key = String(siteId || '').trim();
  if (!key) return null;
  const site = sites.find((row) => String(row?.id || '').trim() === key);
  if (!site) return null;
  return cloneForUndo(site);
}

function buildRuntimeUndoPayload(snapshot = {}, keys = []) {
  const payload = {};
  const src = snapshot && typeof snapshot === 'object' ? snapshot : {};
  for (const key of keys) {
    if (!Object.prototype.hasOwnProperty.call(src, key)) continue;
    payload[key] = src[key];
  }
  return payload;
}

function isLocalTotpDisabled(config = {}) {
  if (!config || typeof config !== 'object') return false;
  return Object.prototype.hasOwnProperty.call(config, 'localTotpEnabled') && config.localTotpEnabled === false;
}

function renderRuntimeSecurityNotice(config = {}, options = {}) {
  if (!runtimeConfigMsg) return;
  const warning = isLocalTotpDisabled(config) ? 'Security warning: Local TOTP MFA is disabled.' : '';
  if (options.saved) {
    runtimeConfigMsg.textContent = warning ? `Advanced settings saved. ${warning}` : 'Advanced settings saved.';
    return;
  }
  if (warning) runtimeConfigMsg.textContent = warning;
}

function buildSsoUndoPayload(snapshot = {}) {
  const payload = {};
  if (snapshot && typeof snapshot === 'object') {
    if (typeof snapshot.tenantId === 'string') payload.tenantId = snapshot.tenantId;
    if (typeof snapshot.clientId === 'string') payload.clientId = snapshot.clientId;
    if (typeof snapshot.redirectUri === 'string') payload.redirectUri = snapshot.redirectUri;
    if (typeof snapshot.scope === 'string') payload.scope = snapshot.scope;
    if (typeof snapshot.clientSecret === 'string' && snapshot.clientSecret !== SSO_MASK) {
      payload.clientSecret = snapshot.clientSecret;
    }
  }
  return payload;
}

function sanitizeMonitorConfigForPatch(config = {}) {
  const patch = {};
  const source = config && typeof config === 'object' ? config : {};
  for (const [key, value] of Object.entries(source)) {
    if (key === 'enabled' || key === 'lastChanged' || key === 'lastChangedBy') continue;
    patch[key] = value;
  }
  return patch;
}

function buildSiteMetaUndoPayload(siteSnapshot = {}) {
  const site = siteSnapshot && typeof siteSnapshot === 'object' ? siteSnapshot : {};
  const firewall = site.firewall && typeof site.firewall === 'object' ? site.firewall : {};
  return {
    name: String(site.name || ''),
    model: String(site.model || ''),
    internalIp: String(site.internalIp || ''),
    dhcpScope: String(site.dhcpScope || ''),
    isp1: String(site.isp1 || ''),
    isp2: String(site.isp2 || ''),
    role: normalizeRole(site.role || 'firewall'),
    firewallName: String(firewall.name || ''),
    wanIp: String(firewall.wanIp || ''),
    wanIp2: String(firewall.wanIp2 || '')
  };
}

async function runLatestSettingsUndo() {
  if (!canAdmin() || settingsUndoInFlight || !settingsUndoStack.length) return;
  const entry = settingsUndoStack.pop();
  if (!entry || typeof entry.undo !== 'function') {
    renderGlobalUndoButton();
    return;
  }

  settingsUndoInFlight = true;
  renderGlobalUndoButton();
  try {
    await entry.undo();
    runUndoVisibleFlash(entry.flashTargets);
    showToast(`Undo complete: ${entry.label}`);
  } catch (err) {
    settingsUndoStack.push(entry);
    setNotice(`Undo failed: ${err.message}`);
  } finally {
    settingsUndoInFlight = false;
    renderGlobalUndoButton();
  }
}

function resolveDownloadFilename(contentDisposition = '', fallback = 'download.bin') {
  const raw = String(contentDisposition || '').trim();
  if (!raw) return fallback;
  const utf8Match = raw.match(/filename\*\s*=\s*UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) {
    try {
      return decodeURIComponent(String(utf8Match[1]).trim().replace(/^"|"$/g, ''));
    } catch {
      return String(utf8Match[1]).trim().replace(/^"|"$/g, '');
    }
  }
  const plainMatch = raw.match(/filename\s*=\s*"([^"]+)"/i) || raw.match(/filename\s*=\s*([^;]+)/i);
  if (plainMatch?.[1]) return String(plainMatch[1]).trim().replace(/^"|"$/g, '');
  return fallback;
}

async function setupCollectorAgent(siteId = '', platform = 'linux') {
  const id = String(siteId || '').trim();
  if (!id) throw new Error('Missing site id');
  const site = sites.find((row) => row.id === id);
  if (!site) throw new Error('Site not found');

  const isWindows = platform === 'windows';
  const platformLabel = isWindows ? 'Windows' : 'Linux';

  const setup = isWindows ? await askLinuxAgentSetup(site, 'Windows') : await askLinuxAgentSetup(site);
  if (!setup) return { cancelled: true };
  const setupSiteId = String(setup.siteId || '').trim();
  if (!setupSiteId || setupSiteId !== id) {
    throw new Error(`Collector site id mismatch. Re-open ${platformLabel} Agent setup.`);
  }
  const password = String(setup.password || '');
  const serverUrl = normalizeAgentServerUrl(setup.serverUrl || window.location.origin);
  if (password.length < 8) throw new Error('Password must be at least 8 characters');
  if (!isValidAgentServerUrl(serverUrl)) throw new Error('Cajal URL must start with http:// or https://');

  const bootstrap = await getJson(`/api/sites/${encodeURIComponent(id)}/collector/agent/password`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password })
  });

  let packageFilename;
  let selectedDownload = null;
  if (isWindows) {
    const downloadAttempts = [
      { format: 'exe', fallbackName: 'cajal-windows-agent.exe' },
      { format: 'ps1', fallbackName: 'cajal-windows-agent.ps1' }
    ];
    let selectedResponse = null;
    for (const attempt of downloadAttempts) {
      const endpoint = `/api/agent/windows/download?format=${attempt.format}`;
      const response = await fetch(endpoint, { cache: 'no-store' });
      if (response.ok) {
        selectedDownload = attempt;
        selectedResponse = response;
        break;
      }
      if (attempt.format === 'exe' && response.status === 404) {
        continue;
      }
      let detail = '';
      try {
        const payload = await response.json();
        detail = payload?.error || '';
      } catch {
        detail = '';
      }
      throw new Error(detail || `Failed to download Windows agent package (${response.status})`);
    }

    if (!selectedDownload || !selectedResponse) {
      throw new Error('Windows agent download is unavailable. Upload cajal-windows-agent.exe or use the PowerShell installer.');
    }
    const packageBlob = await selectedResponse.blob();
    if (!packageBlob || !Number(packageBlob.size || 0)) {
      throw new Error('Windows agent download returned empty content');
    }
    packageFilename = resolveDownloadFilename(
      selectedResponse.headers.get('content-disposition'),
      selectedDownload.fallbackName
    );
    downloadBlobFile(packageFilename, packageBlob);
  } else {
    const packageEndpoint = '/api/agent/linux/download?format=deb';
    const packageRes = await fetch(packageEndpoint, { cache: 'no-store' });
    if (!packageRes.ok) {
      let detail = '';
      try {
        const payload = await packageRes.json();
        detail = payload?.error || '';
      } catch {
        detail = '';
      }
      throw new Error(detail || `Failed to download Linux agent package (${packageRes.status})`);
    }
    const packageBlob = await packageRes.blob();
    if (!packageBlob || !Number(packageBlob.size || 0)) {
      throw new Error('Linux agent package download returned empty content');
    }
    packageFilename = resolveDownloadFilename(packageRes.headers.get('content-disposition'), 'cajal-agent.deb');
    downloadBlobFile(packageFilename, packageBlob);
  }

  let installSteps;
  if (isWindows) {
    installSteps = buildWindowsCollectorEnrollCommands({
      siteId: id,
      serverUrl,
      downloadFilename: packageFilename,
      downloadFormat: selectedDownload.format
    });
    installSteps.push(`Use the same password from this dialog when prompted by -Password (${selectedDownload.format.toUpperCase()}).`);
  } else {
    installSteps = buildCollectorEnrollCommands({
      siteId: id,
      serverUrl,
      packageFilename
    });
    installSteps.push('Use the same password from this dialog when prompted.');
  }

  const stepText = installSteps.join('\n');
  if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
    navigator.clipboard.writeText(stepText).catch(() => {});
  }

  const terminalLines = isWindows
    ? [
        `Windows agent bootstrap configured for ${site.name}.`,
        selectedDownload.format === 'exe'
          ? 'Installer type: native .exe package.'
          : 'Installer type: PowerShell script fallback (.ps1).',
        `Server URL: ${serverUrl}`,
        'Run on Windows collector host:',
        ...installSteps
      ]
    : [
        `Linux agent bootstrap configured for ${site.name}.`,
        `Server URL: ${serverUrl}`,
        'Run on collector host:',
        ...installSteps
      ];

  const term = getCollectorToolsTerminalState(id, TERMINAL_SCOPE_AGENT);
  appendCollectorToolsLines(id, terminalLines, TERMINAL_SCOPE_AGENT);
  term.pending = false;
  renderTiles();
  queueCollectorToolsTerminalScroll(id, TERMINAL_SCOPE_AGENT);

  const apiKey = isWindows ? 'windows' : 'linux';
  const apiSteps = Array.isArray(bootstrap?.[apiKey]?.installSteps) ? bootstrap[apiKey].installSteps : [];
  return {
    ok: true,
    steps: installSteps,
    apiSteps
  };
}

async function setupLinuxCollectorAgent(siteId = '') {
  return setupCollectorAgent(siteId, 'linux');
}

async function setupWindowsCollectorAgent(siteId = '') {
  return setupCollectorAgent(siteId, 'windows');
}

function getCollectorToolsTerminalState(siteId = '', scope = TERMINAL_SCOPE_CAJAL) {
  const siteKey = String(siteId || '').trim();
  const normalizedScope = normalizeTerminalScope(scope);
  if (!siteKey) {
    return {
      lines: [],
      input: 'help',
      pending: false,
      history: [],
      historyCursor: 0,
      historyDraft: ''
    };
  }
  const key = `${normalizedScope}:${siteKey}`;
  if (!collectorToolsTerminalBySite.has(key)) {
    const welcome = normalizedScope === TERMINAL_SCOPE_AGENT
      ? ['Collector agent terminal ready.', 'Press Enter to run "help".']
      : ['Cajal tools terminal ready.', 'Press Enter to run "help".'];
    collectorToolsTerminalBySite.set(key, {
      lines: welcome,
      input: 'help',
      pending: false,
      history: [],
      historyCursor: 0,
      historyDraft: ''
    });
  }
  const state = collectorToolsTerminalBySite.get(key);
  if (!Array.isArray(state.lines)) state.lines = [];
  if (typeof state.input !== 'string') state.input = '';
  if (typeof state.pending !== 'boolean') state.pending = false;
  if (!Array.isArray(state.history)) state.history = [];
  if (typeof state.historyDraft !== 'string') state.historyDraft = '';
  if (!Number.isInteger(state.historyCursor)) state.historyCursor = state.history.length;
  state.historyCursor = Math.max(0, Math.min(state.history.length, state.historyCursor));
  return state;
}

function trimCollectorToolsLines(lines = []) {
  const items = Array.isArray(lines)
    ? lines.map((line) => String(line || '').replace(/\r/g, '')).filter((line) => line.length > 0)
    : [];
  if (!items.length) return [''];
  return items.slice(-COLLECTOR_TOOLS_MAX_LINES);
}

function appendCollectorToolsLines(siteId, lines = [], scope = TERMINAL_SCOPE_CAJAL) {
  const state = getCollectorToolsTerminalState(siteId, scope);
  const merged = trimCollectorToolsLines([...(state.lines || []), ...lines]);
  state.lines = merged;
}

function collectorToolsTerminalKey(siteId = '', scope = TERMINAL_SCOPE_CAJAL) {
  const siteKey = String(siteId || '').trim();
  const normalizedScope = normalizeTerminalScope(scope);
  if (!siteKey) return '';
  return `${normalizedScope}:${siteKey}`;
}

function captureCollectorToolsTerminalScrollPositions() {
  const forms = Array.from(document.querySelectorAll('.collector-tools-terminal-form'));
  for (const form of forms) {
    const siteId = String(form?.dataset?.siteId || '').trim();
    const scope = normalizeTerminalScope(form?.dataset?.terminalScope || '');
    const key = collectorToolsTerminalKey(siteId, scope);
    if (!key) continue;
    const output = form.closest('.collector-card, .collector-terminal-card')?.querySelector('.collector-tools-terminal-window');
    if (!output) continue;
    const scrollTop = Number(output.scrollTop || 0);
    const maxTop = Math.max(0, Number(output.scrollHeight || 0) - Number(output.clientHeight || 0));
    collectorToolsTerminalScrollByKey.set(key, {
      scrollTop,
      atBottom: maxTop - scrollTop <= 2
    });
  }
}

function restoreCollectorToolsTerminalScrollPositions() {
  const forms = Array.from(document.querySelectorAll('.collector-tools-terminal-form'));
  for (const form of forms) {
    const siteId = String(form?.dataset?.siteId || '').trim();
    const scope = normalizeTerminalScope(form?.dataset?.terminalScope || '');
    const key = collectorToolsTerminalKey(siteId, scope);
    if (!key) continue;
    const saved = collectorToolsTerminalScrollByKey.get(key);
    if (!saved) continue;
    const output = form.closest('.collector-card, .collector-terminal-card')?.querySelector('.collector-tools-terminal-window');
    if (!output) continue;
    const maxTop = Math.max(0, Number(output.scrollHeight || 0) - Number(output.clientHeight || 0));
    if (saved.atBottom) {
      output.scrollTop = maxTop;
      continue;
    }
    output.scrollTop = Math.max(0, Math.min(maxTop, Number(saved.scrollTop || 0)));
  }
}

function scrollCollectorToolsTerminalToBottom(siteId = '', scope = TERMINAL_SCOPE_CAJAL) {
  const siteKey = String(siteId || '').trim();
  const normalizedScope = normalizeTerminalScope(scope);
  if (!siteKey) return;
  const forms = Array.from(document.querySelectorAll('.collector-tools-terminal-form'));
  const form = forms.find((node) => (
    String(node?.dataset?.siteId || '').trim() === siteKey
    && normalizeTerminalScope(node?.dataset?.terminalScope || '') === normalizedScope
  ));
  if (!form) return;
  const output = form.closest('.collector-card, .collector-terminal-card')?.querySelector('.collector-tools-terminal-window');
  if (!output) return;
  output.scrollTop = output.scrollHeight;
}

function queueCollectorToolsTerminalScroll(siteId = '', scope = TERMINAL_SCOPE_CAJAL) {
  const siteKey = String(siteId || '').trim();
  const normalizedScope = normalizeTerminalScope(scope);
  if (!siteKey) return;
  requestAnimationFrame(() => {
    scrollCollectorToolsTerminalToBottom(siteKey, normalizedScope);
  });
}

function focusCollectorToolsTerminalInput(siteId = '', scope = TERMINAL_SCOPE_CAJAL) {
  const siteKey = String(siteId || '').trim();
  const normalizedScope = normalizeTerminalScope(scope);
  if (!siteKey) return;
  const inputs = Array.from(document.querySelectorAll('.collector-tools-terminal-input'));
  const input = inputs.find((node) => (
    String(node?.dataset?.siteId || '').trim() === siteKey
    && normalizeTerminalScope(node?.dataset?.terminalScope || '') === normalizedScope
  ));
  if (!input || input.disabled) return;
  input.focus({ preventScroll: true });
  const length = String(input.value || '').length;
  try {
    input.setSelectionRange(length, length);
  } catch {
    // Ignore selection errors on unsupported inputs.
  }
}

function queueCollectorToolsTerminalInputFocus(siteId = '', scope = TERMINAL_SCOPE_CAJAL) {
  const siteKey = String(siteId || '').trim();
  const normalizedScope = normalizeTerminalScope(scope);
  if (!siteKey) return;
  requestAnimationFrame(() => {
    focusCollectorToolsTerminalInput(siteKey, normalizedScope);
  });
}

function pushCollectorToolsTerminalHistory(terminal, command = '') {
  if (!terminal) return;
  const value = String(command || '').trim();
  if (!value) {
    terminal.historyCursor = Array.isArray(terminal.history) ? terminal.history.length : 0;
    terminal.historyDraft = '';
    return;
  }
  if (!Array.isArray(terminal.history)) terminal.history = [];
  const history = terminal.history;
  if (!history.length || history[history.length - 1] !== value) {
    history.push(value);
    if (history.length > COLLECTOR_TOOLS_MAX_HISTORY) {
      history.splice(0, history.length - COLLECTOR_TOOLS_MAX_HISTORY);
    }
  }
  terminal.historyCursor = history.length;
  terminal.historyDraft = '';
}

function navigateCollectorToolsTerminalHistory(terminal, currentInput = '', direction = -1) {
  if (!terminal || !Array.isArray(terminal.history) || !terminal.history.length) return null;
  const step = direction < 0 ? -1 : 1;
  const historyLength = terminal.history.length;
  let cursor = Number.isInteger(terminal.historyCursor) ? terminal.historyCursor : historyLength;
  cursor = Math.max(0, Math.min(historyLength, cursor));

  if (step < 0) {
    if (cursor === 0) return null;
    if (cursor === historyLength) terminal.historyDraft = String(currentInput || '');
    cursor -= 1;
    terminal.historyCursor = cursor;
    return String(terminal.history[cursor] || '');
  }

  if (cursor >= historyLength) return null;
  cursor += 1;
  terminal.historyCursor = cursor;
  if (cursor === historyLength) return String(terminal.historyDraft || '');
  return String(terminal.history[cursor] || '');
}

function openHelpDoc(sectionId = '') {
  const id = String(sectionId || '').trim();
  const hash = id ? `#${encodeURIComponent(id)}` : '';
  window.open(`/help.html${hash}`, '_blank', 'noopener,noreferrer');
}

function getToolsTerminalProfile(siteId = '', scope = TERMINAL_SCOPE_CAJAL) {
  const normalizedScope = normalizeTerminalScope(scope);
  if (normalizedScope === TERMINAL_SCOPE_AGENT) {
    return {
      commands: TOOLS_TERMINAL_COLLECTOR_TOP_LEVEL_COMMANDS,
      subcommands: TOOLS_TERMINAL_COLLECTOR_SUBCOMMANDS
    };
  }
  return {
    commands: TOOLS_TERMINAL_DEFAULT_TOP_LEVEL_COMMANDS,
    subcommands: TOOLS_TERMINAL_DEFAULT_SUBCOMMANDS
  };
}

function toolsTerminalCommonPrefix(items = []) {
  if (!Array.isArray(items) || !items.length) return '';
  let prefix = String(items[0] || '');
  for (let i = 1; i < items.length; i += 1) {
    const current = String(items[i] || '');
    let j = 0;
    const max = Math.min(prefix.length, current.length);
    while (j < max && prefix[j] === current[j]) j += 1;
    prefix = prefix.slice(0, j);
    if (!prefix) break;
  }
  return prefix;
}

function listToolsTerminalCompletions(query = '', siteId = '', scope = TERMINAL_SCOPE_CAJAL) {
  const profile = getToolsTerminalProfile(siteId, scope);
  const topLevel = profile.commands || [];
  const subcommandMap = profile.subcommands || {};
  const normalized = String(query || '').trim().toLowerCase();
  if (!normalized) return topLevel.slice();
  const tokens = normalized.split(/\s+/).filter(Boolean);
  if (!tokens.length) return topLevel.slice();
  const rootToken = tokens[0];
  const rootMatches = topLevel.filter((cmd) => cmd.startsWith(rootToken));
  if (tokens.length === 1) {
    const subcommands = subcommandMap[rootToken];
    if (Array.isArray(subcommands) && subcommands.length) {
      return subcommands.map((sub) => `${rootToken} ${sub}`);
    }
    return rootMatches;
  }
  const subcommands = subcommandMap[rootToken];
  if (!Array.isArray(subcommands) || !subcommands.length) return [];
  const subPrefix = tokens.slice(1).join(' ');
  return subcommands
    .filter((sub) => String(sub).toLowerCase().startsWith(subPrefix))
    .map((sub) => `${rootToken} ${sub}`);
}

function formatToolsTerminalSuggestionLines(query = '', options = []) {
  const q = String(query || '').trim();
  if (!options.length) {
    return [`No command matches "${q || '?'}".`, 'Type "help" for all commands.'];
  }
  const head = q ? `Suggestions for "${q}"` : 'Suggestions';
  return [head, ...options.map((opt) => `- ${opt}`)];
}

function completeToolsTerminalInput(rawValue = '', siteId = '', scope = TERMINAL_SCOPE_CAJAL) {
  const profile = getToolsTerminalProfile(siteId, scope);
  const topLevel = profile.commands || [];
  const subcommandMap = profile.subcommands || {};
  const raw = String(rawValue || '');
  const trimmed = raw.trim().toLowerCase();
  const trailingSpace = /\s$/.test(raw);
  if (!trimmed) {
    return { changed: false, value: raw, options: topLevel.slice() };
  }

  const tokens = trimmed.split(/\s+/).filter(Boolean);
  const rootToken = tokens[0];

  if (tokens.length === 1 && !trailingSpace) {
    const options = topLevel.filter((cmd) => cmd.startsWith(rootToken));
    if (!options.length) return { changed: false, value: raw, options: [] };
    if (options.length === 1) {
      const cmd = options[0];
      const hasConcreteSubcommand = (subcommandMap[cmd] || []).some((sub) => !String(sub).startsWith('<'));
      const value = hasConcreteSubcommand ? `${cmd} ` : cmd;
      return { changed: value !== raw, value, options };
    }
    const prefix = toolsTerminalCommonPrefix(options);
    if (prefix.length > rootToken.length) {
      return { changed: true, value: prefix, options };
    }
    return { changed: false, value: raw, options };
  }

  const subcommands = subcommandMap[rootToken];
  if (!Array.isArray(subcommands) || !subcommands.length) {
    return { changed: false, value: raw, options: [] };
  }
  const concreteSubcommands = subcommands.filter((sub) => !String(sub).startsWith('<'));
  if (!concreteSubcommands.length) {
    return { changed: false, value: raw, options: [] };
  }
  const subPrefix = trailingSpace ? '' : tokens.slice(1).join(' ');
  const options = concreteSubcommands.filter((sub) => sub.startsWith(subPrefix));
  if (!options.length) return { changed: false, value: raw, options: [] };
  if (options.length === 1) {
    const value = `${rootToken} ${options[0]}`;
    return { changed: value !== raw, value, options };
  }
  const prefix = toolsTerminalCommonPrefix(options);
  if (prefix.length > subPrefix.length) {
    return { changed: true, value: `${rootToken} ${prefix}`, options };
  }
  return { changed: false, value: raw, options };
}

function downloadTextFile(filename, content, mimeType = 'application/json;charset=utf-8') {
  const blob = new Blob([String(content || '')], { type: String(mimeType || 'text/plain;charset=utf-8') });
  const href = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = href;
  link.download = filename || 'cajal-backup.cajalbak';
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(href), 2000);
}

function downloadBlobFile(filename, blob) {
  const href = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = href;
  link.download = String(filename || 'download.bin');
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(href), 2000);
}

function askBackupPassword({ title, message } = {}) {
  return new Promise((resolve) => {
    if (!backupPasswordDialog || !backupPasswordForm || !backupPasswordInput) {
      resolve('');
      return;
    }
    if (backupPasswordTitle) backupPasswordTitle.textContent = title || 'Backup Password';
    if (backupPasswordMsg) backupPasswordMsg.textContent = message || 'Enter backup password.';
    backupPasswordInput.value = '';
    backupPasswordSubmitted = false;
    backupPasswordResolve = resolve;
    if (typeof backupPasswordDialog.showModal === 'function') {
      backupPasswordDialog.showModal();
    } else {
      resolve('');
    }
  });
}

function askActionConfirm({ title, message, confirmLabel, cancelLabel, dangerous, typeToConfirm } = {}) {
  return new Promise((resolve) => {
    if (!confirmActionDialog || !confirmActionForm || !confirmActionConfirm || !confirmActionCancel) {
      resolve(false);
      return;
    }
    if (confirmActionTitle) confirmActionTitle.textContent = String(title || 'Are You Sure?');
    if (confirmActionMsg) confirmActionMsg.textContent = String(message || 'Please confirm this action.');
    confirmActionConfirm.textContent = String(confirmLabel || 'Confirm');
    confirmActionCancel.textContent = String(cancelLabel || 'Cancel');
    confirmActionConfirm.classList.toggle('meta-delete', Boolean(dangerous));
    confirmActionRequiredPhrase = String(typeToConfirm || '');
    if (confirmTypeToConfirmWrap) confirmTypeToConfirmWrap.hidden = !typeToConfirm;
    if (confirmTypeToConfirmInput) {
      confirmTypeToConfirmInput.value = '';
      confirmTypeToConfirmInput.placeholder = typeToConfirm ? `Type "${typeToConfirm}" to confirm` : '';
    }
    confirmActionConfirm.disabled = Boolean(typeToConfirm);
    confirmActionSubmitted = false;
    confirmActionResolve = resolve;
    if (typeof confirmActionDialog.showModal === 'function') {
      confirmActionDialog.showModal();
    } else {
      resolve(false);
    }
  });
}

function isValidAgentServerUrl(value = '') {
  const raw = normalizeAgentServerUrl(value);
  if (!raw) return false;
  try {
    const parsed = new URL(raw);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function askLinuxAgentSetup(site = null, platformLabel = 'Linux') {
  return new Promise((resolve) => {
    if (!linuxAgentDialog || !linuxAgentServerInput || !linuxAgentPasswordInput || !linuxAgentConfirmInput || !linuxAgentSiteInput) {
      resolve(null);
      return;
    }
    const siteName = String(site?.name || 'Collector').trim() || 'Collector';
    const siteId = String(site?.id || '').trim();
    const platform = String(platformLabel || 'Linux').trim() || 'Linux';
    if (linuxAgentTitle) linuxAgentTitle.textContent = `${platform} Agent Setup · ${siteName}`;
    if (linuxAgentSubmit) linuxAgentSubmit.textContent = `Download ${platform} Agent`;
    if (linuxAgentMsg) linuxAgentMsg.textContent = `Set the agent password, then run the copied ${platform} enroll command on the collector host. Setup pre-fills server and site automatically.`;
    linuxAgentServerInput.value = normalizeAgentServerUrl(window.location.origin);
    linuxAgentSiteInput.value = siteId;
    linuxAgentPasswordInput.value = '';
    linuxAgentConfirmInput.value = '';
    linuxAgentSetupSubmitted = false;
    linuxAgentSetupResolve = resolve;
    if (typeof linuxAgentDialog.showModal === 'function') {
      linuxAgentDialog.showModal();
      setTimeout(() => {
        linuxAgentServerInput.focus();
        linuxAgentServerInput.select();
      }, 0);
      return;
    }
    resolve(null);
  });
}

function populateSsoForm(config = {}) {
  if (!ssoConfigForm) return;
  const setValue = (name, value) => {
    const input = ssoConfigForm.querySelector(`[name="${name}"]`);
    if (input) input.value = value || '';
  };
  setValue('tenantId', config.tenantId);
  setValue('clientId', config.clientId);
  setValue('clientSecret', config.clientSecret || '');
  setValue('redirectUri', config.redirectUri);
  setValue('scope', config.scope);
}

function populateLdapForm(config = {}) {
  if (!ldapConfigForm) return;
  const setValue = (name, value) => {
    const input = ldapConfigForm.querySelector(`[name="${name}"]`);
    if (input) input.value = value ?? '';
  };
  setValue('serverUrl', config.serverUrl);
  setValue('port', config.port || 389);
  setValue('baseDn', config.baseDn);
  setValue('adminGroup', config.adminGroup);
  setValue('monitorGroup', config.monitorGroup);
  setValue('bindDn', config.bindDn);
  setValue('bindPassword', config.bindPassword || '');
  if (ldapStatusLine) {
    ldapStatusLine.textContent = config.serverUrl
      ? `LDAP: ${config.serverUrl}:${config.port || 389}`
      : 'LDAP: Not configured';
  }
}

function populateRuntimeForm(config = {}) {
  if (!runtimeConfigForm) return;
  const fields = ['syslogUdpPort', 'syslogTcpPort', 'netflowPort', 'snmpPollIntervalMs', 'flowTimeoutMs', 'pingIntervalMs', 'globalDataRefreshMs', 'wanTestIntervalMs'];
  fields.forEach((name) => {
    const input = runtimeConfigForm.querySelector(`[name="${name}"]`);
    if (input) input.value = config[name] ?? '';
  });
  const localTotpToggle = runtimeConfigForm.querySelector('[name="localTotpEnabled"]');
  if (localTotpToggle) localTotpToggle.checked = Boolean(config.localTotpEnabled);
}

function populateTeamsForm(config = {}) {
  if (!teamsConfigForm) return;
  const webhook = teamsConfigForm.querySelector('[name="teamsWebhookUrl"]');
  const timeout = teamsConfigForm.querySelector('[name="teamsWebhookTimeoutMs"]');
  if (webhook) webhook.value = String(config.teamsWebhookUrl || '').trim();
  if (timeout) timeout.value = config.teamsWebhookTimeoutMs ?? '';
  if (teamsPayloadGroupInput) teamsPayloadGroupInput.value = String(config.teamsPayloadGroup || '').trim();
}

function ensureTeamsPayloadDefaults() {
  if (teamsPayloadTitleInput && !String(teamsPayloadTitleInput.value || '').trim()) {
    teamsPayloadTitleInput.value = '[CAJAL TEST] Power Automate webhook';
  }
  if (teamsPayloadGroupInput && !String(teamsPayloadGroupInput.value || '').trim()) {
    teamsPayloadGroupInput.value = 'cajal';
  }
  if (teamsPayloadMessageInput && !String(teamsPayloadMessageInput.value || '').trim()) {
    teamsPayloadMessageInput.value = 'This is a test webhook payload from CAJAL.';
  }
}

function populateClockForm(config = {}) {
  if (!clockConfigForm) return;
  const tz = clockConfigForm.querySelector('[name="globalClockTimeZone"]');
  const mode = clockConfigForm.querySelector('[name="globalClockHourMode"]');
  if (tz) {
    if (tz.getElementsByTagName('option').length === 0) {
      let zones = null;
      if (typeof Intl !== 'undefined' && typeof Intl.supportedValuesOf === 'function') {
        try { zones = Intl.supportedValuesOf('timeZone'); } catch { /* ignore */ }
      }
      if (!zones || zones.length === 0) {
        zones = ['UTC','America/Anchorage','America/Chicago','America/Denver','America/Edmonton','America/Halifax','America/Los_Angeles','America/New_York','America/Regina','America/St_Johns','America/Toronto','America/Vancouver','America/Winnipeg','Asia/Kolkata','Asia/Shanghai','Asia/Tokyo','Australia/Sydney','Europe/Berlin','Europe/London','Europe/Paris','Pacific/Auckland','Pacific/Honolulu'];
      }
      let html = '';
      for (let i = 0; i < zones.length; i++) html += '<option value="' + zones[i] + '">' + zones[i].replace(/_/g, ' ') + '</option>';
      tz.innerHTML = html;
    }
    tz.value = config.globalClockTimeZone || 'UTC';
  }
  if (mode) mode.value = config.globalClockHourMode === '12h' ? '12h' : '24h';
}

function populateSslForm(config = {}) {
  if (!sslConfigForm) return;
  const cert = sslConfigForm.querySelector('[name="certPem"]');
  const key = sslConfigForm.querySelector('[name="keyPem"]');
  const ca = sslConfigForm.querySelector('[name="caPem"]');
  if (cert) cert.value = config.certPem || '';
  if (key) key.value = config.keyPem || '';
  if (ca) ca.value = config.caPem || '';
}

function normalizeLocationSettings(config = {}) {
  const normalizePingMonitors = (rows = []) => (Array.isArray(rows) ? rows : [])
    .map((row) => ({
      id: String(row?.id || '').trim().toLowerCase(),
      label: String(row?.label || '').trim().slice(0, 48),
      target: String(row?.target || '').trim().slice(0, 255)
    }))
    .filter((row) => row.target)
    .slice(0, 5);
  const sections = Array.isArray(config.sections)
    ? config.sections
      .map((s) => ({
        id: String(s?.id || '').trim().toLowerCase(),
        name: String(s?.name || '').trim(),
        address: String(s?.address || '').trim(),
        pingMonitors: normalizePingMonitors(s?.pingMonitors || [])
      }))
      .filter((s) => s.id && s.name)
    : [];
  const fallbackSections = [
    { id: 'internal', name: String(config.internalName || 'Location 1').trim() || 'Location 1', address: '', pingMonitors: [] }
  ];
  if (config.customerName) {
    fallbackSections.push({ id: 'customer', name: String(config.customerName).trim(), address: '', pingMonitors: [] });
  }
  const normalizedSections = sections.length ? sections : fallbackSections;
  return {
    companyName: String(config.companyName || 'My Organization').trim() || 'My Organization',
    internalName: String(config.internalName || normalizedSections[0]?.name || 'Location 1').trim() || 'Location 1',
    customerName: String(config.customerName || normalizedSections[1]?.name || '').trim(),
    sections: normalizedSections
  };
}

function currentSections() {
  const normalized = normalizeLocationSettings(locationSettingsState);
  const fromState = Array.isArray(normalized.sections) ? normalized.sections : [];
  const existingIds = new Set(fromState.map((s) => s.id));
  const extras = [];
  for (const site of sites) {
    const id = String(site?.category || '').trim().toLowerCase();
    if (!id || existingIds.has(id)) continue;
    existingIds.add(id);
    extras.push({ id, name: id.replace(/-/g, ' ').replace(/\b\w/g, (m) => m.toUpperCase()), address: '', pingMonitors: [] });
  }
  return fromState.concat(extras);
}

function locationNameForSite(site = {}) {
  const category = String(site?.category || '').trim().toLowerCase();
  if (!category) return 'Location';
  const section = currentSections().find((item) => String(item?.id || '').trim().toLowerCase() === category);
  return String(section?.name || category || 'Location').trim() || 'Location';
}

function renderLocationSectionAdmin() {
  if (!locationSectionList) return;
  const sections = currentSections();
  locationSectionList.innerHTML = sections
    .map(
      (section) => `
      <div class="location-row" data-section-id="${escapeHtml(section.id)}">
        <input class="section-name-input" value="${escapeHtml(section.name || '')}" />
        <input class="section-address-input" value="${escapeHtml(section.address || '')}" placeholder="Address" />
        <button type="button" class="save-location-section">Save</button>
        <button type="button" class="delete-location-section">Delete</button>
      </div>
    `
    )
    .join('');
}

function populateLocationForm(config = {}) {
  if (!locationConfigForm) return;
  const normalized = normalizeLocationSettings(config);
  const company = locationConfigForm.querySelector('[name="companyName"]');
  const internal = locationConfigForm.querySelector('[name="internalName"]');
  const customer = locationConfigForm.querySelector('[name="customerName"]');
  if (company) company.value = normalized.companyName;
  if (internal) internal.value = normalized.internalName;
  if (customer) customer.value = normalized.customerName;
}

function renderLocationTitles() {
  const normalized = normalizeLocationSettings(locationSettingsState);
  if (companyNameDisplay) companyNameDisplay.textContent = normalized.companyName;
  renderLocationSectionAdmin();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function protocolLabel(protocol) {
  if (protocol === 'syslog') return 'Syslog';
  if (protocol === 'snmp') return 'SNMP';
  if (protocol === 'netflow') return 'NetFlow';
  return protocol;
}

function normalizePublicServiceStatus(status = '') {
  const value = String(status || '').trim().toLowerCase();
  if (value === 'up') return 'up';
  if (value === 'down') return 'down';
  return 'unknown';
}

function publicServiceBadgeStateText(status = '') {
  const value = normalizePublicServiceStatus(status);
  if (value === 'up') return 'UP';
  return 'DOWN';
}

function normalizeLocationPingMonitorStatus(status = '') {
  const value = String(status || '').trim().toLowerCase();
  if (value === 'up') return 'up';
  if (value === 'down') return 'down';
  return 'unknown';
}

function locationPingMonitorBadgeStateText(status = '') {
  const value = normalizeLocationPingMonitorStatus(status);
  if (value === 'up') return 'UP';
  if (value === 'down') return 'DOWN';
  return 'CHECKING';
}

function locationPingMonitorStatusMapForSection(sectionId = '') {
  const key = String(sectionId || '').trim().toLowerCase();
  const map = new Map();
  if (!key) return map;
  for (const row of Array.isArray(locationPingMonitorStatuses) ? locationPingMonitorStatuses : []) {
    const rowSectionId = String(row?.sectionId || '').trim().toLowerCase();
    if (rowSectionId !== key) continue;
    const monitorId = String(row?.monitorId || '').trim().toLowerCase();
    if (!monitorId) continue;
    map.set(monitorId, row);
  }
  return map;
}

function renderLocationPingMonitorBadgesForSection(section = {}, admin = false) {
  const sectionId = String(section?.id || '').trim().toLowerCase();
  if (!sectionId) return '';
  const monitors = Array.isArray(section?.pingMonitors) ? section.pingMonitors.slice(0, 5) : [];
  const statusById = locationPingMonitorStatusMapForSection(sectionId);
  const badges = monitors
    .map((monitor) => {
      const monitorId = String(monitor?.id || '').trim().toLowerCase();
      const label = String(monitor?.label || monitor?.target || 'Ping').trim() || 'Ping';
      const target = String(monitor?.target || '').trim();
      const state = statusById.get(monitorId) || null;
      const status = normalizeLocationPingMonitorStatus(state?.status);
      const stateText = locationPingMonitorBadgeStateText(status);
      const checkedAt = String(state?.lastCheckedAt || '').trim();
      const latencyMs = Number(state?.latencyMs);
      const lastError = String(state?.lastError || '').trim();
      const titleParts = [
        `${label}${target ? ` (${target})` : ''}`,
        `status=${status}`
      ];
      if (checkedAt) titleParts.push(`checked=${formatMaybeDate(checkedAt)}`);
      if (Number.isFinite(latencyMs) && latencyMs >= 0) titleParts.push(`latency=${Math.max(1, Math.round(latencyMs))}ms`);
      if (lastError) titleParts.push(`detail=${lastError}`);
      if (admin) {
        return `<button type="button" class="public-service-badge ${status} location-ping-monitor-badge location-ping-monitor-edit" data-section-id="${escapeHtml(sectionId)}" data-monitor-id="${escapeHtml(monitorId)}" title="${escapeHtml(titleParts.join(' | '))}">${escapeHtml(label)}: ${escapeHtml(stateText)}</button>`;
      }
      return `<span class="public-service-badge ${status} location-ping-monitor-badge" title="${escapeHtml(titleParts.join(' | '))}">${escapeHtml(label)}: ${escapeHtml(stateText)}</span>`;
    })
    .join('');
  const addControl = admin && monitors.length < 5
    ? `<button type="button" class="location-ping-monitor-add public-service-badge unknown" data-section-id="${escapeHtml(sectionId)}">+ Ping</button>`
    : '';
  if (!badges && !addControl) return '';
  return `<div class="location-ping-monitor-badges" data-location-ping-badges="${escapeHtml(sectionId)}">${badges}${addControl}</div>`;
}

function renderPublicServiceBadges() {
  const badgeTargets = Array.from(document.querySelectorAll('[data-public-service-badges="tools"]'));
  if (!badgeTargets.length) return;
  const rows = Array.isArray(publicServiceStatuses) ? publicServiceStatuses : [];
  if (!rows.length) {
    const fallbackHtml = '<span class="public-service-badge unknown">Public Services: Checking</span>';
    badgeTargets.forEach((node) => {
      node.innerHTML = fallbackHtml;
    });
    return;
  }
  const badgesHtml = rows
    .map((row) => {
      const label = String(row?.label || row?.id || 'Service').trim() || 'Service';
      const serviceId = String(row?.id || '').trim().toLowerCase();
      const target = String(row?.target || '').trim();
      const status = normalizePublicServiceStatus(row?.status);
      const checkedAt = String(row?.lastCheckedAt || '').trim();
      const latencyMs = Number(row?.latencyMs);
      const latencyText = Number.isFinite(latencyMs) && latencyMs >= 0 ? ` ${latencyMs}ms` : '';
      const stateText = publicServiceBadgeStateText(status);
      const titleParts = [
        `${label}${target ? ` (${target})` : ''}`,
        `status=${status}`
      ];
      if (checkedAt) titleParts.push(`checked=${formatMaybeDate(checkedAt)}`);
      if (latencyText) titleParts.push(`latency=${latencyText.trim()}`);
      if (serviceId === 'internal-dns') {
        const editable = canAdmin();
        const title = editable
          ? `${titleParts.join(' | ')} | click to edit target`
          : titleParts.join(' | ');
        return `<button type="button" class="public-service-badge ${status} public-service-badge-editable" data-service-id="internal-dns" data-target="${escapeHtml(target)}" title="${escapeHtml(title)}" ${editable ? '' : 'disabled'}>${escapeHtml(label)}: ${escapeHtml(stateText)}</button>`;
      }
      return `<span class="public-service-badge ${status}" title="${escapeHtml(titleParts.join(' | '))}">${escapeHtml(label)}: ${escapeHtml(stateText)}</span>`;
    })
    .join('');
  badgeTargets.forEach((node) => {
    node.innerHTML = badgesHtml;
  });
}

async function loadPublicServiceStatuses() {
  try {
    const payload = await getJson('/api/public-services');
    publicServiceStatuses = Array.isArray(payload?.services) ? payload.services : [];
  } catch {
    publicServiceStatuses = [];
  }
  renderPublicServiceBadges();
}

async function loadLocationPingMonitorStatuses() {
  try {
    const payload = await getJson('/api/location-monitors');
    locationPingMonitorStatuses = Array.isArray(payload?.monitors) ? payload.monitors : [];
  } catch {
    locationPingMonitorStatuses = [];
  }
}

function normalizeRole(role) {
  const value = String(role || '').trim().toLowerCase();
  return ['firewall', 'collector', 'other'].includes(value) ? value : 'firewall';
}

function roleOptions(selectedRole) {
  const current = normalizeRole(selectedRole);
  const options = [
    { value: 'firewall', label: 'FIREWALL' },
    { value: 'collector', label: 'COLLECTOR' },
    { value: 'other', label: 'OTHER' }
  ];

  return options
    .map((opt) => `<option value="${opt.value}" ${current === opt.value ? 'selected' : ''}>${opt.label}</option>`)
    .join('');
}

function normalizeAccessRole(role) {
  const value = String(role || '').trim().toLowerCase();
  if (['admin', 'monitor'].includes(value)) return value;
  return 'monitor';
}

function canAdmin() {
  return normalizeAccessRole(authState.user?.role) === 'admin';
}

function applyAuthUi() {
  const user = authState.user || { authenticated: false, displayName: 'Guest', role: 'monitor' };
  const roleLabel = normalizeAccessRole(user.role);
  const useSso = user.authenticated ? user.provider === 'entra' : Boolean(authState.config?.enabled);
  const admin = canAdmin();
  if (topRoleBadge) {
    topRoleBadge.textContent = roleLabel;
    topRoleBadge.className = `top-role-badge ${roleLabel}`;
  }
  if (authActionBtn) {
    const displayName = user.displayName || user.email || '';
    authActionBtn.textContent = user.authenticated ? `${displayName} · Logout` : 'Login';
  }
  if (ssoStatusLine) {
    ssoStatusLine.textContent = authState.config?.enabled
      ? 'SSO: Entra configured'
      : 'SSO: Not configured (using local login fallback)';
  }
  if (systemDepsLine) {
    const snmp = authState.system?.dependencies?.snmpget || {};
    const ready = Boolean(snmp.available);
    const detail = String(snmp.detail || '').trim();
    if (ready) {
      const path = String(snmp.path || 'snmpget').trim();
      systemDepsLine.textContent = `System CLI Dependency: Ready (${path}${detail ? ` | ${detail}` : ''})`;
      systemDepsLine.className = 'system-deps-line ok';
    } else {
      systemDepsLine.textContent = `System CLI Dependency: Missing (${detail || 'required package not installed on server'})`;
      systemDepsLine.className = 'system-deps-line warn';
    }
  }
  if (ssoLoginBtn) {
    ssoLoginBtn.textContent = authState.config?.enabled ? 'Login with Entra' : 'Local Admin Login';
  }
  if (ssoConfigPanel) ssoConfigPanel.hidden = !admin;
  if (ldapConfigPanel) ldapConfigPanel.hidden = !admin;
  if (sslConfigPanel) sslConfigPanel.hidden = !admin;
  if (teamsConfigPanel) teamsConfigPanel.hidden = !admin;
  if (webhookRoutingPanel) webhookRoutingPanel.hidden = !admin;
  if (runtimeConfigPanel) runtimeConfigPanel.hidden = !admin;
  if (clockConfigPanel) clockConfigPanel.hidden = !admin;
  if (systemHealthPanel) systemHealthPanel.hidden = !admin;
  if (backupPanel) backupPanel.hidden = !admin;
  if (errorLogPanel) errorLogPanel.hidden = !admin;
  if (diagnosticsPanel) diagnosticsPanel.hidden = !admin;
  if (rawTelemetryPanel) rawTelemetryPanel.hidden = !admin;
  if (firewallCheckerPanel) firewallCheckerPanel.hidden = !admin;
  if (storagePanel) storagePanel.hidden = !admin;
  if (apiAccessPanel) apiAccessPanel.hidden = !admin;
  if (locationAdminPanel) locationAdminPanel.hidden = !admin;
  if (userAdminPanel) userAdminPanel.hidden = !admin;
  if (mySecurityPanel) mySecurityPanel.hidden = admin;
  if (!admin) setRawTelemetryAutoRefresh(false);
  if (!admin) clearSettingsUndoStack();
  if (syncNowBtn) syncNowBtn.hidden = !admin;
  if (ssoLoginBtn) ssoLoginBtn.hidden = !admin;
  document.querySelectorAll('.admin-only').forEach((el) => {
    el.hidden = !admin;
  });
  renderGlobalUndoButton();
  renderServerSelfMonitorBadges(systemHealthSnapshot, '', firewallCheckSnapshot);
}

function formatChanged(isoDate) {
  if (!isoDate) return 'never';
  const date = new Date(isoDate);
  if (Number.isNaN(date.getTime())) return 'unknown';
  return date.toLocaleString();
}

function formatMaybeDate(isoDate) {
  if (!isoDate) return 'Never';
  const d = new Date(isoDate);
  if (Number.isNaN(d.getTime())) return 'Invalid';
  return d.toLocaleString();
}

function formatMaybeTime(isoDate) {
  if (!isoDate) return 'Never';
  const d = new Date(isoDate);
  if (Number.isNaN(d.getTime())) return 'Invalid';
  return d.toLocaleTimeString();
}

function formatBytes(bytes) {
  const n = Number(bytes);
  if (!Number.isFinite(n) || n <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const idx = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  const value = n / 1024 ** idx;
  return `${value >= 10 || idx === 0 ? value.toFixed(0) : value.toFixed(1)} ${units[idx]}`;
}

function formatNetflowRate(mbpsValue) {
  const mbps = Number(mbpsValue);
  if (!Number.isFinite(mbps) || mbps <= 0) return '0.0 Mbps';
  if (mbps >= 10) return `${mbps.toFixed(1)} Mbps`;
  if (mbps >= 1) return `${mbps.toFixed(2)} Mbps`;
  const kbps = mbps * 1000;
  if (kbps >= 1) return `${kbps.toFixed(1)} Kbps`;
  return `${Math.max(1, Math.round(kbps * 1000))} bps`;
}

function formatNetflowLastError(errorValue) {
  const text = String(errorValue || '').trim();
  if (!text) return 'none';
  return text;
}

function formatPercent(value, digits = 2) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return `0.${'0'.repeat(Math.max(0, digits))}%`;
  return `${n.toFixed(Math.max(0, digits))}%`;
}

function formatTroublemakerRecordedAt(row = {}) {
  const last = String(row?.lastSeenAt || '').trim();
  const first = String(row?.firstSeenAt || '').trim();
  if (last && first && last !== first) {
    return `${formatMaybeDate(last)} (range from ${formatMaybeDate(first)})`;
  }
  if (last) return formatMaybeDate(last);
  if (first) return formatMaybeDate(first);
  return 'Unknown';
}

function renderNetflowTroublemakersReport(payload = {}, siteLabel = '') {
  const rows = Array.isArray(payload?.rows) ? payload.rows : [];
  const siteName = String(siteLabel || payload?.locationName || payload?.siteName || 'Site').trim() || 'Site';
  const uniqueIps = Math.max(0, Number(payload?.uniqueIps || 0));
  const topCount = Math.max(0, Number(payload?.topCount || 0));
  const topPercent = Math.max(0, Number(payload?.topPercent || 10));
  const totalBytes = Math.max(0, Number(payload?.totalBytes || 0));
  const topBytes = Math.max(0, Number(payload?.topBytes || 0));
  const sampledPackets = Math.max(0, Number(payload?.sampledPackets || 0));
  const sampledRecords = Math.max(0, Number(payload?.sampledRecords || 0));
  const days = Math.max(1, Number(payload?.days || 7));
  const summary = `
    <div class="troublemakers-summary-grid">
      <p><span>Site</span><strong>${escapeHtml(siteName)}</strong></p>
      <p><span>Window</span><strong>${escapeHtml(String(days))} day(s)</strong></p>
      <p><span>Top Set</span><strong>${escapeHtml(String(topCount))} of ${escapeHtml(String(uniqueIps))} (${escapeHtml(formatPercent(topPercent, 1))})</strong></p>
      <p><span>Total Usage</span><strong>${escapeHtml(formatBytes(totalBytes))}</strong></p>
      <p><span>Top Set Usage</span><strong>${escapeHtml(formatBytes(topBytes))}</strong></p>
      <p><span>Samples</span><strong>${escapeHtml(String(sampledPackets))} packets / ${escapeHtml(String(sampledRecords))} records</strong></p>
      <p><span>From</span><strong>${escapeHtml(formatMaybeDate(payload?.windowStart || ''))}</strong></p>
      <p><span>To</span><strong>${escapeHtml(formatMaybeDate(payload?.windowEnd || ''))}</strong></p>
    </div>
  `;
  if (!rows.length) {
    return `${summary}<p class="troublemakers-empty">No NetFlow usage samples matched this site for the selected window.</p>`;
  }
  const body = rows
    .map((row) => `
      <tr>
        <td>${escapeHtml(String(row.rank || ''))}</td>
        <td>${escapeHtml(String(row.ip || 'unknown'))}</td>
        <td>${escapeHtml(formatBytes(row.totalBytes || 0))}</td>
        <td>${escapeHtml(formatBytes(row.downBytes || 0))}</td>
        <td>${escapeHtml(formatBytes(row.upBytes || 0))}</td>
        <td title="${escapeHtml(formatTroublemakerRecordedAt(row))}">${escapeHtml(formatTroublemakerRecordedAt(row))}</td>
        <td>${escapeHtml(formatPercent(row.sharePercent || 0, 2))}</td>
      </tr>
    `)
    .join('');
  return `
    ${summary}
    <div class="troublemakers-table-wrap">
      <table class="troublemakers-table">
        <thead>
          <tr>
            <th>#</th>
            <th>Device IP</th>
            <th>Total</th>
            <th>Down</th>
            <th>Up</th>
            <th>Recorded</th>
            <th>Share</th>
          </tr>
        </thead>
        <tbody>${body}</tbody>
      </table>
    </div>
  `;
}

async function openNetflowTroublemakersReport(siteId = '') {
  const key = String(siteId || '').trim();
  if (!key || !netflowTroublemakersOutput) return;
  const site = sites.find((item) => item.id === key);
  netflowTroublemakersRenderCache = '<p class="troublemakers-loading">Loading NetFlow trouble makers report...</p>';
  netflowTroublemakersOutput.innerHTML = netflowTroublemakersRenderCache;
  if (typeof netflowTroublemakersDialog?.showModal === 'function' && !netflowTroublemakersDialog.open) {
    netflowTroublemakersDialog.showModal();
  }
  try {
    const payload = await getJson(`/api/sites/${encodeURIComponent(key)}/netflow/troublemakers?days=7`);
    const locationLabel = locationNameForSite(site);
    netflowTroublemakersRenderCache = renderNetflowTroublemakersReport(payload, locationLabel);
    netflowTroublemakersOutput.innerHTML = netflowTroublemakersRenderCache;
  } catch (err) {
    netflowTroublemakersRenderCache = `<p class="troublemakers-error">Failed to load report: ${escapeHtml(err.message || 'Unknown error')}</p>`;
    netflowTroublemakersOutput.innerHTML = netflowTroublemakersRenderCache;
  }
}

function formatDuration(totalSeconds) {
  if (totalSeconds == null) return 'n/a';
  const seconds = Math.max(0, Number(totalSeconds));
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function formatCountdown(ms) {
  const totalSec = Math.max(0, Math.ceil(ms / 1000));
  const min = Math.floor(totalSec / 60);
  const sec = totalSec % 60;
  return `${String(min).padStart(2, '0')}:${String(sec).padStart(2, '0')}`;
}

function splitSystemUptimeParts(ms) {
  let totalSec = Math.max(0, Math.floor(ms / 1000));
  const years = Math.floor(totalSec / (365 * 24 * 60 * 60));
  totalSec -= years * 365 * 24 * 60 * 60;
  const months = Math.floor(totalSec / (30 * 24 * 60 * 60));
  totalSec -= months * 30 * 24 * 60 * 60;
  const days = Math.floor(totalSec / (24 * 60 * 60));
  totalSec -= days * 24 * 60 * 60;
  const hours = Math.floor(totalSec / 3600);
  totalSec -= hours * 3600;
  const minutes = Math.floor(totalSec / 60);
  const seconds = totalSec % 60;
  return { years, months, days, hours, minutes, seconds };
}

function toTwoDigitSegment(value) {
  const raw = String(value ?? '').trim();
  if (!raw) return '00';
  const digitsOnly = raw.replace(/[^\d]/g, '');
  if (!digitsOnly) return '00';
  return digitsOnly.slice(-2).padStart(2, '0');
}

function formatSystemUptime(ms) {
  const parts = splitSystemUptimeParts(ms);
  return `${toTwoDigitSegment(parts.years)}Y ${toTwoDigitSegment(parts.months)}MO ${toTwoDigitSegment(parts.days)}D ${toTwoDigitSegment(parts.hours)}H ${toTwoDigitSegment(parts.minutes)}M ${toTwoDigitSegment(parts.seconds)}S`;
}

function formatUnitBadge(label = '', className = '') {
  return `<span class="time-unit ${className}">${escapeHtml(label)}</span>`;
}

function formatSystemUptimeHtml(ms, timezone = 'UTC') {
  const parts = splitSystemUptimeParts(ms);
  return `System Uptime <span class="system-time-value">${toTwoDigitSegment(parts.years)}${formatUnitBadge('Y', 'time-unit-y')} ${toTwoDigitSegment(parts.months)}${formatUnitBadge('MO', 'time-unit-mo')} ${toTwoDigitSegment(parts.days)}${formatUnitBadge('D', 'time-unit-d')} ${toTwoDigitSegment(parts.hours)}${formatUnitBadge('H', 'time-unit-h')} ${toTwoDigitSegment(parts.minutes)}${formatUnitBadge('M', 'time-unit-m')} ${toTwoDigitSegment(parts.seconds)}${formatUnitBadge('S', 'time-unit-s')}</span> <span class="system-timezone">(${escapeHtml(timezone)})</span>`;
}

function formatGlobalSystemClockParts(now = new Date()) {
  const use12h = String(globalClockHourMode || '24h').toLowerCase() === '12h';
  try {
    const formatter = new Intl.DateTimeFormat('en-US', {
      timeZone: globalClockTimeZone || 'UTC',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: use12h
    });
    const partRows = formatter.formatToParts(now);
    const read = (type, fallback = '') => String(partRows.find((part) => part.type === type)?.value || fallback).trim();
    return {
      year: toTwoDigitSegment(read('year', '00')),
      month: toTwoDigitSegment(read('month', '00')),
      day: toTwoDigitSegment(read('day', '00')),
      hour: toTwoDigitSegment(read('hour', '00')),
      minute: toTwoDigitSegment(read('minute', '00')),
      second: toTwoDigitSegment(read('second', '00')),
      dayPeriod: read('dayPeriod', '')
    };
  } catch {
    const local = new Date(now);
    let hour = local.getHours();
    let dayPeriod = '';
    if (use12h) {
      dayPeriod = hour >= 12 ? 'PM' : 'AM';
      hour = hour % 12 || 12;
    }
    return {
      year: toTwoDigitSegment(local.getFullYear()),
      month: toTwoDigitSegment(local.getMonth() + 1),
      day: toTwoDigitSegment(local.getDate()),
      hour: toTwoDigitSegment(hour),
      minute: toTwoDigitSegment(local.getMinutes()),
      second: toTwoDigitSegment(local.getSeconds()),
      dayPeriod
    };
  }
}

function formatGlobalSystemClock(now = new Date()) {
  const parts = formatGlobalSystemClockParts(now);
  const suffix = parts.dayPeriod ? ` ${parts.dayPeriod.toUpperCase()}` : '';
  return `${parts.month}/${parts.day}/${parts.year} ${parts.hour}:${parts.minute}:${parts.second}${suffix}`;
}

function formatGlobalSystemClockHtml(now = new Date(), timezone = 'UTC') {
  const parts = formatGlobalSystemClockParts(now);
  const dayPeriod = parts.dayPeriod ? ` <span class="system-day-period">${escapeHtml(parts.dayPeriod.toUpperCase())}</span>` : '';
  return `System Clock <span class="system-time-value">${escapeHtml(parts.year)}${formatUnitBadge('Y', 'time-unit-y')} ${escapeHtml(parts.month)}${formatUnitBadge('MO', 'time-unit-mo')} ${escapeHtml(parts.day)}${formatUnitBadge('D', 'time-unit-d')} ${escapeHtml(parts.hour)}${formatUnitBadge('H', 'time-unit-h')} ${escapeHtml(parts.minute)}${formatUnitBadge('M', 'time-unit-m')} ${escapeHtml(parts.second)}${formatUnitBadge('S', 'time-unit-s')}${dayPeriod}</span> <span class="system-timezone">(${escapeHtml(timezone)})</span>`;
}

function formatUptimeAxisLabel(tsMs, windowMs = 0) {
  const use12h = String(globalClockHourMode || '24h').toLowerCase() === '12h';
  const window = Number(windowMs) || 0;
  let options;
  if (window <= 24 * 60 * 60 * 1000) {
    options = {
      hour: '2-digit',
      minute: '2-digit',
      hour12: use12h
    };
  } else if (window <= 3 * 24 * 60 * 60 * 1000) {
    options = {
      month: 'numeric',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: use12h
    };
  } else {
    options = {
      month: 'numeric',
      day: 'numeric'
    };
  }

  try {
    return new Intl.DateTimeFormat('en-US', {
      timeZone: globalClockTimeZone || 'UTC',
      ...options
    }).format(new Date(tsMs));
  } catch {
    return new Intl.DateTimeFormat('en-US', options).format(new Date(tsMs));
  }
}

function eventClassLabel(classId) {
  const n = Number(classId) || 0;
  if (n >= 100 && n < 200) return 'CONFIG';
  if (n >= 200 && n < 300) return 'SYSTEM';
  if (n >= 300 && n < 400) return 'RUNTIME';
  if (n >= 400 && n < 500) return 'AUTH';
  return 'MISC';
}

function eventTypeClass(classId) {
  const type = eventClassLabel(classId);
  if (type === 'CONFIG') return 'type-config';
  if (type === 'SYSTEM') return 'type-system';
  if (type === 'RUNTIME') return 'type-runtime';
  if (type === 'AUTH') return 'type-auth';
  return 'type-misc';
}

function eventLine(e) {
  const ts = new Date(e.ts || Date.now()).toLocaleString();
  const location = String(e.location || '').trim();
  const device = String(e.device || '').trim();
  const actor = String(e.actor || 'system').trim();
  const action = String(e.action || 'event').trim();
  const locPart = location ? ` [LOC:${location}]` : '';
  const devPart = device ? ` [DEV:${device}]` : '';
  return `[${ts}] [C${String(e.classId || 0).padStart(3, '0')}] [${eventClassLabel(e.classId)}] [${String(
    e.source || 'system'
  ).toUpperCase()}]${locPart}${devPart} [ACT:${action}] [BY:${actor}] ${e.message || action || 'event'}${e.detail ? ` :: ${e.detail}` : ''}`;
}

function eventLineHtml(e) {
  const ts = escapeHtml(new Date(e.ts || Date.now()).toLocaleString());
  const classCode = escapeHtml(`C${String(e.classId || 0).padStart(3, '0')}`);
  const classLabel = escapeHtml(eventClassLabel(e.classId));
  const source = escapeHtml(String(e.source || 'system').toUpperCase());
  const location = escapeHtml(String(e.location || '').trim());
  const device = escapeHtml(String(e.device || '').trim());
  const actor = escapeHtml(String(e.actor || 'system').trim());
  const action = escapeHtml(String(e.action || 'event').trim());
  const message = escapeHtml(e.message || e.action || 'event');
  const detail = e.detail ? ` <span class="event-detail">:: ${escapeHtml(e.detail)}</span>` : '';
  const locPart = location ? ` [LOC:${location}]` : '';
  const devPart = device ? ` [DEV:${device}]` : '';
  return `<span class="event-line ${eventTypeClass(e.classId)}">[${ts}] [${classCode}] [${classLabel}] [${source}]${locPart}${devPart} [ACT:${action}] [BY:${actor}] ${message}${detail}</span>`;
}

function renderAuditTrail(events = []) {
  if (!auditTrailList) return;
  if (!events.length) {
    auditTrailList.innerHTML = '<p class="empty">No audit records.</p>';
    return;
  }
  auditTrailList.innerHTML = events
    .map(
      (e) =>
        `<article class="audit-row"><strong>C${escapeHtml(String(e.classId || 0))}</strong> ${escapeHtml(
          e.message || e.action || 'event'
        )} <span class="sub">(${escapeHtml(e.actor || 'system')} · ${escapeHtml(new Date(e.ts).toLocaleString())})</span></article>`
    )
    .join('');
}

function renderEventViewer(events = []) {
  if (!eventViewerLog) return;
  const previousMaxTop = Math.max(0, eventViewerLog.scrollHeight - eventViewerLog.clientHeight);
  const previousScrollTop = Math.max(0, Math.min(previousMaxTop, Number(eventViewerLog.scrollTop || 0)));
  const wasNearBottom = previousMaxTop - previousScrollTop <= 2;
  const classFilter = Number(eventClassFilter?.value || 0);
  const sourceFilter = String(eventSourceFilter?.value || '').trim().toLowerCase();
  const searchTerm = String(eventSearchInput?.value || '').trim().toLowerCase();
  let filtered = Array.isArray(events) ? events : [];
  if (classFilter > 0) filtered = filtered.filter((e) => Number(e.classId) === classFilter);
  if (sourceFilter) filtered = filtered.filter((e) => String(e.source || '').trim().toLowerCase() === sourceFilter);
  if (searchTerm) filtered = filtered.filter((e) => String(e._search || eventLine(e).toLowerCase()).includes(searchTerm));
  eventViewerLog.innerHTML = filtered.map((e) => e._html || eventLineHtml(e)).join('\n') || '<span class="event-line type-misc">No events yet.</span>';
  const nextMaxTop = Math.max(0, eventViewerLog.scrollHeight - eventViewerLog.clientHeight);
  eventViewerLog.scrollTop = wasNearBottom
    ? nextMaxTop
    : Math.max(0, Math.min(nextMaxTop, previousScrollTop));
}

function renderEventViewerError(message) {
  if (!eventViewerLog) return;
  const msg = String(message || 'Unable to load events');
  eventViewerLog.innerHTML = `<span class="event-line type-misc">Event Viewer error: ${escapeHtml(msg)}</span>`;
}

function refreshEventFilters(events = []) {
  if (!eventClassFilter || !eventSourceFilter) return;
  const classes = [...new Set(events.map((e) => Number(e.classId) || 0).filter(Boolean))].sort((a, b) => a - b);
  const sources = [...new Set(events.map((e) => String(e.source || '').trim().toLowerCase()).filter(Boolean))].sort();
  const signature = `${classes.join(',')}|${sources.join(',')}`;
  if (signature === lastEventFilterSignature) return;
  lastEventFilterSignature = signature;
  const classValue = eventClassFilter.value;
  const sourceValue = eventSourceFilter.value;
  eventClassFilter.innerHTML = '<option value="">All</option>' + classes.map((n) => `<option value="${n}">${n}</option>`).join('');
  eventSourceFilter.innerHTML = '<option value="">All</option>' + sources.map((s) => `<option value="${escapeHtml(s)}">${escapeHtml(s)}</option>`).join('');
  if (classes.includes(Number(classValue))) eventClassFilter.value = classValue;
  if (sources.includes(String(sourceValue || '').toLowerCase())) eventSourceFilter.value = sourceValue;
}

async function loadAuditTrail() {
  const payload = await getJson('/api/audit?limit=300');
  const events = Array.isArray(payload.events) ? payload.events : [];
  renderAuditTrail(events);
}

async function loadTickerAuditEvents() {
  try {
    const payload = await getJson('/api/audit?limit=500');
    tickerAuditEvents = Array.isArray(payload?.events) ? payload.events : [];
  } catch {
    tickerAuditEvents = [];
  }
}

async function loadEventViewer() {
  const params = new URLSearchParams();
  params.set('limit', String(EVENT_VIEWER_FETCH_LIMIT));
  const payload = await getJson(`/api/events?${params.toString()}`);
  const events = Array.isArray(payload.events) ? payload.events : [];
  eventsCache = events.map((e) => {
    const line = eventLine(e);
    return { ...e, _search: line.toLowerCase(), _html: eventLineHtml(e) };
  });
  refreshEventFilters(events);
  renderEventViewer(eventsCache);
}

async function openEventViewer({
  source = '',
  classId = '',
  search = '',
  reload = true
} = {}) {
  if (!eventPanel) return;
  const normalizedSource = String(source || '').trim().toLowerCase();
  const normalizedClass = String(classId || '').trim();
  const normalizedSearch = String(search || '').trim();
  eventPanel.hidden = false;
  setEventPolling(true);
  if (eventSearchInput) eventSearchInput.value = normalizedSearch;
  if (eventClassFilter) eventClassFilter.value = normalizedClass;
  if (eventSourceFilter) eventSourceFilter.value = normalizedSource;

  if (reload) {
    lastEventFilterSignature = '';
    await loadEventViewer();
  } else {
    refreshEventFilters(eventsCache);
  }

  if (eventClassFilter) eventClassFilter.value = normalizedClass;
  if (eventSourceFilter) eventSourceFilter.value = normalizedSource;
  renderEventViewer(eventsCache);
}

function setEventPolling(enabled) {
  if (eventPollTimer) clearInterval(eventPollTimer);
  eventPollTimer = null;
  if (!enabled) return;
  eventPollTimer = setInterval(() => {
    loadEventViewer().catch((err) => {
      renderEventViewerError(err.message);
    });
  }, 2000);
}

function currentAutoRefreshIntervalMs() {
  return Math.max(10000, Number(autoRefreshMs) || DEFAULT_AUTO_REFRESH_MS);
}

function computeNextAutoRefreshAtServerMs(nowMs = currentServerNowMs(), intervalMs = currentAutoRefreshIntervalMs()) {
  const now = Number(nowMs);
  const safeNow = Number.isFinite(now) ? now : currentServerNowMs();
  const safeInterval = Math.max(10000, Number(intervalMs) || DEFAULT_AUTO_REFRESH_MS);
  return Math.floor(safeNow / safeInterval) * safeInterval + safeInterval;
}

function ensureRefreshClockContent(admin = false) {
  if (!refreshClock) return;
  if (admin) {
    if (refreshClockInteractiveMode && refreshClockManualButton && refreshClockCountdownSpan) return;
    refreshClock.textContent = '';
    const prefix = document.createElement('span');
    prefix.className = 'refresh-clock-prefix';
    prefix.textContent = 'Global Data';
    const actionButton = document.createElement('button');
    actionButton.type = 'button';
    actionButton.className = 'refresh-trigger-link';
    actionButton.dataset.action = 'manual-refresh';
    const countdown = document.createElement('span');
    countdown.className = 'refresh-clock-countdown';
    refreshClock.append(prefix, actionButton, countdown);
    refreshClockManualButton = actionButton;
    refreshClockCountdownSpan = countdown;
    refreshClockStaticSpan = null;
    refreshClockInteractiveMode = true;
    return;
  }
  if (!refreshClockInteractiveMode && refreshClockStaticSpan) return;
  refreshClock.textContent = '';
  const staticLabel = document.createElement('span');
  staticLabel.className = 'refresh-clock-text';
  refreshClock.append(staticLabel);
  refreshClockStaticSpan = staticLabel;
  refreshClockManualButton = null;
  refreshClockCountdownSpan = null;
  refreshClockInteractiveMode = false;
}

function renderRefreshClock() {
  if (!refreshClock) return;
  const intervalMs = currentAutoRefreshIntervalMs();
  const serverNowMs = currentServerNowMs();
  nextAutoRefreshAtServerMs = computeNextAutoRefreshAtServerMs(serverNowMs, intervalMs);
  const remaining = Math.max(0, nextAutoRefreshAtServerMs - serverNowMs);
  const admin = canAdmin();
  const countdown = formatCountdown(remaining);
  const label = `Global Data Refresh ${countdown}`;
  ensureRefreshClockContent(admin);
  const signature = `${admin ? '1' : '0'}|${manualGlobalRefreshInFlight ? '1' : '0'}|${label}`;
  if (refreshClockLastLabel !== signature) {
    if (admin) {
      const refreshLabel = manualGlobalRefreshInFlight ? 'Refreshing' : 'Refresh';
      if (refreshClockManualButton) {
        refreshClockManualButton.textContent = refreshLabel;
        refreshClockManualButton.disabled = manualGlobalRefreshInFlight;
      }
      if (refreshClockCountdownSpan) refreshClockCountdownSpan.textContent = countdown;
    } else {
      if (refreshClockStaticSpan) refreshClockStaticSpan.textContent = label;
    }
    refreshClockLastLabel = signature;
  }
  const ratio = Math.max(0, Math.min(1, 1 - (remaining / intervalMs)));
  refreshClock.style.setProperty('--refresh-progress', ratio.toFixed(4));
}

function updateStickyHeaderOffsets() {
  const topbarHeight = topbar ? topbar.offsetHeight : 0;
  document.documentElement.style.setProperty('--topbar-sticky-height', `${Math.max(0, topbarHeight)}px`);
}

function startRefreshClockAnimation() {
  if (refreshClockTickerTimeout) clearTimeout(refreshClockTickerTimeout);
  const tick = () => {
    renderRefreshClock();
    const nowMs = currentServerNowMs();
    const delayMs = Math.max(50, REFRESH_CLOCK_TICK_MS - (Math.floor(nowMs) % REFRESH_CLOCK_TICK_MS));
    refreshClockTickerTimeout = setTimeout(tick, delayMs);
  };
  tick();
}

function startUiSecondTicker() {
  if (uiSecondTickerTimeout) clearTimeout(uiSecondTickerTimeout);
  const tick = () => {
    refreshHeartbeatTimers();
    renderSystemClock();
    renderSystemUptime();
    renderAlertSilenceControls();
    const nowMs = currentServerNowMs();
    const delayMs = Math.max(25, 1000 - (Math.floor(nowMs) % 1000));
    uiSecondTickerTimeout = setTimeout(tick, delayMs);
  };
  tick();
}

function renderSystemUptime() {
  if (!systemUptime) return;
  const upMs = Math.max(0, currentServerNowMs() - systemStartedAtMs);
  const tz = String(globalClockTimeZone || 'UTC').trim() || 'UTC';
  systemUptime.innerHTML = formatSystemUptimeHtml(upMs, tz);
}

function renderSystemClock() {
  if (!systemClock) return;
  const tz = String(globalClockTimeZone || 'UTC').trim() || 'UTC';
  const serverNow = new Date(currentServerNowMs());
  systemClock.innerHTML = formatGlobalSystemClockHtml(serverNow, tz);
}

function renderAlertSilenceControls() {
  if (!silenceAlertsBtn || !silenceAlertsCountdown) return;
  const remainingMs = Math.max(0, alertSilenceUntilMs - Date.now());
  const silenced = remainingMs > 0;
  silenceAlertsBtn.textContent = silenced ? 'Re-enable Alerts' : 'Silence 15m';
  silenceAlertsBtn.classList.toggle('silence-active', silenced);
  silenceAlertsCountdown.hidden = !silenced;
  if (silenced) {
    silenceAlertsCountdown.textContent = `Alerting muted ${formatCountdown(remainingMs)}`;
  }
}

function scheduleAutoRefresh() {
  if (autoRefreshTimer) clearTimeout(autoRefreshTimer);
  const intervalMs = currentAutoRefreshIntervalMs();
  const serverNowMs = currentServerNowMs();
  nextAutoRefreshAtServerMs = computeNextAutoRefreshAtServerMs(serverNowMs, intervalMs);
  const delayMs = Math.max(25, nextAutoRefreshAtServerMs - serverNowMs);
  nextAutoRefreshAt = Date.now() + delayMs;
  renderRefreshClock();
  autoRefreshTimer = setTimeout(async () => {
    try {
      await loadDashboard({ fromGlobalClockRefresh: true });
      if (canAdmin()) await loadSystemHealth();
    } catch {
      // Keep silent for periodic refresh errors.
    } finally {
      scheduleAutoRefresh();
    }
  }, delayMs);
}

function blinkDeviceTilesOnGlobalRefresh() {
  // Keep refresh pulse lightweight: animate only top-level site cards.
  const pulseTargets = Array.from(document.querySelectorAll('.site-tile'));
  if (!pulseTargets.length) return;
  const pulseDurationSec = 1.4;
  pulseTargets.forEach((node) => {
    node.style.setProperty('--global-refresh-duration', `${pulseDurationSec.toFixed(3)}s`);
    node.classList.remove('global-refresh-unified');
    node.classList.remove('global-refresh-purple-blast');
    node.classList.remove('purple-cascade-on-refresh');
    node.classList.remove('purple-fill-to-teal-on-refresh');
  });
  // One shared reflow keeps visual start times synchronized across cards.
  void document.body.offsetWidth;
  pulseTargets.forEach((node) => {
    node.classList.add('global-refresh-unified');
    const existingTimer = collectorToolsPulseCleanupTimers.get(node);
    if (existingTimer) clearTimeout(existingTimer);
    const cleanupMs = Math.max(1200, Math.ceil(pulseDurationSec * 1000) + 160);
    const cleanupTimer = setTimeout(() => {
      node.classList.remove('global-refresh-unified');
      node.classList.remove('global-refresh-purple-blast');
      node.classList.remove('purple-cascade-on-refresh');
      node.classList.remove('purple-fill-to-teal-on-refresh');
      collectorToolsPulseCleanupTimers.delete(node);
    }, cleanupMs);
    collectorToolsPulseCleanupTimers.set(node, cleanupTimer);
  });
}

function formatRelativeTime(epochMs) {
  const diffSec = Math.max(0, Math.floor((Date.now() - epochMs) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
  if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
  return `${Math.floor(diffSec / 86400)}d ago`;
}

function shouldFallbackTickerActor(value = '') {
  const actor = String(value || '').trim().toLowerCase();
  return TICKER_FALLBACK_ACTORS.has(actor);
}

function resolveTickerActorFromAudit(site = {}, source = '', changedAtMs = NaN, fallback = 'system') {
  const sourceKey = String(source || '').trim().toLowerCase();
  if (!sourceKey || !Array.isArray(tickerAuditEvents) || !tickerAuditEvents.length) {
    return String(fallback || 'system').trim() || 'system';
  }
  const siteName = String(site?.name || '').trim().toLowerCase();
  const siteId = String(site?.id || '').trim().toLowerCase();
  let bestActor = '';
  let bestDelta = Number.POSITIVE_INFINITY;

  for (const evt of tickerAuditEvents) {
    if (String(evt?.source || '').trim().toLowerCase() !== sourceKey) continue;
    const actor = String(evt?.actor || '').trim();
    if (!actor || shouldFallbackTickerActor(actor)) continue;
    const device = String(evt?.device || '').trim().toLowerCase();
    if (device && device !== siteName && device !== siteId) continue;
    if (!Number.isFinite(changedAtMs)) return actor;
    const eventMs = Date.parse(String(evt?.ts || ''));
    if (!Number.isFinite(eventMs)) continue;
    const delta = Math.abs(eventMs - changedAtMs);
    if (delta < bestDelta) {
      bestActor = actor;
      bestDelta = delta;
    }
  }

  if (bestActor && bestDelta <= 24 * 60 * 60 * 1000) return bestActor;
  if (bestActor) return bestActor;
  return String(fallback || 'system').trim() || 'system';
}

function collectRecentChanges(siteList = []) {
  const sinceMs = Date.now() - 24 * 60 * 60 * 1000;
  const changes = [];
  const sectionNameById = new Map(
    currentSections().map((section) => [String(section.id || '').toLowerCase(), section.name || section.id || 'Location'])
  );

  siteList.forEach((site) => {
    const siteName = site.name || site.id || 'Unknown Site';
    const locationName = sectionNameById.get(String(site.category || '').toLowerCase()) || String(site.category || 'Location');
    const prefix = `${locationName} / ${siteName}`;
    const notificationsChanged = site.notifications?.lastChanged ? new Date(site.notifications.lastChanged).getTime() : NaN;
    if (!Number.isNaN(notificationsChanged) && notificationsChanged >= sinceMs) {
      const rawChangedBy = String(site.notifications?.lastChangedBy || '').trim() || 'system';
      const changedBy = shouldFallbackTickerActor(rawChangedBy)
        ? resolveTickerActorFromAudit(site, 'notifications', notificationsChanged, rawChangedBy)
        : rawChangedBy;
      if (!shouldFallbackTickerActor(changedBy)) {
        changes.push({
          at: notificationsChanged,
          text: `${prefix}: Notification targets updated by ${changedBy} ${formatRelativeTime(notificationsChanged)}`
        });
      }
    }

    const monitorConfig = site.monitorConfig || {};
    ['syslog', 'snmp', 'netflow'].forEach((protocol) => {
      const changedAt = monitorConfig?.[protocol]?.lastChanged ? new Date(monitorConfig[protocol].lastChanged).getTime() : NaN;
      if (!Number.isNaN(changedAt) && changedAt >= sinceMs) {
        const rawChangedBy = String(monitorConfig?.[protocol]?.lastChangedBy || '').trim() || 'system';
        const changedBy = shouldFallbackTickerActor(rawChangedBy)
          ? resolveTickerActorFromAudit(site, protocol, changedAt, rawChangedBy)
          : rawChangedBy;
        if (!shouldFallbackTickerActor(changedBy)) {
          changes.push({
            at: changedAt,
            text: `${prefix}: ${protocolLabel(protocol)} config updated by ${changedBy} ${formatRelativeTime(changedAt)}`
          });
        }
      }
    });
  });

  return changes.sort((a, b) => b.at - a.at);
}

function renderChangeTicker(siteList = []) {
  if (!changeTicker) return;
  const changes = collectRecentChanges(siteList);
  if (!changes.length) {
    changeTicker.textContent = 'No changes detected in the last 24 hours.';
    changeTicker.classList.remove('is-active');
    changeTickerWrap?.classList.remove('has-changes');
    updateStickyHeaderOffsets();
    return;
  }

  const feed = changes.map((item) => item.text).join('   |   ');
  changeTicker.textContent = `${feed}   |   ${feed}`;
  changeTicker.classList.add('is-active');
  changeTickerWrap?.classList.add('has-changes');
  updateStickyHeaderOffsets();
}

function currentServerNowMs() {
  const estimate = Date.now() + Number(serverClockOffsetMs || 0);
  return Number.isFinite(estimate) ? estimate : Date.now();
}

function updateServerClockOffsetEstimate(estimatedOffsetMs, sampleWeight = 0.2) {
  const next = Number(estimatedOffsetMs);
  if (!Number.isFinite(next)) return;
  const weight = Math.max(0.05, Math.min(1, Number(sampleWeight) || 0.2));
  if (!Number.isFinite(serverClockOffsetMs)) {
    serverClockOffsetMs = next;
    return;
  }
  const delta = Math.abs(next - serverClockOffsetMs);
  if (delta > 5000) {
    serverClockOffsetMs = next;
    return;
  }
  serverClockOffsetMs = (serverClockOffsetMs * (1 - weight)) + (next * weight);
}

async function getJson(url, options = {}) {
  const requestStartedAt = Date.now();
  const res = await fetch(url, options);
  const responseReceivedAt = Date.now();
  const dateHeader = res.headers.get('date');
  const serverNowMs = Date.parse(String(dateHeader || ''));
  if (Number.isFinite(serverNowMs) && serverNowMs > 0) {
    const midpoint = requestStartedAt + ((responseReceivedAt - requestStartedAt) / 2);
    updateServerClockOffsetEstimate(serverNowMs - midpoint, 0.25);
  }
  if (!res.ok) {
    const payload = await res.json().catch(() => ({}));
    throw new Error(payload.error || `Request failed: ${res.status}`);
  }
  return res.json();
}

async function loadAuthState() {
  const requestStartedAt = Date.now();
  try {
    authState = await getJson('/api/auth/me');
  } catch {
    authState = {
      user: { authenticated: false, displayName: 'Guest', email: '', role: 'monitor' },
      config: { enabled: false },
      runtime: { globalDataRefreshMs: DEFAULT_AUTO_REFRESH_MS, globalClockTimeZone: 'UTC', globalClockHourMode: '24h', localTotpEnabled: true },
      alerting: { silenced: false, silencedUntil: '', silenceRemainingSec: 0 },
      system: {
        nowMs: Date.now(),
        startedAt: new Date().toISOString(),
        uptimeSec: 0,
        dependencies: { snmpget: { available: true, path: '', detail: '' } }
      }
    };
  }
  const receivedAt = Date.now();
  const rttMs = Math.max(0, receivedAt - requestStartedAt);
  const startedAt = new Date(authState?.system?.startedAt || '').getTime();
  const explicitNowMs = Number(authState?.system?.nowMs || authState?.system?.serverNowMs || 0);
  if (Number.isFinite(explicitNowMs) && explicitNowMs > 0) {
    updateServerClockOffsetEstimate(explicitNowMs + (rttMs / 2) - receivedAt, 1);
  } else if (Number.isFinite(startedAt) && startedAt > 0) {
    const uptimeSecForNow = Number(authState?.system?.uptimeSec || 0);
    updateServerClockOffsetEstimate((startedAt + Math.max(0, uptimeSecForNow) * 1000) - receivedAt, 1);
  } else {
    updateServerClockOffsetEstimate(0, 1);
  }
  if (Number.isFinite(startedAt) && startedAt > 0) {
    systemStartedAtMs = startedAt;
  } else {
    const uptimeSec = Number(authState?.system?.uptimeSec || 0);
    systemStartedAtMs = Date.now() - Math.max(0, uptimeSec) * 1000;
  }
  const refreshMs = Number(authState?.runtime?.globalDataRefreshMs);
  autoRefreshMs = Number.isFinite(refreshMs) && refreshMs >= 10000 ? refreshMs : DEFAULT_AUTO_REFRESH_MS;
  globalClockTimeZone = String(authState?.runtime?.globalClockTimeZone || 'UTC').trim() || 'UTC';
  globalClockHourMode = String(authState?.runtime?.globalClockHourMode || '24h').trim().toLowerCase() === '12h' ? '12h' : '24h';
  alertSilenceUntilMs = new Date(String(authState?.alerting?.silencedUntil || '')).getTime();
  if (!Number.isFinite(alertSilenceUntilMs)) alertSilenceUntilMs = 0;
  applyAuthUi();
  if (canAdmin() && authState?.runtime?.localTotpEnabled === false) {
    if (!mfaDisabledWarningShown) {
      showToast('Security warning: Local TOTP MFA is disabled.');
      mfaDisabledWarningShown = true;
    }
  } else {
    mfaDisabledWarningShown = false;
  }
  renderSystemUptime();
  renderSystemClock();
  renderAlertSilenceControls();
}

function setLocalAuthStage(next = {}) {
  const stage = next.stage || 'login';
  localAuthFlow = {
    stage,
    setupToken: next.setupToken || localAuthFlow.setupToken || '',
    email: next.email || localAuthFlow.email || ''
  };

  if (!localAuthTitle || !localAuthMsg || !localAuthSubmit) return;
  localAuthEmail.disabled = stage !== 'login';
  localAuthPasswordWrap.hidden = false;
  localAuthTotpWrap.hidden = true;
  localAuthQrWrap.hidden = true;
  if (localAuthPassword) localAuthPassword.required = stage === 'login' || stage === 'set_password' || stage === 'verify_totp';
  if (localAuthTotp) localAuthTotp.required = stage === 'verify_totp' || stage === 'enroll_totp';
  if (localAuthTotp) localAuthTotp.value = '';

  if (stage === 'login') {
    localAuthTitle.textContent = 'Local Login';
    localAuthMsg.textContent = 'Enter your local account credentials.';
    localAuthSubmit.textContent = 'Login';
    localAuthPassword.placeholder = '';
    localAuthPassword.autocomplete = 'current-password';
  } else if (stage === 'set_password') {
    localAuthTitle.textContent = 'Set Local Password';
    localAuthMsg.textContent = 'First-time login: create your local password.';
    localAuthSubmit.textContent = 'Save Password';
    localAuthPassword.placeholder = 'Minimum 10 characters';
    localAuthPassword.autocomplete = 'new-password';
  } else if (stage === 'verify_totp') {
    localAuthTitle.textContent = 'Verify TOTP';
    localAuthMsg.textContent = 'Enter your 6-digit authenticator code.';
    localAuthSubmit.textContent = 'Verify';
    localAuthTotpWrap.hidden = false;
  } else if (stage === 'enroll_totp') {
    localAuthTitle.textContent = 'Enroll TOTP';
    localAuthMsg.textContent = 'Scan the QR code, then enter a 6-digit code to finish setup.';
    localAuthSubmit.textContent = 'Verify TOTP';
    localAuthPasswordWrap.hidden = true;
    localAuthTotpWrap.hidden = false;
    localAuthQrWrap.hidden = false;
    if (localAuthQrImage) localAuthQrImage.src = next.qrUrl || '';
    if (localAuthSecret) localAuthSecret.textContent = next.secret || '';
  }
}

function openLocalAuthDialog(prefillEmail = '') {
  if (!localAuthDialog) return;
  if (localAuthEmail) localAuthEmail.value = String(prefillEmail || authState.user?.email || '').trim();
  if (localAuthPassword) localAuthPassword.value = '';
  setLocalAuthStage({ stage: 'login', setupToken: '', email: localAuthEmail?.value || '' });
  if (typeof localAuthDialog.showModal === 'function') {
    localAuthDialog.showModal();
  }
}

function closeLocalAuthDialog() {
  if (!localAuthDialog) return;
  localAuthDialog.close();
  localAuthFlow = { stage: 'login', setupToken: '', email: '' };
}

function openInternalDnsDialog(currentTarget = '') {
  if (!internalDnsDialog || !internalDnsTargetInput) return;
  internalDnsTargetInput.value = String(currentTarget || '').trim();
  if (internalDnsMsg) internalDnsMsg.textContent = 'Set internal DNS target (IP or hostname). Leave blank to clear.';
  if (typeof internalDnsDialog.showModal === 'function' && !internalDnsDialog.open) {
    internalDnsDialog.showModal();
  }
  requestAnimationFrame(() => internalDnsTargetInput.focus());
}

function closeInternalDnsDialog() {
  internalDnsDialog?.close();
}

function openLocationPingMonitorDialog(options = {}) {
  if (!locationPingDialog || !locationPingForm || !locationPingTargetInput) return;
  const normalizedSectionId = String(options?.sectionId || '').trim().toLowerCase();
  const normalizedMonitorId = String(options?.monitorId || '').trim().toLowerCase();
  if (!normalizedSectionId) return;
  const section = (locationSettingsState?.sections || []).find((row) => String(row?.id || '').trim().toLowerCase() === normalizedSectionId);
  if (!section) return;
  const currentMonitors = Array.isArray(section.pingMonitors) ? section.pingMonitors.slice(0, 5) : [];
  const monitor = normalizedMonitorId
    ? currentMonitors.find((row) => String(row?.id || '').trim().toLowerCase() === normalizedMonitorId)
    : null;
  const editing = Boolean(monitor);

  pendingLocationPingMonitorSectionId = normalizedSectionId;
  pendingLocationPingMonitorId = editing ? normalizedMonitorId : '';
  locationPingForm.reset();

  if (locationPingTitle) locationPingTitle.textContent = editing ? 'Edit Ping Monitor' : 'Add Ping Monitor';
  if (locationPingSubmit) locationPingSubmit.textContent = editing ? 'Save Ping Monitor' : 'Add Ping Monitor';
  if (locationPingMsg) {
    locationPingMsg.textContent = editing
      ? 'Update IP or name, or delete this monitor.'
      : 'Set an IP address. Name is optional.';
  }
  if (locationPingDelete) locationPingDelete.hidden = !editing;

  if (editing) {
    const target = String(monitor?.target || '').trim();
    const label = String(monitor?.label || '').trim();
    locationPingTargetInput.value = target;
    if (locationPingNameInput) locationPingNameInput.value = label && label !== target ? label : '';
  }

  if (typeof locationPingDialog.showModal === 'function' && !locationPingDialog.open) {
    locationPingDialog.showModal();
  }
  requestAnimationFrame(() => locationPingTargetInput.focus());
}

function closeLocationPingMonitorDialog() {
  locationPingDialog?.close();
}

function renderManagedUsers() {
  if (!userList) return;
  if (!managedUsers.length) {
    userList.innerHTML = '<p class="empty">No users configured.</p>';
    return;
  }

  const header = `
    <div class="user-row user-row-head" aria-hidden="true">
      <span>Login</span>
      <span>Login Status</span>
      <span>Display Name</span>
      <span>Role</span>
      <span>Save</span>
      <span>Reset PW</span>
      <span>Reset TOTP</span>
      <span>Delete</span>
    </div>
  `;

  userList.innerHTML = header + managedUsers
    .map(
      (user) => `
      <div class="user-row" data-email="${escapeHtml(user.email)}">
        <span class="user-email" title="${escapeHtml(user.email)}">
          ${escapeHtml(user.email)}
        </span>
        <span class="user-login-state">
          ${!user.lastLoginAt ? '<em class="never-logged-badge">Never Logged In</em>' : `<em class="active-login-badge">Last login ${escapeHtml(new Date(user.lastLoginAt).toLocaleString())}</em>`}
        </span>
        <input class="user-name-input" value="${escapeHtml(user.displayName || '')}" />
        <select class="user-role-select">
          <option value="monitor" ${normalizeAccessRole(user.role) === 'monitor' ? 'selected' : ''}>Monitor</option>
          <option value="admin" ${normalizeAccessRole(user.role) === 'admin' ? 'selected' : ''}>Admin</option>
        </select>
        <button type="button" class="save-user-role">Save</button>
        <button type="button" class="reset-user-password">Reset PW Next Login</button>
        <button type="button" class="reset-user-totp">Reset TOTP</button>
        <button type="button" class="delete-user user-delete-btn">Delete</button>
      </div>
    `
    )
    .join('');
}

async function loadAdminSettings(url, populateFn, msgEl, onErrorFn) {
  if (!canAdmin()) return;
  try {
    const data = await getJson(url);
    populateFn(data);
  } catch (err) {
    if (msgEl) msgEl.textContent = err.message;
    if (typeof onErrorFn === 'function') onErrorFn(err);
  }
}

async function loadManagedUsers() {
  return loadAdminSettings('/api/users', (data) => {
    managedUsers = data;
    renderManagedUsers();
  }, userAdminMsg);
}

async function loadSsoSettings() {
  return loadAdminSettings('/api/settings/sso', (config) => {
    ssoConfigState = cloneForUndo(config) || {};
    populateSsoForm(ssoConfigState);
  }, ssoConfigMsg);
}

async function loadLdapSettings() {
  return loadAdminSettings('/api/settings/ldap', (config) => {
    ldapConfigState = cloneForUndo(config) || {};
    populateLdapForm(ldapConfigState);
  }, ldapConfigMsg);
}

async function loadRuntimeSettings() {
  if (!canAdmin()) return;
  try {
    runtimeConfigState = await getJson('/api/settings/runtime');
    populateRuntimeForm(runtimeConfigState);
    populateTeamsForm(runtimeConfigState);
    ensureTeamsPayloadDefaults();
    populateClockForm(runtimeConfigState);
    const refreshMs = Number(runtimeConfigState.globalDataRefreshMs);
    autoRefreshMs = Number.isFinite(refreshMs) && refreshMs >= 10000 ? refreshMs : DEFAULT_AUTO_REFRESH_MS;
    globalClockTimeZone = String(runtimeConfigState.globalClockTimeZone || 'UTC').trim() || 'UTC';
    globalClockHourMode = String(runtimeConfigState.globalClockHourMode || '24h').trim().toLowerCase() === '12h' ? '12h' : '24h';
    renderSystemClock();
    scheduleAutoRefresh();
    renderRuntimeSecurityNotice(runtimeConfigState);
  } catch (err) {
    if (runtimeConfigMsg) runtimeConfigMsg.textContent = err.message;
  }
}

function normalizeWebhookRoutingState(payload = {}) {
  const sections = Array.isArray(payload?.sections)
    ? payload.sections
      .map((row) => ({
        id: String(row?.id || '').trim().toLowerCase(),
        label: String(row?.label || '').trim()
      }))
      .filter((row) => row.id)
    : [];
  const catalog = Array.isArray(payload?.catalog)
    ? payload.catalog
      .map((row) => ({
        id: String(row?.id || '').trim().toLowerCase(),
        section: String(row?.section || '').trim().toLowerCase() || 'other',
        signal: String(row?.signal || '').trim().toLowerCase() || 'warn',
        label: String(row?.label || '').trim(),
        description: String(row?.description || '').trim()
      }))
      .filter((row) => row.id)
    : [];
  const routes = payload && typeof payload.routes === 'object' && payload.routes
    ? Object.fromEntries(
      Object.entries(payload.routes).map(([key, value]) => [String(key || '').trim().toLowerCase(), Boolean(value)])
    )
    : {};
  const sectionModes = payload && typeof payload.sectionModes === 'object' && payload.sectionModes
    ? Object.fromEntries(
      Object.entries(payload.sectionModes)
        .map(([key, value]) => [String(key || '').trim().toLowerCase(), String(value || '').trim().toLowerCase()])
        .filter(([, mode]) => WEBHOOK_SECTION_MODE_VALUES.has(mode))
    )
    : {};
  const messages = payload && typeof payload.messages === 'object' && payload.messages
    ? Object.fromEntries(
      Object.entries(payload.messages).map(([key, value]) => [String(key || '').trim().toLowerCase(), String(value ?? '').trim()])
    )
    : {};
  const mergedSections = sections.length
    ? sections
    : WEBHOOK_SECTION_ORDER
      .filter((sectionId) => catalog.some((route) => route.section === sectionId))
      .map((id) => ({ id, label: WEBHOOK_SECTION_LABELS[id] || id.toUpperCase() }));
  for (const section of mergedSections) {
    if (!WEBHOOK_SECTION_MODE_VALUES.has(sectionModes[section.id])) {
      sectionModes[section.id] = 'warn';
    }
  }
  return { sections: mergedSections, catalog, routes, sectionModes, messages };
}

function routeLabel(routeId = '') {
  const id = String(routeId || '').trim().toLowerCase();
  const match = (webhookRoutingState.catalog || []).find((row) => row.id === id);
  return match?.label || id || 'route';
}

function sectionLabel(sectionId = '') {
  const id = String(sectionId || '').trim().toLowerCase();
  const match = (webhookRoutingState.sections || []).find((row) => row.id === id);
  return match?.label || WEBHOOK_SECTION_LABELS[id] || id.toUpperCase();
}

function routeSignalLabel(signal = '') {
  const id = String(signal || '').trim().toLowerCase();
  if (id === 'offline') return 'OFFLINE';
  if (id === 'restore') return 'RESTORE';
  return 'WARN';
}

function sectionModeOptions(selected = 'warn') {
  const current = WEBHOOK_SECTION_MODE_VALUES.has(selected) ? selected : 'warn';
  const options = [
    { value: 'warn', label: 'WARN' },
    { value: 'offline', label: 'OFFLINE' },
    { value: 'restore', label: 'RESTORE' },
    { value: 'never', label: 'NEVER' }
  ];
  return options.map((option) => `<option value="${option.value}" ${option.value === current ? 'selected' : ''}>${option.label}</option>`).join('');
}

function renderWebhookRoutingSettings() {
  if (!webhookRoutingContent) return;
  const sections = Array.isArray(webhookRoutingState?.sections) ? webhookRoutingState.sections : [];
  const catalog = Array.isArray(webhookRoutingState?.catalog) ? webhookRoutingState.catalog : [];
  const routes = webhookRoutingState?.routes && typeof webhookRoutingState.routes === 'object'
    ? webhookRoutingState.routes
    : {};
  const sectionModes = webhookRoutingState?.sectionModes && typeof webhookRoutingState.sectionModes === 'object'
    ? webhookRoutingState.sectionModes
    : {};
  const messages = webhookRoutingState?.messages && typeof webhookRoutingState.messages === 'object'
    ? webhookRoutingState.messages
    : {};
  if (!catalog.length) {
    webhookRoutingContent.innerHTML = '<p class="empty">No webhook routes available.</p>';
    return;
  }
  const sectionOrder = sections.length
    ? sections.map((section) => section.id)
    : WEBHOOK_SECTION_ORDER.filter((id) => catalog.some((route) => route.section === id));
  webhookRoutingContent.innerHTML = sectionOrder.map((sectionId) => {
    const sectionRoutes = catalog.filter((route) => route.section === sectionId);
    if (!sectionRoutes.length) return '';
    const mode = WEBHOOK_SECTION_MODE_VALUES.has(sectionModes[sectionId]) ? sectionModes[sectionId] : 'warn';
    const routeRows = sectionRoutes.map((route) => {
      const enabled = routes[route.id] !== false;
      const desc = route.description || 'No description';
      const message = String(messages[route.id] || '').trim();
      return `
        <article class="webhook-routing-row" data-route-id="${escapeHtml(route.id)}">
          <div>
            <div class="webhook-routing-title">${escapeHtml(route.label || route.id)} <span class="webhook-routing-signal">${escapeHtml(routeSignalLabel(route.signal))}</span></div>
            <div class="webhook-routing-desc">${escapeHtml(desc)}</div>
            <textarea class="webhook-routing-message" data-route-id="${escapeHtml(route.id)}" rows="2" placeholder="Custom payload message (supports {{status}}, {{siteName}}, {{locationName}}...)">${escapeHtml(message)}</textarea>
            <div class="settings-actions">
              <button type="button" class="flow flow-btn webhook-routing-save-msg" data-route-id="${escapeHtml(route.id)}">Save Msg</button>
            </div>
          </div>
          <button type="button" class="flow flow-btn webhook-routing-toggle ${enabled ? 'enabled' : 'disabled'}" data-route-id="${escapeHtml(route.id)}">${enabled ? 'ON' : 'OFF'}</button>
          <button type="button" class="flow flow-btn webhook-routing-test" data-route-id="${escapeHtml(route.id)}">Test</button>
        </article>
      `;
    }).join('');
    return `
      <section class="webhook-routing-section" data-section-id="${escapeHtml(sectionId)}">
        <div class="webhook-routing-section-head">
          <div class="webhook-routing-section-title">${escapeHtml(sectionLabel(sectionId))}</div>
          <div class="webhook-routing-section-controls">
            <label>Global Mode
              <select class="webhook-routing-section-mode" data-section-id="${escapeHtml(sectionId)}">
                ${sectionModeOptions(mode)}
              </select>
            </label>
            <button type="button" class="flow flow-btn webhook-routing-section-save" data-section-id="${escapeHtml(sectionId)}">Save</button>
          </div>
        </div>
        <div class="webhook-routing-section-list">${routeRows}</div>
      </section>
    `;
  }).join('');
}

async function loadWebhookRoutingSettings() {
  return loadAdminSettings('/api/settings/webhook-routing', (payload) => {
    webhookRoutingState = normalizeWebhookRoutingState(payload);
    renderWebhookRoutingSettings();
  }, webhookRoutingMsg, () => {
    if (webhookRoutingContent) webhookRoutingContent.innerHTML = '<p class="empty">Failed to load webhook routing.</p>';
  });
}

function normalizeApiTokenState(payload = {}) {
  const limit = Number(payload?.limit);
  const tokens = Array.isArray(payload?.tokens) ? payload.tokens : [];
  return {
    limit: Number.isFinite(limit) && limit > 0 ? Math.floor(limit) : 0,
    tokens: tokens
      .map((row) => ({
        id: String(row?.id || '').trim(),
        name: String(row?.name || '').trim(),
        role: normalizeAccessRole(row?.role),
        tokenPrefix: String(row?.tokenPrefix || '').trim(),
        createdAt: String(row?.createdAt || '').trim(),
        createdBy: String(row?.createdBy || '').trim(),
        lastUsedAt: String(row?.lastUsedAt || '').trim(),
        expiresAt: String(row?.expiresAt || '').trim(),
        revokedAt: String(row?.revokedAt || '').trim(),
        status: String(row?.status || '').trim().toLowerCase()
      }))
      .filter((row) => row.id)
  };
}

function apiTokenStatusLabel(status = '') {
  const value = String(status || '').trim().toLowerCase();
  if (value === 'revoked') return 'REVOKED';
  if (value === 'expired') return 'EXPIRED';
  return 'ACTIVE';
}

function formatApiTokenStamp(isoDate = '') {
  const iso = String(isoDate || '').trim();
  if (!iso) return 'Never';
  const value = new Date(iso);
  if (Number.isNaN(value.getTime())) return 'Invalid';
  return value.toLocaleString();
}

function renderApiTokenSettings() {
  if (!apiTokenList) return;
  const rows = Array.isArray(apiTokenState.tokens) ? apiTokenState.tokens : [];
  if (!rows.length) {
    apiTokenList.innerHTML = '<p class="empty">No API tokens yet.</p>';
  } else {
    apiTokenList.innerHTML = rows.map((row) => {
      const status = (row.status === 'expired' || row.status === 'revoked') ? row.status : 'active';
      const active = status === 'active';
      const name = row.name || row.id;
      const prefix = row.tokenPrefix || 'n/a';
      const role = normalizeAccessRole(row.role);
      return `
        <article class="api-token-row" data-token-id="${escapeHtml(row.id)}">
          <div class="api-token-main">
            <div class="api-token-title">${escapeHtml(name)} <span class="api-token-status ${escapeHtml(status)}">${escapeHtml(apiTokenStatusLabel(status))}</span></div>
            <div class="api-token-meta">ID ${escapeHtml(row.id)} | Prefix ${escapeHtml(prefix)} | Role ${escapeHtml(role.toUpperCase())}</div>
            <div class="api-token-meta">Created ${escapeHtml(formatApiTokenStamp(row.createdAt))} by ${escapeHtml(row.createdBy || 'system')}</div>
            <div class="api-token-meta">Last used ${escapeHtml(formatApiTokenStamp(row.lastUsedAt))}${row.expiresAt ? ` | Expires ${escapeHtml(formatApiTokenStamp(row.expiresAt))}` : ''}</div>
          </div>
          <button type="button" class="flow flow-btn api-token-revoke" data-token-id="${escapeHtml(row.id)}" ${active ? '' : 'disabled'}>Revoke</button>
        </article>
      `;
    }).join('');
  }

  const revealToken = String(apiTokenState.revealToken || '').trim();
  if (apiTokenReveal) apiTokenReveal.hidden = !revealToken;
  if (apiTokenRevealValue) apiTokenRevealValue.textContent = revealToken;
}

async function loadApiTokenSettings() {
  if (!canAdmin()) return;
  try {
    const payload = await getJson('/api/settings/api/tokens');
    apiTokenState = { ...normalizeApiTokenState(payload), revealToken: '' };
    renderApiTokenSettings();
  } catch (err) {
    if (apiTokenMsg) apiTokenMsg.textContent = err.message;
    if (apiTokenList) apiTokenList.innerHTML = '<p class="empty">Failed to load API tokens.</p>';
  }
}


async function loadSslSettings() {
  return loadAdminSettings('/api/settings/ssl', (data) => {
    sslConfigState = data;
    populateSslForm(sslConfigState);
  }, sslConfigMsg);
}

async function loadLocationSettings() {
  try {
    locationSettingsState = normalizeLocationSettings(await getJson('/api/settings/locations'));
    if (canAdmin()) populateLocationForm(locationSettingsState);
    renderLocationTitles();
  } catch (err) {
    renderLocationTitles();
    if (locationAdminMsg) locationAdminMsg.textContent = err.message;
  }
}

function normalizeServerBadgeTone(tone = '') {
  const value = String(tone || '').trim().toLowerCase();
  if (value === 'up' || value === 'warn' || value === 'down') return value;
  return 'pending';
}

function serverHealthBadgeHtml(label = '', value = '', tone = 'pending', title = '') {
  const safeTone = normalizeServerBadgeTone(tone);
  const safeLabel = String(label || '').trim() || 'Status';
  const safeValue = String(value || '').trim() || 'n/a';
  const safeTitle = String(title || '').trim();
  const ariaLabel = safeTitle ? `${safeLabel}: ${safeValue}. ${safeTitle}` : `${safeLabel}: ${safeValue}`;
  const tooltipAttrs = safeTitle
    ? ` title="${escapeHtml(safeTitle)}" data-tooltip="${escapeHtml(safeTitle)}" tabindex="0"`
    : '';
  return `<span class="server-health-badge ${safeTone}"${tooltipAttrs} aria-label="${escapeHtml(ariaLabel)}">${escapeHtml(
    safeLabel
  )}: <strong>${escapeHtml(safeValue)}</strong></span>`;
}

function formatRefreshInterval(ms) {
  const value = Number(ms);
  if (!Number.isFinite(value) || value <= 0) return 'n/a';
  if (value >= 60000 && value % 60000 === 0) return `${Math.round(value / 60000)}m`;
  if (value >= 1000 && value % 1000 === 0) return `${Math.round(value / 1000)}s`;
  return `${Math.round(value)}ms`;
}

function protocolActivityBadge(label = '', activeCount = 0, enabledCount = 0) {
  const active = Math.max(0, Number(activeCount) || 0);
  const enabled = Math.max(0, Number(enabledCount) || 0);
  if (enabled <= 0) {
    return serverHealthBadgeHtml(label, 'OFF', 'warn', `${label} monitoring is disabled for all sites`);
  }
  if (active >= enabled) {
    return serverHealthBadgeHtml(label, `${active}/${enabled}`, 'up', `${label} telemetry active on all enabled sites`);
  }
  if (active > 0) {
    return serverHealthBadgeHtml(label, `${active}/${enabled}`, 'warn', `${label} telemetry only partially active`);
  }
  return serverHealthBadgeHtml(label, `0/${enabled}`, 'down', `${label} telemetry not active on any enabled site`);
}

function renderServerSelfMonitorBadges(data = null, errorMessage = '', firewallPayload = null) {
  if (!serverSelfMonitorBadges) return;
  if (!canAdmin()) {
    serverSelfMonitorBadges.innerHTML = '';
    return;
  }
  const errText = String(errorMessage || '').trim();
  if (errText) {
    serverSelfMonitorBadges.innerHTML = serverHealthBadgeHtml('Health Check', 'Error', 'down', errText);
    return;
  }
  if (!data || typeof data !== 'object') {
    serverSelfMonitorBadges.innerHTML = serverHealthBadgeHtml('Health Check', 'Loading', 'pending');
    return;
  }

  const snmpCli = data.snmpCli || {};
  const teams = data.teams || data.smtp || {};
  const backup = data.backup || {};
  const proc = data.process || {};
  const host = data.host || {};
  const telemetry = data.telemetry || {};
  const runtime = data.runtime || {};
  const listeners = data.listeners || {};
  const alerting = data.alerting || {};
  const firewallSummary = firewallPayload?.summary || {};

  const apiUp = Number(proc.pid) > 0;
  const uptimeSec = Math.max(0, Number(proc.uptimeSec || 0));
  const uptimeText = formatDuration(uptimeSec);
  const hostname = String(host.hostname || '').trim();
  const primaryIp = String(host.primaryIp || '').trim();
  const hostIpv4 = Array.isArray(host.ipv4) ? host.ipv4.map((v) => String(v || '').trim()).filter(Boolean) : [];
  const hostIpv6 = Array.isArray(host.ipv6) ? host.ipv6.map((v) => String(v || '').trim()).filter(Boolean) : [];
  const hostnameTone = hostname ? 'up' : 'warn';
  const ipTone = primaryIp ? 'up' : 'warn';
  const ipTitle = [
    hostIpv4.length ? `IPv4 ${hostIpv4.join(', ')}` : '',
    hostIpv6.length ? `IPv6 ${hostIpv6.join(', ')}` : ''
  ]
    .filter(Boolean)
    .join(' | ') || 'No non-loopback IP detected';
  const storageBackend = String(proc.storageBackend || '').trim().toLowerCase();
  const storageLabel = storageBackend ? storageBackend.toUpperCase() : 'UNKNOWN';
  const storageTone = storageBackend === 'postgres' ? 'up' : (storageBackend === 'file' ? 'warn' : 'down');
  const snmpTone = snmpCli.available ? 'up' : 'down';
  const snmpPath = String(snmpCli.path || '').trim();
  const snmpDetail = String(snmpCli.detail || '').trim();
  const snmpEnabledSites = Math.max(0, Number(telemetry.enabledByProtocol?.snmp || 0));
  const snmpPortsTone = snmpEnabledSites <= 0 ? 'pending' : (snmpCli.available ? 'up' : 'down');
  const snmpPortsValue = snmpEnabledSites <= 0 ? 'OFF' : '161|162';
  const snmpTelemetryBadge = snmpEnabledSites <= 0
    ? serverHealthBadgeHtml('SNMP Telemetry', 'OFF', 'pending', 'SNMP monitoring is disabled for all sites')
    : protocolActivityBadge('SNMP Telemetry', telemetry.activeByProtocol?.snmp, telemetry.enabledByProtocol?.snmp);
  const teamsEnabledSites = Math.max(0, Number(teams.enabledSites || 0));
  const teamsMode = String(teams.mode || '').trim().toLowerCase();
  const teamsEngine = teamsMode === 'teams' ? 'Teams webhook' : (teamsMode === 'smtp' ? 'SMTP relay' : 'sendmail');
  const teamsPath = String(teams.path || '').trim();
  const teamsDetail = String(teams.detail || '').trim();
  const teamsProbeOk = teams.probeOk !== false;
  let teamsTone = 'warn';
  let teamsValue = 'OFF';
  let teamsTitle = 'Teams notifications are disabled for all sites.';
  if (teamsEnabledSites > 0) {
    teamsValue = `${teamsEnabledSites} site${teamsEnabledSites === 1 ? '' : 's'}`;
    if (!teams.available) {
      teamsTone = 'down';
      teamsValue = 'MISSING';
      teamsTitle = teamsDetail || `${teamsEngine} is not ready on the CAJAL server.`;
    } else if (!teamsProbeOk) {
      teamsTone = 'warn';
      teamsTitle = `${teamsPath || teamsEngine} detected, but startup probe reported warnings${teamsDetail ? ` (${teamsDetail})` : ''}`;
    } else {
      teamsTone = 'up';
      teamsTitle = `${teamsPath || teamsEngine} ready for Teams notifications`;
    }
  } else if (teams.available) {
    teamsTitle = `${teamsPath || teamsEngine} ready. Enable notifications on collector cards to post to Teams.`;
  }
  const syslogUdpPort = Number(listeners.syslogUdpPort || 0);
  const syslogTcpPort = Number(listeners.syslogTcpPort || 0);
  const netflowPort = Number(listeners.netflowPort || 0);
  const syslogUdpUp = Number.isFinite(syslogUdpPort) && syslogUdpPort > 0;
  const syslogTcpUp = Number.isFinite(syslogTcpPort) && syslogTcpPort > 0;
  const syslogTone = syslogUdpUp && syslogTcpUp ? 'up' : ((syslogUdpUp || syslogTcpUp) ? 'warn' : 'down');
  const netflowTone = Number.isFinite(netflowPort) && netflowPort > 0 ? 'up' : 'down';
  const silenceActive = Boolean(alerting.active);
  const silenceRemainingMs = Math.max(0, Number(alerting.remainingSec || 0) * 1000);
  const alertingValue = silenceActive ? `MUTED ${formatCountdown(silenceRemainingMs)}` : 'LIVE';
  const alertingTone = silenceActive ? 'warn' : 'up';
  const heapUsedBytes = Number(proc.heapUsedBytes || 0);
  const heapTotalBytes = Number(proc.heapTotalBytes || 0);
  const heapRatio = heapTotalBytes > 0 ? heapUsedBytes / heapTotalBytes : NaN;
  const heapPct = Number.isFinite(heapRatio) ? Math.round(heapRatio * 100) : NaN;
  const heapTone = !Number.isFinite(heapRatio) ? 'pending' : (heapRatio >= 0.9 ? 'down' : (heapRatio >= 0.8 ? 'warn' : 'up'));
  const refreshValue = formatRefreshInterval(runtime.globalDataRefreshMs);
  const refreshMs = Number(runtime.globalDataRefreshMs || 0);
  const refreshTone = Number.isFinite(refreshMs) && refreshMs >= 10000 ? 'up' : 'warn';

  const lastBackupAt = String(backup.lastBackupAt || '').trim();
  const lastBackupMs = new Date(lastBackupAt).getTime();
  let backupTone = 'warn';
  let backupValue = 'Never';
  if (Number.isFinite(lastBackupMs) && lastBackupMs > 0) {
    const ageHours = Math.max(0, (Date.now() - lastBackupMs) / (60 * 60 * 1000));
    backupValue = ageHours <= 24 ? 'Fresh' : (ageHours <= 72 ? 'Stale' : 'Old');
    backupTone = ageHours <= 24 ? 'up' : (ageHours <= 72 ? 'warn' : 'down');
  }

  const fwPass = Math.max(0, Number(firewallSummary.pass || 0));
  const fwWarn = Math.max(0, Number(firewallSummary.warn || 0));
  const fwFail = Math.max(0, Number(firewallSummary.fail || 0));
  const fwUnknown = Math.max(0, Number(firewallSummary.unknown || 0));
  const fwTotal = fwPass + fwWarn + fwFail + fwUnknown;
  let firewallTone = 'pending';
  let firewallValue = 'Checking';
  if (fwTotal > 0) {
    firewallTone = fwFail > 0 ? 'down' : (fwWarn > 0 ? 'warn' : (fwUnknown > 0 ? 'pending' : 'up'));
    firewallValue = `P${fwPass}/W${fwWarn}/F${fwFail}/U${fwUnknown}`;
  } else if (firewallPayload && typeof firewallPayload === 'object') {
    firewallTone = 'up';
    firewallValue = 'N/A';
  }

  const badges = [
    // Row 1
    serverHealthBadgeHtml('API', apiUp ? 'UP' : 'DOWN', apiUp ? 'up' : 'down', `PID ${String(proc.pid || 'n/a')}`),
    serverHealthBadgeHtml('Uptime', uptimeText, apiUp ? 'up' : 'pending', `Started ${formatMaybeDate(proc.startedAt)}`),
    serverHealthBadgeHtml(
      'SNMP',
      snmpPortsValue,
      snmpPortsTone,
      snmpEnabledSites <= 0
        ? 'No SNMP monitors are enabled on sites.'
        : (snmpDetail || (snmpPath ? `Using ${snmpPath} for UDP 161 polling; UDP 162 used for traps` : 'UDP 161 polling and UDP 162 traps'))
    ),
    serverHealthBadgeHtml('FW Check', firewallValue, firewallTone, 'Open port/rules health summary from firewall checker'),
    protocolActivityBadge('NetFlow Telemetry', telemetry.activeByProtocol?.netflow, telemetry.enabledByProtocol?.netflow),
    serverHealthBadgeHtml(
      'Heap',
      Number.isFinite(heapPct) ? `${heapPct}%` : 'n/a',
      heapTone,
      `Heap ${formatBytes(heapUsedBytes)} / ${formatBytes(heapTotalBytes)}`
    ),
    // Row 2
    serverHealthBadgeHtml('Hostname', hostname || 'n/a', hostnameTone, hostname ? 'Detected from server host' : 'Hostname unavailable'),
    serverHealthBadgeHtml(
      'Storage',
      storageLabel,
      storageTone,
      storageBackend === 'file'
        ? 'File backend active. Consider Postgres for stronger durability and concurrency.'
        : `Storage backend ${storageLabel}`
    ),
    serverHealthBadgeHtml(
      'Syslog',
      `${syslogUdpUp ? syslogUdpPort : '-'}|${syslogTcpUp ? syslogTcpPort : '-'}`,
      syslogTone,
      `Syslog listeners UDP:${syslogUdpUp ? syslogUdpPort : 'down'} TCP:${syslogTcpUp ? syslogTcpPort : 'down'}`
    ),
    serverHealthBadgeHtml('Alerting', alertingValue, alertingTone, silenceActive ? 'Alerts are temporarily muted' : 'Alerts active'),
    snmpTelemetryBadge,
    serverHealthBadgeHtml('TEAMS', teamsValue, teamsTone, teamsTitle),
    // Row 3
    serverHealthBadgeHtml('Server IP', primaryIp || 'n/a', ipTone, ipTitle),
    serverHealthBadgeHtml('Refresh', refreshValue, refreshTone, `Global refresh interval ${String(runtime.globalDataRefreshMs || 'n/a')} ms`),
    serverHealthBadgeHtml('NetFlow Port', netflowTone === 'up' ? String(netflowPort) : 'DOWN', netflowTone, 'NetFlow listener (UDP)'),
    serverHealthBadgeHtml(
      'Inventory',
      `${Math.max(0, Number(telemetry.sites || 0))}S/${Math.max(0, Number(telemetry.devices || 0))}D`,
      Number(telemetry.sites || 0) > 0 ? 'up' : 'warn',
      'Configured sites/devices'
    ),
    protocolActivityBadge('Syslog Telemetry', telemetry.activeByProtocol?.syslog, telemetry.enabledByProtocol?.syslog),
    serverHealthBadgeHtml('Backup', backupValue, backupTone, `Last backup ${formatMaybeDate(lastBackupAt)}`)
  ];

  serverSelfMonitorBadges.innerHTML = badges.join('');
}

function renderSystemHealth(data = {}) {
  if (!systemHealthContent) return;
  const snmpCli = data.snmpCli || {};
  const teams = data.teams || data.smtp || {};
  const backup = data.backup || {};
  const proc = data.process || {};
  const telemetry = data.telemetry || {};
  const runtime = data.runtime || {};
  const listeners = data.listeners || {};
  const alerting = data.alerting || {};
  const storageRows = Array.isArray(data.storage) ? data.storage : [];
  const storageText = storageRows.length
    ? storageRows.map((row) => `${row.name}: ${formatBytes(row.bytes)} (${formatMaybeDate(row.mtime)})`).join('<br/>')
    : 'No storage stats';

  systemHealthContent.innerHTML = `
    <article class="health-card">
      <h4>SNMP CLI Checker</h4>
      <p>Status: <strong>${snmpCli.available ? 'READY' : 'MISSING'}</strong></p>
      <p>Path: <strong>${escapeHtml(snmpCli.path || 'n/a')}</strong></p>
      <p>Detail: <strong>${escapeHtml(snmpCli.detail || 'n/a')}</strong></p>
    </article>
    <article class="health-card">
      <h4>Teams / Notifications</h4>
      <p>Status: <strong>${teams.available ? (teams.probeOk === false ? 'WARN' : 'READY') : 'MISSING'}</strong></p>
      <p>Mode: <strong>${escapeHtml(String(teams.mode || 'teams').toUpperCase())}</strong></p>
      <p>Webhook Host: <strong>${escapeHtml(teams.path || 'n/a')}</strong></p>
      <p>Detail: <strong>${escapeHtml(teams.detail || 'n/a')}</strong></p>
      <p>Enabled Sites: <strong>${escapeHtml(String(teams.enabledSites || 0))}</strong></p>
    </article>
    <article class="health-card">
      <h4>Backup Health</h4>
      <p>Last Backup: <strong>${escapeHtml(formatMaybeDate(backup.lastBackupAt))}</strong></p>
      <p>By: <strong>${escapeHtml(backup.lastBackupBy || 'n/a')}</strong></p>
      <p>Last Restore: <strong>${escapeHtml(formatMaybeDate(backup.lastRestoreAt))}</strong></p>
      <p>By: <strong>${escapeHtml(backup.lastRestoreBy || 'n/a')}</strong></p>
    </article>
    <article class="health-card">
      <h4>Process Health</h4>
      <p>Node: <strong>${escapeHtml(proc.node || 'n/a')}</strong></p>
      <p>PID: <strong>${escapeHtml(String(proc.pid || 'n/a'))}</strong></p>
      <p>Uptime: <strong>${escapeHtml(formatSystemUptime(Number(proc.uptimeSec || 0) * 1000))}</strong></p>
      <p>Memory: <strong>RSS ${escapeHtml(formatBytes(proc.rssBytes))}, Heap ${escapeHtml(formatBytes(proc.heapUsedBytes))}</strong></p>
    </article>
    <article class="health-card">
      <h4>Telemetry Health</h4>
      <p>Sites/Devices: <strong>${escapeHtml(String(telemetry.sites || 0))}/${escapeHtml(String(telemetry.devices || 0))}</strong></p>
      <p>SNMP: <strong>${escapeHtml(String(telemetry.activeByProtocol?.snmp || 0))}/${escapeHtml(String(telemetry.enabledByProtocol?.snmp || 0))} active/enabled</strong></p>
      <p>Syslog: <strong>${escapeHtml(String(telemetry.activeByProtocol?.syslog || 0))}/${escapeHtml(String(telemetry.enabledByProtocol?.syslog || 0))} active/enabled</strong></p>
      <p>NetFlow: <strong>${escapeHtml(String(telemetry.activeByProtocol?.netflow || 0))}/${escapeHtml(String(telemetry.enabledByProtocol?.netflow || 0))} active/enabled</strong></p>
    </article>
    <article class="health-card">
      <h4>Runtime Health</h4>
      <p>Global Refresh: <strong>${escapeHtml(String(runtime.globalDataRefreshMs || 'n/a'))} ms</strong></p>
      <p>Clock: <strong>${escapeHtml(String(runtime.globalClockTimeZone || 'UTC'))} (${escapeHtml(String(runtime.globalClockHourMode || '24h'))})</strong></p>
      <p>Alert Silence: <strong>${alerting.active ? `ON (${formatCountdown(Number(alerting.remainingSec || 0) * 1000)} left)` : 'OFF'}</strong></p>
      <p>Listeners: <strong>syslog ${escapeHtml(String(listeners.syslogUdpPort || 'n/a'))}/${escapeHtml(String(listeners.syslogTcpPort || 'n/a'))}, netflow ${escapeHtml(String(listeners.netflowPort || 'n/a'))}</strong></p>
    </article>
    <article class="health-card">
      <h4>Storage Health</h4>
      <p>${storageText}</p>
    </article>
  `;
}

async function loadSystemHealth() {
  if (!canAdmin()) {
    renderServerSelfMonitorBadges(null, '', firewallCheckSnapshot);
    return;
  }
  if (systemHealthMsg) systemHealthMsg.textContent = 'Loading system health...';
  renderServerSelfMonitorBadges(systemHealthSnapshot, '', firewallCheckSnapshot);
  try {
    const [healthResult, firewallResult] = await Promise.allSettled([
      getJson('/api/settings/system-health'),
      getJson('/api/settings/firewall-check')
    ]);
    if (healthResult.status !== 'fulfilled') throw healthResult.reason;
    systemHealthSnapshot = healthResult.value || {};
    if (firewallResult.status === 'fulfilled') firewallCheckSnapshot = firewallResult.value || {};
    renderSystemHealth(systemHealthSnapshot);
    renderServerSelfMonitorBadges(systemHealthSnapshot, '', firewallCheckSnapshot);
    if (systemHealthMsg) systemHealthMsg.textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (err) {
    renderServerSelfMonitorBadges(systemHealthSnapshot, err?.message || 'Unable to load system health', firewallCheckSnapshot);
    if (systemHealthMsg) systemHealthMsg.textContent = err.message;
  }
}

function formatFirewallCheck(payload = {}) {
  const generatedAt = formatMaybeDate(payload.generatedAt);
  const ufw = payload.ufw || {};
  const summary = payload.summary || {};
  const checks = Array.isArray(payload.checks) ? payload.checks : [];
  const suggestions = Array.isArray(payload.suggestions) ? payload.suggestions : [];
  const lines = [];
  lines.push(`[${generatedAt}] Local Firewall Checker`);
  lines.push(`UFW available=${Boolean(ufw.available)} active=${String(ufw.active)}`);
  lines.push(`UFW status: ${String(ufw.statusText || 'n/a')}`);
  lines.push(`Summary: pass=${Number(summary.pass || 0)} warn=${Number(summary.warn || 0)} fail=${Number(summary.fail || 0)} unknown=${Number(summary.unknown || 0)}`);
  lines.push('');
  lines.push('Checks:');
  for (const check of checks) {
    const status = String(check.status || 'unknown').toUpperCase();
    const site = String(check.siteName || check.siteId || 'unknown');
    const sourceIp = String(check.sourceIp || '').trim() || 'source?';
    lines.push(
      `- [${status}] ${site} ${String(check.protocol || '').toUpperCase()} ${String(check.transport || '').toUpperCase()} ${Number(check.port || 0)} src=${sourceIp} :: ${String(check.detail || '')}`
    );
  }
  if (suggestions.length) {
    lines.push('');
    lines.push('Suggested commands:');
    for (const cmd of suggestions) lines.push(`- ${cmd}`);
  }
  return lines.join('\n');
}

function renderFirewallCheck(payload = {}) {
  if (!firewallCheckerViewer) return;
  firewallCheckerViewer.textContent = formatFirewallCheck(payload);
}

async function loadFirewallCheck() {
  if (!canAdmin()) return;
  if (firewallCheckerMsg) firewallCheckerMsg.textContent = 'Running firewall check...';
  try {
    const payload = await getJson('/api/settings/firewall-check');
    firewallCheckSnapshot = payload || {};
    renderFirewallCheck(payload || {});
    renderServerSelfMonitorBadges(systemHealthSnapshot, '', firewallCheckSnapshot);
    if (firewallCheckerMsg) firewallCheckerMsg.textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (err) {
    renderServerSelfMonitorBadges(systemHealthSnapshot, '', firewallCheckSnapshot);
    if (firewallCheckerMsg) firewallCheckerMsg.textContent = err.message;
  }
}

function formatStorageViewer(payload = {}) {
  const generatedAt = formatMaybeDate(payload.generatedAt);
  const retentionDays = Number(payload.retentionDays || 90);
  const files = Array.isArray(payload.files) ? payload.files : [];
  const lines = [];
  lines.push(`[${generatedAt}] Storage Summary`);
  lines.push(`Retention: up to ${retentionDays} days`);
  lines.push(`Current Used: ${formatBytes(payload.currentBytes)} (${formatBytes(payload.currentLogBytes)} logs)`);
  lines.push(`Estimated Max: ${formatBytes(payload.estimatedMaxBytes)} (${formatBytes(payload.estimatedLogMaxBytes)} logs)`);
  lines.push(`Headroom: ${formatBytes(payload.estimatedHeadroomBytes)} | Usage: ${Number(payload.usagePercent || 0).toFixed(1)}%`);
  lines.push('');
  lines.push('Files:');
  for (const row of files) {
    const maxText = Number(row.maxBytes || 0) > 0 ? formatBytes(row.maxBytes) : 'n/a';
    lines.push(
      `- ${String(row.name || 'unknown')} [${String(row.category || 'n/a')}] ${formatBytes(row.bytes)} / ${maxText} (${formatMaybeDate(row.mtime)})`
    );
  }
  return lines.join('\n');
}

function renderStorageSummary(payload = {}) {
  if (storageSummaryContent) {
    const retentionDays = Number(payload.retentionDays || 90);
    const policy = String(payload.retentionPolicy || `Logs and telemetry are retained for up to ${retentionDays} days.`);
    storageSummaryContent.innerHTML = `
      <article class="health-card">
        <h4>Retention Policy</h4>
        <p><strong>Up to ${escapeHtml(String(retentionDays))} days</strong></p>
        <p>${escapeHtml(policy)}</p>
      </article>
      <article class="health-card">
        <h4>Current Usage</h4>
        <p><strong>${escapeHtml(formatBytes(payload.currentBytes))}</strong></p>
        <p>Logs: ${escapeHtml(formatBytes(payload.currentLogBytes))}</p>
      </article>
      <article class="health-card">
        <h4>Estimated Maximum</h4>
        <p><strong>${escapeHtml(formatBytes(payload.estimatedMaxBytes))}</strong></p>
        <p>Logs cap: ${escapeHtml(formatBytes(payload.estimatedLogMaxBytes))}</p>
      </article>
      <article class="health-card">
        <h4>Headroom</h4>
        <p><strong>${escapeHtml(formatBytes(payload.estimatedHeadroomBytes))}</strong></p>
        <p>Usage: ${escapeHtml(Number(payload.usagePercent || 0).toFixed(1))}%</p>
      </article>
    `;
  }
  if (storageViewer) storageViewer.textContent = formatStorageViewer(payload);
}

async function loadStorageSummary() {
  if (!canAdmin()) return;
  if (storageMsg) storageMsg.textContent = 'Loading storage summary...';
  try {
    const payload = await getJson('/api/settings/storage');
    renderStorageSummary(payload || {});
    if (storageMsg) storageMsg.textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch (err) {
    if (storageMsg) storageMsg.textContent = err.message;
  }
}

async function purgeStorageSummaryLogs() {
  if (!canAdmin()) return;
  const ok = await askActionConfirm({
    title: 'Purge Logs',
    message: 'Purge all stored logs (events, error logs, diagnostics, raw telemetry)? This cannot be undone.',
    confirmLabel: 'Purge Logs',
    cancelLabel: 'Cancel',
    dangerous: true
  });
  if (!ok) return;
  if (storageMsg) storageMsg.textContent = 'Purging logs...';
  try {
    const result = await getJson('/api/settings/storage/purge-logs', { method: 'POST' });
    renderStorageSummary(result?.after || {});
    if (storageMsg) storageMsg.textContent = `Logs purged at ${formatMaybeDate(result?.purgedAt)}`;
    diagnosticsRenderCache = 'No diagnostics logs loaded yet.';
    rawTelemetryRenderCache = 'No raw telemetry loaded yet.';
    loadSystemHealth().catch(() => {});
    loadErrorLogs().catch(() => {});
    loadDiagnosticsLogs().catch(() => {});
    loadRawTelemetry().catch(() => {});
    loadEventViewer().catch(() => {});
  } catch (err) {
    if (storageMsg) storageMsg.textContent = err.message;
  }
}

async function triggerFactoryResetForDeployment() {
  if (!canAdmin()) return;
  const ok = await askActionConfirm({
    title: 'Factory Reset',
    message: 'This wipes all stored sites, devices, users, logs, tokens, and settings to a clean deployment baseline. Continue?',
    confirmLabel: 'Continue',
    cancelLabel: 'Cancel',
    dangerous: true
  });
  if (!ok) return;

  const confirmed = await askActionConfirm({
    title: 'Final Confirmation',
    message: 'Type the phrase below to authorize the factory reset.',
    confirmLabel: 'Factory Reset',
    cancelLabel: 'Cancel',
    dangerous: true,
    typeToConfirm: 'FACTORY RESET'
  });
  if (!confirmed) {
    if (runtimeConfigMsg) runtimeConfigMsg.textContent = 'Factory reset canceled.';
    return;
  }

  if (runtimeConfigMsg) runtimeConfigMsg.textContent = 'Running factory reset...';
  if (factoryResetBtn) factoryResetBtn.disabled = true;
  try {
    const payload = await getJson('/api/settings/factory-reset', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        confirmText: 'FACTORY RESET',
        mode: 'deployment'
      })
    });
    clearSettingsUndoStack();
    showToast('Factory reset complete');
    if (runtimeConfigMsg) runtimeConfigMsg.textContent = payload?.detail || 'Factory reset complete. Redirecting to login...';
    setTimeout(() => {
      window.location.assign('/login.html');
    }, 900);
  } catch (err) {
    if (runtimeConfigMsg) runtimeConfigMsg.textContent = err.message;
  } finally {
    if (factoryResetBtn) factoryResetBtn.disabled = false;
  }
}

function formatErrorEntry(entry = {}) {
  const ts = formatMaybeDate(entry.ts);
  const scope = String(entry.scope || 'unknown');
  const name = String(entry.name || 'Error');
  const message = String(entry.message || 'Unknown error');
  const code = String(entry.code || '').trim();
  const context = entry.context && typeof entry.context === 'object' ? JSON.stringify(entry.context, null, 2) : '';
  const stack = String(entry.stack || '').trim();
  const lines = [];
  lines.push(`[${ts}] ${scope}`);
  lines.push(`${name}${code ? ` (${code})` : ''}: ${message}`);
  if (context) lines.push(`Context:\n${context}`);
  if (stack) lines.push(`Stack:\n${stack}`);
  return lines.join('\n');
}

function renderErrorLogs(entries = []) {
  if (!errorLogViewer) return;
  if (!Array.isArray(entries) || !entries.length) {
    errorLogViewer.textContent = 'No error logs found.';
    return;
  }
  errorLogViewer.textContent = entries.map((entry) => formatErrorEntry(entry)).join('\n\n----------------------------------------\n\n');
}

async function loadErrorLogs() {
  if (!canAdmin()) return;
  const rawLimit = Number(errorLogLimitInput?.value || 250);
  const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(1000, Math.floor(rawLimit))) : 250;
  if (errorLogLimitInput) errorLogLimitInput.value = String(limit);
  if (errorLogMsg) errorLogMsg.textContent = 'Loading error logs...';
  try {
    const payload = await getJson(`/api/settings/error-logs?limit=${limit}`);
    const entries = Array.isArray(payload?.entries) ? payload.entries : [];
    renderErrorLogs(entries);
    if (errorLogMsg) errorLogMsg.textContent = `Loaded ${entries.length} entries at ${new Date().toLocaleTimeString()}.`;
  } catch (err) {
    if (errorLogMsg) errorLogMsg.textContent = err.message;
  }
}

function formatLogEntry(entry = {}, tagFields = []) {
  const message = String(entry.message || '').trim();
  const detail = String(entry.detail || '').trim();
  const context = entry.context && typeof entry.context === 'object' && Object.keys(entry.context).length
    ? JSON.stringify(entry.context, null, 2)
    : '';
  const tags = tagFields.filter(Boolean).map((t) => `[${t}]`);
  const siteName = String(entry.siteName || entry.siteId || '').trim();
  const sourceIp = String(entry.sourceIp || '').trim();
  const action = String(entry.action || '').trim();
  if (siteName) tags.push(`[SITE:${siteName}]`);
  if (sourceIp) tags.push(`[SRC:${sourceIp}]`);
  if (action) tags.push(`[ACT:${action}]`);
  const lines = [`${tags.join(' ')} ${message}`.trim()];
  if (detail) lines.push(`detail: ${detail}`);
  if (context) lines.push(`context:\n${context}`);
  return lines.join('\n');
}

function formatDiagnosticsEntry(entry = {}) {
  const ts = formatMaybeDate(entry.ts);
  const level = String(entry.level || 'info').toUpperCase();
  const scope = String(entry.scope || 'system');
  const protocol = String(entry.protocol || '').trim().toUpperCase();
  return formatLogEntry(entry, [ts, level, scope, protocol]);
}

function renderDiagnosticsLogs(entries = []) {
  const text = Array.isArray(entries) && entries.length
    ? entries.map((entry) => formatDiagnosticsEntry(entry)).join('\n\n----------------------------------------\n\n')
    : 'No diagnostics logs found.';
  diagnosticsRenderCache = text;
  if (diagnosticsLogViewer) diagnosticsLogViewer.textContent = text;
  if (diagnosticConsoleOutput) diagnosticConsoleOutput.textContent = text;
}

function summarizeDiagnosticsResult(diagnostics = null) {
  if (!diagnostics || typeof diagnostics !== 'object') return '';
  const summary = diagnostics.summary || {};
  const passed = Number(summary.passed || 0);
  const warnings = Number(summary.warnings || 0);
  const failed = Number(summary.failed || 0);
  return `${passed} pass / ${warnings} warn / ${failed} fail`;
}

async function loadDiagnosticsLogs() {
  if (!canAdmin()) return;
  const rawLimit = Number(diagnosticsLogLimitInput?.value || 400);
  const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(2000, Math.floor(rawLimit))) : 400;
  if (diagnosticsLogLimitInput) diagnosticsLogLimitInput.value = String(limit);
  const protocol = String(diagnosticsProtocolFilter?.value || '').trim().toLowerCase();
  const level = String(diagnosticsLevelFilter?.value || '').trim().toLowerCase();
  const siteId = String(diagnosticsSiteFilter?.value || '').trim();
  if (diagnosticsLogMsg) diagnosticsLogMsg.textContent = 'Loading diagnostics logs...';
  try {
    const params = new URLSearchParams();
    params.set('limit', String(limit));
    if (protocol) params.set('protocol', protocol);
    if (level) params.set('level', level);
    if (siteId) params.set('siteId', siteId);
    const payload = await getJson(`/api/settings/diagnostics-logs?${params.toString()}`);
    const entries = Array.isArray(payload?.entries) ? payload.entries : [];
    renderDiagnosticsLogs(entries);
    if (diagnosticsLogMsg) diagnosticsLogMsg.textContent = `Loaded ${entries.length} entries at ${new Date().toLocaleTimeString()}.`;
  } catch (err) {
    if (diagnosticsLogMsg) diagnosticsLogMsg.textContent = err.message;
  }
}

async function clearDiagnosticsLogs() {
  if (!canAdmin()) return;
  if (diagnosticsLogMsg) diagnosticsLogMsg.textContent = 'Clearing diagnostics logs...';
  try {
    await getJson('/api/settings/diagnostics-logs', { method: 'DELETE' });
    renderDiagnosticsLogs([]);
    if (diagnosticsLogMsg) diagnosticsLogMsg.textContent = 'Diagnostics logs cleared.';
  } catch (err) {
    if (diagnosticsLogMsg) diagnosticsLogMsg.textContent = err.message;
  }
}

function formatRawTelemetryEntry(entry = {}) {
  const ts = formatMaybeDate(entry.ts);
  const protocol = String(entry.protocol || 'unknown').toUpperCase();
  const transport = String(entry.transport || '').trim().toUpperCase();
  return formatLogEntry(entry, [ts, protocol, transport]);
}

function renderRawTelemetry(entries = []) {
  const text = Array.isArray(entries) && entries.length
    ? entries.map((entry) => formatRawTelemetryEntry(entry)).join('\n\n----------------------------------------\n\n')
    : 'No raw telemetry found.';
  rawTelemetryRenderCache = text;
  if (rawTelemetryViewer) rawTelemetryViewer.textContent = text;
  if (rawTelemetryConsoleOutput) rawTelemetryConsoleOutput.textContent = text;
}

async function loadRawTelemetry() {
  if (!canAdmin()) return;
  const rawLimit = Number(rawTelemetryLimitInput?.value || 1000);
  const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(5000, Math.floor(rawLimit))) : 1000;
  if (rawTelemetryLimitInput) rawTelemetryLimitInput.value = String(limit);
  const protocol = String(rawTelemetryProtocolFilter?.value || '').trim().toLowerCase();
  const siteId = String(rawTelemetrySiteFilter?.value || '').trim();
  const q = String(rawTelemetrySearchFilter?.value || '').trim();
  if (rawTelemetryMsg) rawTelemetryMsg.textContent = 'Loading raw telemetry...';
  try {
    const params = new URLSearchParams();
    params.set('limit', String(limit));
    if (protocol) params.set('protocol', protocol);
    if (siteId) params.set('siteId', siteId);
    if (q) params.set('q', q);
    const payload = await getJson(`/api/telemetry/raw?${params.toString()}`);
    const entries = Array.isArray(payload?.entries) ? payload.entries : [];
    renderRawTelemetry(entries);
    if (rawTelemetryMsg) rawTelemetryMsg.textContent = `Loaded ${entries.length} rows at ${new Date().toLocaleTimeString()}.`;
  } catch (err) {
    if (rawTelemetryMsg) rawTelemetryMsg.textContent = err.message;
  }
}

async function clearRawTelemetry() {
  if (!canAdmin()) return;
  if (rawTelemetryMsg) rawTelemetryMsg.textContent = 'Clearing raw telemetry...';
  try {
    await getJson('/api/telemetry/raw', { method: 'DELETE' });
    renderRawTelemetry([]);
    if (rawTelemetryMsg) rawTelemetryMsg.textContent = 'Raw telemetry cleared.';
  } catch (err) {
    if (rawTelemetryMsg) rawTelemetryMsg.textContent = err.message;
  }
}

function setRawTelemetryAutoRefresh(enabled) {
  if (rawTelemetryAutoTimer) {
    clearInterval(rawTelemetryAutoTimer);
    rawTelemetryAutoTimer = null;
  }
  if (!enabled) return;
  rawTelemetryAutoTimer = setInterval(() => {
    if (!canAdmin()) return;
    if (settingsPanel?.hidden) return;
    loadRawTelemetry().catch(() => {});
  }, 2000);
}

async function loadAlertSilenceState() {
  try {
    const payload = await getJson('/api/alerts/silence');
    const until = new Date(String(payload?.silencedUntil || '')).getTime();
    alertSilenceUntilMs = Number.isFinite(until) ? until : 0;
  } catch {
    // keep previous value
  }
  renderAlertSilenceControls();
}

function flowBadge(site, protocol) {
  const enabled = Boolean(site.telemetry?.[protocol]);
  const isActive = activeEditor?.siteId === site.id && activeEditor?.protocol === protocol;
  if (!canAdmin()) {
    return `<span class="flow ${enabled ? 'on' : 'off'}">${protocolLabel(protocol)}: ${enabled ? 'Flowing' : 'Off'}</span>`;
  }

  return `
    <button
      type="button"
      class="flow flow-btn ${enabled ? 'on' : 'off'} ${isActive ? 'active' : ''}"
      data-site-id="${escapeHtml(site.id)}"
      data-protocol="${escapeHtml(protocol)}"
    >
      ${protocolLabel(protocol)}: ${enabled ? 'Flowing' : 'Off'}
    </button>
  `;
}

function protocolFlowIndicator(site, protocol, metrics) {
  const enabled = Boolean(site?.monitorConfig?.[protocol]?.enabled);
  const flowing = Boolean(site?.telemetry?.[protocol]);
  if (!enabled) return { chipClass: 'disabled', label: 'DISABLED' };
  if (!flowing) return { chipClass: 'down', label: 'DOWN' };
  if (protocol === 'snmp') {
    const ifCount = Number(metrics?.snmp?.interfaceCount ?? -1);
    if (ifCount === 0) return { chipClass: 'stale', label: 'NO IFACES' };
  }
  if (protocol === 'netflow') {
    const templateCount = Number(metrics?.netflow?.templateCount ?? -1);
    if (templateCount === 0) return { chipClass: 'stale', label: 'NO TEMPLATE' };
  }
  return { chipClass: 'live', label: 'LIVE' };
}

function heartbeatFlowIndicator(site) {
  const hb = site?.heartbeat || {};
  const lastPrimaryMs = Date.parse(String(hb.lastSeenAt || ''));
  const lastSecondaryMs = Date.parse(String(hb.lastSeenAt2 || ''));
  const latestMs = Math.max(
    Number.isFinite(lastPrimaryMs) ? lastPrimaryMs : 0,
    Number.isFinite(lastSecondaryMs) ? lastSecondaryMs : 0
  );
  if (!latestMs) {
    return { chipClass: 'down', label: 'DOWN' };
  }
  const ageSec = Math.max(0, Math.floor((Date.now() - latestMs) / 1000));
  if (ageSec <= 75) {
    return { chipClass: 'live', label: 'LIVE' };
  }
  if (ageSec <= 300) {
    return { chipClass: 'live', label: 'LIVE' };
  }
  return { chipClass: 'down', label: 'DOWN' };
}

function wanPingBadge(state) {
  const normalized = String(state || '').toLowerCase();
  if (normalized === 'up') {
    return '<span class="wan-ping-badge up">UP</span>';
  }
  if (normalized === 'down') {
    return '<span class="wan-ping-badge down">DOWN</span>';
  }
  if (normalized === 'off') {
    return '<span class="wan-ping-badge off">OFF</span>';
  }
  return '<span class="wan-ping-badge unknown">N/A</span>';
}

function isNoneValue(value) {
  const v = String(value || '').trim().toLowerCase();
  return !v || v === 'none' || v === 'n/a';
}

function topUsers(topTalkers = []) {
  const header = `
    <li class="netflow-user-head">
      <span>IP</span>
      <span>Down</span>
      <span>Up</span>
    </li>
  `;
  if (!topTalkers.length) {
    return `
      ${header}
      <li class="netflow-user-row">
        <span class="netflow-user-ip">No NetFlow talker data.</span>
        <strong>${escapeHtml(formatNetflowRate(0))}</strong>
        <strong>${escapeHtml(formatNetflowRate(0))}</strong>
      </li>
    `;
  }
  const rows = topTalkers
    .map((user) => {
      const ip = user.ip || user.name || 'unknown';
      const down = Number(user.downMbps || 0);
      const up = Number(user.upMbps || 0);
      const downLabel = formatNetflowRate(down);
      const upLabel = formatNetflowRate(up);
      return `
        <li class="netflow-user-row">
          <span class="netflow-user-ip">${escapeHtml(ip)}</span>
          <strong>${escapeHtml(downLabel)}</strong>
          <strong>${escapeHtml(upLabel)}</strong>
        </li>
      `;
    })
    .join('');
  return `${header}${rows}`;
}

function speedTests(tests = []) {
  if (!tests.length) {
    return '<li>No speed tests recorded.</li>';
  }

  return tests
    .map(
      (test) =>
        `<li><span>${escapeHtml(relativeTime(test.timestamp))}</span><span>Down ${escapeHtml(test.downloadMbps)} / Up ${escapeHtml(test.uploadMbps)} Mbps · ${escapeHtml(test.latencyMs)} ms</span></li>`
    )
    .join('');
}

function speedChangeSummary(tests = []) {
  const recent = Array.isArray(tests) ? tests.slice(0, 6) : [];
  if (recent.length < 2) return '~ n/a';

  const totalSpeed = (test) => {
    const down = Number(test?.downloadMbps);
    const up = Number(test?.uploadMbps);
    const d = Number.isFinite(down) ? down : 0;
    const u = Number.isFinite(up) ? up : 0;
    return d + u;
  };

  const newest = totalSpeed(recent[0]);
  const oldest = totalSpeed(recent[recent.length - 1]);
  const delta = newest - oldest;
  const symbol = delta > 0.05 ? '+' : delta < -0.05 ? '-' : '~';
  return `${symbol} ${Math.abs(delta).toFixed(1)} Mbps vs ${recent.length} tests`;
}

function parseMetricNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

function wanSlotLabelFromTimestamp(value = '') {
  const ts = new Date(value).getTime();
  if (!Number.isFinite(ts)) return '';
  const hour = new Date(ts).getHours();
  const slotHour = Math.floor(Math.max(0, Math.min(23, hour)) / 4) * 4;
  const labels = {
    0: '12AM',
    4: '4AM',
    8: '8AM',
    12: '12PM',
    16: '4PM',
    20: '8PM'
  };
  return labels[slotHour] || '';
}

function formatWanBadgeMetric(value) {
  const n = parseMetricNumber(value);
  if (n == null) return '--';
  if (Math.abs(n - Math.round(n)) < 0.05) return String(Math.round(n));
  return n.toFixed(1);
}

function collectorBadgeSampleBySlot(site) {
  const tests = Array.isArray(site?.metrics?.wanTests) ? site.metrics.wanTests : [];
  const map = new Map();
  for (const row of tests) {
    const slotLabel = String(row?.slotLabel || '').trim().toUpperCase() || wanSlotLabelFromTimestamp(row?.timestamp);
    if (!slotLabel || map.has(slotLabel)) continue;
    map.set(slotLabel, row);
  }
  return map;
}

function collectorConnectivityState(site) {
  const collector = site?.collector || {};
  const metrics = site?.metrics || {};
  const serverUrl = normalizeAgentServerUrl(window.location.origin) || '';
  let serverLabel = 'local';
  try {
    serverLabel = new URL(serverUrl).host || serverLabel;
  } catch {
    serverLabel = serverUrl || serverLabel;
  }

  const agentConnected = Boolean(collector.agentConnected);
  const agentRemoteIp = String(collector.agentRemoteIp || '').trim();
  const agentLocalIp = String(collector.localIp || '').trim();
  const agentLastSeenRaw = String(collector.agentLastSeenAt || '').trim();
  const agentLastSeenMs = Date.parse(agentLastSeenRaw);
  const agentSeenBefore = Number.isFinite(agentLastSeenMs);
  const collectorTone = agentConnected ? 'up' : (agentSeenBefore ? 'warn' : 'down');
  const collectorStatus = agentConnected ? 'Connected' : (agentSeenBefore ? 'Stale' : 'No Link');
  const collectorDetail = agentLocalIp || agentRemoteIp || collectorStatus;

  const heartbeatTarget = String(site?.heartbeatTarget || 'wan1').trim().toLowerCase();
  const wanTargetSlot = heartbeatTarget === 'wan2' ? 'wan2' : 'wan1';
  const wanTargetIp = String(
    wanTargetSlot === 'wan2'
      ? (site?.firewall?.wanIp2 || '')
      : (site?.firewall?.wanIp || '')
  ).trim();
  const wanPingState = String(site?.wanPing?.[wanTargetSlot] || '').trim().toLowerCase();

  const wanTests = Array.isArray(metrics.wanTests) ? metrics.wanTests : [];
  const latestWan = wanTests[0] && typeof wanTests[0] === 'object' ? wanTests[0] : null;
  const down = parseMetricNumber(latestWan?.downloadMbps);
  const up = parseMetricNumber(latestWan?.uploadMbps);
  const latency = parseMetricNumber(latestWan?.latencyMs);
  const hasSample = Boolean(latestWan);
  const hasThroughput = down != null || up != null;
  const hasLatency = latency != null;
  const wanHasData = hasThroughput || hasLatency;
  const wanLooksUp = (down != null && down > 0) || (up != null && up > 0) || (latency != null && latency > 0);
  const wanTone = wanLooksUp
    ? 'up'
    : wanPingState === 'down'
      ? 'down'
      : wanPingState === 'up'
        ? 'up'
        : wanPingState === 'off'
          ? 'warn'
          : (wanHasData || hasSample ? 'warn' : 'down');
  const wanDetail = wanTargetIp || 'N/A';
  const detectedWanIp = String(site?.metrics?.wanDetectedPublicIp || latestWan?.publicIp || '').trim();
  const detectedWanTone = detectedWanIp
    ? 'up'
    : (wanHasData || hasSample ? 'warn' : 'down');
  const linkB = collectorTone === 'down' ? 'down' : detectedWanTone;
  const linkC = detectedWanTone === 'down' ? 'down' : wanTone;

  return {
    cajal: {
      label: 'CAJAL',
      detail: serverLabel,
      tone: collectorTone
    },
    collector: {
      label: 'COLLECTOR',
      detail: collectorDetail,
      tone: collectorTone
    },
    gateway: {
      label: 'WAN',
      detail: detectedWanIp || 'Detecting',
      tone: detectedWanTone
    },
    wan: {
      label: 'TARGET',
      detail: wanDetail,
      tone: wanTone
    },
    linkA: agentConnected ? 'up' : (agentSeenBefore ? 'warn' : 'down'),
    linkB,
    linkC
  };
}

function collectorTerminalCard(site, tests = []) {
  const terminal = getCollectorToolsTerminalState(site.id, TERMINAL_SCOPE_AGENT);
  const lines = trimCollectorToolsLines(terminal.lines);
  const inputValue = String(terminal.input ?? '');
  const editable = canAdmin();
  const chain = collectorConnectivityState(site);

  return `
    <article class="metric-card collector-terminal-card">
      <h4>Collector Terminal</h4>
      <div class="collector-connect-chain" role="img" aria-label="Connectivity path from Cajal server to collector agent to WAN to target">
        <div class="collector-connect-node ${escapeHtml(chain.cajal.tone)}">
          <span class="collector-connect-label">${escapeHtml(chain.cajal.label)}</span>
          <strong>${escapeHtml(chain.cajal.detail)}</strong>
        </div>
        <span class="collector-connect-link ${escapeHtml(chain.linkA)}" aria-hidden="true"></span>
        <div class="collector-connect-node ${escapeHtml(chain.collector.tone)}">
          <span class="collector-connect-label">${escapeHtml(chain.collector.label)}</span>
          <strong>${escapeHtml(chain.collector.detail)}</strong>
        </div>
        <span class="collector-connect-link ${escapeHtml(chain.linkB)}" aria-hidden="true"></span>
        <div class="collector-connect-node ${escapeHtml(chain.gateway.tone)}">
          <span class="collector-connect-label">${escapeHtml(chain.gateway.label)}</span>
          <strong>${escapeHtml(chain.gateway.detail)}</strong>
        </div>
        <span class="collector-connect-link ${escapeHtml(chain.linkC)}" aria-hidden="true"></span>
        <div class="collector-connect-node ${escapeHtml(chain.wan.tone)}">
          <span class="collector-connect-label">${escapeHtml(chain.wan.label)}</span>
          <strong>${escapeHtml(chain.wan.detail)}</strong>
        </div>
      </div>
      <pre class="collector-tools-terminal-window">${escapeHtml(lines.join('\n'))}</pre>
      <form class="collector-tools-terminal-form" data-site-id="${escapeHtml(site.id)}" data-terminal-scope="${TERMINAL_SCOPE_AGENT}">
        <label class="collector-tools-terminal-input-row">
          <span class="collector-tools-terminal-prompt">agent$</span>
          <input
            class="collector-tools-terminal-input"
            name="command"
            data-site-id="${escapeHtml(site.id)}"
            data-terminal-scope="${TERMINAL_SCOPE_AGENT}"
            value="${escapeHtml(inputValue)}"
            autocomplete="off"
            spellcheck="false"
            ${terminal.pending || !editable ? 'disabled' : ''}
          />
        </label>
      </form>
    </article>
  `;
}

function collectorTerminalTimeBadgeStrip(site) {
  const slotSamples = collectorBadgeSampleBySlot(site);
  const badgeRow = COLLECTOR_TERMINAL_TIME_BADGES
    .map((label) => {
      const key = String(label || '').trim().toUpperCase();
      const sample = slotSamples.get(key);
      const down = formatWanBadgeMetric(sample?.downloadMbps);
      const up = formatWanBadgeMetric(sample?.uploadMbps);
      const latency = formatWanBadgeMetric(sample?.latencyMs);
      const hasAny = sample && (parseMetricNumber(sample.downloadMbps) != null || parseMetricNumber(sample.uploadMbps) != null || parseMetricNumber(sample.latencyMs) != null);
      const looksUp = hasAny && (
        (parseMetricNumber(sample?.downloadMbps) || 0) > 0
        || (parseMetricNumber(sample?.uploadMbps) || 0) > 0
        || (parseMetricNumber(sample?.latencyMs) || 0) > 0
      );
      const toneClass = !hasAny ? 'unknown' : (looksUp ? 'up' : 'warn');
      const valueText = down === '--' && up === '--' && latency !== '--'
        ? `L${latency}`
        : `${down}/${up}`;
      const title = sample?.timestamp
        ? `${label}: Down ${down} / Up ${up} Mbps · ${latency} ms @ ${formatMaybeDate(sample.timestamp)}`
        : `${label}: No speed test yet`;
      return `
        <span class="collector-terminal-time-badge ${toneClass}" title="${escapeHtml(title)}">
          <span class="collector-terminal-time-label">${escapeHtml(label)}</span>
          <strong class="collector-terminal-time-value">${escapeHtml(valueText)}</strong>
        </span>
      `;
    })
    .join('');
  return `
    <div class="collector-terminal-time-strip" role="list" aria-label="Collector timeline in four hour increments">
      <p class="collector-terminal-time-strip-label">Speed Tests</p>
      <div class="collector-terminal-time-strip-grid">
        ${badgeRow}
      </div>
    </div>
  `;
}

function relativeTime(value) {
  const ts = new Date(value).getTime();
  if (Number.isNaN(ts)) return String(value || 'unknown');
  const diffSec = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (diffSec < 60) return `${diffSec}s ago`;
  const min = Math.floor(diffSec / 60);
  if (min < 60) return `${min}m ago`;
  const hours = Math.floor(min / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function seededHash(text) {
  let hash = 2166136261;
  for (let i = 0; i < text.length; i += 1) {
    hash ^= text.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function generateUptime14d(siteId = 'site') {
  const hash = seededHash(siteId);
  const points = [];
  let current = 96 + (hash % 35) / 10;

  for (let i = 0; i < 14; i += 1) {
    const wobble = ((hash >> (i % 16)) % 11 - 5) * 0.08;
    current = Math.max(88, Math.min(100, current + wobble));
    points.push(Number(current.toFixed(2)));
  }

  return points;
}

function normalizeUptimeScaleId(value) {
  const target = String(value || '').trim().toLowerCase();
  return UPTIME_SCALE_OPTIONS.some((opt) => opt.id === target) ? target : DEFAULT_UPTIME_SCALE_ID;
}

function getUptimeScaleConfig(scaleId) {
  const normalized = normalizeUptimeScaleId(scaleId);
  return UPTIME_SCALE_OPTIONS.find((opt) => opt.id === normalized) || UPTIME_SCALE_OPTIONS[UPTIME_SCALE_OPTIONS.length - 1];
}

function uptimeScaleSelect(siteId, scaleId) {
  const normalized = normalizeUptimeScaleId(scaleId);
  const options = UPTIME_SCALE_OPTIONS
    .map((opt) => `<option value="${escapeHtml(opt.id)}" ${opt.id === normalized ? 'selected' : ''}>${escapeHtml(opt.label)}</option>`)
    .join('');
  return `<select class="uptime-scale-select" data-site-id="${escapeHtml(siteId)}" aria-label="Uptime graph scale">${options}</select>`;
}

function buildUptimeSeriesFromSamples(samples = [], scaleId = DEFAULT_UPTIME_SCALE_ID, fallback = []) {
  const config = getUptimeScaleConfig(scaleId);
  const rows = Array.isArray(samples) ? samples : [];
  const fallbackSeries = Array.isArray(fallback) ? fallback : [];
  if (!rows.length) {
    return fallbackSeries.length ? fallbackSeries.map((v) => Math.max(0, Math.min(100, Number(v)))) : [];
  }

  const now = Date.now();
  const cutoff = now - config.windowMs;
  const bucketMs = config.windowMs / Math.max(1, config.bins);
  const counts = new Array(config.bins).fill(0);
  const ups = new Array(config.bins).fill(0);
  for (const row of rows) {
    const ts = Number(row?.ts);
    if (!Number.isFinite(ts) || ts < cutoff || ts > now) continue;
    const idx = Math.max(0, Math.min(config.bins - 1, Math.floor((ts - cutoff) / bucketMs)));
    counts[idx] += 1;
    ups[idx] += row?.up ? 1 : 0;
  }

  const fallbackSeed = fallbackSeries.length ? Number(fallbackSeries[fallbackSeries.length - 1]) : 100;
  const out = [];
  for (let i = 0; i < config.bins; i += 1) {
    if (counts[i] > 0) {
      out.push(Number(((ups[i] / counts[i]) * 100).toFixed(2)));
    } else if (i > 0) {
      out.push(out[i - 1]);
    } else {
      out.push(Number((Number.isFinite(fallbackSeed) ? fallbackSeed : 100).toFixed(2)));
    }
  }
  return out;
}

function uptimeChart(values = [], status = 'down', secondaryValues = [], scaleId = DEFAULT_UPTIME_SCALE_ID, siteId = '', flowIndicator = null) {
  const scale = getUptimeScaleConfig(scaleId);
  const scaleSelectHtml = uptimeScaleSelect(siteId, scale.id);
  const flowChipClass = String(flowIndicator?.chipClass || '').trim() || 'idle';
  const flowChipLabel = String(flowIndicator?.label || '').trim() || String(status || 'down').toUpperCase();
  if (!values.length) {
    return `
      <aside class="uptime-panel">
        <div class="uptime-head">
          <div class="uptime-head-left"><h4>Uptime</h4>${scaleSelectHtml}</div>
          <span class="signal-flow-chip uptime-flow-chip ${escapeHtml(flowChipClass)}">${escapeHtml(flowChipLabel)}</span>
        </div>
        <p class="empty">No uptime trend data.</p>
      </aside>
    `;
  }

  const points = values.slice(-14).map((value) => Math.max(0, Math.min(100, Number(value))));
  const width = 260;
  const height = 54;
  const pad = 8;
  const usableW = width - pad * 2;
  const usableH = height - pad * 2;
  const buildLinePoints = (chartPoints = []) => chartPoints
    .map((point, idx) => {
      const x = pad + (idx * usableW) / (chartPoints.length - 1 || 1);
      const y = pad + ((100 - point) * usableH) / 100;
      return `${x.toFixed(2)},${y.toFixed(2)}`;
    })
    .join(' ');
  const linePoints = buildLinePoints(points);
  const secondaryPointsRaw = Array.isArray(secondaryValues) && secondaryValues.length ? secondaryValues : points;
  const secondaryPoints = secondaryPointsRaw.slice(-14).map((value) => Math.max(0, Math.min(100, Number(value))));
  const linePointsSecondary = buildLinePoints(secondaryPoints);
  const nowTs = Date.now();
  const axisStartTs = nowTs - scale.windowMs;
  const axisMidTs = axisStartTs + Math.floor(scale.windowMs / 2);
  const axisStartLabel = formatUptimeAxisLabel(axisStartTs, scale.windowMs);
  const axisMidLabel = formatUptimeAxisLabel(axisMidTs, scale.windowMs);
  const axisNowLabel = formatUptimeAxisLabel(nowTs, scale.windowMs);

  return `
      <aside class="uptime-panel">
      <div class="uptime-head">
        <div class="uptime-head-left"><h4>Uptime</h4>${scaleSelectHtml}</div>
        <div class="uptime-meta">
          <span class="signal-flow-chip uptime-flow-chip ${escapeHtml(flowChipClass)}">${escapeHtml(flowChipLabel)}</span>
        </div>
      </div>
      <div class="uptime-charts">
        <svg class="uptime-chart target-1" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" aria-label="Target 1 uptime trend">
          <line class="grid" x1="${pad}" y1="${height - pad}" x2="${width - pad}" y2="${height - pad}" />
          <line class="grid" x1="${pad}" y1="${height / 2}" x2="${width - pad}" y2="${height / 2}" />
          <polyline class="line" points="${linePoints}" />
        </svg>
        <svg class="uptime-chart target-2" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none" aria-label="Target 2 uptime trend">
          <line class="grid" x1="${pad}" y1="${height - pad}" x2="${width - pad}" y2="${height - pad}" />
          <line class="grid" x1="${pad}" y1="${height / 2}" x2="${width - pad}" y2="${height / 2}" />
          <polyline class="line" points="${linePointsSecondary}" />
        </svg>
      </div>
      <div class="uptime-axis" aria-label="Uptime graph time axis">
        <span>${escapeHtml(axisStartLabel)}</span>
        <span>${escapeHtml(axisMidLabel)}</span>
        <span>${escapeHtml(axisNowLabel)}</span>
      </div>
    </aside>
  `;
}

function heartbeatPanel(site) {
  const hb = site.heartbeat || {};
  const flow = heartbeatFlowIndicator(site);
  const hbLastError = String(site?.metrics?.heartbeat?.lastError || '').trim();
  const method = 'ping';
  const lastSeen = hb.lastSeenAt ? new Date(hb.lastSeenAt).toLocaleString() : 'Never';
  const lastSeen2 = hb.lastSeenAt2 ? new Date(hb.lastSeenAt2).toLocaleString() : 'Never';
  const target = String(site.heartbeatTarget || 'wan1').toLowerCase();
  const target2 = String(site.heartbeatTarget2 || 'wan2').toLowerCase();
  const targetOptions = [
    { value: 'wan1', label: `WAN IP 1 (${site.firewall?.wanIp || 'N/A'})` },
    { value: 'wan2', label: `WAN IP 2 (${site.firewall?.wanIp2 || 'N/A'})` },
    { value: 'gateway', label: `Gateway (${site.gatewayIp || site.internalIp || 'N/A'})` },
    { value: 'internal', label: `Internal IP (${site.gatewayIp || site.internalIp || 'N/A'})` }
  ];
  const targetLabel = targetOptions.find((opt) => opt.value === target)?.label || targetOptions[0].label;
  const targetLabel2 = targetOptions.find((opt) => opt.value === target2)?.label || targetOptions[1]?.label || targetOptions[0].label;

  return `
    <article class="heartbeat-card uptime-panel">
      <div class="heartbeat-head-row">
        <h4>Heart Beat</h4>
        <span class="signal-flow-chip metric-head-flow ${escapeHtml(flow.chipClass)}">${escapeHtml(flow.label)}</span>
      </div>
      <p>Method: <strong>${escapeHtml(method)}</strong></p>
      <p class="heartbeat-target-row">
        <span class="hb-target-badge primary">Target 1</span>
        ${canAdmin()
          ? `<select class="heartbeat-target-select" data-site-id="${escapeHtml(site.id)}" data-heartbeat-slot="primary">
              ${targetOptions
                .map((opt) => `<option value="${escapeHtml(opt.value)}" ${opt.value === target ? 'selected' : ''}>${escapeHtml(opt.label)}</option>`)
                .join('')}
            </select>`
          : `<strong class="hb-target-value">${escapeHtml(targetLabel)}</strong>`}
      </p>
      <p>Last Check-In 1: <strong class="hb-ts">${escapeHtml(lastSeen)}</strong></p>
      <p class="heartbeat-target-row">
        <span class="hb-target-badge secondary">Target 2</span>
        ${canAdmin()
          ? `<select class="heartbeat-target-select" data-site-id="${escapeHtml(site.id)}" data-heartbeat-slot="secondary">
              ${targetOptions
                .map((opt) => `<option value="${escapeHtml(opt.value)}" ${opt.value === target2 ? 'selected' : ''}>${escapeHtml(opt.label)}</option>`)
                .join('')}
            </select>`
          : `<strong class="hb-target-value">${escapeHtml(targetLabel2)}</strong>`}
      </p>
      <p>Last Check-In 2: <strong class="hb-ts">${escapeHtml(lastSeen2)}</strong></p>
      <p>Last Error: <strong>${escapeHtml(hbLastError || 'none')}</strong></p>
    </article>
  `;
}

function collectorPanel(site, expanded = false) {
  const terminal = getCollectorToolsTerminalState(site.id, TERMINAL_SCOPE_CAJAL);
  const lines = trimCollectorToolsLines(terminal.lines);
  const inputValue = String(terminal.input ?? '');
  const editable = canAdmin();
  const toggleLabel = 'Close';
  const toggleAria = 'Close terminal';

  return `
    <article class="collector-card uptime-panel ${expanded ? 'is-expanded' : ''}">
      <div class="collector-tools-head">
        <h4>Tools</h4>
        ${expanded
          ? `
        <button
          type="button"
          class="tools-expand-toggle"
          data-site-id="${escapeHtml(site.id)}"
          aria-label="${escapeHtml(toggleAria)}"
        >${escapeHtml(toggleLabel)}</button>
        `
          : ''}
      </div>
      ${expanded
        ? ''
        : `
      <section class="collector-tools-status">
        <p class="collector-tools-section-title">Service Monitors</p>
        <div class="public-service-badges collector-public-service-badges" data-public-service-badges="tools" aria-live="polite"></div>
      </section>
      `}
      ${expanded
        ? `
      <pre class="collector-tools-terminal-window">${escapeHtml(lines.join('\n'))}</pre>
      <form class="collector-tools-terminal-form" data-site-id="${escapeHtml(site.id)}" data-terminal-scope="${TERMINAL_SCOPE_CAJAL}">
        <label class="collector-tools-terminal-input-row">
          <span class="collector-tools-terminal-prompt">tools$</span>
          <input
            class="collector-tools-terminal-input"
            name="command"
            data-site-id="${escapeHtml(site.id)}"
            data-terminal-scope="${TERMINAL_SCOPE_CAJAL}"
            value="${escapeHtml(inputValue)}"
            autocomplete="off"
            spellcheck="false"
            ${terminal.pending || !editable ? 'disabled' : ''}
          />
        </label>
      </form>
      `
        : `
      <div class="collector-tools-collapsed">
        <div class="collector-tools-actions">
          <button type="button" class="flow flow-btn tools-learn-btn" data-help-section="tools-terminal">Learn Terminal</button>
          <button
            type="button"
            class="flow flow-btn tools-expand-toggle tools-launch-btn"
            data-site-id="${escapeHtml(site.id)}"
            aria-label="Launch terminal"
          >Launch Terminal</button>
        </div>
      </div>
      `}
    </article>
  `;
}

function monitorFields(protocol, config) {
  if (protocol === 'snmp') {
    return `
      <label>Target Host/IP
        <input name="targetHost" value="${escapeHtml(config.targetHost || '')}" />
      </label>
      <label>SNMP Version
        <select name="version">
          <option value="1" ${config.version === '1' ? 'selected' : ''}>1</option>
          <option value="2c" ${config.version === '2c' ? 'selected' : ''}>2c</option>
          <option value="3" ${config.version === '3' ? 'selected' : ''}>3</option>
        </select>
      </label>
      <label>Community String
        <input name="communityString" value="${escapeHtml(config.communityString || '')}" />
      </label>
      <label>Auth User
        <input name="authUser" value="${escapeHtml(config.authUser || '')}" />
      </label>
      <label>Auth Password
        <input name="authPassword" type="password" value="${escapeHtml(config.authPassword || '')}" />
      </label>
      <div class="trap-receiver-info">
        <strong>SNMP Trap Receiver</strong>
        <span>Point your device's trap destination to <code>${escapeHtml(window.location.hostname)}:${snmpTrapPort}</code> — traps appear in the Event Viewer immediately.</span>
      </div>
    `;
  }

  if (protocol === 'netflow') {
    return `
      <label>Exporter Source IP
        <input name="sourceIp" value="${escapeHtml(config.sourceIp || '')}" />
      </label>
      <label>Collector IP
        <input name="collectorIp" value="${escapeHtml(config.collectorIp || '')}" />
      </label>
      <label>Collector Port
        <input name="collectorPort" value="${escapeHtml(config.collectorPort || '')}" />
      </label>
      <label>Exporter ID
        <input name="exporterId" value="${escapeHtml(config.exporterId || '')}" />
      </label>
      <label>Shared Secret
        <input name="sharedSecret" type="password" value="${escapeHtml(config.sharedSecret || '')}" />
      </label>
    `;
  }

  return `
    <label>Device Source IP
      <input name="sourceIp" value="${escapeHtml(config.sourceIp || '')}" />
    </label>
    <label>Syslog Server
      <input name="server" value="${escapeHtml(config.server || '')}" />
    </label>
    <label>Port
      <input name="port" value="${escapeHtml(config.port || '')}" />
    </label>
    <label>Transport
      <select name="protocol">
        <option value="udp" ${config.protocol === 'udp' ? 'selected' : ''}>UDP</option>
        <option value="tcp" ${config.protocol === 'tcp' ? 'selected' : ''}>TCP</option>
      </select>
    </label>
    <label>Auth Token
      <input name="authToken" type="password" value="${escapeHtml(config.authToken || '')}" />
    </label>
  `;
}

function monitorEditor(site) {
  if (!activeEditor || activeEditor.siteId !== site.id) {
    return '';
  }

  const protocol = activeEditor.protocol;
  const config = site.monitorConfig?.[protocol] || {};
  const enabled = Boolean(config.enabled);
  const isSnmp = protocol === 'snmp';
  const isSyslog = protocol === 'syslog';
  const isNetflow = protocol === 'netflow';

  return `
    <form class="monitor-editor" data-site-id="${escapeHtml(site.id)}" data-protocol="${escapeHtml(protocol)}">
      <div class="editor-head">
        <h4>${protocolLabel(protocol)} Monitor Settings</h4>
        <span>Last changed: ${escapeHtml(formatChanged(config.lastChanged))}</span>
      </div>
      <label class="enabled-toggle">
        <input type="checkbox" name="enabled" ${enabled ? 'checked' : ''} /> Enabled
      </label>
      <input type="hidden" name="siteId" value="${escapeHtml(site.id)}" />
      <input type="hidden" name="monitorProtocol" value="${escapeHtml(protocol)}" />
      <div class="editor-grid">
        ${monitorFields(protocol, config)}
      </div>
      <div class="editor-actions">
        <button type="submit">Save ${protocolLabel(protocol)} Settings</button>
        <button type="button" class="monitor-diagnostic-btn ghost-btn">Run Diagnostics</button>
        ${isSnmp ? '<button type="button" class="snmp-test-btn ghost-btn">Test SNMP Now</button>' : ''}
        ${isSyslog ? '<button type="button" class="syslog-test-btn ghost-btn">Test Syslog Now</button>' : ''}
        ${isNetflow ? '<button type="button" class="netflow-test-btn ghost-btn">Test NetFlow Now</button>' : ''}
        <button type="button" class="monitor-close-btn ghost-btn">Close</button>
        <span class="monitor-save-msg"></span>
      </div>
    </form>
  `;
}

function siteTile(site) {
  const firewall = site.firewall || {};
  const firewallStatus = String(firewall.status || '').trim().toLowerCase();
  const isDeviceDown = firewallStatus === 'down';
  const metrics = site.metrics || {};
  const notifications = site.notifications || {};
  const collector = site.collector || {};
  const hb = site.heartbeat || {};
  const model = String(site.model || '').trim();
  const isp1 = String(site.isp1 || '').trim();
  const isp2 = String(site.isp2 || '').trim();
  const role = normalizeRole(site.role);
  const isCollectorRole = role === 'collector';
  const toolsExpanded = !isCollectorRole && collectorToolsExpandedSites.has(site.id);
  const collectorDetailsExpanded = isCollectorRole && collectorDetailsExpandedSites.has(site.id);
  const wanPing = site.wanPing || {};
  const wan1DisplayState = isNoneValue(firewall.wanIp) || isNoneValue(isp1) ? 'off' : wanPing.wan1;
  const wan2DisplayState = isNoneValue(firewall.wanIp2) || isNoneValue(isp2) ? 'off' : wanPing.wan2;
  const recipients = Array.isArray(notifications.recipients) ? notifications.recipients : [];
  const uptimeScale = normalizeUptimeScaleId(uptimeScaleBySite.get(site.id) || DEFAULT_UPTIME_SCALE_ID);
  const fallbackUptime = Array.isArray(metrics.uptime14d) && metrics.uptime14d.length ? metrics.uptime14d : generateUptime14d(site.id);
  const uptimePoints = buildUptimeSeriesFromSamples(metrics.uptimeSamples, uptimeScale, fallbackUptime);
  const fallbackUptimeSecondary = Array.isArray(metrics.uptime14dSecondary) && metrics.uptime14dSecondary.length ? metrics.uptime14dSecondary : fallbackUptime;
  const uptimePointsSecondary = buildUptimeSeriesFromSamples(metrics.uptimeSamplesSecondary, uptimeScale, fallbackUptimeSecondary);
  const snmpIndicator = protocolFlowIndicator(site, 'snmp', metrics);
  const syslogIndicator = protocolFlowIndicator(site, 'syslog', metrics);
  const netflowIndicator = protocolFlowIndicator(site, 'netflow', metrics);
  const heartbeatIndicator = heartbeatFlowIndicator(site);
  const syslogViewActive = activeEditor?.siteId === site.id && activeEditor?.protocol === 'syslog';
  const snmpViewActive = activeEditor?.siteId === site.id && activeEditor?.protocol === 'snmp';
  const netflowViewActive = activeEditor?.siteId === site.id && activeEditor?.protocol === 'netflow';
  const collectorHost = String(collector.terminalHost || collector.ip || firewall.wanIp || '').trim() || 'N/A';
  const collectorConfiguredHost = String(collector.ip || '').trim() || 'N/A';
  const collectorLocalIp = String(collector.localIp || '').trim() || 'N/A';
  const collectorSiteId = String(site.id || '').trim() || 'N/A';
  const cajalServerHint = normalizeAgentServerUrl(window.location.origin) || 'N/A';
  const agentRegisterEndpoint = cajalServerHint !== 'N/A' ? `${cajalServerHint}/api/agent/register` : 'N/A';
  const agentPollEndpoint = cajalServerHint !== 'N/A' ? `${cajalServerHint}/api/agent/poll` : 'N/A';
  const lastHeartbeat = hb.lastSeenAt ? formatMaybeDate(hb.lastSeenAt) : 'Never';
  const agentLastSeenAt = String(collector.agentLastSeenAt || '').trim();
  const agentLastSeen = agentLastSeenAt ? formatMaybeDate(agentLastSeenAt) : 'Never';
  const agentLastSeenMs = agentLastSeenAt ? new Date(agentLastSeenAt).getTime() : NaN;
  const agentLastSeenAgo = Number.isFinite(agentLastSeenMs) ? formatRelativeTime(agentLastSeenMs) : 'never';
  const agentPasswordSet = Boolean(collector.agentPasswordSet);
  const agentPasswordLabel = agentPasswordSet ? 'Set' : 'Missing';
  const agentPasswordTone = agentPasswordSet ? 'ok' : 'down';
  const agentVersionRaw = String(collector.agentVersion || '').trim();
  const agentVersionLabel = agentVersionRaw || 'Unknown';
  const nextAgentVersionRaw = String(collector.nextAgentVersion || '').trim();
  const nextAgentVersionLabel = nextAgentVersionRaw || 'Unknown';
  const agentResponsive = Boolean(collector.agentConnected);
  const agentPlatform = String(collector.agentPlatform || '').trim().toLowerCase();
  const agentLooksWindows = /windows|win32|win64|msys|cygwin/.test(agentPlatform);
  const agentLooksLinux = /linux|ubuntu|debian|fedora|centos|rhel|red hat|arch|kali/.test(agentPlatform);
  const linuxAgentResponsive = agentResponsive && agentLooksLinux;
  const windowsAgentResponsive = agentResponsive && agentLooksWindows;
  const agentUpdateAvailable = Boolean(
    collector.updateAvailable
    || (agentVersionRaw && nextAgentVersionRaw && agentVersionRaw !== nextAgentVersionRaw)
  );
  let agentState = 'Unknown';
  let agentTone = 'warn';
  if (typeof collector.agentConnected === 'boolean') {
    agentState = collector.agentConnected ? 'Connected' : (agentLastSeenAt ? 'Stale' : 'No Link');
    agentTone = collector.agentConnected ? 'ok' : (agentLastSeenAt ? 'warn' : 'down');
  } else if (hb.lastSeenAt) {
    agentState = 'Connected';
    agentTone = 'ok';
  }
  const suppressCollectorDownTracer = isCollectorRole && agentTone === 'ok';
  const showDownTracer = isDeviceDown && !suppressCollectorDownTracer;
  const allowManage = canAdmin();
  const showMetaEditor = allowManage && activeMetaEditorSiteId === site.id;
  const notifyEditable = allowManage && showMetaEditor;
  const metaFormId = `site-meta-${site.id}`;
  const collectorTopInfo = isCollectorRole && !showMetaEditor
    ? `
            <div class="collector-info-grid">
              <p class="collector-info-item">
                <span class="collector-info-label">Site ID</span>
                <code class="line-value">${escapeHtml(collectorSiteId)}</code>
              </p>
              <p class="collector-info-item">
                <span class="collector-info-label">Agent Hostname</span>
                <code class="ip-value">${escapeHtml(collectorHost)}</code>
              </p>
              <p class="collector-info-item">
                <span class="collector-info-label">Agent Status</span>
                <code class="line-value collector-value ${escapeHtml(agentTone)}">${escapeHtml(agentState)}</code>
              </p>
              <p class="collector-info-item">
                <span class="collector-info-label">Agent Version</span>
                <code class="line-value">${escapeHtml(agentVersionLabel)}</code>
              </p>
              <p class="collector-info-item collector-info-item-wide">
                <span class="collector-info-label">Last Agent Check-In</span>
                <code class="line-value">${escapeHtml(agentLastSeen)}${agentLastSeenAt ? ` (${escapeHtml(agentLastSeenAgo)})` : ''}</code>
              </p>
              <p class="collector-info-item">
                <span class="collector-info-label">Configured Collector Host</span>
                <code class="line-value">${escapeHtml(collectorConfiguredHost)}</code>
              </p>
              <p class="collector-info-item">
                <span class="collector-info-label">Device Internal IP</span>
                <code class="line-value">${escapeHtml(site.internalIp || 'N/A')}</code>
              </p>
            </div>
            `
    : '';

  return `
    <article class="site-tile role-${escapeHtml(role)} ${dirtyMetaSites.has(site.id) ? 'is-dirty' : ''} ${showMetaEditor ? 'is-editing' : ''} ${toolsExpanded ? 'tools-expanded' : ''} ${collectorDetailsExpanded ? 'collector-details-expanded' : ''} ${showDownTracer ? 'is-device-down' : ''}" data-site-id="${escapeHtml(site.id)}">
      <div class="site-top">
        <div class="site-details">
          ${allowManage
            ? `
          <div class="site-tools">
            <select
              class="role-selector role-${escapeHtml(role)}"
              data-site-id="${escapeHtml(site.id)}"
              aria-label="Select role for ${escapeHtml(site.name)}"
            >
              ${roleOptions(role)}
            </select>
          </div>
          `
            : ''}
          <div class="site-header">
            <h3>${escapeHtml(site.name)}</h3>
            <span class="model-inline-readonly">Model: <code class="line-value">${escapeHtml(model || 'N/A')}</code></span>
          </div>
	          ${showMetaEditor
	            ? `
	            <form class="site-meta-form compact" id="${escapeHtml(metaFormId)}" data-site-id="${escapeHtml(site.id)}">
	              <div class="meta-grid">
	                <label class="meta-label"><span>Name</span><input name="name" value="${escapeHtml(site.name || '')}" /></label>
	                <label class="meta-label"><span>Model</span><input name="model" value="${escapeHtml(model || '')}" placeholder="Model #" /></label>
	                ${isCollectorRole
	                  ? `
	                <label class="meta-label"><span>WAN IP 1</span><input name="wanIp" value="${escapeHtml(firewall.wanIp || '')}" /></label>
	                `
	                  : `
	                <label class="meta-label"><span>WAN IP 1</span><input name="wanIp" value="${escapeHtml(firewall.wanIp || '')}" /></label>
	                <label class="meta-label"><span>ISP 1</span><input name="isp1" value="${escapeHtml(site.isp1 || '')}" /></label>
	                <label class="meta-label"><span>WAN IP 2</span><input name="wanIp2" value="${escapeHtml(firewall.wanIp2 || '')}" /></label>
	                <label class="meta-label"><span>ISP 2</span><input name="isp2" value="${escapeHtml(site.isp2 || '')}" /></label>
	                <label class="meta-label"><span>DHCP Scope</span><input name="dhcpScope" value="${escapeHtml(site.dhcpScope || '')}" /></label>
	                <label class="meta-label"><span>Firewall</span><input name="firewallName" value="${escapeHtml(firewall.name || '')}" /></label>
	                <label class="meta-label"><span>WAN 1 Ping</span><span class="meta-static">${wanPingBadge(wan1DisplayState)}</span></label>
	                <label class="meta-label"><span>WAN 2 Ping</span><span class="meta-static">${wanPingBadge(wan2DisplayState)}</span></label>
	                <label class="meta-label"><span>Internal IP</span><input name="internalIp" value="${escapeHtml(site.internalIp || '')}" /></label>
	                `}
	              </div>
	              <div class="meta-actions">
	                <button type="submit" class="meta-save">Save Details</button>
	                <button
                  type="button"
                  class="meta-delete delete-device"
                  data-site-id="${escapeHtml(site.id)}"
                  data-site-name="${escapeHtml(site.name || site.id)}"
                >Delete Device</button>
              </div>
              <span class="meta-save-msg"></span>
            </form>
            `
            : isCollectorRole
              ? ''
              : `
            <p class="wan wan-row wan-paired">
              <span class="wan-primary">WAN IP 1: <code class="ip-value">${escapeHtml(firewall.wanIp || 'N/A')}</code></span>
              <span class="wan-secondary">ISP 1: <code class="line-value">${escapeHtml(isp1 || 'N/A')}</code></span>
              <span class="wan-ping-col">${wanPingBadge(wan1DisplayState)}</span>
            </p>
            <p class="wan wan-row wan-paired">
              <span class="wan-primary">WAN IP 2: <code class="ip-value">${escapeHtml(firewall.wanIp2 || 'N/A')}</code></span>
              <span class="wan-secondary wan-secondary-align wan-secondary-isp2"><span class="wan-secondary-label">ISP 2:</span><code class="line-value">${escapeHtml(isp2 || 'N/A')}</code></span>
              <span class="wan-ping-col">${wanPingBadge(wan2DisplayState)}</span>
            </p>
            <p class="wan wan-row wan-paired">
              <span class="wan-primary">Internal IP: <code class="line-value">${escapeHtml(site.internalIp || 'N/A')}</code></span>
              <span class="wan-secondary wan-secondary-align"><span class="wan-secondary-label">DHCP Scope:</span><code class="line-value">${escapeHtml(site.dhcpScope || 'N/A')}</code></span>
              <span class="wan-ping-col wan-ping-col-empty" aria-hidden="true"></span>
            </p>
            `}
        </div>
        <div class="top-controls">
          <div class="badge-cluster">
            <div class="badge-row">
              ${isCollectorRole ? '' : `${flowBadge(site, 'syslog')}${flowBadge(site, 'snmp')}${flowBadge(site, 'netflow')}`}
              ${allowManage
                ? `
              ${isCollectorRole
                ? `
              <button
                type="button"
                class="flow flow-btn agent-download-placeholder ${linuxAgentResponsive ? 'agent-download-live' : ''}"
                data-site-id="${escapeHtml(site.id)}"
                data-agent-os="linux"
              >
                <span class="agent-os-icon agent-os-icon-linux" aria-hidden="true">
                  <svg viewBox="0 0 16 16" focusable="false" aria-hidden="true">
                    <path
                      d="M8.9 3.1c1.7.1 3 1.4 3 2.9 0 1.2-.8 2.2-2 2.7-.6.2-1 .6-1 1.1 0 .6.6 1 1.4 1 1.2 0 2.2-.5 3-.9-.2 1.8-1.8 3.1-3.9 3.1-2.4 0-4.3-1.6-4.3-3.7 0-1.4.9-2.5 2.1-3 .6-.2 1-.6 1-1.1 0-.5-.4-.8-.9-.8-.6 0-1.1.3-1.6.7.3-1.2 1.6-2.1 3.2-2z"
                      fill="none"
                      stroke="currentColor"
                      stroke-width="1.25"
                      stroke-linecap="round"
                      stroke-linejoin="round"
                    ></path>
                    <circle cx="8.3" cy="8.15" r="0.85"></circle>
                  </svg>
                </span>
                <span>Linux Agent</span>
              </button>
              <button
                type="button"
                class="flow flow-btn agent-download-placeholder ${windowsAgentResponsive ? 'agent-download-live' : ''}"
                data-site-id="${escapeHtml(site.id)}"
                data-agent-os="windows"
              >
                <span class="agent-os-icon agent-os-icon-windows" aria-hidden="true">
                  <svg viewBox="0 0 16 16" focusable="false" aria-hidden="true">
                    <rect x="1.2" y="1.8" width="6.2" height="5.8"></rect>
                    <rect x="8.6" y="1.8" width="6.2" height="5.8"></rect>
                    <rect x="1.2" y="8.4" width="6.2" height="5.8"></rect>
                    <rect x="8.6" y="8.4" width="6.2" height="5.8"></rect>
                  </svg>
                </span>
                <span>Windows Agent</span>
              </button>
              `
                : ''}
              ${isCollectorRole
                ? `
              <button
                type="button"
                class="flow flow-btn collector-details-toggle ${collectorDetailsExpanded ? 'active' : ''}"
                data-site-id="${escapeHtml(site.id)}"
                aria-expanded="${collectorDetailsExpanded ? 'true' : 'false'}"
                aria-label="Show collector details for ${escapeHtml(site.name)}"
              >DETAILS</button>
              `
                : ''}
              ${isCollectorRole
                ? `
              <button
                type="button"
                class="flow flow-btn collector-agent-update-btn ${agentUpdateAvailable ? 'update-available' : ''}"
                data-site-id="${escapeHtml(site.id)}"
                data-current-version="${escapeHtml(agentVersionRaw)}"
                data-next-version="${escapeHtml(nextAgentVersionRaw)}"
                aria-label="Update collector agent for ${escapeHtml(site.name)}"
              >UPDATE</button>
              `
                : ''}
              <button
                type="button"
                class="flow flow-btn meta-toggle edit-toggle ${showMetaEditor ? 'active' : ''}"
                data-site-id="${escapeHtml(site.id)}"
                aria-label="Edit details for ${escapeHtml(site.name)}"
              >EDIT</button>
              `
                : `${isCollectorRole
                  ? `
              <button
                type="button"
                class="flow flow-btn collector-details-toggle ${collectorDetailsExpanded ? 'active' : ''}"
                data-site-id="${escapeHtml(site.id)}"
                aria-expanded="${collectorDetailsExpanded ? 'true' : 'false'}"
                aria-label="Show collector details for ${escapeHtml(site.name)}"
              >DETAILS</button>
              `
                  : ''}`}
            </div>
            ${isCollectorRole && collectorDetailsExpanded
              ? `
              <div class="collector-details-panel" role="region" aria-label="Collector details">
                <p class="collector-details-item"><span>Site ID</span><code class="line-value">${escapeHtml(collectorSiteId)}</code></p>
                <p class="collector-details-item"><span>Agent Hostname</span><code class="line-value">${escapeHtml(collectorHost)}</code></p>
                <p class="collector-details-item"><span>Agent Status</span><code class="line-value collector-value ${escapeHtml(agentTone)}">${escapeHtml(agentState)}</code></p>
                <p class="collector-details-item"><span>Agent Password</span><code class="line-value collector-value ${escapeHtml(agentPasswordTone)}">${escapeHtml(agentPasswordLabel)}</code></p>
                <p class="collector-details-item"><span>Last Agent Check-In</span><code class="line-value">${escapeHtml(agentLastSeen)}${agentLastSeenAt ? ` (${escapeHtml(agentLastSeenAgo)})` : ''}</code></p>
                <p class="collector-details-item"><span>Last Heart Beat (Ping)</span><code class="line-value">${escapeHtml(lastHeartbeat)}</code></p>
                <p class="collector-details-item"><span>Configured Collector Host</span><code class="line-value">${escapeHtml(collectorConfiguredHost)}</code></p>
                <p class="collector-details-item"><span>Collector Local IP</span><code class="line-value">${escapeHtml(collectorLocalIp)}</code></p>
                <p class="collector-details-item"><span>Device Internal IP</span><code class="line-value">${escapeHtml(site.internalIp || 'N/A')}</code></p>
                <p class="collector-details-item"><span>Current Agent Version</span><code class="line-value">${escapeHtml(agentVersionLabel)}</code></p>
                <p class="collector-details-item"><span>Next Agent Version</span><code class="line-value">${escapeHtml(nextAgentVersionLabel)}</code></p>
                <p class="collector-details-item collector-details-item-wide"><span>Agent Server URL</span><code class="line-value wrap" title="Set this as CAJAL_AGENT_SERVER on this collector">${escapeHtml(cajalServerHint)}</code></p>
                <p class="collector-details-item collector-details-item-wide"><span>Register Endpoint</span><code class="line-value wrap">${escapeHtml(agentRegisterEndpoint)}</code></p>
                <p class="collector-details-item collector-details-item-wide"><span>Poll Endpoint</span><code class="line-value wrap">${escapeHtml(agentPollEndpoint)}</code></p>
              </div>
              `
              : ''}
          </div>
        </div>
        ${collectorTopInfo
          ? `
        <div class="collector-top-fill">
          ${collectorTopInfo}
        </div>
          `
          : ''}
        ${isCollectorRole ? '' : `<div class="top-blank">${collectorPanel(site, toolsExpanded)}</div>`}
        ${isCollectorRole ? '' : `<div class="top-heartbeat">${heartbeatPanel(site)}</div>`}
        ${isCollectorRole ? '' : `<div class="top-uptime">${uptimeChart(uptimePoints, firewall.status || 'down', uptimePointsSecondary, uptimeScale, site.id, heartbeatIndicator)}</div>`}
      </div>

      ${monitorEditor(site)}

      <div class="metric-grid ${isCollectorRole ? 'collector-metric-grid' : ''}">
        ${isCollectorRole
          ? `${collectorTerminalTimeBadgeStrip(site)}${collectorTerminalCard(site, metrics.wanTests)}`
          : ''}

        ${isCollectorRole
          ? ''
          : `
        <article class="metric-card monitor-metric-card">
          <h4 class="metric-card-head">
            <span>SYSLOG</span>
            <span class="signal-flow-chip metric-head-flow ${escapeHtml(syslogIndicator.chipClass)}">${escapeHtml(syslogIndicator.label)}</span>
          </h4>
          <p>Syslog EPS: <strong>${escapeHtml(metrics.syslog?.eventsPerSecond ?? 'N/A')}</strong></p>
          <p>Syslog Total: <strong>${escapeHtml(String(metrics.syslog?.totalIngested || 0))}</strong></p>
          <p>Syslog Last Ingest: <strong>${escapeHtml(formatMaybeTime(metrics.syslog?.lastIngestAt || ''))}</strong></p>
          <p>Syslog Last Error: <strong>${escapeHtml(metrics.syslog?.lastError || 'none')}</strong></p>
          ${allowManage
            ? `
          <div class="metric-view-row">
            <button
              type="button"
              class="flow flow-btn metric-view-btn ${syslogViewActive ? 'active' : ''}"
              data-site-id="${escapeHtml(site.id)}"
              data-protocol="syslog"
              aria-label="View syslog activity for ${escapeHtml(site.name)}"
            >VIEW</button>
          </div>
          `
            : ''}
        </article>

        <article class="metric-card monitor-metric-card">
          <h4 class="metric-card-head">
            <span>SNMP</span>
            <span class="signal-flow-chip metric-head-flow ${escapeHtml(snmpIndicator.chipClass)}">${escapeHtml(snmpIndicator.label)}</span>
          </h4>
          <p>SNMP Version: <strong>${escapeHtml(site.monitorConfig?.snmp?.version || 'N/A')}</strong></p>
          <p>Uptime: <strong>${escapeHtml(metrics.snmp?.uptime || 'Unknown')}</strong></p>
          <p>Interface Poll: <strong>${escapeHtml(metrics.snmp?.lastPoll || 'N/A')}</strong></p>
          <p>Interfaces: <strong>${metrics.snmp?.interfaceCount !== undefined ? escapeHtml(String(metrics.snmp.interfaceCount)) : 'N/A'}${Number(metrics.snmp?.interfaceCount) === 0 ? ' — IF-MIB inaccessible' : ''}</strong></p>
          <p>SNMP Success/Fail: <strong>${escapeHtml(String(metrics.snmp?.successCount || 0))}/${escapeHtml(String(metrics.snmp?.failureCount || 0))}</strong></p>
          <p>SNMP Last Error: <strong>${escapeHtml(metrics.snmp?.lastError || 'none')}</strong></p>
          ${allowManage
            ? `
          <div class="metric-view-row">
            <button
              type="button"
              class="flow flow-btn metric-view-btn ${snmpViewActive ? 'active' : ''}"
              data-site-id="${escapeHtml(site.id)}"
              data-protocol="snmp"
              aria-label="View snmp activity for ${escapeHtml(site.name)}"
            >VIEW</button>
          </div>
          `
            : ''}
        </article>

        <article class="metric-card netflow-metric-card">
          <h4 class="metric-card-head">
            <span>NETFLOW</span>
            <span class="signal-flow-chip metric-head-flow ${escapeHtml(netflowIndicator.chipClass)}">${escapeHtml(netflowIndicator.label)}</span>
          </h4>
          <ul class="metric-list netflow-user-list">${topUsers(metrics.netflow?.topTalkers)}</ul>
          <p>Templates: <strong>${metrics.netflow?.templateCount !== undefined ? escapeHtml(String(metrics.netflow.templateCount)) : 'N/A'}${Number(metrics.netflow?.templateCount) === 0 ? ' — no templates yet' : ''}</strong></p>
          <p>NetFlow Last Error: <strong>${escapeHtml(formatNetflowLastError(metrics.netflow?.lastError))}</strong></p>
          <div class="netflow-troublemakers-row">
            <button type="button" class="netflow-troublemakers-btn" data-site-id="${escapeHtml(site.id)}">Trouble Makers</button>
            ${allowManage
              ? `
            <button
              type="button"
              class="flow flow-btn metric-view-btn ${netflowViewActive ? 'active' : ''}"
              data-site-id="${escapeHtml(site.id)}"
              data-protocol="netflow"
              aria-label="View netflow activity for ${escapeHtml(site.name)}"
            >VIEW</button>
            `
              : ''}
          </div>
        </article>

        `}
      </div>
    </article>
  `;
}

function formatIfSpeed(bps) {
  if (!bps || bps <= 0) return 'N/A';
  if (bps >= 1000000000) return `${(bps / 1000000000).toFixed(bps % 1000000000 === 0 ? 0 : 1)} Gbps`;
  if (bps >= 1000000) return `${(bps / 1000000).toFixed(0)} Mbps`;
  if (bps >= 1000) return `${(bps / 1000).toFixed(0)} Kbps`;
  return `${bps} bps`;
}

function lanLinkMonitorCard(site, metrics) {
  const interfaces = metrics.snmp?.interfaces || [];
  const cfg = site.monitorConfig?.snmp || {};
  if (!cfg.enabled) return '';
  const upCount = interfaces.filter((i) => i.ifOperStatus === 'up').length;
  const downCount = interfaces.filter((i) => i.ifOperStatus === 'down').length;
  const totalCount = interfaces.length;
  const maxMbps = interfaces.reduce((m, i) => Math.max(m, i.totalMbps || 0), 0) || 1;
  const lastPoll = metrics.snmp?.lastInterfacePoll ? new Date(metrics.snmp.lastInterfacePoll).toLocaleTimeString() : 'Never';
  const pollMs = metrics.snmp?.interfacePollMs || 0;

  const rows = interfaces.map((iface) => {
    const barWidth = maxMbps > 0 ? Math.max(1, Math.round(((iface.totalMbps || 0) / maxMbps) * 100)) : 0;
    const utilColor = (iface.utilization || 0) > 80 ? 'var(--down)' : (iface.utilization || 0) > 50 ? 'var(--warn)' : 'var(--accent)';
    return `<tr>
      <td>${escapeHtml(iface.ifDescr)}</td>
      <td class="lan-link-status ${escapeHtml(iface.ifOperStatus)}">${escapeHtml(iface.ifOperStatus?.toUpperCase())}</td>
      <td>${escapeHtml(formatIfSpeed(iface.ifSpeed))}</td>
      <td>${escapeHtml(String(iface.inMbps ?? 0))}</td>
      <td>${escapeHtml(String(iface.outMbps ?? 0))}</td>
      <td><strong>${escapeHtml(String(iface.totalMbps ?? 0))}</strong></td>
      <td>${escapeHtml(String(iface.utilization ?? 0))}%</td>
      <td><span class="lan-link-bar" style="width:${barWidth}%;background:${utilColor}"></span></td>
    </tr>`;
  }).join('');

  const hasData = totalCount > 0;
  const allowDelete = canAdmin();
  const allowManage = canAdmin();
  const showLanEditor = allowManage && activeLanLinkEditorSiteId === site.id;
  return `
    <article class="site-tile lan-link-card${hasData ? '' : ' is-device-down'}" data-site-id="${escapeHtml(site.id)}">
      <div class="site-top">
        <div class="site-details">
          <span class="lan-links-badge">LAN LINKS</span>
        </div>
        <div class="top-controls">
          ${allowManage ? `<button type="button" class="ghost-btn lan-link-edit-btn${showLanEditor ? ' active' : ''}" data-site-id="${escapeHtml(site.id)}">EDIT</button>` : ''}
          ${allowDelete ? `<button type="button" class="ghost-btn lan-link-delete-btn" data-site-id="${escapeHtml(site.id)}" data-site-name="${escapeHtml(site.name || site.id)}">DELETE</button>` : ''}
        </div>
      </div>
      ${showLanEditor
        ? `<form class="lan-link-name-form" data-site-id="${escapeHtml(site.id)}">
            <label class="meta-label"><span>Card Title</span><input name="name" value="${escapeHtml(site.name || '')}" /></label>
            <div class="meta-actions"><button type="submit" class="meta-save">Save</button></div>
            <span class="lan-link-save-msg"></span>
          </form>`
        : ''}
      <h4 class="metric-card-head">
        <span>LAN LINK MONITOR — ${escapeHtml(site.name)}</span>
        <span class="signal-flow-chip metric-head-flow ${hasData ? 'flow-on' : 'flow-off'}">${hasData ? `${upCount} UP / ${downCount} DN` : 'NO DATA'}</span>
      </h4>
      ${totalCount > 0
        ? `
      <table class="lan-link-table">
        <thead><tr>
          <th>Interface</th>
          <th>Status</th>
          <th>Speed</th>
          <th>In Mbps</th>
          <th>Out Mbps</th>
          <th>Total</th>
          <th>Util %</th>
          <th></th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <p style="margin-top:auto;padding-top:0.2rem;font-size:0.6rem;color:var(--muted)">
        ${escapeHtml(String(totalCount))} interfaces · Poll: ${escapeHtml(lastPoll)} (${escapeHtml(String(pollMs))}ms)
      </p>
      `
        : `<p class="lan-link-empty">Enable SNMP to monitor LAN interfaces</p>`}
    </article>
  `;
}

function renderTiles() {
  if (!locationPanels) return;
  captureCollectorToolsTerminalScrollPositions();
  const admin = canAdmin();
  const sections = currentSections();
  locationPanels.innerHTML = sections
    .map((section) => {
      const sectionSites = sites.filter((site) => String(site.category || '').trim().toLowerCase() === section.id);
      return `
        <section class="panel" data-section-id="${escapeHtml(section.id)}">
          <div class="panel-head">
            <div class="panel-head-row">
              <div class="location-title-wrap">
                <h2>${escapeHtml(section.name)}</h2>
                <div class="location-address-monitor-row">
                  <span class="location-address">${escapeHtml(section.address || '')}</span>
                  ${renderLocationPingMonitorBadgesForSection(section, admin)}
                </div>
              </div>
              <button
                type="button"
                class="ghost-btn admin-only location-add-device"
                data-category="${escapeHtml(section.id)}"
                ${admin ? '' : 'hidden'}
              >Add New Device</button>
            </div>
          </div>
          <div class="tile-grid">
            ${(() => { const tileSites = sectionSites.filter(s => !(normalizeRole(s.role) === 'other' && s.monitorConfig?.snmp?.enabled)); return tileSites.length ? tileSites.map(siteTile).join('') : (sectionSites.length ? '' : '<p class="empty">No devices configured.</p>'); })()}
            ${sectionSites.map(s => lanLinkMonitorCard(s, s.metrics || {})).join('')}
          </div>
        </section>
      `;
    })
    .join('');

  heartbeatCardRefs = [];
  renderPublicServiceBadges();
  restoreCollectorToolsTerminalScrollPositions();
}

function refreshHeartbeatTimers() {
  // Heartbeat panel now displays fixed check-in timestamps for target 1 and target 2.
}

async function loadDashboard(options = {}) {
  const fromGlobalClockRefresh = Boolean(options?.fromGlobalClockRefresh);
  const [siteRows] = await Promise.all([
    getJson('/api/sites'),
    loadTickerAuditEvents()
  ]);
  sites = Array.isArray(siteRows) ? siteRows : [];
  await Promise.all([
    loadPublicServiceStatuses(),
    loadLocationPingMonitorStatuses()
  ]);
  // Skip DOM rebuild during auto-refresh if user is actively interacting with tile inputs
  const skipTileRender = fromGlobalClockRefresh && (() => {
    if (activeEditor || activeMetaEditorSiteId) return true;
    const el = document.activeElement;
    if (el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT')) {
      if (locationPanels && locationPanels.contains(el)) return true;
    }
    return false;
  })();
  if (!skipTileRender) {
    renderTiles();
    if (fromGlobalClockRefresh) {
      blinkDeviceTilesOnGlobalRefresh();
    }
  }
  renderLocationTitles();
  renderChangeTicker(sites);
  refreshHeartbeatTimers();
}

async function loadAdminSections() {
  await loadSsoSettings();
  await loadLdapSettings();
  await loadRuntimeSettings();
  await loadWebhookRoutingSettings();
  await loadSslSettings();
  await loadLocationSettings();
  await loadSystemHealth();
  initVersionCheckSection();
  await loadManagedUsers();
}

async function reloadAfterLogin() {
  await loadAuthState();
  await loadAlertSilenceState();
  await loadAdminSections();
  await loadDashboard();
}

async function initialize() {
  try {
    await loadAuthState();
    if (!authState?.user?.authenticated) {
      window.location.replace('/login.html');
      return; // Don't schedule refresh — we're leaving the page
    }
    // Fetch version from the public health endpoint (non-fatal if it fails)
    try {
      const health = await getJson('/api/health');
      if (health?.version) {
        updateTopbarVersion(health.version);
      }
      if (health?.snmpTrapPort) {
        snmpTrapPort = health.snmpTrapPort;
      }
    } catch {
      // Version display degrades gracefully
    }
    await loadAlertSilenceState();
    await Promise.all([loadAdminSections(), loadDashboard()]);
  } catch (err) {
    setNotice(err.message);
  }
  if (authState?.user?.authenticated) {
    scheduleAutoRefresh();
  }
}

syncNowBtn?.addEventListener('click', () => {
  loadDashboard()
    .then(async () => {
      if (canAdmin()) await loadSystemHealth();
    })
    .catch((err) => {
      setNotice(err.message);
    })
    .finally(() => {
      scheduleAutoRefresh();
    });
});

refreshClock?.addEventListener('click', async (event) => {
  const trigger = event.target.closest('[data-action="manual-refresh"]');
  if (!trigger) return;
  event.preventDefault();
  if (!canAdmin() || manualGlobalRefreshInFlight) return;
  manualGlobalRefreshInFlight = true;
  refreshClockLastLabel = '';
  renderRefreshClock();
  try {
    await getJson('/api/events/manual-refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
  } catch {
    // Don't block refresh if event logging endpoint fails.
  }
  try {
    await loadDashboard({ fromGlobalClockRefresh: true });
    if (canAdmin()) await loadSystemHealth();
  } catch (err) {
    setNotice(err.message);
  } finally {
    manualGlobalRefreshInFlight = false;
    refreshClockLastLabel = '';
    renderRefreshClock();
    scheduleAutoRefresh();
  }
});

auditTrailBtn?.addEventListener('click', () => {
  if (!auditPanel) return;
  const opening = auditPanel.hidden;
  auditPanel.hidden = !auditPanel.hidden;
  if (opening) { window.scrollTo(0, 0); loadAuditTrail().catch(() => {}); }
});

eventViewerBtn?.addEventListener('click', () => {
  if (!eventPanel) return;
  const opening = eventPanel.hidden;
  eventPanel.hidden = !eventPanel.hidden;
  setEventPolling(opening);
  if (opening) {
    openEventViewer({ source: '', classId: '', search: '', reload: true }).catch((err) => {
      renderEventViewerError(err.message);
    });
  }
});

eventViewerClose?.addEventListener('click', () => {
  if (!eventPanel) return;
  eventPanel.hidden = true;
  setEventPolling(false);
});

auditRefreshBtn?.addEventListener('click', () => {
  loadAuditTrail().catch((err) => {
    if (auditTrailList) auditTrailList.innerHTML = `<p class="empty">${escapeHtml(err.message)}</p>`;
  });
});

auditCloseBtn?.addEventListener('click', () => {
  if (!auditPanel) return;
  auditPanel.hidden = true;
});

eventClassFilter?.addEventListener('change', () => {
  renderEventViewer(eventsCache);
});

eventSourceFilter?.addEventListener('change', () => {
  renderEventViewer(eventsCache);
});

eventSearchInput?.addEventListener('input', () => {
  if (eventSearchDebounceTimer) clearTimeout(eventSearchDebounceTimer);
  eventSearchDebounceTimer = setTimeout(() => {
    renderEventViewer(eventsCache);
  }, 120);
});

helpBtn?.addEventListener('click', () => {
  openHelpDoc();
});

settingsBtn?.addEventListener('click', () => {
  if (!settingsPanel) return;
  settingsPanel.hidden = !settingsPanel.hidden;
  if (!settingsPanel.hidden) {
    window.scrollTo(0, 0);
    loadManagedUsers().catch(() => {});
    loadSsoSettings().catch(() => {});
    loadLdapSettings().catch(() => {});
    loadRuntimeSettings().catch(() => {});
    loadWebhookRoutingSettings().catch(() => {});
    loadSslSettings().catch(() => {});
    loadLocationSettings().catch(() => {});
    loadSystemHealth().catch(() => {});
    loadFirewallCheck().catch(() => {});
    loadStorageSummary().catch(() => {});
    loadApiTokenSettings().catch(() => {});
    loadErrorLogs().catch(() => {});
    loadDiagnosticsLogs().catch(() => {});
    loadRawTelemetry().catch(() => {});
    setRawTelemetryAutoRefresh(Boolean(rawTelemetryAutoRefresh?.checked));
  } else {
    setRawTelemetryAutoRefresh(false);
  }
});

closeSettingsBtn?.addEventListener('click', () => {
  if (settingsPanel) settingsPanel.hidden = true;
  setRawTelemetryAutoRefresh(false);
});

settingsPanel?.addEventListener('click', (event) => {
  const tabBtn = event.target.closest('.settings-tab');
  if (tabBtn && tabBtn.dataset.tab) {
    settingsPanel.querySelectorAll('.settings-tab').forEach(b => { b.classList.remove('active'); b.setAttribute('aria-selected', 'false'); });
    settingsPanel.querySelectorAll('.settings-tab-content').forEach(d => d.classList.remove('active'));
    tabBtn.classList.add('active');
    tabBtn.setAttribute('aria-selected', 'true');
    const target = settingsPanel.querySelector(`.settings-tab-content[data-settings-tab="${tabBtn.dataset.tab}"]`);
    if (target) target.classList.add('active');
    return;
  }
  const toggle = event.target.closest('.settings-toggle');
  if (!toggle) return;
  const section = toggle.closest('.settings-section');
  if (!section || section.hidden) return;
  section.classList.toggle('is-collapsed');
});

apiTokenCopyBtn?.addEventListener('click', async () => {
  const token = String(apiTokenState.revealToken || '').trim();
  if (!token) return;
  try {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      await navigator.clipboard.writeText(token);
      if (apiTokenMsg) apiTokenMsg.textContent = 'Token copied to clipboard.';
      return;
    }
  } catch {
    // fallback path below
  }
  if (apiTokenRevealValue) {
    const range = document.createRange();
    range.selectNodeContents(apiTokenRevealValue);
    const selection = window.getSelection();
    selection?.removeAllRanges();
    selection?.addRange(range);
  }
  if (apiTokenMsg) apiTokenMsg.textContent = 'Copy manually from the token field.';
});

ssoLoginBtn?.addEventListener('click', () => {
  if (authState.config?.enabled) {
    window.location.href = '/api/auth/login';
    return;
  }
  openLocalAuthDialog(authState.user?.email || 'admin@cajal.local');
});

authActionBtn?.addEventListener('click', () => {
  if (authState.user?.authenticated) {
    askActionConfirm({
      title: 'Log Out',
      message: 'Are you sure you want to log out?',
      confirmLabel: 'Log Out',
      cancelLabel: 'Cancel'
    }).then((ok) => {
      if (!ok) return;
      fetch('/api/auth/logout', { method: 'POST' })
        .catch(() => {})
        .finally(() => {
          window.location.href = '/login.html';
        });
    });
    return;
  }
  if (authState.config?.enabled) {
    window.location.href = '/api/auth/login';
    return;
  }
  openLocalAuthDialog('admin@cajal.local');
});

localAuthCancel?.addEventListener('click', () => {
  closeLocalAuthDialog();
});

localAuthDialog?.addEventListener('close', () => {
  localAuthFlow = { stage: 'login', setupToken: '', email: '' };
});

backupPasswordCancel?.addEventListener('click', () => {
  backupPasswordDialog?.close();
  if (backupPasswordResolve) {
    backupPasswordResolve('');
    backupPasswordResolve = null;
  }
});

confirmActionCancel?.addEventListener('click', () => {
  confirmActionDialog?.close();
  if (confirmActionResolve) {
    confirmActionResolve(false);
    confirmActionResolve = null;
  }
});

linuxAgentCancel?.addEventListener('click', () => {
  linuxAgentDialog?.close();
  if (linuxAgentSetupResolve) {
    linuxAgentSetupResolve(null);
    linuxAgentSetupResolve = null;
  }
});

internalDnsCancel?.addEventListener('click', () => {
  closeInternalDnsDialog();
});

internalDnsForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!canAdmin()) return;
  const previousRuntime = cloneForUndo(runtimeConfigState) || {};
  const nextTarget = String(internalDnsTargetInput?.value || '').trim();
  if (nextTarget && (nextTarget.length > 255 || !/^[A-Za-z0-9._:-]+$/.test(nextTarget))) {
    if (internalDnsMsg) internalDnsMsg.textContent = 'Internal DNS target must be a valid IP or hostname.';
    return;
  }
  if (internalDnsMsg) internalDnsMsg.textContent = 'Saving Internal DNS target...';
  try {
    const runtime = await getJson('/api/settings/runtime', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ internalDnsTarget: nextTarget })
    });
    runtimeConfigState = runtime || runtimeConfigState;
    const undoPayload = buildRuntimeUndoPayload(previousRuntime, ['internalDnsTarget']);
    if (Object.keys(undoPayload).length) {
      pushSettingsUndo('Internal DNS target', async () => {
        runtimeConfigState = await getJson('/api/settings/runtime', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(undoPayload)
        });
        await loadRuntimeSettings();
        await loadPublicServiceStatuses();
        renderTiles();
      }, {
        flashTargets: ['.public-service-badges', '#runtimeConfigPanel']
      });
    }
    await loadPublicServiceStatuses();
    showToast(nextTarget ? `Internal DNS set to ${nextTarget}` : 'Internal DNS cleared');
    closeInternalDnsDialog();
  } catch (err) {
    if (internalDnsMsg) internalDnsMsg.textContent = err.message;
  }
});

diagnosticsProtocolFilter?.addEventListener('change', () => {
  loadDiagnosticsLogs().catch(() => {});
});

diagnosticsLevelFilter?.addEventListener('change', () => {
  loadDiagnosticsLogs().catch(() => {});
});

diagnosticsSiteFilter?.addEventListener('change', () => {
  loadDiagnosticsLogs().catch(() => {});
});

rawTelemetryProtocolFilter?.addEventListener('change', () => {
  loadRawTelemetry().catch(() => {});
});

rawTelemetryLimitInput?.addEventListener('change', () => {
  loadRawTelemetry().catch(() => {});
});

rawTelemetrySiteFilter?.addEventListener('change', () => {
  loadRawTelemetry().catch(() => {});
});

rawTelemetrySearchFilter?.addEventListener('change', () => {
  loadRawTelemetry().catch(() => {});
});

rawTelemetrySearchFilter?.addEventListener('input', () => {
  if (rawTelemetrySearchDebounceTimer) clearTimeout(rawTelemetrySearchDebounceTimer);
  rawTelemetrySearchDebounceTimer = setTimeout(() => {
    loadRawTelemetry().catch(() => {});
  }, 180);
});

rawTelemetryAutoRefresh?.addEventListener('change', () => {
  setRawTelemetryAutoRefresh(Boolean(rawTelemetryAutoRefresh.checked));
});

backupPasswordForm?.addEventListener('submit', (event) => {
  event.preventDefault();
  const pass = String(backupPasswordInput?.value || '');
  backupPasswordSubmitted = true;
  if (backupPasswordResolve) {
    backupPasswordResolve(pass);
    backupPasswordResolve = null;
  }
  backupPasswordDialog?.close();
});

confirmActionForm?.addEventListener('submit', (event) => {
  event.preventDefault();
  confirmActionSubmitted = true;
  if (confirmActionResolve) {
    confirmActionResolve(true);
    confirmActionResolve = null;
  }
  confirmActionDialog?.close();
});

linuxAgentForm?.addEventListener('submit', (event) => {
  event.preventDefault();
  const serverUrl = normalizeAgentServerUrl(linuxAgentServerInput?.value || '');
  const siteId = String(linuxAgentSiteInput?.value || '').trim();
  const password = String(linuxAgentPasswordInput?.value || '');
  const confirm = String(linuxAgentConfirmInput?.value || '');
  if (!siteId) {
    if (linuxAgentMsg) linuxAgentMsg.textContent = 'Collector site id is missing.';
    linuxAgentSiteInput?.focus();
    return;
  }
  if (!isValidAgentServerUrl(serverUrl)) {
    if (linuxAgentMsg) linuxAgentMsg.textContent = 'Cajal URL must start with http:// or https://';
    linuxAgentServerInput?.focus();
    return;
  }
  if (password.length < 8) {
    if (linuxAgentMsg) linuxAgentMsg.textContent = 'Password must be at least 8 characters.';
    linuxAgentPasswordInput?.focus();
    return;
  }
  if (password.length > 256) {
    if (linuxAgentMsg) linuxAgentMsg.textContent = 'Password is too long (max 256 characters).';
    linuxAgentPasswordInput?.focus();
    return;
  }
  if (password !== confirm) {
    if (linuxAgentMsg) linuxAgentMsg.textContent = 'Password confirmation did not match.';
    linuxAgentConfirmInput?.focus();
    return;
  }
  linuxAgentSetupSubmitted = true;
  if (linuxAgentSetupResolve) {
    linuxAgentSetupResolve({ serverUrl, siteId, password });
    linuxAgentSetupResolve = null;
  }
  linuxAgentDialog?.close();
});

backupPasswordDialog?.addEventListener('close', () => {
  if (!backupPasswordSubmitted && backupPasswordResolve) {
    backupPasswordResolve('');
    backupPasswordResolve = null;
  }
});

confirmTypeToConfirmInput?.addEventListener('input', () => {
  if (!confirmActionRequiredPhrase) return;
  confirmActionConfirm.disabled =
    confirmTypeToConfirmInput.value.trim().toUpperCase() !== confirmActionRequiredPhrase.toUpperCase();
});

confirmActionDialog?.addEventListener('close', () => {
  if (!confirmActionSubmitted && confirmActionResolve) {
    confirmActionResolve(false);
    confirmActionResolve = null;
  }
  if (confirmTypeToConfirmWrap) confirmTypeToConfirmWrap.hidden = true;
  if (confirmTypeToConfirmInput) confirmTypeToConfirmInput.value = '';
  if (confirmActionConfirm) confirmActionConfirm.disabled = false;
  confirmActionRequiredPhrase = '';
});

linuxAgentDialog?.addEventListener('close', () => {
  if (!linuxAgentSetupSubmitted && linuxAgentSetupResolve) {
    linuxAgentSetupResolve(null);
    linuxAgentSetupResolve = null;
  }
});

localAuthForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!localAuthMsg || !localAuthSubmit) return;
  localAuthMsg.textContent = 'Working...';
  localAuthSubmit.disabled = true;
  try {
    if (localAuthFlow.stage === 'set_password') {
      const result = await getJson('/api/auth/local/setup-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          setupToken: localAuthFlow.setupToken,
          password: localAuthPassword?.value || ''
        })
      });
      if (result?.ok) {
        closeLocalAuthDialog();
        await reloadAfterLogin();
        return;
      }
      if (result?.next === 'enroll_totp' && result?.setupToken) {
        setLocalAuthStage({
          stage: 'enroll_totp',
          setupToken: result.setupToken,
          email: localAuthFlow.email,
          qrUrl: result.qrUrl,
          secret: result.secret
        });
        localAuthMsg.textContent = 'Password saved. Scan QR and enter code.';
        return;
      }
      throw new Error('Unexpected setup response from server.');
    }

    if (localAuthFlow.stage === 'enroll_totp') {
      await getJson('/api/auth/local/verify-totp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          setupToken: localAuthFlow.setupToken,
          totp: localAuthTotp?.value || ''
        })
      });
      closeLocalAuthDialog();
      await reloadAfterLogin();
      return;
    }

    const email = String(localAuthEmail?.value || '').trim().toLowerCase();
    const payload = {
      email,
      password: localAuthPassword?.value || '',
      totp: localAuthTotp?.value || ''
    };
    const result = await getJson('/api/auth/local/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    if (result.ok) {
      closeLocalAuthDialog();
      await reloadAfterLogin();
      return;
    }
    if (result.next === 'set_password') {
      setLocalAuthStage({ stage: 'set_password', setupToken: result.setupToken, email });
      localAuthMsg.textContent = 'Set a new local password.';
      return;
    }
    if (result.next === 'enroll_totp') {
      setLocalAuthStage({
        stage: 'enroll_totp',
        setupToken: result.setupToken,
        email,
        qrUrl: result.qrUrl,
        secret: result.secret
      });
      localAuthMsg.textContent = 'Scan QR and enter 6-digit code.';
      return;
    }
    if (result.next === 'verify_totp') {
      setLocalAuthStage({ stage: 'verify_totp', email });
      localAuthMsg.textContent = 'Enter current 6-digit authenticator code.';
      return;
    }
  } catch (err) {
    localAuthMsg.textContent = err.message;
  } finally {
    localAuthSubmit.disabled = false;
  }
});

document.addEventListener('click', async (event) => {
  const deleteUserBtn = event.target.closest('.delete-user');
  if (deleteUserBtn) {
    if (!canAdmin()) return;
    const row = deleteUserBtn.closest('.user-row');
    const email = row?.dataset.email || '';
    if (!email) return;
    pendingDeleteUser = { email };
    if (deleteUserMsg) deleteUserMsg.textContent = `Are you sure you want to delete user "${email}"? This cannot be undone.`;
    if (typeof deleteUserDialog?.showModal === 'function') deleteUserDialog.showModal();
    return;
  }

  const resetPwBtn = event.target.closest('.reset-user-password');
  if (resetPwBtn) {
    if (!canAdmin()) return;
    const row = resetPwBtn.closest('.user-row');
    const email = row?.dataset.email || '';
    if (!email) return;
    if (userAdminMsg) userAdminMsg.textContent = 'Resetting password...';
    try {
      await getJson(`/api/users/${encodeURIComponent(email)}/reset-local`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: true })
      });
      if (userAdminMsg) userAdminMsg.textContent = 'Password reset. User must set a new one at next login.';
      await loadManagedUsers();
    } catch (err) {
      if (userAdminMsg) userAdminMsg.textContent = err.message;
    }
    return;
  }

  const resetTotpBtn = event.target.closest('.reset-user-totp');
  if (resetTotpBtn) {
    if (!canAdmin()) return;
    const row = resetTotpBtn.closest('.user-row');
    const email = row?.dataset.email || '';
    if (!email) return;
    if (userAdminMsg) userAdminMsg.textContent = 'Resetting TOTP...';
    try {
      await getJson(`/api/users/${encodeURIComponent(email)}/reset-local`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ totp: true })
      });
      if (userAdminMsg) userAdminMsg.textContent = 'TOTP reset. User will enroll again at next login.';
      await loadManagedUsers();
    } catch (err) {
      if (userAdminMsg) userAdminMsg.textContent = err.message;
    }
    return;
  }

  const saveBtn = event.target.closest('.save-user-role');
  if (!saveBtn) return;
  if (!canAdmin()) return;
  const row = saveBtn.closest('.user-row');
  if (!row) return;
  const email = row.dataset.email || '';
  const select = row.querySelector('.user-role-select');
  const displayInput = row.querySelector('.user-name-input');
  if (!email || !select || !displayInput) return;
  if (userAdminMsg) userAdminMsg.textContent = 'Saving user role...';
  try {
    await getJson(`/api/users/${encodeURIComponent(email)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        role: normalizeAccessRole(select.value),
        displayName: String(displayInput.value || '').trim()
      })
    });
    if (userAdminMsg) userAdminMsg.textContent = 'User role saved.';
    await loadManagedUsers();
    if (authState.user?.email && authState.user.email.toLowerCase() === email.toLowerCase()) {
      await loadAuthState();
      renderTiles();
    }
  } catch (err) {
    if (userAdminMsg) userAdminMsg.textContent = err.message;
  }
});

addUserForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!canAdmin()) return;
  const payload = Object.fromEntries(new FormData(addUserForm).entries());
  if (userAdminMsg) userAdminMsg.textContent = 'Adding user...';
  const submitBtn = addUserForm.querySelector('button[type="submit"]');
  if (submitBtn) submitBtn.disabled = true;
  try {
    await getJson('/api/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    addUserForm.reset();
    if (userAdminMsg) userAdminMsg.textContent = 'User added.';
    await loadManagedUsers();
  } catch (err) {
    if (userAdminMsg) userAdminMsg.textContent = err.message;
  } finally {
    if (submitBtn) submitBtn.disabled = false;
  }
});

locationConfigForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!canAdmin()) return;
  const previousLocationSettings = cloneForUndo(locationSettingsState) || {};
  if (locationAdminMsg) locationAdminMsg.textContent = 'Saving location labels...';
  try {
    const payload = Object.fromEntries(new FormData(locationConfigForm).entries());
    locationSettingsState = normalizeLocationSettings(
      await getJson('/api/settings/locations', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })
    );
    pushSettingsUndo('Location labels', async () => {
      locationSettingsState = normalizeLocationSettings(
        await getJson('/api/settings/locations', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            companyName: String(previousLocationSettings.companyName || ''),
            internalName: String(previousLocationSettings.internalName || ''),
            customerName: String(previousLocationSettings.customerName || '')
          })
        })
      );
      await loadLocationSettings();
      renderTiles();
    }, {
      flashTargets: ['#companyNameDisplay', '#locationAdminPanel']
    });
    populateLocationForm(locationSettingsState);
    renderLocationTitles();
    await loadLocationSettings();
    if (locationAdminMsg) locationAdminMsg.textContent = 'Location labels saved.';
    showToast('Settings Saved');
  } catch (err) {
    if (locationAdminMsg) locationAdminMsg.textContent = err.message;
  }
});

teamsConfigForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!canAdmin()) return;
  const previousRuntime = cloneForUndo(runtimeConfigState) || {};
  if (teamsConfigMsg) teamsConfigMsg.textContent = 'Saving Teams settings...';
  const form = new FormData(teamsConfigForm);
  const payload = {
    teamsWebhookUrl: String(form.get('teamsWebhookUrl') || '').trim(),
    teamsWebhookTimeoutMs: String(form.get('teamsWebhookTimeoutMs') || '').trim(),
    teamsPayloadGroup: String(form.get('teamsPayloadGroup') || '').trim()
  };
  try {
    runtimeConfigState = await getJson('/api/settings/runtime', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    populateTeamsForm(runtimeConfigState);
    const undoPayload = buildRuntimeUndoPayload(previousRuntime, ['teamsWebhookUrl', 'teamsWebhookTimeoutMs', 'teamsPayloadGroup']);
    if (Object.keys(undoPayload).length) {
      pushSettingsUndo('Teams notifications', async () => {
        runtimeConfigState = await getJson('/api/settings/runtime', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(undoPayload)
        });
        await loadRuntimeSettings();
        await loadSystemHealth();
      }, {
        flashTargets: ['#teamsConfigPanel', '.public-service-badges']
      });
    }
    await loadSystemHealth();
    if (teamsConfigMsg) teamsConfigMsg.textContent = 'Teams settings saved.';
    showToast('Settings Saved');
  } catch (err) {
    if (teamsConfigMsg) teamsConfigMsg.textContent = err.message;
  }
});

teamsConfigTestBtn?.addEventListener('click', async () => {
  if (!canAdmin()) return;
  ensureTeamsPayloadDefaults();
  if (teamsConfigMsg) teamsConfigMsg.textContent = 'Sending webhook test...';
  try {
    const title = String(teamsPayloadTitleInput?.value || '').trim();
    const group = String(teamsPayloadGroupInput?.value || '').trim();
    const message = String(teamsPayloadMessageInput?.value || '').trim();
    const result = await getJson('/api/settings/teams/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title, group, message })
    });
    await loadSystemHealth();
    if (teamsConfigMsg) teamsConfigMsg.textContent = result?.detail || 'Teams notification posted.';
    showToast('Webhook test sent');
  } catch (err) {
    if (teamsConfigMsg) teamsConfigMsg.textContent = err.message;
  }
});

apiTokenForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!canAdmin()) return;
  if (apiTokenMsg) apiTokenMsg.textContent = 'Creating API token...';
  const name = String(apiTokenNameInput?.value || '').trim();
  const role = normalizeAccessRole(apiTokenRoleInput?.value || 'monitor');
  const expiresRaw = String(apiTokenExpiresInput?.value || '').trim();
  let expiresAt = '';
  if (expiresRaw) {
    const dt = new Date(expiresRaw);
    if (Number.isNaN(dt.getTime())) {
      if (apiTokenMsg) apiTokenMsg.textContent = 'Invalid expiration date/time.';
      return;
    }
    expiresAt = dt.toISOString();
  }
  try {
    const payload = await getJson('/api/settings/api/tokens', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, role, expiresAt })
    });
    apiTokenState = {
      ...normalizeApiTokenState(payload),
      revealToken: String(payload?.token || '').trim()
    };
    renderApiTokenSettings();
    if (apiTokenMsg) apiTokenMsg.textContent = 'API token created. Copy it now.';
    if (apiTokenNameInput) apiTokenNameInput.value = '';
    if (apiTokenRoleInput) apiTokenRoleInput.value = 'monitor';
    if (apiTokenExpiresInput) apiTokenExpiresInput.value = '';
    showToast('Settings Saved');
  } catch (err) {
    if (apiTokenMsg) apiTokenMsg.textContent = err.message;
  }
});

apiTokenList?.addEventListener('click', async (event) => {
  if (!canAdmin()) return;
  const revokeBtn = event.target.closest('.api-token-revoke');
  if (!revokeBtn || revokeBtn.disabled) return;
  const tokenId = String(revokeBtn.dataset.tokenId || '').trim();
  if (!tokenId) return;
  const confirmed = await askActionConfirm({
    title: 'Revoke API Token',
    message: 'This token will stop working immediately. Continue?',
    confirmLabel: 'Revoke',
    cancelLabel: 'Cancel',
    dangerous: true
  });
  if (!confirmed) return;
  if (apiTokenMsg) apiTokenMsg.textContent = 'Revoking API token...';
  try {
    const payload = await getJson(`/api/settings/api/tokens/${encodeURIComponent(tokenId)}`, {
      method: 'DELETE'
    });
    apiTokenState = { ...normalizeApiTokenState(payload), revealToken: '' };
    renderApiTokenSettings();
    if (apiTokenMsg) apiTokenMsg.textContent = 'API token revoked.';
    showToast('Settings Saved');
  } catch (err) {
    if (apiTokenMsg) apiTokenMsg.textContent = err.message;
  }
});


webhookRoutingContent?.addEventListener('click', async (event) => {
  if (!canAdmin()) return;
  const sectionSaveBtn = event.target.closest('.webhook-routing-section-save');
  if (sectionSaveBtn) {
    const sectionId = String(sectionSaveBtn.dataset.sectionId || '').trim().toLowerCase();
    if (!sectionId) return;
    const sectionEl = sectionSaveBtn.closest('.webhook-routing-section');
    const modeSelect = sectionEl?.querySelector('.webhook-routing-section-mode');
    const selectedMode = String(modeSelect?.value || '').trim().toLowerCase();
    if (!WEBHOOK_SECTION_MODE_VALUES.has(selectedMode)) return;
    const previousModes = { ...(webhookRoutingState.sectionModes || {}) };
    const previousMode = WEBHOOK_SECTION_MODE_VALUES.has(previousModes[sectionId]) ? previousModes[sectionId] : 'warn';
    if (webhookRoutingMsg) webhookRoutingMsg.textContent = `Saving ${sectionLabel(sectionId)} mode...`;
    try {
      const payload = await getJson('/api/settings/webhook-routing', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sectionModes: { [sectionId]: selectedMode } })
      });
      webhookRoutingState = normalizeWebhookRoutingState(payload);
      renderWebhookRoutingSettings();
      await loadSystemHealth();
      pushSettingsUndo(`Webhook section ${sectionLabel(sectionId)}`, async () => {
        const restored = await getJson('/api/settings/webhook-routing', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ sectionModes: { [sectionId]: previousMode } })
        });
        webhookRoutingState = normalizeWebhookRoutingState(restored);
        renderWebhookRoutingSettings();
        await loadSystemHealth();
      }, {
        flashTargets: ['#webhookRoutingPanel', '.public-service-badges']
      });
      if (webhookRoutingMsg) webhookRoutingMsg.textContent = `${sectionLabel(sectionId)} mode set to ${selectedMode.toUpperCase()}.`;
      showToast('Settings Saved');
    } catch (err) {
      if (webhookRoutingMsg) webhookRoutingMsg.textContent = err.message;
    }
    return;
  }

  const saveMsgBtn = event.target.closest('.webhook-routing-save-msg');
  if (saveMsgBtn) {
    const routeId = String(saveMsgBtn.dataset.routeId || '').trim().toLowerCase();
    if (!routeId) return;
    const row = saveMsgBtn.closest('.webhook-routing-row');
    const messageInput = row?.querySelector('.webhook-routing-message');
    const message = String(messageInput?.value || '').trim();
    const previousMessages = { ...(webhookRoutingState.messages || {}) };
    const previousValue = String(previousMessages[routeId] || '');
    if (webhookRoutingMsg) webhookRoutingMsg.textContent = `Saving message for ${routeLabel(routeId)}...`;
    try {
      const payload = await getJson('/api/settings/webhook-routing', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages: { [routeId]: message } })
      });
      webhookRoutingState = normalizeWebhookRoutingState(payload);
      renderWebhookRoutingSettings();
      pushSettingsUndo(`Webhook message ${routeLabel(routeId)}`, async () => {
        const restored = await getJson('/api/settings/webhook-routing', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ messages: { [routeId]: previousValue } })
        });
        webhookRoutingState = normalizeWebhookRoutingState(restored);
        renderWebhookRoutingSettings();
      }, {
        flashTargets: ['#webhookRoutingPanel']
      });
      if (webhookRoutingMsg) webhookRoutingMsg.textContent = `Message saved for ${routeLabel(routeId)}.`;
      showToast('Settings Saved');
    } catch (err) {
      if (webhookRoutingMsg) webhookRoutingMsg.textContent = err.message;
    }
    return;
  }

  const toggleBtn = event.target.closest('.webhook-routing-toggle');
  if (toggleBtn) {
    const routeId = String(toggleBtn.dataset.routeId || '').trim().toLowerCase();
    if (!routeId) return;
    const previousRoutes = { ...(webhookRoutingState.routes || {}) };
    const current = previousRoutes[routeId] !== false;
    const next = !current;
    if (webhookRoutingMsg) webhookRoutingMsg.textContent = `Updating ${routeLabel(routeId)}...`;
    try {
      const payload = await getJson('/api/settings/webhook-routing', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ routes: { [routeId]: next } })
      });
      webhookRoutingState = normalizeWebhookRoutingState(payload);
      renderWebhookRoutingSettings();
      await loadSystemHealth();
      const undoValue = Object.prototype.hasOwnProperty.call(previousRoutes, routeId) ? previousRoutes[routeId] : true;
      pushSettingsUndo(`Webhook route ${routeLabel(routeId)}`, async () => {
        const restored = await getJson('/api/settings/webhook-routing', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ routes: { [routeId]: undoValue } })
        });
        webhookRoutingState = normalizeWebhookRoutingState(restored);
        renderWebhookRoutingSettings();
        await loadSystemHealth();
      }, {
        flashTargets: ['#webhookRoutingPanel', '.public-service-badges']
      });
      if (webhookRoutingMsg) webhookRoutingMsg.textContent = `${routeLabel(routeId)} ${next ? 'enabled' : 'disabled'}.`;
      showToast('Settings Saved');
    } catch (err) {
      if (webhookRoutingMsg) webhookRoutingMsg.textContent = err.message;
    }
    return;
  }

  const testBtn = event.target.closest('.webhook-routing-test');
  if (!testBtn) return;
  const routeId = String(testBtn.dataset.routeId || '').trim().toLowerCase();
  if (!routeId) return;
  const row = testBtn.closest('.webhook-routing-row');
  const messageInput = row?.querySelector('.webhook-routing-message');
  const message = String(messageInput?.value || '').trim();
  if (webhookRoutingMsg) webhookRoutingMsg.textContent = `Sending test for ${routeLabel(routeId)}...`;
  try {
    const result = await getJson('/api/settings/webhook-routing/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ routeId, message })
    });
    if (webhookRoutingMsg) webhookRoutingMsg.textContent = result?.detail || `Webhook test posted for ${routeLabel(routeId)}.`;
    showToast('Webhook test sent');
  } catch (err) {
    if (webhookRoutingMsg) webhookRoutingMsg.textContent = err.message;
  }
});

runtimeConfigForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!canAdmin()) return;
  const previousRuntime = cloneForUndo(runtimeConfigState) || {};
  if (runtimeConfigMsg) runtimeConfigMsg.textContent = 'Saving advanced settings...';
  const payload = Object.fromEntries(new FormData(runtimeConfigForm).entries());
  const localTotpToggle = runtimeConfigForm.querySelector('[name="localTotpEnabled"]');
  if (localTotpToggle) payload.localTotpEnabled = Boolean(localTotpToggle.checked);
  try {
    runtimeConfigState = await getJson('/api/settings/runtime', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    populateRuntimeForm(runtimeConfigState);
    populateTeamsForm(runtimeConfigState);
    populateClockForm(runtimeConfigState);
    const refreshMs = Number(runtimeConfigState.globalDataRefreshMs);
    autoRefreshMs = Number.isFinite(refreshMs) && refreshMs >= 10000 ? refreshMs : DEFAULT_AUTO_REFRESH_MS;
    globalClockTimeZone = String(runtimeConfigState.globalClockTimeZone || 'UTC').trim() || 'UTC';
    globalClockHourMode = String(runtimeConfigState.globalClockHourMode || '24h').trim().toLowerCase() === '12h' ? '12h' : '24h';
    renderSystemClock();
    scheduleAutoRefresh();
    const undoPayload = buildRuntimeUndoPayload(previousRuntime, [
      'syslogUdpPort',
      'syslogTcpPort',
      'netflowPort',
      'snmpPollIntervalMs',
      'flowTimeoutMs',
      'pingIntervalMs',
      'globalDataRefreshMs',
      'localTotpEnabled',
      'wanTestIntervalMs'
    ]);
    if (Object.keys(undoPayload).length) {
      pushSettingsUndo('Advanced options', async () => {
        await getJson('/api/settings/runtime', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(undoPayload)
        });
        await loadRuntimeSettings();
        await loadDashboard();
      }, {
        flashTargets: ['#runtimeConfigPanel', '#refreshClock']
      });
    }
    renderRuntimeSecurityNotice(runtimeConfigState, { saved: true });
    showToast('Settings Saved');
  } catch (err) {
    if (runtimeConfigMsg) runtimeConfigMsg.textContent = err.message;
  }
});

clockConfigForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!canAdmin()) return;
  const previousRuntime = cloneForUndo(runtimeConfigState) || {};
  if (clockConfigMsg) clockConfigMsg.textContent = 'Saving clock settings...';
  const payload = Object.fromEntries(new FormData(clockConfigForm).entries());
  try {
    runtimeConfigState = await getJson('/api/settings/runtime', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    populateClockForm(runtimeConfigState);
    globalClockTimeZone = String(runtimeConfigState.globalClockTimeZone || 'UTC').trim() || 'UTC';
    globalClockHourMode = String(runtimeConfigState.globalClockHourMode || '24h').trim().toLowerCase() === '12h' ? '12h' : '24h';
    renderSystemClock();
    const undoPayload = buildRuntimeUndoPayload(previousRuntime, ['globalClockTimeZone', 'globalClockHourMode']);
    if (Object.keys(undoPayload).length) {
      pushSettingsUndo('Clock settings', async () => {
        await getJson('/api/settings/runtime', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(undoPayload)
        });
        await loadRuntimeSettings();
      }, {
        flashTargets: ['#clockConfigPanel', '#systemClock']
      });
    }
    if (clockConfigMsg) clockConfigMsg.textContent = 'Clock settings saved.';
    showToast('Settings Saved');
  } catch (err) {
    if (clockConfigMsg) clockConfigMsg.textContent = err.message;
  }
});

sslConfigForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!canAdmin()) return;
  const previousSsl = cloneForUndo(sslConfigState) || {};
  if (sslConfigMsg) sslConfigMsg.textContent = 'Saving SSL settings...';
  const payload = Object.fromEntries(new FormData(sslConfigForm).entries());
  try {
    sslConfigState = await getJson('/api/settings/ssl', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    pushSettingsUndo('SSL settings', async () => {
      sslConfigState = await getJson('/api/settings/ssl', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          certPem: String(previousSsl.certPem || ''),
          keyPem: String(previousSsl.keyPem || ''),
          caPem: String(previousSsl.caPem || '')
        })
      });
      await loadSslSettings();
    }, {
      flashTargets: ['#sslConfigPanel']
    });
    populateSslForm(sslConfigState);
    if (sslConfigMsg) sslConfigMsg.textContent = 'SSL settings saved.';
    showToast('Settings Saved');
  } catch (err) {
    if (sslConfigMsg) sslConfigMsg.textContent = err.message;
  }
});

ssoConfigForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!canAdmin()) return;
  const previousSso = cloneForUndo(ssoConfigState) || {};
  if (ssoConfigMsg) ssoConfigMsg.textContent = 'Saving SSO config...';
  const payload = Object.fromEntries(new FormData(ssoConfigForm).entries());
  try {
    ssoConfigState = await getJson('/api/settings/sso', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const undoPayload = buildSsoUndoPayload(previousSso);
    if (Object.keys(undoPayload).length) {
      pushSettingsUndo('SSO configuration', async () => {
        await getJson('/api/settings/sso', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(undoPayload)
        });
        await loadAuthState();
        await loadSsoSettings();
      }, {
        flashTargets: ['#ssoConfigPanel']
      });
    }
    if (ssoConfigMsg) ssoConfigMsg.textContent = 'SSO config saved.';
    await loadAuthState();
    await loadSsoSettings();
    showToast('Settings Saved');
  } catch (err) {
    if (ssoConfigMsg) ssoConfigMsg.textContent = err.message;
  }
});

// ── LDAP Config ─────────────────────────────────────────────────────────────
ldapConfigForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!canAdmin()) return;
  const previousLdap = cloneForUndo(ldapConfigState) || {};
  if (ldapConfigMsg) ldapConfigMsg.textContent = 'Saving LDAP config...';
  const payload = Object.fromEntries(new FormData(ldapConfigForm).entries());
  if (payload.port) payload.port = Number(payload.port) || 389;
  try {
    ldapConfigState = await getJson('/api/settings/ldap', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const undoPayload = {};
    for (const key of ['serverUrl', 'port', 'baseDn', 'adminGroup', 'monitorGroup', 'bindDn', 'bindPassword']) {
      if (typeof previousLdap[key] === 'string' || typeof previousLdap[key] === 'number') {
        if (key === 'bindPassword' && previousLdap[key] === SSO_MASK) continue;
        undoPayload[key] = previousLdap[key];
      }
    }
    if (Object.keys(undoPayload).length) {
      pushSettingsUndo('LDAP configuration', async () => {
        await getJson('/api/settings/ldap', {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(undoPayload)
        });
        await loadLdapSettings();
      }, {
        flashTargets: ['#ldapConfigPanel']
      });
    }
    if (ldapConfigMsg) ldapConfigMsg.textContent = 'LDAP config saved.';
    await loadLdapSettings();
    showToast('Settings Saved');
  } catch (err) {
    if (ldapConfigMsg) ldapConfigMsg.textContent = err.message;
  }
});

function renderLdapSteps(steps = []) {
  if (!ldapTestSteps) return;
  const icons = { ok: '+', fail: 'X', warn: '!', running: '~' };
  ldapTestSteps.innerHTML = steps.map((s) =>
    `<div class="ldap-step ldap-step-${escapeHtml(s.status)}">` +
    `<span class="ldap-step-icon">[${icons[s.status] || '?'}]</span>` +
    `<span class="ldap-step-name">${escapeHtml(s.name)}</span>` +
    `<span class="ldap-step-detail">${escapeHtml(s.detail)}</span>` +
    `</div>`
  ).join('');
  ldapTestSteps.scrollTop = ldapTestSteps.scrollHeight;
}

function renderLdapUserTable(users = []) {
  if (!ldapTestUserTable || !ldapTestUserList) return;
  if (!users.length) {
    ldapTestUserList.hidden = true;
    return;
  }
  ldapTestUserList.hidden = false;
  const header = '<div class="ldap-user-row"><span>Username</span><span>Display Name</span><span>Role</span></div>';
  const rows = users.map((u) =>
    `<div class="ldap-user-row">` +
    `<span>${escapeHtml(u.sAMAccountName || '')}</span>` +
    `<span>${escapeHtml(u.displayName || '')}</span>` +
    `<span class="ldap-user-role-${escapeHtml(u.role || 'monitor')}">${escapeHtml(u.role || 'monitor')}</span>` +
    `</div>`
  ).join('');
  ldapTestUserTable.innerHTML = header + rows;
}

ldapTestBtn?.addEventListener('click', async () => {
  if (!canAdmin()) return;
  ldapTestPendingUsers = [];
  if (ldapTestSteps) ldapTestSteps.innerHTML = '';
  if (ldapTestUserList) ldapTestUserList.hidden = true;
  if (ldapTestApprove) ldapTestApprove.hidden = true;

  if (typeof ldapTestDialog?.showModal === 'function') {
    ldapTestDialog.showModal();
  }

  // Show running state
  renderLdapSteps([{ name: 'Initializing', status: 'running', detail: 'Sending test request...' }]);

  // Get current form values to send as test params
  const payload = Object.fromEntries(new FormData(ldapConfigForm).entries());
  if (payload.port) payload.port = Number(payload.port) || 389;

  try {
    const result = await getJson('/api/settings/ldap/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    renderLdapSteps(result.steps || []);
    ldapTestPendingUsers = result.users || [];
    renderLdapUserTable(ldapTestPendingUsers);

    if (ldapTestApprove && ldapTestPendingUsers.length > 0) {
      ldapTestApprove.hidden = false;
      ldapTestApprove.textContent = `Approve Import (${ldapTestPendingUsers.length} users)`;
    }
  } catch (err) {
    renderLdapSteps([{ name: 'Error', status: 'fail', detail: err.message }]);
  }
});

ldapTestApprove?.addEventListener('click', async () => {
  if (!ldapTestPendingUsers.length) return;
  ldapTestApprove.disabled = true;
  ldapTestApprove.textContent = 'Importing...';

  try {
    const result = await getJson('/api/settings/ldap/import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ users: ldapTestPendingUsers })
    });

    const summary = [];
    if (result.created?.length) summary.push(`${result.created.length} created`);
    if (result.updated?.length) summary.push(`${result.updated.length} updated`);
    if (result.skipped?.length) summary.push(`${result.skipped.length} skipped`);

    renderLdapSteps([
      ...(ldapTestSteps ? Array.from(ldapTestSteps.querySelectorAll('.ldap-step')).map((el) => ({
        name: el.querySelector('.ldap-step-name')?.textContent || '',
        status: (el.className.match(/ldap-step-(\w+)/) || [])[1] || 'ok',
        detail: el.querySelector('.ldap-step-detail')?.textContent || ''
      })) : []),
      { name: 'Import Complete', status: 'ok', detail: summary.join(', ') || 'No changes' }
    ]);

    ldapTestApprove.hidden = true;
    ldapTestPendingUsers = [];
    showToast(`LDAP import: ${summary.join(', ')}`);
    await loadManagedUsers();
  } catch (err) {
    ldapTestApprove.textContent = `Approve Import (${ldapTestPendingUsers.length} users)`;
    renderLdapSteps([
      { name: 'Import Failed', status: 'fail', detail: err.message }
    ]);
  } finally {
    ldapTestApprove.disabled = false;
  }
});

ldapTestClose?.addEventListener('click', () => {
  ldapTestDialog?.close();
});

resetOwnTotpBtn?.addEventListener('click', async () => {
  if (canAdmin()) return;
  if (mySecurityMsg) mySecurityMsg.textContent = 'Resetting your TOTP...';
  try {
    await getJson('/api/auth/local/reset-totp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    if (mySecurityMsg) mySecurityMsg.textContent = 'TOTP reset. Re-enroll on next local login.';
  } catch (err) {
    if (mySecurityMsg) mySecurityMsg.textContent = err.message;
  }
});

backupNowBtn?.addEventListener('click', async () => {
  if (!canAdmin()) return;
  const password = await askBackupPassword({
    title: 'Create Backup',
    message: 'Enter a password to encrypt the backup file.'
  });
  if (!password) return;
  if (backupMsg) backupMsg.textContent = 'Creating backup...';
  try {
    const result = await getJson('/api/backup/export', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });
    downloadTextFile(result.filename, JSON.stringify(result.backup, null, 2));
    if (backupMsg) backupMsg.textContent = 'Backup file created.';
    await loadSystemHealth();
    showToast('Backup Created');
  } catch (err) {
    if (backupMsg) backupMsg.textContent = err.message;
  }
});

refreshSystemHealthBtn?.addEventListener('click', () => {
  loadSystemHealth().catch(() => {});
});

refreshFirewallCheckerBtn?.addEventListener('click', () => {
  loadFirewallCheck().catch(() => {});
});

refreshStorageBtn?.addEventListener('click', () => {
  loadStorageSummary().catch(() => {});
});

purgeStorageLogsBtn?.addEventListener('click', () => {
  purgeStorageSummaryLogs().catch(() => {});
});

factoryResetBtn?.addEventListener('click', () => {
  triggerFactoryResetForDeployment().catch(() => {});
});

refreshErrorLogBtn?.addEventListener('click', () => {
  loadErrorLogs().catch(() => {});
});

refreshDiagnosticsBtn?.addEventListener('click', () => {
  loadDiagnosticsLogs().catch(() => {});
});

clearDiagnosticsBtn?.addEventListener('click', () => {
  clearDiagnosticsLogs().catch(() => {});
});

refreshRawTelemetryBtn?.addEventListener('click', () => {
  loadRawTelemetry().catch(() => {});
});

clearRawTelemetryBtn?.addEventListener('click', () => {
  clearRawTelemetry().catch(() => {});
});

openDiagnosticsConsoleBtn?.addEventListener('click', () => {
  if (!diagnosticConsoleDialog || typeof diagnosticConsoleDialog.showModal !== 'function') return;
  loadDiagnosticsLogs().catch(() => {});
  if (!diagnosticConsoleDialog.open) diagnosticConsoleDialog.showModal();
  if (diagnosticConsoleOutput) diagnosticConsoleOutput.textContent = diagnosticsRenderCache;
});

openRawTelemetryConsoleBtn?.addEventListener('click', () => {
  if (!rawTelemetryConsoleDialog || typeof rawTelemetryConsoleDialog.showModal !== 'function') return;
  loadRawTelemetry().catch(() => {});
  if (!rawTelemetryConsoleDialog.open) rawTelemetryConsoleDialog.showModal();
  if (rawTelemetryConsoleOutput) rawTelemetryConsoleOutput.textContent = rawTelemetryRenderCache;
});

diagnosticConsoleClose?.addEventListener('click', () => {
  diagnosticConsoleDialog?.close();
});

rawTelemetryConsoleClose?.addEventListener('click', () => {
  rawTelemetryConsoleDialog?.close();
});

netflowTroublemakersClose?.addEventListener('click', () => {
  netflowTroublemakersDialog?.close();
});

silenceAlertsBtn?.addEventListener('click', async () => {
  if (!canAdmin()) return;
  try {
    const payload = await getJson('/api/alerts/silence/toggle', { method: 'POST' });
    const until = new Date(String(payload?.silencedUntil || '')).getTime();
    alertSilenceUntilMs = Number.isFinite(until) ? until : 0;
    renderAlertSilenceControls();
    showToast(payload?.silenced ? 'Alerts silenced for 15 minutes' : 'Alerts re-enabled');
    loadSystemHealth().catch(() => {});
  } catch (err) {
    setNotice(err.message);
  }
});

globalUndoBtn?.addEventListener('click', () => {
  runLatestSettingsUndo().catch((err) => setNotice(err.message));
});

backupRestoreForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!canAdmin()) return;
  const file = backupFileInput?.files?.[0];
  if (!file) {
    if (backupMsg) backupMsg.textContent = 'Select a backup file first.';
    return;
  }
  const password = await askBackupPassword({
    title: 'Restore Backup',
    message: 'Enter the backup file password to restore.'
  });
  if (!password) return;
  if (backupMsg) backupMsg.textContent = 'Restoring backup...';
  try {
    const content = await file.text();
    await getJson('/api/backup/import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password, backup: content })
    });
    if (backupMsg) backupMsg.textContent = 'Backup restored.';
    showToast('Backup Restored');
    await loadLocationSettings();
    await loadDashboard();
    await loadSystemHealth();
  } catch (err) {
    if (backupMsg) backupMsg.textContent = err.message;
  }
});

document.addEventListener('click', (event) => {
  const saveLocationSectionButton = event.target.closest('.save-location-section');
  if (saveLocationSectionButton) {
    if (!canAdmin()) return;
    const row = saveLocationSectionButton.closest('.location-row');
    const sectionId = String(row?.dataset.sectionId || '').trim().toLowerCase();
    const name = String(row?.querySelector('.section-name-input')?.value || '').trim();
    const address = String(row?.querySelector('.section-address-input')?.value || '').trim();
    if (!sectionId || !name) return;
    const previousSection = cloneForUndo(
      (locationSettingsState?.sections || []).find((section) => String(section?.id || '').trim().toLowerCase() === sectionId) || null
    );
    getJson(`/api/settings/locations/sections/${encodeURIComponent(sectionId)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, address })
    })
      .then((settings) => {
        locationSettingsState = normalizeLocationSettings(settings);
        if (previousSection) {
          pushSettingsUndo('Location section', async () => {
            locationSettingsState = normalizeLocationSettings(
              await getJson(`/api/settings/locations/sections/${encodeURIComponent(sectionId)}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                  name: String(previousSection.name || ''),
                  address: String(previousSection.address || '')
                })
              })
            );
            renderLocationTitles();
            renderTiles();
          }, {
            flashTargets: [() => sectionFlashSelector(sectionId), '#locationAdminPanel']
          });
        }
        renderLocationTitles();
        renderTiles();
        showToast('Settings Saved');
      })
      .catch((err) => setNotice(err.message));
    return;
  }

  const deleteLocationSectionButton = event.target.closest('.delete-location-section');
  if (deleteLocationSectionButton) {
    if (!canAdmin()) return;
    const row = deleteLocationSectionButton.closest('.location-row');
    const sectionId = String(row?.dataset.sectionId || '').trim().toLowerCase();
    const name = String(row?.querySelector('.section-name-input')?.value || sectionId).trim();
    if (!sectionId) return;
    askActionConfirm({
      title: 'Delete Location',
      message: `Delete location "${name}" and all devices inside it? This cannot be undone.`,
      confirmLabel: 'Delete Location',
      cancelLabel: 'Cancel',
      dangerous: true
    })
      .then((ok) => {
        if (!ok) return null;
        return getJson(`/api/settings/locations/sections/${encodeURIComponent(sectionId)}`, {
          method: 'DELETE'
        })
          .then(async () => {
            await loadLocationSettings();
            await loadDashboard();
            showToast('Location Deleted');
          });
      })
      .catch((err) => setNotice(err.message));
    return;
  }

  const locationPingAddButton = event.target.closest('.location-ping-monitor-add');
  if (locationPingAddButton) {
    if (!canAdmin()) return;
    const sectionId = String(locationPingAddButton.dataset.sectionId || '').trim().toLowerCase();
    if (!sectionId) return;
    const section = (locationSettingsState?.sections || []).find((row) => String(row?.id || '').trim().toLowerCase() === sectionId);
    if (!section) return;
    const currentMonitors = Array.isArray(section.pingMonitors) ? section.pingMonitors.slice(0, 5) : [];
    if (currentMonitors.length >= 5) {
      setNotice('A maximum of 5 ping monitors is allowed per location.');
      return;
    }
    openLocationPingMonitorDialog({ sectionId });
    return;
  }

  const locationPingEditButton = event.target.closest('.location-ping-monitor-edit');
  if (locationPingEditButton) {
    if (!canAdmin()) return;
    const sectionId = String(locationPingEditButton.dataset.sectionId || '').trim().toLowerCase();
    const monitorId = String(locationPingEditButton.dataset.monitorId || '').trim().toLowerCase();
    if (!sectionId || !monitorId) return;
    openLocationPingMonitorDialog({ sectionId, monitorId });
    return;
  }

  const lanLinkDeleteButton = event.target.closest('.lan-link-delete-btn');
  if (lanLinkDeleteButton) {
    if (!canAdmin()) return;
    const siteId = String(lanLinkDeleteButton.dataset.siteId || '').trim();
    const siteName = String(lanLinkDeleteButton.dataset.siteName || siteId).trim();
    if (!siteId) return;
    const site = sites.find((s) => s.id === siteId);
    const isLanLinkOnly = normalizeRole(site?.role) === 'other';
    if (isLanLinkOnly) {
      askActionConfirm({
        title: 'Delete LAN Link Device',
        message: `Delete "${siteName}"? This cannot be undone.`,
        confirmLabel: 'Delete',
        cancelLabel: 'Cancel',
        dangerous: true
      })
        .then((ok) => {
          if (!ok) return null;
          return getJson(`/api/sites/${encodeURIComponent(siteId)}`, { method: 'DELETE' })
            .then(async () => { showToast('LAN Link Deleted'); await loadDashboard(); });
        })
        .catch((err) => setNotice(err.message));
    } else {
      askActionConfirm({
        title: 'Remove LAN Link Card',
        message: `Disable SNMP monitoring for "${siteName}"? The device will remain, only the LAN link card is removed.`,
        confirmLabel: 'Disable SNMP',
        cancelLabel: 'Cancel',
        dangerous: false
      })
        .then((ok) => {
          if (!ok) return null;
          return getJson(`/api/sites/${encodeURIComponent(siteId)}/monitors/snmp`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: false })
          })
            .then(async () => { showToast('SNMP Disabled'); await loadDashboard(); });
        })
        .catch((err) => setNotice(err.message));
    }
    return;
  }

  const deleteDeviceButton = event.target.closest('.delete-device');
  if (deleteDeviceButton) {
    if (!canAdmin()) return;
    const siteId = String(deleteDeviceButton.dataset.siteId || '').trim();
    const siteName = String(deleteDeviceButton.dataset.siteName || siteId).trim();
    if (!siteId) return;
    askActionConfirm({
      title: 'Delete Device',
      message: `Delete device "${siteName}"? This cannot be undone.`,
      confirmLabel: 'Delete Device',
      cancelLabel: 'Cancel',
      dangerous: true
    })
      .then((ok) => {
        if (!ok) return null;
        return getJson(`/api/sites/${encodeURIComponent(siteId)}`, { method: 'DELETE' })
          .then(async () => {
            if (activeMetaEditorSiteId === siteId) activeMetaEditorSiteId = null;
            dirtyMetaSites.delete(siteId);
            collectorDetailsExpandedSites.delete(siteId);
            collectorToolsExpandedSites.delete(siteId);
            showToast('Device Deleted');
            await loadDashboard();
          });
      })
      .catch((err) => setNotice(err.message));
    return;
  }

  const locationAddButton = event.target.closest('.location-add-device');
  if (locationAddButton) {
    if (!canAdmin()) return;
    const category = String(locationAddButton.dataset.category || '');
    if (!category) return;
    pendingAddDeviceCategory = category;
    if (addDeviceName) addDeviceName.value = '';
    if (addDeviceType) addDeviceType.value = 'firewall';
    if (addDeviceMsg) addDeviceMsg.textContent = 'Create a new device in this location.';
    if (typeof addDeviceDialog?.showModal === 'function') addDeviceDialog.showModal();
    return;
  }

  const toolsExpandToggle = event.target.closest('.tools-expand-toggle');
  if (toolsExpandToggle) {
    const siteId = String(toolsExpandToggle.dataset.siteId || '').trim();
    if (!siteId) return;
    const opening = !collectorToolsExpandedSites.has(siteId);
    if (collectorToolsExpandedSites.has(siteId)) {
      collectorToolsExpandedSites.delete(siteId);
    } else {
      collectorToolsExpandedSites.add(siteId);
    }
    renderTiles();
    if (opening) queueCollectorToolsTerminalScroll(siteId, TERMINAL_SCOPE_CAJAL);
    return;
  }

  const helpSectionButton = event.target.closest('[data-help-section]');
  if (helpSectionButton) {
    const sectionId = String(helpSectionButton.dataset.helpSection || '').trim() || 'tools-terminal';
    openHelpDoc(sectionId);
    return;
  }

  const publicServiceEditableBadge = event.target.closest('.public-service-badge-editable');
  if (publicServiceEditableBadge) {
    if (!canAdmin()) return;
    const serviceId = String(publicServiceEditableBadge.dataset.serviceId || '').trim().toLowerCase();
    if (serviceId !== 'internal-dns') return;
    const currentTarget = String(publicServiceEditableBadge.dataset.target || '').trim();
    openInternalDnsDialog(currentTarget);
    return;
  }

  const metaToggle = event.target.closest('.meta-toggle');
  if (metaToggle) {
    if (!canAdmin()) return;
    const siteId = metaToggle.dataset.siteId || '';
    if (!siteId) return;
    const opening = activeMetaEditorSiteId !== siteId;
    activeMetaEditorSiteId = opening ? siteId : null;
    if (!opening) dirtyMetaSites.delete(siteId);
    renderTiles();
    refreshHeartbeatTimers();
    return;
  }

  const lanLinkEditBtn = event.target.closest('.lan-link-edit-btn');
  if (lanLinkEditBtn) {
    if (!canAdmin()) return;
    const siteId = lanLinkEditBtn.dataset.siteId || '';
    if (!siteId) return;
    activeLanLinkEditorSiteId = activeLanLinkEditorSiteId !== siteId ? siteId : null;
    renderTiles();
    return;
  }

  const collectorDetailsToggle = event.target.closest('.collector-details-toggle');
  if (collectorDetailsToggle) {
    const siteId = collectorDetailsToggle.dataset.siteId || '';
    if (!siteId) return;
    if (collectorDetailsExpandedSites.has(siteId)) {
      collectorDetailsExpandedSites.delete(siteId);
    } else {
      collectorDetailsExpandedSites.add(siteId);
    }
    renderTiles();
    refreshHeartbeatTimers();
    return;
  }

  const notifyButton = event.target.closest('.notify-toggle');
  if (notifyButton) {
    if (!canAdmin()) return;
    const siteId = notifyButton.dataset.siteId;
    const site = sites.find((s) => s.id === siteId);
    if (!site) return;

    const current = Boolean(site.notifications?.enabled);
    const next = !current;
    site.notifications = site.notifications || {};
    site.notifications.enabled = next;
    renderTiles();

    getJson(`/api/sites/${encodeURIComponent(siteId)}/notifications`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: next })
    })
      .then(() => loadDashboard())
      .catch((err) => {
        site.notifications.enabled = current;
        renderTiles();
        setNotice(
          err.message.includes('404')
            ? 'Notification toggle endpoint unavailable. Restart server.'
            : err.message
        );
      });
    return;
  }

  const testNotifyButton = event.target.closest('.test-notify');
  if (testNotifyButton) {
    if (!canAdmin()) return;
    const siteId = testNotifyButton.dataset.siteId || '';
    if (!siteId) return;

    const formEl = testNotifyButton.closest('.notify-form');
    const msg = formEl?.querySelector('.notify-save-msg');
    if (msg) msg.textContent = 'Sending test...';

    getJson(`/api/sites/${encodeURIComponent(siteId)}/test-notify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    })
      .then((result) => {
        if (msg) msg.textContent = result.detail || (result.sent ? 'Test Teams notification sent.' : 'Test simulated.');
      })
      .catch((err) => {
        if (msg) msg.textContent = err.message;
      });
    return;
  }

  const agentDownloadPlaceholderButton = event.target.closest('.agent-download-placeholder');
  if (agentDownloadPlaceholderButton) {
    if (!canAdmin()) return;
    const siteId = String(agentDownloadPlaceholderButton.dataset.siteId || '').trim();
    const os = String(agentDownloadPlaceholderButton.dataset.agentOs || '').trim().toLowerCase();
    if (!siteId) return;
    if (os === 'windows') {
      setupWindowsCollectorAgent(siteId)
        .then((result) => {
          if (result?.cancelled) return;
          showToast('Windows agent script downloaded. Install commands copied to clipboard.');
          setNotice(`Windows agent ready. Install on collector host:\n${(result?.steps || []).join('\n')}`);
        })
        .catch((err) => {
          setNotice(err.message);
        });
      return;
    }
    setupLinuxCollectorAgent(siteId)
      .then((result) => {
        if (result?.cancelled) return;
        showToast('Linux agent package downloaded. Install commands copied to clipboard.');
        setNotice(`Linux agent ready. Install on collector host:\n${(result?.steps || []).join('\n')}`);
      })
      .catch((err) => {
        setNotice(err.message);
      });
    return;
  }

  const collectorAgentUpdateButton = event.target.closest('.collector-agent-update-btn');
  if (collectorAgentUpdateButton) {
    if (!canAdmin()) return;
    const siteId = String(collectorAgentUpdateButton.dataset.siteId || '').trim();
    if (!siteId) return;
    const site = sites.find((row) => String(row?.id || '') === siteId);
    if (!site) {
      setNotice('Collector site not found.');
      return;
    }
    const collector = site.collector || {};
    if (!collector.agentConnected) {
      setNotice(`Collector agent is offline for ${site.name}. Bring the agent online before pushing updates.`);
      return;
    }

    const currentVersion = String(collectorAgentUpdateButton.dataset.currentVersion || collector.agentVersion || '').trim() || 'Unknown';
    const nextVersion = String(collectorAgentUpdateButton.dataset.nextVersion || collector.nextAgentVersion || '').trim() || 'Unknown';
    askActionConfirm({
      title: `Push Agent Update · ${site.name}`,
      message: `Current version: ${currentVersion}\nNext version: ${nextVersion}\nPush update from this CAJAL server now?`,
      confirmLabel: 'Push Update',
      cancelLabel: 'Cancel',
      dangerous: false
    })
      .then((proceed) => {
        if (!proceed) return null;
        setNotice(`Pushing agent update to ${site.name}...`);
        return getJson(`/api/sites/${encodeURIComponent(siteId)}/collector/agent/update`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            targetVersion: nextVersion === 'Unknown' ? '' : nextVersion
          })
        })
          .then(async (result) => {
            const outputLines = Array.isArray(result?.lines) ? result.lines : [String(result?.error || result?.message || 'No output')];
            appendCollectorToolsLines(siteId, [
              `Agent update requested for ${site.name}.`,
              ...outputLines
            ], TERMINAL_SCOPE_AGENT);
            renderTiles();
            queueCollectorToolsTerminalScroll(siteId, TERMINAL_SCOPE_AGENT);
            showToast(
              result?.ok
                ? 'Collector update pushed'
                : (result?.legacyAgentUnsupportedUpdate
                  ? 'Legacy agent detected, run manual update commands'
                  : 'Collector update request failed')
            );
            setNotice(outputLines.join('\n'));
            await loadDashboard();
          })
          .catch((err) => {
            setNotice(`Collector update failed: ${err.message}`);
          });
      })
      .catch((err) => setNotice(err.message));
    return;
  }

  const monitorDiagButton = event.target.closest('.monitor-diagnostic-btn');
  if (monitorDiagButton) {
    if (!canAdmin()) return;
    const editor = monitorDiagButton.closest('.monitor-editor');
    if (!editor) return;
    const msg = editor.querySelector('.monitor-save-msg');
    const formData = new FormData(editor);
    const siteId = String(formData.get('siteId') || '');
    const protocol = String(formData.get('monitorProtocol') || '');
    const enabled = formData.get('enabled') === 'on';
    if (!siteId || !protocol) return;
    const config = {};
    for (const [key, value] of formData.entries()) {
      if (key === 'siteId' || key === 'monitorProtocol' || key === 'enabled') continue;
      config[key] = String(value).trim();
    }
    monitorDiagButton.disabled = true;
    if (msg) msg.textContent = `Running ${protocolLabel(protocol)} diagnostics...`;
    getJson(`/api/sites/${encodeURIComponent(siteId)}/monitors/${encodeURIComponent(protocol)}/diagnostics`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled, config })
      })
      .then((result) => {
        if (msg) msg.textContent = `${protocolLabel(protocol)} diagnostics: ${summarizeDiagnosticsResult(result)}`;
        loadDiagnosticsLogs().catch(() => {});
        loadRawTelemetry().catch(() => {});
        if (typeof diagnosticConsoleDialog?.showModal === 'function' && !diagnosticConsoleDialog.open) {
          diagnosticConsoleDialog.showModal();
        }
      })
      .catch((err) => {
        if (msg) msg.textContent = `${protocolLabel(protocol)} diagnostics failed: ${err.message}`;
      })
      .finally(() => {
        monitorDiagButton.disabled = false;
      });
    return;
  }

  const snmpTestButton = event.target.closest('.snmp-test-btn');
  if (snmpTestButton) {
    if (!canAdmin()) return;
    const editor = snmpTestButton.closest('.monitor-editor');
    if (!editor) return;
    const msg = editor.querySelector('.monitor-save-msg');
    const formData = new FormData(editor);
    const siteId = String(formData.get('siteId') || '');
    const protocol = String(formData.get('monitorProtocol') || '');
    if (!siteId || protocol !== 'snmp') return;
    const config = {};
    for (const [key, value] of formData.entries()) {
      if (key === 'siteId' || key === 'monitorProtocol' || key === 'enabled') continue;
      config[key] = String(value).trim();
    }
    snmpTestButton.disabled = true;
    if (msg) msg.textContent = 'Testing SNMP...';
    getJson(`/api/sites/${encodeURIComponent(siteId)}/monitors/snmp/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ config })
    })
      .then((result) => {
        const summary = summarizeDiagnosticsResult(result?.diagnostics);
        if (msg) {
          msg.textContent = `SNMP OK (${result.version || '2c'}) ${result.targetHost || ''} uptime=${result.uptime || 'n/a'} in ${result.durationMs || 0}ms${summary ? ` | checks ${summary}` : ''}`;
        }
        loadDiagnosticsLogs().catch(() => {});
        loadRawTelemetry().catch(() => {});
      })
      .catch((err) => {
        if (msg) msg.textContent = `SNMP test failed: ${err.message}`;
      })
      .finally(() => {
        snmpTestButton.disabled = false;
      });
    return;
  }

  const syslogTestButton = event.target.closest('.syslog-test-btn');
  if (syslogTestButton) {
    if (!canAdmin()) return;
    const editor = syslogTestButton.closest('.monitor-editor');
    if (!editor) return;
    const msg = editor.querySelector('.monitor-save-msg');
    const formData = new FormData(editor);
    const siteId = String(formData.get('siteId') || '');
    const protocol = String(formData.get('monitorProtocol') || '');
    if (!siteId || protocol !== 'syslog') return;
    const config = {};
    for (const [key, value] of formData.entries()) {
      if (key === 'siteId' || key === 'monitorProtocol' || key === 'enabled') continue;
      config[key] = String(value).trim();
    }
    syslogTestButton.disabled = true;
    if (msg) msg.textContent = 'Testing Syslog...';
    getJson(`/api/sites/${encodeURIComponent(siteId)}/monitors/syslog/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ config })
    })
      .then((result) => {
        const summary = summarizeDiagnosticsResult(result?.diagnostics);
        if (msg) {
          msg.textContent = `SYSLOG OK ${result.sourceIp || ''} ${result.transport || ''}:${result.port || ''} eps=${result.eventsPerSecond || 0}${summary ? ` | checks ${summary}` : ''}`;
        }
        loadDiagnosticsLogs().catch(() => {});
        loadRawTelemetry().catch(() => {});
      })
      .catch((err) => {
        if (msg) msg.textContent = `SYSLOG test failed: ${err.message}`;
      })
      .finally(() => {
        syslogTestButton.disabled = false;
      });
    return;
  }

  const netflowTestButton = event.target.closest('.netflow-test-btn');
  if (netflowTestButton) {
    if (!canAdmin()) return;
    const editor = netflowTestButton.closest('.monitor-editor');
    if (!editor) return;
    const msg = editor.querySelector('.monitor-save-msg');
    const formData = new FormData(editor);
    const siteId = String(formData.get('siteId') || '');
    const protocol = String(formData.get('monitorProtocol') || '');
    if (!siteId || protocol !== 'netflow') return;
    const config = {};
    for (const [key, value] of formData.entries()) {
      if (key === 'siteId' || key === 'monitorProtocol' || key === 'enabled') continue;
      config[key] = String(value).trim();
    }
    netflowTestButton.disabled = true;
    if (msg) msg.textContent = 'Testing NetFlow...';
    getJson(`/api/sites/${encodeURIComponent(siteId)}/monitors/netflow/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ config })
    })
      .then((result) => {
        const top = Array.isArray(result?.topTalkers) ? result.topTalkers[0] : null;
        const summary = summarizeDiagnosticsResult(result?.diagnostics);
        if (msg) msg.textContent = `NETFLOW OK ${result.sourceIp || ''}${top ? ` top=${top.ip}:${top.mbps}Mbps` : ''}${summary ? ` | checks ${summary}` : ''}`;
        loadDiagnosticsLogs().catch(() => {});
        loadRawTelemetry().catch(() => {});
      })
      .catch((err) => {
        if (msg) msg.textContent = `NETFLOW test failed: ${err.message}`;
      })
      .finally(() => {
        netflowTestButton.disabled = false;
      });
    return;
  }

  const troubleMakersButton = event.target.closest('.netflow-troublemakers-btn');
  if (troubleMakersButton) {
    const siteId = String(troubleMakersButton.dataset.siteId || '').trim();
    if (!siteId) return;
    openNetflowTroublemakersReport(siteId).catch(() => {});
    return;
  }

  const metricViewButton = event.target.closest('.metric-view-btn');
  if (metricViewButton) {
    if (!canAdmin()) return;
    const protocol = String(metricViewButton.dataset.protocol || '').trim().toLowerCase();
    if (!['syslog', 'snmp', 'netflow'].includes(protocol)) return;
    openEventViewer({ source: protocol, classId: '', search: '', reload: true })
      .catch((err) => {
        renderEventViewerError(err.message);
      });
    return;
  }

  const monitorCloseButton = event.target.closest('.monitor-close-btn');
  if (monitorCloseButton) {
    if (!canAdmin()) return;
    activeEditor = null;
    renderTiles();
    return;
  }

  const button = event.target.closest('.flow-btn');
  if (!button) return;
  if (!canAdmin()) return;

  const siteId = button.dataset.siteId;
  const protocol = button.dataset.protocol;
  if (!siteId || !protocol) return;

  if (activeEditor && activeEditor.siteId === siteId && activeEditor.protocol === protocol) {
    activeEditor = null;
  } else {
    activeEditor = { siteId, protocol };
  }

  renderTiles();
});

document.addEventListener('change', async (event) => {
  const uptimeScaleSelectEl = event.target.closest('.uptime-scale-select');
  if (uptimeScaleSelectEl) {
    const siteId = String(uptimeScaleSelectEl.dataset.siteId || '').trim();
    if (!siteId) return;
    const scaleId = normalizeUptimeScaleId(uptimeScaleSelectEl.value);
    uptimeScaleBySite.set(siteId, scaleId);
    renderTiles();
    return;
  }

  const hbTarget = event.target.closest('.heartbeat-target-select');
  if (hbTarget) {
    if (!canAdmin()) return;
    const siteId = hbTarget.dataset.siteId || '';
    const previousSite = snapshotSiteForUndo(siteId);
    const heartbeatTarget = String(hbTarget.value || '').trim().toLowerCase();
    const slot = String(hbTarget.dataset.heartbeatSlot || 'primary').trim().toLowerCase();
    if (!siteId) return;

    try {
      const payload = slot === 'secondary'
        ? { heartbeatTarget2: heartbeatTarget }
        : { heartbeatTarget };
      await getJson(`/api/sites/${encodeURIComponent(siteId)}/meta`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (previousSite) {
        const undoKey = slot === 'secondary' ? 'heartbeatTarget2' : 'heartbeatTarget';
        const undoValue = String(previousSite?.[undoKey] || (slot === 'secondary' ? 'wan2' : 'wan1')).trim().toLowerCase();
        pushSettingsUndo('Heartbeat target', async () => {
          await getJson(`/api/sites/${encodeURIComponent(siteId)}/meta`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ [undoKey]: undoValue })
          });
          await loadDashboard();
        }, {
          flashTargets: [() => `${siteFlashSelector(siteId)} .heartbeat-card`, () => siteFlashSelector(siteId)]
        });
      }
      showToast('Heartbeat target saved');
      await loadDashboard();
    } catch (err) {
      setNotice(err.message);
      await loadDashboard();
    }
    return;
  }

  const roleSelector = event.target.closest('.role-selector');
  if (!roleSelector) return;
  if (!canAdmin()) return;

  const siteId = roleSelector.dataset.siteId || '';
  const role = normalizeRole(roleSelector.value);
  if (!siteId) return;
  const previousSite = snapshotSiteForUndo(siteId);

  roleSelector.className = `role-selector role-${role}`;

  try {
    await getJson(`/api/sites/${encodeURIComponent(siteId)}/meta`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ role })
    });
    if (previousSite) {
      const previousRole = normalizeRole(previousSite.role || 'firewall');
      pushSettingsUndo('Device role', async () => {
        await getJson(`/api/sites/${encodeURIComponent(siteId)}/meta`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ role: previousRole })
        });
        await loadDashboard();
      }, {
        flashTargets: [() => siteFlashSelector(siteId)]
      });
    }
    const site = sites.find((s) => s.id === siteId);
    if (site) site.role = role;
    renderChangeTicker(sites);
  } catch (err) {
    setNotice(err.message);
    await loadDashboard();
  }
});

document.addEventListener('submit', async (event) => {
  const toolsTerminalForm = event.target.closest('.collector-tools-terminal-form');
  if (toolsTerminalForm) {
    event.preventDefault();
    if (!canAdmin()) {
      setNotice('Admin access required for tools terminal.');
      return;
    }
    const siteId = String(toolsTerminalForm.dataset.siteId || '').trim();
    const terminalScope = normalizeTerminalScope(toolsTerminalForm.dataset.terminalScope || '');
    const commandInput = toolsTerminalForm.querySelector('.collector-tools-terminal-input');
    const command = String(commandInput?.value || '').trim();
    if (!siteId) return;
    const terminal = getCollectorToolsTerminalState(siteId, terminalScope);
    const prompt = terminalScope === TERMINAL_SCOPE_AGENT ? 'agent$' : 'tools$';
    terminal.input = command;
    if (!command) {
      renderTiles();
      queueCollectorToolsTerminalInputFocus(siteId, terminalScope);
      return;
    }
    pushCollectorToolsTerminalHistory(terminal, command);
    if (/\?$/.test(command)) {
      const query = command.replace(/\?+$/, '').trim();
      const options = listToolsTerminalCompletions(query, siteId, terminalScope);
      appendCollectorToolsLines(siteId, [`${prompt} ${command}`, ...formatToolsTerminalSuggestionLines(query, options)], terminalScope);
      terminal.pending = false;
      terminal.input = '';
      renderTiles();
      queueCollectorToolsTerminalScroll(siteId, terminalScope);
      queueCollectorToolsTerminalInputFocus(siteId, terminalScope);
      return;
    }
    if (/^(clear|cls)$/i.test(command)) {
      terminal.lines = ['Terminal cleared.'];
      terminal.input = '';
      terminal.pending = false;
      renderTiles();
      queueCollectorToolsTerminalScroll(siteId, terminalScope);
      queueCollectorToolsTerminalInputFocus(siteId, terminalScope);
      return;
    }
    appendCollectorToolsLines(siteId, [`${prompt} ${command}`], terminalScope);
    terminal.pending = true;
    renderTiles();
    queueCollectorToolsTerminalScroll(siteId, terminalScope);
    try {
      const endpoint = terminalScope === TERMINAL_SCOPE_AGENT
        ? `/api/sites/${encodeURIComponent(siteId)}/collector/terminal`
        : `/api/sites/${encodeURIComponent(siteId)}/tools/terminal`;
      const result = await getJson(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command })
      });
      const lines = Array.isArray(result?.lines) ? result.lines : [String(result?.error || result?.message || 'No output')];
      appendCollectorToolsLines(siteId, lines, terminalScope);
    } catch (err) {
      appendCollectorToolsLines(siteId, [`ERROR: ${err.message}`], terminalScope);
    } finally {
      terminal.pending = false;
      terminal.input = '';
      renderTiles();
      queueCollectorToolsTerminalScroll(siteId, terminalScope);
      queueCollectorToolsTerminalInputFocus(siteId, terminalScope);
    }
    return;
  }

  const metaForm = event.target.closest('.site-meta-form');
	  if (metaForm) {
	    if (!canAdmin()) return;
	    event.preventDefault();
	    const siteId = metaForm.dataset.siteId || '';
	    const previousSite = snapshotSiteForUndo(siteId);
	    const msg = metaForm.querySelector('.meta-save-msg');
	    const formInput = (name) => {
	      const el = metaForm.querySelector(`[name="${name}"]`);
	      return el || null;
	    };
	    const formValue = (name) => {
	      const el = formInput(name);
	      return el ? String(el.value || '').trim() : undefined;
	    };
	    const payload = {};
	    const assignField = (payloadKey, formKey = payloadKey) => {
	      const value = formValue(formKey);
	      if (value !== undefined) payload[payloadKey] = value;
	    };
	    assignField('name');
	    assignField('model');
	    assignField('internalIp');
	    assignField('dhcpScope');
	    assignField('isp1');
	    assignField('isp2');
	    assignField('firewallName');
	    assignField('wanIp');
	    assignField('wanIp2');
	    const roleSelector = document.querySelector(`.role-selector[data-site-id="${siteId}"]`);
	    payload.role = normalizeRole(roleSelector?.value);
	    if (!siteId) return;
	    if (msg) msg.textContent = 'Saving...';

    try {
      const result = await getJson(`/api/sites/${encodeURIComponent(siteId)}/meta`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      if (previousSite) {
        const undoPayload = buildSiteMetaUndoPayload(previousSite);
        pushSettingsUndo('Device details', async () => {
          await getJson(`/api/sites/${encodeURIComponent(siteId)}/meta`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(undoPayload)
          });
          await loadDashboard();
        }, {
          flashTargets: [() => siteFlashSelector(siteId)]
        });
      }

	      const saved = result?.site || {};
	      const hasPayload = (key) => Object.prototype.hasOwnProperty.call(payload, key);
	      const mismatch = [
	        hasPayload('name') && String(saved.name || '') !== String(payload.name || '').trim(),
	        hasPayload('model') && String(saved.model || '') !== String(payload.model || '').trim(),
	        hasPayload('internalIp') && String(saved.internalIp || '') !== String(payload.internalIp || '').trim(),
	        hasPayload('dhcpScope') && String(saved.dhcpScope || '') !== String(payload.dhcpScope || '').trim(),
	        hasPayload('isp1') && String(saved.isp1 || '') !== String(payload.isp1 || '').trim(),
	        hasPayload('isp2') && String(saved.isp2 || '') !== String(payload.isp2 || '').trim(),
	        hasPayload('role') && String(saved.role || '') !== String(payload.role || '').trim(),
	        hasPayload('firewallName') && String(saved.firewall?.name || '') !== String(payload.firewallName || '').trim(),
	        hasPayload('wanIp') && String(saved.firewall?.wanIp || '') !== String(payload.wanIp || '').trim(),
	        hasPayload('wanIp2') && String(saved.firewall?.wanIp2 || '') !== String(payload.wanIp2 || '').trim()
	      ].some(Boolean);

      dirtyMetaSites.delete(siteId);
      activeMetaEditorSiteId = null;
      if (msg) msg.textContent = mismatch ? 'Saved partially. Restart server, then save again.' : 'Saved.';
      await loadDashboard();
    } catch (err) {
      if (msg) msg.textContent = err.message;
    }
    return;
  }

  const lanLinkNameForm = event.target.closest('.lan-link-name-form');
  if (lanLinkNameForm) {
    if (!canAdmin()) return;
    event.preventDefault();
    const siteId = lanLinkNameForm.dataset.siteId || '';
    const nameInput = lanLinkNameForm.querySelector('input[name="name"]');
    const msg = lanLinkNameForm.querySelector('.lan-link-save-msg');
    if (!siteId || !nameInput) return;
    const newName = String(nameInput.value || '').trim();
    if (!newName) { if (msg) msg.textContent = 'Name cannot be empty.'; return; }
    if (msg) msg.textContent = 'Saving...';
    try {
      await getJson(`/api/sites/${encodeURIComponent(siteId)}/meta`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: newName })
      });
      activeLanLinkEditorSiteId = null;
      showToast('Card title saved');
      await loadDashboard();
    } catch (err) {
      if (msg) msg.textContent = err.message;
    }
    return;
  }

  const notifyForm = event.target.closest('.notify-form');
  if (notifyForm) {
    if (!canAdmin()) return;
    event.preventDefault();
    const siteId = notifyForm.dataset.siteId || '';
    const previousSite = snapshotSiteForUndo(siteId);
    const input = notifyForm.querySelector('input[name="recipients"]');
    const msg = notifyForm.querySelector('.notify-save-msg');
    if (!siteId || !input) return;

    const recipients = String(input.value || '')
      .split(/[,;\n]/)
      .map((v) => v.trim())
      .filter(Boolean);

    if (msg) msg.textContent = 'Saving...';

    try {
      await getJson(`/api/sites/${encodeURIComponent(siteId)}/notifications`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ recipients })
      });
      if (previousSite) {
        const previousRecipients = Array.isArray(previousSite?.notifications?.recipients)
          ? previousSite.notifications.recipients.map((value) => String(value || '')).filter(Boolean)
          : [];
        pushSettingsUndo('Notification targets', async () => {
          await getJson(`/api/sites/${encodeURIComponent(siteId)}/notifications`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ recipients: previousRecipients })
          });
          await loadDashboard();
        }, {
          flashTargets: [() => siteFlashSelector(siteId)]
        });
      }
      if (msg) msg.textContent = 'Saved.';
      await loadDashboard();
    } catch (err) {
      if (msg) msg.textContent = err.message;
    }
    return;
  }

  const editor = event.target.closest('.monitor-editor');
  if (!editor) return;
  if (!canAdmin()) return;

  event.preventDefault();

  const msg = editor.querySelector('.monitor-save-msg');
  if (msg) msg.textContent = 'Saving...';

  const formData = new FormData(editor);
  const siteId = String(formData.get('siteId') || '');
  const protocol = String(formData.get('monitorProtocol') || '');
  const previousSite = snapshotSiteForUndo(siteId);
  const enabled = formData.get('enabled') === 'on';

  const config = {};
  for (const [key, value] of formData.entries()) {
    if (key === 'siteId' || key === 'monitorProtocol' || key === 'enabled') continue;
    config[key] = String(value).trim();
  }

  try {
    const result = await getJson(`/api/sites/${encodeURIComponent(siteId)}/monitors/${encodeURIComponent(protocol)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled, config })
    });
    if (previousSite) {
      const previousMonitor = previousSite?.monitorConfig?.[protocol] || {};
      const previousEnabled = Boolean(previousMonitor?.enabled);
      const previousConfig = sanitizeMonitorConfigForPatch(previousMonitor);
      pushSettingsUndo(`${protocolLabel(protocol)} settings`, async () => {
        await getJson(`/api/sites/${encodeURIComponent(siteId)}/monitors/${encodeURIComponent(protocol)}`, {
          method: 'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ enabled: previousEnabled, config: previousConfig })
        });
        await loadDashboard();
      }, {
        flashTargets: [() => siteFlashSelector(siteId)]
      });
    }

    const summary = summarizeDiagnosticsResult(result?.diagnostics);
    if (msg) msg.textContent = summary ? `Saved. Checks: ${summary}` : 'Saved.';
    loadDiagnosticsLogs().catch(() => {});
    loadRawTelemetry().catch(() => {});
    await loadDashboard();
  } catch (err) {
    if (msg) msg.textContent = err.message;
  }
});

document.addEventListener('input', (event) => {
  const toolsTerminalInput = event.target.closest('.collector-tools-terminal-input');
  if (toolsTerminalInput) {
    const siteId = String(toolsTerminalInput.dataset.siteId || '').trim();
    const terminalScope = normalizeTerminalScope(toolsTerminalInput.dataset.terminalScope || '');
    if (!siteId) return;
    const terminal = getCollectorToolsTerminalState(siteId, terminalScope);
    terminal.input = String(toolsTerminalInput.value || '');
    terminal.historyCursor = terminal.history.length;
    terminal.historyDraft = terminal.input;
    return;
  }

  const metaForm = event.target.closest('.site-meta-form');
  if (!metaForm) return;
  const siteId = metaForm.dataset.siteId || '';
  if (!siteId) return;

  const dirty = Array.from(metaForm.querySelectorAll('input')).some((input) => input.value !== input.defaultValue);
  if (dirty) {
    dirtyMetaSites.add(siteId);
  } else {
    dirtyMetaSites.delete(siteId);
  }

  const tile = metaForm.closest('.site-tile');
  if (tile) tile.classList.toggle('is-dirty', dirty);
});

document.addEventListener('keydown', (event) => {
  const toolsTerminalInput = event.target.closest('.collector-tools-terminal-input');
  if (!toolsTerminalInput) return;
  const siteId = String(toolsTerminalInput.dataset.siteId || '').trim();
  const terminalScope = normalizeTerminalScope(toolsTerminalInput.dataset.terminalScope || '');
  if (!siteId) return;
  if (toolsTerminalInput.disabled) return;

  if (event.key === 'ArrowUp' || event.key === 'ArrowDown') {
    event.preventDefault();
    const terminal = getCollectorToolsTerminalState(siteId, terminalScope);
    const direction = event.key === 'ArrowUp' ? -1 : 1;
    const nextValue = navigateCollectorToolsTerminalHistory(terminal, String(toolsTerminalInput.value || ''), direction);
    if (nextValue == null) return;
    toolsTerminalInput.value = nextValue;
    terminal.input = nextValue;
    const length = nextValue.length;
    requestAnimationFrame(() => {
      try {
        toolsTerminalInput.setSelectionRange(length, length);
      } catch {
        // Ignore selection errors on unsupported inputs.
      }
    });
    return;
  }

  if (event.key !== 'Tab') return;
  event.preventDefault();

  const completed = completeToolsTerminalInput(String(toolsTerminalInput.value || ''), siteId, terminalScope);
  if (!completed.changed) return;
  toolsTerminalInput.value = completed.value;
  const terminal = getCollectorToolsTerminalState(siteId, terminalScope);
  terminal.input = completed.value;
});

startUiSecondTicker();
startRefreshClockAnimation();
updateStickyHeaderOffsets();
window.addEventListener('resize', () => {
  updateStickyHeaderOffsets();
});

addLocationBtn?.addEventListener('click', async () => {
  if (!canAdmin()) return;
  if (!addLocationDialog || !addLocationForm) return;
  addLocationForm.reset();
  if (addLocationGroup) addLocationGroup.value = 'new section';
  if (typeof addLocationDialog.showModal === 'function') addLocationDialog.showModal();
});

roadmapBtn?.addEventListener('click', () => {
  if (!roadmapDialog) return;
  if (typeof roadmapDialog.showModal === 'function' && !roadmapDialog.open) {
    roadmapDialog.showModal();
  }
});

roadmapClose?.addEventListener('click', () => {
  roadmapDialog?.close();
});

document.getElementById('honkBtn')?.addEventListener('click', () => {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const t = ctx.currentTime;
    const master = ctx.createGain();
    master.gain.setValueAtTime(0.45, t);
    master.connect(ctx.destination);

    // Fundamental — nasal sawtooth honk
    const o1 = ctx.createOscillator();
    const g1 = ctx.createGain();
    o1.type = 'sawtooth';
    o1.frequency.setValueAtTime(180, t);
    o1.frequency.exponentialRampToValueAtTime(240, t + 0.04);
    o1.frequency.exponentialRampToValueAtTime(210, t + 0.25);
    o1.frequency.exponentialRampToValueAtTime(160, t + 0.5);
    g1.gain.setValueAtTime(0, t);
    g1.gain.linearRampToValueAtTime(0.6, t + 0.03);
    g1.gain.setValueAtTime(0.6, t + 0.12);
    g1.gain.linearRampToValueAtTime(0.35, t + 0.35);
    g1.gain.linearRampToValueAtTime(0, t + 0.52);
    o1.connect(g1).connect(master);

    // Harmonic — square wave overtone for raspy texture
    const o2 = ctx.createOscillator();
    const g2 = ctx.createGain();
    o2.type = 'square';
    o2.frequency.setValueAtTime(360, t);
    o2.frequency.exponentialRampToValueAtTime(480, t + 0.04);
    o2.frequency.exponentialRampToValueAtTime(420, t + 0.25);
    o2.frequency.exponentialRampToValueAtTime(320, t + 0.5);
    g2.gain.setValueAtTime(0, t);
    g2.gain.linearRampToValueAtTime(0.18, t + 0.03);
    g2.gain.linearRampToValueAtTime(0.1, t + 0.3);
    g2.gain.linearRampToValueAtTime(0, t + 0.5);
    o2.connect(g2).connect(master);

    // Noise burst for the breathy attack
    const bufLen = ctx.sampleRate * 0.12;
    const noiseBuf = ctx.createBuffer(1, bufLen, ctx.sampleRate);
    const noiseData = noiseBuf.getChannelData(0);
    for (let i = 0; i < bufLen; i++) noiseData[i] = (Math.random() * 2 - 1) * 0.5;
    const noise = ctx.createBufferSource();
    noise.buffer = noiseBuf;
    const ng = ctx.createGain();
    const nf = ctx.createBiquadFilter();
    nf.type = 'bandpass';
    nf.frequency.value = 800;
    nf.Q.value = 2;
    ng.gain.setValueAtTime(0.3, t);
    ng.gain.linearRampToValueAtTime(0, t + 0.1);
    noise.connect(nf).connect(ng).connect(master);

    o1.start(t); o1.stop(t + 0.55);
    o2.start(t); o2.stop(t + 0.53);
    noise.start(t); noise.stop(t + 0.12);
    o1.onended = () => ctx.close();
  } catch { /* no audio support */ }
});

addLocationCancel?.addEventListener('click', () => {
  addLocationDialog?.close();
});

addDeviceCancel?.addEventListener('click', () => {
  addDeviceDialog?.close();
  pendingAddDeviceCategory = '';
});

locationPingCancel?.addEventListener('click', () => {
  closeLocationPingMonitorDialog();
});

locationPingDialog?.addEventListener('close', () => {
  pendingLocationPingMonitorSectionId = '';
  pendingLocationPingMonitorId = '';
});

locationPingForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!canAdmin()) return;
  const sectionId = String(pendingLocationPingMonitorSectionId || '').trim().toLowerCase();
  const monitorId = String(pendingLocationPingMonitorId || '').trim().toLowerCase();
  const editing = Boolean(monitorId);
  if (!sectionId) {
    closeLocationPingMonitorDialog();
    return;
  }
  const target = String(locationPingTargetInput?.value || '').trim();
  const name = String(locationPingNameInput?.value || '').trim();
  if (!target) {
    if (locationPingMsg) locationPingMsg.textContent = 'IP address is required.';
    locationPingTargetInput?.focus();
    return;
  }
  const section = (locationSettingsState?.sections || []).find((row) => String(row?.id || '').trim().toLowerCase() === sectionId);
  if (!section) {
    if (locationPingMsg) locationPingMsg.textContent = 'Location section was not found.';
    return;
  }
  const currentMonitors = Array.isArray(section.pingMonitors) ? section.pingMonitors.slice(0, 5) : [];
  if (!editing && currentMonitors.length >= 5) {
    if (locationPingMsg) locationPingMsg.textContent = 'Maximum 5 monitors allowed for this location.';
    return;
  }
  if (editing && !currentMonitors.some((row) => String(row?.id || '').trim().toLowerCase() === monitorId)) {
    if (locationPingMsg) locationPingMsg.textContent = 'Ping monitor no longer exists.';
    return;
  }

  const nextMonitors = editing
    ? currentMonitors.map((row) => {
      const rowId = String(row?.id || '').trim().toLowerCase();
      if (rowId !== monitorId) return row;
      return name ? { id: monitorId, label: name, target } : { id: monitorId, target };
    })
    : [...currentMonitors, (name ? { label: name, target } : { target })];

  if (locationPingMsg) locationPingMsg.textContent = 'Saving...';
  try {
    const settings = await getJson(`/api/settings/locations/sections/${encodeURIComponent(sectionId)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        pingMonitors: nextMonitors
      })
    });
    locationSettingsState = normalizeLocationSettings(settings);
    await loadLocationPingMonitorStatuses();
    closeLocationPingMonitorDialog();
    renderLocationTitles();
    renderTiles();
    showToast(editing ? 'Ping Monitor Updated' : 'Ping Monitor Added');
  } catch (err) {
    if (locationPingMsg) locationPingMsg.textContent = err.message;
  }
});

locationPingDelete?.addEventListener('click', async () => {
  if (!canAdmin()) return;
  const sectionId = String(pendingLocationPingMonitorSectionId || '').trim().toLowerCase();
  const monitorId = String(pendingLocationPingMonitorId || '').trim().toLowerCase();
  if (!sectionId || !monitorId) return;
  const section = (locationSettingsState?.sections || []).find((row) => String(row?.id || '').trim().toLowerCase() === sectionId);
  if (!section) {
    if (locationPingMsg) locationPingMsg.textContent = 'Location section was not found.';
    return;
  }
  const currentMonitors = Array.isArray(section.pingMonitors) ? section.pingMonitors.slice(0, 5) : [];
  const monitor = currentMonitors.find((row) => String(row?.id || '').trim().toLowerCase() === monitorId);
  if (!monitor) {
    if (locationPingMsg) locationPingMsg.textContent = 'Ping monitor no longer exists.';
    return;
  }
  if (locationPingMsg) locationPingMsg.textContent = 'Removing...';
  try {
    const nextMonitors = currentMonitors.filter((row) => String(row?.id || '').trim().toLowerCase() !== monitorId);
    const settings = await getJson(`/api/settings/locations/sections/${encodeURIComponent(sectionId)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pingMonitors: nextMonitors })
    });
    locationSettingsState = normalizeLocationSettings(settings);
    await loadLocationPingMonitorStatuses();
    closeLocationPingMonitorDialog();
    renderLocationTitles();
    renderTiles();
    showToast('Ping Monitor Removed');
  } catch (err) {
    if (locationPingMsg) locationPingMsg.textContent = err.message;
  }
});

addDeviceForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!canAdmin()) return;
  const name = String(addDeviceName?.value || '').trim();
  const rawType = String(addDeviceType?.value || 'firewall').trim().toLowerCase();
  const isLanLinks = rawType === 'lan-links';
  const role = isLanLinks ? 'other' : normalizeRole(rawType);
  const category = String(pendingAddDeviceCategory || '').trim().toLowerCase();
  if (!name || !category) return;
  const submitBtn = addDeviceForm.querySelector('button[type="submit"]');
  if (submitBtn) submitBtn.disabled = true;
  try {
    const created = await getJson('/api/sites', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, category })
    });
    const siteId = created?.site?.id;
    if (siteId && role !== 'firewall') {
      await getJson(`/api/sites/${encodeURIComponent(siteId)}/meta`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role })
      });
    }
    if (siteId && isLanLinks) {
      await getJson(`/api/sites/${encodeURIComponent(siteId)}/monitors/snmp`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: true, config: {} })
      });
    }
    addDeviceDialog?.close();
    pendingAddDeviceCategory = '';
    showToast('Device Added');
    await loadDashboard();
  } catch (err) {
    if (addDeviceMsg) addDeviceMsg.textContent = err.message;
  } finally {
    if (submitBtn) submitBtn.disabled = false;
  }
});

deleteDeviceCancel?.addEventListener('click', () => {
  deleteDeviceDialog?.close();
  pendingDeleteDevice = { siteId: '', siteName: '' };
});

deleteUserCancel?.addEventListener('click', () => {
  deleteUserDialog?.close();
  pendingDeleteUser = { email: '' };
});

deleteUserForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!canAdmin()) return;
  const email = String(pendingDeleteUser?.email || '').trim();
  if (!email) {
    deleteUserDialog?.close();
    return;
  }
  if (userAdminMsg) userAdminMsg.textContent = `Deleting user ${email}...`;
  try {
    await getJson(`/api/users/${encodeURIComponent(email)}`, { method: 'DELETE' });
    if (userAdminMsg) userAdminMsg.textContent = 'User deleted.';
    await loadManagedUsers();
    await loadAuthState();
    deleteUserDialog?.close();
    pendingDeleteUser = { email: '' };
  } catch (err) {
    if (userAdminMsg) userAdminMsg.textContent = err.message;
  }
});

deleteDeviceForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const siteId = String(pendingDeleteDevice.siteId || '').trim();
  if (!siteId) {
    deleteDeviceDialog?.close();
    return;
  }
  try {
    await getJson(`/api/sites/${encodeURIComponent(siteId)}`, { method: 'DELETE' });
    deleteDeviceDialog?.close();
    pendingDeleteDevice = { siteId: '', siteName: '' };
    showToast('Device Deleted');
    await loadDashboard();
  } catch (err) {
    setNotice(err.message);
  }
});

addLocationForm?.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!canAdmin()) return;
  const previousSectionIds = new Set(
    Array.isArray(locationSettingsState?.sections)
      ? locationSettingsState.sections.map((section) => String(section?.id || '').trim().toLowerCase()).filter(Boolean)
      : []
  );
  const name = String(addLocationName?.value || '').trim();
  if (!name) return;
  const submitBtn = addLocationForm.querySelector('button[type="submit"]');
  if (submitBtn) submitBtn.disabled = true;
  setNotice('Adding location...');
  try {
    locationSettingsState = normalizeLocationSettings(await getJson('/api/settings/locations/sections', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name })
    }));
    const createdSection = (locationSettingsState.sections || []).find(
      (section) => !previousSectionIds.has(String(section?.id || '').trim().toLowerCase())
    );
    if (createdSection?.id) {
      const createdSectionId = String(createdSection.id).trim().toLowerCase();
      pushSettingsUndo('Location add', async () => {
        locationSettingsState = normalizeLocationSettings(
          await getJson(`/api/settings/locations/sections/${encodeURIComponent(createdSectionId)}`, {
            method: 'DELETE'
          })
        );
        renderLocationTitles();
        renderTiles();
      }, {
        flashTargets: [() => sectionFlashSelector(createdSectionId), '#locationAdminPanel']
      });
    }
    addLocationDialog?.close();
    setNotice('Location added.');
    showToast('Location Added');
    renderLocationTitles();
    renderTiles();
  } catch (err) {
    setNotice(err.message);
  } finally {
    if (submitBtn) submitBtn.disabled = false;
  }
});

// ── Version check + update ────────────────────────────────────────────────────
let versionCheckResult = null;
let updateInProgress = false;

function renderVersionCheckSection(result = null, loading = false, statusMsg = '') {
  if (!versionCheckSection) return;
  if (loading) {
    versionCheckSection.innerHTML = '<p class="version-check-loading">Checking for updates\u2026</p>';
    return;
  }
  if (!result) {
    const currentLabel = appVersion ? `v${appVersion}` : 'unknown';
    versionCheckSection.innerHTML = `
      <div class="version-check-row">
        <span class="version-check-current">Version: <strong>${escapeHtml(currentLabel)}</strong></span>
        <button id="checkUpdatesBtn" type="button" class="ghost-btn version-check-btn">Check for Updates</button>
      </div>`;
    document.getElementById('checkUpdatesBtn')?.addEventListener('click', checkForUpdates, { once: true });
    return;
  }
  if (!result.configured) {
    versionCheckSection.innerHTML = `
      <div class="version-check-row">
        <span class="version-check-current">Version: <strong>${escapeHtml(result.current ? `v${result.current}` : 'unknown')}</strong></span>
      </div>`;
    return;
  }
  const currentLabel = `v${escapeHtml(result.current || '?')}`;
  const latestLabel = `v${escapeHtml(result.latest || '?')}`;
  const pubDate = result.publishedAt ? new Date(result.publishedAt).toLocaleDateString() : '';
  let updateCard = '';
  if (result.updateAvailable) {
    const statusHtml = statusMsg
      ? `<p class="update-status-msg">${escapeHtml(statusMsg)}</p>`
      : '';
    updateCard = `
      <div class="update-available-card">
        <p class="update-available-title">Update Available</p>
        <p class="update-available-detail">Latest: <strong>${latestLabel}</strong>${pubDate ? ` &mdash; ${escapeHtml(pubDate)}` : ''}</p>
        ${statusHtml}
        <div class="update-available-actions">
          ${result.releaseUrl ? `<a href="${escapeHtml(result.releaseUrl)}" target="_blank" rel="noopener noreferrer" class="ghost-btn update-notes-link">Release Notes &#8599;</a>` : ''}
          ${result.watchtowerReady === false
            ? '<span class="update-warning">Watchtower not configured &mdash; update manually with <code>docker compose pull &amp;&amp; docker compose up -d</code></span>'
            : `<button id="applyUpdateBtn" type="button" class="update-now-btn" ${updateInProgress ? 'disabled' : ''}>${updateInProgress ? 'Updating\u2026' : 'Update Now'}</button>`}
        </div>
      </div>`;
  } else {
    updateCard = `<p class="version-up-to-date">&#10003; Up to date</p>`;
  }
  versionCheckSection.innerHTML = `
    <div class="version-check-row">
      <span class="version-check-current">Version: <strong>${currentLabel}</strong></span>
      <button id="checkUpdatesBtn" type="button" class="ghost-btn version-check-btn">Re-check</button>
    </div>
    ${updateCard}`;
  document.getElementById('checkUpdatesBtn')?.addEventListener('click', checkForUpdates, { once: true });
  document.getElementById('applyUpdateBtn')?.addEventListener('click', applyUpdate, { once: true });
}

async function checkForUpdates() {
  renderVersionCheckSection(null, true);
  try {
    const result = await getJson('/api/system/version/check');
    versionCheckResult = result;
    renderVersionCheckSection(result);
  } catch (err) {
    if (versionCheckSection) versionCheckSection.innerHTML = `<p class="version-check-error">Update check failed: ${escapeHtml(err.message)}</p>`;
  }
}

async function applyUpdate() {
  if (updateInProgress) return;
  const ok = await askActionConfirm({
    title: 'Apply Update',
    message: 'The application will restart. Active users will be briefly disconnected for ~30 seconds.',
    confirmLabel: 'Update Now',
    cancelLabel: 'Cancel'
  });
  if (!ok) return;
  updateInProgress = true;
  renderVersionCheckSection(versionCheckResult, false, 'Triggering update\u2026');
  try {
    const result = await getJson('/api/system/update/apply', { method: 'POST' });
    if (!result.ok) throw new Error(result.error || 'Update failed');
    renderVersionCheckSection(versionCheckResult, false, 'Update triggered — app will restart shortly. Waiting for server\u2026');
    // Poll /api/health until the server comes back, then reload
    const pollStart = Date.now();
    const pollMax = 120_000;
    const poll = setInterval(async () => {
      if (Date.now() - pollStart > pollMax) {
        clearInterval(poll);
        updateInProgress = false;
        renderVersionCheckSection(versionCheckResult, false, 'Restart timed out. Reload the page manually.');
        return;
      }
      try {
        const health = await getJson('/api/health');
        if (health && health.version && health.version !== (versionCheckResult?.current || '')) {
          clearInterval(poll);
          window.location.reload();
        }
      } catch {
        // Server still restarting — keep polling
      }
    }, 3000);
  } catch (err) {
    updateInProgress = false;
    renderVersionCheckSection(versionCheckResult, false, `Error: ${escapeHtml(err.message)}`);
  }
}

// Initialise the version-check section with just the current version + button (no auto-check)
function initVersionCheckSection() {
  if (!versionCheckSection || !canAdmin()) return;
  renderVersionCheckSection(null);
}

// Update the topbar version label
function updateTopbarVersion(version) {
  const label = document.querySelector('.version-label-inline');
  if (label && version) label.textContent = `Version ${version}`;
}

initialize();
