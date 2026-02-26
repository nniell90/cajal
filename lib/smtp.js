'use strict';
const crypto = require('crypto');
const os = require('os');
const net = require('net');
const tls = require('tls');
const { spawn } = require('child_process');
const {
  SMTP_TRANSPORT_CONFIG,
  smtpConfigEnabled,
  smtpTransportLabel,
  sanitizeMailAddress,
} = require('./constants');

// ── Mail header utilities ─────────────────────────────────────────────────────
function sanitizeMailHeaderValue(value = '') {
  return String(value || '').replace(/[\r\n]+/g, ' ').trim();
}

function buildPlainTextEmailMessage({ from, recipients, subject, body }) {
  const safeFrom = sanitizeMailHeaderValue(from);
  const safeTo = recipients.map((v) => sanitizeMailHeaderValue(v)).filter(Boolean).join(', ');
  const safeSubject = sanitizeMailHeaderValue(subject);
  const safeBody = String(body || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  return [
    `From: ${safeFrom}`,
    `To: ${safeTo}`,
    `Subject: ${safeSubject}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${Date.now()}.${crypto.randomBytes(6).toString('hex')}@${os.hostname() || 'localhost'}>`,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=utf-8',
    'Content-Transfer-Encoding: 8bit',
    '',
    safeBody,
    ''
  ].join('\n');
}

// ── SMTP dot-stuffing ─────────────────────────────────────────────────────────
function smtpDotStuffMessage(text = '') {
  const normalized = String(text || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  return normalized.split('\n').map((line) => (line.startsWith('.') ? `.${line}` : line)).join('\r\n');
}

// ── SMTP response parsing ─────────────────────────────────────────────────────
function parseSmtpResponseLine(line = '') {
  const match = String(line || '').match(/^(\d{3})([\s-])(.*)$/);
  if (!match) return null;
  return {
    code: Number(match[1]),
    complete: match[2] === ' ',
    text: String(match[3] || '').trim()
  };
}

function smtpCapabilitiesFromResponse(lines = []) {
  const features = new Set();
  const authMethods = new Set();
  for (const line of lines) {
    const parsed = parseSmtpResponseLine(line);
    if (!parsed) continue;
    const text = String(parsed.text || '').trim();
    if (!text) continue;
    const upper = text.toUpperCase();
    const [feature, ...rest] = upper.split(/\s+/).filter(Boolean);
    if (feature) features.add(feature);
    if (feature === 'AUTH') {
      for (const method of rest) authMethods.add(method);
    }
  }
  return { features, authMethods };
}

// ── SMTP connection ───────────────────────────────────────────────────────────
function createSmtpLineReader(socket) {
  let buffer = '';
  const queued = [];
  let pending = null;
  let ended = false;

  const settlePending = (fn) => {
    if (!pending) return;
    const next = pending;
    pending = null;
    clearTimeout(next.timer);
    fn(next);
  };

  const onData = (chunk) => {
    buffer += Buffer.isBuffer(chunk) ? chunk.toString('utf8') : String(chunk || '');
    while (true) {
      const idx = buffer.indexOf('\n');
      if (idx < 0) break;
      const line = buffer.slice(0, idx).replace(/\r$/, '');
      buffer = buffer.slice(idx + 1);
      if (pending) settlePending((next) => next.resolve(line));
      else queued.push(line);
    }
  };

  const onError = (err) => settlePending((next) => next.reject(err || new Error('SMTP socket error')));
  const onClose = () => {
    ended = true;
    settlePending((next) => next.reject(new Error('SMTP socket closed')));
  };

  socket.on('data', onData);
  socket.once('error', onError);
  socket.once('close', onClose);

  return {
    nextLine(timeoutMs = 15000) {
      if (queued.length) return Promise.resolve(queued.shift());
      if (ended) return Promise.reject(new Error('SMTP socket closed'));
      return new Promise((resolve, reject) => {
        pending = {
          resolve,
          reject,
          timer: setTimeout(() => {
            settlePending((next) => next.reject(new Error('SMTP response timeout')));
          }, Math.max(1000, Number(timeoutMs) || 15000))
        };
      });
    }
  };
}

async function readSmtpResponse(reader, timeoutMs = 15000) {
  const lines = [];
  let code = 0;
  while (true) {
    const line = await reader.nextLine(timeoutMs);
    lines.push(line);
    const parsed = parseSmtpResponseLine(line);
    if (!parsed) continue;
    code = parsed.code;
    if (parsed.complete) break;
  }
  return { code, lines };
}

function smtpWriteLine(socket, line = '') {
  socket.write(`${String(line)}\r\n`);
}

async function smtpCommand(socket, reader, line, okCodes = [250], timeoutMs = 15000) {
  if (line !== null && line !== undefined) smtpWriteLine(socket, line);
  const response = await readSmtpResponse(reader, timeoutMs);
  if (!okCodes.includes(response.code)) {
    const detail = response.lines.join(' | ') || `SMTP ${response.code}`;
    throw new Error(`SMTP command failed (${line || 'response'}): ${detail}`);
  }
  return response;
}

function connectSmtpSocket(config = SMTP_TRANSPORT_CONFIG, existingSocket = null) {
  const timeoutMs = Math.max(1000, Number(config.timeoutMs) || 15000);
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (err, socket) => {
      if (settled) return;
      settled = true;
      if (err) return reject(err);
      return resolve(socket);
    };

    let activeSocket;
    let useTls = false;
    if (existingSocket) {
      useTls = true;
      activeSocket = tls.connect({
        socket: existingSocket,
        servername: config.host || undefined,
        rejectUnauthorized: !config.allowInvalidCert
      });
    } else if (config.secure) {
      useTls = true;
      activeSocket = tls.connect({
        host: config.host,
        port: config.port,
        servername: config.host || undefined,
        rejectUnauthorized: !config.allowInvalidCert
      });
    } else {
      activeSocket = net.connect({
        host: config.host,
        port: config.port
      });
    }

    activeSocket.setTimeout(timeoutMs);
    activeSocket.once('timeout', () => {
      activeSocket.destroy();
      finish(new Error(`SMTP connection timeout after ${timeoutMs}ms`));
    });
    activeSocket.once('error', (err) => finish(err));
    activeSocket.once(useTls ? 'secureConnect' : 'connect', () => {
      activeSocket.setTimeout(0);
      finish(null, activeSocket);
    });
  });
}

async function runSmtpConnectionProbe(config = SMTP_TRANSPORT_CONFIG) {
  let socket = null;
  try {
    socket = await connectSmtpSocket(config);
    let reader = createSmtpLineReader(socket);
    const banner = await readSmtpResponse(reader, config.timeoutMs);
    if (banner.code !== 220) {
      return { ok: false, detail: `Banner was ${banner.code}, expected 220` };
    }
    let ehlo = await smtpCommand(socket, reader, `EHLO ${config.heloName}`, [250], config.timeoutMs);
    const capabilities = smtpCapabilitiesFromResponse(ehlo.lines);
    if (!config.secure && config.starttls !== 'off') {
      const hasStarttls = capabilities.features.has('STARTTLS');
      if (hasStarttls) {
        await smtpCommand(socket, reader, 'STARTTLS', [220], config.timeoutMs);
        socket = await connectSmtpSocket(config, socket);
        reader = createSmtpLineReader(socket);
        ehlo = await smtpCommand(socket, reader, `EHLO ${config.heloName}`, [250], config.timeoutMs);
      } else if (config.starttls === 'required') {
        return { ok: false, detail: 'STARTTLS required but not advertised by server' };
      }
    }
    await smtpCommand(socket, reader, 'QUIT', [221], config.timeoutMs).catch(() => {});
    const first = (ehlo.lines[0] || '').trim();
    return { ok: true, detail: first || 'EHLO succeeded' };
  } catch (err) {
    return { ok: false, detail: String(err?.message || err || 'SMTP probe failed') };
  } finally {
    if (socket && !socket.destroyed) socket.destroy();
  }
}

async function smtpAuthenticate(socket, reader, capabilities, config = SMTP_TRANSPORT_CONFIG) {
  if (!config.user) return;
  const methods = capabilities?.authMethods || new Set();
  const loginAllowed = methods.size === 0 || methods.has('LOGIN');
  const plainAllowed = methods.size === 0 || methods.has('PLAIN');
  if (plainAllowed) {
    try {
      const token = Buffer.from(`\u0000${config.user}\u0000${config.pass}`, 'utf8').toString('base64');
      await smtpCommand(socket, reader, `AUTH PLAIN ${token}`, [235, 503], config.timeoutMs);
      return;
    } catch {
      // fall through to AUTH LOGIN
    }
  }
  if (!loginAllowed) {
    throw new Error('SMTP AUTH required but server does not advertise LOGIN/PLAIN');
  }
  await smtpCommand(socket, reader, 'AUTH LOGIN', [334], config.timeoutMs);
  await smtpCommand(socket, reader, Buffer.from(config.user, 'utf8').toString('base64'), [334], config.timeoutMs);
  await smtpCommand(socket, reader, Buffer.from(config.pass, 'utf8').toString('base64'), [235], config.timeoutMs);
}

async function sendMailWithSmtp(config = SMTP_TRANSPORT_CONFIG, { from, recipients, subject, body }) {
  const envelopeFrom = sanitizeMailAddress(from);
  if (!envelopeFrom) throw new Error('SMTP sender address is empty');
  const envelopeRecipients = recipients.map((v) => sanitizeMailAddress(v)).filter(Boolean);
  if (!envelopeRecipients.length) throw new Error('SMTP recipient list is empty');

  const message = buildPlainTextEmailMessage({ from, recipients, subject, body });
  let socket = null;
  try {
    socket = await connectSmtpSocket(config);
    let reader = createSmtpLineReader(socket);
    const banner = await readSmtpResponse(reader, config.timeoutMs);
    if (banner.code !== 220) {
      throw new Error(`SMTP banner rejected (${banner.code})`);
    }
    let ehlo = await smtpCommand(socket, reader, `EHLO ${config.heloName}`, [250], config.timeoutMs);
    let capabilities = smtpCapabilitiesFromResponse(ehlo.lines);
    if (!config.secure && config.starttls !== 'off') {
      const hasStarttls = capabilities.features.has('STARTTLS');
      if (hasStarttls) {
        await smtpCommand(socket, reader, 'STARTTLS', [220], config.timeoutMs);
        socket = await connectSmtpSocket(config, socket);
        reader = createSmtpLineReader(socket);
        ehlo = await smtpCommand(socket, reader, `EHLO ${config.heloName}`, [250], config.timeoutMs);
        capabilities = smtpCapabilitiesFromResponse(ehlo.lines);
      } else if (config.starttls === 'required') {
        throw new Error('SMTP STARTTLS required but not supported by server');
      }
    }
    await smtpAuthenticate(socket, reader, capabilities, config);
    await smtpCommand(socket, reader, `MAIL FROM:<${envelopeFrom}>`, [250], config.timeoutMs);
    for (const rcpt of envelopeRecipients) {
      await smtpCommand(socket, reader, `RCPT TO:<${rcpt}>`, [250, 251], config.timeoutMs);
    }
    await smtpCommand(socket, reader, 'DATA', [354], config.timeoutMs);
    socket.write(`${smtpDotStuffMessage(message)}\r\n.\r\n`);
    await smtpCommand(socket, reader, null, [250], config.timeoutMs);
    await smtpCommand(socket, reader, 'QUIT', [221], config.timeoutMs).catch(() => {});
  } finally {
    if (socket && !socket.destroyed) socket.destroy();
  }
}

function sendMailWithSendmail({ from, recipients, subject, body }) {
  return new Promise((resolve, reject) => {
    const child = spawn('sendmail', ['-t', '-i']);
    let stderr = '';

    child.stderr.on('data', (chunk) => {
      stderr += String(chunk);
    });

    child.on('error', (err) => reject(err));
    child.on('close', (code) => {
      if (code !== 0) {
        return reject(new Error(stderr.trim() || `sendmail exited ${code}`));
      }
      resolve();
    });

    child.stdin.write(buildPlainTextEmailMessage({ from, recipients, subject, body }));
    child.stdin.end();
  });
}

async function sendMailWithTransport(payload) {
  if (smtpConfigEnabled()) {
    try {
      await sendMailWithSmtp(SMTP_TRANSPORT_CONFIG, payload);
      return;
    } catch (smtpErr) {
      try {
        await sendMailWithSendmail(payload);
        return;
      } catch (sendmailErr) {
        const smtpMsg = String(smtpErr?.message || smtpErr || 'unknown smtp error');
        const sendmailMsg = String(sendmailErr?.message || sendmailErr || 'unknown sendmail error');
        throw new Error(`SMTP relay failed (${smtpMsg}); sendmail fallback failed (${sendmailMsg})`);
      }
    }
  }
  await sendMailWithSendmail(payload);
}

// ── SMTP config validation ────────────────────────────────────────────────────
function validateSmtpTransportConfig(config = SMTP_TRANSPORT_CONFIG) {
  if (!smtpConfigEnabled(config)) {
    return { ok: false, detail: 'CAJAL_SMTP_HOST is not set' };
  }
  if (!Number.isFinite(Number(config.port)) || Number(config.port) <= 0 || Number(config.port) > 65535) {
    return { ok: false, detail: 'CAJAL_SMTP_PORT must be between 1 and 65535' };
  }
  if (config.user && !config.pass) {
    return { ok: false, detail: 'CAJAL_SMTP_PASS is required when CAJAL_SMTP_USER is set' };
  }
  return { ok: true, detail: '' };
}

module.exports = {
  sanitizeMailHeaderValue,
  buildPlainTextEmailMessage,
  smtpDotStuffMessage,
  parseSmtpResponseLine,
  smtpCapabilitiesFromResponse,
  createSmtpLineReader,
  readSmtpResponse,
  smtpWriteLine,
  smtpCommand,
  connectSmtpSocket,
  runSmtpConnectionProbe,
  smtpAuthenticate,
  sendMailWithSmtp,
  sendMailWithSendmail,
  sendMailWithTransport,
  validateSmtpTransportConfig,
};
