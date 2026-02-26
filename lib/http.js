'use strict';
const { incrementRequestMetric } = require('./storage');
const { logSystemError, redactSecretsInText } = require('./logging');
const { normalizeAccessRole } = require('./tokens');

// ── JSON response helper ──────────────────────────────────────────────────────
function sendJson(res, statusCode, payload) {
  let out = payload;
  if (
    statusCode === 400
    && out
    && typeof out === 'object'
    && !Array.isArray(out)
    && typeof out.error === 'string'
    && !Object.prototype.hasOwnProperty.call(out, 'code')
  ) {
    out = { ...out, code: 'invalid_request' };
  }
  const body = JSON.stringify(out);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body)
  });
  res.end(body);
  incrementRequestMetric(statusCode);
}

// ── Server error response helper ─────────────────────────────────────────────
function sendServerError(res, err, context = {}, message = '') {
  const msg = String(message || err?.message || 'Internal server error').trim() || 'Internal server error';
  logSystemError(String(context?.scope || 'http.server_error'), err, context);
  try {
    if (res.headersSent) return;
    sendJson(res, 500, { error: msg });
  } catch {
    // Ignore response errors after partial write.
  }
}

// ── Request payload validation ────────────────────────────────────────────────
class RequestValidationError extends Error {
  constructor(message = 'Invalid request payload', code = 'invalid_request', field = '') {
    super(String(message || 'Invalid request payload'));
    this.name = 'RequestValidationError';
    this.code = String(code || 'invalid_request').trim() || 'invalid_request';
    this.field = String(field || '').trim();
  }
}

function isPlainObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function walkPayloadForUnsafeKeys(value, path = '', depth = 0) {
  if (depth > 24) {
    throw new RequestValidationError('Payload nesting is too deep', 'invalid_request_depth', path || '');
  }
  if (Array.isArray(value)) {
    value.forEach((item, idx) => walkPayloadForUnsafeKeys(item, `${path}[${idx}]`, depth + 1));
    return;
  }
  if (!isPlainObject(value)) return;
  const keys = Object.keys(value);
  if (keys.length > 2000) {
    throw new RequestValidationError('Payload has too many keys', 'invalid_request_keys', path || '');
  }
  for (const key of keys) {
    if (key === '__proto__' || key === 'prototype' || key === 'constructor') {
      const fieldPath = path ? `${path}.${key}` : key;
      throw new RequestValidationError(`Unsupported payload field: ${fieldPath}`, 'invalid_request_key', fieldPath);
    }
    const nextPath = path ? `${path}.${key}` : key;
    walkPayloadForUnsafeKeys(value[key], nextPath, depth + 1);
  }
}

function normalizeAllowedPayloadKeys(allowedKeys = null) {
  if (!allowedKeys) return null;
  const list = Array.isArray(allowedKeys) ? allowedKeys : [];
  if (!list.length) return null;
  return new Set(list.map((key) => String(key || '').trim()).filter(Boolean));
}

function validateRequestPayload(payload, options = {}) {
  const requireObject = options.requireObject !== false;
  if (requireObject && !isPlainObject(payload)) {
    throw new RequestValidationError('Payload must be a JSON object', 'invalid_payload_type');
  }
  walkPayloadForUnsafeKeys(payload);

  const allowed = normalizeAllowedPayloadKeys(options.allowedKeys);
  if (allowed && isPlainObject(payload)) {
    for (const key of Object.keys(payload)) {
      if (!allowed.has(key)) {
        throw new RequestValidationError(`Unsupported payload field: ${key}`, 'invalid_payload_field', key);
      }
    }
  }

  if (typeof options.validate === 'function') {
    options.validate(payload);
  }
  return payload;
}

function badRequestPayload(err, fallback = 'Invalid request payload') {
  const message = redactSecretsInText(String(err?.message || fallback || 'Invalid request payload')).trim() || 'Invalid request payload';
  const code = String(err?.code || 'invalid_request').trim() || 'invalid_request';
  const field = String(err?.field || '').trim();
  const payload = { error: message, code };
  if (field) payload.field = field;
  return payload;
}

function readRequestBody(req, options = {}) {
  const maxBytes = Math.max(1024, Math.min(200 * 1024 * 1024, Number(options?.maxBytes || 1e6)));
  return new Promise((resolve, reject) => {
    let raw = '';
    let settled = false;
    const fail = (err) => {
      if (settled) return;
      settled = true;
      reject(err);
      try {
        req.destroy();
      } catch {
        // Ignore socket teardown errors.
      }
    };
    req.on('data', (chunk) => {
      if (settled) return;
      raw += chunk;
      if (raw.length > maxBytes) fail(new RequestValidationError('Payload too large', 'payload_too_large'));
    });
    req.on('end', () => {
      if (settled) return;
      if (!raw) {
        try {
          return resolve(validateRequestPayload({}, options));
        } catch (err) {
          return fail(err);
        }
      }
      try {
        const parsed = JSON.parse(raw);
        resolve(validateRequestPayload(parsed, options));
      } catch {
        fail(new RequestValidationError('Invalid JSON payload', 'invalid_json'));
      }
    });
    req.on('error', (err) => fail(err));
  });
}

// ── Authorization helper ──────────────────────────────────────────────────────
function ensureAllowed(user, allowedRoles = []) {
  const role = normalizeAccessRole(user?.role);
  return allowedRoles.includes(role);
}

module.exports = {
  sendJson,
  sendServerError,
  RequestValidationError,
  isPlainObject,
  walkPayloadForUnsafeKeys,
  normalizeAllowedPayloadKeys,
  validateRequestPayload,
  badRequestPayload,
  readRequestBody,
  ensureAllowed,
};
