'use strict';
const crypto = require('crypto');
const { MIN_CONFIG_KEY_LENGTH, BACKUP_KDF_ITERATIONS } = require('./constants');

// ── Config key validation ─────────────────────────────────────────────────────
function validateConfigKeyStrength(keySource = '') {
  const raw = String(keySource || '').trim();
  if (!raw) {
    return { ok: false, reason: 'CAJAL_CONFIG_KEY is required.' };
  }
  if (raw.length < MIN_CONFIG_KEY_LENGTH) {
    return {
      ok: false,
      reason: `CAJAL_CONFIG_KEY must be at least ${MIN_CONFIG_KEY_LENGTH} characters.`
    };
  }
  const hasLower = /[a-z]/.test(raw);
  const hasUpper = /[A-Z]/.test(raw);
  const hasDigit = /\d/.test(raw);
  const hasSymbol = /[^A-Za-z0-9]/.test(raw);
  const classCount = [hasLower, hasUpper, hasDigit, hasSymbol].filter(Boolean).length;
  if (classCount < 3) {
    return {
      ok: false,
      reason: 'CAJAL_CONFIG_KEY must include at least three character classes (uppercase, lowercase, number, symbol).'
    };
  }
  const normalized = raw.toLowerCase();
  if (
    normalized.includes('changeme')
    || normalized.includes('password')
    || normalized.includes('default')
    || normalized.includes('example')
  ) {
    return {
      ok: false,
      reason: 'CAJAL_CONFIG_KEY contains weak/dictionary fragments and must be replaced.'
    };
  }
  return { ok: true };
}

// ── AES-256-GCM encryption with config key ────────────────────────────────────
const HKDF_SALT = Buffer.from('cajal-config-key-v1', 'utf8');
const HKDF_INFO = Buffer.from('cajal-aes-256-gcm', 'utf8');

function deriveCryptoKeyHkdf(keySource) {
  const input = String(keySource || '');
  return Buffer.from(crypto.hkdfSync('sha256', input, HKDF_SALT, HKDF_INFO, 32));
}

function deriveCryptoKeyLegacy(keySource) {
  return crypto.createHash('sha256').update(String(keySource || '')).digest();
}

// Primary derivation uses HKDF; legacy SHA256 kept for backward-compat decryption.
function deriveCryptoKey(keySource) {
  return deriveCryptoKeyHkdf(keySource);
}

function getCryptoKey() {
  const keySource = String(process.env.CAJAL_CONFIG_KEY || '').trim();
  const validation = validateConfigKeyStrength(keySource);
  if (!validation.ok) {
    throw new Error(`CAJAL_CONFIG_KEY validation failed: ${validation.reason}`);
  }
  return deriveCryptoKey(keySource);
}

function getPreviousCryptoKey() {
  const prev = String(process.env.CAJAL_CONFIG_KEY_PREVIOUS || '').trim();
  if (!prev) return null;
  const validation = validateConfigKeyStrength(prev);
  if (!validation.ok) return null;
  return deriveCryptoKey(prev);
}

function encryptJson(value) {
  const key = getCryptoKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(value), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return {
    iv: iv.toString('base64'),
    tag: tag.toString('base64'),
    data: ciphertext.toString('base64')
  };
}

function decryptJsonWithKey(blob, key) {
  const iv = Buffer.from(blob.iv, 'base64');
  const tag = Buffer.from(blob.tag, 'base64');
  const data = Buffer.from(blob.data, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(data), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

function decryptJson(blob) {
  const keySource = String(process.env.CAJAL_CONFIG_KEY || '').trim();
  const validation = validateConfigKeyStrength(keySource);
  if (!validation.ok) {
    throw new Error(`CAJAL_CONFIG_KEY validation failed: ${validation.reason}`);
  }
  // Try HKDF-derived key first (current), then legacy SHA256 for backward compat
  const candidates = [
    deriveCryptoKeyHkdf(keySource),
    deriveCryptoKeyLegacy(keySource)
  ];
  const prevSource = String(process.env.CAJAL_CONFIG_KEY_PREVIOUS || '').trim();
  if (prevSource && validateConfigKeyStrength(prevSource).ok) {
    candidates.push(deriveCryptoKeyHkdf(prevSource));
    candidates.push(deriveCryptoKeyLegacy(prevSource));
  }
  let lastErr = null;
  for (const key of candidates) {
    try {
      return decryptJsonWithKey(blob, key);
    } catch (err) {
      lastErr = lastErr || err;
    }
  }
  throw lastErr;
}

// ── Backup encryption (password-based) ───────────────────────────────────────
function deriveBackupKey(password, salt, iterations = BACKUP_KDF_ITERATIONS) {
  return crypto.pbkdf2Sync(String(password || ''), salt, iterations, 32, 'sha256');
}

function encryptBackupPayload(payload, password) {
  const pass = String(password || '');
  if (pass.length < 16) throw new Error('Backup password must be at least 16 characters');
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = deriveBackupKey(pass, salt);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    format: 'cajal-backup-v1',
    createdAt: new Date().toISOString(),
    kdf: { name: 'pbkdf2-sha256', iterations: BACKUP_KDF_ITERATIONS, salt: salt.toString('base64') },
    cipher: {
      name: 'aes-256-gcm',
      iv: iv.toString('base64'),
      tag: tag.toString('base64'),
      data: ciphertext.toString('base64')
    }
  };
}

function decryptBackupPayload(backupBlob, password) {
  const blob = typeof backupBlob === 'string' ? JSON.parse(backupBlob) : backupBlob;
  if (!blob || blob.format !== 'cajal-backup-v1' || !blob.kdf || !blob.cipher) {
    throw new Error('Invalid backup file format');
  }
  const pass = String(password || '');
  if (!pass) throw new Error('Backup password is required');
  const salt = Buffer.from(String(blob.kdf.salt || ''), 'base64');
  const iv = Buffer.from(String(blob.cipher.iv || ''), 'base64');
  const tag = Buffer.from(String(blob.cipher.tag || ''), 'base64');
  const data = Buffer.from(String(blob.cipher.data || ''), 'base64');
  const iterations = Number(blob.kdf.iterations) || BACKUP_KDF_ITERATIONS;
  const key = deriveBackupKey(pass, salt, iterations);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(data), decipher.final()]);
  return JSON.parse(plaintext.toString('utf8'));
}

function validateBackupImportPayload(decrypted) {
  if (!decrypted || typeof decrypted !== 'object') throw new Error('Invalid backup: payload is not an object');
  if (decrypted.version !== 1) throw new Error(`Unsupported backup version: ${decrypted.version ?? '(missing)'}`);
  if (!Array.isArray(decrypted.sites)) throw new Error('Invalid backup: sites field is missing or not an array');
  if (decrypted.sites.length === 0) throw new Error('Backup contains no sites');
  if (decrypted.sites.length > 10000) throw new Error('Backup exceeds maximum site limit (10000)');
  if (!Array.isArray(decrypted.devices)) throw new Error('Invalid backup: devices field is missing or not an array');
  if (decrypted.devices.length > 100000) throw new Error('Backup exceeds maximum device limit (100000)');
  const siteIds = new Set();
  for (const site of decrypted.sites) {
    const id = String(site?.id || '').trim();
    if (!id) throw new Error('Backup contains a site with a missing or empty id');
    if (siteIds.has(id)) throw new Error(`Backup contains duplicate site id: ${id}`);
    siteIds.add(id);
  }
  return true;
}

// ── TOTP (RFC 6238) ───────────────────────────────────────────────────────────
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Encode(buf) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(value) {
  const clean = String(value || '')
    .toUpperCase()
    .replace(/=+$/g, '')
    .replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let current = 0;
  const out = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx < 0) continue;
    current = (current << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((current >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20));
}

function totpAt(secret, unixTime) {
  const key = base32Decode(secret);
  const counter = Math.floor(unixTime / 30);
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 2 ** 32), 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
  return String(code % 1000000).padStart(6, '0');
}

function verifyTotp(secret, code, windowSize = 1) {
  const clean = String(code || '').trim();
  if (!/^\d{6}$/.test(clean)) return false;
  const now = Math.floor(Date.now() / 1000);
  for (let i = -windowSize; i <= windowSize; i += 1) {
    if (totpAt(secret, now + i * 30) === clean) return true;
  }
  return false;
}

// ── API token hashing ─────────────────────────────────────────────────────────
function hashApiToken(token = '') {
  return crypto.createHash('sha256').update(String(token || ''), 'utf8').digest('hex');
}

module.exports = {
  validateConfigKeyStrength,
  deriveCryptoKey,
  getCryptoKey,
  getPreviousCryptoKey,
  encryptJson,
  decryptJsonWithKey,
  decryptJson,
  deriveBackupKey,
  encryptBackupPayload,
  decryptBackupPayload,
  validateBackupImportPayload,
  BASE32_ALPHABET,
  base32Encode,
  base32Decode,
  generateTotpSecret,
  totpAt,
  verifyTotp,
  hashApiToken,
};
