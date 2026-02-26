'use strict';
const fs = require('fs');
const fsp = fs.promises;
const readline = require('readline');
const { TELEMETRY_LOG_FILE } = require('./constants');
const { locationNameForSite } = require('./events');

// ── Buffer helpers ────────────────────────────────────────────────────────────
function parseLinesFromBuffer(buf) {
  if (!buf || !Buffer.isBuffer(buf) || !buf.length) return [];
  const text = buf.toString('utf8').replace(/\0/g, '');
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

function formatPacketPreview(buf, maxLen = 180) {
  if (!buf || !Buffer.isBuffer(buf) || !buf.length) return '';
  const slice = buf.subarray(0, Math.min(buf.length, maxLen));
  return slice
    .toString('utf8')
    .replace(/[^\x20-\x7E]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

// ── Netflow usage tracking ────────────────────────────────────────────────────
function normalizeNetflowUsageIp(value = '') {
  return String(value || '').trim().slice(0, 128);
}

function addNetflowUsage(usageByIp, ip, upBytes = 0, downBytes = 0) {
  const key = normalizeNetflowUsageIp(ip);
  if (!key) return;
  const up = Math.max(0, Number(upBytes || 0));
  const down = Math.max(0, Number(downBytes || 0));
  if (!up && !down) return;
  const bucket = usageByIp.get(key) || { upBytes: 0, downBytes: 0, totalBytes: 0, firstTs: 0, lastTs: 0 };
  bucket.upBytes += up;
  bucket.downBytes += down;
  bucket.totalBytes += up + down;
  usageByIp.set(key, bucket);
}

async function buildNetflowTroublemakersReport(state, site, options = {}) {
  const windowDays = Math.max(1, Math.min(30, Math.floor(Number(options.days) || 7)));
  const topPercentRatio = Math.max(0.01, Math.min(0.5, Number(options.topPercent) || 0.1));
  const windowEndMs = Date.now();
  const windowStartMs = windowEndMs - (windowDays * 24 * 60 * 60 * 1000);
  const siteId = String(site?.id || '').trim();
  const siteName = String(site?.name || '').trim();
  const siteNameLower = siteName.toLowerCase();

  const base = {
    siteId,
    siteName,
    locationName: locationNameForSite(site),
    days: windowDays,
    topPercent: Number((topPercentRatio * 100).toFixed(1)),
    windowStart: new Date(windowStartMs).toISOString(),
    windowEnd: new Date(windowEndMs).toISOString(),
    sampledPackets: 0,
    sampledRecords: 0,
    uniqueIps: 0,
    topCount: 0,
    totalBytes: 0,
    topBytes: 0,
    rows: []
  };

  try {
    await fsp.access(TELEMETRY_LOG_FILE, fs.constants.F_OK);
  } catch {
    return base;
  }

  const usageByIp = new Map();
  const stream = fs.createReadStream(TELEMETRY_LOG_FILE, { encoding: 'utf8' });
  const lineReader = readline.createInterface({ input: stream, crlfDelay: Infinity });

  try {
    for await (const lineRaw of lineReader) {
      const line = String(lineRaw || '').trim();
      if (!line) continue;
      let parsed;
      try {
        parsed = JSON.parse(line);
      } catch {
        continue;
      }
      if (String(parsed.protocol || '').toLowerCase() !== 'netflow') continue;
      const tsMs = Date.parse(String(parsed.ts || ''));
      if (!Number.isFinite(tsMs) || tsMs < windowStartMs || tsMs > windowEndMs) continue;

      const rowSiteId = String(parsed.siteId || '').trim();
      const rowSiteNameLower = String(parsed.siteName || '').trim().toLowerCase();
      if (siteId && rowSiteId) {
        if (rowSiteId !== siteId) continue;
      } else if (siteNameLower && rowSiteNameLower) {
        if (rowSiteNameLower !== siteNameLower) continue;
      } else if (siteId) {
        if (!rowSiteNameLower || rowSiteNameLower !== siteNameLower) continue;
      } else if (siteNameLower && !rowSiteNameLower) {
        continue;
      }

      const sample = Array.isArray(parsed?.context?.sample) ? parsed.context.sample : [];
      if (!sample.length) continue;
      base.sampledPackets += 1;
      for (const rec of sample) {
        if (!rec || typeof rec !== 'object') continue;
        const src = normalizeNetflowUsageIp(rec.src || rec.sourceIp || rec.ip || '');
        const dst = normalizeNetflowUsageIp(rec.dst || rec.destinationIp || '');
        const rawUp = Number(rec.upBytes);
        const rawDown = Number(rec.downBytes);
        let upBytes = Number.isFinite(rawUp) && rawUp > 0 ? rawUp : 0;
        let downBytes = Number.isFinite(rawDown) && rawDown > 0 ? rawDown : 0;
        if (!upBytes && !downBytes) {
          const rawBytes = Number(rec.bytes);
          if (Number.isFinite(rawBytes) && rawBytes > 0) {
            upBytes = rawBytes;
            downBytes = rawBytes;
          }
        }
        if (!upBytes && !downBytes) continue;
        if (!src && !dst) continue;
        if (src) {
          addNetflowUsage(usageByIp, src, upBytes, 0);
          const srcBucket = usageByIp.get(src);
          if (srcBucket) {
            srcBucket.firstTs = srcBucket.firstTs ? Math.min(srcBucket.firstTs, tsMs) : tsMs;
            srcBucket.lastTs = Math.max(srcBucket.lastTs || 0, tsMs);
            usageByIp.set(src, srcBucket);
          }
        }
        if (dst) {
          addNetflowUsage(usageByIp, dst, 0, downBytes);
          const dstBucket = usageByIp.get(dst);
          if (dstBucket) {
            dstBucket.firstTs = dstBucket.firstTs ? Math.min(dstBucket.firstTs, tsMs) : tsMs;
            dstBucket.lastTs = Math.max(dstBucket.lastTs || 0, tsMs);
            usageByIp.set(dst, dstBucket);
          }
        }
        base.sampledRecords += 1;
      }
    }
  } finally {
    lineReader.close();
    stream.destroy();
  }

  const ranked = [...usageByIp.entries()]
    .map(([ip, bucket]) => ({
      ip,
      upBytes: Math.max(0, Math.round(Number(bucket.upBytes || 0))),
      downBytes: Math.max(0, Math.round(Number(bucket.downBytes || 0))),
      totalBytes: Math.max(0, Math.round(Number(bucket.totalBytes || 0))),
      firstTs: Number(bucket.firstTs || 0),
      lastTs: Number(bucket.lastTs || 0)
    }))
    .filter((row) => row.totalBytes > 0)
    .sort((a, b) => b.totalBytes - a.totalBytes || a.ip.localeCompare(b.ip));

  base.uniqueIps = ranked.length;
  base.totalBytes = ranked.reduce((sum, row) => sum + row.totalBytes, 0);
  base.topCount = base.uniqueIps > 0 ? Math.max(1, Math.ceil(base.uniqueIps * topPercentRatio)) : 0;
  base.rows = ranked.slice(0, base.topCount).map((row, idx) => ({
    rank: idx + 1,
    ip: row.ip,
    upBytes: row.upBytes,
    downBytes: row.downBytes,
    totalBytes: row.totalBytes,
    firstSeenAt: row.firstTs > 0 ? new Date(row.firstTs).toISOString() : '',
    lastSeenAt: row.lastTs > 0 ? new Date(row.lastTs).toISOString() : '',
    sharePercent: base.totalBytes > 0 ? Number(((row.totalBytes / base.totalBytes) * 100).toFixed(2)) : 0
  }));
  base.topBytes = base.rows.reduce((sum, row) => sum + row.totalBytes, 0);
  return base;
}

// ── Netflow V5 parser ─────────────────────────────────────────────────────────
function parseNetflowV5(buf) {
  if (buf.length < 24) return null;
  const version = buf.readUInt16BE(0);
  if (version !== 5) return null;
  const count = buf.readUInt16BE(2);
  const records = [];
  let offset = 24;

  for (let i = 0; i < count; i += 1) {
    if (offset + 48 > buf.length) break;
    const srcAddr = `${buf[offset]}.${buf[offset + 1]}.${buf[offset + 2]}.${buf[offset + 3]}`;
    const dstAddr = `${buf[offset + 4]}.${buf[offset + 5]}.${buf[offset + 6]}.${buf[offset + 7]}`;
    const dOctets = buf.readUInt32BE(offset + 20);
    records.push({ srcAddr, dstAddr, bytes: dOctets });
    offset += 48;
  }

  return records;
}

// ── Netflow V9 / IPFIX helpers ────────────────────────────────────────────────
function readUnsignedBE(buf, offset, length) {
  if (offset + length > buf.length) return 0;
  if (length === 1) return buf.readUInt8(offset);
  if (length === 2) return buf.readUInt16BE(offset);
  if (length === 4) return buf.readUInt32BE(offset);
  if (length === 8) {
    const hi = buf.readUInt32BE(offset);
    const lo = buf.readUInt32BE(offset + 4);
    return hi * 2 ** 32 + lo;
  }
  let n = 0;
  for (let i = 0; i < length; i += 1) {
    n = n * 256 + buf[offset + i];
  }
  return n;
}

function parseIPv4(buf, offset, length) {
  if (length < 4 || offset + 4 > buf.length) return '';
  return `${buf[offset]}.${buf[offset + 1]}.${buf[offset + 2]}.${buf[offset + 3]}`;
}

function parseTemplateFlowSet(buf, offset, length, targetMap) {
  let pos = offset;
  const end = offset + length;
  while (pos + 4 <= end) {
    const templateId = buf.readUInt16BE(pos);
    const fieldCount = buf.readUInt16BE(pos + 2);
    pos += 4;
    const fields = [];
    for (let i = 0; i < fieldCount; i += 1) {
      if (pos + 4 > end) break;
      const type = buf.readUInt16BE(pos);
      const fieldLength = buf.readUInt16BE(pos + 2);
      pos += 4;
      fields.push({ type, length: fieldLength });
    }
    if (templateId >= 256 && fields.length) targetMap.set(templateId, fields);
  }
}

function parseDataWithTemplate(buf, offset, length, fields) {
  const records = [];
  const recordLen = fields.reduce((sum, f) => sum + f.length, 0);
  if (!recordLen) return records;
  const end = offset + length;
  let pos = offset;
  while (pos + recordLen <= end) {
    let srcAddr = '';
    let dstAddr = '';
    let bytes = 0;
    let fpos = pos;
    for (const field of fields) {
      if (field.type === 8) srcAddr = parseIPv4(buf, fpos, field.length);
      if (field.type === 12) dstAddr = parseIPv4(buf, fpos, field.length);
      if (field.type === 1) bytes = readUnsignedBE(buf, fpos, field.length);
      fpos += field.length;
    }
    if (srcAddr && bytes > 0) records.push({ srcAddr, dstAddr, bytes });
    pos += recordLen;
  }
  return records;
}

function parseNetflowV9(buf, templateMap) {
  if (buf.length < 24) return [];
  const records = [];
  let offset = 24;
  while (offset + 4 <= buf.length) {
    const flowSetId = buf.readUInt16BE(offset);
    const length = buf.readUInt16BE(offset + 2);
    if (!length || offset + length > buf.length) break;
    if (flowSetId === 0) {
      parseTemplateFlowSet(buf, offset + 4, length - 4, templateMap);
    } else if (flowSetId >= 256 && templateMap.has(flowSetId)) {
      records.push(...parseDataWithTemplate(buf, offset + 4, length - 4, templateMap.get(flowSetId)));
    }
    offset += length;
  }
  return records;
}

function parseIPFIX(buf, templateMap) {
  if (buf.length < 16) return [];
  const records = [];
  let offset = 16;
  while (offset + 4 <= buf.length) {
    const setId = buf.readUInt16BE(offset);
    const length = buf.readUInt16BE(offset + 2);
    if (!length || offset + length > buf.length) break;
    if (setId === 2) {
      parseTemplateFlowSet(buf, offset + 4, length - 4, templateMap);
    } else if (setId >= 256 && templateMap.has(setId)) {
      records.push(...parseDataWithTemplate(buf, offset + 4, length - 4, templateMap.get(setId)));
    }
    offset += length;
  }
  return records;
}

function parseAnyNetflow(buf, templateMap) {
  if (buf.length < 2) return [];
  const version = buf.readUInt16BE(0);
  if (version === 5) return parseNetflowV5(buf);
  if (version === 9) return parseNetflowV9(buf, templateMap);
  if (version === 10) return parseIPFIX(buf, templateMap);
  return [];
}

module.exports = {
  parseLinesFromBuffer,
  formatPacketPreview,
  normalizeNetflowUsageIp,
  addNetflowUsage,
  buildNetflowTroublemakersReport,
  parseNetflowV5,
  readUnsignedBE,
  parseIPv4,
  parseTemplateFlowSet,
  parseDataWithTemplate,
  parseNetflowV9,
  parseIPFIX,
  parseAnyNetflow,

  __test: {
    parseLinesFromBuffer,
    parseNetflowV5,
    parseNetflowV9,
  },
};
