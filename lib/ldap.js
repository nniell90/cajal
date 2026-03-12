'use strict';
const net = require('net');
const ldap = require('ldapjs');

/** Escape special characters for LDAP filter values (RFC 4515). */
function escapeLdapFilter(value) {
  return String(value).replace(/([\\*()\\x00])/g, (ch) => {
    return '\\' + ch.charCodeAt(0).toString(16).padStart(2, '0');
  });
}

/**
 * LDAP integration module for Cajal ICBM.
 *
 * Provides a multi-step test flow:
 *   1. TCP ping to domain controller
 *   2. LDAP bind with service account credentials
 *   3. Search for admin and monitor AD groups
 *   4. Enumerate members of those groups
 *
 * Returns a verbose step-by-step log for the frontend progress dialog.
 */

function tcpPing(host, port, timeoutMs = 5000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    const timer = setTimeout(() => {
      socket.destroy();
      resolve({ ok: false, ms: timeoutMs, error: `Connection timed out after ${timeoutMs}ms` });
    }, timeoutMs);
    const start = Date.now();
    socket.connect(port, host, () => {
      clearTimeout(timer);
      const ms = Date.now() - start;
      socket.destroy();
      resolve({ ok: true, ms, error: '' });
    });
    socket.on('error', (err) => {
      clearTimeout(timer);
      const ms = Date.now() - start;
      socket.destroy();
      resolve({ ok: false, ms, error: err?.message || String(err) });
    });
  });
}

function createLdapClient(serverUrl, port) {
  const url = serverUrl.includes('://') ? serverUrl : `ldap://${serverUrl}:${port}`;
  return ldap.createClient({
    url,
    connectTimeout: 10000,
    timeout: 15000
  });
}

function ldapErrorDetail(err) {
  if (!err) return 'Unknown error';
  const parts = [];
  if (err.name && err.name !== 'Error') parts.push(err.name);
  if (err.code !== undefined) parts.push(`code=${err.code}`);
  if (err.message) parts.push(err.message);
  return parts.length ? parts.join(' — ') : String(err);
}

function ldapBind(client, bindDn, bindPassword) {
  return new Promise((resolve, reject) => {
    client.bind(bindDn, bindPassword, (err) => {
      if (err) return reject(err);
      resolve();
    });
  });
}

/** Query the LDAP Root DSE to discover the default naming context (base DN). */
function discoverBaseDn(client) {
  return new Promise((resolve, reject) => {
    client.search('', {
      filter: '(objectClass=*)',
      scope: 'base',
      attributes: ['defaultNamingContext', 'namingContexts'],
      timeLimit: 10
    }, (err, res) => {
      if (err) return reject(err);
      let found = '';
      res.on('searchEntry', (entry) => {
        if (entry.pojo && entry.pojo.attributes) {
          for (const attr of entry.pojo.attributes) {
            if (attr.type === 'defaultNamingContext' && attr.values.length) {
              found = attr.values[0];
            } else if (!found && attr.type === 'namingContexts' && attr.values.length) {
              const ctx = Array.isArray(attr.values) ? attr.values : [attr.values];
              const domain = ctx.find((v) => /^DC=/i.test(v) && !/CN=Configuration|CN=Schema/i.test(v));
              if (domain) found = domain;
              else if (ctx.length) found = found || ctx[0];
            }
          }
        }
      });
      res.on('error', reject);
      res.on('end', () => {
        if (found) resolve(String(found).trim());
        else reject(new Error('Root DSE query returned no naming context — domain controller may not expose defaultNamingContext'));
      });
    });
  });
}

function ldapSearch(client, baseDn, filter, attributes = []) {
  return new Promise((resolve, reject) => {
    const opts = {
      filter,
      scope: 'sub',
      attributes,
      sizeLimit: 500,
      timeLimit: 15
    };
    client.search(baseDn, opts, (err, searchRes) => {
      if (err) return reject(err);
      const entries = [];
      searchRes.on('searchEntry', (entry) => {
        const obj = {};
        if (entry.pojo && entry.pojo.attributes) {
          for (const attr of entry.pojo.attributes) {
            obj[attr.type] = attr.values.length === 1 ? attr.values[0] : attr.values;
          }
        }
        obj.dn = entry.objectName || entry.dn?.toString() || '';
        entries.push(obj);
      });
      searchRes.on('error', (err2) => reject(err2));
      searchRes.on('end', () => resolve(entries));
    });
  });
}

function ldapUnbind(client) {
  return new Promise((resolve) => {
    try {
      client.unbind(() => resolve());
    } catch {
      resolve();
    }
  });
}

/**
 * Extract group members from AD group entries.
 * Handles both `member` attribute (list of DNs) and flat user search.
 */
async function resolveGroupMembers(client, baseDn, groupName) {
  // First, find the group
  const groupFilter = `(&(objectClass=group)(cn=${escapeLdapFilter(groupName)}))`;
  const groups = await ldapSearch(client, baseDn, groupFilter, ['cn', 'member', 'distinguishedName']);
  if (!groups.length) {
    // Try searching as an OU or posixGroup
    const posixFilter = `(&(objectClass=posixGroup)(cn=${escapeLdapFilter(groupName)}))`;
    const posixGroups = await ldapSearch(client, baseDn, posixFilter, ['cn', 'memberUid']);
    if (!posixGroups.length) return { found: false, members: [], groupDn: '' };
    const memberUids = Array.isArray(posixGroups[0].memberUid) ? posixGroups[0].memberUid : posixGroups[0].memberUid ? [posixGroups[0].memberUid] : [];
    const members = [];
    for (const uid of memberUids) {
      members.push({ dn: '', sAMAccountName: uid, displayName: uid, mail: '' });
    }
    return { found: true, members, groupDn: posixGroups[0].dn || '' };
  }

  const group = groups[0];
  const groupDn = group.dn || group.distinguishedName || '';
  const memberDns = Array.isArray(group.member) ? group.member : group.member ? [group.member] : [];

  // Also search via memberOf for AD environments
  const memberOfFilter = `(&(objectClass=user)(memberOf=${escapeLdapFilter(groupDn)}))`;
  let users = [];
  try {
    users = await ldapSearch(client, baseDn, memberOfFilter, ['sAMAccountName', 'userPrincipalName', 'displayName', 'mail', 'cn']);
  } catch {
    // memberOf search failed — fall back to member DN list
  }

  if (users.length) {
    return {
      found: true,
      groupDn,
      members: users.map((u) => ({
        dn: u.dn || '',
        sAMAccountName: u.sAMAccountName || u.cn || '',
        displayName: u.displayName || u.cn || u.sAMAccountName || '',
        mail: u.mail || u.userPrincipalName || ''
      }))
    };
  }

  // Fall back to DN list
  const members = memberDns.map((dn) => {
    const cnMatch = dn.match(/^CN=([^,]+)/i);
    return {
      dn,
      sAMAccountName: cnMatch ? cnMatch[1] : dn,
      displayName: cnMatch ? cnMatch[1] : dn,
      mail: ''
    };
  });

  return { found: true, groupDn, members };
}

/**
 * Run the full LDAP test flow. Returns a structured result with verbose steps.
 */
async function testLdapConnection({ serverUrl, port, baseDn, adminGroup, monitorGroup, bindDn, bindPassword }) {
  const steps = [];
  const addStep = (name, status, detail = '') => {
    steps.push({ name, status, detail, timestamp: new Date().toISOString() });
  };

  // Determine host for TCP ping
  let host = serverUrl;
  try {
    const urlObj = new URL(serverUrl.includes('://') ? serverUrl : `ldap://${serverUrl}`);
    host = urlObj.hostname;
  } catch {
    // use raw value
  }

  // Step 1: TCP Ping
  const resolvedPort = Number(port) || 389;
  const ldapUrl = serverUrl.includes('://') ? serverUrl : `ldap://${serverUrl}:${resolvedPort}`;
  addStep('TCP Ping', 'running', `Connecting to ${host}:${resolvedPort} (${ldapUrl})...`);
  const pingResult = await tcpPing(host, resolvedPort, 5000);
  if (pingResult.ok) {
    steps[steps.length - 1].status = 'ok';
    steps[steps.length - 1].detail = `TCP connected to ${host}:${resolvedPort} in ${pingResult.ms}ms`;
  } else {
    steps[steps.length - 1].status = 'fail';
    steps[steps.length - 1].detail = `TCP connect failed to ${host}:${resolvedPort} — ${pingResult.error}. Check that the DC is reachable and port ${resolvedPort} is open.`;
    return { ok: false, steps, users: [] };
  }

  // Step 2: LDAP Bind
  addStep('LDAP Bind', 'running', `Authenticating as "${bindDn}" on ${ldapUrl}...`);
  let client;
  try {
    client = createLdapClient(serverUrl, resolvedPort);
    await ldapBind(client, bindDn, bindPassword);
    steps[steps.length - 1].status = 'ok';
    const bindHint = bindDn.includes('@') ? ' (UPN)' : bindDn.includes('\\') ? ' (down-level)' : bindDn.includes('=') ? ' (DN)' : '';
    steps[steps.length - 1].detail = `Bind succeeded as "${bindDn}"${bindHint}`;
  } catch (err) {
    steps[steps.length - 1].status = 'fail';
    const hint = err?.code === 49 ? ' (code 49 = invalid credentials — check bindDn and password)'
      : err?.code === 32 ? ' (code 32 = no such object — check bindDn format)'
      : err?.code === 34 ? ' (code 34 = invalid DN syntax — check bindDn format)'
      : '';
    steps[steps.length - 1].detail = `Bind failed: ${ldapErrorDetail(err)}${hint}`;
    if (client) await ldapUnbind(client).catch(() => {});
    return { ok: false, steps, users: [] };
  }

  // Step 2b: Auto-discover base DN if not provided
  let resolvedBaseDn = String(baseDn || '').trim();
  if (!resolvedBaseDn) {
    addStep('Discover Base DN', 'running', 'Querying Root DSE for defaultNamingContext...');
    try {
      resolvedBaseDn = await discoverBaseDn(client);
      steps[steps.length - 1].status = 'ok';
      steps[steps.length - 1].detail = `Base DN discovered: ${resolvedBaseDn}`;
    } catch (err) {
      steps[steps.length - 1].status = 'fail';
      steps[steps.length - 1].detail = `Base DN discovery failed: ${ldapErrorDetail(err)}. You can enter it manually in the Base DN field.`;
      await ldapUnbind(client).catch(() => {});
      return { ok: false, steps, users: [] };
    }
  }

  // Step 3: Search admin group
  const allUsers = [];
  if (adminGroup) {
    addStep('Read Admin Group', 'running', `Searching for group "${adminGroup}" in ${resolvedBaseDn}...`);
    try {
      const result = await resolveGroupMembers(client, resolvedBaseDn, adminGroup);
      if (!result.found) {
        steps[steps.length - 1].status = 'warn';
        steps[steps.length - 1].detail = `Group "${adminGroup}" not found under "${resolvedBaseDn}". Searched as AD group (objectClass=group) and posixGroup. Check the group name is exact (case-sensitive in some directories).`;
      } else {
        steps[steps.length - 1].status = 'ok';
        steps[steps.length - 1].detail = `Found ${result.members.length} member(s) in "${adminGroup}" — DN: ${result.groupDn}`;
        for (const m of result.members) {
          allUsers.push({ ...m, role: 'admin', source: adminGroup });
        }
      }
    } catch (err) {
      steps[steps.length - 1].status = 'fail';
      steps[steps.length - 1].detail = `Admin group search failed: ${ldapErrorDetail(err)}`;
    }
  }

  // Step 4: Search monitor group
  if (monitorGroup) {
    addStep('Read Monitor Group', 'running', `Searching for group "${monitorGroup}" in ${resolvedBaseDn}...`);
    try {
      const result = await resolveGroupMembers(client, resolvedBaseDn, monitorGroup);
      if (!result.found) {
        steps[steps.length - 1].status = 'warn';
        steps[steps.length - 1].detail = `Group "${monitorGroup}" not found under "${resolvedBaseDn}". Searched as AD group and posixGroup. Check the group name is exact.`;
      } else {
        steps[steps.length - 1].status = 'ok';
        steps[steps.length - 1].detail = `Found ${result.members.length} member(s) in "${monitorGroup}" — DN: ${result.groupDn}`;
        for (const m of result.members) {
          // Skip if already in admin group (admin takes precedence)
          if (allUsers.some((u) => u.sAMAccountName === m.sAMAccountName)) continue;
          allUsers.push({ ...m, role: 'monitor', source: monitorGroup });
        }
      }
    } catch (err) {
      steps[steps.length - 1].status = 'fail';
      steps[steps.length - 1].detail = `Monitor group search failed: ${ldapErrorDetail(err)}`;
    }
  }

  // Cleanup
  await ldapUnbind(client).catch(() => {});

  // Summary step
  addStep('Summary', allUsers.length > 0 ? 'ok' : 'warn',
    allUsers.length > 0
      ? `${allUsers.length} user(s) ready to import`
      : 'No users found in the specified groups');

  return { ok: true, steps, users: allUsers, discoveredBaseDn: resolvedBaseDn };
}

module.exports = {
  tcpPing,
  testLdapConnection,
};
