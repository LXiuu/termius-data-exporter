#!/usr/bin/env node
/**
 * Termius 主机数据导出工具
 *
 * 功能：从本地 Termius 数据库提取并解密所有数据
 * 输出：termius_import.csv
 *
 * 依赖：npm install libsodium-wrappers keytar snappyjs
 */

const sodium = require('libsodium-wrappers');
const keytar = require('keytar');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const snappy = require('snappyjs');
const v8 = require('v8');

const BOM = '\ufeff';
function getDatabasePath(platform = process.platform, env = process.env, home = os.homedir()) {
  let appData;
  switch (platform) {
    case 'win32':
      appData = env.APPDATA || path.join(home, 'AppData', 'Roaming');
      break;
    case 'darwin':
      appData = path.join(home, 'Library', 'Application Support');
      break;
    case 'linux':
      appData = env.XDG_CONFIG_HOME || path.join(home, '.config');
      break;
    default:
      throw new Error(`不支持的操作系统: ${platform}`);
  }
  return path.join(appData, 'Termius', 'IndexedDB', 'file__0.indexeddb.leveldb');
}

const DB_PATH = getDatabasePath();
const OUTPUT_DIR = __dirname;
const OUTPUT_FILES = Object.freeze({
  hostsCsv: 'termius_import.csv',
  schemaReport: 'schema-report.json',
  identityReport: 'identity-report.json',
  fieldReport: 'field-report.json',
  blankReport: 'blank-report.json'
});
const IMPORT_CSV_HEADERS = ['Groups', 'Label', 'Tags', 'Hostname/IP', 'Protocol', 'Port', 'Username', 'Password'];
const REPORT_FLAGS = Object.freeze({
  schema: '--schema-report',
  field: '--field-report',
  identity: '--identity-report',
  blank: '--blank-report'
});
const EXPORT_SOURCE_LABELS = Object.freeze({
  hostDefinitions: '当前主机定义',
  fieldHostDefinitions: '字段级主机重建',
  connectionHistory: '连接历史兜底'
});
const PASSWORD_SOURCE_LABELS = Object.freeze({
  direct: '连接记录密码',
  nested: '嵌套凭据密码',
  referenced: '引用身份密码',
  label: '标签匹配密码',
  usernameFallback: '用户名兜底匹配',
  hostDirect: '主机记录密码',
  hostSshConfigIdentity: 'SSH 配置关联身份',
  missing: '缺少可用密码',
  missingIdentityPassword: '身份缺少密码',
  missingIdentity: '未找到关联身份',
  missingFieldCredential: '字段级记录缺少凭据',
  missingSshConfig: '未找到 SSH 配置',
  ambiguousUsername: '用户名匹配不唯一',
  ambiguousHostIdentity: '主机身份不唯一'
});

const RECORD_ID_FIELDS = [
  'id',
  '_id',
  'uuid',
  'uid',
  'identifier',
  'local_id',
  'localId',
  '__termius_id',
  '__termius_local_id'
];
const DIRECT_REFERENCE_ID_FIELDS = [
  'identity_id',
  'identityId',
  'credential_id',
  'credentialId',
  'credentials_id',
  'credentialsId',
  'account_id',
  'accountId',
  'auth_id',
  'authId',
  'authentication_id',
  'authenticationId',
  'login_id',
  'loginId',
  'password_id',
  'passwordId',
  'visible_identity_id',
  'visibleIdentityId',
  '__termius_visible_identity_id'
];
const REFERENCE_ID_FIELDS = [
  ...DIRECT_REFERENCE_ID_FIELDS
];
const IDENTITY_ID_FIELDS = [...RECORD_ID_FIELDS, ...REFERENCE_ID_FIELDS];
const KEY_ID_FIELDS = ['key_id', 'keyId', 'private_key_id', 'privateKeyId'];
const ID_FIELDS = [...IDENTITY_ID_FIELDS, ...KEY_ID_FIELDS];
const LABEL_FIELDS = ['label', 'title', 'name', 'nickname'];
const HOST_FIELDS = ['host', 'hostname', 'hostname_ip', 'address', 'ip'];
const USERNAME_FIELDS = ['user_name', 'username', 'login', 'user'];
const PASSWORD_FIELDS = ['password', 'pass', 'ssh_password', 'sshPassword'];
const IDENTITY_FIELD_PARTS = new Set(['label', 'username', 'user_name', 'password']);
const FIELD_LEVEL_RECORD_PARTS = new Set([
  ...IDENTITY_FIELD_PARTS,
  'address',
  'hostname',
  'host',
  'hostname_ip',
  'ip',
  'title',
  'port',
  'ssh_port',
  'connection_type',
  'protocol'
]);
const PORT_FIELDS = ['port', 'ssh_port'];
const PROTOCOL_FIELDS = ['connection_type', 'protocol', 'type'];
const SSH_CONFIG_FIELDS = [
  'env_variables',
  'envVariables',
  'charset',
  'agent_forwarding',
  'agentForwarding',
  'proxycommand',
  'startup_snippet',
  'startupSnippet',
  ...PORT_FIELDS
];
const NESTED_CREDENTIAL_FIELDS = [
  'identity',
  'credential',
  'credentials',
  'auth',
  'authentication',
  'account',
  'login_credentials',
  'loginCredentials',
  'ssh',
  'ssh_config',
  'sshConfig'
];
const CREDENTIAL_LABEL_FIELDS = [
  'identity',
  'credential',
  'credentials',
  'account',
  'identity_label',
  'identityLabel',
  'credential_label',
  'credentialLabel',
  'account_label',
  'accountLabel'
];
const PRIVATE_KEY_FIELDS = [
  'private_key',
  'privateKey',
  'private',
  'key',
  'key_body',
  'keyBody',
  'pem',
  'identity'
];
const PASSPHRASE_FIELDS = [
  'passphrase',
  'key_passphrase',
  'keyPassphrase',
  'private_key_passphrase',
  'privateKeyPassphrase'
];
const SECRET_FIELD_RE = /password|passphrase|private.?key|secret|token|credential/i;
const PRIVATE_KEY_RE = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/;
const PUBLIC_HOST_KEY_RE = /^(ssh-(rsa|ed25519)|ecdsa-sha2-[^\s]+)\s+/;
const ENCRYPTED_BLOCK_RE = /BA[A-Za-z0-9+/=]{30,}/g;
const CONTEXT_RADIUS = 900;
const NEARBY_ID_RADIUS = 360;
const FIELD_LEVEL_PAIR_DISTANCE = 8;

function resultText(result) {
  return typeof result === 'string' ? result : (result && result.text) || '';
}

function resultMeta(result) {
  return typeof result === 'string' ? {} : (result && result.meta) || {};
}

function hasPlainObjectRecord(text) {
  const raw = valueToString(text).trim();
  return raw.startsWith('{') || raw.startsWith('[');
}

function valueToString(value) {
  if (value === undefined || value === null) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) {
    return value.map(valueToString).filter(Boolean).join(',');
  }
  if (typeof value === 'object') {
    return firstString(value, [...LABEL_FIELDS, 'value', ...ID_FIELDS]);
  }
  return '';
}

function firstValue(obj, fields) {
  if (!obj || typeof obj !== 'object') return undefined;
  for (const field of fields) {
    if (Object.prototype.hasOwnProperty.call(obj, field)) {
      const value = obj[field];
      if (value !== undefined && value !== null && valueToString(value) !== '') {
        return value;
      }
    }
  }
  return undefined;
}

function firstString(obj, fields) {
  return valueToString(firstValue(obj, fields)).trim();
}

function readVarint(buf, pos) {
  let result = 0;
  let shift = 0;

  for (let i = pos; i < Math.min(buf.length, pos + 10); i++) {
    const byte = buf[i];
    result += (byte & 0x7f) * Math.pow(2, shift);
    if ((byte & 0x80) === 0) {
      return { value: result, end: i + 1 };
    }
    shift += 7;
  }

  return null;
}

function decodeZigZag(value) {
  return value % 2 === 0 ? value / 2 : -((value + 1) / 2);
}

function extractSerializedFieldIntegers(buffer, fieldName) {
  const name = Buffer.from(fieldName);
  const values = [];

  for (let i = 0; i < buffer.length - name.length - 4; i++) {
    if (buffer[i] !== 0x22 || buffer[i + 1] !== name.length) continue;
    if (!buffer.subarray(i + 2, i + 2 + name.length).equals(name)) continue;

    const valuePos = i + 2 + name.length;
    if (buffer[valuePos] !== 0x49) continue;

    const parsed = readVarint(buffer, valuePos + 1);
    if (parsed) {
      values.push({ pos: i, value: String(decodeZigZag(parsed.value)) });
    }
  }

  return values;
}

function extractSerializedFieldIntegersInRange(buffer, fieldName, start, end) {
  return extractSerializedFieldIntegers(buffer, fieldName)
    .filter(entry => entry.pos >= start && entry.pos < end);
}

function nearestSerializedFieldName(buffer, encryptedStart) {
  const fields = [];
  const start = Math.max(0, encryptedStart - 80);

  for (let i = start; i < encryptedStart - 2; i++) {
    if (buffer[i] !== 0x22) continue;

    const length = buffer[i + 1];
    if (length < 1 || length > 40 || i + 2 + length > buffer.length) continue;

    const name = buffer.subarray(i + 2, i + 2 + length).toString('utf8');
    if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
      fields.push({ name, pos: i });
    }
  }

  return fields.at(-1)?.name || '';
}

function distanceFromEncrypted(pos, encryptedStart, encryptedEnd) {
  if (pos < encryptedStart) return encryptedStart - pos;
  if (pos >= encryptedEnd) return pos - encryptedEnd;
  return 0;
}

function sideFromEncrypted(pos, encryptedStart, encryptedEnd) {
  if (pos < encryptedStart) return 'before';
  if (pos >= encryptedEnd) return 'after';
  return 'inside';
}

function nearestSerializedFieldInteger(buffer, encryptedStart, encryptedEnd, fieldName, maxDistance = NEARBY_ID_RADIUS) {
  return extractSerializedFieldIntegers(buffer, fieldName)
    .filter(entry => {
      const side = sideFromEncrypted(entry.pos, encryptedStart, encryptedEnd);
      return side !== 'inside' && distanceFromEncrypted(entry.pos, encryptedStart, encryptedEnd) <= maxDistance;
    })
    .map(entry => ({
      ...entry,
      side: sideFromEncrypted(entry.pos, encryptedStart, encryptedEnd),
      distance: distanceFromEncrypted(entry.pos, encryptedStart, encryptedEnd)
    }))
    .sort((a, b) => a.distance - b.distance || (a.side === 'before' ? -1 : 1))
    .at(0)?.value || '';
}

function dedupeNearbyIdEntries(entries) {
  const bestByValue = new Map();

  entries.forEach(entry => {
    const current = bestByValue.get(entry.value);
    if (!current || entry.distance < current.distance) {
      bestByValue.set(entry.value, entry);
    }
  });

  return [...bestByValue.values()]
    .sort((a, b) => a.distance - b.distance || a.value.localeCompare(b.value))
    .slice(0, 80);
}

function readUnsignedVarintsAround(buffer, encryptedStart, encryptedEnd, maxDistance = NEARBY_ID_RADIUS) {
  const values = [];
  const start = Math.max(0, encryptedStart - maxDistance);
  const end = Math.min(buffer.length, encryptedEnd + maxDistance);

  for (let i = start; i < end; i++) {
    if (i >= encryptedStart && i < encryptedEnd) {
      i = encryptedEnd - 1;
      continue;
    }

    const parsed = readVarint(buffer, i);
    if (!parsed || parsed.end <= i) continue;
    if (i < encryptedStart && parsed.end > encryptedStart) continue;
    if (i >= encryptedEnd && parsed.end > end) continue;

    const value = decodeZigZag(parsed.value);
    if (Number.isSafeInteger(value) && value > 1000 && value < 1_000_000_000_000) {
      const side = sideFromEncrypted(i, encryptedStart, encryptedEnd);
      values.push({
        pos: i,
        value: String(value),
        distance: distanceFromEncrypted(i, encryptedStart, encryptedEnd),
        side
      });
    }
  }

  return dedupeNearbyIdEntries(values);
}

function extractSerializedObjectRefs(buffer, encryptedStart, encryptedEnd, objectName) {
  const marker = Buffer.from(objectName);
  const refs = [];
  let pos = -1;

  while ((pos = buffer.indexOf(marker, pos + 1)) !== -1) {
    if (pos >= encryptedStart && pos < encryptedEnd) continue;
    if (buffer[pos + marker.length] !== 0x6f) continue;

    const objectStart = pos + marker.length + 1;
    const objectEnd = Math.min(buffer.length, objectStart + 120);
    const ids = extractSerializedFieldIntegersInRange(buffer, 'id', objectStart, objectEnd).map(entry => entry.value);
    const localIds = extractSerializedFieldIntegersInRange(buffer, 'local_id', objectStart, objectEnd).map(entry => entry.value);

    refs.push({
      pos,
      ids,
      localIds,
      distance: distanceFromEncrypted(pos, encryptedStart, encryptedEnd),
      side: sideFromEncrypted(pos, encryptedStart, encryptedEnd)
    });
  }

  return refs.sort((a, b) => a.distance - b.distance);
}

function buildEncryptedBlockMeta(buffer, encryptedStart, encryptedEnd) {
  const contextStart = Math.max(0, encryptedStart - CONTEXT_RADIUS);
  const contextEnd = Math.min(buffer.length, encryptedEnd + CONTEXT_RADIUS);
  const context = buffer.subarray(contextStart, contextEnd);
  const relativeStart = encryptedStart - contextStart;
  const relativeEnd = encryptedEnd - contextStart;

  const identityRefs = extractSerializedObjectRefs(context, relativeStart, relativeEnd, 'identity');
  const sshConfigRefs = extractSerializedObjectRefs(context, relativeStart, relativeEnd, 'ssh_config');
  const nearbyIdEntries = readUnsignedVarintsAround(context, relativeStart, relativeEnd);

  return {
    encryptedField: nearestSerializedFieldName(context, relativeStart),
    id: nearestSerializedFieldInteger(context, relativeStart, relativeEnd, 'id'),
    local_id: nearestSerializedFieldInteger(context, relativeStart, relativeEnd, 'local_id'),
    host_id: nearestSerializedFieldInteger(context, relativeStart, relativeEnd, 'host_id'),
    visible_identity_id: nearestSerializedFieldInteger(context, relativeStart, relativeEnd, 'visible_identity_id'),
    identity_object_ids: identityRefs.flatMap(ref => ref.ids),
    identity_object_local_ids: identityRefs.flatMap(ref => ref.localIds),
    identity_object_refs: identityRefs.map(ref => ({
      ids: ref.ids,
      localIds: ref.localIds,
      distance: ref.distance,
      side: ref.side
    })),
    ssh_config_object_ids: sshConfigRefs.flatMap(ref => ref.ids),
    ssh_config_object_local_ids: sshConfigRefs.flatMap(ref => ref.localIds),
    ssh_config_object_refs: sshConfigRefs.map(ref => ({
      ids: ref.ids,
      localIds: ref.localIds,
      distance: ref.distance,
      side: ref.side
    })),
    nearby_ids: nearbyIdEntries.map(entry => entry.value),
    nearby_id_entries: nearbyIdEntries.map(entry => ({
      value: entry.value,
      distance: entry.distance,
      side: entry.side
    }))
  };
}

function applyMetadataIds(obj, meta) {
  if (!obj || typeof obj !== 'object' || !meta) return obj;

  if (meta.id) {
    obj.__termius_id = meta.id;
  }

  if (meta.local_id) {
    obj.__termius_local_id = meta.local_id;
  }

  if (meta.host_id) {
    obj.__termius_host_id = meta.host_id;
  }

  if (meta.visible_identity_id) {
    obj.__termius_visible_identity_id = meta.visible_identity_id;
  }

  if (Array.isArray(meta.identity_object_ids) && meta.identity_object_ids.length) {
    obj.__termius_identity_object_id = meta.identity_object_ids.at(-1);
    obj.__termius_identity_object_ids = meta.identity_object_ids;
  }

  if (Array.isArray(meta.identity_object_local_ids) && meta.identity_object_local_ids.length) {
    obj.__termius_identity_object_local_id = meta.identity_object_local_ids.at(-1);
    obj.__termius_identity_object_local_ids = meta.identity_object_local_ids;
  }

  if (Array.isArray(meta.identity_object_refs) && meta.identity_object_refs.length) {
    obj.__termius_identity_object_refs = meta.identity_object_refs;
  }

  if (Array.isArray(meta.ssh_config_object_ids) && meta.ssh_config_object_ids.length) {
    obj.__termius_ssh_config_object_id = meta.ssh_config_object_ids.at(-1);
    obj.__termius_ssh_config_object_ids = meta.ssh_config_object_ids;
  }

  if (Array.isArray(meta.ssh_config_object_local_ids) && meta.ssh_config_object_local_ids.length) {
    obj.__termius_ssh_config_object_local_id = meta.ssh_config_object_local_ids.at(-1);
    obj.__termius_ssh_config_object_local_ids = meta.ssh_config_object_local_ids;
  }

  if (Array.isArray(meta.ssh_config_object_refs) && meta.ssh_config_object_refs.length) {
    obj.__termius_ssh_config_object_refs = meta.ssh_config_object_refs;
  }

  if (Array.isArray(meta.nearby_ids) && meta.nearby_ids.length) {
    obj.__termius_nearby_ids = meta.nearby_ids;
  }

  if (Array.isArray(meta.nearby_id_entries) && meta.nearby_id_entries.length) {
    obj.__termius_nearby_id_entries = meta.nearby_id_entries;
  }

  if (meta.encryptedField) {
    obj.__termius_encrypted_field = meta.encryptedField;
  }

  return obj;
}

function collectReferenceProfiles(connections) {
  const profiles = new Map();

  connections.forEach(conn => {
    const username = firstString(conn, USERNAME_FIELDS);
    const host = firstString(conn, HOST_FIELDS);

    collectReferenceEntries(conn).forEach(({ id, source }) => {
      if (!profiles.has(id)) {
        profiles.set(id, {
          id,
          count: 0,
          users: new Set(),
          hosts: new Set(),
          sources: new Map(),
          usersBySource: new Map()
        });
      }

      const profile = profiles.get(id);
      profile.count++;
      if (username) profile.users.add(username);
      if (host) profile.hosts.add(host);
      profile.sources.set(source, (profile.sources.get(source) || 0) + 1);
      if (username) {
        if (!profile.usersBySource.has(source)) profile.usersBySource.set(source, new Set());
        profile.usersBySource.get(source).add(username);
      }
    });
  });

  return profiles;
}

function addIdentityReferenceProfile(profiles, id, username, host, source) {
  if (!id) return;
  if (!profiles.has(id)) {
    profiles.set(id, {
      id,
      count: 0,
      users: new Set(),
      hosts: new Set(),
      sources: new Map(),
      usersBySource: new Map()
    });
  }

  const profile = profiles.get(id);
  profile.count++;
  if (username) profile.users.add(username);
  if (host) profile.hosts.add(host);
  profile.sources.set(source, (profile.sources.get(source) || 0) + 1);
  if (username) {
    if (!profile.usersBySource.has(source)) profile.usersBySource.set(source, new Set());
    profile.usersBySource.get(source).add(username);
  }
}

function selectedHostDefinitions(data) {
  const structured = data.hostDefinitions.filter(hostDefinition => !hostDefinition.__termius_field_host_definition);
  if (structured.length) {
    return { hostDefinitions: structured, source: 'hostDefinitions' };
  }

  const fieldLevel = data.hostDefinitions.filter(hostDefinition => hostDefinition.__termius_field_host_definition);
  if (fieldLevel.length) {
    return { hostDefinitions: fieldLevel, source: 'fieldHostDefinitions' };
  }

  return { hostDefinitions: [], source: '' };
}

function collectHostDefinitionIdentityProfiles(data) {
  const profiles = new Map();
  selectedHostDefinitions(data).hostDefinitions
    .forEach(hostDefinition => {
      const host = firstString(hostDefinition, ['address', 'hostname', ...HOST_FIELDS]);
      const { identityIds } = identitiesForHostDefinition(data, hostDefinition);
      identityIds.forEach(id => {
        const identity = identityForExactId(data, id);
        addIdentityReferenceProfile(
          profiles,
          id,
          identity ? firstString(identity, USERNAME_FIELDS) : '',
          host,
          'hostSshConfigIdentity'
        );
      });
    });

  return profiles;
}

function usernameMatchesProfile(identity, profile, preferredSource = '') {
  const username = firstString(identity, USERNAME_FIELDS);
  const sourceUsers = preferredSource && profile.usersBySource
    ? profile.usersBySource.get(preferredSource)
    : null;
  const users = sourceUsers && sourceUsers.size ? sourceUsers : profile.users;
  return !username || !users.size || users.has(username);
}

function addFieldIdentityCandidate(data, identity) {
  if (!isIdentityRecord(identity)) return;

  data.identities.push(identity);
  addToListMap(data.identitiesByUser, firstString(identity, USERNAME_FIELDS), identity);
  addToListMap(data.identitiesByLabel, firstString(identity, LABEL_FIELDS), identity);

  collectRecordIds(identity).forEach(id => {
    if (!data.identitiesById.has(id) || extractPasswordFromObject(identity, { nested: true })) {
      data.identitiesById.set(id, identity);
    }
  });
}

function collectFieldPartKeys(part) {
  const meta = part.meta || {};
  const keys = [];
  if (meta.id) keys.push({ type: 'id', value: meta.id, key: `id:${meta.id}` });
  if (meta.local_id) keys.push({ type: 'local_id', value: meta.local_id, key: `local:${meta.local_id}` });
  if (!keys.length) {
    const source = part.file && part.sequence !== undefined
      ? `${part.file}:${part.sequence}`
      : `idx:${part.recordIndex ?? ''}`;
    keys.push({ type: 'source', value: source, key: `source:${source}` });
  }
  return keys;
}

function applyFieldPartKey(record, key) {
  if (key.type === 'id' && !record.__termius_id) {
    record.__termius_id = key.value;
  }

  if (key.type === 'local_id' && !record.__termius_local_id) {
    record.__termius_local_id = key.value;
  }
}

function identityFromFieldRecord(record) {
  const identity = {
    __termius_field_identity: true
  };

  if (record.__termius_id) identity.__termius_id = record.__termius_id;
  if (record.__termius_local_id) identity.__termius_local_id = record.__termius_local_id;
  if (Array.isArray(record.__termius_nearby_id_entries)) {
    identity.__termius_nearby_id_entries = record.__termius_nearby_id_entries;
    identity.__termius_nearby_ids = record.__termius_nearby_ids;
  }

  const label = firstString(record, ['label', 'title']);
  const username = firstString(record, USERNAME_FIELDS);
  const password = firstPasswordString(record);

  if (label) identity.label = label;
  if (username) identity.username = username;
  if (password) identity.password = password;

  return identity;
}

function findFieldRecordConnection(data, host, username, label) {
  const candidates = data.connections.filter(conn => firstString(conn, HOST_FIELDS) === host);
  if (!candidates.length) return null;

  return candidates
    .map(conn => {
      let score = 0;
      if (username && firstString(conn, USERNAME_FIELDS) === username) score += 4;
      if (label && (firstString(conn, LABEL_FIELDS) || firstString(conn, HOST_FIELDS)) === label) score += 2;
      if (!firstString(conn, ['error_message', 'errorMessage'])) score += 1;
      return { conn, score };
    })
    .sort((a, b) => b.score - a.score)
    .at(0)?.conn || candidates[0];
}

function isFieldHostRecord(record) {
  return Boolean(firstString(record, ['address', 'hostname', ...HOST_FIELDS]));
}

function isFieldCredentialRecord(record) {
  return Boolean(firstPasswordString(record) || firstString(record, USERNAME_FIELDS));
}

function orderedFieldRecords(records) {
  return records
    .slice()
    .sort((a, b) => (a.__termius_field_order ?? 0) - (b.__termius_field_order ?? 0));
}

function nearestUnpairedHost(hosts, credential, direction) {
  const credentialOrder = credential.__termius_field_order ?? 0;
  const candidates = hosts
    .filter(host => !firstPasswordString(host))
    .filter(host => {
      const hostOrder = host.__termius_field_order ?? 0;
      return direction === 'before'
        ? hostOrder < credentialOrder
        : hostOrder > credentialOrder;
    })
    .map(host => ({
      host,
      distance: Math.abs((host.__termius_field_order ?? 0) - credentialOrder)
    }))
    .filter(item => item.distance <= FIELD_LEVEL_PAIR_DISTANCE)
    .sort((a, b) => a.distance - b.distance);

  return candidates[0]?.host || null;
}

function pairFieldLevelHostCredentials(records) {
  const ordered = orderedFieldRecords(records);
  const hosts = ordered.filter(isFieldHostRecord);
  const credentials = ordered.filter(record => isFieldCredentialRecord(record) && !isFieldHostRecord(record));

  credentials.forEach(credential => {
    const host = nearestUnpairedHost(hosts, credential, 'before') ||
      nearestUnpairedHost(hosts, credential, 'after');
    if (!host) return;

    const username = firstString(credential, USERNAME_FIELDS);
    const password = firstPasswordString(credential);

    if (username && !firstString(host, USERNAME_FIELDS)) {
      host.username = username;
    }

    if (password && !firstPasswordString(host)) {
      host.password = password;
      host.__termius_field_credential_order = credential.__termius_field_order;
    }
  });
}

function addFieldHostDefinitionCandidate(data, record) {
  const host = firstString(record, ['address', 'hostname', ...HOST_FIELDS]);
  if (!host) return;

  const recordUsername = firstString(record, USERNAME_FIELDS);
  const recordLabel = firstString(record, ['label', 'title']);
  const connection = findFieldRecordConnection(data, host, recordUsername, recordLabel);
  const username = recordUsername || firstString(connection, USERNAME_FIELDS);
  const label = recordLabel || firstString(connection, LABEL_FIELDS) || host;
  const protocol = normalizeProtocol(firstString(record, PROTOCOL_FIELDS) || firstString(connection, PROTOCOL_FIELDS));
  const port = firstString(record, PORT_FIELDS) || firstString(connection, PORT_FIELDS) || (protocol === 'ssh' ? '22' : '');
  const password = firstPasswordString(record);

  if (!label && !username && !password) return;

  data.hostDefinitions.push({
    ...record,
    address: host,
    label,
    username,
    password,
    protocol,
    port,
    tags: firstValue(record, ['tags']) ?? firstValue(connection, ['tags']),
    __termius_field_host_definition: true
  });
}

function attachFieldLevelIdentities(data, fieldParts) {
  const byId = new Map();

  fieldParts.forEach(part => {
    collectFieldPartKeys(part).forEach(key => {
      if (!byId.has(key.key)) {
        byId.set(key.key, {
          __termius_nearby_id_entries: [],
          __termius_field_identity: true,
          __termius_field_order: part.recordIndex
        });
      }

      const record = byId.get(key.key);
      applyFieldPartKey(record, key);
      record.__termius_field_order = Math.min(record.__termius_field_order ?? part.recordIndex, part.recordIndex);
      if (!record[part.field]) {
        record[part.field] = part.value;
      }

      if (Array.isArray(part.meta.nearby_id_entries)) {
        record.__termius_nearby_id_entries.push(...part.meta.nearby_id_entries);
      }
    });
  });

  const records = [...byId.values()];
  records.forEach(record => {
    if (Array.isArray(record.__termius_nearby_id_entries)) {
      record.__termius_nearby_id_entries = dedupeNearbyIdEntries(record.__termius_nearby_id_entries);
      record.__termius_nearby_ids = record.__termius_nearby_id_entries.map(entry => entry.value);
    }
  });

  pairFieldLevelHostCredentials(records);

  records.forEach(record => {
    const identity = identityFromFieldRecord(record);
    addFieldIdentityCandidate(data, identity);
    addFieldHostDefinitionCandidate(data, record);
  });
}

function recordPrimaryIds(obj) {
  return [
    ...new Set(
      ['id', '_id', 'uuid', 'uid', 'identifier', 'localId', '__termius_id']
        .map(field => firstString(obj, [field]))
        .filter(Boolean)
    )
  ];
}

function recordPrimaryLocalIds(obj) {
  return [
    ...new Set(
      ['local_id', '__termius_local_id']
        .map(field => firstString(obj, [field]))
        .filter(Boolean)
    )
  ];
}

function attachPasswordFragmentsById(data, fieldParts) {
  data.passwordsById = data.passwordsById || new Map();

  fieldParts.forEach(part => {
    if (part.field !== 'password' || !part.meta?.id) return;
    const password = passwordValueToString(part.value);
    if (!password) return;

    if (!data.passwordsById.has(part.meta.id)) data.passwordsById.set(part.meta.id, new Set());
    data.passwordsById.get(part.meta.id).add(password);
  });
}

function identityForExactId(data, id, username = '') {
  const identity = data.identitiesById.get(valueToString(id).trim());
  if (!identity) return null;
  if (username && !usernameMatchesProfile(identity, { users: new Set([username]) })) {
    return null;
  }
  return identity;
}

function trustedPasswordsForIdentityId(data, id, username) {
  const exactIdentity = identityForExactId(data, id, username);
  if (exactIdentity) {
    const password = extractPasswordFromObject(exactIdentity, { nested: true });
    return password ? [password] : [];
  }

  if (username) {
    return [];
  }

  return [...(data.passwordsById?.get(valueToString(id).trim()) || [])].filter(Boolean);
}

function uniquePasswordFromIdentityIds(data, identityIds, username) {
  const passwords = [
    ...new Set(
      identityIds
        .flatMap(id => trustedPasswordsForIdentityId(data, id, username))
        .filter(Boolean)
    )
  ];

  if (passwords.length === 1) return { password: passwords[0], ambiguous: false };
  if (passwords.length > 1) return { password: '', ambiguous: true };
  return { password: '', ambiguous: false };
}

function isSshConfigRecord(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return false;
  if (isConnectionRecord(obj) || isKnownHostKeyRecord(obj) || isIdentityRecord(obj)) return false;

  return SSH_CONFIG_FIELDS.some(field => Object.prototype.hasOwnProperty.call(obj, field)) ||
    (Array.isArray(obj.__termius_identity_object_refs) && obj.__termius_identity_object_refs.length);
}

function isHostDefinitionRecord(obj) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return false;
  if (isConnectionRecord(obj) || isKnownHostKeyRecord(obj) || isIdentityRecord(obj)) return false;

  return Boolean(
    firstString(obj, ['address', 'hostname']) &&
    (
      firstString(obj, LABEL_FIELDS) ||
      Array.isArray(obj.__termius_ssh_config_object_refs)
    )
  );
}

function addSshConfigCandidate(data, obj) {
  if (!isSshConfigRecord(obj)) return;
  if (!data.sshConfigs.includes(obj)) data.sshConfigs.push(obj);
}

function addHostDefinitionCandidate(data, obj) {
  if (!isHostDefinitionRecord(obj)) return;
  if (!data.hostDefinitions.includes(obj)) data.hostDefinitions.push(obj);
}

function passwordValueToString(value, seen = new Set()) {
  if (value === undefined || value === null) return '';
  if (typeof value === 'string') return value.trim();
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) {
    return value.map(item => passwordValueToString(item, seen)).find(Boolean) || '';
  }
  if (typeof value !== 'object') return '';
  if (seen.has(value)) return '';
  seen.add(value);

  for (const field of ['value', 'secret', 'plaintext', 'plain_text', 'plainText', 'text']) {
    if (Object.prototype.hasOwnProperty.call(value, field)) {
      const password = passwordValueToString(value[field], seen);
      if (password) return password;
    }
  }

  return '';
}

function firstPasswordString(obj) {
  if (!obj || typeof obj !== 'object') return '';

  for (const field of PASSWORD_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(obj, field)) {
      const password = passwordValueToString(obj[field]);
      if (password) return password;
    }
  }

  return '';
}

function csvCell(value) {
  const text = valueToString(value);
  if (/[",\r\n]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}

function csvRow(values) {
  return values.map(csvCell).join(',');
}

function normalizePrivateKey(value) {
  return valueToString(value)
    .replace(/\\r\\n/g, '\n')
    .replace(/\\n/g, '\n')
    .replace(/\r\n/g, '\n')
    .trim();
}

function extractPrivateKey(value, seen = new Set()) {
  if (!value) return '';

  if (typeof value === 'string') {
    const key = normalizePrivateKey(value);
    const match = key.match(PRIVATE_KEY_RE);
    return match ? match[0] : '';
  }

  if (typeof value !== 'object') return '';
  if (seen.has(value)) return '';
  seen.add(value);

  if (Array.isArray(value)) {
    for (const item of value) {
      const key = extractPrivateKey(item, seen);
      if (key) return key;
    }
    return '';
  }

  for (const field of PRIVATE_KEY_FIELDS) {
    const key = extractPrivateKey(value[field], seen);
    if (key) return key;
  }

  for (const [field, nested] of Object.entries(value)) {
    if (/public_?key/i.test(field)) continue;
    const key = extractPrivateKey(nested, seen);
    if (key) return key;
  }

  return '';
}

function extractPassphrase(obj) {
  return firstString(obj, PASSPHRASE_FIELDS);
}

function isKnownHostKeyRecord(obj) {
  return Boolean(
    obj &&
    typeof obj === 'object' &&
    !Array.isArray(obj) &&
    typeof obj.key === 'string' &&
    PUBLIC_HOST_KEY_RE.test(obj.key.trim()) &&
    (obj.hostnames !== undefined || obj.hostname !== undefined)
  );
}

function addToListMap(map, key, value) {
  if (!key) return;
  if (!map.has(key)) map.set(key, []);
  map.get(key).push(value);
}

function collectIds(value, fields, ids = new Set()) {
  if (value === undefined || value === null) return ids;

  if (Array.isArray(value)) {
    value.forEach(item => collectIds(item, fields, ids));
    return ids;
  }

  if (typeof value === 'object') {
    fields.forEach(field => {
      if (!Object.prototype.hasOwnProperty.call(value, field)) return;
      const id = valueToString(value[field]).trim();
      if (id) ids.add(id);
    });
    return ids;
  }

  const id = valueToString(value).trim();
  if (id) ids.add(id);
  return ids;
}

function collectRecordIds(obj) {
  return [...collectIds(obj, RECORD_ID_FIELDS)];
}

function collectDirectRecordIds(obj) {
  return [...collectIds(obj, RECORD_ID_FIELDS)];
}

function extractPasswordFromObject(obj, { nested = false } = {}, seen = new Set(), depth = 2) {
  if (!obj || typeof obj !== 'object') return '';
  if (seen.has(obj)) return '';
  seen.add(obj);

  const direct = firstPasswordString(obj);
  if (direct) return direct;

  if (!nested || depth <= 0) return '';

  for (const field of NESTED_CREDENTIAL_FIELDS) {
    const value = obj[field];
    if (!value || typeof value !== 'object') continue;

    const candidates = Array.isArray(value) ? value : [value];
    for (const candidate of candidates) {
      const password = extractPasswordFromObject(candidate, { nested: true }, seen, depth - 1);
      if (password) return password;
    }
  }

  return '';
}

function extractNestedCredentialPassword(conn) {
  for (const field of NESTED_CREDENTIAL_FIELDS) {
    const value = conn[field];
    if (!value || typeof value !== 'object') continue;

    const candidates = Array.isArray(value) ? value : [value];
    for (const candidate of candidates) {
      const password = extractPasswordFromObject(candidate, { nested: true });
      if (password) return password;
    }
  }

  return '';
}

function collectReferenceIds(conn) {
  return [...new Set(collectReferenceEntries(conn).map(entry => entry.id))];
}

function collectReferenceEntries(conn) {
  const ids = new Set();
  const entries = [];
  const addEntries = (source, fields) => {
    const before = new Set(ids);
    fields.forEach(field => {
      collectIds(conn[field], IDENTITY_ID_FIELDS, ids);
    });
    [...ids]
      .filter(id => !before.has(id))
      .forEach(id => entries.push({ id, source }));
  };

  addEntries('direct', DIRECT_REFERENCE_ID_FIELDS);

  NESTED_CREDENTIAL_FIELDS.forEach(field => {
    const value = conn[field];
    if (value && typeof value === 'object') {
      const before = new Set(ids);
      collectIds(value, IDENTITY_ID_FIELDS, ids);
      [...ids]
        .filter(id => !before.has(id))
        .forEach(id => entries.push({ id, source: `nested:${field}` }));
    }
  });

  return entries;
}

function collectReferenceLabels(conn) {
  const labels = new Set();

  CREDENTIAL_LABEL_FIELDS.forEach(field => {
    const value = conn[field];
    if (value === undefined || value === null) return;

    if (Array.isArray(value)) {
      value.forEach(item => {
        const label = typeof item === 'object' ? firstString(item, LABEL_FIELDS) : valueToString(item).trim();
        if (label) labels.add(label);
      });
      return;
    }

    const label = typeof value === 'object' ? firstString(value, LABEL_FIELDS) : valueToString(value).trim();
    if (label) labels.add(label);
  });

  return [...labels];
}

function uniquePasswordFromIdentities(identities = []) {
  const passwords = [
    ...new Set(
      identities
        .map(identity => extractPasswordFromObject(identity, { nested: true }))
        .filter(Boolean)
    )
  ];

  if (passwords.length === 1) {
    return { password: passwords[0], ambiguous: false };
  }

  return { password: '', ambiguous: passwords.length > 1 };
}

function passwordFingerprint(password) {
  if (!password) return '';
  return `${password.length}:${crypto.createHash('sha256').update(password).digest('hex').slice(0, 12)}`;
}

function passwordCandidateSummary(passwords) {
  const unique = [...new Set(passwords.filter(Boolean))];
  return {
    count: unique.length,
    fingerprints: unique.map(passwordFingerprint)
  };
}

function identityPasswordCandidateSummary(identities = []) {
  return passwordCandidateSummary(
    identities.map(identity => extractPasswordFromObject(identity, { nested: true }))
  );
}

function resolveStrongPassword(conn, data) {
  const direct = firstPasswordString(conn);
  if (direct) return { password: direct, source: 'direct' };

  const nested = extractNestedCredentialPassword(conn);
  if (nested) return { password: nested, source: 'nested' };

  const referenced = uniquePasswordFromIdentityIds(data, collectReferenceIds(conn), firstString(conn, USERNAME_FIELDS));
  if (referenced.password) return { password: referenced.password, source: 'referenced' };

  for (const label of collectReferenceLabels(conn)) {
    if (!data.identitiesByLabel.has(label)) continue;

    const match = uniquePasswordFromIdentities(data.identitiesByLabel.get(label));
    if (match.password) return { password: match.password, source: 'label' };
  }

  return { password: '', source: 'missing' };
}

function resolveStrongPasswordCached(conn, data) {
  if (!data.__strongPasswordCache) data.__strongPasswordCache = new WeakMap();
  if (data.__strongPasswordCache.has(conn)) {
    return data.__strongPasswordCache.get(conn);
  }

  const resolved = resolveStrongPassword(conn, data);
  data.__strongPasswordCache.set(conn, resolved);
  return resolved;
}

function resolvePasswordCore(conn, data) {
  const strong = resolveStrongPasswordCached(conn, data);
  if (strong.password) return strong;

  const username = firstString(conn, USERNAME_FIELDS);
  if (username && data.identitiesByUser.has(username)) {
    const match = uniquePasswordFromIdentities(data.identitiesByUser.get(username));
    if (match.password) return { password: match.password, source: 'usernameFallback' };
    if (match.ambiguous) return { password: '', source: 'ambiguousUsername' };
  }

  return { password: '', source: 'missing' };
}

function resolvePassword(conn, data) {
  return resolvePasswordCore(conn, data);
}

function createPasswordStats() {
  return {};
}

function makeUniqueLabel(map, preferredLabel, fallbackPrefix) {
  const base = (preferredLabel || `${fallbackPrefix}_${map.size + 1}`).trim() || `${fallbackPrefix}_${map.size + 1}`;
  let label = base;
  let index = 2;
  while (map.has(label)) {
    label = `${base}_${index}`;
    index++;
  }
  return label;
}

function normalizeProtocol(value) {
  const protocol = valueToString(value).trim().toLowerCase();
  if (!protocol) return 'ssh';
  if (protocol.includes('ssh')) return 'ssh';
  if (protocol.includes('telnet')) return 'telnet';
  if (protocol.includes('mosh')) return 'mosh';
  return protocol;
}

function normalizeTags(value) {
  if (value === undefined || value === null) return '';
  if (Array.isArray(value)) {
    return [...new Set(value.map(item => valueToString(item).trim()).filter(Boolean))].join(',');
  }
  return valueToString(value).trim();
}

function resolveTags(conn) {
  return normalizeTags(firstValue(conn, ['tags', 'tag_names', 'tagNames', 'tag']));
}

function normalizeGroupValue(value) {
  if (value === undefined || value === null) return '';
  if (Array.isArray(value)) {
    return value.map(normalizeGroupValue).filter(Boolean).join('/');
  }
  if (typeof value === 'object') {
    return firstString(value, ['path', 'group_path', 'groupPath', ...LABEL_FIELDS]);
  }
  return valueToString(value).replace(/\\/g, '/').trim();
}

function buildGroupPath(groupId, groupsById) {
  const labels = [];
  const visited = new Set();
  let currentId = groupId;

  while (currentId && groupsById.has(currentId) && !visited.has(currentId)) {
    visited.add(currentId);
    const group = groupsById.get(currentId);
    const label = firstString(group, LABEL_FIELDS);
    if (label) labels.unshift(label);
    currentId = firstString(group, ['parent_id', 'parentId', 'folder_id', 'folderId']);
  }

  return labels.join('/');
}

function resolveGroupPath(conn, groupsById) {
  const direct = normalizeGroupValue(firstValue(conn, [
    'group_path',
    'groupPath',
    'groups',
    'group',
    'folder_path',
    'folderPath',
    'folder',
    'folder_name',
    'folderName',
    'group_name',
    'groupName'
  ]));
  if (direct) return direct;

  const groupId = firstString(conn, ['group_id', 'groupId', 'folder_id', 'folderId', 'parent_id', 'parentId']);
  return groupId ? buildGroupPath(groupId, groupsById) : '';
}

function isConnectionRecord(obj) {
  const host = firstString(obj, HOST_FIELDS);
  if (!host) return false;

  return Boolean(
    firstString(obj, USERNAME_FIELDS) ||
    firstString(obj, PROTOCOL_FIELDS) ||
    firstString(obj, PORT_FIELDS)
  );
}

function isIdentityRecord(obj) {
  if (isConnectionRecord(obj)) return false;

  return Boolean(
    firstString(obj, USERNAME_FIELDS) &&
    extractPasswordFromObject(obj, { nested: true }) &&
    !extractPrivateKey(obj)
  );
}

function isGroupRecord(obj) {
  if (isConnectionRecord(obj)) return false;
  const id = collectRecordIds(obj)[0];
  const label = firstString(obj, LABEL_FIELDS);
  if (!id || !label) return false;

  const type = firstString(obj, ['type', 'entity_type', 'entityType', 'record_type', 'recordType', 'kind', 'collection']);
  return /group|folder/i.test(type) || obj.parent_id !== undefined || obj.parentId !== undefined;
}

function addKey(keysByLabel, keyData, preferredLabel, source) {
  const privateKey = extractPrivateKey(keyData);
  if (!privateKey) return false;

  for (const existing of keysByLabel.values()) {
    if (existing.private_key === privateKey) return false;
  }

  const label = makeUniqueLabel(keysByLabel, preferredLabel, 'ssh_key');
  keysByLabel.set(label, {
    ...((keyData && typeof keyData === 'object' && !Array.isArray(keyData)) ? keyData : {}),
    label,
    source,
    private_key: privateKey
  });
  return true;
}

// ==================== 解密模块 ====================

async function getEncryptionKey() {
  const key = await keytar.getPassword('Termius', 'localKey');
  if (!key) throw new Error('未找到 Termius 加密密钥，请确保已登录 Termius');
  return Buffer.from(key, 'base64');
}

async function decrypt(base64Data, key) {
  const data = Buffer.from(base64Data, 'base64');
  if (data[0] !== 4) return null;

  const nonce = data.slice(2, 26);
  const ciphertext = data.slice(26);

  try {
    const decrypted = sodium.crypto_secretbox_open_easy(
      new Uint8Array(ciphertext),
      new Uint8Array(nonce),
      new Uint8Array(key)
    );
    return Buffer.from(decrypted).toString('utf8');
  } catch {
    return null;
  }
}

function levelDbReadVarint(buffer, offset) {
  let result = 0n;
  let shift = 0n;

  for (let i = offset; i < Math.min(buffer.length, offset + 10); i++) {
    const byte = BigInt(buffer[i]);
    result |= (byte & 0x7fn) << shift;
    if ((byte & 0x80n) === 0n) {
      return { value: Number(result), next: i + 1 };
    }
    shift += 7n;
  }

  return null;
}

function levelDbReadLengthPrefixedSlice(buffer, offset) {
  const length = levelDbReadVarint(buffer, offset);
  if (!length) return null;

  const end = length.next + length.value;
  if (end > buffer.length) return null;

  return {
    value: buffer.subarray(length.next, end),
    next: end
  };
}

function levelDbReadBlockHandle(buffer, offset) {
  const blockOffset = levelDbReadVarint(buffer, offset);
  if (!blockOffset) return null;

  const blockSize = levelDbReadVarint(buffer, blockOffset.next);
  if (!blockSize) return null;

  return {
    offset: blockOffset.value,
    size: blockSize.value,
    next: blockSize.next
  };
}

function levelDbReadBlock(fileBuffer, handle) {
  const blockEnd = handle.offset + handle.size;
  if (blockEnd + 5 > fileBuffer.length) return null;

  const raw = fileBuffer.subarray(handle.offset, blockEnd);
  const compressionType = fileBuffer[blockEnd];

  if (compressionType === 0) return raw;
  if (compressionType === 1) return Buffer.from(snappy.uncompress(raw));

  return null;
}

function levelDbParseBlockEntries(block) {
  if (!block || block.length < 4) return [];

  const restartCount = block.readUInt32LE(block.length - 4);
  const entriesEnd = block.length - 4 - restartCount * 4;
  if (entriesEnd < 0 || entriesEnd > block.length) return [];

  const entries = [];
  let pos = 0;
  let key = Buffer.alloc(0);

  while (pos < entriesEnd) {
    const shared = levelDbReadVarint(block, pos);
    if (!shared) break;
    pos = shared.next;

    const nonShared = levelDbReadVarint(block, pos);
    if (!nonShared) break;
    pos = nonShared.next;

    const valueLength = levelDbReadVarint(block, pos);
    if (!valueLength) break;
    pos = valueLength.next;

    if (shared.value > key.length || pos + nonShared.value + valueLength.value > entriesEnd) break;

    key = Buffer.concat([
      key.subarray(0, shared.value),
      block.subarray(pos, pos + nonShared.value)
    ]);
    pos += nonShared.value;

    const value = block.subarray(pos, pos + valueLength.value);
    pos += valueLength.value;

    entries.push({ key, value });
  }

  return entries;
}

function levelDbInternalKeyInfo(internalKey) {
  if (!internalKey || internalKey.length < 8) return null;

  const trailer = internalKey.readBigUInt64LE(internalKey.length - 8);
  return {
    userKey: internalKey.subarray(0, internalKey.length - 8),
    sequence: Number(trailer >> 8n),
    valueType: Number(trailer & 0xffn)
  };
}

function levelDbRecordLatestValue(records, userKey, sequence, valueType, value, file = '') {
  if (!userKey || !Number.isSafeInteger(sequence)) return;

  const key = userKey.toString('hex');
  const existing = records.get(key);
  if (existing && existing.sequence > sequence) return;

  records.set(key, {
    userKey,
    sequence,
    valueType,
    value: valueType === 1 ? value : null,
    file
  });
}

function levelDbReadTableEntries(filePath, records) {
  const fileBuffer = fs.readFileSync(filePath);
  if (fileBuffer.length < 48) return;

  const footer = fileBuffer.subarray(fileBuffer.length - 48);
  const magic = footer.subarray(40, 48).toString('hex');
  if (magic !== '57fb808b247547db') return;

  const metaIndex = levelDbReadBlockHandle(footer, 0);
  if (!metaIndex) return;

  const index = levelDbReadBlockHandle(footer, metaIndex.next);
  if (!index) return;

  const indexBlock = levelDbReadBlock(fileBuffer, index);
  const indexEntries = levelDbParseBlockEntries(indexBlock);

  indexEntries.forEach(indexEntry => {
    const dataHandle = levelDbReadBlockHandle(indexEntry.value, 0);
    if (!dataHandle) return;

    const dataBlock = levelDbReadBlock(fileBuffer, dataHandle);
    levelDbParseBlockEntries(dataBlock).forEach(entry => {
      const info = levelDbInternalKeyInfo(entry.key);
      if (!info) return;

      levelDbRecordLatestValue(
        records,
        info.userKey,
        info.sequence,
        info.valueType,
        entry.value,
        path.basename(filePath)
      );
    });
  });
}

function levelDbLogPhysicalRecords(buffer) {
  const records = [];
  const blockSize = 32768;
  let blockStart = 0;
  let fragment = [];

  while (blockStart < buffer.length) {
    const blockEnd = Math.min(buffer.length, blockStart + blockSize);
    let pos = blockStart;

    while (pos + 7 <= blockEnd) {
      const length = buffer.readUInt16LE(pos + 4);
      const type = buffer[pos + 6];
      pos += 7;

      if (length === 0 && type === 0) break;
      if (pos + length > blockEnd) break;

      const payload = buffer.subarray(pos, pos + length);
      pos += length;

      if (type === 1) {
        records.push(payload);
        fragment = [];
      } else if (type === 2) {
        fragment = [payload];
      } else if (type === 3 && fragment.length) {
        fragment.push(payload);
      } else if (type === 4 && fragment.length) {
        fragment.push(payload);
        records.push(Buffer.concat(fragment));
        fragment = [];
      }
    }

    blockStart += blockSize;
  }

  return records;
}

function levelDbReadLogEntries(filePath, records) {
  const buffer = fs.readFileSync(filePath);

  levelDbLogPhysicalRecords(buffer).forEach(batch => {
    if (batch.length < 12) return;

    const startSequence = batch.readBigUInt64LE(0);
    const count = batch.readUInt32LE(8);
    let pos = 12;

    for (let index = 0; index < count && pos < batch.length; index++) {
      const valueType = batch[pos++];
      const key = levelDbReadLengthPrefixedSlice(batch, pos);
      if (!key) break;
      pos = key.next;

      let value = null;
      if (valueType === 1) {
        const parsedValue = levelDbReadLengthPrefixedSlice(batch, pos);
        if (!parsedValue) break;
        value = parsedValue.value;
        pos = parsedValue.next;
      } else if (valueType !== 0) {
        break;
      }

      const sequence = Number(startSequence + BigInt(index));
      levelDbRecordLatestValue(records, key.value, sequence, valueType, value, path.basename(filePath));
    }
  });
}

function levelDbApplyVersionEdit(edit, liveFiles) {
  let pos = 0;

  while (pos < edit.length) {
    const tag = levelDbReadVarint(edit, pos);
    if (!tag) return;
    pos = tag.next;

    if (tag.value === 1) {
      const comparator = levelDbReadLengthPrefixedSlice(edit, pos);
      if (!comparator) return;
      pos = comparator.next;
      continue;
    }

    if ([2, 3, 4, 9].includes(tag.value)) {
      const value = levelDbReadVarint(edit, pos);
      if (!value) return;
      pos = value.next;
      continue;
    }

    if (tag.value === 5) {
      const level = levelDbReadVarint(edit, pos);
      if (!level) return;
      const key = levelDbReadLengthPrefixedSlice(edit, level.next);
      if (!key) return;
      pos = key.next;
      continue;
    }

    if (tag.value === 6) {
      const level = levelDbReadVarint(edit, pos);
      if (!level) return;
      const file = levelDbReadVarint(edit, level.next);
      if (!file) return;
      liveFiles.delete(`${level.value}:${file.value}`);
      pos = file.next;
      continue;
    }

    if (tag.value === 7) {
      const level = levelDbReadVarint(edit, pos);
      if (!level) return;
      const file = levelDbReadVarint(edit, level.next);
      if (!file) return;
      const size = levelDbReadVarint(edit, file.next);
      if (!size) return;
      const smallest = levelDbReadLengthPrefixedSlice(edit, size.next);
      if (!smallest) return;
      const largest = levelDbReadLengthPrefixedSlice(edit, smallest.next);
      if (!largest) return;

      liveFiles.set(`${level.value}:${file.value}`, {
        level: level.value,
        file: file.value,
        size: size.value
      });
      pos = largest.next;
      continue;
    }

    return;
  }
}

function levelDbReadManifestLiveFiles(snapshotDir) {
  const currentPath = path.join(snapshotDir, 'CURRENT');
  if (!fs.existsSync(currentPath)) return null;

  const manifestName = fs.readFileSync(currentPath, 'utf8').trim();
  if (!manifestName) return null;

  const manifestPath = path.join(snapshotDir, manifestName);
  if (!fs.existsSync(manifestPath)) return null;

  const liveFiles = new Map();
  levelDbLogPhysicalRecords(fs.readFileSync(manifestPath))
    .forEach(edit => levelDbApplyVersionEdit(edit, liveFiles));

  return new Set([...liveFiles.values()].map(entry => entry.file));
}

function copyLevelDbSnapshot(sourceDir) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'termius-leveldb-'));
  fs.cpSync(sourceDir, tmpDir, { recursive: true });
  return tmpDir;
}

function extractCurrentLevelDbValues(sourceDir) {
  const snapshotDir = copyLevelDbSnapshot(sourceDir);
  const records = new Map();

  try {
    const files = fs.readdirSync(snapshotDir);
    const liveTableFiles = levelDbReadManifestLiveFiles(snapshotDir);

    files
      .filter(file => file.endsWith('.ldb'))
      .filter(file => {
        if (!liveTableFiles || !liveTableFiles.size) return true;
        const fileNumber = Number(path.basename(file, '.ldb'));
        return liveTableFiles.has(fileNumber);
      })
      .sort()
      .forEach(file => levelDbReadTableEntries(path.join(snapshotDir, file), records));

    files
      .filter(file => file.endsWith('.log'))
      .sort()
      .forEach(file => levelDbReadLogEntries(path.join(snapshotDir, file), records));

    return [...records.values()]
      .filter(record => record.valueType === 1 && record.value && record.value.length)
      .map(record => ({
        userKey: record.userKey,
        value: record.value,
        file: record.file,
        sequence: record.sequence
      }));
  } finally {
    fs.rmSync(snapshotDir, { recursive: true, force: true });
  }
}

function deserializeIndexedDbValue(buffer) {
  // Chromium prefixes V8 data with an IndexedDB version and a Blink envelope.
  // Probe only the header; encrypted strings elsewhere are not record boundaries.
  for (let offset = 0; offset < Math.min(buffer.length - 1, 16); offset++) {
    if (buffer[offset] !== 0xff) continue;
    try {
      return v8.deserialize(buffer.subarray(offset));
    } catch {}
  }
  return null;
}

function decodeIndexedDbKey(key) {
  if (!key || key.length < 4) return null;
  const lengths = [(key[0] >> 5) + 1, ((key[0] >> 2) & 7) + 1, (key[0] & 3) + 1];
  let offset = 1;
  const ids = [];
  for (const length of lengths) {
    if (offset + length > key.length) return null;
    let value = 0n;
    for (let index = 0; index < length; index++) value |= BigInt(key[offset + index]) << BigInt(index * 8);
    ids.push(value.toString());
    offset += length;
  }
  const primaryKey = key[offset] === 3 && key.length === offset + 9 ? key.readDoubleLE(offset + 1) : undefined;
  return { databaseId: ids[0], storeId: ids[1], indexId: ids[2], offset, primaryKey };
}

function normalizeCurrentRecord(record) {
  let content = {};
  const payload = record.content || record.command;
  if (typeof payload === 'string') {
    try {
      const parsed = JSON.parse(payload);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) content = parsed;
    } catch {}
  }
  const current = { ...content, ...record, __termius_current_record: true };
  delete current.content;
  delete current.command;
  return current;
}

async function extractAndDecrypt(key) {
  let encryptedCount = 0;
  let decryptedCount = 0;
  const decryptCache = new Map();
  const results = [];
  const structuredResults = [];
  const records = extractCurrentLevelDbValues(DB_PATH);
  const stores = new Map();
  for (const record of records) {
    const prefix = decodeIndexedDbKey(record.userKey);
    if (!prefix || prefix.storeId !== '0' || prefix.indexId !== '0') continue;
    const metadata = record.userKey.subarray(prefix.offset);
    if (metadata[0] !== 50) continue;
    const store = levelDbReadVarint(metadata, 1);
    if (!store || store.next !== metadata.length - 1 || metadata[store.next] !== 0) continue;
    if (record.value.length % 2) continue;
    const name = Buffer.from(record.value).swap16().toString('utf16le');
    stores.set(`${prefix.databaseId}:${store.value}`, name);
  }

  for (const record of records) {
    const buffer = record.value;
    const structured = deserializeIndexedDbValue(buffer);
    if (structured && typeof structured === 'object' && !Array.isArray(structured)) {
      const decode = async (value, field = '') => {
        if (typeof value === 'string' && /^BA[A-Za-z0-9+/=]{30,}$/.test(value)) {
          encryptedCount++;
          if (!decryptCache.has(value)) decryptCache.set(value, await decrypt(value, key));
          const plaintext = decryptCache.get(value);
          if (plaintext === null) throw new Error(`数据库字段解密失败 (${field})，已停止导出以避免写入不完整数据`);
          decryptedCount++;
          return plaintext;
        }
        if (Array.isArray(value)) return Promise.all(value.map(item => decode(item, field)));
        if (value && typeof value === 'object') {
          const decoded = {};
          for (const [name, item] of Object.entries(value)) decoded[name] = await decode(item, name);
          return decoded;
        }
        return value;
      };
      const decoded = await decode(structured);
      const prefix = decodeIndexedDbKey(record.userKey);
      if (prefix) {
        decoded.__termius_collection = stores.get(`${prefix.databaseId}:${prefix.storeId}`) || '';
        if (decoded.local_id === undefined && Number.isSafeInteger(prefix.primaryKey)) decoded.local_id = prefix.primaryKey;
      }
      structuredResults.push({
        text: JSON.stringify(normalizeCurrentRecord(decoded)),
        file: record.file,
        sequence: record.sequence,
        current: true,
        meta: {}
      });
      continue;
    }
    const text = buffer.toString('latin1');
    let match;

    ENCRYPTED_BLOCK_RE.lastIndex = 0;
    while ((match = ENCRYPTED_BLOCK_RE.exec(text))) {
      encryptedCount++;

      const encrypted = match[0];
      let decrypted = decryptCache.get(encrypted);
      if (decrypted === undefined) {
        decrypted = null;
        decryptCache.set(encrypted, decrypted);
      }

      results.push({
        text: encrypted,
        encrypted: true,
        file: record.file,
        index: match.index,
        sequence: record.sequence,
        current: true,
        meta: buildEncryptedBlockMeta(buffer, match.index, match.index + encrypted.length)
      });
    }
  }

  for (const result of results) {
    let decrypted = decryptCache.get(result.text);
    if (decrypted === null) {
      decrypted = await decrypt(result.text, key);
      decryptCache.set(result.text, decrypted);
    }

    result.encryptedText = result.text;
    result.text = decrypted || '';
    if (decrypted) decryptedCount++;
  }

  const decryptedResults = [...structuredResults, ...results.filter(result => result.text)];
  Object.defineProperty(decryptedResults, 'stats', {
    enumerable: false,
    value: {
      encryptedBlocks: encryptedCount,
      uniqueBlocks: decryptCache.size,
      decryptedBlocks: decryptedCount
    }
  });
  return decryptedResults;
}

// ==================== 数据解析模块 ====================

function parseDecryptedData(results) {
  const identities = [];
  const identitiesByUser = new Map();
  const identitiesById = new Map();
  const identitiesByLabel = new Map();
  const keysByLabel = new Map();
  const groupsById = new Map();
  const connections = [];
  const sshConfigs = [];
  const hostDefinitions = [];
  const snippets = new Map();
  const knownHostKeys = new Map();
  const fieldParts = [];
  const tags = [];
  const tagHosts = [];

  results.forEach((result, index) => {
    const raw = resultText(result).trim();
    const meta = resultMeta(result);
    if (!raw) return;

    if (!hasPlainObjectRecord(raw)) {
      if (FIELD_LEVEL_RECORD_PARTS.has(meta.encryptedField)) {
        fieldParts.push({
          field: meta.encryptedField,
          value: raw,
          meta,
          file: result.file || '',
          sequence: result.sequence,
          recordIndex: index,
          valueIndex: result.index
        });
        return;
      }

      addKey(keysByLabel, raw, '', 'raw');
      return;
    }

    try {
      const parsed = JSON.parse(raw);
      const objects = Array.isArray(parsed) ? parsed : [parsed];

      objects.forEach(obj => {
        if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return;
        if (/DELETE|REMOVED/i.test(valueToString(obj.status)) || obj.deleted === true) return;
        applyMetadataIds(obj, meta);

        if (obj.__termius_collection === 'tags') {
          tags.push(obj);
          return;
        }
        if (obj.__termius_collection === 'tag_hosts') {
          tagHosts.push(obj);
          return;
        }
        if (obj.__termius_collection === 'groups') {
          collectRecordIds(obj).forEach(id => groupsById.set(id, obj));
          return;
        }

        // Current Termius stores SSH-config/identity links as separate records.
        if (obj.__termius_current_record && obj.ssh_config && obj.identity && !obj.address) {
          sshConfigs.push({
            ...obj.ssh_config,
            identity: obj.identity,
            __termius_current_record: true
          });
          return;
        }

        // 身份认证 (带密码)
        if (isIdentityRecord(obj)) {
          const username = firstString(obj, USERNAME_FIELDS);
          identities.push(obj);
          addToListMap(identitiesByUser, username, obj);

          const label = firstString(obj, LABEL_FIELDS);
          addToListMap(identitiesByLabel, label, obj);

          collectRecordIds(obj).forEach(id => {
            if (!identitiesById.has(id) || extractPasswordFromObject(obj, { nested: true })) {
              identitiesById.set(id, obj);
            }
          });
        }

        // SSH 密钥。Termius 可能把 PEM 放在不同字段里，也可能直接解密成裸 PEM。
        addKey(keysByLabel, obj, firstString(obj, LABEL_FIELDS) || `ssh_key_${index + 1}`, 'json');
        if (isKnownHostKeyRecord(obj)) {
          knownHostKeys.set(obj.key, obj);
        }

        // 分组记录
        if (isGroupRecord(obj)) {
          groupsById.set(collectRecordIds(obj)[0], obj);
        }

        // 连接记录
        if (isConnectionRecord(obj)) {
          connections.push(obj);
        }

        // Termius 会把 Host 与 ssh_config/identity 分散成多条记录。
        addSshConfigCandidate({ sshConfigs }, obj);
        addHostDefinitionCandidate({ hostDefinitions }, obj);

        // 代码片段
        if (obj.script && firstString(obj, LABEL_FIELDS)) {
          snippets.set(firstString(obj, LABEL_FIELDS), obj);
        }
      });
    } catch {}
  });

  const matchesReference = (record, ref) => {
    if (!ref || typeof ref !== 'object') return false;
    if (ref.id !== undefined && record.id !== undefined) return valueToString(ref.id) === valueToString(record.id);
    return ref.local_id !== undefined && record.local_id !== undefined && valueToString(ref.local_id) === valueToString(record.local_id);
  };
  hostDefinitions.forEach(host => {
    if (!host.__termius_current_record) return;
    const labels = tagHosts.filter(link => matchesReference(host, link.host))
      .flatMap(link => tags.filter(tag => matchesReference(tag, link.tag)))
      .map(tag => firstString(tag, LABEL_FIELDS)).filter(Boolean);
    host.tags = [...new Set(labels)];
  });

  const data = { identities, identitiesByUser, identitiesById, identitiesByLabel, keysByLabel, groupsById, connections, sshConfigs, hostDefinitions, snippets, knownHostKeys };
  attachPasswordFragmentsById(data, fieldParts);
  attachFieldLevelIdentities(data, fieldParts);
  return data;
}

// ==================== 导出模块 ====================

function toStringList(values = []) {
  return values
    .map(value => valueToString(value).trim())
    .filter(Boolean);
}

function uniqueObjects(items = []) {
  return [...new Set(items.filter(Boolean))];
}

function buildSshConfigIndex(data) {
  if (data.__sshConfigIndex) return data.__sshConfigIndex;

  const byId = new Map();
  const byLocalId = new Map();
  const add = (map, key, config) => {
    if (!key) return;
    if (!map.has(key)) map.set(key, []);
    if (!map.get(key).includes(config)) map.get(key).push(config);
  };

  data.sshConfigs.forEach(config => {
    recordPrimaryIds(config).forEach(id => add(byId, id, config));
    recordPrimaryLocalIds(config).forEach(id => add(byLocalId, id, config));
  });

  data.__sshConfigIndex = { byId, byLocalId };
  return data.__sshConfigIndex;
}

function referencedSshConfigIds(hostDefinition) {
  if (hostDefinition.__termius_current_record) {
    return {
      ids: toStringList([hostDefinition.ssh_config?.id]),
      localIds: toStringList([hostDefinition.ssh_config?.local_id])
    };
  }
  const ownIds = new Set(recordPrimaryIds(hostDefinition));
  const ownLocalIds = new Set(recordPrimaryLocalIds(hostDefinition));
  const refs = Array.isArray(hostDefinition.__termius_ssh_config_object_refs)
    ? hostDefinition.__termius_ssh_config_object_refs
    : [];

  const ids = toStringList([
    ...refs.flatMap(ref => Array.isArray(ref.ids) ? ref.ids : []),
    ...(Array.isArray(hostDefinition.__termius_ssh_config_object_ids) ? hostDefinition.__termius_ssh_config_object_ids : []),
    hostDefinition.__termius_ssh_config_object_id
  ]).filter(id => !ownIds.has(id));

  const localIds = toStringList([
    ...refs.flatMap(ref => Array.isArray(ref.localIds) ? ref.localIds : []),
    ...(Array.isArray(hostDefinition.__termius_ssh_config_object_local_ids) ? hostDefinition.__termius_ssh_config_object_local_ids : []),
    hostDefinition.__termius_ssh_config_object_local_id
  ]).filter(id => !ownLocalIds.has(id));

  return {
    ids: [...new Set(ids)],
    localIds: [...new Set(localIds)]
  };
}

function sshConfigsForHostDefinition(data, hostDefinition) {
  const index = buildSshConfigIndex(data);
  const refIds = referencedSshConfigIds(hostDefinition);
  const configs = refIds.ids.flatMap(id => index.byId.get(id) || []);

  if (configs.length) {
    return uniqueObjects(configs);
  }

  return uniqueObjects(refIds.localIds.flatMap(id => index.byLocalId.get(id) || []));
}

function exactIdentityIdsFromSshConfig(data, config) {
  const ownIds = new Set(recordPrimaryIds(config));
  const ownLocalIds = new Set(recordPrimaryLocalIds(config));
  const refs = Array.isArray(config.__termius_identity_object_refs)
    ? config.__termius_identity_object_refs
    : [];

  const directIds = toStringList([
    ...refs.flatMap(ref => Array.isArray(ref.ids) ? ref.ids : []),
    ...(Array.isArray(config.__termius_identity_object_ids) ? config.__termius_identity_object_ids : []),
    config.__termius_identity_object_id,
    firstString(config, DIRECT_REFERENCE_ID_FIELDS)
  ]).filter(id => !ownIds.has(id));

  const matchedIds = [...new Set(directIds)]
    .filter(id => identityForExactId(data, id));
  if (matchedIds.length) return matchedIds;

  const localIds = toStringList([
    ...refs.flatMap(ref => Array.isArray(ref.localIds) ? ref.localIds : []),
    ...(Array.isArray(config.__termius_identity_object_local_ids) ? config.__termius_identity_object_local_ids : []),
    config.__termius_identity_object_local_id
  ]).filter(id => !ownLocalIds.has(id));

  return [...new Set(localIds)]
    .filter(id => identityForExactId(data, id));
}

function identitiesForHostDefinition(data, hostDefinition) {
  const configs = sshConfigsForHostDefinition(data, hostDefinition);
  if (hostDefinition.__termius_current_record) {
    const identities = uniqueObjects(configs.flatMap(config => {
      const ref = config.identity;
      if (!ref || typeof ref !== 'object') return [];
      const current = data.identities.filter(identity => identity.__termius_current_record);
      const byId = ref.id === undefined ? [] : current.filter(identity => valueToString(identity.id) === valueToString(ref.id));
      if (byId.length) return byId;
      return ref.local_id === undefined ? [] : current.filter(identity => valueToString(identity.local_id) === valueToString(ref.local_id));
    }));
    return {
      configs,
      configIds: [...new Set(configs.flatMap(recordPrimaryIds))],
      identityIds: [...new Set(identities.flatMap(collectRecordIds))],
      identities
    };
  }
  const identityIds = [
    ...new Set(configs.flatMap(config => exactIdentityIdsFromSshConfig(data, config)))
  ];
  const identities = uniqueObjects(identityIds.map(id => identityForExactId(data, id)));

  return {
    configs,
    configIds: [
      ...new Set(configs.flatMap(config => recordPrimaryIds(config)))
    ],
    identityIds,
    identities
  };
}

function uniqueIdentityPassword(identities) {
  const passwords = [
    ...new Set(
      identities
        .map(identity => extractPasswordFromObject(identity, { nested: true }))
        .filter(Boolean)
    )
  ];

  if (passwords.length === 1) return { password: passwords[0], ambiguous: false };
  if (passwords.length > 1) return { password: '', ambiguous: true };
  return { password: '', ambiguous: false };
}

function resolveHostDefinitionCredentials(hostDefinition, data) {
  const direct = firstPasswordString(hostDefinition);
  const directUsername = firstString(hostDefinition, USERNAME_FIELDS);
  if (direct) {
    return {
      username: directUsername,
      password: direct,
      source: 'hostDirect',
      configs: [],
      configIds: [],
      identityIds: []
    };
  }

  const { configs, configIds, identityIds, identities } = identitiesForHostDefinition(data, hostDefinition);
  const usernames = [
    ...new Set(identities.map(identity => firstString(identity, USERNAME_FIELDS)).filter(Boolean))
  ];
  const match = uniqueIdentityPassword(identities);

  let source = 'missing';
  if (match.password) source = 'hostSshConfigIdentity';
  else if (match.ambiguous) source = 'ambiguousHostIdentity';
  else if (identityIds.length) source = 'missingIdentityPassword';
  else if (configs.length) source = 'missingIdentity';
  else if (hostDefinition.__termius_field_host_definition) source = 'missingFieldCredential';
  else source = 'missingSshConfig';

  return {
    username: usernames.length === 1 ? usernames[0] : '',
    password: match.password,
    source,
    configs,
    configIds,
    identityIds
  };
}

function addHostConfig(hostMap, hostConfig) {
  const key = [hostConfig.host, hostConfig.port, hostConfig.username, hostConfig.label, hostConfig.protocol].join('\u0000');

  if (!hostMap.has(key)) {
    hostMap.set(key, hostConfig);
    return;
  }

  const existing = hostMap.get(key);
  if (!existing.password && hostConfig.password) {
    hostMap.set(key, {
      ...existing,
      ...hostConfig,
      groups: existing.groups || hostConfig.groups,
      tags: existing.tags || hostConfig.tags
    });
  }
}

function buildHostDefinitionHostConfig(data, selectedDefinitions = null) {
  const hostMap = new Map();
  const hostDefinitions = selectedDefinitions || selectedHostDefinitions(data).hostDefinitions;

  hostDefinitions.forEach(hostDefinition => {
    const host = firstString(hostDefinition, ['address', 'hostname', ...HOST_FIELDS]);
    if (!host) return;

    const credentials = resolveHostDefinitionCredentials(hostDefinition, data);
    const ports = [
      ...new Set(credentials.configs.map(config => firstString(config, PORT_FIELDS)).filter(Boolean))
    ];
    const protocol = normalizeProtocol(firstString(hostDefinition, PROTOCOL_FIELDS));
    const label = firstString(hostDefinition, LABEL_FIELDS) || host;
    const port = firstString(hostDefinition, PORT_FIELDS) || ports[0] || (protocol === 'ssh' ? '22' : '');

    addHostConfig(hostMap, {
      groups: resolveGroupPath(hostDefinition, data.groupsById),
      label,
      tags: resolveTags(hostDefinition),
      host,
      protocol,
      port,
      username: credentials.username,
      password: credentials.password,
      passwordSource: credentials.source,
      sourceRecord: hostDefinition.__termius_field_host_definition ? 'fieldHostDefinition' : 'hostDefinition',
      hostId: firstString(hostDefinition, RECORD_ID_FIELDS),
      sshConfigIds: credentials.configIds,
      identityIds: credentials.identityIds
    });
  });

  return hostMap;
}

function buildConnectionHostConfig(data) {
  const hostMap = new Map();

  data.connections.forEach(conn => {
    const host = firstString(conn, HOST_FIELDS);
    if (!host) return;

    const port = firstString(conn, PORT_FIELDS);
    const username = firstString(conn, USERNAME_FIELDS);
    const label = firstString(conn, LABEL_FIELDS) || host;
    const protocol = normalizeProtocol(firstString(conn, PROTOCOL_FIELDS));
    const passwordMatch = resolvePassword(conn, data);

    addHostConfig(hostMap, {
      groups: resolveGroupPath(conn, data.groupsById),
      label,
      tags: resolveTags(conn),
      host,
      protocol,
      port,
      username,
      password: passwordMatch.password,
      passwordSource: passwordMatch.source,
      sourceRecord: 'connectionHistory',
      hostId: firstString(conn, ['host_id', 'hostId', '__termius_host_id']),
      identityIds: collectReferenceIds(conn)
    });
  });

  return hostMap;
}

function finalizePasswordStats(data, hostMap) {
  const passwordStats = createPasswordStats();
  hostMap.forEach(host => {
    const key = host.passwordSource || 'missing';
    passwordStats[key] = (passwordStats[key] || 0) + 1;
  });
  data.passwordStats = passwordStats;
}

function buildHostConfig(data) {
  const selected = selectedHostDefinitions(data);
  const hostMap = selected.hostDefinitions.length
    ? buildHostDefinitionHostConfig(data, selected.hostDefinitions)
    : buildConnectionHostConfig(data);

  data.exportSource = selected.hostDefinitions.length ? selected.source : 'connectionHistory';
  finalizePasswordStats(data, hostMap);
  return hostMap;
}

function outputPath(fileName) {
  return path.join(OUTPUT_DIR, fileName);
}

function exportHostsCsv(hostMap) {
  const rows = [IMPORT_CSV_HEADERS];
  hostMap.forEach(h => {
    rows.push([
      h.groups,
      h.label,
      h.tags,
      h.host,
      h.protocol,
      h.port,
      h.username,
      h.password
    ]);
  });
  const csv = rows.map(csvRow).join('\n') + '\n';
  fs.writeFileSync(outputPath(OUTPUT_FILES.hostsCsv), BOM + csv);
  return hostMap.size;
}

function exportDataFiles(hostMap) {
  return {
    hosts: {
      path: outputPath(OUTPUT_FILES.hostsCsv),
      count: exportHostsCsv(hostMap)
    }
  };
}

function summarizeValue(value, field = '') {
  if (value === undefined || value === null) return String(value);
  if (SECRET_FIELD_RE.test(field)) return '<redacted>';
  if (typeof value === 'string') {
    if (PRIVATE_KEY_RE.test(value)) return '<private-key>';
    if (value.length > 80) return `<string:${value.length}>`;
    return value.replace(/[^\x20-\x7E]/g, '?');
  }
  if (Array.isArray(value)) return `<array:${value.length}>`;
  if (typeof value === 'object') return `<object:${Object.keys(value).length}>`;
  return String(value);
}

function objectKind(obj) {
  if (isConnectionRecord(obj)) return 'connection';
  if (isIdentityRecord(obj)) return 'identity';
  if (extractPrivateKey(obj)) return 'ssh_key';
  if (isGroupRecord(obj)) return 'group';
  if (obj && obj.script && firstString(obj, LABEL_FIELDS)) return 'snippet';
  return 'other';
}

function buildSchemaReport(results) {
  const report = new Map();

  results.forEach(result => {
    const raw = resultText(result).trim();
    if (!raw || (!raw.startsWith('{') && !raw.startsWith('['))) return;

    try {
      const parsed = JSON.parse(raw);
      const objects = Array.isArray(parsed) ? parsed : [parsed];

      objects.forEach(obj => {
        if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return;

        const kind = objectKind(obj);
        if (!report.has(kind)) {
          report.set(kind, { count: 0, fields: new Map(), samples: [] });
        }

        const entry = report.get(kind);
        entry.count++;

        Object.entries(obj).forEach(([field, value]) => {
          if (!entry.fields.has(field)) {
            entry.fields.set(field, {
              count: 0,
              type: Array.isArray(value) ? 'array' : typeof value,
              sample: summarizeValue(value, field)
            });
          }
          entry.fields.get(field).count++;
        });

        if (entry.samples.length < 3) {
          entry.samples.push(
            Object.fromEntries(
              Object.entries(obj)
                .slice(0, 20)
                .map(([field, value]) => [field, summarizeValue(value, field)])
            )
          );
        }
      });
    } catch {}
  });

  return [...report.entries()].map(([kind, entry]) => ({
    kind,
    count: entry.count,
    fields: [...entry.fields.entries()]
      .sort((a, b) => b[1].count - a[1].count || a[0].localeCompare(b[0]))
      .slice(0, 80)
      .map(([name, info]) => ({ name, count: info.count, type: info.type, sample: info.sample })),
    samples: entry.samples
  }));
}

function writeSchemaReport(results) {
  const reportPath = outputPath(OUTPUT_FILES.schemaReport);
  fs.writeFileSync(reportPath, JSON.stringify(buildSchemaReport(results), null, 2));
  return reportPath;
}

function sortedSetValues(values, limit = 12) {
  return [...values].sort().slice(0, limit);
}

function buildIdentityReport(data) {
  const selected = selectedHostDefinitions(data);
  const hasHostDefinitions = selected.hostDefinitions.length > 0;
  const referenceProfiles = hasHostDefinitions
    ? collectHostDefinitionIdentityProfiles(data)
    : (data.identityReferenceProfiles || collectReferenceProfiles(data.connections));
  const sourceRecord = hasHostDefinitions ? selected.source : 'connectionHistory';
  const rows = [...referenceProfiles.values()]
    .map(profile => {
      const identity = data.identitiesById.get(profile.id);
      const link = identity?.__termius_identity_link || null;

      return {
        id: profile.id,
        source_record: sourceRecord,
        reference_count: profile.count,
        connection_count: profile.count,
        users: sortedSetValues(profile.users),
        host_count: profile.hosts.size,
        hosts_sample: sortedSetValues(profile.hosts, 8),
        sources: Object.fromEntries([...profile.sources.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))),
        source_users: Object.fromEntries(
          [...profile.usersBySource.entries()]
            .sort((a, b) => a[0].localeCompare(b[0]))
            .map(([source, users]) => [source, sortedSetValues(users)])
        ),
        matched_identity: Boolean(identity),
        identity_username: identity ? firstString(identity, USERNAME_FIELDS) : '',
        identity_label: identity ? firstString(identity, LABEL_FIELDS) : '',
        identity_has_password: identity ? Boolean(extractPasswordFromObject(identity, { nested: true })) : false,
        link_source: link?.source || '',
        link_distance: link?.distance ?? null,
        link_side: link?.side || ''
      };
    })
    .sort((a, b) => b.connection_count - a.connection_count || a.id.localeCompare(b.id));

  const summary = {
    source_record: sourceRecord,
    referenced_identity_ids: rows.length,
    matched_identity_ids: rows.filter(row => row.matched_identity).length,
    matched_password_ids: rows.filter(row => row.identity_has_password).length,
    unmatched_identity_ids: rows.filter(row => !row.matched_identity).length,
    parsed_identities: data.identities.length,
    mapped_identity_ids: data.identitiesById.size
  };

  return {
    generated_at: new Date().toISOString(),
    summary,
    references: rows
  };
}

function writeIdentityReport(data) {
  const report = buildIdentityReport(data);
  const reportPath = outputPath(OUTPUT_FILES.identityReport);
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  return { reportPath, summary: report.summary };
}

function buildFieldReport(results) {
  const fields = new Map();

  results.forEach(result => {
    const raw = resultText(result).trim();
    const meta = resultMeta(result);
    if (!raw || raw.startsWith('{') || raw.startsWith('[')) return;

    const field = meta.encryptedField || '<unknown>';
    if (!fields.has(field)) {
      fields.set(field, {
        count: 0,
        lengths: new Map(),
        id_count: 0,
        local_id_count: 0,
        visible_identity_id_count: 0,
        nearby_id_count: 0,
        samples: []
      });
    }

    const entry = fields.get(field);
    entry.count++;
    const lengthBucket = raw.length > 80 ? '>80' : String(raw.length);
    entry.lengths.set(lengthBucket, (entry.lengths.get(lengthBucket) || 0) + 1);
    if (meta.id) entry.id_count++;
    if (meta.local_id) entry.local_id_count++;
    if (meta.visible_identity_id) entry.visible_identity_id_count++;
    if (Array.isArray(meta.nearby_id_entries) && meta.nearby_id_entries.length) entry.nearby_id_count++;
    if (entry.samples.length < 16) {
      entry.samples.push({
        length: raw.length,
        value: SECRET_FIELD_RE.test(field) || field === '<unknown>' ? '<redacted>' : raw,
        id: meta.id || '',
        local_id: meta.local_id || '',
        visible_identity_id: meta.visible_identity_id || '',
        identity_object_ids: Array.isArray(meta.identity_object_ids) ? meta.identity_object_ids.slice(0, 8) : [],
        nearby_id_entries: Array.isArray(meta.nearby_id_entries)
          ? meta.nearby_id_entries.slice(0, 12)
          : []
      });
    }
  });

  return [...fields.entries()]
    .sort((a, b) => b[1].count - a[1].count || a[0].localeCompare(b[0]))
    .map(([field, entry]) => ({
      field,
      count: entry.count,
      id_count: entry.id_count,
      local_id_count: entry.local_id_count,
      visible_identity_id_count: entry.visible_identity_id_count,
      nearby_id_count: entry.nearby_id_count,
      lengths: [...entry.lengths.entries()]
        .sort((a, b) => Number(a[0].replace('>', '999')) - Number(b[0].replace('>', '999')))
        .slice(0, 20)
        .map(([length, count]) => ({ length, count })),
      samples: entry.samples
    }));
}

function writeFieldReport(results) {
  const report = buildFieldReport(results);
  const reportPath = outputPath(OUTPUT_FILES.fieldReport);
  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2));
  return reportPath;
}

function buildPasswordCandidateDiagnostics(conn, data) {
  const username = firstString(conn, USERNAME_FIELDS);
  const referencedIds = collectReferenceIds(conn);
  const referencedPasswords = referencedIds
    .flatMap(id => trustedPasswordsForIdentityId(data, id, username));

  const labelIdentities = collectReferenceLabels(conn)
    .flatMap(refLabel => data.identitiesByLabel.get(refLabel) || []);
  const usernameIdentities = username ? (data.identitiesByUser.get(username) || []) : [];

  return {
    referenced_ids: referencedIds.slice(0, 16),
    referenced_passwords: passwordCandidateSummary(referencedPasswords),
    label_passwords: identityPasswordCandidateSummary(labelIdentities),
    username_passwords: identityPasswordCandidateSummary(usernameIdentities)
  };
}

function mergePasswordCandidateDiagnostics(items) {
  const referencedIds = new Set();
  const merged = {
    referencedPasswords: [],
    labelPasswords: [],
    usernamePasswords: []
  };

  items.forEach(item => {
    item.referenced_ids.forEach(id => referencedIds.add(id));
    merged.referencedPasswords.push(...item.referenced_passwords.fingerprints);
    merged.labelPasswords.push(...item.label_passwords.fingerprints);
    merged.usernamePasswords.push(...item.username_passwords.fingerprints);
  });

  const summarizeFingerprints = fingerprints => ({
    count: new Set(fingerprints.filter(Boolean)).size,
    fingerprints: [...new Set(fingerprints.filter(Boolean))].slice(0, 16)
  });

  return {
    referenced_ids: [...referencedIds].slice(0, 16),
    referenced_passwords: summarizeFingerprints(merged.referencedPasswords),
    label_passwords: summarizeFingerprints(merged.labelPasswords),
    username_passwords: summarizeFingerprints(merged.usernamePasswords)
  };
}

function buildBlankReport(data, hostMap) {
  const rows = [...hostMap.values()]
    .filter(host => !host.password)
    .map(host => {
      const relatedConnections = data.connections.filter(conn =>
        firstString(conn, HOST_FIELDS) === host.host &&
        firstString(conn, PORT_FIELDS) === host.port &&
        firstString(conn, USERNAME_FIELDS) === host.username &&
        (firstString(conn, LABEL_FIELDS) || firstString(conn, HOST_FIELDS)) === host.label
      );
      const referenceIds = [...new Set(relatedConnections.flatMap(collectReferenceIds))];
      const hostIds = [...new Set(
        relatedConnections
          .map(conn => firstString(conn, ['host_id', 'hostId', '__termius_host_id']))
          .filter(Boolean)
      )];
      const sshConfigRefs = relatedConnections
        .flatMap(conn => Array.isArray(conn.__termius_ssh_config_object_refs) ? conn.__termius_ssh_config_object_refs : [])
        .map(ref => ({
          ids: Array.isArray(ref.ids) ? ref.ids : [],
          localIds: Array.isArray(ref.localIds) ? ref.localIds : [],
          distance: ref.distance ?? null,
          side: ref.side || ''
        }))
        .slice(0, 12);
      const candidateDiagnostics = mergePasswordCandidateDiagnostics(
        relatedConnections.map(conn => buildPasswordCandidateDiagnostics(conn, data))
      );

      return {
        label: host.label,
        host: host.host,
        port: host.port,
        username: host.username,
        reason: host.passwordSource || 'missing',
        source_record: host.sourceRecord || '',
        host_id: host.hostId || '',
        ssh_config_ids: Array.isArray(host.sshConfigIds) ? host.sshConfigIds.slice(0, 16) : [],
        identity_ids: Array.isArray(host.identityIds) ? host.identityIds.slice(0, 16) : [],
        related_connection_count: relatedConnections.length,
        host_ids: hostIds,
        reference_ids: referenceIds.slice(0, 16),
        ssh_config_refs: sshConfigRefs,
        candidates: candidateDiagnostics
      };
    });

  return {
    generated_at: new Date().toISOString(),
    summary: {
      blank_rows: rows.length,
      by_reason: rows.reduce((acc, row) => {
        acc[row.reason] = (acc[row.reason] || 0) + 1;
        return acc;
      }, {})
    },
    rows
  };
}

function writeBlankReport(data, hostMap) {
  const reportPath = outputPath(OUTPUT_FILES.blankReport);
  fs.writeFileSync(reportPath, JSON.stringify(buildBlankReport(data, hostMap), null, 2));
  return reportPath;
}

function displayPath(filePath) {
  const relativePath = path.relative(OUTPUT_DIR, filePath);
  if (!relativePath || relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
    return filePath;
  }
  return relativePath;
}

function formatPercent(part, total) {
  if (!total) return '0.0%';
  return `${(part / total * 100).toFixed(1)}%`;
}

function formatRatio(part, total) {
  return `${part}/${total} (${formatPercent(part, total)})`;
}

function sourceLabel(source, labels) {
  return labels[source] || source || '未知';
}

function formatPasswordStats(stats = {}) {
  const summary = Object.entries(stats)
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([source, count]) => `${sourceLabel(source, PASSWORD_SOURCE_LABELS)} ${count}`)
    .join(', ');
  return summary || '无';
}

function hostCountWithoutPassword(hostMap) {
  return [...hostMap.values()].filter(host => !host.password).length;
}

function logHeader() {
  console.log('=== Termius 数据导出器 ===');
  console.log(`输出目录: ${OUTPUT_DIR}\n`);
}

function logStep(index, total, title) {
  console.log(`[${index}/${total}] ${title}`);
}

function logDetail(label, value) {
  console.log(`    ${label}: ${value}`);
}

function logNote(message) {
  console.log(`    ${message}`);
}

function logDecryptSummary(results) {
  const stats = results.stats || {};
  logDetail('加密块', `${stats.encryptedBlocks || 0} 个，唯一块 ${stats.uniqueBlocks || 0} 个`);
  logDetail('解密成功', formatRatio(stats.decryptedBlocks || 0, stats.encryptedBlocks || 0));
  logDetail('有效明文', `${results.length} 条\n`);
}

function logParseSummary(data) {
  logDetail('主机定义', data.hostDefinitions.length);
  logDetail('SSH 配置', data.sshConfigs.length);
  logDetail('身份认证', data.identities.length);
  logDetail('分组记录', data.groupsById.size);
  logDetail('连接历史', `${data.connections.length}\n`);
}

function logReportDone(label, reportPath, details = []) {
  logDetail(label, displayPath(reportPath));
  details.forEach(([detailLabel, value]) => logDetail(detailLabel, value));
  logNote('诊断报告已脱敏，不会写出明文密码或私钥。');
  console.log('');
}

function writeEarlyReportIfRequested(args, results) {
  if (args.includes(REPORT_FLAGS.schema)) {
    const reportPath = writeSchemaReport(results);
    logReportDone('结构报告', reportPath);
    return true;
  }

  if (args.includes(REPORT_FLAGS.field)) {
    const reportPath = writeFieldReport(results);
    logReportDone('字段报告', reportPath);
    return true;
  }

  return false;
}

function writeParsedReportIfRequested(args, data) {
  if (!args.includes(REPORT_FLAGS.identity)) return false;

  const { reportPath, summary } = writeIdentityReport(data);
  logReportDone('Identity 引用报告', reportPath, [
    ['引用 ID', summary.referenced_identity_ids],
    ['已匹配 Identity', summary.matched_identity_ids],
    ['已匹配密码', summary.matched_password_ids],
    ['未匹配', summary.unmatched_identity_ids]
  ]);
  return true;
}

function writeBlankReportIfRequested(args, data, hostMap) {
  if (!args.includes(REPORT_FLAGS.blank)) return false;

  const reportPath = writeBlankReport(data, hostMap);
  logReportDone('空密码报告', reportPath, [
    ['空密码主机', `${hostCountWithoutPassword(hostMap)}/${hostMap.size}`]
  ]);
  return true;
}

function logHostConfigSummary(data, hostMap) {
  const blankCount = hostCountWithoutPassword(hostMap);
  logDetail('导出来源', sourceLabel(data.exportSource, EXPORT_SOURCE_LABELS));
  logDetail('主机配置', `${hostMap.size} 条`);
  logDetail('密码匹配', blankCount ? `${hostMap.size - blankCount} 条成功，${blankCount} 条为空` : '全部已匹配');
  logDetail('匹配来源', `${formatPasswordStats(data.passwordStats)}\n`);
}

function logExportSummary(exportResult) {
  logDetail('主机 CSV', `${displayPath(exportResult.hosts.path)} (${exportResult.hosts.count} 条)`);
  console.log('');
}

function logDone() {
  console.log('=== 导出完成 ===');
  console.log(`Termius 导入 CSV: ${displayPath(outputPath(OUTPUT_FILES.hostsCsv))}`);
}

// ==================== 主程序 ====================

async function main() {
  const args = process.argv.slice(2);
  logHeader();

  // 初始化
  await sodium.ready;

  if (!fs.existsSync(DB_PATH)) {
    throw new Error(`未找到 Termius 数据库: ${DB_PATH}，请确保已安装并登录 Termius`);
  }

  // 获取密钥
  logStep(1, 4, '准备解密密钥');
  logNote('正在读取系统凭据存储中的 Termius localKey...');
  const key = await getEncryptionKey();
  logNote('密钥读取成功。\n');

  // 解密数据
  logStep(2, 4, '扫描并解密本地数据库');
  logDetail('数据库', DB_PATH);
  const results = await extractAndDecrypt(key);
  logDecryptSummary(results);

  if (writeEarlyReportIfRequested(args, results)) return;

  // 解析数据
  logStep(3, 4, '解析 Termius 数据');
  const data = parseDecryptedData(results);
  logParseSummary(data);

  if (writeParsedReportIfRequested(args, data)) return;

  // 导出
  logStep(4, 4, '整理主机配置并写出文件');
  const hostMap = buildHostConfig(data);
  logHostConfigSummary(data, hostMap);
  if (writeBlankReportIfRequested(args, data, hostMap)) return;

  const exportResult = exportDataFiles(hostMap);
  logExportSummary(exportResult);
  logDone();
}

if (require.main === module) {
  main().catch(err => {
    console.error('错误:', err.message);
    process.exit(1);
  });
}

module.exports = {
  decodeIndexedDbKey,
  deserializeIndexedDbValue,
  normalizeCurrentRecord,
  getDatabasePath,
  parseDecryptedData,
  buildHostConfig,
  exportHostsCsv,
  exportDataFiles,
  getEncryptionKey,
  extractAndDecrypt,
  extractPrivateKey,
  resolvePassword,
  buildSchemaReport,
  buildIdentityReport,
  buildFieldReport,
  buildBlankReport,
  OUTPUT_FILES,
  IMPORT_CSV_HEADERS
};
