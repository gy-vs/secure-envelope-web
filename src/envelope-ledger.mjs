import {createCipheriv, createDecipheriv, createHash, randomBytes} from 'node:crypto';

// Error classes that pause an item for operator review by default.
const DEFAULT_MANUAL_CONFIRM_ERRORS = ['unwrap_failed', 'source_version_changed'];

function sha256(text) {
  return createHash('sha256').update(text).digest('hex');
}

function newMaterial() {
  return randomBytes(32).toString('hex');
}

function wrapDataKey(materialHex, dataKeyHex) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(materialHex, 'hex'), iv);
  const body = Buffer.concat([cipher.update(dataKeyHex, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString('base64');
}

function unwrapDataKey(materialHex, blob) {
  const raw = Buffer.from(blob, 'base64');
  const decipher = createDecipheriv('aes-256-gcm', Buffer.from(materialHex, 'hex'), raw.subarray(0, 12));
  decipher.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8');
}

function fail(message, statusCode = 400, errorClass = null) {
  const error = new Error(message);
  error.statusCode = statusCode;
  if (errorClass) error.errorClass = errorClass;
  return error;
}

function clone(keyring) {
  return structuredClone(keyring);
}

// Every state transition is stamped with a monotonic sequence number and an
// explicit source; wall-clock time is never used to infer progress.
function stamp(keyring) {
  keyring.seq += 1;
  return keyring.seq;
}

export function createKeyring() {
  return {seq: 0, keys: new Map(), envelopes: new Map(), rotations: []};
}

function requireKey(keyring, keyId, wording = 'unknown key') {
  const key = keyring.keys.get(keyId);
  if (!key) throw fail(wording, 404);
  return key;
}

function requireVersion(key, version, wording) {
  const record = key.versions.get(version);
  if (!record) throw fail(wording, 404);
  return record;
}

// Accepts 'keyId' (current version) or 'keyId@version'.
function parseRef(keyring, ref, role) {
  if (typeof ref !== 'string' || ref.length === 0) throw fail(`${role} key missing`, 400);
  const [keyId, versionText] = ref.split('@');
  const key = keyring.keys.get(keyId);
  if (!key) throw fail(`${role} key missing`, 404);
  const version = versionText === undefined ? key.currentVersion : Number(versionText);
  if (!Number.isInteger(version) || !key.versions.has(version)) throw fail(`${role} key version missing`, 404);
  return {keyId, version};
}

export function addKey(keyring, keyId) {
  if (typeof keyId !== 'string' || keyId.length === 0) throw fail('key id required');
  if (keyring.keys.has(keyId)) throw fail('key already exists', 409);
  const next = clone(keyring);
  const seq = stamp(next);
  next.keys.set(keyId, {
    id: keyId,
    currentVersion: 1,
    createdSeq: seq,
    versions: new Map([[1, {version: 1, material: newMaterial(), status: 'active', createdSeq: seq}]]),
  });
  return next;
}

export function addKeyVersion(keyring, keyId) {
  requireKey(keyring, keyId);
  const next = clone(keyring);
  const key = next.keys.get(keyId);
  const version = key.currentVersion + 1;
  key.versions.set(version, {version, material: newMaterial(), status: 'active', createdSeq: stamp(next)});
  key.currentVersion = version;
  return next;
}

export function setKeyVersionStatus(keyring, keyId, version, status) {
  requireKey(keyring, keyId);
  if (!['active', 'disabled'].includes(status)) throw fail('unsupported key version status');
  const next = clone(keyring);
  requireVersion(next.keys.get(keyId), version, 'key version missing').status = status;
  return next;
}

function currentWrap(envelope) {
  return envelope.wraps.find(wrap => wrap.state === 'current') ?? null;
}

export function seal(keyring, id, keyId, digest) {
  const key = requireKey(keyring, keyId);
  const versionRecord = requireVersion(key, key.currentVersion, 'key version missing');
  if (versionRecord.status !== 'active') throw fail('key version not active', 409);
  const next = clone(keyring);
  const seq = stamp(next);
  const dataKey = newMaterial();
  const prior = next.envelopes.get(id);
  const wraps = prior ? prior.wraps.map(wrap => wrap.state === 'current' ? {...wrap, state: 'superseded'} : wrap) : [];
  wraps.push({
    seq,
    keyId,
    keyVersion: key.currentVersion,
    wrappedDataKey: wrapDataKey(versionRecord.material, dataKey),
    state: 'current',
    rotationId: null,
    attempt: 0,
  });
  next.envelopes.set(id, {
    id,
    digest,
    keyId,
    keyVersion: key.currentVersion,
    dataKey,
    wraps,
    createdSeq: prior ? prior.createdSeq : seq,
  });
  return next;
}

export function startRotation(keyring, fromRef, toRef, options = {}) {
  const from = parseRef(keyring, fromRef, 'source');
  const to = parseRef(keyring, toRef, 'target');
  if (from.keyId === to.keyId && from.version === to.version) throw fail('source and target key version match');
  const targetVersion = requireVersion(keyring.keys.get(to.keyId), to.version, 'target key version missing');
  if (targetVersion.status !== 'active') throw fail('target key version not active', 409);
  const blocked = new Set();
  for (const rotation of keyring.rotations) {
    for (const item of rotation.items) {
      if (item.status !== 'succeeded') blocked.add(item.envelopeId);
    }
  }
  const candidates = [...keyring.envelopes.values()].filter(
    envelope => envelope.keyId === from.keyId && envelope.keyVersion === from.version,
  );
  for (const envelope of candidates) {
    if (blocked.has(envelope.id)) throw fail(`envelope ${envelope.id} already in an unfinished rotation`, 409);
  }
  const next = clone(keyring);
  const createdSeq = stamp(next);
  const id = next.rotations.length + 1;
  const batchSize = Math.max(1, Number(options.batchSize ?? 2));
  const policy = {
    maxAttempts: Math.max(1, Number(options.maxAttempts ?? 2)),
    manualConfirmErrors: Array.isArray(options.manualConfirmErrors)
      ? [...options.manualConfirmErrors]
      : [...DEFAULT_MANUAL_CONFIRM_ERRORS],
  };
  const items = candidates.map(envelope => ({
    id: `${id}:${envelope.id}`,
    envelopeId: envelope.id,
    status: 'pending',
    attempts: 0,
    lastError: null,
    errorClass: null,
    snapshotWrapSeq: currentWrap(envelope).seq,
    history: [{seq: createdSeq, from: null, to: 'pending', source: `rotation:${id}`, reason: 'rotation created'}],
  }));
  const batches = [];
  for (let index = 0; index < items.length; index += batchSize) {
    batches.push({
      seq: batches.length + 1,
      status: 'pending',
      itemIds: items.slice(index, index + batchSize).map(item => item.id),
      ranSeq: null,
    });
  }
  const rotation = {
    id,
    from,
    to,
    status: items.length === 0 ? 'completed' : 'pending',
    policy,
    batchSize,
    items,
    batches,
    done: [],
    events: [{seq: createdSeq, type: 'created', source: 'api', detail: {from, to, batchSize, policy}}],
    createdSeq,
  };
  next.rotations.push(rotation);
  return next;
}

function transition(next, item, to, source, reason = null) {
  const from = item.status;
  item.status = to;
  item.history.push({seq: stamp(next), from, to, source, reason});
}

function refreshRotationStatus(next, rotation, source) {
  const items = rotation.items;
  let status;
  if (items.length === 0 || items.every(item => item.status === 'succeeded')) {
    status = 'completed';
  } else if (items.some(item => item.status === 'pending' || item.status === 'processing')) {
    const started = items.some(item => item.attempts > 0 || item.status === 'succeeded');
    status = started ? 'running' : 'pending';
  } else {
    status = 'attention_required';
  }
  if (status !== rotation.status) {
    rotation.events.push({seq: stamp(next), type: 'status', from: rotation.status, to: status, source});
    rotation.status = status;
  }
}

// One wrap attempt. Never throws for wrap failures: the failure is recorded on
// the item with its reason, and the envelope keeps its previous current wrap.
function attemptItem(next, rotation, item, source) {
  const envelope = next.envelopes.get(item.envelopeId);
  item.attempts += 1;
  const attemptNo = item.attempts;
  transition(next, item, 'processing', source, `attempt ${attemptNo}`);
  try {
    if (!envelope) throw fail('envelope no longer exists', 400, 'envelope_missing');
    const wrap = currentWrap(envelope);
    if (!wrap) throw fail('envelope has no current wrap', 400, 'envelope_missing');
    if (wrap.seq !== item.snapshotWrapSeq) {
      throw fail(
        `envelope wrap advanced past rotation snapshot (${item.snapshotWrapSeq} -> ${wrap.seq})`,
        409,
        'source_version_changed',
      );
    }
    const targetVersion = next.keys.get(rotation.to.keyId)?.versions.get(rotation.to.version);
    if (!targetVersion || targetVersion.status !== 'active') {
      throw fail(`target ${rotation.to.keyId}@${rotation.to.version} is not active`, 409, 'target_key_unavailable');
    }
    const sourceVersion = next.keys.get(wrap.keyId)?.versions.get(wrap.keyVersion);
    if (!sourceVersion) throw fail(`source key ${wrap.keyId}@${wrap.keyVersion} is missing`, 400, 'source_key_missing');
    let dataKey;
    try {
      dataKey = unwrapDataKey(sourceVersion.material, wrap.wrappedDataKey);
    } catch {
      throw fail('current wrap cannot be unwrapped with its recorded key version', 400, 'unwrap_failed');
    }
    const alreadyAtTarget = wrap.keyId === rotation.to.keyId && wrap.keyVersion === rotation.to.version;
    if (!alreadyAtTarget) {
      // The new wrap becomes current only after it has been fully produced;
      // the old current wrap is superseded in the same state transition.
      const wrapped = wrapDataKey(targetVersion.material, dataKey);
      for (const entry of envelope.wraps) {
        if (entry.state === 'current') entry.state = 'superseded';
      }
      envelope.wraps.push({
        seq: stamp(next),
        keyId: rotation.to.keyId,
        keyVersion: rotation.to.version,
        wrappedDataKey: wrapped,
        state: 'current',
        rotationId: rotation.id,
        attempt: attemptNo,
      });
      envelope.keyId = rotation.to.keyId;
      envelope.keyVersion = rotation.to.version;
    }
    transition(next, item, 'succeeded', source, alreadyAtTarget ? 'already at target version' : null);
    item.lastError = null;
    item.errorClass = null;
    if (!rotation.done.includes(item.envelopeId)) rotation.done.push(item.envelopeId);
    refreshRotationStatus(next, rotation, source);
    return {envelopeId: item.envelopeId, outcome: 'succeeded', attempt: attemptNo};
  } catch (error) {
    const errorClass = error.errorClass ?? 'internal';
    item.lastError = error.message;
    item.errorClass = errorClass;
    if (rotation.policy.manualConfirmErrors.includes(errorClass)) {
      transition(next, item, 'needs_confirmation', source, error.message);
    } else if (item.attempts >= rotation.policy.maxAttempts) {
      transition(next, item, 'failed', source, error.message);
    } else {
      transition(next, item, 'pending', source, error.message);
    }
    refreshRotationStatus(next, rotation, source);
    return {envelopeId: item.envelopeId, outcome: 'failed', errorClass, error: error.message, attempt: attemptNo};
  }
}

function requireRotation(keyring, rotationId) {
  const rotation = keyring.rotations.find(entry => entry.id === Number(rotationId));
  if (!rotation) throw fail('rotation not found', 404);
  return rotation;
}

function requireItem(rotation, envelopeId) {
  const item = rotation.items.find(entry => entry.envelopeId === envelopeId);
  if (!item) throw fail('rotation item not found', 404);
  return item;
}

export function runBatch(keyring, rotationId, batchSeq) {
  const next = clone(keyring);
  const rotation = requireRotation(next, rotationId);
  const batch = rotation.batches.find(entry => entry.seq === Number(batchSeq));
  if (!batch) throw fail('batch not found', 404);
  const source = `rotation:${rotation.id}/batch:${batch.seq}`;
  const results = [];
  for (const itemId of batch.itemIds) {
    const item = rotation.items.find(entry => entry.id === itemId);
    if (item.status !== 'pending') {
      results.push({envelopeId: item.envelopeId, outcome: 'skipped', status: item.status});
      continue;
    }
    results.push(attemptItem(next, rotation, item, source));
  }
  batch.status = 'done';
  batch.ranSeq = stamp(next);
  rotation.events.push({seq: batch.ranSeq, type: 'batch-run', batch: batch.seq, source});
  refreshRotationStatus(next, rotation, source);
  return {keyring: next, rotation, results};
}

export function retryItem(keyring, rotationId, envelopeId) {
  const next = clone(keyring);
  const rotation = requireRotation(next, rotationId);
  const item = requireItem(rotation, envelopeId);
  if (item.status === 'succeeded') return {keyring: next, rotation, item, noop: true};
  if (item.status === 'needs_confirmation') throw fail('item requires manual confirmation before retry', 409);
  if (item.status === 'processing') throw fail('item is currently processing', 409);
  if (item.status === 'failed' && item.attempts >= rotation.policy.maxAttempts) {
    throw fail('retry budget exhausted under current policy', 409);
  }
  const outcome = attemptItem(next, rotation, item, `rotation:${rotation.id}/retry`);
  return {keyring: next, rotation, item, outcome};
}

export function confirmItem(keyring, rotationId, envelopeId, note = null) {
  const next = clone(keyring);
  const rotation = requireRotation(next, rotationId);
  const item = requireItem(rotation, envelopeId);
  if (item.status !== 'needs_confirmation') throw fail('item is not awaiting confirmation', 409);
  const envelope = next.envelopes.get(item.envelopeId);
  if (envelope && currentWrap(envelope)) item.snapshotWrapSeq = currentWrap(envelope).seq;
  transition(next, item, 'pending', `rotation:${rotation.id}/confirm`, note ?? 'confirmed by operator');
  refreshRotationStatus(next, rotation, `rotation:${rotation.id}/confirm`);
  return {keyring: next, rotation, item};
}

export function updateRotationPolicy(keyring, rotationId, patch = {}) {
  const next = clone(keyring);
  const rotation = requireRotation(next, rotationId);
  if (patch.maxAttempts !== undefined) {
    const maxAttempts = Number(patch.maxAttempts);
    if (!Number.isInteger(maxAttempts) || maxAttempts < 1) throw fail('maxAttempts must be a positive integer');
    rotation.policy.maxAttempts = maxAttempts;
  }
  if (patch.manualConfirmErrors !== undefined) {
    if (!Array.isArray(patch.manualConfirmErrors)) throw fail('manualConfirmErrors must be an array');
    rotation.policy.manualConfirmErrors = [...patch.manualConfirmErrors];
  }
  rotation.events.push({
    seq: stamp(next),
    type: 'policy',
    source: 'api',
    detail: {maxAttempts: rotation.policy.maxAttempts, manualConfirmErrors: rotation.policy.manualConfirmErrors},
  });
  refreshRotationStatus(next, rotation, 'api');
  return next;
}

// Backwards-compatible single-envelope rotation used by the original tests.
export function rotateOne(keyring, rotationId, envelopeId) {
  const next = clone(keyring);
  const rotation = next.rotations.find(entry => entry.id === Number(rotationId));
  const item = rotation?.items.find(entry => entry.envelopeId === envelopeId);
  if (!rotation || !item) throw fail('rotation target missing', 404);
  if (item.status === 'succeeded') return next;
  if (item.status !== 'pending') throw fail(`rotation item is ${item.status}`, 409);
  const outcome = attemptItem(next, rotation, item, `rotation:${rotation.id}/rotateOne`);
  if (outcome.outcome === 'failed') throw fail(outcome.error, 409);
  return next;
}

// Decrypt resolves the envelope's current wrap and unwraps with exactly the
// recorded key version, so historical versions keep working. Key material
// never leaves the server: callers receive a digest of the data key only.
export function decryptEnvelope(keyring, envelopeId) {
  const envelope = keyring.envelopes.get(envelopeId);
  if (!envelope) throw fail('envelope not found', 404);
  const wrap = currentWrap(envelope);
  if (!wrap) throw fail('envelope has no current wrap', 409);
  const version = keyring.keys.get(wrap.keyId)?.versions.get(wrap.keyVersion);
  if (!version) throw fail(`key version ${wrap.keyId}@${wrap.keyVersion} unavailable`, 409);
  let dataKey;
  try {
    dataKey = unwrapDataKey(version.material, wrap.wrappedDataKey);
  } catch {
    throw fail('unwrap failed for current wrap', 409);
  }
  return {
    id: envelope.id,
    digest: envelope.digest,
    keyId: wrap.keyId,
    keyVersion: wrap.keyVersion,
    dataKeyDigest: sha256(dataKey),
  };
}

function publicWrap(wrap) {
  return {
    seq: wrap.seq,
    keyId: wrap.keyId,
    keyVersion: wrap.keyVersion,
    state: wrap.state,
    rotationId: wrap.rotationId,
    attempt: wrap.attempt,
    fingerprint: sha256(wrap.wrappedDataKey).slice(0, 16),
  };
}

export function publicEnvelope(envelope) {
  return {
    id: envelope.id,
    digest: envelope.digest,
    keyId: envelope.keyId,
    keyVersion: envelope.keyVersion,
    createdSeq: envelope.createdSeq,
    wraps: envelope.wraps.map(publicWrap),
  };
}

export function publicRotation(rotation) {
  const items = rotation.items.map(item => ({
    id: item.id,
    envelopeId: item.envelopeId,
    status: item.status,
    attempts: item.attempts,
    lastError: item.lastError,
    errorClass: item.errorClass,
    snapshotWrapSeq: item.snapshotWrapSeq,
    history: item.history,
    actions: {
      retry: item.status === 'pending' || (item.status === 'failed' && item.attempts < rotation.policy.maxAttempts),
      confirm: item.status === 'needs_confirmation',
    },
  }));
  return {
    id: rotation.id,
    from: rotation.from,
    to: rotation.to,
    status: rotation.status,
    policy: rotation.policy,
    batchSize: rotation.batchSize,
    done: [...rotation.done],
    createdSeq: rotation.createdSeq,
    events: rotation.events,
    batches: rotation.batches.map(batch => ({
      seq: batch.seq,
      status: batch.status,
      ranSeq: batch.ranSeq,
      itemIds: batch.itemIds,
      counts: summarizeStatuses(items.filter(item => batch.itemIds.includes(item.id))),
    })),
    items,
  };
}

function summarizeStatuses(items) {
  const counts = {pending: 0, processing: 0, succeeded: 0, failed: 0, needs_confirmation: 0};
  for (const item of items) {
    if (item.status in counts) counts[item.status] += 1;
  }
  return counts;
}

// Sanitized view for browsers: references, statuses, fingerprints and audit
// history only — never key material, data keys or wrapped key blobs.
export function publicView(keyring) {
  return {
    keys: [...keyring.keys.values()].map(key => ({
      id: key.id,
      currentVersion: key.currentVersion,
      createdSeq: key.createdSeq,
      versions: [...key.versions.values()].map(version => ({
        version: version.version,
        status: version.status,
        createdSeq: version.createdSeq,
        fingerprint: sha256(version.material).slice(0, 16),
      })),
    })),
    envelopes: [...keyring.envelopes.values()].map(publicEnvelope),
    rotations: keyring.rotations.map(publicRotation),
  };
}

export function serialize(keyring) {
  return JSON.stringify({
    format: 1,
    seq: keyring.seq,
    keys: [...keyring.keys.values()].map(key => ({...key, versions: [...key.versions.values()]})),
    envelopes: [...keyring.envelopes.values()],
    rotations: keyring.rotations,
  });
}

export function deserialize(text) {
  const raw = JSON.parse(text);
  if (raw.format !== 1) throw fail('unsupported state format');
  return {
    seq: raw.seq,
    keys: new Map(raw.keys.map(key => [key.id, {...key, versions: new Map(key.versions.map(version => [version.version, version]))}])),
    envelopes: new Map(raw.envelopes.map(envelope => [envelope.id, envelope])),
    rotations: raw.rotations,
  };
}
