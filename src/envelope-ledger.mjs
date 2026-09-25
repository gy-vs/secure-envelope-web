import {createCipheriv, createDecipheriv, randomBytes} from 'node:crypto';

// Rotation item lifecycle: pending -> in_progress -> succeeded | failed | needs_review
// failed -> (retry) -> in_progress ... ; needs_review -> (retry|skip) -> in_progress | skipped
export const ITEM_STATUSES = ['pending', 'in_progress', 'succeeded', 'failed', 'needs_review', 'skipped'];
const KEY_STATUSES = new Set(['active', 'disabled']);

// A data key is wrapped with AES-256-GCM under a master key version. The wrapped
// payload is bound to that exact key material: unwrapping with any other version
// fails the GCM auth tag check.
export function wrapDataKey(dek, material) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', material, iv);
  const sealed = Buffer.concat([cipher.update(dek), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), sealed]).toString('base64');
}

export function unwrapDataKey(payload, material) {
  const raw = Buffer.from(payload, 'base64');
  const decipher = createDecipheriv('aes-256-gcm', material, raw.subarray(0, 12));
  decipher.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]);
}

function currentWrap(envelope) {
  return envelope.wraps.find(wrap => wrap.wrapId === envelope.currentWrapId);
}

function keyView(key) {
  return {version: key.version, status: key.status, createdSeq: key.createdSeq};
}

function wrapView(wrap) {
  return {wrapId: wrap.wrapId, keyVersion: wrap.keyVersion, state: wrap.state, rotationId: wrap.rotationId, createdSeq: wrap.createdSeq};
}

function envelopeView(envelope) {
  const current = currentWrap(envelope);
  return {id: envelope.id, keyId: current.keyVersion, currentWrapId: current.wrapId, wraps: envelope.wraps.map(wrapView)};
}

function itemView(item) {
  return {envelopeId: item.envelopeId, status: item.status, attempts: item.attempts, failureReason: item.failureReason, updatedSeq: item.updatedSeq};
}

function rotationStatusOf(rotation) {
  const items = [...rotation.items.values()];
  if (items.some(item => item.status === 'pending' || item.status === 'in_progress')) return 'running';
  if (items.some(item => item.status === 'failed' || item.status === 'needs_review')) return 'completed_with_failures';
  return 'completed';
}

function rotationView(rotation) {
  const items = [...rotation.items.values()].map(itemView);
  const counts = {};
  for (const item of items) counts[item.status] = (counts[item.status] ?? 0) + 1;
  return {id: rotation.id, from: rotation.from, to: rotation.to, status: rotationStatusOf(rotation), createdSeq: rotation.createdSeq, counts, items};
}

function hydrate(saved) {
  return {
    seq: saved.seq ?? 0,
    wrapSeq: saved.wrapSeq ?? 0,
    keys: new Map((saved.keys ?? []).map(key => [key.version, {...key, material: Buffer.from(key.material, 'base64')}])),
    envelopes: new Map((saved.envelopes ?? []).map(envelope => [envelope.id, {...envelope, wraps: envelope.wraps.map(wrap => ({...wrap}))}])),
    rotations: (saved.rotations ?? []).map(rotation => ({...rotation, items: new Map((rotation.items ?? []).map(item => [item.envelopeId, {...item}]))})),
    events: (saved.events ?? []).map(event => ({...event})),
  };
}

export function createLedger(saved) {
  const state = saved ? hydrate(saved) : {seq: 0, wrapSeq: 0, keys: new Map(), envelopes: new Map(), rotations: [], events: []};

  // Every state transition goes through here and is recorded with a monotonic
  // sequence number. Nothing in the ledger derives completion from wall-clock
  // time; the event log is the source of truth for how state was reached.
  function transition(type, detail = {}) {
    state.seq += 1;
    state.events.push({seq: state.seq, type, ...detail});
    return state.seq;
  }

  function findRotation(rotationId) {
    const rotation = state.rotations.find(entry => entry.id === Number(rotationId));
    if (!rotation) throw new Error(`rotation ${rotationId} missing`);
    return rotation;
  }

  function updateRotationStatus(rotation) {
    const status = rotationStatusOf(rotation);
    if (status !== rotation.status) {
      rotation.status = status;
      transition('rotation_status_changed', {rotationId: rotation.id, status});
    }
  }

  function addKey(keyId) {
    if (!keyId || typeof keyId !== 'string') throw new Error('key id required');
    if (state.keys.has(keyId)) throw new Error(`key version ${keyId} already exists`);
    const key = {version: keyId, status: 'active', material: randomBytes(32), createdSeq: 0};
    key.createdSeq = transition('key_added', {keyVersion: keyId});
    state.keys.set(keyId, key);
    return keyView(key);
  }

  function setKeyStatus(keyId, status) {
    const key = state.keys.get(keyId);
    if (!key) throw new Error(`unknown key version ${keyId}`);
    if (!KEY_STATUSES.has(status)) throw new Error(`unsupported key status ${status}`);
    if (key.status === status) return keyView(key);
    key.status = status;
    transition('key_status_changed', {keyVersion: keyId, status});
    return keyView(key);
  }

  function seal(id, keyId, digest) {
    const key = state.keys.get(keyId);
    if (!key) throw new Error(`unknown key version ${keyId}`);
    if (key.status !== 'active') throw new Error(`key version ${keyId} is ${key.status}`);
    if (!id || typeof id !== 'string') throw new Error('envelope id required');
    if (state.envelopes.has(id)) throw new Error(`envelope ${id} already exists`);
    if (!digest || typeof digest !== 'string') throw new Error('digest required');
    const dek = randomBytes(32);
    const seq = transition('envelope_sealed', {envelopeId: id, keyVersion: keyId});
    const wrap = {wrapId: ++state.wrapSeq, keyVersion: keyId, wrappedDek: wrapDataKey(dek, key.material), state: 'current', rotationId: null, createdSeq: seq};
    const envelope = {id, ciphertext: wrapDataKey(Buffer.from(digest, 'utf8'), dek), wraps: [wrap], currentWrapId: wrap.wrapId};
    state.envelopes.set(id, envelope);
    return envelopeView(envelope);
  }

  // Decrypt compatibility interface: without a version it uses the current wrap;
  // with an explicit version it reads a historical (superseded) wrap, so data
  // sealed under older key versions stays openable after rotation.
  function open(id, keyVersion) {
    const envelope = state.envelopes.get(id);
    if (!envelope) throw new Error(`unknown envelope ${id}`);
    const wrap = keyVersion
      ? envelope.wraps.find(entry => entry.keyVersion === keyVersion && (entry.state === 'current' || entry.state === 'superseded'))
      : currentWrap(envelope);
    if (!wrap) throw new Error(`no wrap for key version ${keyVersion}`);
    const key = state.keys.get(wrap.keyVersion);
    if (!key) throw new Error(`unknown key version ${wrap.keyVersion}`);
    const dek = unwrapDataKey(wrap.wrappedDek, key.material);
    return {id, keyVersion: wrap.keyVersion, digest: unwrapDataKey(envelope.ciphertext, dek).toString('utf8')};
  }

  function startRotation(from, to) {
    if (!state.keys.has(from)) throw new Error(`source key version ${from} missing`);
    if (!state.keys.has(to)) throw new Error(`target key version ${to} missing`);
    if (from === to) throw new Error('source and target key versions must differ');
    const rotation = {id: state.rotations.length + 1, from, to, status: 'running', createdSeq: 0, items: new Map()};
    for (const envelope of state.envelopes.values()) {
      if (currentWrap(envelope).keyVersion === from) {
        rotation.items.set(envelope.id, {envelopeId: envelope.id, status: 'pending', attempts: 0, failureReason: null, baseWrapId: null, candidateWrapId: null, updatedSeq: 0});
      }
    }
    if (rotation.items.size === 0) rotation.status = 'completed';
    rotation.createdSeq = transition('rotation_started', {rotationId: rotation.id, from, to, itemCount: rotation.items.size});
    state.rotations.push(rotation);
    return rotationView(rotation);
  }

  // Phase 1 of an item: build the candidate wrap under the target version. The
  // envelope's current reference is NOT replaced here; that only happens in
  // commitItem once the new wrap exists and the base reference is unchanged.
  function processItem(rotation, item) {
    const envelope = state.envelopes.get(item.envelopeId);
    if (!envelope) throw new Error(`envelope ${item.envelopeId} missing`);
    item.attempts += 1;
    if (item.status === 'failed') transition('rotation_item_requeued', {rotationId: rotation.id, envelopeId: envelope.id, attempt: item.attempts});
    item.status = 'in_progress';
    item.failureReason = null;
    item.updatedSeq = transition('rotation_item_processing', {rotationId: rotation.id, envelopeId: envelope.id, attempt: item.attempts});
    // A retry abandons the stale candidate from the previous attempt so an
    // envelope never accumulates competing candidates from the same rotation.
    for (const wrap of envelope.wraps) {
      if (wrap.state === 'candidate' && wrap.rotationId === rotation.id) {
        wrap.state = 'abandoned';
        transition('wrap_abandoned', {rotationId: rotation.id, envelopeId: envelope.id, wrapId: wrap.wrapId});
      }
    }
    item.candidateWrapId = null;
    const finish = (status, reason, type, extra = {}) => {
      item.status = status;
      item.failureReason = reason;
      item.updatedSeq = transition(type, {rotationId: rotation.id, envelopeId: envelope.id, ...(reason ? {reason} : {}), ...extra});
    };
    const target = state.keys.get(rotation.to);
    if (!target) return finish('failed', `target key version ${rotation.to} is missing`, 'rotation_item_failed');
    if (target.status !== 'active') return finish('failed', `target key version ${rotation.to} is ${target.status}`, 'rotation_item_failed');
    const source = state.keys.get(rotation.from);
    if (!source) return finish('failed', `source key version ${rotation.from} is missing`, 'rotation_item_failed');
    const current = currentWrap(envelope);
    if (current.keyVersion === rotation.to) {
      // Already on the target version (e.g. another rotation committed it):
      // succeed without creating a competing wrap.
      item.baseWrapId = current.wrapId;
      return finish('succeeded', null, 'rotation_item_succeeded', {alreadyOnTarget: true});
    }
    if (current.keyVersion !== rotation.from) {
      return finish('needs_review', `current version is ${current.keyVersion}; expected ${rotation.from}`, 'rotation_item_needs_review');
    }
    const foreign = envelope.wraps.find(wrap => wrap.state === 'candidate');
    if (foreign) return finish('needs_review', `candidate wrap from rotation ${foreign.rotationId} is in flight`, 'rotation_item_needs_review');
    let dek;
    try {
      dek = unwrapDataKey(current.wrappedDek, source.material);
    } catch {
      return finish('failed', `cannot unwrap data key with ${rotation.from}`, 'rotation_item_failed');
    }
    const seq = transition('wrap_prepared', {rotationId: rotation.id, envelopeId: envelope.id, keyVersion: rotation.to});
    const candidate = {wrapId: ++state.wrapSeq, keyVersion: rotation.to, wrappedDek: wrapDataKey(dek, target.material), state: 'candidate', rotationId: rotation.id, createdSeq: seq};
    envelope.wraps.push(candidate);
    item.baseWrapId = current.wrapId;
    item.candidateWrapId = candidate.wrapId;
    item.updatedSeq = seq;
  }

  // Phase 2 of an item: replace the current reference with the prepared
  // candidate, but only if the reference we read in phase 1 is still current.
  function commitItem(rotation, item) {
    const envelope = state.envelopes.get(item.envelopeId);
    const candidate = envelope.wraps.find(wrap => wrap.wrapId === item.candidateWrapId && wrap.state === 'candidate');
    if (!candidate) {
      item.status = 'needs_review';
      item.failureReason = 'candidate wrap is missing';
      item.updatedSeq = transition('rotation_item_needs_review', {rotationId: rotation.id, envelopeId: envelope.id, reason: item.failureReason});
      return;
    }
    const current = currentWrap(envelope);
    if (current.wrapId !== item.baseWrapId) {
      item.status = 'needs_review';
      item.failureReason = `current version changed to ${current.keyVersion} while rotation ${rotation.id} was in flight`;
      item.updatedSeq = transition('rotation_item_needs_review', {rotationId: rotation.id, envelopeId: envelope.id, reason: item.failureReason});
      return;
    }
    current.state = 'superseded';
    candidate.state = 'current';
    envelope.currentWrapId = candidate.wrapId;
    transition('wrap_committed', {rotationId: rotation.id, envelopeId: envelope.id, wrapId: candidate.wrapId, from: current.keyVersion, to: candidate.keyVersion});
    item.status = 'succeeded';
    item.failureReason = null;
    item.updatedSeq = transition('rotation_item_succeeded', {rotationId: rotation.id, envelopeId: envelope.id});
  }

  function processBatch(rotationId, batchSize = 1) {
    const rotation = findRotation(rotationId);
    const size = Number.isInteger(batchSize) && batchSize > 0 ? batchSize : 1;
    let processed = 0;
    for (const item of rotation.items.values()) {
      if (processed >= size) break;
      if (item.status !== 'pending') continue;
      processItem(rotation, item);
      processed += 1;
    }
    updateRotationStatus(rotation);
    return rotationView(rotation);
  }

  function commitRotation(rotationId, envelopeIds) {
    const rotation = findRotation(rotationId);
    const filter = Array.isArray(envelopeIds) ? new Set(envelopeIds) : null;
    for (const item of rotation.items.values()) {
      if (item.status !== 'in_progress' || item.candidateWrapId == null) continue;
      if (filter && !filter.has(item.envelopeId)) continue;
      commitItem(rotation, item);
    }
    updateRotationStatus(rotation);
    return rotationView(rotation);
  }

  // Retry gives failed items another attempt and re-wraps in-progress items.
  // Succeeded and skipped items are left untouched, so retrying an already
  // finished rotation is a no-op and can never create a second current wrap.
  function retryRotation(rotationId, envelopeIds) {
    const rotation = findRotation(rotationId);
    const filter = Array.isArray(envelopeIds) ? new Set(envelopeIds) : null;
    for (const item of rotation.items.values()) {
      if (filter && !filter.has(item.envelopeId)) continue;
      if (item.status === 'failed' || (item.status === 'in_progress' && item.candidateWrapId != null)) {
        processItem(rotation, item);
      }
    }
    updateRotationStatus(rotation);
    return rotationView(rotation);
  }

  function resolveItem(rotationId, envelopeId, action) {
    const rotation = findRotation(rotationId);
    const item = rotation.items.get(envelopeId);
    if (!item) throw new Error(`rotation ${rotation.id} has no item for envelope ${envelopeId}`);
    if (item.status !== 'needs_review') throw new Error(`item for envelope ${envelopeId} is ${item.status}, not needs_review`);
    if (action === 'skip') {
      const envelope = state.envelopes.get(envelopeId);
      for (const wrap of envelope.wraps) {
        if (wrap.state === 'candidate' && wrap.rotationId === rotation.id) {
          wrap.state = 'abandoned';
          transition('wrap_abandoned', {rotationId: rotation.id, envelopeId, wrapId: wrap.wrapId});
        }
      }
      item.status = 'skipped';
      item.updatedSeq = transition('rotation_item_skipped', {rotationId: rotation.id, envelopeId});
    } else if (action === 'retry') {
      item.status = 'pending';
      item.updatedSeq = transition('rotation_item_requeued', {rotationId: rotation.id, envelopeId, attempt: item.attempts + 1});
      processItem(rotation, item);
    } else {
      throw new Error(`unsupported action ${action}`);
    }
    updateRotationStatus(rotation);
    return rotationView(rotation);
  }

  function getRotation(rotationId) {
    return rotationView(findRotation(rotationId));
  }

  // Browser-facing view: key versions, envelope/wrap references, rotation items
  // and the transition log. Key material, wrapped data keys and ciphertext are
  // deliberately excluded.
  function snapshot() {
    return {
      seq: state.seq,
      keys: [...state.keys.values()].map(keyView),
      envelopes: [...state.envelopes.values()].map(envelopeView),
      rotations: state.rotations.map(rotationView),
      events: state.events.map(event => ({...event})),
    };
  }

  function toJSON() {
    return {
      seq: state.seq,
      wrapSeq: state.wrapSeq,
      keys: [...state.keys.values()].map(key => ({version: key.version, status: key.status, material: key.material.toString('base64'), createdSeq: key.createdSeq})),
      envelopes: [...state.envelopes.values()].map(envelope => ({id: envelope.id, ciphertext: envelope.ciphertext, currentWrapId: envelope.currentWrapId, wraps: envelope.wraps.map(wrap => ({...wrap}))})),
      rotations: state.rotations.map(rotation => ({id: rotation.id, from: rotation.from, to: rotation.to, status: rotation.status, createdSeq: rotation.createdSeq, items: [...rotation.items.values()].map(item => ({...item}))})),
      events: state.events.map(event => ({...event})),
    };
  }

  function invariants() {
    const problems = [];
    for (const envelope of state.envelopes.values()) {
      const currents = envelope.wraps.filter(wrap => wrap.state === 'current');
      if (currents.length !== 1) problems.push(`envelope ${envelope.id} has ${currents.length} current wraps`);
      if (currents[0] && currents[0].wrapId !== envelope.currentWrapId) problems.push(`envelope ${envelope.id} currentWrapId does not match its current wrap`);
      const candidates = envelope.wraps.filter(wrap => wrap.state === 'candidate');
      if (candidates.length > 1) problems.push(`envelope ${envelope.id} has ${candidates.length} candidate wraps`);
    }
    return problems;
  }

  return {addKey, setKeyStatus, seal, open, startRotation, processBatch, commitRotation, retryRotation, resolveItem, getRotation, snapshot, toJSON, invariants};
}
