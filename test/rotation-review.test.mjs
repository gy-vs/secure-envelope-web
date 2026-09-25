import test from 'node:test';
import assert from 'node:assert/strict';
import {
  addKey,
  addKeyVersion,
  confirmItem,
  createKeyring,
  decryptEnvelope,
  deserialize,
  retryItem,
  rotateOne,
  runBatch,
  seal,
  serialize,
  setKeyVersionStatus,
  startRotation,
  updateRotationPolicy,
} from '../src/envelope-ledger.mjs';

// Envelopes are always sealed with the key's current version, so tests seal
// first and only then introduce the next key version.
function keyringWithKey() {
  return addKey(createKeyring(), 'mk');
}

function currentWraps(envelope) {
  return envelope.wraps.filter(wrap => wrap.state === 'current');
}

test('wrap success binds the envelope to the target key version exactly once', () => {
  let keyring = keyringWithKey();
  keyring = seal(keyring, 'env', 'mk', 'digest-1');
  const before = decryptEnvelope(keyring, 'env');
  assert.equal(before.keyVersion, 1);

  keyring = addKeyVersion(keyring, 'mk');
  keyring = startRotation(keyring, 'mk@1', 'mk@2', {batchSize: 1});
  const {keyring: rotated} = runBatch(keyring, 1, 1);
  keyring = rotated;

  const envelope = keyring.envelopes.get('env');
  assert.equal(envelope.keyId, 'mk');
  assert.equal(envelope.keyVersion, 2);
  assert.equal(currentWraps(envelope).length, 1);
  assert.equal(envelope.wraps[0].state, 'superseded');
  assert.equal(envelope.wraps[1].state, 'current');
  assert.equal(envelope.wraps[1].rotationId, 1);

  const after = decryptEnvelope(keyring, 'env');
  assert.equal(after.keyVersion, 2);
  assert.equal(after.dataKeyDigest, before.dataKeyDigest, 'same data key, re-wrapped under v2');
});

test('partial failure keeps failed envelopes on the old version and records reasons', () => {
  let keyring = keyringWithKey();
  keyring = seal(keyring, 'e1', 'mk', 'd1');
  keyring = seal(keyring, 'e2', 'mk', 'd2');
  keyring = addKeyVersion(keyring, 'mk');
  keyring = startRotation(keyring, 'mk@1', 'mk@2', {batchSize: 1, maxAttempts: 1});
  keyring = setKeyVersionStatus(keyring, 'mk', 2, 'disabled');

  const first = runBatch(keyring, 1, 1);
  keyring = first.keyring;
  assert.equal(first.results[0].outcome, 'failed');
  assert.equal(first.results[0].errorClass, 'target_key_unavailable');

  let rotation = keyring.rotations[0];
  let item = rotation.items[0];
  assert.equal(item.status, 'failed');
  assert.equal(item.attempts, 1);
  assert.match(item.lastError, /not active/);
  assert.ok(item.history.every(entry => Number.isInteger(entry.seq) && entry.source), 'every transition has seq + source');
  assert.equal(rotation.status, 'running', 'e2 is still pending in batch 2');

  // The old version is still readable while the rotation is stuck.
  const stuck = decryptEnvelope(keyring, 'e1');
  assert.equal(stuck.keyVersion, 1);
  assert.equal(keyring.envelopes.get('e1').keyVersion, 1);
  assert.equal(currentWraps(keyring.envelopes.get('e1')).length, 1);

  // Untouched envelopes keep working too.
  assert.equal(decryptEnvelope(keyring, 'e2').keyVersion, 1);

  keyring = runBatch(keyring, 1, 2).keyring;
  rotation = keyring.rotations[0];
  assert.equal(rotation.items[1].status, 'failed');
  assert.equal(rotation.status, 'attention_required', 'no pending work left, failures remain');

  keyring = setKeyVersionStatus(keyring, 'mk', 2, 'active');
  keyring = updateRotationPolicy(keyring, 1, {maxAttempts: 2});
  const retried = retryItem(keyring, 1, 'e1');
  keyring = retried.keyring;
  assert.equal(retried.item.status, 'succeeded');
  assert.equal(keyring.rotations[0].status, 'attention_required', 'e2 still failed');
  keyring = retryItem(keyring, 1, 'e2').keyring;
  assert.equal(keyring.rotations[0].status, 'completed');
  assert.equal(decryptEnvelope(keyring, 'e1').keyVersion, 2);
});

test('retry is idempotent and never creates competing current wraps', () => {
  let keyring = keyringWithKey();
  keyring = seal(keyring, 'e1', 'mk', 'd1');
  keyring = addKeyVersion(keyring, 'mk');
  keyring = startRotation(keyring, 'mk@1', 'mk@2', {batchSize: 1, maxAttempts: 1});
  keyring = setKeyVersionStatus(keyring, 'mk', 2, 'disabled');
  keyring = runBatch(keyring, 1, 1).keyring;
  assert.equal(keyring.rotations[0].items[0].status, 'failed');

  // The retry budget is exhausted under maxAttempts=1; the operator widens
  // the policy before retrying, mirroring the review workflow.
  assert.throws(() => retryItem(keyring, 1, 'e1'), /budget exhausted/);
  keyring = updateRotationPolicy(keyring, 1, {maxAttempts: 2});
  keyring = setKeyVersionStatus(keyring, 'mk', 2, 'active');
  const first = retryItem(keyring, 1, 'e1');
  keyring = first.keyring;
  assert.equal(first.item.status, 'succeeded');
  const wrapsAfterSuccess = keyring.envelopes.get('e1').wraps.length;

  const again = retryItem(keyring, 1, 'e1');
  assert.equal(again.noop, true, 'retrying a succeeded item is a no-op');
  keyring = again.keyring;
  assert.equal(keyring.envelopes.get('e1').wraps.length, wrapsAfterSuccess);
  assert.equal(currentWraps(keyring.envelopes.get('e1')).length, 1);
  assert.equal(keyring.envelopes.get('e1').wraps.filter(wrap => wrap.keyVersion === 2).length, 1);

  const viaRotateOne = rotateOne(keyring, 1, 'e1');
  assert.equal(viaRotateOne.envelopes.get('e1').wraps.length, wrapsAfterSuccess);
});

test('retry budget follows the policy and policy changes reopen retries', () => {
  let keyring = keyringWithKey();
  keyring = seal(keyring, 'e1', 'mk', 'd1');
  keyring = addKeyVersion(keyring, 'mk');
  keyring = startRotation(keyring, 'mk@1', 'mk@2', {batchSize: 1, maxAttempts: 2});
  keyring = setKeyVersionStatus(keyring, 'mk', 2, 'disabled');

  keyring = runBatch(keyring, 1, 1).keyring;
  assert.equal(keyring.rotations[0].items[0].status, 'pending', 'first failure leaves a retry opportunity');
  assert.equal(keyring.rotations[0].items[0].attempts, 1);

  keyring = runBatch(keyring, 1, 1).keyring;
  assert.equal(keyring.rotations[0].items[0].status, 'failed', 'budget exhausted');
  assert.throws(() => retryItem(keyring, 1, 'e1'), /budget exhausted/);

  keyring = updateRotationPolicy(keyring, 1, {maxAttempts: 4});
  keyring = setKeyVersionStatus(keyring, 'mk', 2, 'active');
  const retried = retryItem(keyring, 1, 'e1');
  assert.equal(retried.item.status, 'succeeded');
  assert.equal(retried.item.attempts, 3);
});

test('re-sealing mid-rotation requires manual confirmation before retry', () => {
  let keyring = keyringWithKey();
  keyring = seal(keyring, 'e1', 'mk', 'd1');
  keyring = addKeyVersion(keyring, 'mk');
  keyring = startRotation(keyring, 'mk@1', 'mk@2', {batchSize: 1});
  keyring = seal(keyring, 'e1', 'mk', 'd1-resealed'); // advances the current wrap past the snapshot

  const {keyring: ran} = runBatch(keyring, 1, 1);
  keyring = ran;
  const item = keyring.rotations[0].items[0];
  assert.equal(item.status, 'needs_confirmation');
  assert.equal(item.errorClass, 'source_version_changed');
  assert.throws(() => retryItem(keyring, 1, 'e1'), /manual confirmation/);

  const confirmed = confirmItem(keyring, 1, 'e1', 'operator verified the re-seal');
  keyring = confirmed.keyring;
  assert.equal(confirmed.item.status, 'pending');
  assert.equal(confirmed.item.history.at(-1).reason, 'operator verified the re-seal');

  const retried = retryItem(keyring, 1, 'e1');
  keyring = retried.keyring;
  assert.equal(retried.item.status, 'succeeded');
  const envelope = keyring.envelopes.get('e1');
  assert.equal(currentWraps(envelope).length, 1);
  assert.equal(envelope.keyVersion, 2, 're-seal already landed on the target version');
});

test('a corrupted wrap routes to manual confirmation with its error class', () => {
  let keyring = keyringWithKey();
  keyring = seal(keyring, 'e1', 'mk', 'd1');
  keyring.envelopes.get('e1').wraps[0].wrappedDataKey = 'AAAA corrupted blob';
  keyring = addKeyVersion(keyring, 'mk');
  keyring = startRotation(keyring, 'mk@1', 'mk@2', {batchSize: 1});
  const {keyring: ran} = runBatch(keyring, 1, 1);
  const item = ran.rotations[0].items[0];
  assert.equal(item.status, 'needs_confirmation');
  assert.equal(item.errorClass, 'unwrap_failed');
  assert.equal(ran.envelopes.get('e1').keyVersion, 1, 'failed wrap never replaces the current reference');
});

test('a second rotation cannot compete for an envelope mid-rotation', () => {
  let keyring = keyringWithKey();
  keyring = seal(keyring, 'e1', 'mk', 'd1');
  keyring = addKeyVersion(keyring, 'mk');
  keyring = startRotation(keyring, 'mk@1', 'mk@2');
  assert.throws(() => startRotation(keyring, 'mk@1', 'mk@2'), /unfinished rotation/);
  keyring = runBatch(keyring, 1, 1).keyring;
  const again = startRotation(keyring, 'mk@1', 'mk@2');
  assert.equal(again.rotations.at(-1).items.length, 0, 'completed rotation releases the envelope');
});

test('state survives a serialize/deserialize round trip with history intact', () => {
  let keyring = keyringWithKey();
  keyring = seal(keyring, 'e1', 'mk', 'd1');
  keyring = seal(keyring, 'e2', 'mk', 'd2');
  keyring = addKeyVersion(keyring, 'mk');
  keyring = startRotation(keyring, 'mk@1', 'mk@2', {batchSize: 1});
  keyring = runBatch(keyring, 1, 1).keyring;
  const digestBefore = decryptEnvelope(keyring, 'e1').dataKeyDigest;

  const restored = deserialize(serialize(keyring));
  assert.equal(restored.seq, keyring.seq);
  assert.equal(restored.rotations[0].status, keyring.rotations[0].status);
  assert.deepEqual(restored.rotations[0].items[0].history, keyring.rotations[0].items[0].history);
  assert.equal(decryptEnvelope(restored, 'e1').dataKeyDigest, digestBefore);
  assert.equal(decryptEnvelope(restored, 'e2').keyVersion, 1, 'historical version still readable after reload');
});
