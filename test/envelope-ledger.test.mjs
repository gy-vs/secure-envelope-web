import test from 'node:test';
import assert from 'node:assert/strict';
import {Buffer} from 'node:buffer';
import {createLedger, unwrapDataKey} from '../src/envelope-ledger.mjs';

function seededLedger() {
  const ledger = createLedger();
  ledger.addKey('mkv-1');
  ledger.addKey('mkv-2');
  ledger.addKey('mkv-3');
  return ledger;
}

test('sealing with an unknown or disabled key is rejected', () => {
  const ledger = createLedger();
  assert.throws(() => ledger.seal('env', 'missing', 'x'), /unknown key version/);
  ledger.addKey('mkv-1');
  ledger.setKeyStatus('mkv-1', 'disabled');
  assert.throws(() => ledger.seal('env', 'mkv-1', 'x'), /disabled/);
});

test('an envelope is cryptographically bound to the key version that wrapped its data key', () => {
  const ledger = seededLedger();
  ledger.seal('env1', 'mkv-1', 'digest-one');
  assert.deepEqual(ledger.open('env1'), {id: 'env1', keyVersion: 'mkv-1', digest: 'digest-one'});
  assert.throws(() => ledger.open('env1', 'mkv-2'), /no wrap for key version/);
  const stored = ledger.toJSON();
  const envelope = stored.envelopes.find(entry => entry.id === 'env1');
  const wrap = envelope.wraps[0];
  assert.equal(wrap.keyVersion, 'mkv-1');
  const mkv1 = stored.keys.find(key => key.version === 'mkv-1');
  const mkv2 = stored.keys.find(key => key.version === 'mkv-2');
  // The wrapping key opens the data key; the other version must not.
  assert.ok(unwrapDataKey(wrap.wrappedDek, Buffer.from(mkv1.material, 'base64')));
  assert.throws(() => unwrapDataKey(wrap.wrappedDek, Buffer.from(mkv2.material, 'base64')));
});

test('a rotation only enlists envelopes whose current wrap uses the source version', () => {
  const ledger = seededLedger();
  ledger.seal('env-a', 'mkv-1', 'a');
  ledger.seal('env-b', 'mkv-1', 'b');
  ledger.seal('env-c', 'mkv-3', 'c');
  const rotation = ledger.startRotation('mkv-1', 'mkv-2');
  assert.deepEqual(rotation.items.map(item => item.envelopeId).sort(), ['env-a', 'env-b']);
  assert.throws(() => ledger.startRotation('mkv-1', 'mkv-9'), /target key version/);
  assert.throws(() => ledger.startRotation('mkv-9', 'mkv-2'), /source key version/);
});

test('the candidate wrap completes before the current reference is replaced', () => {
  const ledger = seededLedger();
  ledger.seal('env1', 'mkv-1', 'digest-one');
  const rotation = ledger.startRotation('mkv-1', 'mkv-2');
  ledger.processBatch(rotation.id, 1);
  const view = ledger.snapshot();
  const envelope = view.envelopes.find(entry => entry.id === 'env1');
  // Phase 1: candidate exists, current reference still points at mkv-1.
  assert.equal(envelope.keyId, 'mkv-1');
  assert.ok(envelope.wraps.some(wrap => wrap.state === 'candidate' && wrap.keyVersion === 'mkv-2'));
  assert.equal(rotationView(ledger, rotation.id).items[0].status, 'in_progress');
  // Old version stays readable mid-rotation.
  assert.equal(ledger.open('env1').keyVersion, 'mkv-1');
  // Phase 2: commit swaps the reference and retires the old wrap.
  ledger.commitRotation(rotation.id);
  const committed = ledger.snapshot().envelopes.find(entry => entry.id === 'env1');
  assert.equal(committed.keyId, 'mkv-2');
  assert.deepEqual(committed.wraps.map(wrap => wrap.state), ['superseded', 'current']);
  assert.deepEqual(ledger.invariants(), []);
});

test('historical key versions remain readable after the new version becomes current', () => {
  const ledger = seededLedger();
  ledger.seal('env1', 'mkv-1', 'digest-one');
  const rotation = ledger.startRotation('mkv-1', 'mkv-2');
  ledger.processBatch(rotation.id, 1);
  ledger.commitRotation(rotation.id);
  assert.equal(ledger.open('env1').keyVersion, 'mkv-2');
  assert.equal(ledger.open('env1', 'mkv-1').digest, 'digest-one');
  // Disabled keys can still decrypt historical data, just not wrap new data.
  ledger.setKeyStatus('mkv-1', 'disabled');
  assert.equal(ledger.open('env1', 'mkv-1').digest, 'digest-one');
});

test('a partial failure keeps the reason and a retry chance; retry then completes', () => {
  const ledger = seededLedger();
  ledger.seal('env1', 'mkv-1', 'a');
  ledger.seal('env2', 'mkv-1', 'b');
  ledger.seal('env3', 'mkv-1', 'c');
  const rotation = ledger.startRotation('mkv-1', 'mkv-2');
  ledger.processBatch(rotation.id, 2);
  ledger.commitRotation(rotation.id);
  // Simulate the target version going down mid-rotation.
  ledger.setKeyStatus('mkv-2', 'disabled');
  ledger.processBatch(rotation.id, 2);
  const failedView = rotationView(ledger, rotation.id);
  assert.equal(failedView.status, 'completed_with_failures');
  const failedItem = failedView.items.find(item => item.envelopeId === 'env3');
  assert.equal(failedItem.status, 'failed');
  assert.match(failedItem.failureReason, /mkv-2 is disabled/);
  assert.equal(failedItem.attempts, 1);
  // Repair the key (retry strategy change), retry, then commit.
  ledger.setKeyStatus('mkv-2', 'active');
  ledger.retryRotation(rotation.id);
  assert.equal(rotationView(ledger, rotation.id).items.find(item => item.envelopeId === 'env3').status, 'in_progress');
  ledger.commitRotation(rotation.id);
  const done = rotationView(ledger, rotation.id);
  assert.equal(done.status, 'completed');
  assert.equal(done.items.find(item => item.envelopeId === 'env3').attempts, 2);
  assert.equal(ledger.open('env3').keyVersion, 'mkv-2');
  assert.equal(ledger.open('env3', 'mkv-1').digest, 'c');
  assert.deepEqual(ledger.invariants(), []);
});

test('retry is idempotent and never creates competing current wraps', () => {
  const ledger = seededLedger();
  ledger.seal('env1', 'mkv-1', 'a');
  const rotation = ledger.startRotation('mkv-1', 'mkv-2');
  ledger.processBatch(rotation.id, 1);
  ledger.commitRotation(rotation.id);
  const seqAfterCompletion = ledger.snapshot().seq;
  const wrapsAfterCompletion = ledger.snapshot().envelopes[0].wraps.length;
  // No failed or in-progress items: retry, process and commit are no-ops.
  ledger.retryRotation(rotation.id);
  ledger.processBatch(rotation.id, 1);
  ledger.commitRotation(rotation.id);
  assert.equal(ledger.snapshot().seq, seqAfterCompletion);
  const envelope = ledger.snapshot().envelopes[0];
  assert.equal(envelope.wraps.length, wrapsAfterCompletion);
  assert.equal(envelope.wraps.filter(wrap => wrap.state === 'current').length, 1);
  assert.equal(envelope.keyId, 'mkv-2');
});

test('a rotation that finds an unexpected current version needs manual confirmation', () => {
  const ledger = seededLedger();
  ledger.seal('env1', 'mkv-1', 'a');
  const rotationA = ledger.startRotation('mkv-1', 'mkv-2');
  const rotationB = ledger.startRotation('mkv-1', 'mkv-3');
  ledger.processBatch(rotationB.id, 1);
  ledger.commitRotation(rotationB.id); // another task moves env1 first
  ledger.processBatch(rotationA.id, 1);
  const item = rotationView(ledger, rotationA.id).items[0];
  assert.equal(item.status, 'needs_review');
  assert.match(item.failureReason, /current version is mkv-3; expected mkv-1/);
  // Retrying before the conflict is really resolved stays in review; the
  // operator confirms a skip and the task closes.
  ledger.resolveItem(rotationA.id, 'env1', 'retry');
  assert.equal(rotationView(ledger, rotationA.id).items[0].status, 'needs_review');
  ledger.resolveItem(rotationA.id, 'env1', 'skip');
  assert.equal(rotationView(ledger, rotationA.id).status, 'completed');
  assert.deepEqual(ledger.invariants(), []);
});

test('an envelope already moved to the target version succeeds without a new wrap', () => {
  const ledger = seededLedger();
  ledger.seal('env1', 'mkv-1', 'a');
  const first = ledger.startRotation('mkv-1', 'mkv-2');
  const duplicate = ledger.startRotation('mkv-1', 'mkv-2');
  ledger.processBatch(first.id, 1);
  ledger.commitRotation(first.id);
  const wrapsBefore = ledger.snapshot().envelopes[0].wraps.length;
  ledger.processBatch(duplicate.id, 1);
  assert.equal(rotationView(ledger, duplicate.id).items[0].status, 'succeeded');
  assert.equal(ledger.snapshot().envelopes[0].wraps.length, wrapsBefore);
  assert.equal(ledger.snapshot().envelopes[0].wraps.filter(wrap => wrap.state === 'current').length, 1);
});

test('every state transition has a strictly ordered event log entry', () => {
  const ledger = seededLedger();
  ledger.seal('env1', 'mkv-1', 'a');
  const rotation = ledger.startRotation('mkv-1', 'mkv-2');
  ledger.processBatch(rotation.id, 1);
  ledger.commitRotation(rotation.id);
  const events = ledger.snapshot().events;
  assert.deepEqual(events.map(event => event.seq), events.map((_, index) => index + 1));
  const commit = events.find(event => event.type === 'wrap_committed');
  assert.ok(commit);
  assert.equal(commit.rotationId, rotation.id);
  assert.equal(commit.envelopeId, 'env1');
  assert.equal(commit.from, 'mkv-1');
  assert.equal(commit.to, 'mkv-2');
  const committed = events.find(event => event.type === 'rotation_item_succeeded');
  assert.ok(committed.seq > commit.seq);
  const envelope = ledger.snapshot().envelopes[0];
  assert.ok(events.some(event => event.seq === envelope.wraps[1].createdSeq && event.type === 'wrap_prepared'));
  const statusChanges = events.filter(event => event.type === 'rotation_status_changed');
  assert.ok(statusChanges.some(event => event.status === 'completed'));
});

test('state survives persistence and keeps both retry and historical reads working', () => {
  const ledger = seededLedger();
  ledger.seal('env1', 'mkv-1', 'a');
  ledger.seal('env2', 'mkv-1', 'b');
  const rotation = ledger.startRotation('mkv-1', 'mkv-2');
  ledger.processBatch(rotation.id, 1);
  ledger.commitRotation(rotation.id);
  ledger.setKeyStatus('mkv-2', 'disabled');
  ledger.processBatch(rotation.id, 1);
  const restored = createLedger(ledger.toJSON());
  assert.deepEqual(restored.snapshot(), ledger.snapshot());
  restored.setKeyStatus('mkv-2', 'active');
  restored.retryRotation(rotation.id);
  restored.commitRotation(rotation.id);
  assert.equal(rotationView(restored, rotation.id).status, 'completed');
  assert.equal(restored.open('env2').digest, 'b');
  assert.equal(restored.open('env2', 'mkv-1').digest, 'b');
});

function rotationView(ledger, id) {
  return ledger.getRotation(id);
}
