import test from 'node:test';
import assert from 'node:assert/strict';
import {applySnapshot, createViewState, currentRotation, rotationItems, selectRotation} from '../public/app.js';

function snapshotAt(seq, status) {
  return {
    seq,
    keys: [],
    envelopes: [],
    rotations: [{id: 1, from: 'mkv-1', to: 'mkv-2', status: 'running', counts: {}, items: [{envelopeId: 'env1', status, attempts: 0, failureReason: null, updatedSeq: seq}]}],
    events: [],
  };
}

test('a fresh page shows no task results until the server answers', () => {
  const view = createViewState();
  assert.equal(view.snapshot, null);
  assert.deepEqual(rotationItems(view), []);
  assert.equal(currentRotation(view), null);
});

test('an older response never overwrites a newer server snapshot', () => {
  let view = createViewState();
  view = applySnapshot(view, snapshotAt(1, 'pending'));
  view = selectRotation(view, 1);
  view = applySnapshot(view, snapshotAt(2, 'in_progress'));
  view = applySnapshot(view, snapshotAt(3, 'failed'));
  // Simulate a delayed/replayed response for an older revision arriving late.
  view = applySnapshot(view, snapshotAt(2, 'in_progress'));
  assert.equal(view.seq, 3);
  assert.equal(rotationItems(view)[0].status, 'failed');
  // The same revision can be applied again (idempotent re-render).
  const reapplied = applySnapshot(view, snapshotAt(3, 'failed'));
  assert.equal(reapplied.seq, 3);
  // Malformed responses are ignored.
  assert.equal(applySnapshot(view, null).seq, 3);
  assert.equal(applySnapshot(view, {}).seq, 3);
});

test('switching batches reads items only from the newest snapshot', () => {
  const both = {
    seq: 4,
    keys: [],
    envelopes: [],
    rotations: [
      {id: 1, from: 'a', to: 'b', status: 'completed', counts: {}, items: [{envelopeId: 'env1', status: 'failed', attempts: 1, failureReason: 'old', updatedSeq: 2}]},
      {id: 2, from: 'a', to: 'c', status: 'completed', counts: {}, items: [{envelopeId: 'env2', status: 'succeeded', attempts: 1, failureReason: null, updatedSeq: 4}]},
    ],
    events: [],
  };
  let view = applySnapshot(createViewState(), both);
  view = selectRotation(view, 1);
  assert.equal(rotationItems(view)[0].envelopeId, 'env1');
  view = selectRotation(view, 2);
  assert.equal(rotationItems(view)[0].status, 'succeeded');
  // A stale response from batch #1's time cannot revert the selected view.
  view = applySnapshot(view, {seq: 2, keys: [], envelopes: [], rotations: [both.rotations[0]], events: []});
  assert.equal(view.snapshot.seq, 4);
  assert.equal(currentRotation(view).id, 2);
  assert.equal(rotationItems(view)[0].status, 'succeeded');
});

test('reopening the page starts empty and adopts the latest server state', () => {
  const serverState = snapshotAt(7, 'succeeded');
  let view = createViewState();
  view = applySnapshot(view, serverState);
  view = selectRotation(view, 1);
  assert.equal(rotationItems(view)[0].status, 'succeeded');
  // Reopening: a brand new view carries nothing over; one fresh fetch wins.
  const reopened = applySnapshot(createViewState(), snapshotAt(7, 'succeeded'));
  assert.equal(reopened.seq, 7);
  assert.equal(currentRotation(reopened), null);
  assert.equal(selectRotation(reopened, 1) && rotationItems(selectRotation(reopened, 1))[0].status, 'succeeded');
});
