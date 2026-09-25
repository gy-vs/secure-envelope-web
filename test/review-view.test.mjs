import test from 'node:test';
import assert from 'node:assert/strict';
import {
  batchItems,
  createViewGuard,
  keyRef,
  rotationStatusLabel,
  statusLabel,
  summarizeItems,
} from '../public/review-view.mjs';

const rotation = {
  id: 1,
  status: 'running',
  batches: [
    {seq: 1, itemIds: ['1:e1', '1:e2']},
    {seq: 2, itemIds: ['1:e3']},
  ],
  items: [
    {id: '1:e1', envelopeId: 'e1', status: 'succeeded'},
    {id: '1:e2', envelopeId: 'e2', status: 'failed'},
    {id: '1:e3', envelopeId: 'e3', status: 'needs_confirmation'},
  ],
};

test('the five review states map to distinct labels', () => {
  assert.equal(statusLabel('pending'), '待处理');
  assert.equal(statusLabel('processing'), '进行中');
  assert.equal(statusLabel('succeeded'), '成功');
  assert.equal(statusLabel('failed'), '失败');
  assert.equal(statusLabel('needs_confirmation'), '需要人工确认');
  assert.equal(rotationStatusLabel('attention_required'), '需要处理');
});

test('summaries count each of the five states from the server payload', () => {
  assert.deepEqual(summarizeItems(rotation.items), {
    pending: 0,
    processing: 0,
    succeeded: 1,
    failed: 1,
    needs_confirmation: 1,
  });
});

test('switching batches shows exactly the items of the selected batch', () => {
  assert.deepEqual(batchItems(rotation, 1).map(item => item.envelopeId), ['e1', 'e2']);
  assert.deepEqual(batchItems(rotation, 2).map(item => item.envelopeId), ['e3']);
  assert.deepEqual(batchItems(rotation, 99), []);
});

test('the view guard discards stale responses after a newer request', () => {
  const guard = createViewGuard();
  const first = guard.next();
  const second = guard.next();
  assert.equal(guard.isCurrent(first), false, 'an older fetch must not overwrite newer state');
  assert.equal(guard.isCurrent(second), true);
  const third = guard.next();
  assert.equal(guard.isCurrent(second), false);
  assert.equal(guard.isCurrent(third), true);
});

test('key references render as keyId@version', () => {
  assert.equal(keyRef('mk', 2), 'mk@2');
});
