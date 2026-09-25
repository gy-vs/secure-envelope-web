import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync, rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createApp} from '../server.mjs';

const bodies = [];

async function request(port, method, path, payload) {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: {'content-type': 'application/json'},
    body: payload === undefined ? undefined : JSON.stringify(payload),
  });
  const text = await response.text();
  bodies.push(text);
  return {status: response.status, json: text ? JSON.parse(text) : null};
}

async function listen(app) {
  await new Promise(resolve => app.listen(0, '127.0.0.1', resolve));
  return app.address().port;
}

function close(app) {
  return new Promise(resolve => app.close(resolve));
}

test('rotation review scenario: partial failure, policy change, reopen', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'envelope-rotation-'));
  const dataFile = join(dir, 'keyring.json');
  t.after(() => rmSync(dir, {recursive: true, force: true}));

  let app = createApp({dataFile});
  let port = await listen(app);
  t.after(async () => {
    await close(app).catch(() => {});
  });

  // 1. Create a master key and several envelopes, then a second key version.
  let result = await request(port, 'POST', '/api/keys', {keyId: 'mk'});
  assert.equal(result.status, 201);
  for (const [id, digest] of [['e1', 'd1'], ['e2', 'd2'], ['e3', 'd3'], ['e4', 'd4']]) {
    result = await request(port, 'POST', '/api/envelopes', {id, keyId: 'mk', digest});
    assert.equal(result.status, 201);
    assert.equal(result.json.keyVersion, 1);
  }
  result = await request(port, 'POST', '/api/keys/mk/versions');
  assert.equal(result.status, 201);
  assert.equal(result.json.currentVersion, 2);

  // 2. Start a tracked rotation mk@1 -> mk@2 in two batches, one attempt each.
  result = await request(port, 'POST', '/api/rotations', {from: 'mk@1', to: 'mk@2', batchSize: 2, maxAttempts: 1});
  assert.equal(result.status, 201);
  assert.equal(result.json.status, 'pending');
  assert.equal(result.json.items.length, 4);
  assert.equal(result.json.batches.length, 2);

  // 3. First batch succeeds.
  result = await request(port, 'POST', '/api/rotations/1/batches/1/run');
  assert.deepEqual(result.json.results.map(entry => entry.outcome), ['succeeded', 'succeeded']);
  assert.equal(result.json.rotation.status, 'running');

  // 4. Simulate a mid-rotation incident: e4 gets re-sealed, then the target
  //    key version is disabled before batch 2 runs.
  result = await request(port, 'POST', '/api/envelopes', {id: 'e4', keyId: 'mk', digest: 'd4-resealed'});
  assert.equal(result.json.keyVersion, 2);
  result = await request(port, 'POST', '/api/keys/mk/versions/2/status', {status: 'disabled'});
  assert.equal(result.status, 200);

  result = await request(port, 'POST', '/api/rotations/1/batches/2/run');
  assert.equal(result.status, 200);
  const items = Object.fromEntries(result.json.rotation.items.map(item => [item.envelopeId, item]));
  assert.equal(items.e3.status, 'failed');
  assert.equal(items.e3.errorClass, 'target_key_unavailable');
  assert.match(items.e3.lastError, /not active/);
  assert.equal(items.e3.actions.retry, false, 'budget exhausted under maxAttempts=1');
  assert.equal(items.e4.status, 'needs_confirmation');
  assert.equal(items.e4.errorClass, 'source_version_changed');
  assert.equal(items.e4.actions.confirm, true);
  assert.equal(result.json.rotation.status, 'attention_required');

  // 5. Old versions remain readable while the rotation is stuck.
  const stuckDecrypt = await request(port, 'POST', '/api/envelopes/e3/decrypt');
  assert.equal(stuckDecrypt.status, 200);
  assert.equal(stuckDecrypt.json.keyVersion, 1);
  const rotatedDecrypt = await request(port, 'POST', '/api/envelopes/e1/decrypt');
  assert.equal(rotatedDecrypt.json.keyVersion, 2);

  // 6. A needs_confirmation item cannot be retried before confirmation.
  result = await request(port, 'POST', '/api/rotations/1/items/e4/retry');
  assert.equal(result.status, 409);
  assert.match(result.json.error, /manual confirmation/);

  // 7. Operator adjusts the retry policy, re-enables the target version.
  result = await request(port, 'PATCH', '/api/rotations/1/policy', {maxAttempts: 3});
  assert.equal(result.status, 200);
  assert.equal(result.json.policy.maxAttempts, 3);
  const e3AfterPolicy = result.json.items.find(item => item.envelopeId === 'e3');
  assert.equal(e3AfterPolicy.actions.retry, true, 'policy change reopens the retry opportunity');
  await request(port, 'POST', '/api/keys/mk/versions/2/status', {status: 'active'});

  // 8. Retry e3 twice: the second retry is a no-op, no competing current wrap.
  result = await request(port, 'POST', '/api/rotations/1/items/e3/retry');
  assert.equal(result.status, 200);
  assert.equal(result.json.rotation.items.find(item => item.envelopeId === 'e3').status, 'succeeded');
  result = await request(port, 'POST', '/api/rotations/1/items/e3/retry');
  assert.equal(result.json.noop, true);
  const view = await request(port, 'GET', '/api/keyring');
  const e3 = view.json.envelopes.find(envelope => envelope.id === 'e3');
  assert.equal(e3.wraps.filter(wrap => wrap.state === 'current').length, 1);
  assert.equal(e3.wraps.filter(wrap => wrap.keyVersion === 2).length, 1);

  // 9. Confirm e4, then retry: it already sits on the target version, so the
  //    retry succeeds without adding another wrap.
  result = await request(port, 'POST', '/api/rotations/1/items/e4/confirm', {note: 're-seal verified'});
  assert.equal(result.status, 200);
  result = await request(port, 'POST', '/api/rotations/1/items/e4/retry');
  assert.equal(result.json.rotation.status, 'completed');
  const e4 = result.json.rotation.items.find(item => item.envelopeId === 'e4');
  assert.equal(e4.status, 'succeeded');
  const e4View = view.json.envelopes.find(envelope => envelope.id === 'e4');
  assert.equal(e4View.wraps.filter(wrap => wrap.state === 'current').length, 1);

  // 10. The data key survived the whole journey: same digest before/after.
  const e3DecryptAfter = await request(port, 'POST', '/api/envelopes/e3/decrypt');
  assert.equal(e3DecryptAfter.json.keyVersion, 2);
  assert.equal(e3DecryptAfter.json.dataKeyDigest, stuckDecrypt.json.dataKeyDigest);

  // 11. Every recorded transition carries a sequence number and a source.
  const finalRotation = (await request(port, 'GET', '/api/rotations/1')).json;
  for (const item of finalRotation.items) {
    assert.ok(item.history.length >= 2);
    for (const entry of item.history) {
      assert.ok(Number.isInteger(entry.seq), 'transition stamped');
      assert.ok(entry.source, 'transition has an explicit source');
    }
  }

  // 12. Reopen the review: a fresh server over the same data file must serve
  //     identical state — the browser never relies on its own memory.
  const beforeReopen = (await request(port, 'GET', '/api/rotations/1')).json;
  await close(app);
  app = createApp({dataFile});
  port = await listen(app);
  const afterReopen = await request(port, 'GET', '/api/rotations/1');
  assert.deepEqual(afterReopen.json, beforeReopen);
  const reopenedView = await request(port, 'GET', '/api/keyring');
  assert.ok(reopenedView.json.envelopes.every(envelope => envelope.keyVersion === 2));
  const reopenedDecrypt = await request(port, 'POST', '/api/envelopes/e3/decrypt');
  assert.equal(reopenedDecrypt.json.dataKeyDigest, stuckDecrypt.json.dataKeyDigest);
});

test('unknown keys and envelopes are rejected without leaking state', async t => {
  const dir = mkdtempSync(join(tmpdir(), 'envelope-errors-'));
  t.after(() => rmSync(dir, {recursive: true, force: true}));
  const app = createApp({dataFile: join(dir, 'keyring.json')});
  const port = await listen(app);
  t.after(() => close(app));

  let result = await request(port, 'POST', '/api/envelopes', {id: 'x', keyId: 'ghost', digest: 'd'});
  assert.equal(result.status, 404);
  assert.match(result.json.error, /unknown key/);
  result = await request(port, 'POST', '/api/envelopes/nope/decrypt');
  assert.equal(result.status, 404);
  result = await request(port, 'POST', '/api/rotations', {from: 'a@1', to: 'b@1'});
  assert.equal(result.status, 404);
});

test.after(() => {
  const leaked = bodies.filter(text =>
    text.includes('material') || text.includes('wrappedDataKey') || /\bdataKey\b/.test(text));
  assert.deepEqual(leaked, [], `key material must never reach API responses:\n${leaked.join('\n')}`);
});
