import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, readFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createApp} from '../server.mjs';

async function startServer(dataFile) {
  const app = createApp(dataFile ? {dataFile} : {});
  await new Promise((resolve, reject) => app.once('listening', resolve).once('error', reject).listen(0, '127.0.0.1'));
  return {app, base: `http://127.0.0.1:${app.address().port}`};
}

function stopServer(server) {
  return new Promise(resolve => server.close(resolve));
}

async function post(base, path, body) {
  const response = await fetch(`${base}${path}`, {method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(body ?? {})});
  return {status: response.status, body: await response.json()};
}

async function get(base, path) {
  const response = await fetch(`${base}${path}`);
  const text = await response.text();
  const type = response.headers.get('content-type');
  let body = null;
  if (type && type.includes('application/json')) body = JSON.parse(text);
  return {status: response.status, type, text, body};
}

test('full rotation review flow over HTTP keeps failure state, retry and historical reads', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'keyring-'));
  const dataFile = join(dir, 'state.json');
  const {app, base} = await startServer(dataFile);
  try {
    assert.equal((await post(base, '/api/keys', {keyId: 'mkv-1'})).status, 201);
    assert.equal((await post(base, '/api/keys', {keyId: 'mkv-2'})).status, 201);
    for (const id of ['env1', 'env2', 'env3']) {
      assert.equal((await post(base, '/api/envelopes', {id, keyId: 'mkv-1', digest: `digest-${id}`})).status, 201);
    }
    const rotation = (await post(base, '/api/rotations', {from: 'mkv-1', to: 'mkv-2'})).body;
    assert.equal(rotation.items.length, 3);
    assert.deepEqual(new Set(rotation.items.map(item => item.status)), new Set(['pending']));

    const firstBatch = (await post(base, '/api/rotations/1/process', {batchSize: 2})).body;
    assert.equal(firstBatch.items.filter(item => item.status === 'in_progress').length, 2);
    const committed = (await post(base, '/api/rotations/1/commit', {})).body;
    assert.equal(committed.items.filter(item => item.status === 'succeeded').length, 2);

    // Current reference of processed envelopes moved; mid-rotation open still works.
    let keyring = (await get(base, '/api/keyring')).body;
    assert.equal(keyring.envelopes.find(entry => entry.id === 'env1').keyId, 'mkv-2');
    assert.equal(keyring.envelopes.find(entry => entry.id === 'env3').keyId, 'mkv-1');

    assert.equal((await post(base, '/api/keys/mkv-2/status', {status: 'disabled'})).status, 200);
    const failed = (await post(base, '/api/rotations/1/process', {batchSize: 2})).body;
    const failedItem = failed.items.find(item => item.envelopeId === 'env3');
    assert.equal(failedItem.status, 'failed');
    assert.match(failedItem.failureReason, /mkv-2 is disabled/);
    assert.equal(failed.status, 'completed_with_failures');

    // Reopening review must show the server-side failure, not stale success.
    keyring = (await get(base, '/api/keyring')).body;
    assert.equal(keyring.rotations[0].items.find(item => item.envelopeId === 'env3').status, 'failed');

    // Change the retry strategy (re-activate the target), retry and commit.
    assert.equal((await post(base, '/api/keys/mkv-2/status', {status: 'active'})).status, 200);
    const retried = (await post(base, '/api/rotations/1/retry', {})).body;
    assert.equal(retried.items.find(item => item.envelopeId === 'env3').status, 'in_progress');
    const completed = (await post(base, '/api/rotations/1/commit', {})).body;
    assert.equal(completed.status, 'completed');
    assert.equal(completed.items.filter(item => item.status === 'succeeded').length, 3);

    // Decrypt with current and with historical key versions.
    const current = (await post(base, '/api/envelopes/env3/open', {})).body;
    assert.deepEqual(current, {id: 'env3', keyVersion: 'mkv-2', digest: 'digest-env3'});
    const historical = (await post(base, '/api/envelopes/env3/open', {keyVersion: 'mkv-1'})).body;
    assert.equal(historical.digest, 'digest-env3');
    assert.equal(historical.keyVersion, 'mkv-1');

    // The browser payload must not contain key material, wrapped data keys or ciphertext.
    const persisted = JSON.parse(await readFile(dataFile, 'utf8'));
    const secrets = [];
    for (const key of persisted.keys) secrets.push(key.material);
    for (const envelope of persisted.envelopes) {
      secrets.push(envelope.ciphertext);
      for (const wrap of envelope.wraps) secrets.push(wrap.wrappedDek);
    }
    const browserText = (await get(base, '/api/keyring')).text;
    for (const secret of secrets) assert.ok(!browserText.includes(secret), 'server leaked secret material to the browser');
    for (const field of ['material', 'wrappedDek', 'ciphertext']) {
      assert.ok(!browserText.includes(field), `snapshot exposes the ${field} field`);
    }
  } finally {
    await stopServer(app);
    await rm(dir, {recursive: true, force: true});
  }
});

test('rotation state survives a server restart and work can continue', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'keyring-restart-'));
  const dataFile = join(dir, 'state.json');
  const first = await startServer(dataFile);
  let seq;
  try {
    await post(first.base, '/api/keys', {keyId: 'mkv-1'});
    await post(first.base, '/api/keys', {keyId: 'mkv-2'});
    await post(first.base, '/api/envelopes', {id: 'env1', keyId: 'mkv-1', digest: 'a'});
    await post(first.base, '/api/envelopes', {id: 'env2', keyId: 'mkv-1', digest: 'b'});
    await post(first.base, '/api/rotations', {from: 'mkv-1', to: 'mkv-2'});
    await post(first.base, '/api/rotations/1/process', {batchSize: 1});
    await post(first.base, '/api/rotations/1/commit', {});
    seq = (await get(first.base, '/api/keyring')).body.seq;
  } finally {
    await stopServer(first.app);
  }
  const second = await startServer(dataFile);
  try {
    const keyring = (await get(second.base, '/api/keyring')).body;
    assert.equal(keyring.seq, seq);
    assert.equal(keyring.envelopes.find(entry => entry.id === 'env1').keyId, 'mkv-2');
    assert.equal(keyring.envelopes.find(entry => entry.id === 'env2').keyId, 'mkv-1');
    await post(second.base, '/api/rotations/1/process', {batchSize: 5});
    await post(second.base, '/api/rotations/1/commit', {});
    const done = (await get(second.base, '/api/keyring')).body.rotations[0];
    assert.equal(done.status, 'completed');
    assert.equal((await post(second.base, '/api/envelopes/env2/open', {})).body.digest, 'b');
  } finally {
    await stopServer(second.app);
    await rm(dir, {recursive: true, force: true});
  }
});

test('needs_review items are resolved through the HTTP API', async () => {
  const {app, base} = await startServer();
  try {
    for (const keyId of ['mkv-1', 'mkv-2', 'mkv-3']) await post(base, '/api/keys', {keyId});
    await post(base, '/api/envelopes', {id: 'env1', keyId: 'mkv-1', digest: 'a'});
    await post(base, '/api/rotations', {from: 'mkv-1', to: 'mkv-2'});
    await post(base, '/api/rotations', {from: 'mkv-1', to: 'mkv-3'});
    await post(base, '/api/rotations/2/process', {batchSize: 1});
    await post(base, '/api/rotations/2/commit', {});
    const conflicted = (await post(base, '/api/rotations/1/process', {batchSize: 1})).body;
    assert.equal(conflicted.items[0].status, 'needs_review');
    const resolved = (await post(base, '/api/rotations/1/items/env1', {action: 'skip'})).body;
    assert.equal(resolved.items[0].status, 'skipped');
    const bad = await post(base, '/api/envelopes', {id: 'x', keyId: 'nope', digest: 'y'});
    assert.equal(bad.status, 400);
    assert.equal((await get(base, '/nope')).status, 404);
  } finally {
    await stopServer(app);
  }
});

test('the browser app and assets are served', async () => {
  const {app, base} = await startServer();
  try {
    const page = await get(base, '/');
    assert.equal(page.status, 200);
    assert.match(page.type, /text\/html/);
    assert.match(page.text, /Envelope rotation review/);
    const script = await get(base, '/app.js');
    assert.equal(script.status, 200);
    assert.match(script.type, /javascript/);
    const styles = await get(base, '/style.css');
    assert.equal(styles.status, 200);
    assert.match(styles.type, /text\/css/);
  } finally {
    await stopServer(app);
  }
});
