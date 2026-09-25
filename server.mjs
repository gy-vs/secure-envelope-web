import {createServer} from 'node:http';
import {existsSync, mkdirSync, readFileSync, renameSync, writeFileSync} from 'node:fs';
import {dirname, join, normalize} from 'node:path';
import {fileURLToPath} from 'node:url';
import {
  addKey,
  addKeyVersion,
  confirmItem,
  createKeyring,
  decryptEnvelope,
  deserialize,
  publicEnvelope,
  publicRotation,
  publicView,
  retryItem,
  runBatch,
  seal,
  serialize,
  setKeyVersionStatus,
  startRotation,
  updateRotationPolicy,
} from './src/envelope-ledger.mjs';

const root = dirname(fileURLToPath(import.meta.url));
const publicDir = join(root, 'public');
const defaultDataFile = join(root, 'data', 'keyring.json');

const staticTypes = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
};

async function body(req) {
  let text = '';
  for await (const part of req) text += part;
  return JSON.parse(text || '{}');
}

function json(res, code, value) {
  res.writeHead(code, {'content-type': 'application/json; charset=utf-8'});
  res.end(JSON.stringify(value));
}

export function createApp({dataFile = process.env.ENVELOPE_DATA_FILE ?? defaultDataFile} = {}) {
  let keyring = existsSync(dataFile) ? deserialize(readFileSync(dataFile, 'utf8')) : createKeyring();

  function persist() {
    mkdirSync(dirname(dataFile), {recursive: true});
    const tmp = `${dataFile}.tmp`;
    writeFileSync(tmp, serialize(keyring));
    renameSync(tmp, dataFile);
  }

  function apply(next) {
    if (next !== keyring) {
      keyring = next;
      persist();
    }
    return keyring;
  }

  return createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const path = url.pathname;
    try {
      if (path === '/api/keys' && req.method === 'POST') {
        const item = await body(req);
        apply(addKey(keyring, item.keyId));
        return json(res, 201, publicView(keyring).keys.at(-1));
      }
      const versionMatch = path.match(/^\/api\/keys\/([^/]+)\/versions$/);
      if (versionMatch && req.method === 'POST') {
        apply(addKeyVersion(keyring, decodeURIComponent(versionMatch[1])));
        return json(res, 201, publicView(keyring).keys.find(key => key.id === decodeURIComponent(versionMatch[1])));
      }
      const statusMatch = path.match(/^\/api\/keys\/([^/]+)\/versions\/(\d+)\/status$/);
      if (statusMatch && req.method === 'POST') {
        const item = await body(req);
        apply(setKeyVersionStatus(keyring, decodeURIComponent(statusMatch[1]), Number(statusMatch[2]), item.status));
        return json(res, 200, publicView(keyring).keys.find(key => key.id === decodeURIComponent(statusMatch[1])));
      }
      if (path === '/api/envelopes' && req.method === 'POST') {
        const item = await body(req);
        apply(seal(keyring, item.id, item.keyId, item.digest));
        return json(res, 201, publicEnvelope(keyring.envelopes.get(item.id)));
      }
      const envelopeMatch = path.match(/^\/api\/envelopes\/([^/]+)$/);
      if (envelopeMatch && req.method === 'GET') {
        const envelope = keyring.envelopes.get(decodeURIComponent(envelopeMatch[1]));
        if (!envelope) return json(res, 404, {error: 'envelope not found'});
        return json(res, 200, publicEnvelope(envelope));
      }
      const decryptMatch = path.match(/^\/api\/envelopes\/([^/]+)\/decrypt$/);
      if (decryptMatch && req.method === 'POST') {
        return json(res, 200, decryptEnvelope(keyring, decodeURIComponent(decryptMatch[1])));
      }
      if (path === '/api/rotations' && req.method === 'POST') {
        const item = await body(req);
        apply(startRotation(keyring, item.from, item.to, item));
        return json(res, 201, publicRotation(keyring.rotations.at(-1)));
      }
      const rotationMatch = path.match(/^\/api\/rotations\/(\d+)$/);
      if (rotationMatch && req.method === 'GET') {
        const rotation = keyring.rotations.find(entry => entry.id === Number(rotationMatch[1]));
        if (!rotation) return json(res, 404, {error: 'rotation not found'});
        return json(res, 200, publicRotation(rotation));
      }
      const policyMatch = path.match(/^\/api\/rotations\/(\d+)\/policy$/);
      if (policyMatch && (req.method === 'PATCH' || req.method === 'POST')) {
        apply(updateRotationPolicy(keyring, Number(policyMatch[1]), await body(req)));
        return json(res, 200, publicRotation(keyring.rotations.find(entry => entry.id === Number(policyMatch[1]))));
      }
      const batchMatch = path.match(/^\/api\/rotations\/(\d+)\/batches\/(\d+)\/run$/);
      if (batchMatch && req.method === 'POST') {
        const result = runBatch(keyring, Number(batchMatch[1]), Number(batchMatch[2]));
        apply(result.keyring);
        return json(res, 200, {rotation: publicRotation(result.rotation), results: result.results});
      }
      const retryMatch = path.match(/^\/api\/rotations\/(\d+)\/items\/([^/]+)\/retry$/);
      if (retryMatch && req.method === 'POST') {
        const result = retryItem(keyring, Number(retryMatch[1]), decodeURIComponent(retryMatch[2]));
        apply(result.keyring);
        return json(res, 200, {rotation: publicRotation(result.rotation), noop: result.noop === true});
      }
      const confirmMatch = path.match(/^\/api\/rotations\/(\d+)\/items\/([^/]+)\/confirm$/);
      if (confirmMatch && req.method === 'POST') {
        const item = await body(req);
        const result = confirmItem(keyring, Number(confirmMatch[1]), decodeURIComponent(confirmMatch[2]), item.note);
        apply(result.keyring);
        return json(res, 200, {rotation: publicRotation(result.rotation)});
      }
      if (path === '/api/keyring' && req.method === 'GET') {
        return json(res, 200, publicView(keyring));
      }
      if (req.method === 'GET' && !path.startsWith('/api/')) {
        const relative = path === '/' ? 'index.html' : normalize(path).replace(/^[/\\]+/, '');
        const file = join(publicDir, relative);
        if (!file.startsWith(publicDir) || !existsSync(file)) return json(res, 404, {error: 'not found'});
        const type = staticTypes[file.slice(file.lastIndexOf('.'))] ?? 'application/octet-stream';
        res.writeHead(200, {'content-type': type});
        return res.end(readFileSync(file));
      }
      return json(res, 404, {error: 'not found'});
    } catch (error) {
      return json(res, error.statusCode ?? 400, {error: error.message});
    }
  });
}

export const app = createApp();

if (import.meta.url === `file://${process.argv[1]}`) {
  app.listen(Number(process.env.PORT ?? 4182));
}
