import {createServer} from 'node:http';
import {mkdir, readFile, rename, writeFile} from 'node:fs/promises';
import {readFileSync} from 'node:fs';
import {dirname, extname} from 'node:path';
import {createLedger} from './src/envelope-ledger.mjs';

const STATIC_FILES = new Map([['/', 'index.html'], ['/app.js', 'app.js'], ['/style.css', 'style.css']]);
const STATIC_TYPES = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8'};

function loadLedger(dataFile) {
  if (!dataFile) return createLedger();
  try {
    return createLedger(JSON.parse(readFileSync(dataFile, 'utf8')));
  } catch {
    return createLedger();
  }
}

async function persist(dataFile, ledger) {
  if (!dataFile) return;
  const tmp = `${dataFile}.tmp`;
  await mkdir(dirname(dataFile), {recursive: true});
  await writeFile(tmp, JSON.stringify(ledger.toJSON(), null, 2));
  await rename(tmp, dataFile);
}

async function readBody(req) {
  let text = '';
  for await (const part of req) text += part;
  return JSON.parse(text || '{}');
}

function json(res, code, value) {
  res.writeHead(code, {'content-type': 'application/json'});
  res.end(JSON.stringify(value));
}

export function createApp({dataFile} = {}) {
  const ledger = loadLedger(dataFile);

  async function mutate(res, code, fn) {
    let result;
    try {
      result = fn();
    } catch (error) {
      return json(res, 400, {error: error.message});
    }
    try {
      await persist(dataFile, ledger);
    } catch (error) {
      return json(res, 500, {error: `persistence failed: ${error.message}`});
    }
    return json(res, code, result);
  }

  return createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    const segments = url.pathname.split('/').filter(Boolean).map(decodeURIComponent);
    try {
      if (segments[0] === 'api') {
        if (req.method === 'GET' && url.pathname === '/api/keyring') return json(res, 200, ledger.snapshot());
        if (req.method === 'GET' && segments[1] === 'rotations' && segments.length === 3) return json(res, 200, ledger.getRotation(segments[2]));
        if (req.method !== 'POST') return json(res, 404, {error: 'not found'});
        const body = await readBody(req);
        if (segments[1] === 'keys' && segments.length === 2) {
          return mutate(res, 201, () => {
            ledger.addKey(body.keyId);
            return {keys: ledger.snapshot().keys};
          });
        }
        if (segments[1] === 'keys' && segments.length === 4 && segments[3] === 'status') {
          return mutate(res, 200, () => ledger.setKeyStatus(segments[2], body.status));
        }
        if (segments[1] === 'envelopes' && segments.length === 2) {
          return mutate(res, 201, () => ledger.seal(body.id, body.keyId, body.digest));
        }
        if (segments[1] === 'envelopes' && segments.length === 4 && segments[3] === 'open') {
          // Read-only decrypt interface; accepts an optional historical key version.
          return json(res, 200, ledger.open(segments[2], body.keyVersion));
        }
        if (segments[1] === 'rotations' && segments.length === 2) {
          return mutate(res, 201, () => ledger.startRotation(body.from, body.to));
        }
        if (segments[1] === 'rotations' && segments.length === 4 && segments[3] === 'process') {
          return mutate(res, 200, () => ledger.processBatch(segments[2], body.batchSize));
        }
        if (segments[1] === 'rotations' && segments.length === 4 && segments[3] === 'commit') {
          return mutate(res, 200, () => ledger.commitRotation(segments[2], body.envelopeIds));
        }
        if (segments[1] === 'rotations' && segments.length === 4 && segments[3] === 'retry') {
          return mutate(res, 200, () => ledger.retryRotation(segments[2], body.envelopeIds));
        }
        if (segments[1] === 'rotations' && segments.length === 5 && segments[3] === 'items') {
          return mutate(res, 200, () => ledger.resolveItem(segments[2], segments[4], body.action));
        }
        return json(res, 404, {error: 'not found'});
      }
      if (req.method === 'GET' && STATIC_FILES.has(url.pathname)) {
        const file = STATIC_FILES.get(url.pathname);
        const content = await readFile(new URL(`./public/${file}`, import.meta.url));
        res.writeHead(200, {'content-type': STATIC_TYPES[extname(file)] ?? 'application/octet-stream'});
        return res.end(content);
      }
      return json(res, 404, {error: 'not found'});
    } catch (error) {
      return json(res, 400, {error: error.message});
    }
  });
}

const app = createApp({dataFile: process.env.KEYRING_DATA ?? './data/keyring.json'});
if (import.meta.url === `file://${process.argv[1]}`) app.listen(Number(process.env.PORT ?? 4182));
export {app};
