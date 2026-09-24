import {createServer} from 'node:http';
import {addKey, createKeyring, rotateOne, seal, startRotation} from './src/envelope-ledger.mjs';
let keyring = createKeyring();
async function body(req) { let text = ''; for await (const part of req) text += part; return JSON.parse(text || '{}'); }
function json(res, code, value) { res.writeHead(code, {'content-type': 'application/json'}); res.end(JSON.stringify(value)); }
const app = createServer(async (req, res) => { const url = new URL(req.url ?? '/', 'http://localhost'); try { if (url.pathname === '/api/keys' && req.method === 'POST') { keyring = addKey(keyring, (await body(req)).keyId); return json(res, 201, {keys: [...keyring.keys]}); } if (url.pathname === '/api/envelopes' && req.method === 'POST') { const item = await body(req); keyring = seal(keyring, item.id, item.keyId, item.digest); return json(res, 201, keyring.envelopes.get(item.id)); } if (url.pathname === '/api/rotations' && req.method === 'POST') { const item = await body(req); keyring = startRotation(keyring, item.from, item.to); return json(res, 201, keyring.rotations.at(-1)); } if (url.pathname === '/api/keyring') return json(res, 200, {keys: [...keyring.keys], envelopes: [...keyring.envelopes.values()], rotations: keyring.rotations}); return json(res, 404, {error: 'not found'}); } catch (error) { return json(res, 400, {error: error.message}); } });
if (import.meta.url === `file://${process.argv[1]}`) app.listen(Number(process.env.PORT ?? 4182));
export {app};
