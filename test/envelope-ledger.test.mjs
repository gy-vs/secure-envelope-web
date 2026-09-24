import test from 'node:test';
import assert from 'node:assert/strict';
import {addKey, createKeyring, rotateOne, seal, startRotation} from '../src/envelope-ledger.mjs';
test('rotation changes an envelope only when a target key exists', () => { let keyring = addKey(addKey(createKeyring(), 'old'), 'new'); keyring = seal(keyring, 'env1', 'old', 'digest'); keyring = startRotation(keyring, 'old', 'new'); keyring = rotateOne(keyring, 1, 'env1'); assert.equal(keyring.envelopes.get('env1').keyId, 'new'); });
test('sealing with an unknown key is rejected', () => { assert.throws(() => seal(createKeyring(), 'env', 'missing', 'x'), /unknown/); });
