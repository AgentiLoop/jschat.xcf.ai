// Unit tests for the WebAuthn port (no Cloudflare runtime needed).
import test from 'node:test';
import assert from 'node:assert/strict';
import { WebAuthnManager } from '../src/webauthn/manager.js';
import { WebAuthnServer } from '../src/webauthn/server.js';
import { SoftAuthenticator } from './soft-authenticator.mjs';

const memoryStore = () => {
  const m = new Map();
  return { loadAll: () => [...m.values()], put: (c) => m.set(c.username, c), delete: (u) => m.delete(u) };
};

const post = (server, path, body, ua = 'Mozilla/5.0 Chrome/140') =>
  server.handleRequest(new Request(`https://jschat.xcf.ai${path}`, {
    method: 'POST', headers: { 'content-type': 'application/json', 'user-agent': ua }, body: JSON.stringify(body),
  })).then(async (r) => ({ status: r.status, json: await r.json() }));

test('passkey register + authenticate round trip (incl. Android endpoint)', async () => {
  const manager = new WebAuthnManager({ rpId: 'jschat.xcf.ai', store: memoryStore(), adminUsername: 'XCF Admin' });
  const server = new WebAuthnServer(manager);
  const auth = new SoftAuthenticator('jschat.xcf.ai', 'https://jschat.xcf.ai');

  assert.equal((await post(server, '/webauthn/username/check', { username: 'alice' })).json.available, true);

  const begin = await post(server, '/webauthn/register/begin/android', { username: 'alice' });
  assert.equal(begin.status, 200);
  assert.equal(begin.json.publicKey.authenticatorSelection.userVerification, 'preferred');

  const cred = await auth.create(begin.json);
  const done = await post(server, '/webauthn/register/complete', { ...cred, username: 'alice', emoji: '🦊' });
  assert.deepEqual(done.json, { success: true, message: 'Registration successful' });
  assert.equal(manager.getUserEmoji('alice'), '🦊');
  assert.equal(manager.getCredential('alice').userNumber, 1);

  const dup = await post(server, '/webauthn/register/complete', { ...cred, username: 'alice' });
  assert.equal(dup.json.error, 'Registration verification failed: Username already exists');

  // usernameless (discoverable) login
  const opts = await post(server, '/webauthn/authenticate/begin', {});
  assert.deepEqual(opts.json.publicKey.allowCredentials, []);
  const assertion = await auth.get(opts.json);
  const login = await post(server, '/webauthn/authenticate/complete', assertion);
  assert.deepEqual(login.json, { success: true, username: 'alice' });
  assert.equal(manager.getCredential('alice').signCount, 1); // platform authenticator: 0 → own counter

  // username login with allowCredentials
  const opts2 = await post(server, '/webauthn/authenticate/begin', { username: 'alice' });
  assert.equal(opts2.json.publicKey.allowCredentials.length, 1);
  const login2 = await post(server, '/webauthn/authenticate/complete', { ...(await auth.get(opts2.json)), username: 'alice' });
  assert.deepEqual(login2.json, { success: true, username: 'alice' });
});

test('rejects wrong origin, tampered signature, disabled user', async () => {
  const manager = new WebAuthnManager({ rpId: 'jschat.xcf.ai', store: memoryStore() });
  const server = new WebAuthnServer(manager);
  const evil = new SoftAuthenticator('jschat.xcf.ai', 'https://evil.example');
  const begin = await post(server, '/webauthn/register/begin', { username: 'bob' });
  const bad = await post(server, '/webauthn/register/complete', { ...(await evil.create(begin.json)), username: 'bob' });
  assert.equal(bad.status, 400);

  const auth = new SoftAuthenticator('jschat.xcf.ai', 'https://jschat.xcf.ai');
  await post(server, '/webauthn/register/complete', { ...(await auth.create(begin.json)), username: 'bob' });
  const opts = await post(server, '/webauthn/authenticate/begin', {});
  const a = await auth.get(opts.json);
  const sig = Buffer.from(a.response.signature, 'base64'); sig[sig.length - 1] ^= 1;
  a.response.signature = sig.toString('base64');
  assert.equal((await post(server, '/webauthn/authenticate/complete', a)).json.error, 'Credential verification failed');

  manager.updateUserEnabledStatus('bob', false);
  const r = await post(server, '/webauthn/authenticate/complete', await auth.get(opts.json));
  assert.equal(r.json.error, 'Access denied');
});

test('admin username is auto-promoted on registration', async () => {
  const manager = new WebAuthnManager({ rpId: 'localhost', store: memoryStore(), adminUsername: 'XCF Admin' });
  const server = new WebAuthnServer(manager);
  const auth = new SoftAuthenticator('localhost', 'http://localhost:8787');
  const begin = await post(server, '/webauthn/register/begin', { username: 'XCF Admin' }, 'Safari');
  assert.equal(begin.json.publicKey.authenticatorSelection.residentKey, 'required');
  await post(server, '/webauthn/register/complete', { ...(await auth.create(begin.json)), username: 'XCF Admin' });
  assert.equal(manager.getCredential('XCF Admin').isAdmin, true);
});
