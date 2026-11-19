// End-to-end smoke test against a running worker:  npm run dev  →  node test/e2e.mjs [baseUrl]
import assert from 'node:assert/strict';
import { SoftAuthenticator } from './soft-authenticator.mjs';

const BASE = process.argv[2] || 'http://localhost:8787';
const rpId = new URL(BASE).hostname;
const tag = Date.now().toString(36);

const post = async (path, body, headers = {}) => {
  const r = await fetch(BASE + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });
  return { status: r.status, headers: r.headers, json: await r.json() };
};

async function registerPasskey(username, emoji) {
  const auth = new SoftAuthenticator(rpId, BASE);
  const begin = await post('/webauthn/register/begin', { username });
  const done = await post('/webauthn/register/complete', { ...(await auth.create(begin.json)), username, emoji });
  assert.equal(done.json.success, true, JSON.stringify(done.json));
  return auth;
}

async function login(auth, username) {
  const opts = await post('/webauthn/authenticate/begin', username ? { username } : {});
  return post('/webauthn/authenticate/complete', { ...(await auth.get(opts.json)), ...(username ? { username } : {}) });
}

function socket() {
  const ws = new WebSocket(BASE.replace(/^http/, 'ws') + '/ws');
  const inbox = [];
  const waiters = [];
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data);
    const i = waiters.findIndex((w) => w.pred(m));
    if (i >= 0) waiters.splice(i, 1)[0].resolve(m); else inbox.push(m);
  };
  const next = (pred) => {
    const i = inbox.findIndex(pred);
    if (i >= 0) return Promise.resolve(inbox.splice(i, 1)[0]);
    return new Promise((resolve, reject) => {
      waiters.push({ pred, resolve });
      setTimeout(() => reject(new Error('timeout waiting for ws message')), 5000);
    });
  };
  return new Promise((res) => { ws.onopen = () => res({ ws, next, send: (o) => ws.send(JSON.stringify(o)) }); });
}

// 1. Static + generated assets
for (const [p, type] of [['/', 'text/html'], ['/chat.js', 'javascript'], ['/static/style.css', 'text/css'],
  ['/manifest.json', 'application/json'], ['/admin', 'text/html'], ['/icons/apple-icon-180x180.png', 'image/png']]) {
  const r = await fetch(BASE + p);
  assert.equal(r.status, 200, p);
  assert.ok(r.headers.get('content-type').includes(type), `${p}: ${r.headers.get('content-type')}`);
}
assert.equal((await fetch(BASE + '/admin/panel.html')).status, 404);
console.log('✅ static + icons + admin gating');

// 2. Passkey registration + usernameless login
const alice = `alice-${tag}`;
const aliceAuth = await registerPasskey(alice, '🦊');
assert.deepEqual((await login(aliceAuth)).json, { success: true, username: alice });
console.log('✅ passkey register + login');

// 3. Chat over WebSocket
const a = await socket();
a.send({ type: 'join', username: alice, emoji: '🦊' });
const roomList = await a.next((m) => m.type === 'roomList');
assert.equal(roomList.userEmoji, '🦊');
const joined = await a.next((m) => m.type === 'roomJoined');
assert.equal(joined.room.name, 'Lobby');

const b = await socket();
b.send({ type: 'join', username: `bob-${tag}` });
await b.next((m) => m.type === 'roomJoined');

a.send({ type: 'sendMessage', roomId: joined.room.id, content: `hello ${tag}` });
const got = await b.next((m) => m.type === 'chatMessage' && m.message.content === `hello ${tag}`);
assert.equal(got.message.sender, alice);
assert.equal(got.message.emoji, '🦊');

a.send({ type: 'createRoom', name: `Room ${tag}` });
const created = await b.next((m) => m.type === 'roomCreated');
assert.equal(created.room.name, `Room ${tag}`);
a.send({ type: 'createRoom', name: 'lobby' });
assert.equal((await a.next((m) => m.type === 'error')).message, 'A room with this name already exists');
a.send({ type: 'ping' });
await a.next((m) => m.type === 'pong');
console.log('✅ websocket chat (join, message broadcast, rooms, ping)');

// 4. File upload + file message + download
const form = new FormData();
form.append('file', new Blob(['hello file'], { type: 'text/plain' }), 'hello.txt');
const up = await (await fetch(BASE + '/upload', { method: 'POST', body: form })).json();
assert.equal(up.success, true, JSON.stringify(up));
a.send({ type: 'sendFileMessage', roomId: joined.room.id, attachment: { id: up.attachment.id }, caption: '' });
const fileMsg = await b.next((m) => m.type === 'chatMessage' && m.message.attachment);
assert.equal(fileMsg.message.messageType, 'file');
assert.equal(await (await fetch(BASE + fileMsg.message.attachment.url)).text(), 'hello file');
console.log('✅ upload + file message + download');

// 5. Emoji colour analysis
const colors = await post('/emoji/analyze', { emoji: '🦊' });
console.log(colors.json.success ? `✅ emoji analyze ${JSON.stringify(colors.json)}` : `⚠️ emoji analyze unavailable: ${colors.json.error}`);

// 6. Admin: register configured admin, login, list users
const adminName = 'XCF Admin';
const check = await post('/webauthn/username/check', { username: adminName });
if (check.json.available) {
  const adminAuth = await registerPasskey(adminName, '👑');
  const opts = await post('/webauthn/authenticate/begin', { username: adminName });
  const loginRes = await post('/admin/api/login', { ...(await adminAuth.get(opts.json)), username: adminName });
  assert.equal(loginRes.json.success, true, JSON.stringify(loginRes.json));
  const cookie = loginRes.headers.get('set-cookie').split(';')[0];
  assert.equal((await fetch(BASE + '/admin/panel.html', { headers: { cookie } })).status, 200);
  const users = await (await fetch(BASE + '/admin/api/users', { headers: { cookie } })).json();
  const aliceRow = users.find((u) => u.username === alice);
  assert.ok(aliceRow && aliceRow.emoji === '🦊');
  const toggle = await post(`/admin/api/users/${encodeURIComponent(aliceRow.credentialId)}/toggle`, { enabled: false }, { cookie });
  assert.equal(toggle.json.success, true);
  assert.equal((await login(aliceAuth)).json.error, 'Access denied');
  console.log('✅ admin passkey login, panel, users API, disable user');
} else {
  console.log('ℹ️ admin already registered on this server — skipped admin flow');
}

a.ws.close(); b.ws.close();
console.log('🎉 all e2e checks passed');
