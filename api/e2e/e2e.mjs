// End-to-end against a running stack (bin/run.sh). Run: node api/test/e2e.mjs
import assert from 'node:assert/strict';
import { openDb, sha256, token, now } from '../src/db.js';
import mqtt from 'mqtt';

const API = process.env.API || 'http://127.0.0.1:3020';
const db = openDb(new URL('../../data/iot.db', import.meta.url).pathname);
const USER = 'e2euser';
db.prepare('INSERT OR IGNORE INTO users (user_id, created) VALUES (?,?)').run(USER, now());
const sess = token(32);
db.prepare('INSERT INTO sessions VALUES (?,?,?)').run(sha256(sess), USER, now() + 600);
const H = { 'content-type': 'application/json', cookie: `iot_session=${sess}` };
const call = async (m, p, b, h = H) => {
  const r = await fetch(API + p, { method: m, headers: h, body: b ? JSON.stringify(b) : undefined });
  return { status: r.status, body: await r.json() };
};
const connect = (url, o) => new Promise((res, rej) => {
  const c = mqtt.connect(url, { ...o, reconnectPeriod: 0, protocolVersion: 4 });
  c.once('connect', () => res(c)); c.once('error', rej);
});

// unauthenticated is rejected
assert.equal((await call('GET', '/api/devices', null, {})).status, 401);

const created = await call('POST', '/api/devices', { name: 'Desk lamp', type: 'switch' });
assert.equal(created.status, 200);
const dev = created.body;
assert.equal((await call('POST', '/api/devices', { name: 'x', type: 'nope' })).status, 400);

const paired = await call('POST', '/api/pair', { code: dev.pairing.code }, { 'content-type': 'application/json' });
assert.equal(paired.status, 200, JSON.stringify(paired.body));
assert.equal((await call('POST', '/api/pair', { code: dev.pairing.code }, { 'content-type': 'application/json' })).status, 400, 'code is single use');
const cred = paired.body;

// device: allowed on own topics, denied on foreign ones
await assert.rejects(connect('mqtt://127.0.0.1:1883', { username: cred.username, password: 'wrong' }));
const d = await connect('mqtt://127.0.0.1:1883', { username: cred.username, password: cred.password, clientId: cred.clientId });
const sub = await d.subscribeAsync(cred.subscribe.cmd);
assert.equal(sub[0].qos, 0);
const denied = (c, topic) => c.subscribeAsync(topic).then(
  () => assert.fail(`subscribe to ${topic} should be denied`),
  (e) => assert.equal(e.packet?.granted?.[0], 128));
await denied(d, `u/${USER}/d/someoneelse/cmd`);
await denied(d, '#');

// browser: token -> ws, sees device state, can command it
const t = (await call('POST', '/api/mqtt-token', {})).body;
const w = await connect('ws://127.0.0.1:9001', { username: t.username, password: t.password });
assert.equal((await w.subscribeAsync(t.topic))[0].qos, 0);
await denied(w, 'u/otheruser/#');
await denied(w, '#');
const gotState = new Promise((r) => w.once('message', (topic, m) => r([topic, m.toString()])));
d.publish(cred.publish.state, '{"on":true}');
assert.deepEqual(await gotState, [cred.publish.state, '{"on":true}']);

const gotCmd = new Promise((r) => d.once('message', (topic, m) => r(m.toString())));
w.publish(`u/${USER}/d/${dev.id}/cmd`, '{"on":false}');
assert.equal(await gotCmd, '{"on":false}');

// deleting the device cuts credentials
assert.equal((await call('DELETE', `/api/devices/${dev.id}`, null, { cookie: H.cookie })).status, 200);
db.prepare('DELETE FROM sessions WHERE token_hash=?').run(sha256(sess));
d.end(); w.end();
console.log('e2e ok');
process.exit(0);
