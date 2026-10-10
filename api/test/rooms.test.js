import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openDb, sha256, token, now } from '../src/db.js';
import { buildApi } from '../src/app.js';

async function setup() {
  const db = openDb(':memory:');
  const app = await buildApi({ db, verify: async () => ({}), cfg: { admins: [], secureCookie: false } });
  const as = (user) => {
    db.prepare('INSERT OR IGNORE INTO users (user_id, created) VALUES (?,?)').run(user, now());
    const t = token(32);
    db.prepare('INSERT INTO sessions VALUES (?,?,?)').run(sha256(t), user, now() + 600);
    return (method, url, payload) => app.inject({ method, url, payload, headers: { authorization: `Bearer ${t}` } });
  };
  return { app, db, as };
}

test('rooms group devices without changing their topic; deleting a room keeps the devices', async () => {
  const { as } = await setup();
  const alice = as('alice');
  const room = (await alice('POST', '/api/rooms', { name: ' Kitchen ' })).json();
  assert.equal(room.name, 'Kitchen');
  const dev = (await alice('POST', '/api/devices', { name: 'Lamp', type: 'switch', room: room.id })).json();
  assert.equal(dev.room, room.id);
  assert.equal(dev.topic, `u/alice/d/${dev.id}`);

  const moved = await alice('PATCH', `/api/devices/${dev.id}`, { room: null });
  assert.equal(moved.json().room, null);
  await alice('PATCH', `/api/devices/${dev.id}`, { room: room.id });

  assert.equal((await alice('DELETE', `/api/rooms/${room.id}`)).statusCode, 200);
  const list = (await alice('GET', '/api/devices')).json();
  assert.equal(list.length, 1);
  assert.equal(list[0].room, null);
  assert.equal(list[0].topic, dev.topic);
});

test("a user can't use or change another user's room or device", async () => {
  const { as } = await setup();
  const alice = as('alice'), bob = as('bob');
  const room = (await alice('POST', '/api/rooms', { name: 'Private' })).json();
  const dev = (await alice('POST', '/api/devices', { name: 'Lamp', type: 'switch' })).json();

  assert.equal((await bob('POST', '/api/devices', { name: 'x', type: 'switch', room: room.id })).statusCode, 400);
  assert.equal((await bob('PATCH', `/api/rooms/${room.id}`, { name: 'mine' })).statusCode, 404);
  assert.equal((await bob('DELETE', `/api/rooms/${room.id}`)).statusCode, 404);
  assert.equal((await bob('PATCH', `/api/devices/${dev.id}`, { name: 'hijack' })).statusCode, 404);
  const own = (await bob('POST', '/api/devices', { name: 'Fan', type: 'switch' })).json();
  assert.equal((await bob('PATCH', `/api/devices/${own.id}`, { room: room.id })).statusCode, 400);
  assert.equal((await bob('GET', '/api/rooms')).json().length, 0);
});

test('room and device names are validated', async () => {
  const { as } = await setup();
  const alice = as('alice');
  assert.equal((await alice('POST', '/api/rooms', { name: '   ' })).statusCode, 400);
  assert.equal((await alice('POST', '/api/rooms', { name: 'x'.repeat(65) })).statusCode, 400);
  assert.equal((await alice('POST', '/api/devices', { name: '', type: 'switch' })).statusCode, 400);
});

test('existing databases get the room_id column on open', async () => {
  const { default: Database } = await import('better-sqlite3');
  const { mkdtempSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const f = mkdtempSync(tmpdir() + '/iot-') + '/old.db';
  const old = new Database(f);
  old.exec(`CREATE TABLE users (user_id TEXT PRIMARY KEY, name TEXT, created INTEGER NOT NULL);
    CREATE TABLE device_types (key TEXT PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL, schema TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE devices (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, name TEXT NOT NULL, type_key TEXT NOT NULL, created INTEGER NOT NULL, paired INTEGER NOT NULL DEFAULT 0);`);
  old.close();
  const db = openDb(f);
  assert.ok(db.prepare("SELECT 1 FROM pragma_table_info('devices') WHERE name='room_id'").get());
});
