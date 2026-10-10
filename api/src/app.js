import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';
import fstatic from '@fastify/static';
import { createHash, randomInt } from 'node:crypto';
import { sha256, token, now } from './db.js';

const SESSION_TTL = 7 * 86400;
const PAIR_TTL = 600;
const WEB_CRED_TTL = 3600;
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // no 0/O/1/I

const B64URL = /^[A-Za-z0-9_-]+$/;
const pkce = (verifier) => createHash('sha256').update(verifier).digest('base64url');
const newCode = () => Array.from({ length: 8 }, () => CODE_ALPHABET[randomInt(CODE_ALPHABET.length)]).join('');
const topicBase = (hiveUser, deviceId) => `u/${hiveUser}/d/${deviceId}`;

// Public API (behind nginx). `verify(snapieToken) -> claims` is injected (see snapie.js; fake in tests).
export async function buildApi({ db, verify, cfg }) {
  const app = Fastify({ logger: true, trustProxy: '127.0.0.1' }); // nginx only; `true` would trust a client-sent X-Forwarded-For
  app.register(cookie);
  // must be awaited: routes defined before the plugin has loaded silently get no limiter
  await app.register(rateLimit, { global: false });
  if (cfg.webDir) {
    app.register(fstatic, { root: cfg.webDir });
    // SPA callback the Snapie login redirects back to
    app.get('/auth/callback', (_req, reply) => reply.sendFile('index.html'));
  }

  const auth = async (req, reply) => {
    const bearer = /^Bearer (.+)$/.exec(req.headers.authorization || '')?.[1];
    const t = bearer || req.cookies.iot_session;
    const row = t && db.prepare('SELECT user_id FROM sessions WHERE token_hash=? AND expires>?').get(sha256(t), now());
    if (!row) return reply.code(401).send({ error: 'unauthorized' });
    req.user = row.user_id;
  };
  // Cookie is SameSite=Strict; additionally require JSON bodies on writes so plain cross-site forms can't hit us.
  app.addHook('preValidation', async (req, reply) => {
    if (req.method !== 'GET' && req.method !== 'DELETE' && req.body !== undefined &&
        !String(req.headers['content-type']).startsWith('application/json'))
      return reply.code(415).send({ error: 'json_required' });
  });

  // Step 1: client asks where to send the user. `state` is single-use; `challenge` is sha256(verifier)
  // (PKCE, base64url) so only the party that started the login can finish it, even if the redirect
  // leaks (another app on the phone owning our deep link, or a link planted for a victim's browser).
  // platform=web -> https callback on our site; platform=app -> the mobile deep link.
  app.get('/api/auth/start', { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } }, async (req, reply) => {
    const redirect = req.query.platform === 'app' ? cfg.appRedirect : cfg.webRedirect;
    if (!redirect) return reply.code(400).send({ error: 'unsupported_platform' });
    const { challenge } = req.query;
    if (typeof challenge !== 'string' || challenge.length !== 43 || !B64URL.test(challenge))
      return reply.code(400).send({ error: 'invalid_challenge' });
    const state = token(18);
    db.prepare('DELETE FROM login_states WHERE expires<?').run(now());
    db.prepare('DELETE FROM sessions WHERE expires<?').run(now());
    db.prepare('INSERT INTO login_states (state, challenge, expires) VALUES (?,?,?)').run(state, challenge, now() + 600);
    const url = new URL(cfg.snapieLoginUrl);
    url.search = new URLSearchParams({ client: cfg.snapieClientId, redirect, state }).toString();
    return { state, url: url.toString() };
  });

  // Step 2: client returns with the token Snapie put in the redirect. We verify it, then issue our own session.
  app.post('/api/auth/snapie', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (req, reply) => {
    const { token: snapieToken, state, verifier } = req.body || {};
    if (typeof snapieToken !== 'string' || typeof state !== 'string' ||
        typeof verifier !== 'string' || verifier.length < 43 || verifier.length > 128 || !B64URL.test(verifier))
      return reply.code(400).send({ error: 'bad_request' });
    // consume the state first so a failed attempt can't be replayed
    const row = db.prepare('DELETE FROM login_states WHERE state=? AND expires>? RETURNING challenge').get(state, now());
    if (!row) return reply.code(400).send({ error: 'invalid_or_expired_state' });
    if (pkce(verifier) !== row.challenge) return reply.code(401).send({ error: 'invalid_verifier' });
    let claims;
    try { claims = await verify(snapieToken); } catch { return reply.code(401).send({ error: 'invalid_token' }); }
    if (claims.nonce !== state || typeof claims.sub !== 'string') return reply.code(401).send({ error: 'invalid_token' });
    const name = typeof claims.name === 'string' ? claims.name.slice(0, 64) : null;
    db.prepare(`INSERT INTO users (user_id, name, created) VALUES (?,?,?)
      ON CONFLICT(user_id) DO UPDATE SET name=excluded.name`).run(claims.sub, name, now());
    const session = token(32);
    db.prepare('INSERT INTO sessions (token_hash, user_id, expires) VALUES (?,?,?)').run(sha256(session), claims.sub, now() + SESSION_TTL);
    reply.setCookie('iot_session', session, { httpOnly: true, secure: cfg.secureCookie, sameSite: 'strict', path: '/', maxAge: SESSION_TTL });
    // `token` is for native apps (send as Authorization: Bearer); browsers can ignore it and use the cookie.
    return { token: session, user: claims.sub, name, admin: cfg.admins.includes(claims.sub) };
  });

  app.post('/api/auth/logout', { preHandler: auth }, async (req, reply) => {
    const bearer = /^Bearer (.+)$/.exec(req.headers.authorization || '')?.[1];
    db.prepare('DELETE FROM sessions WHERE token_hash=?').run(sha256(bearer || req.cookies.iot_session));
    reply.clearCookie('iot_session', { path: '/' });
    return { ok: true };
  });

  app.get('/api/me', { preHandler: auth }, async (req) => ({
    user: req.user, name: db.prepare('SELECT name FROM users WHERE user_id=?').get(req.user)?.name ?? null,
    admin: cfg.admins.includes(req.user) }));

  // ---- device types (dynamic, DB-driven) ----
  app.get('/api/types', { preHandler: auth }, async () =>
    db.prepare('SELECT key,name,category,schema FROM device_types WHERE active=1 ORDER BY name').all()
      .map((t) => ({ ...t, schema: JSON.parse(t.schema) })));

  app.put('/api/types/:key', { preHandler: auth }, async (req, reply) => {
    if (!cfg.admins.includes(req.user)) return reply.code(403).send({ error: 'admin_required' });
    const { name, category, schema, active = true } = req.body || {};
    if (!/^[a-z0-9_-]{1,32}$/.test(req.params.key) || typeof name !== 'string' || typeof category !== 'string' || typeof schema !== 'object')
      return reply.code(400).send({ error: 'bad_request' });
    db.prepare(`INSERT INTO device_types (key,name,category,schema,active) VALUES (?,?,?,?,?)
      ON CONFLICT(key) DO UPDATE SET name=excluded.name, category=excluded.category, schema=excluded.schema, active=excluded.active`)
      .run(req.params.key, name, category, JSON.stringify(schema), active ? 1 : 0);
    return { ok: true };
  });

  // ---- devices ----
  const issueCode = (deviceId) => {
    const code = newCode();
    db.prepare('DELETE FROM pairing_codes WHERE device_id=?').run(deviceId);
    db.prepare('INSERT INTO pairing_codes (code_hash, device_id, expires) VALUES (?,?,?)').run(sha256(code), deviceId, now() + PAIR_TTL);
    return { code, expiresIn: PAIR_TTL };
  };

  // ---- rooms: a per-user label for grouping devices (no effect on topics or ACLs) ----
  const MAX_ROOMS = 50;
  const cleanName = (v) => (typeof v === 'string' && v.trim() && v.length <= 64 ? v.trim() : null);
  const ownsRoom = (user, id) => id == null || !!db.prepare('SELECT 1 FROM rooms WHERE id=? AND user_id=?').get(id, user);

  app.get('/api/rooms', { preHandler: auth }, async (req) =>
    db.prepare('SELECT id,name FROM rooms WHERE user_id=? ORDER BY created, name').all(req.user));

  app.post('/api/rooms', { preHandler: auth }, async (req, reply) => {
    const name = cleanName(req.body?.name);
    if (!name) return reply.code(400).send({ error: 'invalid_name' });
    if (db.prepare('SELECT COUNT(*) n FROM rooms WHERE user_id=?').get(req.user).n >= MAX_ROOMS)
      return reply.code(400).send({ error: 'too_many_rooms' });
    const id = token(9).replace(/[-_]/g, 'x').toLowerCase();
    db.prepare('INSERT INTO rooms (id,user_id,name,created) VALUES (?,?,?,?)').run(id, req.user, name, now());
    return { id, name };
  });

  app.patch('/api/rooms/:id', { preHandler: auth }, async (req, reply) => {
    const name = cleanName(req.body?.name);
    if (!name) return reply.code(400).send({ error: 'invalid_name' });
    const r = db.prepare('UPDATE rooms SET name=? WHERE id=? AND user_id=?').run(name, req.params.id, req.user);
    return r.changes ? { id: req.params.id, name } : reply.code(404).send({ error: 'not_found' });
  });

  // Devices in the room stay; they just become unassigned.
  app.delete('/api/rooms/:id', { preHandler: auth }, async (req, reply) => {
    const r = db.prepare('DELETE FROM rooms WHERE id=? AND user_id=?').run(req.params.id, req.user);
    return r.changes ? { ok: true } : reply.code(404).send({ error: 'not_found' });
  });

  const owned = (req) => db.prepare('SELECT * FROM devices WHERE id=? AND user_id=?').get(req.params.id, req.user);

  app.get('/api/devices', { preHandler: auth }, async (req) =>
    db.prepare('SELECT id,name,type_key AS type,room_id AS room,paired,created FROM devices WHERE user_id=? ORDER BY created DESC').all(req.user)
      .map((d) => ({ ...d, topic: topicBase(req.user, d.id) })));

  app.post('/api/devices', { preHandler: auth }, async (req, reply) => {
    const { type, room = null } = req.body || {};
    const name = cleanName(req.body?.name);
    if (!name) return reply.code(400).send({ error: 'invalid_name' });
    if (!db.prepare('SELECT 1 FROM device_types WHERE key=? AND active=1').get(type)) return reply.code(400).send({ error: 'invalid_type' });
    if (!ownsRoom(req.user, room)) return reply.code(400).send({ error: 'invalid_room' });
    const id = token(9).replace(/[-_]/g, 'x').toLowerCase();
    db.prepare('INSERT INTO devices (id,user_id,name,type_key,room_id,created) VALUES (?,?,?,?,?,?)').run(id, req.user, name, type, room, now());
    return { id, name, type, room, topic: topicBase(req.user, id), pairing: issueCode(id) };
  });

  // Rename and/or move to another room (`room: null` = no room).
  app.patch('/api/devices/:id', { preHandler: auth }, async (req, reply) => {
    const dev = owned(req);
    if (!dev) return reply.code(404).send({ error: 'not_found' });
    const b = req.body || {};
    const name = 'name' in b ? cleanName(b.name) : dev.name;
    const room = 'room' in b ? b.room : dev.room_id;
    if (!name) return reply.code(400).send({ error: 'invalid_name' });
    if (!ownsRoom(req.user, room)) return reply.code(400).send({ error: 'invalid_room' });
    db.prepare('UPDATE devices SET name=?, room_id=? WHERE id=?').run(name, room, dev.id);
    return { id: dev.id, name, room };
  });

  app.post('/api/devices/:id/pairing-code', { preHandler: auth }, async (req, reply) => {
    if (!owned(req)) return reply.code(404).send({ error: 'not_found' });
    return issueCode(req.params.id);
  });

  app.delete('/api/devices/:id', { preHandler: auth }, async (req, reply) => {
    if (!owned(req)) return reply.code(404).send({ error: 'not_found' });
    db.prepare('DELETE FROM devices WHERE id=?').run(req.params.id); // cascades creds + codes
    return { ok: true };
  });

  // Called by the device: one-time code -> its own broker credentials. Re-pairing replaces old credentials.
  app.post('/api/pair', { config: { rateLimit: { max: 10, timeWindow: '1 minute' } } }, async (req, reply) => {
    const code = String(req.body?.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    const row = db.prepare('DELETE FROM pairing_codes WHERE code_hash=? AND expires>? RETURNING device_id').get(sha256(code), now());
    if (!row) return reply.code(400).send({ error: 'invalid_or_expired_code' });
    const dev = db.prepare('SELECT * FROM devices WHERE id=?').get(row.device_id);
    const mqttUser = `d_${dev.id}`;
    const password = token(24);
    db.prepare(`INSERT INTO mqtt_creds (mqtt_user,pw_hash,user_id,device_id) VALUES (?,?,?,?)
      ON CONFLICT(mqtt_user) DO UPDATE SET pw_hash=excluded.pw_hash`).run(mqttUser, sha256(password), dev.user_id, dev.id);
    db.prepare('UPDATE devices SET paired=1 WHERE id=?').run(dev.id);
    const base = topicBase(dev.user_id, dev.id);
    return {
      host: cfg.mqttHost, port: cfg.mqttPort, tls: cfg.mqttTls, username: mqttUser, password,
      clientId: mqttUser, publish: { state: `${base}/state`, status: `${base}/status` }, subscribe: { cmd: `${base}/cmd` },
    };
  });

  // Browser dashboard: short-lived MQTT-over-WS credentials for the logged-in user.
  app.post('/api/mqtt-token', { preHandler: auth }, async (req) => {
    const mqttUser = `w_${req.user}_${token(6).replace(/[-_]/g, 'x')}`;
    const password = token(24);
    db.prepare('DELETE FROM mqtt_creds WHERE device_id IS NULL AND expires<?').run(now());
    db.prepare('INSERT INTO mqtt_creds (mqtt_user,pw_hash,user_id,expires) VALUES (?,?,?,?)')
      .run(mqttUser, sha256(password), req.user, now() + WEB_CRED_TTL);
    return { url: cfg.mqttWsUrl, username: mqttUser, password, topic: `u/${req.user}/#`, expiresIn: WEB_CRED_TTL };
  });

  return app;
}

// Private API consumed by mosquitto-go-auth (http backend). Bind to 127.0.0.1 only.
// Mounted under /broker/<secret>/ so other local processes on this shared host can't use it.
export function buildBrokerApi({ db, secret }) {
  if (!secret || secret.length < 32) throw new Error('broker api secret missing or too short');
  const app = Fastify({ logger: { level: 'warn' } }); // request lines would contain the secret
  const P = `/broker/${secret}`;
  const deny = (reply, code = 403) => reply.code(code).send({ ok: false });
  const allow = { ok: true };

  app.post(`${P}/user`, async (req, reply) => {
    const { username, password } = req.body || {};
    const row = db.prepare('SELECT pw_hash, expires FROM mqtt_creds WHERE mqtt_user=?').get(String(username));
    if (!row || (row.expires && row.expires < now())) return deny(reply, 401);
    return row.pw_hash === sha256(String(password)) ? allow : deny(reply, 401);
  });

  app.post(`${P}/superuser`, async (_req, reply) => deny(reply));

  // acc: 1=read 2=write 4=subscribe 8=unsubscribe (mosquitto-go-auth)
  app.post(`${P}/acl`, async (req, reply) => {
    const { username, topic, acc } = req.body || {};
    const row = db.prepare('SELECT user_id, device_id, expires FROM mqtt_creds WHERE mqtt_user=?').get(String(username));
    if (!row || (row.expires && row.expires < now())) return deny(reply);
    const t = String(topic);
    if (t.includes('+') && row.device_id) return deny(reply);
    if (row.device_id) { // device: strictly its own three topics
      const base = topicBase(row.user_id, row.device_id);
      const writes = [`${base}/state`, `${base}/status`];
      if (acc === 2) return writes.includes(t) ? allow : deny(reply);
      return t === `${base}/cmd` ? allow : deny(reply);
    }
    // browser user: read anything under own prefix, command only own devices
    const prefix = `u/${row.user_id}/`;
    if (acc === 2) return new RegExp(`^u/${row.user_id.replace(/[^a-zA-Z0-9]/g, '')}/d/[a-z0-9]+/cmd$`).test(t) ? allow : deny(reply);
    return t.startsWith(prefix) ? allow : deny(reply);
  });

  return app;
}
