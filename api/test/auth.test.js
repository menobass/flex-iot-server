import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SignJWT, generateKeyPair, exportJWK, createLocalJWKSet } from 'jose';
import { openDb } from '../src/db.js';
import { makeSnapieVerifier } from '../src/snapie.js';
import { createHash, randomBytes } from 'node:crypto';
import { buildApi, buildBrokerApi } from '../src/app.js';

const ISS = 'https://auth.snapie.io';
const { publicKey, privateKey } = await generateKeyPair('RS256');
const other = await generateKeyPair('RS256');
const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };

const mint = (claims = {}, { key = privateKey, aud = 'iot', iss = ISS, exp = '2m', sub = '64b7f0000000000000000001' } = {}) =>
  new SignJWT({ name: 'Alice', hive_user: null, ...claims })
    .setProtectedHeader({ alg: 'RS256', kid: 'k1' })
    .setIssuer(iss).setAudience(aud).setSubject(sub).setIssuedAt().setExpirationTime(exp).sign(key);

async function setup() {
  const db = openDb(':memory:');
  const app = await buildApi({
    db,
    verify: makeSnapieVerifier({ keys: createLocalJWKSet({ keys: [jwk] }), issuer: ISS, audience: 'iot' }),
    cfg: { admins: [], secureCookie: false, snapieClientId: 'iot', snapieLoginUrl: `${ISS}/login`,
      webRedirect: 'https://iot.example.com/auth/callback', appRedirect: 'menoiot://auth' },
  });
  const post = (url, payload) => app.inject({ method: 'POST', url, payload });
  // PKCE: returns the server's {state,url} plus the secret verifier the client keeps
  const start = async (platform = 'web') => {
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const r = await app.inject({ url: `/api/auth/start?platform=${platform}&challenge=${challenge}` });
    return { ...r.json(), verifier };
  };
  return { app, db, post, start };
}

test('start builds the Snapie login URL with a fresh state', async () => {
  const { start } = await setup();
  const web = await start('web');
  const u = new URL(web.url);
  assert.equal(u.origin + u.pathname, `${ISS}/login`);
  assert.equal(u.searchParams.get('client'), 'iot');
  assert.equal(u.searchParams.get('redirect'), 'https://iot.example.com/auth/callback');
  assert.equal(u.searchParams.get('state'), web.state);
  assert.equal(new URL((await start('app')).url).searchParams.get('redirect'), 'menoiot://auth');
});

test('valid token -> session usable via cookie and via Bearer', async () => {
  const { app, post, start } = await setup();
  const { state, verifier } = await start();
  const r = await post('/api/auth/snapie', { token: await mint({ nonce: state }), state, verifier });
  assert.equal(r.statusCode, 200);
  const body = r.json();
  assert.equal(body.user, '64b7f0000000000000000001');
  assert.equal(body.name, 'Alice');
  assert.ok(r.headers['set-cookie'].includes('iot_session='));
  const me = await app.inject({ url: '/api/me', headers: { authorization: `Bearer ${body.token}` } });
  assert.equal(me.statusCode, 200);
  assert.equal(me.json().user, body.user);
  const viaCookie = await app.inject({ url: '/api/me', cookies: { iot_session: body.token } });
  assert.equal(viaCookie.statusCode, 200);
  assert.equal((await app.inject({ url: '/api/me' })).statusCode, 401);
});

test('rejects bad tokens and replays', async () => {
  const { post, start } = await setup();
  const attempt = async (mk) => {
    const { state, verifier } = await start();
    return post('/api/auth/snapie', { token: await mk(state), state, verifier });
  };
  assert.equal((await attempt((s) => mint({ nonce: s }, { aud: 'other' }))).statusCode, 401, 'wrong audience');
  assert.equal((await attempt((s) => mint({ nonce: s }, { iss: 'https://evil.example' }))).statusCode, 401, 'wrong issuer');
  assert.equal((await attempt((s) => mint({ nonce: s }, { key: other.privateKey }))).statusCode, 401, 'wrong signing key');
  assert.equal((await attempt((s) => mint({ nonce: s }, { exp: '-1m' }))).statusCode, 401, 'expired');
  assert.equal((await attempt(() => mint({ nonce: 'someone-elses-state' }))).statusCode, 401, 'nonce != state');
  assert.equal((await attempt(() => 'garbage')).statusCode, 401, 'not a jwt');

  const { state, verifier } = await start();
  const token = await mint({ nonce: state });
  assert.equal((await post('/api/auth/snapie', { token, state, verifier })).statusCode, 200);
  assert.equal((await post('/api/auth/snapie', { token, state, verifier })).statusCode, 400, 'state is single use');
  assert.equal((await post('/api/auth/snapie', { token, state: 'never-issued', verifier })).statusCode, 400, 'unknown state');
});

test('a leaked redirect is useless without the verifier (PKCE)', async () => {
  const { post, start } = await setup();
  const { state, verifier } = await start();
  const token = await mint({ nonce: state });
  const attacker = randomBytes(32).toString('base64url');
  assert.equal((await post('/api/auth/snapie', { token, state, verifier: attacker })).statusCode, 401, 'wrong verifier');
  assert.equal((await post('/api/auth/snapie', { token, state })).statusCode, 400, 'missing verifier');
  // the failed attempt burned the state: even the real client can't finish it, it must start over
  assert.equal((await post('/api/auth/snapie', { token, state, verifier })).statusCode, 400);
});

test('start requires a well-formed challenge', async () => {
  const { app } = await setup();
  for (const q of ['', '&challenge=short', `&challenge=${'!'.repeat(43)}`])
    assert.equal((await app.inject({ url: `/api/auth/start?platform=web${q}` })).statusCode, 400);
});

test('a client-sent X-Forwarded-For cannot dodge the rate limit', async () => {
  const { app } = await setup();
  let last;
  for (let i = 0; i < 12; i++)
    last = await app.inject({ method: 'POST', url: '/api/pair', payload: { code: 'AAAAAAAA' }, remoteAddress: '127.0.0.1',
      headers: { 'x-forwarded-for': `10.0.0.${i}, 203.0.113.9` } }); // nginx appends the real client last
  assert.equal(last.statusCode, 429);
});

test('broker API only answers under the secret path', async () => {
  const db = openDb(':memory:');
  const secret = 'f'.repeat(48);
  assert.throws(() => buildBrokerApi({ db, secret: 'short' }));
  const app = buildBrokerApi({ db, secret });
  const body = { username: 'nobody', password: 'x' };
  assert.equal((await app.inject({ method: 'POST', url: '/broker/user', payload: body })).statusCode, 404);
  assert.equal((await app.inject({ method: 'POST', url: '/broker/wrongsecret/user', payload: body })).statusCode, 404);
  assert.equal((await app.inject({ method: 'POST', url: `/broker/${secret}/user`, payload: body })).statusCode, 401);
});
