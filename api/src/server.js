import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createRemoteJWKSet } from 'jose';
import { openDb } from './db.js';
import { makeSnapieVerifier } from './snapie.js';
import { buildApi, buildBrokerApi } from './app.js';

const env = process.env;
const root = fileURLToPath(new URL('../..', import.meta.url));
const snapie = env.SNAPIE_URL || 'https://auth.snapie.io';
// PUBLIC_URL is where users reach this server (e.g. https://iot.example.com); the MQTT host and
// websocket URL default to the same host.
const publicUrl = (env.PUBLIC_URL || 'http://localhost:3020').replace(/\/$/, '');
const publicHost = new URL(publicUrl).hostname;
const wsScheme = publicUrl.startsWith('https:') ? 'wss' : 'ws';
const cfg = {
  webDir: env.WEB_DIR || `${root}web`,
  admins: (env.ADMIN_USER_IDS || '').split(',').filter(Boolean),
  secureCookie: env.COOKIE_SECURE ? env.COOKIE_SECURE !== '0' : publicUrl.startsWith('https:'),
  snapieClientId: env.SNAPIE_CLIENT_ID || 'iot',
  snapieLoginUrl: `${snapie}/login`,
  webRedirect: env.WEB_REDIRECT || `${publicUrl}/auth/callback`,
  appRedirect: env.APP_REDIRECT || 'menoiot://auth',
  mqttHost: env.MQTT_HOST || publicHost,
  mqttPort: Number(env.MQTT_PORT || 8883),
  mqttTls: env.MQTT_TLS !== '0',
  mqttWsUrl: env.MQTT_WS_URL || `${wsScheme}://${new URL(publicUrl).host}/mqtt`,
};
const verify = makeSnapieVerifier({
  keys: createRemoteJWKSet(new URL(`${snapie}/.well-known/jwks.json`)),
  issuer: env.SNAPIE_ISSUER || snapie,
  audience: cfg.snapieClientId,
});
const brokerSecret = (env.BROKER_API_SECRET || readFileSync(`${root}broker/broker-api-secret`, 'utf8')).trim();
const db = openDb(env.DB_FILE || `${root}data/iot.db`);

await (await buildApi({ db, verify, cfg })).listen({ host: env.API_HOST || '127.0.0.1', port: Number(env.API_PORT || 3020) });
await buildBrokerApi({ db, secret: brokerSecret }).listen({ host: '127.0.0.1', port: Number(env.BROKER_API_PORT || 3021) });
