import Database from 'better-sqlite3';
import { createHash, randomBytes } from 'node:crypto';

export const sha256 = (s) => createHash('sha256').update(s).digest('hex');
export const token = (bytes = 24) => randomBytes(bytes).toString('base64url');
export const now = () => Math.floor(Date.now() / 1000);

export function openDb(file) {
  const db = new Database(file);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (user_id TEXT PRIMARY KEY, name TEXT, created INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS device_types (
      key TEXT PRIMARY KEY, name TEXT NOT NULL, category TEXT NOT NULL,
      schema TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(user_id),
      name TEXT NOT NULL, type_key TEXT NOT NULL REFERENCES device_types(key),
      created INTEGER NOT NULL, paired INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX IF NOT EXISTS devices_user ON devices(user_id);
    -- rooms are only a label for grouping in the UI; topics never depend on them
    CREATE TABLE IF NOT EXISTS rooms (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(user_id),
      name TEXT NOT NULL, created INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS rooms_user ON rooms(user_id);
    CREATE TABLE IF NOT EXISTS pairing_codes (
      code_hash TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
      expires INTEGER NOT NULL);
    -- one row per MQTT identity: device ("d_<id>") or browser ("w_<user_id>_<n>")
    CREATE TABLE IF NOT EXISTS mqtt_creds (
      mqtt_user TEXT PRIMARY KEY, pw_hash TEXT NOT NULL, user_id TEXT NOT NULL,
      device_id TEXT REFERENCES devices(id) ON DELETE CASCADE, expires INTEGER);
    CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires INTEGER NOT NULL);
    DROP TABLE IF EXISTS challenges;
    -- one row per login attempt: Snapie state + sha256 of the client's secret verifier (PKCE)
    CREATE TABLE IF NOT EXISTS login_states (
      state TEXT PRIMARY KEY, challenge TEXT NOT NULL, expires INTEGER NOT NULL);
  `);
  if (!db.prepare("SELECT 1 FROM pragma_table_info('devices') WHERE name='room_id'").get())
    db.exec('ALTER TABLE devices ADD COLUMN room_id TEXT REFERENCES rooms(id) ON DELETE SET NULL');
  const seed = db.prepare('INSERT OR IGNORE INTO device_types (key, name, category, schema) VALUES (?,?,?,?)');
  seed.run('switch', 'Switch / Relay', 'switch', JSON.stringify({
    state: { on: 'boolean' }, cmd: { on: 'boolean' } }));
  seed.run('sensor', 'Sensor', 'sensor', JSON.stringify({
    state: { value: 'number', unit: 'string' }, cmd: {} }));
  return db;
}
