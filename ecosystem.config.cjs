const fs = require('fs');
const root = __dirname;

// Deployment-specific settings live in `.env` (git-ignored), one KEY=value per line. See .env.example.
const fromFile = {};
try {
  for (const line of fs.readFileSync(`${root}/.env`, 'utf8').split('\n')) {
    const m = /^\s*([A-Z_][A-Z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (m && !line.trim().startsWith('#')) fromFile[m[1]] = m[2];
  }
} catch { /* no .env: local defaults */ }
const env = { ...fromFile, ...process.env };

module.exports = {
  apps: [
    {
      name: 'iot-broker',
      script: `${root}/vendor/mosquitto-src/src/mosquitto`,
      args: `-c ${root}/broker/mosquitto.conf`,
      interpreter: 'none',
    },
    {
      name: 'iot-api',
      script: `${root}/api/src/server.js`,
      env: {
        API_PORT: 3020, BROKER_API_PORT: 3021,
        PUBLIC_URL: env.PUBLIC_URL,           // https://iot.example.com
        COOKIE_SECURE: env.COOKIE_SECURE,     // defaults to on when PUBLIC_URL is https
        ADMIN_USER_IDS: env.ADMIN_USER_IDS,   // comma-separated Snapie user ids (the `sub` claim)
        MQTT_HOST: env.MQTT_HOST,
        MQTT_PORT: env.MQTT_PORT || 8883,
        MQTT_WS_URL: env.MQTT_WS_URL,
        SNAPIE_URL: env.SNAPIE_URL,
        APP_REDIRECT: env.APP_REDIRECT,
      },
    },
  ],
};
