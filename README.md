# Flex IOT server

Backend for Flex IOT: users sign in with a Snapie account (Google, Apple or email; no blockchain knowledge needed),
add devices, group them into rooms, pair them with a one-time code, and see/control them live over MQTT.

```
browser --wss--> nginx --ws--> mosquitto :9001 \
device  --tls 8883-----------> mosquitto        > go-auth (http) -> api :3021 (127.0.0.1 only) -> SQLite
browser --https--> nginx ----> api :3020
```

- `api/` Fastify API + broker auth/ACL endpoints. `api/test/` unit tests (`npm test`); `api/e2e/e2e.mjs` runs against a live stack.
- `web/` single-page dashboard (served by the API). `web/vendor/mqtt.min.js` is copied from `api/node_modules/mqtt/dist/`.
- `broker/` Mosquitto 2.1.2 + mosquitto-go-auth 3.0.0. `build.sh` builds them into `vendor/` (no root), `setup.sh`
  writes `mosquitto.conf`, the broker<->API secret and a dev certificate. Broker callbacks are served under
  `/broker/<secret>/` on 127.0.0.1:3021 so other processes on the host can't use them.
- `ecosystem.config.cjs` pm2 definitions (`pm2 start ecosystem.config.cjs`); settings come from `.env` (see `.env.example`).
- `deploy/` example nginx vhost and broker TLS notes.

## Setup from scratch
```
broker/build.sh && broker/setup.sh
(cd api && npm ci) && mkdir -p web/vendor && cp api/node_modules/mqtt/dist/mqtt.min.js web/vendor/
cp .env.example .env        # set PUBLIC_URL
pm2 start ecosystem.config.cjs && pm2 save
(cd api && npm test) && node api/e2e/e2e.mjs
```

## Configuration (`.env`)
| Variable | Meaning |
|---|---|
| `PUBLIC_URL` | Where users reach the server, e.g. `https://iot.example.com`. MQTT host and websocket URL default to this host. |
| `ADMIN_USER_IDS` | Comma-separated Snapie user ids (the token's `sub`) allowed to manage device types. |
| `COOKIE_SECURE` | Defaults to on when `PUBLIC_URL` is https. |
| `SNAPIE_URL`, `APP_REDIRECT`, `MQTT_HOST`, `MQTT_PORT`, `MQTT_WS_URL` | Optional overrides. |

## Rooms and topics
A room is just a label for grouping devices; it does not appear in topics, so moving a device between rooms
never changes its topic or credentials. Topics:

`u/<user_id>/d/<device_id>/{state,status,cmd}`
- device `d_<id>`: publish `state`,`status`; subscribe `cmd`; nothing else.
- browser `w_<user>_<n>` (1h credentials): read `u/<user>/#`; publish `.../cmd` only.

## Device pairing
```
POST /api/pair {"code":"ABCD2345"}   (code from the UI, 10 min, single use)
-> {host, port, tls, username, password, clientId, publish:{state,status}, subscribe:{cmd}}
```
Re-pairing replaces the password. Deleting the device deletes its credentials (broker cache: <= 30 s).

## API (session cookie, or `Authorization: Bearer <token>` for apps)
| | |
|---|---|
| `GET /api/me` | current user |
| `GET/POST /api/rooms`, `PATCH/DELETE /api/rooms/:id` | rooms (deleting one keeps its devices) |
| `GET/POST /api/devices`, `PATCH/DELETE /api/devices/:id` | devices; `PATCH {name?, room?}` renames or moves |
| `POST /api/devices/:id/pairing-code` | new one-time code |
| `GET /api/types` | device types (admins: `PUT /api/types/:key`) |
| `POST /api/mqtt-token` | short-lived MQTT-over-WebSocket credentials |

## Auth
Sign in with Snapie, using PKCE: the client makes a random `verifier` (43-128 chars base64url) and keeps it;
`challenge = base64url(sha256(verifier))`.
`GET /api/auth/start?platform=web|app&challenge=<challenge>` -> `{state,url}`; send the user to `url`.
Snapie redirects back with `token` + `state`; `POST /api/auth/snapie {token,state,verifier}` verifies the RS256 token
against Snapie's JWKS (iss, aud, exp, `nonce==state`) and returns `{token,user,name}` + a session cookie.
A leaked redirect is useless without the verifier. Mobile apps send `Authorization: Bearer <token>`.
Users are keyed by Snapie's `sub`.

This needs Snapie Auth's "app login" feature (`/.well-known/jwks.json`) and this app registered as a client, e.g.
`APP_LOGIN_CLIENTS={"iot":{"name":"Flex IOT","redirects":["https://iot.example.com/auth/callback","yourapp://auth"]}}`.

## Deploying behind nginx
1. DNS for your domain points at the server.
2. nginx vhost: see `deploy/nginx.conf.example` (`/` -> 127.0.0.1:3020, `/mqtt` websocket upgrade -> 127.0.0.1:9001).
3. TLS cert (Let's Encrypt); for devices on 8883 see `deploy/TLS-for-broker.md`.
4. Open `8883/tcp` in the firewall.
5. Set `PUBLIC_URL` in `.env`, then `pm2 restart iot-api --update-env`.
