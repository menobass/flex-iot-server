# Broker TLS (8883) with a Let's Encrypt cert

The cert is root-owned but the broker runs as an unprivileged user. After `certbot` issues the cert,
add a deploy hook that copies it for the broker and restarts it. Replace `DOMAIN`, `BROKER_USER` and
`APP_DIR` with your values.

    sudo tee /etc/letsencrypt/renewal-hooks/deploy/iot-broker.sh >/dev/null <<'H'
    #!/bin/sh
    D=/etc/letsencrypt/live/DOMAIN
    install -o BROKER_USER -g BROKER_USER -m 600 $D/fullchain.pem APP_DIR/broker/certs/server.crt
    install -o BROKER_USER -g BROKER_USER -m 600 $D/privkey.pem   APP_DIR/broker/certs/server.key
    sudo -u BROKER_USER pm2 restart iot-broker
    H
    sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/iot-broker.sh
    sudo /etc/letsencrypt/renewal-hooks/deploy/iot-broker.sh   # first install

Also open `8883/tcp` in your firewall (e.g. `sudo ufw allow 8883/tcp`, plus any provider-level firewall).

## Device TLS requirements (ESP8266 firmware)

The devices use a 1024-byte TLS receive buffer to fit in RAM, so both the
pairing API (nginx on 443) and the broker (Mosquitto on 8883) must honour the
TLS `max_fragment_length` extension (or otherwise keep records within 1 KB).
OpenSSL 1.1.1 or newer is expected to do this by default; confirm on a device
with `WiFiClientSecure::probeMaxFragmentLength(host, port, 1024)`. Devices also pin the server key rather than a CA,
so keep the same key across certificate renewals (certbot `reuse_key = True`).
After changing the TLS stack, check a device can still pair and connect.
