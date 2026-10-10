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
