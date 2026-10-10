#!/usr/bin/env bash
# Builds Mosquitto + mosquitto-go-auth in user space (no root, no apt) into vendor/.
# Needs: gcc, make, git, curl, tar, openssl headers (libssl-dev). Re-runnable; skips finished steps.
# Why the extras: Mosquitto 2.1 hard-requires the cJSON *headers* (not installed here) and the
# go-auth plugin needs Go, so both are fetched locally.
set -euo pipefail

VENDOR=${VENDOR:-"$(cd "$(dirname "$0")/.." && pwd)/vendor"}
MOSQ_VERSION=${MOSQ_VERSION:-v2.1.2}
GOAUTH_VERSION=${GOAUTH_VERSION:-3.0.0}
CJSON_VERSION=${CJSON_VERSION:-v1.7.18}
GO_VERSION=${GO_VERSION:-1.27.2}
mkdir -p "$VENDOR"
cd "$VENDOR"
clone() { [ -d "$3" ] || git clone -q --depth 1 -c advice.detachedHead=false --branch "$2" "$1" "$3"; }

# 1. cJSON: header + shared lib, used only to build against
if [ ! -f deps/lib/libcjson.so.1 ]; then
  clone https://github.com/DaveGamble/cJSON.git "$CJSON_VERSION" cjson-src
  mkdir -p deps/include/cjson deps/lib
  cp cjson-src/cJSON.h deps/include/cjson/
  gcc -O2 -fPIC -shared -Wl,-soname,libcjson.so.1 -o deps/lib/libcjson.so.1 cjson-src/cJSON.c
  ln -sf libcjson.so.1 deps/lib/libcjson.so
fi

# 2. Mosquitto (TLS + native WebSockets; no docs/sqlite/http-api/editline)
if [ ! -x mosquitto-src/src/mosquitto ]; then
  clone https://github.com/eclipse-mosquitto/mosquitto.git "$MOSQ_VERSION" mosquitto-src
  (
    cd mosquitto-src
    export CPATH="$VENDOR/deps/include" LIBRARY_PATH="$VENDOR/deps/lib"
    make -j"$(nproc)" binary WITH_DOCS=no WITH_SQLITE=no WITH_EDITLINE=no WITH_HTTP_API=no \
      WITH_GMOCK=no WITH_TLS_PSK=no LDFLAGS="-Wl,-rpath,$VENDOR/deps/lib"
  )
fi

# 3. Go toolchain (only to build the plugin)
if [ ! -x go-dist/go/bin/go ]; then
  mkdir -p go-dist
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -xz -C go-dist
fi

# 4. mosquitto-go-auth plugin
if [ ! -f go-auth-src/go-auth.so ]; then
  clone https://github.com/iegomez/mosquitto-go-auth.git "$GOAUTH_VERSION" go-auth-src
  (
    cd go-auth-src
    M="$VENDOR/mosquitto-src"
    export PATH="$VENDOR/go-dist/go/bin:$PATH" GOFLAGS=-buildvcs=false
    export CGO_CFLAGS="-I$M/include -I$M/src -I$M/lib -I$VENDOR/deps/include -fPIC"
    make CFLAGS="$CGO_CFLAGS"
  )
fi

echo "ok: $VENDOR/mosquitto-src/src/mosquitto and $VENDOR/go-auth-src/go-auth.so"
