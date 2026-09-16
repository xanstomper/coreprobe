#!/usr/bin/env bash
# CoreProbe / opensleuth field installer - one command, LEA examiner deploy.
# Installs: python deps (pymobiledevice3), libimobiledevice stack, ifuse,
# checkm8 tooling (gaster/irecovery/palera1n), optional web studio service.
#
# Usage:  sudo ./install.sh [--with-web-service] [--with-checkm8-tools] [--with-desktop] [--with-cxx]
set -euo pipefail

PY="${PYTHON:-python3}"
WITH_WEB=0
WITH_C8=0
WITH_DESKTOP=0
WITH_CXX=0
for a in "$@"; do
  case "$a" in
    --with-web-service) WITH_WEB=1 ;;
    --with-checkm8-tools) WITH_C8=1 ;;
    --with-desktop) WITH_DESKTOP=1 ;;
    --with-cxx) WITH_CXX=1 ;;
    *) echo "unknown arg: $a"; exit 2 ;;
  esac
done

echo "== CoreProbe install =="
$PY --version

echo "== apt: libimobiledevice + fuse + forensic stack =="
apt-get update -qq
apt-get install -y -qq \
  libimobiledevice-utils libimobiledevice-1.0-6 \
  libusbmuxd-utils ifuse fuse3 usbmuxd \
  libusb-1.0-0-dev libssl-dev build-essential git curl \
  ${WITH_C8:+/usr/bin/gcc} >/dev/null

echo "== pip: opensleuth + pymobiledevice3 + pyusb =="
$PY -m pip install --break-system-packages -q -e . pymobiledevice3 pyusb lz4 2>/dev/null \
  || $PY -m pip install -q -e . pymobiledevice3 pyusb lz4
echo "opensleuth CLI installed (usable from any directory)"

if [ "$WITH_C8" = "1" ]; then
  echo "== checkm8 tooling =="
  apt-get install -y -qq irecovery libirecovery-1.0-3 >/dev/null 2>&1 || true
  PREFIX="${HOME:-/root}/.local/bin"; mkdir -p "$PREFIX"
  if ! command -v gaster >/dev/null; then
    git clone --depth 1 https://github.com/0x7ff/gaster /tmp/gaster-build
    gcc -DHAVE_LIBUSB /tmp/gaster-build/gaster.c /tmp/gaster-build/lzfse.c \
        -o "$PREFIX/gaster" -lusb-1.0 -lcrypto -O2
  fi
  if ! command -v palera1n >/dev/null && [ -z "${SKIP_PALERA1N:-}" ]; then
    curl -sL https://github.com/palera1n/palera1n/releases/latest/download/palera1n-linux-x86_64 \
      -o "$PREFIX/palera1n" && chmod +x "$PREFIX/palera1n"
  fi
fi

echo "== verify parser + catalog =="
cd "$(dirname "$0")"
$PY -c "import opensleuth; from opensleuth.exploits import ROUTES, RECENT_DISCLOSURES; print(f'catalog: {len(ROUTES)} routes, {len(RECENT_DISCLOSURES)} disclosures')"
$PY -m pytest tests/ -q 2>/dev/null | tail -1 || echo "(pytest optional: skip)"

if [ "$WITH_WEB" = "1" ]; then
  echo "== systemd user unit: opensleuth-web =="
  mkdir -p "$HOME/.config/systemd/user"
  cat > "$HOME/.config/systemd/user/opensleuth-web.service" <<EOF
[Unit]
Description=opensleuth forensic web studio
After=network.target usbmuxd.service

[Service]
ExecStart=$PWD/bin/opensleuth-web
Restart=on-failure
Environment=OPENSLEUTH_PORT=9121
Environment=OPENSLEUTH_HOST=127.0.0.1

[Install]
WantedBy=default.target
EOF
  mkdir -p "$PWD/bin"
  cat > "$PWD/bin/opensleuth-web" <<EOF
#!/usr/bin/env bash
cd "$PWD" && exec $PY -m opensleuth.studio_web
EOF
  chmod +x "$PWD/bin/opensleuth-web"
  systemctl --user daemon-reload
  systemctl --user enable --now opensleuth-web || true
  echo "web studio: http://127.0.0.1:9121"
fi

if [ "$WITH_CXX" = "1" ]; then
  echo "== native C++ core (osleuth_core) =="
  apt-get install -y -qq cmake g++ >/dev/null
  cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
  cmake --build build -j"$(nproc)"
  ./build/osleuth_core selftest
  PREFIX="${HOME:-/root}/.local/bin"
  mkdir -p "$PREFIX"
  ln -sf "$PWD/build/osleuth_core" "$PREFIX/osleuth_core"
  echo "native core: osleuth_core (also opensleuth cxx ...)"
fi

if [ "$WITH_DESKTOP" = "1" ]; then
  echo "== desktop shell (PyQt6 + QtWebEngine) =="
  $PY -m pip install --break-system-packages -q PyQt6 PyQt6-WebEngine 2>/dev/null \
    || $PY -m pip install -q PyQt6 PyQt6-WebEngine
  PREFIX="${HOME:-/root}/.local/bin"; mkdir -p "$PREFIX"
  REPO="$(cd "$(dirname "$0")" && pwd)"
  cat > "$PREFIX/opensleuth-desktop" <<EOF
#!/usr/bin/env bash
cd "$REPO" && exec $PY -m opensleuth.studio_desktop
EOF
  chmod +x "$PREFIX/opensleuth-desktop"
  echo "desktop shell: opensleuth-desktop"
fi

echo "== done =="
echo "Quick check:  python3 -m opensleuth exposure --chip A13 --ios 26.6.1"