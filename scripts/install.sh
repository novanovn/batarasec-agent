#!/usr/bin/env bash
# BataraSec Agent — one-liner installer
# Usage: curl -fsSL https://<platform>/agent/install.sh | sudo bash
#        BATARASEC_PLATFORM_URL=https://... bash install.sh
set -euo pipefail

PLATFORM_URL="${BATARASEC_PLATFORM_URL:-https://103.93.160.112}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/batarasec"
DATA_DIR="/var/lib/batarasec"
BINARY="batarasec-agent"
SYSTEMD_DIR="/etc/systemd/system"

# Supported: Ubuntu 22.04, Debian 12, RHEL 9, Rocky 9
detect_platform() {
  local os arch
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  arch=$(uname -m)
  case "$arch" in
    x86_64)        arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) echo "Unsupported architecture: $arch" >&2; exit 1 ;;
  esac
  echo "${os}-${arch}"
}

main() {
  if [[ $EUID -ne 0 ]]; then
    echo "Please run as root (sudo bash install.sh)" >&2
    exit 1
  fi

  local platform
  platform=$(detect_platform)

  echo "==> Installing BataraSec Agent (${platform})"
  mkdir -p "$CONFIG_DIR" "$DATA_DIR/vuln-db"

  # Download binary and verify checksum.
  local url="${PLATFORM_URL}/agent/releases/${BINARY}-${platform}"
  local checksum_url="${PLATFORM_URL}/agent/releases/checksums.txt"

  echo "==> Downloading ${url}"
  curl -fsSL "$url" -o "${INSTALL_DIR}/${BINARY}"
  chmod +x "${INSTALL_DIR}/${BINARY}"

  # Verify checksum if available.
  if curl -fsSL "$checksum_url" -o /tmp/batarasec-checksums.txt 2>/dev/null; then
    if command -v sha256sum &>/dev/null; then
      expected=$(grep "${BINARY}-${platform}" /tmp/batarasec-checksums.txt | awk '{print $1}')
      actual=$(sha256sum "${INSTALL_DIR}/${BINARY}" | awk '{print $1}')
      if [[ "$expected" != "$actual" ]]; then
        echo "Checksum mismatch! Aborting." >&2
        rm -f "${INSTALL_DIR}/${BINARY}"
        exit 1
      fi
      echo "==> Checksum OK"
    fi
    rm -f /tmp/batarasec-checksums.txt
  fi

  # Write default config if absent.
  if [[ ! -f "${CONFIG_DIR}/agent.yaml" ]]; then
    cat > "${CONFIG_DIR}/agent.yaml" <<EOF
platform_url: "${PLATFORM_URL}"
cache_path: "${DATA_DIR}/cache.db"
vuln_db_path: "${DATA_DIR}/vuln-db"
scan_paths:
  - /home
  - /opt
  - /srv
  - /var/www
log_level: info
tls_skip_verify: false
EOF
    chmod 0600 "${CONFIG_DIR}/agent.yaml"
    echo "==> Config written to ${CONFIG_DIR}/agent.yaml"
  fi

  # Install systemd units.
  if command -v systemctl &>/dev/null; then
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    cp "${script_dir}/systemd/batarasec-agent.service" "$SYSTEMD_DIR/"
    cp "${script_dir}/systemd/batarasec-agent.timer"   "$SYSTEMD_DIR/"
    systemctl daemon-reload
    systemctl enable --now batarasec-agent.timer
    echo "==> Systemd timer enabled (every 6 hours)"
  fi

  echo ""
  echo "Installation complete! Next step:"
  echo "  ${BINARY} enroll --token <YOUR_ENROLLMENT_TOKEN>"
}

main "$@"
