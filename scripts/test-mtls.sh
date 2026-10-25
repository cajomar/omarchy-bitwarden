#!/usr/bin/env bash
# ==============================================================================
# scripts/test-mtls.sh: Local mTLS Deployment, Verification & Teardown Script
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_PATH="${ROOT_DIR}/omawarden/target/debug/omawarden"
WORK_DIR="/tmp/omawarden-mtls-test"
PID_FILE="${WORK_DIR}/server.pid"
BACKUP_CFG="${WORK_DIR}/config_backup.json"
PORT="8443"

ensure_binary() {
  if [ ! -f "${BIN_PATH}" ]; then
    echo ">> Building omawarden debug binary..."
    (cd "${ROOT_DIR}/omawarden" && cargo build)
  fi
}

cmd_setup() {
  ensure_binary
  echo ">> [1/3] Preparing temporary test directory at ${WORK_DIR}..."
  mkdir -p "${WORK_DIR}"

  # Backup user configuration if present
  local default_cfg_path="${XDG_CONFIG_HOME:-${HOME}/.config}/omawarden/config.json"
  if [ -f "${default_cfg_path}" ]; then
    echo ">> Backing up current omawarden config to ${BACKUP_CFG}..."
    cp "${default_cfg_path}" "${BACKUP_CFG}"
  fi

  echo ">> [2/3] Generating local test Certificate Authority & Keys..."
  cd "${WORK_DIR}"

  # 1. Root CA
  openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days 1 \
    -subj "/CN=Omawarden Local CA" 2>/dev/null

  # 2. Server Certificate (SAN for localhost & 127.0.0.1)
  openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
    -subj "/CN=localhost" 2>/dev/null
  openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days 1 \
    -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment") 2>/dev/null

  # 3. Client Certificate & Private Key
  openssl req -newkey rsa:2048 -nodes -keyout client.key -out client.csr \
    -subj "/CN=omawarden-client" 2>/dev/null
  openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out client.crt -days 1 \
    -extfile <(printf "extendedKeyUsage=clientAuth\nkeyUsage=digitalSignature,keyEncipherment") 2>/dev/null

  # 4. Merged PEM bundle
  cat client.crt client.key > client-bundle.pem

  # Set 0600 POSIX permissions
  chmod 600 client.key client-bundle.pem

  echo ">> [3/3] Starting local mTLS OpenSSL gateway on https://127.0.0.1:${PORT}..."
  openssl s_server -accept "127.0.0.1:${PORT}" \
    -cert "${WORK_DIR}/server.crt" \
    -key "${WORK_DIR}/server.key" \
    -CAfile "${WORK_DIR}/ca.crt" \
    -Verify 1 \
    -www >"${WORK_DIR}/server.log" 2>&1 &
  local srv_pid=$!
  echo "${srv_pid}" > "${PID_FILE}"
  sleep 1

  if kill -0 "${srv_pid}" 2>/dev/null; then
    echo ">> mTLS Gateway running successfully (PID: ${srv_pid})."
  else
    echo "ERROR: Failed to start local mTLS gateway."
    cat "${WORK_DIR}/server.log" || true
    exit 1
  fi
}

cmd_test() {
  ensure_binary
  if [ ! -f "${PID_FILE}" ] || ! kill -0 "$(<"${PID_FILE}")" 2>/dev/null; then
    echo "mTLS Gateway is not running. Please run '$0 setup' first."
    exit 1
  fi

  export SSL_CERT_FILE="${WORK_DIR}/ca.crt"
  local srv_url="https://127.0.0.1:${PORT}"

  echo "=========================================================="
  echo ">> [Test 1] Insecure key permissions (0644) rejected..."
  chmod 644 "${WORK_DIR}/client.key"
  set +e
  local perm_output
  perm_output="$("${BIN_PATH}" config set --server-url "${srv_url}" \
      --client-cert "${WORK_DIR}/client.crt" \
      --client-key "${WORK_DIR}/client.key" 2>&1)"
  local perm_code=$?
  set -e

  if [ "${perm_code}" -ne 0 ] && echo "${perm_output}" | grep -q "Insecure permissions"; then
    echo "   [PASS] Successfully blocked insecure key (0644) with actionable warning."
  else
    echo "   [FAIL] Expected 0644 key to be rejected! Output: ${perm_output}"
    exit 1
  fi

  echo ">> [Test 2] Setting valid mTLS credentials (0600)..."
  chmod 600 "${WORK_DIR}/client.key"
  "${BIN_PATH}" config set --server-url "${srv_url}" \
    --client-cert "${WORK_DIR}/client.crt" \
    --client-key "${WORK_DIR}/client.key" >/dev/null

  local bound_server
  bound_server="$("${BIN_PATH}" config get client_cert_server)"
  if [ "${bound_server}" = "${srv_url}" ]; then
    echo "   [PASS] Client cert automatically bound to origin: ${bound_server}"
  else
    echo "   [FAIL] Expected bound server ${srv_url}, got: ${bound_server}"
    exit 1
  fi

  echo ">> [Test 3] Testing mTLS handshake via health status..."
  if "${BIN_PATH}" health 2>/dev/null | grep -q '"server_reachable": true'; then
    echo "   [PASS] Handshake succeeded: gateway accepted client certificate."
  else
    echo "   [FAIL] Health check failed to connect over mTLS."
    "${BIN_PATH}" health || true
    echo ">> Server Log:"
    cat "${WORK_DIR}/server.log" || true
    exit 1
  fi

  echo ">> [Test 4] Origin isolation on server switch..."
  "${BIN_PATH}" config set --server-url "https://vault.bitwarden.com" >/dev/null
  local cert_path_after
  cert_path_after="$("${BIN_PATH}" config get client_cert_path)"
  local bound_server_after
  bound_server_after="$("${BIN_PATH}" config get client_cert_server)"

  if [ "${cert_path_after}" = "${WORK_DIR}/client.crt" ] && [ "${bound_server_after}" = "${srv_url}" ]; then
    echo "   [PASS] Certificate retained for ${srv_url} without leaking to foreign origin."
  else
    echo "   [FAIL] Origin isolation failed after server switch."
    exit 1
  fi

  echo ">> [Test 5] Combined PEM bundle support..."
  "${BIN_PATH}" config set --server-url "${srv_url}" \
    --client-cert "${WORK_DIR}/client-bundle.pem" \
    --client-key "" >/dev/null
  if "${BIN_PATH}" health 2>/dev/null | grep -q '"server_reachable": true'; then
    echo "   [PASS] Handshake succeeded using combined PEM bundle."
  else
    echo "   [FAIL] Combined PEM bundle handshake failed."
    exit 1
  fi

  echo "=========================================================="
  echo ">> ALL LOCAL mTLS VERIFICATION TESTS PASSED SUCCESSFULLY!"
  echo "=========================================================="
}

cmd_restore() {
  echo ">> Restoring environment..."

  # Stop server
  if [ -f "${PID_FILE}" ]; then
    local pid
    pid="$(<"${PID_FILE}")"
    if kill -0 "${pid}" 2>/dev/null; then
      echo ">> Stopping mTLS gateway (PID: ${pid})..."
      kill "${pid}" 2>/dev/null || true
    fi
    rm -f "${PID_FILE}"
  fi

  # Restore config
  local default_cfg_path="${XDG_CONFIG_HOME:-${HOME}/.config}/omawarden/config.json"
  if [ -f "${BACKUP_CFG}" ]; then
    echo ">> Restoring original omawarden configuration from backup..."
    cp "${BACKUP_CFG}" "${default_cfg_path}"
  elif [ -f "${BIN_PATH}" ]; then
    echo ">> Clearing test client cert configuration..."
    "${BIN_PATH}" config set --client-cert "" --client-key "" --server-url "https://vault.bitwarden.com" >/dev/null 2>&1 || true
  fi

  # Remove temp files
  if [ -d "${WORK_DIR}" ]; then
    echo ">> Removing temporary files in ${WORK_DIR}..."
    rm -rf "${WORK_DIR}"
  fi

  echo ">> Teardown and restore complete."
}

usage() {
  echo "Usage: $0 {setup|test|restore|run}"
  echo ""
  echo "Commands:"
  echo "  setup    - Generates test CA & certs, backs up config, and starts local mTLS gateway."
  echo "  test     - Runs automated security, handshake, and origin isolation tests against gateway."
  echo "  restore  - Terminates gateway, restores original config, and removes temp files."
  echo "  run      - (Default) Executes setup -> test -> restore in one clean pass."
  exit 1
}

main() {
  local action="${1:-run}"
  case "${action}" in
    setup)
      cmd_setup
      ;;
    test)
      cmd_test
      ;;
    restore|teardown|clean)
      cmd_restore
      ;;
    run|all)
      trap cmd_restore EXIT
      cmd_setup
      cmd_test
      ;;
    *)
      usage
      ;;
  esac
}

main "$@"
