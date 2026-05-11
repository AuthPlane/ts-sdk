#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ADAPTER="mcp"
RUN_SETUP=1
export ISSUER_URL="${ISSUER_URL:-http://localhost:9000}"
export BASE_URL="${BASE_URL:-http://localhost:8080}"
export RESOURCE_URL="${RESOURCE_URL:-${BASE_URL%/}/mcp}"

usage() {
  cat <<'EOF'
Usage:
  manual-e2e-smoke.sh [--adapter mcp|fastmcp] [--skip-setup]
EOF
}

while [ "${#}" -gt 0 ]; do
  case "$1" in
    --adapter)
      ADAPTER="${2:-}"
      shift
      ;;
    --skip-setup)
      RUN_SETUP=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

if [ "${ADAPTER}" = "mcp" ]; then
  PACKAGE_DIR="${REPO_ROOT}/packages/mcp"
  ADAPTER_PKG="@authplane/mcp"
elif [ "${ADAPTER}" = "fastmcp" ]; then
  PACKAGE_DIR="${REPO_ROOT}/packages/fastmcp"
  ADAPTER_PKG="@authplane/fastmcp"
else
  echo "Invalid adapter: ${ADAPTER}" >&2
  exit 1
fi

SERVER_LOG="/tmp/ts-sdk-manual-e2e-smoke-${ADAPTER}.log"
RESOURCE_BASE="${RESOURCE_URL%/mcp}"
if [ "${RESOURCE_BASE}" = "${RESOURCE_URL}" ]; then
  echo "ERROR: RESOURCE_URL must end with /mcp, got ${RESOURCE_URL}" >&2
  exit 1
fi
PRM_URL="${RESOURCE_BASE}/.well-known/oauth-protected-resource/mcp"

cleanup() {
  if [ -n "${SERVER_PID:-}" ]; then
    pkill -P "${SERVER_PID}" || true
    kill "${SERVER_PID}" || true
  fi
  pkill -f "${REPO_ROOT}/packages/mcp/demo/mcpserver.ts" || true
  pkill -f "${REPO_ROOT}/packages/fastmcp/demo/mcpserver.ts" || true
}
trap cleanup EXIT

if [ "${RUN_SETUP}" -eq 1 ]; then
  bash "${SCRIPT_DIR}/manual-e2e-setup.sh"
fi

if [ ! -f /tmp/authserver-demo.client-id ] || [ ! -f /tmp/authserver-demo.key ]; then
  echo "ERROR: missing /tmp/authserver-demo.client-id or /tmp/authserver-demo.key" >&2
  exit 1
fi

CLIENT_ID="$(cat /tmp/authserver-demo.client-id)"
CLIENT_SECRET="$(cat /tmp/authserver-demo.key)"
DEMO_ENV="${PACKAGE_DIR}/demo/.env"

cat >"${DEMO_ENV}" <<EOF
AUTHPLANE_ISSUER=http://127.0.0.1:9000
AUTHPLANE_CLIENT_ID=${CLIENT_ID}
AUTHPLANE_CLIENT_SECRET=${CLIENT_SECRET}
EOF

if [ "${ADAPTER}" = "mcp" ]; then
  cat >>"${DEMO_ENV}" <<EOF
AUTHPLANE_RESOURCE=${RESOURCE_URL}
EOF
else
  cat >>"${DEMO_ENV}" <<EOF
AUTHPLANE_BASE_URL=${RESOURCE_BASE}
EOF
fi

echo "==> Starting TypeScript demo (${ADAPTER})"
(
  cd "${REPO_ROOT}"
  if [ ! -d node_modules ]; then
    npm ci
  fi
  npm run build -w @authplane/sdk
  npm run build -w "${ADAPTER_PKG}"
  cd "${PACKAGE_DIR}"
  ./demo/run.sh >"${SERVER_LOG}" 2>&1
) &
SERVER_PID=$!

echo "==> Waiting for PRM: ${PRM_URL}"
for _ in $(seq 1 60); do
  status="$(curl -sS -o /dev/null -w "%{http_code}" "${PRM_URL}" || true)"
  if [ "${status}" = "200" ] || [ "${status}" = "401" ]; then
    break
  fi
  sleep 1
done
status="$(curl -sS -o /dev/null -w "%{http_code}" "${PRM_URL}" || true)"
if [ "${status}" != "200" ] && [ "${status}" != "401" ]; then
  echo "ERROR: PRM endpoint not ready (status=${status})" >&2
  echo "Server log: ${SERVER_LOG}" >&2
  exit 1
fi

echo "==> Minting token (tools/add)"
TOKEN_JSON="$(
  curl -sS -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials" \
    -d "resource=${RESOURCE_URL}" \
    -d "scope=tools/add" \
    "${ISSUER_URL}/oauth/token"
)"

TOKEN_ERROR="$(
  echo "${TOKEN_JSON}" | node -e 'let data="";process.stdin.on("data",d=>data+=d);process.stdin.on("end",()=>console.log((JSON.parse(data).error)||""));'
)"
if [ "${TOKEN_ERROR}" = "invalid_scope" ]; then
  echo "==> Scope tools/add not available, retrying token mint without scope"
  TOKEN_JSON="$(
    curl -sS -u "${CLIENT_ID}:${CLIENT_SECRET}" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=client_credentials" \
      -d "resource=${RESOURCE_URL}" \
      "${ISSUER_URL}/oauth/token"
  )"
fi

ACCESS_TOKEN="$(
  echo "${TOKEN_JSON}" | node -e 'let data="";process.stdin.on("data",d=>data+=d);process.stdin.on("end",()=>console.log((JSON.parse(data).access_token)||""));'
)"
if [ -z "${ACCESS_TOKEN}" ]; then
  echo "ERROR: token mint failed" >&2
  echo "${TOKEN_JSON}" >&2
  exit 1
fi

echo "==> Checking unauthenticated /mcp is blocked"
mcp_status="$(
  curl -sS -o /dev/null -w "%{http_code}" -X POST "${RESOURCE_URL}" \
    -H "Content-Type: application/json" \
    -d '{}' || true
)"
if [ "${mcp_status}" = "200" ]; then
  echo "ERROR: unauthenticated /mcp request unexpectedly returned 200" >&2
  exit 1
fi
if [ "${mcp_status}" = "000" ]; then
  echo "ERROR: unauthenticated /mcp check could not reach server" >&2
  exit 1
fi

echo ""
echo "Smoke check passed (ts-sdk, adapter=${ADAPTER})"
echo "PRM: ${PRM_URL}"
echo "Server log: ${SERVER_LOG}"
