#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Check .env exists
if [ ! -f "$SCRIPT_DIR/.env" ]; then
    echo "ERROR: $SCRIPT_DIR/.env not found."
    echo "Copy the example:"
    echo "  cp $SCRIPT_DIR/.env.example $SCRIPT_DIR/.env"
    exit 1
fi

# shellcheck disable=SC1090
source "$SCRIPT_DIR/.env"

# Fall back to demo authserver credentials written to /tmp by the AS.
# Treat empty values as unset so an empty AUTHPLANE_CLIENT_SECRET= in .env
# does not block the fallback.
if [[ -z "${AUTHPLANE_CLIENT_ID:-}" && -z "${CLIENT_ID:-}" && -f /tmp/authserver-demo.client-id ]]; then
    export AUTHPLANE_CLIENT_ID="$(cat /tmp/authserver-demo.client-id)"
fi
if [[ -z "${AUTHPLANE_CLIENT_SECRET:-}" && -z "${CLIENT_SECRET:-}" && -f /tmp/authserver-demo.key ]]; then
    export AUTHPLANE_CLIENT_SECRET="$(cat /tmp/authserver-demo.key)"
fi

ISSUER="${AUTHPLANE_ISSUER:-${ISSUER_URL:-http://127.0.0.1:9000}}"
METADATA_URL="${ISSUER%/}/.well-known/oauth-authorization-server"
if ! command -v curl >/dev/null 2>&1; then
    echo "WARN: curl not found; skipping issuer preflight check ($METADATA_URL)."
else
    if ! curl -fsS "$METADATA_URL" >/dev/null 2>&1; then
        echo "ERROR: cannot reach authorization server metadata at:"
        echo "  $METADATA_URL"
        echo
        echo "Start your AS (authserver) first, or fix AUTHPLANE_ISSUER in demo/.env."
        echo "Tip: prefer http://127.0.0.1:9000 over localhost in this environment."
        exit 1
    fi
fi

REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

cd "$PROJECT_DIR"

# Install dependencies if needed (npm workspaces hoist to repo root)
if [ ! -d "$REPO_ROOT/node_modules" ]; then
    (cd "$REPO_ROOT" && npm ci)
fi

npx tsx "$SCRIPT_DIR/mcpserver.ts"
