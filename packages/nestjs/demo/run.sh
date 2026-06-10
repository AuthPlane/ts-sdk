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

ISSUER="${AUTHPLANE_ISSUER:-${ISSUER_URL:-http://localhost:9000}}"
METADATA_URL="${ISSUER%/}/.well-known/oauth-authorization-server"
if ! command -v curl >/dev/null 2>&1; then
    echo "WARN: curl not found; skipping issuer preflight check ($METADATA_URL)."
else
    if ! curl -fsS "$METADATA_URL" >/dev/null 2>&1; then
        echo "ERROR: cannot reach authorization server metadata at:"
        echo "  $METADATA_URL"
        echo
        echo "Start your AS (authserver) first, or fix AUTHPLANE_ISSUER in demo/.env."
        exit 1
    fi
fi

REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

cd "$PROJECT_DIR"

# Install dependencies if needed (npm workspaces hoist to repo root)
if [ ! -d "$REPO_ROOT/node_modules" ]; then
    (cd "$REPO_ROOT" && npm ci)
fi

# NestJS uses experimental decorators which esbuild (tsx) cannot enable per-file
# when the demo path is excluded from the package tsconfig. ts-node honors the
# nested demo/tsconfig.json and applies experimentalDecorators correctly.
#
# `--import` + a bootstrap that calls node:module's `register()` is the
# forward-compatible replacement for `--loader ts-node/esm`, which Node ≥20
# deprecates and will eventually drop.
#
# TODO: collapse back to `tsx` (and drop ts-node from devDependencies) if/when
# tsx/esbuild grow per-file `experimentalDecorators` support — every other
# adapter demo runs on tsx and we don't want nestjs to drift indefinitely.
TS_NODE_PROJECT="$SCRIPT_DIR/tsconfig.json" \
    node --import "$SCRIPT_DIR/register.mjs" "$SCRIPT_DIR/server.ts"
