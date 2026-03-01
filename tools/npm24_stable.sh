#!/usr/bin/env bash
set -euo pipefail

# Run npm on Node.js 24 in iSH-64 with a stable configuration.
#
# Why this exists:
# - npm startup currently hits a JIT-path crash in Node 24 on iSH-64.
# - Running npm under --jitless avoids that crash.
#
# Usage:
#   tools/npm24_stable.sh --version
#   tools/npm24_stable.sh install left-pad
#   tools/npm24_stable.sh run test

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ISH_BIN="${ISH_BIN:-$ROOT_DIR/build-64/ish}"
ROOTFS="${ROOTFS:-$ROOT_DIR/alpine64}"
NODE_BIN="${NODE_BIN:-/usr/bin/node24}"
NPM_CLI="${NPM_CLI:-/usr/lib/node_modules/npm/bin/npm-cli.js}"

if [[ ! -x "$ISH_BIN" ]]; then
  echo "error: ish binary not found/executable: $ISH_BIN" >&2
  exit 1
fi

exec "$ISH_BIN" -f "$ROOTFS" /bin/sh -lc \
  "NODE_DISABLE_COMPILE_CACHE=1 \"$NODE_BIN\" --jitless \"$NPM_CLI\" \"\$@\"" \
  sh "$@"

