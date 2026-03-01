#!/usr/bin/env bash
set -euo pipefail

# Run npm using Node.js 24 inside iSH-64 with a stable workaround profile.
#
# Usage:
#   tools/npm24_stable.sh --version
#   tools/npm24_stable.sh init -y
#   NODE24_MODE=t1 tools/npm24_stable.sh install lodash
#
# Environment:
#   ISH_BIN: path to ish binary (default: build-64/ish)
#   ROOTFS: guest rootfs path (default: alpine64)
#   NODE_BIN: path to node binary in guest (default: /usr/bin/node24)
#   NPM_CLI: path to npm cli script in guest rootfs
#   NODE24_MODE: mode override (default here: notf)
#   NODE_DISABLE_COMPILE_CACHE: compile cache toggle (default here: 1)

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ISH_BIN="${ISH_BIN:-$ROOT_DIR/build-64/ish}"
ROOTFS="${ROOTFS:-$ROOT_DIR/alpine64}"
NODE_BIN="${NODE_BIN:-/usr/bin/node24}"
NPM_CLI="${NPM_CLI:-/usr/lib/node_modules/npm/bin/npm-cli.js}"

# npm startup on Node 24 is currently most reliable with Turbofan disabled.
: "${NODE24_MODE:=notf}"

# Avoid stale/corrupted cache entries causing validate-engines failures.
: "${NODE_DISABLE_COMPILE_CACHE:=1}"

if [[ ! -x "$ISH_BIN" ]]; then
  echo "error: ish binary not found/executable: $ISH_BIN" >&2
  exit 1
fi

flags=()
case "$NODE24_MODE" in
  nmd)
    flags+=(--no-maglev-destroy-on-background)
    ;;
  t1)
    flags+=(--concurrent-maglev-max-threads=1)
    ;;
  delay)
    flags+=(--concurrent-recompilation-delay=1)
    ;;
  notf)
    flags+=(--no-turbofan)
    ;;
  noopt)
    flags+=(--no-opt)
    ;;
  jitless)
    flags+=(--jitless)
    ;;
  nomaglev)
    flags+=(--no-maglev)
    ;;
  nco)
    flags+=(--no-concurrent-osr)
    ;;
  nrs)
    flags+=(--no-rehash-snapshot)
    ;;
  plain)
    ;;
  *)
    echo "error: unknown NODE24_MODE '$NODE24_MODE' (expected: nmd|t1|delay|notf|noopt|jitless|nomaglev|nco|nrs|plain)" >&2
    exit 2
    ;;
esac

exec "$ISH_BIN" -f "$ROOTFS" /usr/bin/env \
  "NODE_DISABLE_COMPILE_CACHE=$NODE_DISABLE_COMPILE_CACHE" \
  "$NODE_BIN" "${flags[@]}" "$NPM_CLI" "$@"
