#!/usr/bin/env bash
set -euo pipefail

# Run Node.js 24 in iSH-64 with a stability workaround applied by default.
#
# Default mode:
#   delay  -> --concurrent-recompilation-delay=1
#
# Other modes:
#   jitless -> --jitless
#   nco     -> --no-concurrent-osr
#   nrs     -> --no-rehash-snapshot
#   plain   -> no workaround flags
#
# Usage:
#   tools/node24_stable.sh -e 'console.log(42)'
#   NODE24_MODE=jitless tools/node24_stable.sh -e 'console.log(42)'

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ISH_BIN="${ISH_BIN:-$ROOT_DIR/build-64/ish}"
ROOTFS="${ROOTFS:-$ROOT_DIR/alpine64}"
NODE_BIN="${NODE_BIN:-/usr/bin/node24}"
MODE="${NODE24_MODE:-delay}"

if [[ ! -x "$ISH_BIN" ]]; then
  echo "error: ish binary not found/executable: $ISH_BIN" >&2
  exit 1
fi

flags=()
case "$MODE" in
  delay)
    flags+=(--concurrent-recompilation-delay=1)
    ;;
  jitless)
    flags+=(--jitless)
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
    echo "error: unknown NODE24_MODE '$MODE' (expected: delay|jitless|nco|nrs|plain)" >&2
    exit 2
    ;;
esac

if [[ ${#flags[@]} -gt 0 ]]; then
  exec "$ISH_BIN" -f "$ROOTFS" "$NODE_BIN" "${flags[@]}" "$@"
else
  exec "$ISH_BIN" -f "$ROOTFS" "$NODE_BIN" "$@"
fi
