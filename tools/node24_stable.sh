#!/usr/bin/env bash
set -euo pipefail

# Run Node.js 24 in iSH-64 with a stability workaround applied by default.
#
# Default mode:
#   t1      -> --concurrent-maglev-max-threads=1
#
# Other modes:
#   jitless -> --jitless
#   nomaglev -> --no-maglev
#   nco     -> --no-concurrent-osr
#   nrs     -> --no-rehash-snapshot
#   delay   -> --concurrent-recompilation-delay=1
#   plain   -> no workaround flags
#
# Usage:
#   tools/node24_stable.sh -e 'console.log(42)'
#   NODE24_MODE=jitless tools/node24_stable.sh -e 'console.log(42)'

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ISH_BIN="${ISH_BIN:-$ROOT_DIR/build-64/ish}"
ROOTFS="${ROOTFS:-$ROOT_DIR/alpine64}"
NODE_BIN="${NODE_BIN:-/usr/bin/node24}"
MODE="${NODE24_MODE:-t1}"

if [[ ! -x "$ISH_BIN" ]]; then
  echo "error: ish binary not found/executable: $ISH_BIN" >&2
  exit 1
fi

flags=()
case "$MODE" in
  t1)
    flags+=(--concurrent-maglev-max-threads=1)
    ;;
  delay)
    flags+=(--concurrent-recompilation-delay=1)
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
    echo "error: unknown NODE24_MODE '$MODE' (expected: t1|delay|jitless|nomaglev|nco|nrs|plain)" >&2
    exit 2
    ;;
esac

if [[ ${#flags[@]} -gt 0 ]]; then
  exec "$ISH_BIN" -f "$ROOTFS" "$NODE_BIN" "${flags[@]}" "$@"
else
  exec "$ISH_BIN" -f "$ROOTFS" "$NODE_BIN" "$@"
fi
