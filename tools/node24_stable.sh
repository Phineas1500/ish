#!/usr/bin/env bash
set -euo pipefail

# Run Node.js 24 in iSH-64 with a stability workaround applied by default.
#
# Default mode:
#   jitless -> --jitless (most reliable under current stress testing)
#
# Other modes:
#   t1      -> --concurrent-maglev-max-threads=1
#   notf    -> --no-turbofan
#   noopt   -> --no-opt
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
#
# Note:
#   For npm workloads, prefer tools/npm24_stable.sh. It defaults to --jitless
#   to avoid a currently reproducible Node24 JIT-path crash during npm startup.
#   This launcher also disables Node's compile cache by default for stability.

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ISH_BIN="${ISH_BIN:-$ROOT_DIR/build-64/ish}"
ROOTFS="${ROOTFS:-$ROOT_DIR/alpine64}"
NODE_BIN="${NODE_BIN:-/usr/bin/node24}"
MODE="${NODE24_MODE:-jitless}"

if [[ ! -x "$ISH_BIN" ]]; then
  echo "error: ish binary not found/executable: $ISH_BIN" >&2
  exit 1
fi

flags=()
case "$MODE" in
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
    echo "error: unknown NODE24_MODE '$MODE' (expected: nmd|t1|delay|notf|noopt|jitless|nomaglev|nco|nrs|plain)" >&2
    exit 2
    ;;
esac

if [[ ${#flags[@]} -gt 0 ]]; then
  exec "$ISH_BIN" -f "$ROOTFS" /usr/bin/env NODE_DISABLE_COMPILE_CACHE=1 \
    "$NODE_BIN" "${flags[@]}" "$@"
else
  exec "$ISH_BIN" -f "$ROOTFS" /usr/bin/env NODE_DISABLE_COMPILE_CACHE=1 \
    "$NODE_BIN" "$@"
fi
