#!/usr/bin/env bash
set -euo pipefail

# Repro/profile helper for Node 24 no-flags startup crash in iSH-64.
# Compares baseline no-flags startup against --no-maglev-osr.
# Captures fd666 trace output, summarizes thread lifecycle and futex behavior,
# and prints a static lock-instruction histogram for the Node binary.

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ISH_BIN="${ISH_BIN:-$ROOT_DIR/build-64/ish}"
ROOTFS="${ROOTFS:-$ROOT_DIR/alpine64}"
NODE_BIN="${NODE_BIN:-/usr/bin/node24}"
OUT_DIR="${OUT_DIR:-/tmp/ish-node24-maglev-profile}"

mkdir -p "$OUT_DIR"

if [[ ! -x "$ISH_BIN" ]]; then
  echo "error: ish binary not found/executable: $ISH_BIN" >&2
  exit 1
fi

OBJ_DUMP=""
if command -v llvm-objdump >/dev/null 2>&1; then
  OBJ_DUMP="$(command -v llvm-objdump)"
elif command -v objdump >/dev/null 2>&1; then
  OBJ_DUMP="$(command -v objdump)"
fi

run_case() {
  local name="$1"
  shift || true
  local trace="$OUT_DIR/${name}.fd666.log"
  local stdout_log="$OUT_DIR/${name}.stdout.log"
  local stderr_log="$OUT_DIR/${name}.stderr.log"

  echo "=== $name ==="

  local flags_str="$*"
  bash -lc "exec 666>'$trace'; '$ISH_BIN' -f '$ROOTFS' '$NODE_BIN' $flags_str -e 'console.log(42)' >'$stdout_log' 2>'$stderr_log'"
  local rc=$?

  echo "rc=$rc"
  echo "stdout:"
  sed -n '1,6p' "$stdout_log"
  echo "stderr:"
  sed -n '1,16p' "$stderr_log"
  echo "trace lines: $(wc -l < "$trace" | tr -d ' ')"

  echo "threads (pid:name):"
  perl -ne 'if(/^([0-9]+) call \d+\s+prctl\(PRCTL_SET_NAME, "([^"]+)"\)/){print "$1:$2\n"}' "$trace" | awk '!seen[$0]++' | sed -n '1,30p'

  echo "worker syscall counts (pids 2-6):"
  perl -ne 'if(/^([2-6]) call \d+\s+([A-Za-z_][A-Za-z0-9_]*)\(/){$c{"$1:$2"}++} END{for $k (sort {$c{$b}<=>$c{$a}} keys %c){print "$c{$k} $k\n"}}' "$trace" | sed -n '1,30p'

  echo "futex wait return summary:"
  perl -ne 'if(/^([0-9]+) end futex\(FUTEX_WAIT\) = (0x[0-9a-f]+)/){$c{"$1:$2"}++} END{for $k (sort keys %c){print "$c{$k} $k\n"}}' "$trace" | sed -n '1,30p'

  echo
}

run_case baseline_noflags
run_case no_maglev_osr --no-maglev-osr

if [[ -n "$OBJ_DUMP" ]]; then
  NODE_HOST_BIN="$ROOTFS/data$NODE_BIN"
  if [[ -f "$NODE_HOST_BIN" ]]; then
    echo "=== static lock-instruction histogram ($NODE_HOST_BIN) ==="
    "$OBJ_DUMP" -d "$NODE_HOST_BIN" \
      | awk 'BEGIN{want=0} {if (want==1) { n=split($0,f,"\t"); if (n>=2){ split(f[2],g,/ /); if (g[1]!="") print g[1]; } want=0 } if ($0 ~ /\tlock\s*$/) want=1 }' \
      | sort | uniq -c | sort -nr | sed -n '1,20p'
    echo
  else
    echo "note: node host binary not found at $NODE_HOST_BIN"
  fi
else
  echo "note: llvm-objdump/objdump not found; skipping lock-instruction histogram"
fi

echo "profiles written to: $OUT_DIR"
