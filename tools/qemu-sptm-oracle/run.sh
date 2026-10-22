#!/bin/bash
# SPDX-License-Identifier: MIT
# One oracle boot: writes <out>/sptm-trace.txt, serial.log, summary.txt, rows.txt.
#   tools/qemu-sptm-oracle/run.sh <out-dir> [seconds]
# Single CPU, PAC disabled by qemu-sptm, no SPRR TLB coherence: use the trace
# for SPTM/TXM call semantics (types, options, PTEs, status), not for SPRR
# permission enforcement or multi-CPU ordering. x0=5,x1=1 marks a preempted
# call that XNU resumes with dispatch cmd 4.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$ROOT/tools/qemu-sptm-oracle"; W="$ROOT/build/qemu-sptm-oracle"
OUT="$(mkdir -p "$1" && cd "$1" && pwd)"; SECS="${2:-600}"
F="$ROOT/downloads/extracted/j700ap"
export QEMU_SPTM_TRACE="$OUT/sptm-trace.txt" QEMU_SPTM_TRACE_LAYOUT=1
gtimeout --signal=TERM "$SECS" "$W/qemu-sptm/build/qemu-system-aarch64" -M darwin \
  -bootkc "$F/kernelcache.release.mac17p" -dtree "$W/dtree" \
  -tc "$F/basesystem-26A428.trustcache" -ramdisk "$W/media.img" \
  -sptm "$F/sptm.t8140.release" -txm "$F/txm.macosx.release" \
  -args "serial=3 -v -noprogress wdt=-1 cpus=1 acm_fastsim=1 debug=0x8 keepsyms=1 wlan-olyhal-abort" \
  -display none -monitor none -serial "file:$OUT/serial.log" -m 16G \
  2> "$OUT/qemu-stderr.log" || true
python3 "$HERE/sptm_oracle.py" "$OUT/sptm-trace.txt" --json "$OUT/summary.json" > "$OUT/summary.txt"
python3 "$HERE/oracle_rows.py" "$OUT/sptm-trace.txt" "$OUT/rows.txt"
