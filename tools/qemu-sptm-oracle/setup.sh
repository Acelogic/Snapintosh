#!/bin/bash
# SPDX-License-Identifier: MIT
# Build the qemu-sptm SPTM-call oracle (Apple's real SPTM/TXM running this
# repo's 26A428 J700 kernelcache under TCG) into build/qemu-sptm-oracle/.
# Measured on an M3 Max: ~40 s configure + ~60 s make -j14 (aarch64-softmmu).
# Needs: brew glib pixman ninja meson pkgconf dtc libslirp (and network once).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$ROOT/tools/qemu-sptm-oracle"
W="$ROOT/build/qemu-sptm-oracle"
QEMU_COMMIT=2867d847d3471560e773120ee50c42dbcbb6d60b     # jprx/qemu-sptm
DVM_COMMIT=ffdf018                                        # jprx/darwin-vm
mkdir -p "$W"; cd "$W"
if [[ ! -d qemu-sptm ]]; then
  curl -sSL -o qemu-sptm.tar.gz "https://codeload.github.com/jprx/qemu-sptm/tar.gz/$QEMU_COMMIT"
  tar xzf qemu-sptm.tar.gz && mv "qemu-sptm-$QEMU_COMMIT" qemu-sptm
  (cd qemu-sptm && patch -p1 < "$HERE/qemu-sptm-oracle-tracer.patch")
  # gitlab.com/qemu-project returned 503 on 2026-09-24; GitHub mirrors match.
  for w in berkeley-softfloat-3 berkeley-testfloat-3 keycodemapdb dtc; do
    sed -i '' "s#https://gitlab.com/qemu-project/$w.git#https://github.com/qemu/$w.git#" \
      "qemu-sptm/subprojects/$w.wrap"
  done
fi
[[ -d darwin-vm ]] || git clone -q https://github.com/jprx/darwin-vm darwin-vm
mkdir -p qemu-sptm/build && cd qemu-sptm/build
[[ -f config-host.mak ]] || ../configure --target-list=aarch64-softmmu --disable-pvg \
  --disable-docs --extra-cflags=-I/opt/homebrew/include --extra-ldflags=-L/opt/homebrew/lib
make -j"$(sysctl -n hw.ncpu)"
cd "$W"
F="$ROOT/downloads/extracted/j700ap"
python3 "$HERE/j700_dt_fixup.py" "$F/DeviceTree.j700ap" dtree darwin-vm "$F/basesystem-26A428.root-hash"
[[ -f media.img ]] || python3 "$HERE/make_gpt_media.py" "$F/basesystem-26A428.apfs" \
  "${ISC_IMAGE:-$ROOT/build/isc-three-xart-20260923.apfs}" media.img
echo "built $W/qemu-sptm/build/qemu-system-aarch64"
