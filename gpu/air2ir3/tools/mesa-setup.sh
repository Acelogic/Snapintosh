#!/bin/zsh
# SPDX-License-Identifier: MIT
# Fetch (if needed), patch and configure the private Mesa build (README.md "Rebuild").
#   MESA_URL=<git url or local mirror> tools/mesa-setup.sh
# Idempotent: skips the clone when third_party/mesa exists, re-applies nothing that is already applied.
set -e
ROOT=${0:a:h:h}
MESA_URL=${MESA_URL:-https://gitlab.freedesktop.org/mesa/mesa.git}
REV=bbeb2dca9feed6ac88d71234a9dc5ae8aeed4275
export PATH=/opt/homebrew/opt/llvm/bin:$PATH
mkdir -p $ROOT/third_party $ROOT/build $ROOT/scratch $ROOT/results
if [[ ! -d $ROOT/third_party/mesa/.git ]]; then
  git clone --quiet $MESA_URL $ROOT/third_party/mesa
  git -C $ROOT/third_party/mesa checkout --quiet $REV
fi
[[ $(git -C $ROOT/third_party/mesa rev-parse HEAD) == $REV ]] || { echo "third_party/mesa is not at $REV"; exit 1; }
for p in $ROOT/patches/0*.patch; do
  if git -C $ROOT/third_party/mesa apply --reverse --check $p 2>/dev/null; then echo "already applied: ${p:t}";
  else git -C $ROOT/third_party/mesa apply $p; echo "applied: ${p:t}"; fi
done
cp $ROOT/patches/ir3_parse_stub.c $ROOT/patches/ir3_parser.h $ROOT/third_party/mesa/src/freedreno/ir3/
opts=()
while IFS= read -r l; do [[ -n $l ]] && opts+=(-D$l); done < $ROOT/tools/mesa-options.txt
if [[ -f $ROOT/build/mesa/build.ninja ]]; then
  meson configure $ROOT/build/mesa $opts >/dev/null
else
  meson setup $ROOT/build/mesa $ROOT/third_party/mesa $opts
fi
