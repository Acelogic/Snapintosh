#!/bin/sh
# SPDX-License-Identifier: MIT
# SHA-256 of each section's bytes that carries code or data the kext runs (DWARF and paths excluded): __TEXT,__text,
# __TEXT,__cstring, __TEXT,__const, __DATA,__data, __DATA,__const, plus the undefined-symbol list.
for f in "$@"; do
  for s in "__TEXT __text" "__TEXT __cstring" "__TEXT __const" "__DATA __data" "__DATA __const" "__DATA_CONST __const"; do
    set -- $s
    h=$(xcrun otool -s $1 $2 "$f" 2>/dev/null | tail -n +3 | shasum -a 256 | cut -c1-16)
    printf '%s %s,%s %s\n' "$(basename $f)" $1 $2 $h
  done
  printf '%s undef %s\n' "$(basename $f)" "$(xcrun nm -u "$f" | shasum -a 256 | cut -c1-16)"
done
