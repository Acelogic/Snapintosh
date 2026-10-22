#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Run native CA scenarios against an explicitly identified candidate bundle.

Failure inventory and baseline failures: docs/ADRENO-CA-COMPOSITE-20260928.md.
All native submission interception remains in the hash-bound capture harness.
"""
from pathlib import Path
import argparse
import hashlib
import runpy
import sys

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bundle', type=Path, required=True)
    ap.add_argument('--plugin-sha256', required=True)
    ap.add_argument('--compiler-sha256', help='The bundled libAdrenoCompiler.dylib, when it is not the pinned 7d0e1491 compiler')
    ap.add_argument('--scenes', choices=['composite', 'original'], default='composite')
    ap.add_argument('--private-seed', type=int, help='Explicit replay seed for initially undefined private render targets')
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    bundle = args.bundle.resolve()
    assert sha(bundle / 'Contents/MacOS/AdrenoMetal') == args.plugin_sha256
    base = ROOT / 'tools/capture-ca-desktop-scenes.py'
    assert sha(base) == '953e4f8fda60197602eec95e1b759eab39e5245c32c243e8e18638b0899e57d7'
    if args.private_seed is not None:
        assert args.scenes == 'composite' and 0 <= args.private_seed <= 255
        scope = runpy.run_path(str(ROOT / 'tools/ca-private-capture.py'))['capture_scope'](args.private_seed)
    elif args.scenes == 'composite':
        adapter = ROOT / 'tools/capture-ca-composite-layouts.py'
        assert sha(adapter) == 'ff6175450a6fef82b736bdc039b691fba7fbda856b70c2d315259c9a02802462'
        scope = runpy.run_path(str(adapter))['scope']
    else:
        scope = runpy.run_path(str(base))
    # runpy returns a namespace copy; change the actual main-function globals.
    scope = scope['main'].__globals__
    scope.update(BUNDLE=bundle, PLUGIN_SHA=args.plugin_sha256, __file__=__file__)
    if args.compiler_sha256:
        assert sha(bundle / 'Contents/Frameworks/libAdrenoCompiler.dylib') == args.compiler_sha256
        scope.update(COMPILER_SHA=args.compiler_sha256)
    sys.argv = [__file__, '--output', str(args.output)]
    scope['main']()

if __name__ == '__main__':
    main()
