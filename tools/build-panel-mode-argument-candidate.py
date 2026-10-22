#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the captured mode-argument correction in the idle fill checkout.

The running-generation source checkouts remain untouched. Reuse the prior
single-object native link and signature qualification with a new output path.
"""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / 'tools/build-panel-mode-candidate.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == 'a8926bcf309eb02250f5f8f3a424e4f832047491474428c52fa518c75c89dcab'
source = base.read_text()
old = "SOURCE = ROOT.parent / 'Snapintosh-adreno-clear'"
assert source.count(old) == 1
source = source.replace(old, "SOURCE = ROOT.parent / 'Snapintosh-adreno-fill'")
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))
