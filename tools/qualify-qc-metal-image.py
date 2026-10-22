#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the full guest image with the accepted SKS runtime and new code trust."""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT.parent / 'Snapintosh-adreno-sks'
base = ROOT / 'tools/qualify-adreno-gui-image.py'
source = base.read_text()
changes = {
    "str(p.relative_to(ROOT)): sha(p) for directory in ('probes', 'compat', 'shadow')\n        for p in (ROOT/directory).rglob('*')":
        "str(p): sha(p) for directory in ('probes', 'compat', 'shadow')\n        for p in (RUNTIME/directory).rglob('*')",
    "sys.path.insert(0, str(ROOT/'probes'))": "sys.path.insert(0, str(RUNTIME/'probes'))",
    "assert profile == 'j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display'":
        "assert profile == 'j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display-sks'",
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__', RUNTIME=RUNTIME))
