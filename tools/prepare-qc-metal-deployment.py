#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reuse signed bundle staging with the accepted SKS runtime profile/trust code."""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT.parent / 'Snapintosh-adreno-sks'
base = ROOT / 'tools/prepare-adreno-gui-deployment.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == '8c755abf451830fd1da920c17058ed4e5e83214dfd85c3d48e1a08b70a3cf305'
source = base.read_text()
changes = {
    "sources = {str(p.relative_to(ROOT)): sha(p) for p in\n        (Path(__file__), ROOT/'probes/trustcache.py', ROOT/'probes/guestprofile.py')}":
        "sources = {str(p): sha(p) for p in\n        (Path(__file__), base, RUNTIME/'probes/trustcache.py', RUNTIME/'probes/guestprofile.py', RUNTIME/'probes/xnuboot.py')}",
    "sys.path.insert(0, str(ROOT/'probes'))": "sys.path.insert(0, str(RUNTIME/'probes'))",
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__', RUNTIME=RUNTIME, base=base))
