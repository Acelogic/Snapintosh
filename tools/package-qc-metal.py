#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Package the ownership-preserving compiler update and verified rollback."""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / 'tools/package-adreno-gui.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == '3a5d89fc74654406c723d20ae0d95a214e0a9646982751d08537d833ba914a9e'
source = base.read_text()
changes = {
    "assert not stage.get('ownership_preserved')": "assert stage.get('ownership_preserved')",
    'tools/stage-adreno-gui-image.py': 'tools/restage-qc-metal-image.py',
    'tools/normalize-adreno-gui-stage.py': 'tools/normalize-qc-metal-stage.py',
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))
