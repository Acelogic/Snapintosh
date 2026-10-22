#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay all forward and rollback bytes for the new native compiler package."""
from pathlib import Path
import hashlib

base = Path(__file__).resolve().parents[1] / 'tools/replay-adreno-gui-delta.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == '9f38965f12cc48cb211d1dffbefd32c625a9f99af487e5fad263cdbf54269132'
source = base.read_text()
assert source.count('tools/package-adreno-gui.py') == 1
source = source.replace('tools/package-adreno-gui.py', 'tools/package-qc-metal.py')
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))
