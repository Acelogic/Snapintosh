#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay the GUI payload and rollback across the entire fresh APFS baseline."""
from pathlib import Path
import hashlib

base = Path(__file__).resolve().parents[2] / 'Snapintosh-adreno-resource-map/tools/replay-adreno-clear-delta.py'
base_sha = 'c75ace82ea5a20ca36557052bbf48c1f0f3f0b0e0be9a937835421b7a1976af0'
assert hashlib.sha256(base.read_bytes()).hexdigest() == base_sha
source = base.read_text()
changes = {
    "    changes = {":
        "    changes = {\n        \"m['payload_bytes'] <= 64 << 20\": \"m['payload_bytes'] <= p['max_delta_bytes'] == 128 << 20\",",
    'tools/package-adreno-clear.py': 'tools/package-adreno-gui.py',
    "    assert package['result'] == 'PACKAGED_LOCAL_ONLY' and not package['ssd_writes']":
        "    assert package['result'] == 'PACKAGED_LOCAL_ONLY' and not package['ssd_writes']\n    assert 0 < package['payload_bytes'] <= package['max_delta_bytes'] == 128 << 20",
    "base_source_sha256={base_sha!r})":
        f"base_source_sha256={{base_sha!r}}, adapter_base_sha256=\"{base_sha}\")",
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))
