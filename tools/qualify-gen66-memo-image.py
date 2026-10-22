#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Rebuild generation63's -sks full guest image from the generation66 runtime root.

Generation63's image (composite image-v1, 27db00f9) was built by
../Snapintosh-adreno-composite/tools/qualify-qc-metal-image.py: the unchanged
base qualifier tools/qualify-adreno-gui-image.py (2d37fce3) run against the
Snapintosh-adreno-sks probes. This runs the same base qualifier, pinned, against
../Snapintosh-gen66 (23c583f + SWITCH_ROOT memo), whose Python probes are
unchanged, with the same stage and the -sks profile. The launcher compares the
result with 27db00f9: the same device tree 7f011352, params, build log, trust
cache and every chunk except the random-seeded handoff page.

    python3 tools/qualify-gen66-memo-image.py --deployment STAGE/deployment.json \\
        --root-hash ROOT_HASH --output ../Snapintosh-gen66/build/NEW_DIR

Host-only: the synthetic Adreno record replaces adoption; no A16 access.
"""
from pathlib import Path
import hashlib

RUNTIME = Path(__file__).resolve().parents[2] / 'Snapintosh-gen66'
BASE = RUNTIME / 'tools/qualify-adreno-gui-image.py'
assert hashlib.sha256(BASE.read_bytes()).hexdigest() == '2d37fce355f650f1b360b9e7faf751e835989cc973f6c08b9b823f000c6e379e'
source = BASE.read_text()
changes = {
    'ROOT = Path(__file__).resolve().parents[1]': 'ROOT = RUNTIME',
    "    for p in (Path(__file__), helper_path): sources[str(p.relative_to(ROOT))] = sha(p)":
        "    for p in (Path(__file__), helper_path, BASE):\n"
        "        sources[str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else str(p)] = sha(p)",
    "    assert profile == 'j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display'":
        "    assert profile == 'j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display-sks'",
}
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
exec(compile(source, str(BASE), 'exec'),
     dict(__file__=str(Path(__file__).resolve()), __name__='__main__', RUNTIME=RUNTIME, BASE=BASE))
