#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the guest probe with the shader-cache candidate's exact plug-in identity.

Same as build-composite-guest-probe.py, bound to this candidate's native pipeline
evidence (build/qc-pipelines-shader-cache-20260928-v2.json). Failure inventory:
retaining an old plug-in hash, changing compiler inputs, or reading historical draw
pixels as proof of the new GPU code. Host reference only; nothing runs on the A16.
Doc: docs/SHADER-COMPILE-PATH-20260928.md.
"""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / 'tools/build-ca-guest-probe.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == '1b0afa99d635fa89550334f6366899124dcd3ef9d3d5915fceca98506ace1f76'
source = base.read_text()
for old, new in {
    'build/qc-pipelines-vpc-20260928-v1.json': 'build/qc-pipelines-shader-cache-20260928-v2.json',
    '0f7b2ad462e76103da3d52e2b20a534bd1e4d91d15e3a871081f352c8311455a':
        '81e295ad72fd0b6a9d776ce42d12b63c1ae37fa7d0a0ad26a04e82bf3d8369f4',
}.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))
