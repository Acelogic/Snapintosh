#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the guest probe with the new composite candidate's exact identity.

Failure inventory: retaining the old plug-in hash, changing compiler inputs,
using historical draw pixels as proof of the new GPU code, or executing the
guest during the current boot. This builds and runs only the host reference;
the new candidate has not been installed or executed in the guest.
"""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / 'tools/build-ca-guest-probe.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == '1b0afa99d635fa89550334f6366899124dcd3ef9d3d5915fceca98506ace1f76'
source = base.read_text()
for old,new in {
    'build/qc-pipelines-vpc-20260928-v1.json': 'build/qc-pipelines-composite-20260928-v1.json',
    '0f7b2ad462e76103da3d52e2b20a534bd1e4d91d15e3a871081f352c8311455a':
        'e21bc5f0e164a5d230630ccb014ccdd32cb07c41b702ae35bffdba8eda917d58',
}.items():
    assert source.count(old) == 1,old
    source = source.replace(old,new)
exec(compile(source,str(base),'exec'),dict(__file__=__file__,__name__='__main__'))
