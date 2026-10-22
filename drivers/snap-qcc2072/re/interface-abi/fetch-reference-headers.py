#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Fetch pinned architectural references; these are not the current target ABI."""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request
import sys
sys.dont_write_bytecode = True
from evidence_guard import write_new_bytes, write_new_text

COMMIT = '53c51c2cdd6e4b69beb91f310d74c53422b0f8bd'
BASE = f'https://raw.githubusercontent.com/OpenIntelWireless/itlwm/{COMMIT}/include/Airport/'
CLASSES = ('IOSkywalkInterface', 'IOSkywalkNetworkInterface', 'IOSkywalkEthernetInterface',
           'IO80211SkywalkInterface', 'IO80211InfraInterface', 'IO80211InfraProtocol')
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--out', type=Path, required=True)
args = parser.parse_args()
if args.out.exists() or args.out.is_symlink():
    raise SystemExit('Refusing to overwrite reference evidence; choose a NEW directory: '
                     + str(args.out))
args.out.mkdir(parents=True, exist_ok=False)
receipt = []
for name in CLASSES:
    url = BASE+name+'.h'
    data = urllib.request.urlopen(url).read()
    write_new_bytes(args.out/(name+'.h'), data)
    receipt.append({'url':url,'sha256':hashlib.sha256(data).hexdigest()})
write_new_text(args.out/'provenance.json', json.dumps(
    {'commit':COMMIT,'headers':receipt,'role':'HISTORICAL_RETURN_TYPE_REFERENCE_ONLY'},indent=2)+'\n')
print('Fetched',len(receipt),'pinned reference headers')
