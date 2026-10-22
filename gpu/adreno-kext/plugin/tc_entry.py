#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""tc_entry.py <signed Mach-O or bundle> - print the v2 trust-cache entry (24 bytes) for a signed binary.

Entry = CDHash truncated to 20 bytes + hash_type(2=SHA-256), flags(0), constraint category, reserved(0).
The category varies across the 1103 entries of basesystem-26A428.trustcache (0,1,2,3,4,5,10,11,12,19); 2 is what
Apple's own GPU plug-in bundle there (AppleParavirtGPUMetalIOGPUFamily.bundle) and dyld carry, so use 02 00 02 00. Note: injection/augment_trustcache.py packs '<HBB' flags=0x200 -> 00 02 02 00, which is
the known trailer bug; use these bytes instead when augmenting.
WindowServer is library-validated (CodeDirectory flags 0x2000, platform 26): an ad-hoc bundle is rejected with
"mapping process and mapped file (non-platform) have different Team IDs" unless its CDHash is trust-cached.
"""
import subprocess, sys, re
out = subprocess.run(['codesign', '-dvvv', sys.argv[1]], capture_output=True, text=True).stderr
m = re.search(r'CandidateCDHashFull sha256=([0-9a-f]{64})', out)
if not m: sys.exit('no sha256 CodeDirectory: ' + out)
cd = bytes.fromhex(m.group(1))[:20]
ent = cd + bytes([0x02, 0x00, 0x02, 0x00])
print('cdhash20 ', cd.hex())
print('entry24  ', ent.hex())
