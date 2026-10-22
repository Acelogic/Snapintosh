# SPDX-License-Identifier: MIT
"""Bind the user tree memo counters to audited refresh/sync transactions."""
from pathlib import Path
import runpy
import struct
import unittest
module=runpy.run_path(str(Path(__file__).with_name('capture-service-profile.py')))
decode=module['decode_user_tree_memo'];FIELDS=module['TREE_MEMO_FIELDS']
VALID=dict(calls=6400,samples=100,checked=900,mismatches=0,scan_hits=40000,scan_misses=2000,
           copy_hits=70000,copy_misses=5000,notes=123456,allocations=789,errors=0,
           walk_hits=3000,walk_misses=40,forced=25)
def pack(**change):
    row=dict(VALID,**change)
    return struct.pack(f'<{len(FIELDS)}Q',*(row[f] for f in FIELDS))
def run(raw,refresh=2400,sync=4000,sources=60000,destinations=75000):
    return decode(raw,refresh,sync,sources,destinations)
class UserTreeMemoCapture(unittest.TestCase):
    def test_valid(self):
        row=run(pack())
        self.assertAlmostEqual(row['scan_hit_fraction'],40000/42000)
        self.assertAlmostEqual(row['copy_hit_fraction'],70000/75000)
        self.assertAlmostEqual(row['walk_hit_fraction'],3000/3040)
        self.assertIsNone(run(pack(walk_hits=0,walk_misses=0))['walk_hit_fraction'])
    def test_size(self):
        for n in (0,8*len(FIELDS)-1,8*len(FIELDS)+8):
            with self.assertRaises(ValueError):run(bytes(n))
    def test_binding(self):
        for kwargs in (dict(refresh=2401),dict(sync=3999),dict(refresh=0,sync=6400),
                       dict(sources=41999),dict(destinations=74999),dict(destinations=75001)):
            with self.assertRaises(ValueError):run(pack(),**kwargs)
    def test_self_check(self):
        for change in (dict(mismatches=1),dict(errors=1),dict(samples=99),dict(samples=101),
                       dict(checked=0),dict(forced=6301)):
            with self.assertRaises(ValueError):run(pack(**change))
        # Fewer than 64 transactions cannot have sampled a single claim.
        with self.assertRaises(ValueError):run(pack(calls=63,samples=0),refresh=23,sync=40)
    def test_exercised(self):
        for change in (dict(scan_hits=0,scan_misses=42000),dict(copy_hits=0,copy_misses=75000),
                       dict(notes=0),dict(allocations=0),dict(scan_hits=0,scan_misses=0)):
            with self.assertRaises(ValueError):run(pack(**change))
if __name__=='__main__':unittest.main()
