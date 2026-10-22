#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""SEP ROM capture publication: consumer geometry and atomic refusal."""
from dataclasses import replace
from pathlib import Path
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
from appledt import DeviceTree,Property
from guestprofile import J700_26A428
from sepboot import populate_sep_boot

SPEC=J700_26A428.sep_boot


def fixture():
    dt=DeviceTree.__new__(DeviceTree)
    dt.nodes={node:{'compatible':Property('compatible',value+b'\0')}
              for node,value in [(SPEC.node,SPEC.compatible),(SPEC.nub,SPEC.nub_compatible)]}
    return dt


def snapshot(dt):
    return {node:{k:(bytes(v.value),v.placeholder) for k,v in props.items()}
            for node,props in dt.nodes.items()}


class SEPBootTests(unittest.TestCase):
    def test_capacity_matches_consumer_allocation(self):
        dt=fixture();before=snapshot(dt)
        self.assertEqual(populate_sep_boot(dt,SPEC),424)
        raw=dt.get(SPEC.nub,'rom-panic-bytes')
        self.assertEqual(len(raw),4)
        size,=struct.unpack('<I',raw)
        self.assertEqual(size%8,0)
        self.assertEqual(len(bytearray((size>>3)*8)),424)
        self.assertNotEqual(size,0x8000) # CINP is a separate SEPOS buffer.
        after=snapshot(dt);populate_sep_boot(dt,SPEC)
        self.assertEqual(snapshot(dt),after)
        del after[SPEC.nub]['rom-panic-bytes']
        self.assertEqual(before,after)

    def test_bad_capacity_rejected_without_mutation(self):
        for size in [False,0,-8,1,7,425,0x4008,0x100000000,424.0]:
            dt=fixture();before=snapshot(dt)
            with self.assertRaises(ValueError):populate_sep_boot(dt,replace(SPEC,rom_panic_bytes=size))
            self.assertEqual(before,snapshot(dt))

    def test_bindings_and_existing_values_are_not_overwritten(self):
        for value in [b'',b'\xa8\x01',bytes(8),struct.pack('<I',0x8000),struct.pack('<I',0)]:
            dt=fixture();dt.put(SPEC.nub,'rom-panic-bytes',value);before=snapshot(dt)
            with self.assertRaises(ValueError):populate_sep_boot(dt,SPEC)
            self.assertEqual(before,snapshot(dt))
        for node in (SPEC.node,SPEC.nub):
            dt=fixture();dt.nodes[node]['compatible'].placeholder=True;before=snapshot(dt)
            with self.assertRaises(ValueError):populate_sep_boot(dt,SPEC)
            self.assertEqual(before,snapshot(dt))
        dt=fixture();dt.put(SPEC.nub,'rom-panic-bytes',struct.pack('<I',424))
        dt.nodes[SPEC.nub]['rom-panic-bytes'].placeholder=True
        with self.assertRaises(ValueError):populate_sep_boot(dt,SPEC)
        dt=fixture();dt.put(SPEC.nub,'compatible',b'iop-nub,other\0')
        with self.assertRaises(ValueError):populate_sep_boot(dt,SPEC)

    def test_real_profile_serializes_property_on_provider(self):
        import xnuboot as xb
        dt=xb.build_devicetree();serialized=DeviceTree(dt.serialize())
        self.assertEqual(serialized.get(SPEC.nub,'rom-panic-bytes'),struct.pack('<I',424))
        self.assertIsNone(serialized.get(SPEC.node,'rom-panic-bytes'))
        self.assertEqual(len(dt.device_models),120)


if __name__=='__main__':unittest.main()
