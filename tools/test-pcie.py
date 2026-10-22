#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from dataclasses import replace
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
from appledt import DeviceTree, Property
from guestprofile import J700_26A428
from pcie import populate_pcie_reset

SPEC, = J700_26A428.pcie_reset_boot


def fixture():
    dt=DeviceTree.__new__(DeviceTree)
    dt.nodes={SPEC.bridge:{},SPEC.gpio:{}}
    for path,items in [(SPEC.bridge,{'compatible':b'apcie-bridge\0',
                                   'function-perst':struct.pack('<I',0x4c),
                                   'function-perst-tupai':struct.pack('<3I',0x4750494f,112,0)}),
                       (SPEC.gpio,{'compatible':b'gpio,t8101\0',
                                   '#gpio-pins':struct.pack('<I',216),
                                   'AAPL,phandle':struct.pack('<I',0x4c)})]:
        dt.nodes[path]={k:Property(k,v) for k,v in items.items()}
    return dt


class PCIETests(unittest.TestCase):
    def test_complete_and_idempotent(self):
        dt=fixture();populate_pcie_reset(dt,(SPEC,))
        complete=struct.pack('<4I',0x4c,0x4750494f,112,0)
        self.assertEqual(dt.get(SPEC.bridge,'function-perst'),complete)
        populate_pcie_reset(dt,(SPEC,))
        self.assertEqual(dt.get(SPEC.bridge,'function-perst'),complete)

    def test_malformed_prefix_variant_and_provider_refused(self):
        for path,key,value in [(SPEC.bridge,'function-perst',b''),
                               (SPEC.bridge,'function-perst',struct.pack('<I',0x4d)),
                               (SPEC.bridge,'function-perst',struct.pack('<4I',0x4c,0x4750494f,114,0)),
                               (SPEC.bridge,'function-perst-tupai',struct.pack('<3I',0x4750494f,113,0)),
                               (SPEC.gpio,'#gpio-pins',struct.pack('<I',112)),
                               (SPEC.gpio,'AAPL,phandle',bytes(4))]:
            dt=fixture();dt.put(path,key,value);before=dt.get(SPEC.bridge,'function-perst')
            with self.assertRaises(ValueError):populate_pcie_reset(dt,(SPEC,))
            self.assertEqual(dt.get(SPEC.bridge,'function-perst'),before)

    def test_all_bindings_validate_before_writes(self):
        dt=fixture();before=dt.get(SPEC.bridge,'function-perst')
        with self.assertRaises(ValueError):populate_pcie_reset(dt,(SPEC,SPEC))
        self.assertEqual(dt.get(SPEC.bridge,'function-perst'),before)
        dt.nodes[SPEC.bridge]['function-perst-tupai'].placeholder=True
        with self.assertRaises(ValueError):populate_pcie_reset(dt,(SPEC,))
        self.assertEqual(dt.get(SPEC.bridge,'function-perst'),before)
        with self.assertRaises(ValueError):populate_pcie_reset(fixture(),(replace(SPEC,variant='unknown'),))

    def test_serialized_guest_and_source_preservation(self):
        import xnuboot as xb
        # Validate the backend contract even when the virtual board defers Wi-Fi.
        dt=DeviceTree(xb.build_devicetree(include_deferred=True).serialize())
        raw=DeviceTree(Path(xb.DEFAULT_DEVICETREE).read_bytes())
        self.assertEqual(len(raw.get(SPEC.bridge,'function-perst')),4)
        self.assertEqual(dt.get(SPEC.bridge,'function-perst'),
                         raw.get(SPEC.bridge,'function-perst')+raw.get(SPEC.bridge,'function-perst-tupai'))
        self.assertEqual(dt.get(SPEC.bridge,'function-perst-tahiti'),raw.get(SPEC.bridge,'function-perst-tahiti'))


if __name__=='__main__':unittest.main()
