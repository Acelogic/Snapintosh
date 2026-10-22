#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""DART bootstrap identities: independent property consumer and atomic refusals."""
from dataclasses import replace
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
from appledt import DeviceTree, Property
from guestprofile import J700_26A428
from iommu import populate_dart_ids, populate_dart_apf_exceptions, validate_apf_memory

SPEC = J700_26A428.dart_boot
BUS = SPEC.bus
A, B = BUS+'/dart-a', BUS+'/dart-b'


def fixture():
    dt = DeviceTree.__new__(DeviceTree)
    dt.nodes = {BUS: {}}
    for path in (B, A):  # Deliberately reverse the input enumeration order.
        dt.nodes[path] = {key: Property(key, value) for key, value in {
            'device_type': b'dart\0', 'compatible': b'dart,t8110\0',
            'page-size': struct.pack('<I', 0x4000), 'sid-count': struct.pack('<I', 19),
        }.items()}
    return dt


def snapshot(dt):
    return tuple((path, tuple((key, bytes(p.value), p.placeholder)
                             for key, p in node.items())) for path, node in dt.nodes.items())


def windows(path):
    return ((0x300000000 if path == A else 0x300020000, 0x20000),)


class DARTTests(unittest.TestCase):
    def apf_fixture(self):
        dt = fixture()
        dt.put(BUS, 'ranges', struct.pack('<3Q', 0, 0x200000000, 0x400000000))
        record = struct.pack('<2Q', 0x300000000, 0x300003fff)+bytes(36)
        dt.put(A, 'dapf-instance-0', record)
        dt.put(B, 'dapf-instance-1', record+struct.pack('<2Q',0x400000000,0x400000010)+bytes(36))
        return dt, populate_dart_ids(dt, SPEC, windows)

    def test_apf_low_ram_exceptions_and_idempotence(self):
        dt, devices = self.apf_fixture()
        originals = {p: dt.get(p,k) for p,k in [(A,'dapf-instance-0'),(B,'dapf-instance-1')]}
        slices = populate_dart_apf_exceptions(dt,SPEC,devices,0xda000000,[(0xda000000,0x1b000000)])
        self.assertEqual(len(slices),3)
        self.assertEqual(dt.get(A,'allow-dram-apf-slices-0'),struct.pack('<I',0))
        self.assertEqual(dt.get(B,'allow-dram-apf-slices-1'),struct.pack('<2I',0,1))
        self.assertEqual(dt.get(A,'dapf-instance-0'),originals[A])
        self.assertEqual(dt.get(B,'dapf-instance-1'),originals[B])
        before=snapshot(dt)
        self.assertEqual(populate_dart_apf_exceptions(dt,SPEC,devices,0xda000000,[]),slices)
        self.assertEqual(before,snapshot(dt))
        # Actual host work area is known later. It must also be disjoint,
        # including padding in a partially occupied APF page.
        with self.assertRaisesRegex(ValueError,'owned memory'):
            validate_apf_memory(slices,[(0x400002000,0x1000)])
        validate_apf_memory(slices,[(0x400004000,0x1000)])

    def test_apf_high_ram_and_existing_indices(self):
        dt, devices = self.apf_fixture()
        populate_dart_apf_exceptions(dt,SPEC,devices,0x800000000,[(0x800000000,0x18000000)])
        self.assertIsNone(dt.get(A,'allow-dram-apf-slices-0'))
        self.assertIsNone(dt.get(B,'allow-dram-apf-slices-1'))
        dt.put(B,'allow-dram-apf-slices-1',struct.pack('<I',1))
        populate_dart_apf_exceptions(dt,SPEC,devices,0x380000000,[])
        self.assertEqual(dt.get(B,'allow-dram-apf-slices-1'),struct.pack('<I',1))

    def test_apf_bad_records_atomic_refusal(self):
        for value in [b'',bytes(51),bytes(65*52),
                      struct.pack('<2Q',0x300000100,0x300000000)+bytes(36),
                      struct.pack('<2Q',0x1000,0x2000)+bytes(36),
                      struct.pack('<2Q',(1<<36)-1,1<<36)+bytes(36)]:
            dt,devices=self.apf_fixture();dt.put(B,'dapf-instance-1',value);before=snapshot(dt)
            with self.assertRaises(ValueError):
                populate_dart_apf_exceptions(dt,SPEC,devices,0xda000000,[])
            self.assertEqual(before,snapshot(dt))
        dt,devices=self.apf_fixture();dt.nodes[B]['dapf-instance-1'].placeholder=True
        before=snapshot(dt)
        with self.assertRaises(ValueError):populate_dart_apf_exceptions(dt,SPEC,devices,0xda000000,[])
        self.assertEqual(before,snapshot(dt))

    def test_apf_ram_overlap_and_bad_exceptions_refused(self):
        for value in [b'',b'\0',struct.pack('<2I',0,0),struct.pack('<I',2)]:
            dt,devices=self.apf_fixture();dt.put(B,'allow-dram-apf-slices-1',value);before=snapshot(dt)
            with self.assertRaises(ValueError):
                populate_dart_apf_exceptions(dt,SPEC,devices,0xda000000,[])
            self.assertEqual(before,snapshot(dt))
        for exclusions in [[(0x300000000,0x4000)],[(0,0)],[(0,1<<37)]]:
            dt,devices=self.apf_fixture();before=snapshot(dt)
            with self.assertRaises(ValueError):
                populate_dart_apf_exceptions(dt,SPEC,devices,0xda000000,exclusions)
            self.assertEqual(before,snapshot(dt))
        dt,devices=self.apf_fixture()
        with self.assertRaises(ValueError):
            populate_dart_apf_exceptions(dt,replace(SPEC,apf_abi=None),devices,0xda000000,[])

    def test_apf_bus_and_instance_admission(self):
        for raw in [b'',bytes(23),struct.pack('<3Q',0,1 << 48,0x4000),
                    struct.pack('<3Q',0,0x200000000,0)]:
            dt,devices=self.apf_fixture();dt.put(BUS,'ranges',raw);before=snapshot(dt)
            with self.assertRaises(ValueError):
                populate_dart_apf_exceptions(dt,SPEC,devices,0xda000000,[])
            self.assertEqual(before,snapshot(dt))
        for suffix in ['01','32','-1','one']:
            dt,devices=self.apf_fixture()
            dt.put(B,'dapf-instance-'+suffix,dt.get(B,'dapf-instance-1'))
            before=snapshot(dt)
            with self.assertRaises(ValueError):
                populate_dart_apf_exceptions(dt,SPEC,devices,0xda000000,[])
            self.assertEqual(before,snapshot(dt))
        dt,devices=self.apf_fixture();dt.nodes[BUS]['ranges'].placeholder=True
        with self.assertRaises(ValueError):
            populate_dart_apf_exceptions(dt,SPEC,devices,0xda000000,[])

    def test_ids_are_stable_and_existing_handles_preserved(self):
        dt = fixture()
        dt.add(B, 'dart-id', struct.pack('<I', 0))
        devices = populate_dart_ids(dt, SPEC, windows)
        self.assertEqual([(d.path, d.device_id) for d in devices], [(A, 1), (B, 0)])
        before = snapshot(dt)
        self.assertEqual(populate_dart_ids(dt, SPEC, windows), devices)
        self.assertEqual(snapshot(dt), before)
        self.assertEqual(struct.unpack('<I', dt.get(A, 'dart-id')), (1,))
        self.assertEqual(devices[0].windows, ((0x300000000, 0x20000),))

    def test_validation_precedes_all_property_writes(self):
        cases = [('dart-id', b'\0'), ('dart-id', struct.pack('<I', 256)),
                 ('page-size', struct.pack('<I', 0x1000)), ('sid-count', bytes(4)),
                 ('compatible', b'dart,unknown\0'), ('compatible', b'dart,t8110'),
                 ('page-size', bytes(8))]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                dt = fixture();dt.put(B, key, value);before = snapshot(dt)
                with self.assertRaises(ValueError):
                    populate_dart_ids(dt, SPEC, windows)
                self.assertEqual(snapshot(dt), before)
                self.assertIsNone(dt.get(A, 'dart-id'))

    def test_duplicate_and_unresolved_ids_refused(self):
        for duplicate in (False, True):
            dt = fixture()
            dt.add(B, 'dart-id', bytes(4))
            if duplicate:
                dt.add(A, 'dart-id', bytes(4))
            else:
                dt.nodes[B]['dart-id'].placeholder = True
            before = snapshot(dt)
            with self.assertRaises(ValueError):
                populate_dart_ids(dt, SPEC, windows)
            self.assertEqual(snapshot(dt), before)

    def test_bad_windows_and_unknown_abi_refused(self):
        for spans in [(), ((1, 0x4000),), ((0x300000000, 0),),
                      ((0x300000000, 0x8000), (0x300004000, 0x4000)),
                      (((1 << 48)-0x4000, 0x8000),)]:
            dt = fixture();before = snapshot(dt)
            with self.assertRaises(ValueError):
                populate_dart_ids(dt, SPEC, lambda path: spans)
            self.assertEqual(snapshot(dt), before)
        dt = fixture()
        with self.assertRaises(ValueError):
            populate_dart_ids(dt, replace(SPEC, abi='unknown'), windows)

    def test_no_darts_and_exhausted_registry_refused(self):
        dt = fixture();dt.nodes = {BUS: {}}
        with self.assertRaises(ValueError):
            populate_dart_ids(dt, SPEC, windows)
        dt = fixture()
        template = dt.nodes.pop(A);dt.nodes.pop(B)
        for n in range(257):
            dt.nodes[BUS+f'/dart-{n:03}'] = dict(template)
        before = snapshot(dt)
        with self.assertRaises(ValueError):
            populate_dart_ids(dt, SPEC, windows)
        self.assertEqual(snapshot(dt), before)

    def test_serialized_j700_tree_satisfies_driver_id_contract(self):
        import xnuboot
        dt = xnuboot.build_devicetree()
        parsed = DeviceTree(dt.serialize())
        devices = dt.dart_devices
        self.assertEqual(len(devices), 23)
        handles = []
        for device in devices:
            prop = parsed.get(device.path, 'dart-id')
            self.assertEqual(len(prop), 4)
            value, = struct.unpack('<I', prop)
            self.assertLess(value, 256)
            self.assertEqual(value, device.device_id)
            handles.append(value)
        self.assertEqual(len(set(handles)), len(handles))
        self.assertEqual(parsed.get(BUS+'/dart-apcie0', 'dart-id'), b'\x02\0\0\0')
        raw = DeviceTree(Path(xnuboot.DEFAULT_DEVICETREE).read_bytes())
        self.assertTrue(all(raw.get(d.path, 'dart-id') is None for d in devices))
        self.assertEqual(len(dt.dart_apf_slices),57)
        base=struct.unpack('<Q',parsed.get('/device-tree/chosen','dram-base'))[0]
        for item in dt.dart_apf_slices:
            key=f'dapf-instance-{item.instance}'
            self.assertEqual(parsed.get(item.path,key),raw.get(item.path,key))
            prop=parsed.get(item.path,f'allow-dram-apf-slices-{item.instance}') or b''
            allowed=set(v[0] for v in struct.iter_unpack('<I',prop))
            # Independent model of the reached branch: high addresses need
            # an explicit slice exception; low device addresses do not.
            self.assertTrue((item.first < base and item.last < base) or item.index in allowed)
        self.assertEqual(parsed.get(BUS+'/dart-pmp','allow-dram-apf-slices-0'),
                         struct.pack('<27I',*range(27)))


if __name__ == '__main__':
    unittest.main()
