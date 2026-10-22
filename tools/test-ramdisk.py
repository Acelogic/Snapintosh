#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
from dataclasses import replace
import hashlib
import struct
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
from ramdisk import load_ramdisk, root_cmdline, load_root_hash, populate_ramdisk_policy, RootHashSpec, ROOT_HASH_NODE


class RAMDiskTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=Path(self.temp.name)/'geometry-only.apfs'
        self.data=bytearray(0x4000)
        self.data[32:36]=b'NXSB'
        struct.pack_into('<IQ',self.data,36,4096,4)
        self.path.write_bytes(self.data)

    def tearDown(self):
        self.temp.cleanup()

    def test_mapping_is_read_only(self):
        with load_ramdisk(self.path,0x100000000,0x110000000) as payload:
            self.assertEqual(payload[:],self.data)
            with self.assertRaises(TypeError):payload[32]=0

    def test_refuse_wrappers_and_inconsistent_geometry(self):
        for offset,value in [(32,b'IM4P'),(36,struct.pack('<I',16384)),
                             (40,struct.pack('<Q',5))]:
            data=bytearray(self.data);data[offset:offset+len(value)]=value
            self.path.write_bytes(data)
            with self.assertRaises(ValueError):load_ramdisk(self.path,0x100000000,0x110000000)
        for data in [b'',self.data[:-1],self.data+b'\0'*0x4000]:
            self.path.write_bytes(data)
            with self.assertRaises(ValueError):load_ramdisk(self.path,0x100000000,0x110000000)

    def test_placement_and_root_conflicts(self):
        for base,end in [(-0x4000,0x10000000),(1,0x10000000),(0,0x8000000),
                         (0x1000000000,0x1000004000)]:
            with self.assertRaises(ValueError):load_ramdisk(self.path,base,end)
        for line in ['-v rd=disk0s1','rootdev=md1','rd=md0','boot-uuid=unexpected']:
            for mode in ('md0','iokit'):
                with self.assertRaises(ValueError):root_cmdline(line,mode)
        self.assertEqual(root_cmdline('-v'),'-v rd=md0')
        self.assertEqual(root_cmdline('-v','iokit'),'-v')
        with self.assertRaises(ValueError):root_cmdline('-v','unknown')

    def root_fixture(self):
        payload=struct.pack('<4I',2,0,1,32)+bytes(range(192))
        path=Path(self.temp.name)/'root-hash.bin'
        path.write_bytes(payload)
        spec=RootHashSpec(hashlib.sha256(self.data).hexdigest(),
                         hashlib.sha256(payload).hexdigest(),len(payload),
                         'test-component','0'*64,'system-volume-auth-blob',
                         'test-board','test-build')
        return path,payload,spec

    def test_root_hash_is_bound_to_both_payload_and_media(self):
        path,payload,spec=self.root_fixture()
        self.assertEqual(load_root_hash(path,self.data,spec),payload)
        with self.assertRaises(ValueError):load_root_hash(path,self.data,None)
        for raw in (payload[:-1],payload+b'\0',b'X'+payload[1:]):
            path.write_bytes(raw)
            with self.assertRaises(ValueError):load_root_hash(path,self.data,spec)
        path.write_bytes(payload)
        modified=bytearray(self.data);modified[-1]^=1
        with self.assertRaises(ValueError):load_root_hash(path,modified,spec)

    def test_root_hash_requires_media_and_reaches_firmware_unchanged(self):
        import xnuboot as xb
        from unittest.mock import patch
        path,auth,spec=self.root_fixture()
        with self.assertRaises(ValueError):
            xb.build(xb.DEFAULT_KERNELCACHE,root_hash=path)
        with patch.dict(xb.__dict__,xb.__dict__.copy()):
            xb.place(0xda000000,guest_span=384<<20)
            xb.GUEST_PROFILE=replace(xb.GUEST_PROFILE,root_hash=spec)
            built=xb.build(xb.DEFAULT_KERNELCACHE,ramdisk=self.path,root_hash=path)
            pa,size=built['ramdisk_range']
            try:
                dt=xb.DeviceTree(built['chunks'][xb.DEVICETREE_PA])
                self.assertEqual(dt.get(ROOT_HASH_NODE,spec.property_name),auth)
                self.assertEqual(built['chunks'][pa][:],self.data)
                self.assertLessEqual(pa+size,built['alloc_low'])
                args=built['chunks'][xb.HANDOFF_PA+0x1000]
                self.assertIn(b' rd=md0\0',args[0x6c:0x478])
            finally:built['chunks'][pa].close()

    def test_loader_reserves_and_publishes_the_same_bytes(self):
        import xnuboot as xb
        xb.place(0xda000000,guest_span=384<<20)
        built=xb.build(xb.DEFAULT_KERNELCACHE,ramdisk=self.path)
        pa,size=built['ramdisk_range']
        payload=built['chunks'][pa]
        try:
            self.assertEqual(payload[:],self.data)
            dt=xb.DeviceTree(built['chunks'][xb.DEVICETREE_PA])
            self.assertEqual(dt.get('/device-tree/chosen/memory-map','RAMDisk'),struct.pack('<QQ',pa,size))
            self.assertLessEqual(pa+size,built['alloc_low'])
            self.assertEqual(built['tables'].walk(xb.APERTURE_VA+pa-xb.PHYS_BASE),pa)
            args=built['chunks'][xb.HANDOFF_PA+0x1000]
            self.assertEqual(struct.unpack_from('<Q',args,32)[0],built['alloc_low'])
            self.assertIn(b' rd=md0\0',args[0x6c:0x478])
        finally:payload.close()

    def test_iokit_requires_bound_root_inputs(self):
        import xnuboot as xb
        from unittest.mock import patch
        path,auth,spec=self.root_fixture()
        with self.assertRaises(ValueError):
            xb.build(xb.DEFAULT_KERNELCACHE,ramdisk_mode='iokit')
        with self.assertRaises(ValueError):
            xb.build(xb.DEFAULT_KERNELCACHE,ramdisk=self.path,ramdisk_mode='iokit')
        with patch.object(xb,'GUEST_PROFILE',replace(xb.GUEST_PROFILE,root_hash=spec)):
            with self.assertRaises(ValueError):
                xb.build(xb.DEFAULT_KERNELCACHE,ramdisk=self.path,root_hash=path,ramdisk_mode='iokit')
        with self.assertRaises(ValueError):
            xb.build(xb.DEFAULT_KERNELCACHE,ramdisk=self.path,isc_image=self.path)

    def test_iokit_gpt_keeps_root_auth_and_preload_separate(self):
        import xnuboot as xb
        import bootmedia
        from unittest.mock import patch
        path,auth,spec=self.root_fixture()
        spec=replace(spec,boot_uuid='A9037730-2821-4F3A-90DC-91BA521BB080',
                     no_protected_data_recipe=xb.GUEST_PROFILE.root_hash.no_protected_data_recipe)
        with patch.dict(xb.__dict__,xb.__dict__.copy()):
            xb.place(0xda000000,guest_span=384<<20)
            xb.GUEST_PROFILE=replace(xb.GUEST_PROFILE,root_hash=spec)
            built=xb.build(xb.DEFAULT_KERNELCACHE,ramdisk=self.path,root_hash=path,
                           ramdisk_mode='iokit',isc_image=self.path)
            pa,size=built['ramdisk_range']
            root_pa,root_size=built['ramdisk_root_range']
            isc_pa,isc_size=built['ramdisk_isc_range']
            try:
                dt=xb.DeviceTree(built['chunks'][xb.DEVICETREE_PA])
                self.assertEqual(dt.get(ROOT_HASH_NODE,spec.property_name),auth)
                self.assertEqual(dt.get('/device-tree/chosen','protected-data-access'),bytes(4))
                self.assertEqual(dt.get('/device-tree/chosen','boot-ramdmg-extents'),struct.pack('<QQ',pa,size))
                self.assertEqual(dt.get('/device-tree/chosen','boot-ramdmg-size'),struct.pack('<Q',size))
                self.assertEqual(built['chunks'][root_pa][:],self.data)
                self.assertEqual(built['chunks'][isc_pa][:],self.data)
                self.assertNotEqual(pa,root_pa)
                self.assertEqual(root_size,len(self.data))
                self.assertGreater(size,root_size+isc_size)
                self.assertLessEqual(pa+size,built['alloc_low'])
                image=bytearray(size)
                for start,blob in built['chunks'].items():
                    if pa<=start<pa+size:image[start-pa:start-pa+len(blob)]=blob
                layout=bootmedia.inspect(lambda off,n:image[off:off+n],size)
                self.assertEqual(layout['root'],(root_pa-pa,root_size))
                self.assertEqual(layout['isc'],(isc_pa-pa,isc_size))
            finally:
                built['chunks'][root_pa].close()
                built['chunks'][isc_pa].close()

    def test_ramdisk_policy_rejects_changed_firmware_recipe(self):
        import xnuboot as xb
        spec=xb.GUEST_PROFILE.root_hash
        tree=xb.build_devicetree()
        self.assertEqual(tree.get('/device-tree/chosen','protected-data-access'),struct.pack('<I',1))
        self.assertEqual(tree.get('/device-tree/chosen','sepfw-load-at-boot'),struct.pack('<I',1))
        before=tree.serialize()
        populate_ramdisk_policy(tree,replace(spec,no_protected_data_recipe=None,no_sep_firmware_recipe=None))
        self.assertEqual(tree.serialize(),before)
        for recipe in (spec.no_protected_data_recipe,spec.no_sep_firmware_recipe):
            for key,value in [('value',b'\0'),('value',struct.pack('<I',1)),
                              ('node_path',b'arm-io\0'),('property_name',b'other\0')]:
                tree=xb.build_devicetree()
                tree.put(recipe,key,value)
                before=tree.serialize()
                with self.subTest(recipe=recipe,key=key,value=value), self.assertRaises(ValueError):
                    populate_ramdisk_policy(tree,spec)
                self.assertEqual(tree.serialize(),before)
        tree=xb.build_devicetree()
        populate_ramdisk_policy(tree,spec)
        self.assertEqual(tree.get('/device-tree/chosen','protected-data-access'),bytes(4))
        self.assertEqual(tree.get('/device-tree/chosen','sepfw-load-at-boot'),bytes(4))

    def test_iokit_uses_physical_extents_and_uuid_without_md0(self):
        import xnuboot as xb
        from unittest.mock import patch
        path,auth,spec=self.root_fixture()
        spec=replace(spec,boot_uuid='A9037730-2821-4F3A-90DC-91BA521BB080')
        with patch.dict(xb.__dict__,xb.__dict__.copy()):
            xb.place(0xda000000,guest_span=384<<20)
            xb.GUEST_PROFILE=replace(xb.GUEST_PROFILE,root_hash=spec)
            built=xb.build(xb.DEFAULT_KERNELCACHE,ramdisk=self.path,root_hash=path,ramdisk_mode='iokit')
            pa,size=built['ramdisk_range']
            try:
                dt=xb.DeviceTree(built['chunks'][xb.DEVICETREE_PA])
                self.assertEqual(built['chunks'][pa][:],self.data)
                self.assertLessEqual(pa+size,built['alloc_low'])
                self.assertIsNone(dt.get('/device-tree/chosen/memory-map','RAMDisk'))
                self.assertEqual(dt.get('/device-tree/chosen','boot-ramdmg-extents'),struct.pack('<QQ',pa,size))
                self.assertEqual(dt.get('/device-tree/chosen','boot-ramdmg-size'),struct.pack('<Q',size))
                self.assertEqual(dt.get('/device-tree/chosen','boot-uuid'),spec.boot_uuid.encode()+b'\0')
                self.assertEqual(dt.get('/device-tree/chosen','apfs-preboot-uuid'),spec.boot_uuid.encode()+b'\0')
                self.assertEqual(dt.get(ROOT_HASH_NODE,spec.property_name),auth)
                args=built['chunks'][xb.HANDOFF_PA+0x1000]
                self.assertNotIn(b'rd=',args[0x6c:0x478])
                self.assertNotIn(b'rootdev=',args[0x6c:0x478])
                self.assertEqual(built['tables'].walk(xb.APERTURE_VA+pa-xb.PHYS_BASE),pa)
            finally:built['chunks'][pa].close()


if __name__=='__main__':unittest.main()
