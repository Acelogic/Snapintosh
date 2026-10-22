#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preload admission, transactional refusal and profile separation checks."""
from dataclasses import replace
import copy
from pathlib import Path
import hashlib
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'probes'))
import seppreload as p
from appledt import Property
from guestprofile import J700_26A428, J700_26A428_NO_CLPC, J700_26A428_SEP_PRELOAD


class Tree:
    def __init__(self, node):
        self.nodes = {node: {'compatible': Property('compatible', b'iop-nub,sep\0')},
                      p.MEMORY_MAP: {}}

    def add(self, node, name, data):
        assert name not in self.nodes[node]
        self.nodes[node][name] = Property(name, data)

    def get(self,node,name):
        prop=self.nodes.get(node,{}).get(name)
        return prop.value if prop is not None else None


class PreloadTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.payload = bytes(range(256))*64
        self.spec = replace(J700_26A428_SEP_PRELOAD.sep_preload,
                            size=len(self.payload), sha256=hashlib.sha256(self.payload).hexdigest())
        self.path = Path(self.directory.name)/self.spec.filename
        self.path.write_bytes(self.payload)
        self.tree = Tree(self.spec.node)
        low = min(a for a, _ in p.WITNESSES)
        data = bytearray(max(a for a, _ in p.WITNESSES)-low+4)
        for a, w in p.WITNESSES:
            struct.pack_into('<I', data, a-low, w)
        self.image = SimpleNamespace(data=data, segments=[('__TEXT_EXEC',low,len(data),0,len(data))])

    def prepare(self, **kwargs):
        args = dict(tree=self.tree, image=self.image, spec=self.spec,
                    directory=self.directory.name, base=0x110000000, end=0x200000000)
        args.update(kwargs)
        return p.prepare(**args)

    def rejected(self, **kwargs):
        before = {n: {k: bytes(v.value) for k,v in props.items()}
                  for n,props in self.tree.nodes.items()}
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.prepare(**kwargs)
        self.assertEqual(before, {n: {k: bytes(v.value) for k,v in props.items()}
                                  for n,props in self.tree.nodes.items()})

    def test_unchanged_bytes_exact_extent(self):
        self.assertEqual(self.prepare(), self.payload)
        self.assertEqual(self.tree.nodes[p.MEMORY_MAP]['SEPFW'].value,
                         struct.pack('<QQ',0x110000000,len(self.payload)))
        self.assertEqual(self.tree.nodes[self.spec.node]['sepfw-loaded'].value,b'')
        self.assertNotIn('SEPPatches',self.tree.nodes[p.MEMORY_MAP])
        self.assertNotIn('uStuff',self.tree.nodes[p.MEMORY_MAP])

    def dma_built(self):
        self.prepare()
        pa=0x110000000
        return dict(sep_preload_range=(pa,len(self.payload)),dt=self.tree,
                    frame_low=0x100000000,frame_high=0x200000000,alloc_low=0x120000000,
                    ramdisk_range=(0x111000000,0x100000),chunks={pa:self.payload})

    def test_exact_dma_contract_and_disabled_profile(self):
        built=self.dma_built()
        self.assertEqual(p.dma_contract(built,self.spec,0x110000000),[0x110000000,len(self.payload)])
        self.assertEqual(p.dma_contract({},None,0x110000000),[0,0])
        with self.assertRaises(ValueError):p.dma_contract(built,None,0x110000000)

    def test_dma_contract_rejects_placement_and_payload_drift(self):
        original=self.dma_built()
        changes=[dict(sep_preload_range=None),dict(sep_preload_range=(0x110004000,len(self.payload))),
                 dict(sep_preload_range=(0x110000000,len(self.payload)*2)),dict(alloc_low=0x110000000),
                 dict(ramdisk_range=(0x110000000,0x100000)),dict(chunks={0x110000000:bytes(len(self.payload))})]
        for change in changes:
            built=dict(original,**change)
            with self.subTest(change=list(change)),self.assertRaises(ValueError):
                p.dma_contract(built,self.spec,0x110000000)
        for name in ('SEPFW','sepfw-loaded'):
            built=copy.deepcopy(original)
            node=p.MEMORY_MAP if name=='SEPFW' else self.spec.node
            built['dt'].nodes[node][name]=Property(name,b'wrong')
            with self.assertRaises(ValueError):p.dma_contract(built,self.spec,0x110000000)

    def test_placement_and_capacity_refused(self):
        for args in [dict(base=-0x4000),dict(base=1),dict(end=1<<37),
                     dict(end=0x110000000+self.spec.size+0x8000000-1)]:
            with self.subTest(args=args):self.rejected(**args)

    def test_size_refused(self):
        for size in [0,1,0x1004000]:
            self.rejected(spec=replace(self.spec,size=size))

    def test_native_witness_refused(self):
        self.image.data[0] ^= 1
        self.rejected()

    def test_payload_hash_length_and_missing_refused(self):
        for payload in [self.payload[:-1],self.payload+b'\0',bytes(len(self.payload))]:
            self.path.write_bytes(payload)
            self.rejected()
        self.path.unlink()
        self.rejected()

    def test_conflicting_descriptors_refused(self):
        for node,name in [(self.spec.node,'sepfw-loaded')]+[
                (p.MEMORY_MAP,n) for n in ('SEPFW','SEPPatches','uStuff')]:
            self.tree.nodes[node][name]=Property(name,b'')
            self.rejected()
            del self.tree.nodes[node][name]

    def test_wrong_provider_or_missing_memory_map_refused(self):
        self.tree.nodes[self.spec.node]['compatible']=Property('compatible',b'other\0')
        self.rejected()
        self.tree=Tree(self.spec.node)
        del self.tree.nodes[p.MEMORY_MAP]
        self.rejected()

    def test_bundle_escape_refused(self):
        self.rejected(spec=replace(self.spec,filename='../firmware'))

    def test_only_selected_profile_loads_sep(self):
        self.assertIsNone(J700_26A428.sep_preload)
        self.assertIsNone(J700_26A428_NO_CLPC.sep_preload)
        trial=J700_26A428_SEP_PRELOAD
        self.assertEqual(dict(trial.firmware)[trial.sep_preload.filename],trial.sep_preload.sha256)
        self.assertEqual(trial.critical_addresses,J700_26A428_NO_CLPC.critical_addresses)
        self.assertEqual(trial.root_hash,J700_26A428_NO_CLPC.root_hash)


if __name__=='__main__':
    unittest.main()
