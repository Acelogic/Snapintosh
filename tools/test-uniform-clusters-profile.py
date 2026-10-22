#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The uniform-cluster profile changes only cpu4/cpu5 cluster-type (P -> E)."""
import contextlib
import io
import runpy
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import xnuboot as xb


def tree(name):
    xb.configure_guest(name);xb.place(0x8c0000000,guest_span=8192<<20)
    with contextlib.redirect_stdout(io.StringIO()):return xb.build_devicetree()


class UniformClusters(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base=tree('j700ap-26A428-bootfb-xars')
        cls.uniform=tree('j700ap-26A428-bootfb-xars-uniform')

    def test_secondary_admission_accepts_explicit_pinned_profile(self):
        validate=runpy.run_path(str(ROOT/'tools/secondary-runtime.py'))['validate_guest_profile']
        validate('j700ap-26A428-bootfb-xars-uniform')
        with self.assertRaises(ValueError):validate('j700ap-26A428-bootfb-xars-uniform-unknown')

    def test_only_cluster_one_type_changes(self):
        a,b=self.base,self.uniform
        self.assertEqual(a.device_models,b.device_models)
        self.assertEqual(a.deferred_nodes,b.deferred_nodes)
        self.assertEqual(set(a.nodes),set(b.nodes))
        changed=[]
        for path,props in a.nodes.items():
            other=b.nodes[path]
            self.assertEqual(set(props),set(other),path)
            for name,prop in props.items():
                if bytes(prop.value)!=bytes(other[name].value) or prop.placeholder!=other[name].placeholder:
                    changed.append((path,name,bytes(prop.value),bytes(other[name].value)))
        self.assertEqual(sorted(changed),[
            ('/device-tree/cpus/cpu4','cluster-type',b'P\0',b'E\0'),
            ('/device-tree/cpus/cpu5','cluster-type',b'P\0',b'E\0')])
        for cpu in range(6):
            node=b.nodes[f'/device-tree/cpus/cpu{cpu}']
            self.assertEqual(bytes(node['cluster-type'].value),b'E\0')
            self.assertEqual(bytes(node['cluster-id'].value),bytes([int(cpu>=4),0,0,0]))
        self.assertEqual(len(a.serialize()),len(b.serialize()))

    def test_relabel_refuses_unexpected_topology(self):
        for cpu,value in ((4,b'E\0'),(0,b'P\0'),(5,b'X\0')):
            dt=tree('j700ap-26A428-bootfb-xars')
            dt.set(f'/device-tree/cpus/cpu{cpu}','cluster-type',value)
            with self.assertRaises(ValueError):xb.uniform_cpu_clusters(dt)
        dt=tree('j700ap-26A428-bootfb-xars');del dt.nodes['/device-tree/cpus/cpu5']['cluster-type']
        with self.assertRaises(ValueError):xb.uniform_cpu_clusters(dt)


if __name__=='__main__':unittest.main()
