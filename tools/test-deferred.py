#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Absent Apple GPU/HPM/radio nubs must retain backed display and I/O providers."""
from copy import deepcopy
from dataclasses import fields, replace
import hashlib
from pathlib import Path
import plistlib
import runpy
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
from appledt import DeviceTree
from deferred import DeferredFunction, DeferredSubtree, defer_subtrees
import xnuboot as xb


def add(dt, path, **props):
    dt.nodes[path] = {}
    dt.children[path] = []
    parent, name = path.rsplit('/', 1)
    if parent in dt.children:
        dt.children[parent].append(path)
    dt.put(path, 'name', name.encode() + b'\0')
    for key, value in props.items():
        dt.put(path, key, value)


def fixture():
    dt = DeviceTree.__new__(DeviceTree)
    dt.nodes, dt.children = {}, {}
    add(dt, '/device-tree')
    add(dt, '/device-tree/radio', **{'AAPL,phandle': struct.pack('<I', 34)})
    add(dt, '/device-tree/radio/child')
    add(dt, '/device-tree/retained', **{'AAPL,phandle': struct.pack('<I', 76)})
    return dt, (DeferredSubtree('/device-tree/radio',
                hashlib.sha256(dt.serialize('/device-tree/radio')).hexdigest()),)


def snapshot(dt):
    return ({n: {k: (p.name, bytes(p.value), p.placeholder) for k, p in props.items()}
             for n, props in dt.nodes.items()}, deepcopy(dt.children))


class DeferredTests(unittest.TestCase):
    def refused(self, dt, specs, functions=()):
        before = snapshot(dt)
        with self.assertRaises(ValueError):
            defer_subtrees(dt, specs, functions)
        self.assertEqual(snapshot(dt), before)

    def test_no_clpc_policy_only_withdraws_declared_software_board_providers(self):
        from guestprofile import J700_26A428, J700_26A428_NO_CLPC, PROFILES
        policy = J700_26A428_NO_CLPC
        changed = {f.name for f in fields(policy)
                   if getattr(policy, f.name) != getattr(J700_26A428, f.name)}
        self.assertEqual(changed, {'name', 'deferred_subtrees', 'deferred_functions',
                                   'acm_software_mode', 'sep_asc'})
        self.assertTrue(policy.acm_software_mode)
        self.assertEqual(policy.sep_asc, replace(J700_26A428.sep_asc, reply_transport=True))
        # Compare publication with identical pre-existing ACM/SEP policy.
        # Those independent board options must not masquerade as deferral edits.
        baseline = replace(policy, name='test-no-clpc-publication-baseline',
                           deferred_subtrees=J700_26A428.deferred_subtrees,
                           deferred_functions=J700_26A428.deferred_functions)
        PROFILES[baseline.name] = baseline
        saved = xb.GUEST_PROFILE.name
        try:
            xb.configure_guest(baseline.name)
            original = xb.build_devicetree()
            xb.configure_guest(policy.name)
            dt = xb.build_devicetree()
            absent = {'/device-tree/arm-io/pmgr/clpc', '/device-tree/arm-io/avd',
                      '/device-tree/arm-io/scaler0', '/device-tree/arm-io/apr'}
            self.assertEqual(set(original.nodes) - set(dt.nodes), absent)
            self.assertEqual(len(dt.nodes), 391)
            before, after = snapshot(original), snapshot(dt)
            for node in dt.nodes:
                self.assertEqual(after[0][node], before[0][node], node)
                self.assertEqual(after[1][node],
                                 [n for n in before[1][node] if n not in absent], node)
            self.assertEqual(dt.device_models, original.device_models)
            for retained in ('dart-scaler', 'dart-apr', 'disp0', 'dcp', 'dispext0', 'dcpext'):
                self.assertIn('/device-tree/arm-io/'+retained, dt.nodes)
            self.assertEqual(snapshot(DeviceTree(dt.serialize())), after)
            self.assertTrue(absent <= xb.build_devicetree(include_deferred=True).nodes.keys())
            # An added dependency must refuse; it cannot silently lose a provider.
            full = xb.build_devicetree(include_deferred=True)
            full.put('/device-tree/arm-io/pmgr', 'function-test-clpc',
                     struct.pack('<2I', 0x6b, 1))
            self.refused(full, policy.deferred_subtrees)
        finally:
            del PROFILES[baseline.name]
            xb.configure_guest(saved)

    def test_secondary_admission_binds_both_exact_profiles(self):
        import guestprofile as gp
        validate = runpy.run_path(str(ROOT / 'tools/secondary-runtime.py'))['validate_guest_profile']
        for policy in (gp.J700_26A428, gp.J700_26A428_NO_CLPC):
            validate(policy.name)
        with self.assertRaises(ValueError):
            validate('unqualified-profile')
        original = gp.PROFILES[gp.J700_26A428_NO_CLPC.name]
        try:
            gp.PROFILES[original.name] = replace(original, boot_mpidr=0x123)
            with self.assertRaises(ValueError):
                validate(original.name)
        finally:
            gp.PROFILES[original.name] = original

    def test_no_clpc_policy_with_real_high_memory_placement(self):
        from unittest.mock import patch
        with patch.dict(xb.__dict__, xb.__dict__.copy()):
            xb.configure_guest('j700ap-26A428-no-clpc')
            xb.place(0x8c0000000, 29696 << 20, guest_span=8192 << 20)
            full = xb.build_devicetree(include_deferred=True)
            dt = xb.build_devicetree()
            self.assertEqual(len(dt.nodes), 391)
            self.assertEqual(dt.device_models, full.device_models)
            for node in dt.nodes:
                for name in full.nodes[node]:
                    self.assertEqual(dt.get(node, name), full.get(node, name))

    def test_default_board_only_withdraws_exact_absent_hardware_closure(self):
        full = xb.build_devicetree(include_deferred=True)
        dt = xb.build_devicetree()
        removed = set(dt.deferred_nodes)
        self.assertEqual(len(full.nodes), 412)
        self.assertEqual(len(dt.nodes), 395)
        self.assertEqual(removed, set(full.nodes) - set(dt.nodes))
        expected = {
            '/device-tree/arm-io/ane',
            '/device-tree/arm-io/isp',
            '/device-tree/arm-io/sgx',
            '/device-tree/arm-io/nub-spmi-a0/hpm0',
            '/device-tree/arm-io/nub-spmi-a0/hpm1',
            '/device-tree/amfm-sunrise', '/device-tree/arm-io/wlan',
            '/device-tree/arm-io/bluetooth', '/device-tree/arm-io/apcie',
            '/device-tree/arm-io/apcie/pci-bridge0',
            '/device-tree/arm-io/apcie/pci-bridge0/wlan',
            '/device-tree/arm-io/apcie/pci-bridge0/bluetooth-pcie',
            '/device-tree/arm-io/apcie0-piodma', '/device-tree/arm-io/uart4',
            '/device-tree/arm-io/uart4/wlan-debug', '/device-tree/arm-io/uart5',
            '/device-tree/arm-io/uart5/bluetooth-debug',
        }
        self.assertEqual(removed, expected)
        before, _ = snapshot(full)
        after, _ = snapshot(dt)
        self.assertEqual(len(xb.GUEST_PROFILE.deferred_functions), 1)
        for spec in xb.GUEST_PROFILE.deferred_functions:
            self.assertEqual(bytes(full.get(spec.node, spec.name)), spec.value)
            del before[spec.node][spec.name]
        for node in after:
            self.assertEqual(after[node], before[node], node)
            self.assertEqual(dt.children[node],
                             [n for n in full.children[node] if n not in removed], node)
        self.assertEqual(len(dt.device_models), 120)
        self.assertEqual(dt.device_models, full.device_models)
        roundtrip = DeviceTree(dt.serialize())
        self.assertEqual(snapshot(roundtrip), snapshot(dt))
        self.assertIn('/device-tree/arm-io/dart-apcie0', dt.nodes)
        self.assertIn('/device-tree/arm-io/nub-spmi-a0', dt.nodes)
        self.assertIn('/device-tree/arm-io/dart-ane', dt.nodes)
        self.assertIn('/device-tree/arm-io/pmgr/clpc', dt.nodes)
        self.assertIn('/device-tree/arm-io/dart-isp', dt.nodes)
        self.assertNotIn('/device-tree/arm-io/isp', dt.nodes)
        for node in ('disp0', 'dcp', 'dispext0', 'dcpext'):
            self.assertIn('/device-tree/arm-io/'+node, dt.nodes)
        self.assertEqual(dt.monitor_uat_geometry, (1, 43, 64))
        self.assertEqual(dt.monitor_uat_geometry, xb.private_uat_geometry(full))
        # Only the validated constructor can preserve unpublished geometry.
        # A raw missing SGX node must still be rejected by the geometry reader.
        with self.assertRaises(ValueError):
            xb.private_uat_geometry(dt)
        self.assertEqual(full.deferred_nodes, ())

    def test_identity_and_overlap_refuse_atomically(self):
        dt, specs = fixture()
        for candidates in (specs * 2,
                           (replace(specs[0], node='/device-tree'),),
                           (replace(specs[0], node='/missing'),),
                           (replace(specs[0], sha256='0' * 64),),
                           (replace(specs[0], sha256='bad'),),
                           specs + (replace(specs[0], node=specs[0].node+'/child'),)):
            self.refused(dt, candidates)

    def test_new_children_properties_and_unresolved_metadata_refuse(self):
        for mode in ('new-child', 'changed', 'added', 'placeholder'):
            dt, specs = fixture()
            node = specs[0].node
            if mode == 'new-child':
                add(dt, node+'/new')
            elif mode == 'changed':
                dt.put(node, 'AAPL,phandle', struct.pack('<I', 35))
            elif mode == 'added':
                dt.put(node, 'unknown', b'')
            else:
                dt.nodes[node]['name'].placeholder = True
            self.refused(dt, specs)

    def test_broken_child_graph_refuses_before_serialization(self):
        for mode in ('duplicate-root', 'missing-root', 'duplicate-child',
                     'orphan', 'foreign-child', 'missing-children'):
            dt, specs = fixture()
            root = specs[0].node
            if mode == 'duplicate-root': dt.children['/device-tree'].append(root)
            elif mode == 'missing-root': dt.children['/device-tree'].remove(root)
            elif mode == 'duplicate-child': dt.children[root] *= 2
            elif mode == 'orphan': dt.children[root] = []
            elif mode == 'foreign-child': dt.children[root].append('/device-tree/retained')
            else: del dt.children[root+'/child']
            self.refused(dt, specs)

    def test_provider_references_and_aliases_refuse(self):
        for key in ('function-start', 'interrupt-parent', 'other-phandle',
                    'msi-parent-controller', 'amfm-managed-port-control', 'AAPL,phandle'):
            dt, specs = fixture()
            dt.put('/device-tree/retained', key, struct.pack('<I', 34))
            self.refused(dt, specs)

    def test_function_arguments_are_not_provider_phandles(self):
        dt, specs = fixture()
        dt.put('/device-tree/retained', 'function-gpio', struct.pack('<4I', 76, 0, 34, 0))
        before = deepcopy(snapshot(dt)[0]['/device-tree/retained'])
        self.assertEqual(defer_subtrees(dt, specs),
                         ('/device-tree/radio', '/device-tree/radio/child'))
        self.assertEqual(snapshot(dt)[0]['/device-tree/retained'], before)

    def test_explicit_function_withdrawal_and_atomic_refusals(self):
        node, name = '/device-tree/retained', 'function-radio'
        value = struct.pack('<2I', 34, 123)
        spec = DeferredFunction(node, name, value)
        for mode in ('valid', 'changed', 'missing', 'placeholder', 'duplicate',
                     'retained-provider', 'non-function', 'extra-reference',
                     'wrong-node', 'short-value'):
            dt, roots = fixture()
            dt.put(node, name, value)
            funcs = (spec,)
            if mode == 'changed': dt.put(node, name, struct.pack('<2I', 34, 124))
            elif mode == 'missing': del dt.nodes[node][name]
            elif mode == 'placeholder': dt.nodes[node][name].placeholder = True
            elif mode == 'duplicate': funcs *= 2
            elif mode == 'retained-provider':
                dt.put(node, name, struct.pack('<2I', 76, 123))
                funcs = (replace(spec, value=bytes(dt.get(node, name))),)
            elif mode == 'non-function':
                dt.put(node, 'interrupt-parent', value)
                funcs = (replace(spec, name='interrupt-parent'),)
            elif mode == 'extra-reference': dt.put(node, 'function-unlisted', value)
            elif mode == 'wrong-node': funcs = (replace(spec, node=roots[0].node),)
            elif mode == 'short-value':
                dt.put(node, name, value[:4]); funcs = (replace(spec, value=value[:4]),)
            if mode == 'valid':
                before = snapshot(dt)[0][node]
                del before[name]
                defer_subtrees(dt, roots, funcs)
                self.assertEqual(snapshot(dt)[0][node], before)
            else:
                self.refused(dt, roots, funcs)

    def test_ane_deferral_has_same_identity_with_high_guest_memory(self):
        from unittest.mock import patch
        with patch.dict(xb.__dict__, xb.__dict__.copy()):
            xb.place(0x8c0000000, 29696 << 20, guest_span=8192 << 20)
            full = xb.build_devicetree(include_deferred=True)
            dt = xb.build_devicetree()
            self.assertEqual(len(dt.nodes), 395)
            self.assertEqual(dt.device_models, full.device_models)
            for spec in xb.GUEST_PROFILE.deferred_functions:
                self.assertEqual(full.get(spec.node, spec.name), spec.value)
                self.assertIsNone(dt.get(spec.node, spec.name))
            # Every other retained property, including power/frequency tables,
            # must remain byte-for-byte identical at this real placement.
            omitted = {(s.node, s.name) for s in xb.GUEST_PROFILE.deferred_functions}
            for node in dt.nodes:
                for name in full.nodes[node]:
                    if (node, name) not in omitted:
                        self.assertEqual(dt.get(node, name), full.get(node, name))

    def test_invalid_phandles_refuse_even_with_bound_hash(self):
        for value in (b'\0' * 4, b'\x22', struct.pack('<I', 34)):
            dt, specs = fixture()
            dt.put('/device-tree/radio/child', 'AAPL,phandle', value)
            specs = (replace(specs[0], sha256=hashlib.sha256(
                dt.serialize(specs[0].node)).hexdigest()),)
            self.refused(dt, specs)

    def test_stock_driver_matching_and_native_tree_publisher(self):
        blob = (ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes()
        self.assertEqual(hashlib.sha256(blob).hexdigest(),
                         'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62')
        image = xb.kc_load.Image(blob)
        seg = next(s for s in image.segments if s[0] == '__PRELINK_INFO')
        infos = plistlib.loads(blob[seg[3]:seg[3]+seg[4]].rstrip(b'\0'))['_PrelinkInfoDictionary']
        agx = next(p for p in infos if p['CFBundleIdentifier'] == 'com.apple.AGXG17P')
        gpu = agx['IOKitPersonalities']['AGXG17P']
        self.assertEqual(gpu['IOClass'], 'AGXAcceleratorG17P')
        self.assertEqual(gpu['IOProviderClass'], 'AppleARMIODevice')
        self.assertIn('gpu,t8140', gpu['IONameMatch'])
        ane = [p for info in infos for p in info.get('IOKitPersonalities', {}).values()
               if p.get('IOClass') == 'H11ANEIn' and
               'ane,t8132exclave' in p.get('IONameMatch', ())]
        self.assertEqual(len(ane), 1)
        self.assertEqual(ane[0]['IOProviderClass'], 'AppleARMIODevice')
        self.assertTrue(ane[0]['IOExclaveProxy'])
        camera = next(p for p in infos if p['CFBundleIdentifier'] ==
                      'com.apple.driver.AppleH16CameraInterface')
        camera = camera['IOKitPersonalities']['generic-ex']
        self.assertEqual(camera['IOClass'], 'AppleH16CamIn')
        self.assertEqual(camera['IOProviderClass'], 'AppleARMIODevice')
        self.assertEqual(camera['IONameMatch'], 'isp,isp-generic-ex')
        self.assertTrue(camera['IOExclaveProxy'])
        clpc_id = 'com.apple.driver.AppleT8140CLPC'
        clpc_info = next(p for p in infos if p['CFBundleIdentifier'] == clpc_id)
        clpc = clpc_info['IOKitPersonalities']['AppleT8140CLPC']
        self.assertEqual(clpc['IOClass'], 'AppleCLPC')
        self.assertEqual(clpc['IOProviderClass'], 'ApplePMGRNub')
        self.assertEqual(clpc['IONameMatch'], 'clpc,t8140')
        self.assertEqual(clpc['IOPropertyMatch'], {'clpc-match-version': 3})
        self.assertFalse(any(clpc_id in p.get('OSBundleLibraries', {}) for p in infos))
        avd_id = 'com.apple.driver.AppleAVD'
        avd = next(p for p in infos if p['CFBundleIdentifier'] == avd_id)
        avd = avd['IOKitPersonalities']['s5l8920x']
        self.assertEqual(avd['IOClass'], 'AppleAVD')
        self.assertEqual(avd['IOProviderClass'], 'AppleARMIODevice')
        self.assertIn('avd,t8103', avd['IONameMatch'])
        self.assertFalse(any(avd_id in p.get('OSBundleLibraries', {}) for p in infos))
        scaler_id = 'com.apple.driver.AppleM2ScalerCSCDriver'
        scaler = next(p for p in infos if p['CFBundleIdentifier'] == scaler_id)
        scaler = scaler['IOKitPersonalities']['s5l8720x']
        self.assertEqual(scaler['IOClass'], 'AppleM2ScalerCSCDriver')
        self.assertEqual(scaler['IOProviderClass'], 'AppleARMIODevice')
        self.assertEqual(scaler['IONameMatch'], ['scaler,s5l8960x'])
        # The library stays loaded: removal of its hardware provider must not
        # be mistaken for removal of code imported by these display families.
        self.assertEqual({p['CFBundleIdentifier'] for p in infos
                          if scaler_id in p.get('OSBundleLibraries', {})},
                         {'com.apple.driver.AppleMobileDispH17P-DCP',
                          'com.apple.iokit.IOMobileGraphicsFamily-DCP',
                          'com.apple.iokit.IOMobileGraphicsFamily'})
        prores_id = 'com.apple.driver.AppleProResHW'
        prores = next(p for p in infos if p['CFBundleIdentifier'] == prores_id)
        prores = prores['IOKitPersonalities']['apr-k']
        self.assertEqual(prores['IOClass'], 'AppleProResHW')
        self.assertEqual(prores['IOProviderClass'], 'AppleARMIODevice')
        self.assertEqual(prores['IONameMatch'], ['apr,k0'])
        self.assertFalse(any(prores_id in p.get('OSBundleLibraries', {}) for p in infos))
        full = xb.build_devicetree(include_deferred=True)
        self.assertEqual(full.get('/device-tree/arm-io/apr', 'compatible'), b'apr,k0\0')
        self.assertEqual(full.get('/device-tree/arm-io/scaler0', 'compatible'),
                         b'scaler,t8101\0scaler,s5l8960x\0')
        self.assertEqual(full.get('/device-tree/arm-io/avd', 'compatible'), b'avd,t8103\0')
        self.assertEqual(full.get('/device-tree/arm-io/pmgr/clpc', 'compatible'), b'clpc,t8140\0')
        self.assertEqual(full.get('/device-tree/arm-io/sgx','compatible'), b'gpu,t8140\0')
        hpm = next(p for p in infos if p['CFBundleIdentifier'] == 'com.apple.driver.AppleHPM')
        personality = hpm['IOKitPersonalities']['AppleHPMARMSPMIType2']
        self.assertEqual(personality['IOClass'], 'AppleHPMARMSPMI')
        self.assertEqual(personality['IOProviderClass'], 'AppleARMSPMIDevice')
        self.assertEqual(personality['IONameMatch'], 'usbc,sn201202x,spmi')
        for name in ('hpm0', 'hpm1'):
            path='/device-tree/arm-io/nub-spmi-a0/'+name
            self.assertEqual(full.get(path, 'compatible'), b'usbc,sn201202x,spmi\0')
            self.assertEqual(full.children[path], [])
        for bundle, cls, name in (
                ('com.apple.driver.AppleT8140PCIe', 'AppleT8140PCIe', 'apcie,t8140'),
                ('com.apple.driver.AppleT6020PCIePIODMA', 'AppleT6020PCIePIODMA', 'pcie-apiodma,t6020')):
            info = next(p for p in infos if p['CFBundleIdentifier'] == bundle)
            matches = [p for p in info['IOKitPersonalities'].values() if p.get('IOClass') == cls]
            self.assertTrue(matches)
            self.assertTrue(any(p['IOProviderClass'] == 'AppleARMIODevice'
                                and p['IONameMatch'] == name for p in matches))
        def off(va):
            _, base, _, fileoff, _ = next(s for s in image.segments if s[1] <= va < s[1]+s[4])
            return fileoff+va-base
        for va, instruction in ((0xfffffe0008b58f28, 0xaa1403e0),
                                (0xfffffe0008b58f2c, 0x52800041),
                                (0xfffffe0008b58f30, 0x9401308a),
                                (0xfffffe0008b58f34, 0xb4000bc0),
                                (0xfffffe0008b58f64, 0xd73f0910),
                                (0xfffffe0008b5903c, 0xd73f0931)):
            self.assertEqual(struct.unpack_from('<I', blob, off(va))[0], instruction)
        target = off(0xfffffe0007f383e0)
        self.assertEqual(next(v for pos, v in xb.kc_load.chained_fixups(image, 0)
                              if pos == target), 0xfffffe000c0c4d04)


if __name__ == '__main__':
    unittest.main()
