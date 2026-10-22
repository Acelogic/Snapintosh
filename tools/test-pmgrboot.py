#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Stock PMGR table geometry, publication and atomic admission tests."""
from dataclasses import replace
from pathlib import Path
import hashlib
import importlib.util
import struct
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
from appledt import DeviceTree
from pmgrboot import populate_pmgr_boot, VIRTUAL_ANE_STATES, VIRTUAL_ANE_ACTIVE_INDEX
import xnuboot as xb

SPEC=xb.GUEST_PROFILE.pmgr_boot
MISSING=(1,5,8,10,11)


def fixture():
    dt=xb.build_devicetree()
    for domain in MISSING:del dt.nodes[SPEC.node][f'voltage-states{domain}']
    return dt


class PMGRBootTests(unittest.TestCase):
    def test_clpc_requires_a_frequency_format_fane_state(self):
        dt=xb.build_devicetree()
        self.assertEqual(dt.get(SPEC.node,'voltage-states8'),
                         b''.join(struct.pack('<II',*e) for e in VIRTUAL_ANE_STATES))
        # Replay the native kind-0 parser's two formats. Zero voltage makes
        # the first word an index; nonzero voltage makes it Hz. CLPC then
        # filters zero metadata rates before indexing the final point.
        def native(rows):
            if rows[0][1]:
                return len(rows),[(hz*0x431bde83)>>50 for hz,_ in rows]
            return rows[-1][0]+1,[0]*(rows[-1][0]+1)
        rows=tuple(struct.iter_unpack('<II',dt.get(SPEC.node,'voltage-states8')))
        count,rates=native(rows)
        self.assertEqual((count,rates),(2,[0,1000]))
        self.assertGreater(VIRTUAL_ANE_ACTIVE_INDEX,0)
        self.assertLess(VIRTUAL_ANE_ACTIVE_INDEX,count)
        self.assertEqual(rates[VIRTUAL_ANE_ACTIVE_INDEX],1000)
        self.assertLessEqual(count,255)  # native PMGR loop truncates to u8
        self.assertEqual(native(((1000,0),))[0],1001)
        self.assertEqual(native(((0,0),(1,0))), (2,[0,0]))
        for entries in (((0,0),),((1,0),),((1000,0),),((0,0),(1,0)),
                        ((1_000_000_000,0),),((1000,1000),),
                        ((1_000_000_000,1001),), ((1_000_000_000,1000),),
                        VIRTUAL_ANE_STATES*2,((0,0),(1_000_000_000,1000))):
            changed=replace(SPEC,tables=tuple((domain,entries if domain==8 else rows)
                                             for domain,rows in SPEC.tables))
            self.assert_refused(fixture(),changed)

    def test_bound_native_ane_parser_format_and_loop(self):
        spec=importlib.util.spec_from_file_location('kc',ROOT/'tools/kc-load.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        image=module.Image(xb.DEFAULT_KERNELCACHE.read_bytes())
        self.assertEqual(hashlib.sha256(image.data).hexdigest(),
                         'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62')
        def words(low,count):
            va=0xfffffe0000000000+low
            _,base,_,off,_=next(s for s in image.segments if s[1]<=va<s[1]+s[4])
            return struct.unpack_from('<'+'I'*count,image.data,off+va-base)
        # Voltage-word presence, indexed-vs-frequency count branch, and MHz conversion.
        self.assertEqual(words(0x9789aa0,6),(0xb9400409,0x7100013f,0x1a9f07f7,0x38402e8a,0x7100055f,0xf9408ff6))
        self.assertEqual(words(0x9789df0,4),(0x7100015f,0x7a400924,0x54000ca1,0x51000508))
        self.assertEqual(words(0x9789e18,3),(0xb9400128,0x11000508,0xb9000b88))
        self.assertEqual(words(0x9789f8c,2),(0xb9000b88,0x52800037))
        self.assertEqual(words(0x978a148,6),(0x340001aa,0xf9403f8b,0xd37df12c,0xb86c696b,0x9bb87d6b,0xd372fd6b))
        self.assertEqual(words(0x9796928,4),(0x11000739,0xb9400a88,0x6b39011f,0x54fff068))
        # fANE0 is the getFANEIndex return directly wrapped as OSNumber,
        # not the domain's MHz value. CLPC filters index zero.
        self.assertEqual(words(0x97971ec,11),(0xd281f411,0x8b110210,0xf9400208,
            0x12001f22,0xaa1303e0,0x52800003,0xf2eac770,0xd73f0910,
            0x2a0003e0,0x52800401,0x940136ba))
        self.assertEqual(words(0x9b844fc,4),(0x34000080,0xb8355b20,0xb8355b55,0x110006b5))

    def test_cpu_apsc_omission_is_narrow_and_explicit(self):
        source=DeviceTree((ROOT/'downloads/extracted/j700ap/DeviceTree.j700ap').read_bytes())
        payload=source.get(SPEC.node,'cpu-apsc')
        self.assertEqual(payload,struct.pack('<I',1))
        self.assertEqual(hashlib.sha256(payload).hexdigest(),dict(SPEC.omit_features)['cpu-apsc'])
        dt=xb.build_devicetree();expected=dt.serialize()
        self.assertNotIn('cpu-apsc',dt.nodes[SPEC.node])
        dt.put(SPEC.node,'cpu-apsc',payload)
        unbound=replace(SPEC,omit_features=tuple(x for x in SPEC.omit_features if x[0]!='cpu-apsc'))
        populate_pmgr_boot(dt,unbound)
        self.assertEqual(dt.get(SPEC.node,'cpu-apsc'),payload)
        populate_pmgr_boot(dt,SPEC);self.assertEqual(dt.serialize(),expected)
        populate_pmgr_boot(dt,SPEC);self.assertEqual(dt.serialize(),expected)

    def test_cpu_apsc_binding_and_atomic_rejection(self):
        source=DeviceTree((ROOT/'downloads/extracted/j700ap/DeviceTree.j700ap').read_bytes())
        for name,_ in SPEC.omit_features:
            for value,placeholder in ((b'',False),(struct.pack('<I',0),False),
                                      (struct.pack('<I',2),False),(struct.pack('<I',1),True)):
                dt=fixture();dt.put(SPEC.node,name,value)
                dt.nodes[SPEC.node][name].placeholder=placeholder
                dt.put(SPEC.node,'hw-dpe-reg',source.get(SPEC.node,'hw-dpe-reg'))
                self.assert_refused(dt)
        for binding in ('','f'*63,'G'*64,True,'0'*64):
            dt=fixture();dt.put(SPEC.node,'cpu-apsc',struct.pack('<I',1))
            features=tuple((name,binding if name=='cpu-apsc' else digest)
                           for name,digest in SPEC.omit_features)
            self.assert_refused(dt,replace(SPEC,omit_features=features))
        dt=fixture();dt.put(SPEC.node,'cpu-apsc',struct.pack('<I',1))
        self.assert_refused(dt,replace(SPEC,tables=SPEC.tables[:-1]))

    def test_feature_policy_refuses_unreviewed_names_and_duplicates(self):
        digest=dict(SPEC.omit_features)['cpu-apsc']
        for entries in (None,[],('cpu-apsc',),(('cpu-apsc',),),
                        (('pmp',digest),),(('reg',digest),),
                        (('cpu-apsc',None),),(('cpu-apsc',digest),)*2):
            self.assert_refused(fixture(),replace(SPEC,omit_features=entries))

    def test_feature_omission_preserves_every_other_property(self):
        source=DeviceTree((ROOT/'downloads/extracted/j700ap/DeviceTree.j700ap').read_bytes())
        dt=fixture()
        for name,digest in SPEC.omit_features:
            payload=source.get(SPEC.node,name)
            self.assertEqual(payload,struct.pack('<I',1))
            self.assertEqual(hashlib.sha256(payload).hexdigest(),digest)
            dt.put(SPEC.node,name,payload)
        # No omissions while publishing performance tables.
        populate_pmgr_boot(dt,replace(SPEC,omit_features=()))
        before={node:{name:(bytes(p.value),p.placeholder) for name,p in props.items()}
                for node,props in dt.nodes.items()}
        populate_pmgr_boot(dt,SPEC)
        for name,_ in SPEC.omit_features:del before[SPEC.node][name]
        after={node:{name:(bytes(p.value),p.placeholder) for name,p in props.items()}
               for node,props in dt.nodes.items()}
        self.assertEqual(before,after)
        serialized=dt.serialize();populate_pmgr_boot(dt,SPEC)
        self.assertEqual(dt.serialize(),serialized)

    def test_stock_optional_cpu_apsc_feature_contract(self):
        spec=importlib.util.spec_from_file_location('kc',ROOT/'tools/kc-load.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        image=module.Image((ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes())
        def offset(low):
            va=0xfffffe0000000000+low
            _,base,_,off,_=next(s for s in image.segments if s[1]<=va<s[1]+s[4])
            return off+va-base
        def words(low,count):return struct.unpack_from('<'+'I'*count,image.data,offset(low))
        # Feature 0 is cpu-apsc and all fields start zero, including valid.
        fixups=dict(module.chained_fixups(image,0))
        self.assertEqual(fixups[offset(0x8178010)],0xfffffe000762c836)
        self.assertEqual(image.data[offset(0x762c836):offset(0x762c836)+9],b'cpu-apsc\0')
        self.assertEqual(words(0x8178018,4),(0,0,0,0))
        # TVM, throttler and PLL declarations use the same zero-valid template.
        for index,name in ((3,'soc-tvm'),(5,'disp-tvm'),(6,'ave-tvm'),
                           (8,'gfx-tvm'),(10,'dcs-tvm'),(20,'ppt-thrtl'),
                           (21,'llc-thrtl'),(22,'amx-thrtl'),
                           (47,'cpu-fixed-freq-pll-relock')):
            record=0x8178010+24*index
            ptr=fixups[offset(record)]-0xfffffe0000000000
            self.assertEqual(image.data[offset(ptr):offset(ptr)+len(name)+1],name.encode()+b'\0')
            self.assertEqual(words(record+8,4),(0,0,0,0))
        # Constructor copies the full 97 x 24-byte feature table to +1d50.
        self.assertEqual(words(0x977ef30,4),(0xd0ff4fc1,0x91004021,0x8b080000,0x52812302))
        # getProperty failure skips valid/value publication and bootarg override.
        self.assertEqual(words(0x977f580,5),(0x940002fa,0x34000300,0x390022f6,0xb9405be8,0xb9000ee8))
        self.assertEqual(words(0x97801bc,1),(0xb40001a0,))
        # validFeature checks row+8; restoreHW skips this feature if false.
        self.assertEqual(words(0x9780428,2),(0x39400148,0x12000100))
        self.assertEqual(words(0x979e970,2),(0x97ff86a1,0x340002a0))

    def test_optional_hardware_energy_omission_preserves_other_capabilities(self):
        source_path=ROOT/'downloads/extracted/j700ap/DeviceTree.j700ap'
        source_bytes=source_path.read_bytes();source=DeviceTree(source_bytes)
        payload=source.get(SPEC.node,'hw-dpe-reg')
        self.assertEqual(len(payload),760)
        self.assertEqual(hashlib.sha256(payload).hexdigest(),SPEC.omit_hw_dpe_sha256)
        dt=xb.build_devicetree()
        self.assertNotIn('hw-dpe-reg',dt.nodes[SPEC.node])
        for name in ('energy-counters','soc-dpe','ane-dpe','devices','reg'):
            self.assertEqual(dt.get(SPEC.node,name),source.get(SPEC.node,name))
        expected=dt.serialize()
        dt.put(SPEC.node,'hw-dpe-reg',payload)
        populate_pmgr_boot(dt,replace(SPEC,omit_hw_dpe_sha256=None))
        self.assertEqual(dt.get(SPEC.node,'hw-dpe-reg'),payload)
        populate_pmgr_boot(dt,SPEC)
        self.assertEqual(dt.serialize(),expected)
        populate_pmgr_boot(dt,SPEC)
        self.assertEqual(dt.serialize(),expected)
        self.assertEqual(source_path.read_bytes(),source_bytes)

    def test_hardware_energy_binding_and_atomic_omission(self):
        source=DeviceTree((ROOT/'downloads/extracted/j700ap/DeviceTree.j700ap').read_bytes())
        payload=source.get(SPEC.node,'hw-dpe-reg')
        for value,placeholder in ((b'',False),(payload[:-1],False),(payload,True)):
            dt=fixture();dt.put(SPEC.node,'hw-dpe-reg',value)
            dt.nodes[SPEC.node]['hw-dpe-reg'].placeholder=placeholder
            self.assert_refused(dt)
        for binding in ('','f'*63,'G'*64,True,'0'*64):
            dt=fixture();dt.put(SPEC.node,'hw-dpe-reg',payload)
            self.assert_refused(dt,replace(SPEC,omit_hw_dpe_sha256=binding))
        # Valid energy metadata must survive a later performance-table error.
        dt=fixture();dt.put(SPEC.node,'hw-dpe-reg',payload)
        self.assert_refused(dt,replace(SPEC,tables=SPEC.tables[:-1]))

    def test_stock_optional_hardware_energy_branch(self):
        spec=importlib.util.spec_from_file_location('kc',ROOT/'tools/kc-load.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        image=module.Image((ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes())
        def read(low,length):
            va=0xfffffe0000000000+low
            _,base,_,off,_=next(s for s in image.segments if s[1]<=va<s[1]+s[4])
            return image.data[off+va-base:off+va-base+length]
        def words(low,count):return struct.unpack('<'+'I'*count,read(low,4*count))
        self.assertEqual(read(0x762fa96,11),b'hw-dpe-reg\0')
        self.assertEqual(words(0x978e858,2),(0xb0fef501,0x912a5821))
        # Null property skips setup and presence flag, continuing at f040.
        self.assertEqual(words(0x978e870,3),(0xb4003e80,0x52800028,0x3905b268))
        self.assertEqual(read(0x762fcd0,20),b'function-perf-boost\0')
        # Without PMP, the native energy-node count comes from local setup.
        self.assertEqual(words(0x9781ab0,2),(0xb9416669,0xf9000109))
        # restoreHW naturally skips the node loop when the count is zero.
        self.assertEqual(words(0x979e804,2),(0xf94002e8,0xb40007a8))

    def test_stock_consumer_has_nonzero_periods_and_valid_indices(self):
        dt=fixture();counts=dict(populate_pmgr_boot(dt,SPEC))
        self.assertEqual(counts,{0:3,1:1,2:4,5:1,8:2,10:1,11:1})
        for domain in (1,5):
            data=dt.get(SPEC.node,f'voltage-states{domain}')
            self.assertEqual(len(data)%8,0)
            entries=list(struct.iter_unpack('<II',data))
            prefix=next((i for i,(period,_) in enumerate(entries) if not period),len(entries))
            self.assertEqual(prefix,1)
            self.assertEqual([65536000//period for period,_ in entries],[1000])
            self.assertEqual([voltage for _,voltage in entries],[0])
        for domain in (0,2,10,11):
            entries=list(struct.iter_unpack('<II',dt.get(SPEC.node,f'voltage-states{domain}')))
            self.assertEqual(entries[-1][0]+1,counts[domain])

    def test_only_missing_properties_change_and_publication_is_idempotent(self):
        dt=fixture();before=dt.serialize();extra=bytes(dt.get(SPEC.node,'voltage-states9'))
        populate_pmgr_boot(dt,SPEC);after=dt.serialize();populate_pmgr_boot(dt,SPEC)
        self.assertEqual(dt.serialize(),after)
        self.assertEqual(bytes(dt.get(SPEC.node,'voltage-states9')),extra)
        for domain in MISSING:del dt.nodes[SPEC.node][f'voltage-states{domain}']
        self.assertEqual(dt.serialize(),before)

    def assert_refused(self,dt,spec=SPEC):
        before=dt.serialize()
        with self.assertRaises(ValueError):populate_pmgr_boot(dt,spec)
        self.assertEqual(dt.serialize(),before)

    def test_bad_bindings_topology_and_placeholders_refused(self):
        for name in ('compatible','perf-domains'):
            dt=fixture();dt.nodes[SPEC.node][name].placeholder=True;self.assert_refused(dt)
            dt=fixture();del dt.nodes[SPEC.node][name];self.assert_refused(dt)
        dt=fixture();dt.put(SPEC.node,'compatible',b'pmgr1,other\0');self.assert_refused(dt)
        dt=fixture();dt.nodes[SPEC.node]['perf-domains'].value[0]^=1;self.assert_refused(dt)
        dt=fixture();dt.put(SPEC.node,'voltage-states11',struct.pack('<II',0,0))
        dt.nodes[SPEC.node]['voltage-states11'].placeholder=True;self.assert_refused(dt)

    def test_conflicts_and_selection_out_of_bounds_refused_atomically(self):
        for domain in (0,1,5,11):
            dt=fixture();dt.put(SPEC.node,f'voltage-states{domain}',struct.pack('<II',1,2))
            self.assert_refused(dt)
        for prefix in ('initial-performance','nominal-performance','boost-performance'):
            for value in (b'',bytes(8),struct.pack('<I',1)):
                dt=fixture();dt.put(SPEC.node,prefix+'1',value);self.assert_refused(dt)

    def test_incomplete_duplicate_or_unsupported_spec_refused(self):
        for tables in (SPEC.tables[:-1],SPEC.tables+(SPEC.tables[0],),
                       SPEC.tables+((99,((0,0),)),)):
            self.assert_refused(fixture(),replace(SPEC,tables=tables))
        for entries in ((),((0,0),),((1_000_000_000,0),),((65536,700),),
                        ((True,0),),((1<<32,0),),((65536,0),)*32):
            tables=tuple((domain,entries if domain==1 else states) for domain,states in SPEC.tables)
            self.assert_refused(fixture(),replace(SPEC,tables=tables))

    def test_real_profile_serialization_preserves_device_abi_and_timebase(self):
        dt=xb.build_devicetree();parsed=DeviceTree(dt.serialize())
        for domain,states in SPEC.tables:
            self.assertEqual(parsed.get(SPEC.node,f'voltage-states{domain}'),
                             b''.join(struct.pack('<II',*state) for state in states))
        self.assertEqual(len(dt.device_models),120)
        self.assertEqual(struct.unpack('<I',parsed.get('/device-tree/cpus/cpu0','timebase-frequency'))[0],24000000)


if __name__=='__main__':unittest.main()
