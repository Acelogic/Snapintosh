#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import runpy
from pathlib import Path
import struct
import unittest

module=runpy.run_path(str(Path(__file__).with_name('audit-kernel-permissions.py')))
class KernelPermissions(unittest.TestCase):
    def setUp(self):
        self.ram=bytearray(0x40000);self.base=0x100000;self.data=0x900000000
        self.state=bytearray(8256);self.pp=[module['PPERM']|(0x100 if cpu&1 else 0) for cpu in range(6)]
        struct.pack_into('<8Q',self.state,0,self.base,4,*([1]*6))
        self.copies=[]
        for level in range(4):
            copies=[self.base+0x4000+(level*6+cpu)*4096 for cpu in range(6)]
            self.copies.append(copies)
            struct.pack_into('<8Q',self.state,64+64*level,self.base+level*4096,*copies,level)
        for level in range(4):
            for cpu in range(6):
                if level<3:
                    self.put(self.base+level*4096,self.base+(level+1)*4096+3)
                    self.put(self.copies[level][cpu],self.copies[level+1][cpu]+3)
                else:
                    for n in range(4):
                        d=self.data+n*4096+0x703+(1<<54)
                        self.put(self.base+level*4096+n*8,d)
                        self.put(self.copies[level][cpu]+n*8,
                                 (d&~(3<<6))|(3<<53)|(0 if cpu&1 else 2<<6))
        self.kw=dict(state=self.state,installed=self.copies[0],prepared=[True]*6,
                     canonical=[self.base]*6,pperm=self.pp,work_low=self.base,work_high=self.base+len(self.ram))
    def put(self,pa,d):struct.pack_into('<Q',self.ram,pa-self.base,d)
    def read(self,pa,size):
        if not self.base<=pa<=self.base+len(self.ram)-size:raise ValueError('fixture bounds')
        return self.ram[pa-self.base:pa-self.base+size]
    def run_audit(self):return module['audit'](self.read,**self.kw)
    def test_mixed_cpu_permissions(self):
        r=self.run_audit();self.assertEqual(r['protected_4k_pages'],4)
        self.assertEqual(r['private_copy_pages'],24)
        self.assertEqual(r['canonical_table_pages'],[hex(self.base+n*4096) for n in range(4)])
    def test_wrong_installed_root(self):
        self.kw['installed']=[self.base]*6
        with self.assertRaisesRegex(ValueError,'installed TTBR1'):self.run_audit()
    def test_permissions_corrupted_on_each_cpu(self):
        for cpu in range(6):
            with self.subTest(cpu=cpu):
                pa=self.copies[3][cpu];before=self.read(pa,8)
                self.put(pa,int.from_bytes(before,'little')^(2<<6))
                with self.assertRaisesRegex(ValueError,'private descriptor mismatch'):self.run_audit()
                self.put(pa,int.from_bytes(before,'little'))
    def test_alias_between_cpus(self):
        struct.pack_into('<Q',self.state,64+16,self.copies[0][0])
        with self.assertRaisesRegex(ValueError,'aliased private'):self.run_audit()
    def test_unprepared_ancestor(self):
        # Omit L2 from retained records while keeping a protected L3.
        self.state[64+2*64:64+3*64]=self.state[64+3*64:64+4*64]
        self.state[64+3*64:64+4*64]=bytes(64);struct.pack_into('<Q',self.state,8,3)
        with self.assertRaisesRegex(ValueError,'shared table'):self.run_audit()
    def test_unsupported_permission_state(self):
        self.pp[5]^=1
        with self.assertRaisesRegex(ValueError,'unsupported PPERM'):self.run_audit()
    def test_tpro_state_preserves_selector2_views_but_rejects_raw_selector9(self):
        self.pp[2]|=1<<36
        self.assertEqual(self.run_audit()['protected_4k_pages'],4)
        self.put(self.base+0x3000,self.data+0x783+(1<<53))
        with self.assertRaisesRegex(ValueError,'untranslated selector9'):
            self.run_audit()
    def test_frame_type_crosscheck(self):
        va=0xffff800000000000;root=self.base+0x20000
        self.put(root+8*((va>>36)&2047),root+0x4000+3)
        self.put(root+0x4000+8*((va>>25)&2047),root+0x8000+3)
        self.put(root+0x8000+8*((va>>14)&2047),self.data+0x703+(1<<54))
        fm=bytearray(16);fm[2]=25
        kw=dict(protected=self.run_audit()['protected'],root=root,frame_map=fm,
                frame_low=self.data,aperture_low=self.data,aperture_va=va,aperture_size=16384)
        self.assertEqual(module['audit_aperture'](self.read,**kw)['rozone_frames'],1)
        fm[2]=11
        with self.assertRaisesRegex(ValueError,'frame types'):module['audit_aperture'](self.read,**kw)
        fm[2]=25;self.put(root+0x8000+8*((va>>14)&2047),self.data+0x703+(3<<53))
        with self.assertRaisesRegex(ValueError,'descriptor differs'):module['audit_aperture'](self.read,**kw)

    def test_executable_frame_aperture_is_ro_on_every_cpu(self):
        for n in range(4):
            desc=self.data+n*4096+0x783+(3<<53)
            self.put(self.base+0x3000+n*8,desc)
            for cpu in range(6):self.put(self.copies[3][cpu]+n*8,desc)
        report=self.run_audit();va=0xffff800000000000;root=self.base+0x20000
        self.put(root+8*((va>>36)&2047),root+0x4000+3)
        self.put(root+0x4000+8*((va>>25)&2047),root+0x8000+3)
        self.put(root+0x8000+8*((va>>14)&2047),self.data+0x783+(3<<53))
        fm=bytearray(16);fm[2]=14
        kw=dict(protected={},readonly=report['readonly'],root=root,frame_map=fm,
                frame_low=self.data,aperture_low=self.data,aperture_va=va,aperture_size=16384)
        self.assertEqual(module['audit_aperture'](self.read,**kw)['user_exec_frames'],1)
        del kw['readonly'][va+8192]
        with self.assertRaisesRegex(ValueError,'not read-only'):module['audit_aperture'](self.read,**kw)

    def moved_fixture(self,kind,selector):
        """Linear alias at va plus SLIDE_REGION's alias at mva for one frame."""
        va=0xffff800000000000;mva=va+(1<<25);root=self.base+0x20000
        self.put(root+8*((va>>36)&2047),root+0x4000+3)
        self.put(root+0x4000+8*((va>>25)&2047),root+0x8000+3)
        self.put(root+0x4000+8*((mva>>25)&2047),root+0xc000+3)
        want=2 if kind==25 else 11
        leaf=lambda sel:self.data+0x603+((sel&12)<<4)+((sel&3)<<53)
        self.put(root+0x8000+8*((va>>14)&2047),leaf(want))
        self.put(root+0xc000+8*((mva>>14)&2047),leaf(selector))
        fm=bytearray(16);fm[2]=kind
        kw=dict(root=root,frame_map=fm,frame_low=self.data,aperture_low=self.data,
                aperture_va=va,aperture_size=16384,moved=[(mva,self.data,1)])
        return va,mva,kw
    def test_moved_rozone_alias_is_protected(self):
        va,mva,kw=self.moved_fixture(25,2)
        both={a+4096*n:self.data+4096*n for a in (va,mva) for n in range(4)}
        r=module['audit_aperture'](self.read,protected=dict(both),**kw)
        self.assertEqual((r['rozone_frames'],r['moved_aliases']),(1,1))
        linear={va+4096*n:self.data+4096*n for n in range(4)}
        with self.assertRaisesRegex(ValueError,'frame types'):
            module['audit_aperture'](self.read,protected=linear,**kw)
        # The pre-fix state: the moved alias still NX kernel RW (selector 3).
        va,mva,kw=self.moved_fixture(25,3)
        with self.assertRaisesRegex(ValueError,'descriptor differs'):
            module['audit_aperture'](self.read,protected=linear,**kw)
    def test_moved_user_exec_alias_is_read_only(self):
        va,mva,kw=self.moved_fixture(14,11)
        ro={a+4096*n:self.data+4096*n for a in (va,mva) for n in range(4)}
        r=module['audit_aperture'](self.read,protected={},readonly=dict(ro),**kw)
        self.assertEqual((r['user_exec_frames'],r['moved_aliases']),(1,1))
        del ro[mva+4096]
        with self.assertRaisesRegex(ValueError,'not read-only'):
            module['audit_aperture'](self.read,protected={},readonly=ro,**kw)
        va,mva,kw=self.moved_fixture(14,3)
        with self.assertRaisesRegex(ValueError,'descriptor differs'):
            module['audit_aperture'](self.read,protected={},readonly=ro,**kw)

if __name__=='__main__':unittest.main()
