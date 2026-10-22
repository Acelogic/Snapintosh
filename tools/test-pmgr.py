#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate PMGR power and characterization banks against the pinned profile."""
from dataclasses import replace
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import xnuboot as xb
from devicemodel import pmgr_power_models, device_model_words, PMGR_AON_FUSES_V1, AXI2AF_BANKS_V1


class PMGRTests(unittest.TestCase):
    def setUp(self):
        self.dt=xb.build_devicetree()
        self.spec=xb.GUEST_PROFILE.pmgr_boot
        bus,name=self.spec.node.rsplit('/',1)
        self.windows=xb.device_windows(self.dt,name,bus)

    def test_aes_leaf_retains_shared_sio(self):
        raw=self.dt.get(self.spec.node,'devices');rows={}
        for pos in range(0,len(raw),48):
            row=raw[pos:pos+48];rows[struct.unpack_from('<H',row,26)[0] or row[3]]=row
        self.assertEqual(rows[75][32:].split(b'\0')[0],b'AES')
        self.assertEqual(struct.unpack_from('<I',rows[75],16)[0],0x308)
        self.assertEqual(struct.unpack_from('<2H',rows[75],4),(54,0))
        self.assertEqual(rows[54][32:].split(b'\0')[0],b'SIO')
        self.assertEqual(struct.unpack_from('<I',rows[54],16)[0],0x260)
        self.assertFalse(any(75 in struct.unpack_from('<2H',row,4) for row in rows.values()))
        owners={path for path,props in self.dt.nodes.items() if 'clock-gates' in props
                and 75 in [v[0] for v in struct.iter_unpack('<I',props['clock-gates'].value)]}
        self.assertEqual(owners,{'/device-tree/arm-io/aes'})
        sio=[m for m in self.dt.device_models if m.node=='/device-tree/arm-io/dart-sio']
        self.assertEqual([(m.base,m.span,m.config) for m in sio],
            [(0x385060000,0x20000,(16,300,1120,36,1<<21))])
        output=subprocess.run([str(ROOT/'build/test-pmgr-aes'),'--topology'],
                              check=True,capture_output=True,text=True).stdout
        self.assertEqual(output.strip(),'776 608 0')

    def test_atc_dependencies_and_usb_dart_ownership(self):
        raw=self.dt.get(self.spec.node,'devices');rows={}
        for pos in range(0,len(raw),48):
            row=raw[pos:pos+48]
            rows[struct.unpack_from('<H',row,26)[0] or row[3]]=row
        self.assertEqual(rows[47][32:].split(b'\0')[0],b'AFISOCNI2')
        self.assertEqual(struct.unpack_from('<I',rows[47],16)[0],0x228)
        expected={}
        for ident,name in ((102,b'ATC0_USB_AON'),(103,b'ATC0_COMMON'),(104,b'ATC0_USB')):
            row=rows[ident]
            self.assertEqual((row[0],row[3]),(0,0))
            self.assertEqual(row[32:].split(b'\0')[0],name)
            parents=struct.unpack_from('<2H',row,4)
            expected[struct.unpack_from('<I',row,16)[0]]=tuple(
                struct.unpack_from('<I',rows[parent],16)[0] if parent else 0
                for parent in parents)
        self.assertEqual(expected,{0x3e0:(0,0),0x3e8:(0x228,0x3e0),0x3f0:(0x3e8,0)})
        children={ident for ident,row in rows.items()
                  if set(struct.unpack_from('<2H',row,4))&{102,103,104}}
        self.assertEqual(children,{103,104,300,320})
        for ident,parent in ((300,102),(320,104)):
            self.assertEqual(rows[ident][0]&16,16)
            self.assertEqual(struct.unpack_from('<2H',rows[ident],4),(parent,0))
        for node,gates in (('atc-phy0',(300,103)),('dart-usb',(320,320)),
                           ('usb-drd',(104,298,341,342,305))):
            self.assertEqual(tuple(v[0] for v in struct.iter_unpack('<I',
                self.dt.get('/device-tree/arm-io/'+node,'clock-gates'))),gates)
        usb=[m for m in self.dt.device_models if m.node=='/device-tree/arm-io/dart-usb']
        self.assertEqual([(m.kind,m.base,m.span,m.config) for m in usb],
            [(17,base,0xc000,(16,44,1248,36,1<<22)) for base in (0x40af00000,0x40af80000)])
        self.assertFalse(any(m.node in ('/device-tree/arm-io/usb-drd',
            '/device-tree/arm-io/atc-phy0') for m in self.dt.device_models))
        binary=ROOT/'build/test-pmgr-atc'
        self.assertTrue(binary.exists(),'build tools/test-pmgr-atc.c before this contract check')
        output=subprocess.run([str(binary),'--topology'],check=True,capture_output=True,text=True).stdout
        self.assertEqual({values[0]:tuple(values[1:]) for line in output.splitlines()
                          if (values:=list(map(int,line.split())))},expected)

    def test_dpa_dependencies_and_sio_audio_ownership(self):
        self.check_media_dependencies(0x390,2,{92,93},{},'dpa')
        for i,ident in enumerate((92,93)):
            path=f'/device-tree/arm-io/dp-audio{i}'
            for name in ('clock-gates','power-gates'):
                self.assertEqual(self.dt.get(path,name),struct.pack('<I',ident))
            self.assertEqual(self.dt.get(path,'dma-parent'),struct.pack('<I',129))
            self.assertEqual(struct.unpack('<8I',self.dt.get(path,'dma-channels')),
                (100+2*i,2,0,0x800,0x800,0,0,0))
        self.assertEqual(self.dt.get('/device-tree/arm-io/sio/iop-sio-nub/sio-dma',
            'AAPL,phandle'),struct.pack('<I',129))
        self.assertFalse(any('dp-audio' in m.node or 'sio-dma' in m.node
                             for m in self.dt.device_models))
        sio=[m for m in self.dt.device_models if m.node=='/device-tree/arm-io/dart-sio']
        self.assertEqual(len(sio),1)
        self.assertEqual(sio[0].config,(16,300,1120,36,1<<21))

    def test_serial_bus_dependencies_and_consumers(self):
        self.check_media_dependencies(0x330,5,set(range(80,85)),{},'spi')
        self.check_media_dependencies(0x2c8,5,set(range(67,72)),{},'i2c')
        raw=self.dt.get(self.spec.node,'devices');rows={}
        for pos in range(0,len(raw),48):
            row=raw[pos:pos+48];rows[struct.unpack_from('<H',row,26)[0] or row[3]]=row
        leaves=set(range(80,85))|set(range(67,72))
        self.assertFalse(any(set(struct.unpack_from('<2H',r,4))&leaves for r in rows.values()))
        self.assertEqual(rows[72][32:].split(b'\0')[0],b'SPI_P')
        self.assertEqual(struct.unpack_from('<2H',rows[72],4),(54,0))
        self.assertEqual(rows[54][32:].split(b'\0')[0],b'SIO')
        owners={}
        for path,props in self.dt.nodes.items():
            if 'clock-gates' not in props:continue
            gates={v[0] for v in struct.iter_unpack('<I',props['clock-gates'].value)}
            if gates&leaves:owners[path]=gates&leaves
        self.assertEqual(owners,{
            '/device-tree/arm-io/:j700_has_mesa_0/spi2':{82},
            '/device-tree/arm-io/spi3':{83},'/device-tree/arm-io/qspi':{84},
            '/device-tree/arm-io/i2c0':{67},'/device-tree/arm-io/i2c2':{69}})
        spi2='/device-tree/arm-io/:j700_has_mesa_0/spi2'
        self.assertEqual(self.dt.get(spi2,'dma-parent'),struct.pack('<I',129))
        self.assertEqual(tuple(struct.iter_unpack('<8I',self.dt.get(spi2,'dma-channels'))),
            ((24,0,0,0x80,0x40,0,0,0),(25,0,0,0x80,0x40,0,0,0)))
        backed={(m.node,m.kind) for m in self.dt.device_models
                if any(m.node==owner or m.node.startswith(owner+'/') for owner in owners)}
        self.assertEqual(backed,{('/device-tree/arm-io/qspi',41),
                                 ('/device-tree/arm-io/i2c2',43)})

    def test_auxiliary_idle_leaves_and_shared_owners(self):
        self.check_media_dependencies(0x2b8,2,{65,66},{},'pwm')
        self.check_media_dependencies(0x298,1,{61},{49:13},'ase')
        self.check_media_dependencies(0x188,2,{27,28},{},'sensor')
        raw=self.dt.get(self.spec.node,'devices');leaves={65,66,61,27,28}
        self.assertFalse(any(set(struct.unpack_from('<2H',raw,pos+4))&leaves
                             for pos in range(0,len(raw),48)))
        owners={}
        for path,props in self.dt.nodes.items():
            for key in ('clock-gates','power-gates'):
                if key not in props:continue
                gates={v[0] for v in struct.iter_unpack('<I',props[key].value)}
                if gates&leaves:owners[path,key]=gates&leaves
        self.assertEqual(owners,{('/device-tree/arm-io/scaler0',k):{61}
                                 for k in ('clock-gates','power-gates')})
        self.assertFalse(any(m.node==owner or m.node.startswith(owner+'/')
            for m in self.dt.device_models for owner,_ in owners))
        self.assertEqual(self.dt.get('/device-tree/arm-io/scaler0','iommu-parent'),
                         struct.pack('<2I',221,222))
        full=xb.build_devicetree(include_deferred=True)
        self.assertNotIn('/device-tree/arm-io/isp',self.dt.nodes)
        self.assertEqual(full.get('/device-tree/arm-io/isp','iommu-parent'),
                         struct.pack('<7I',250,251,252,253,254,255,256))

    def test_ane_system_virtual_vote_and_dart_binding(self):
        self.check_media_dependencies(0x290,1,{60},{},'ane')
        raw=self.dt.get(self.spec.node,'devices');rows={}
        for pos in range(0,len(raw),48):
            row=raw[pos:pos+48];rows[struct.unpack_from('<H',row,26)[0] or row[3]]=row
        self.assertEqual((rows[60][0],rows[60][3]),(128,0))
        self.assertEqual(struct.unpack_from('<2H',rows[60],4),(47,0))
        self.assertEqual({i for i,r in rows.items() if 60 in struct.unpack_from('<2H',r,4)},
                         {129,291})
        self.assertEqual((rows[129][0],rows[291][0]),(16,16))
        self.assertEqual((rows[338][0],rows[338][3]),(18,6))
        self.assertEqual(struct.unpack_from('<2H',rows[338],4),(0,0))
        pmp=list(struct.iter_unpack('<31I',self.dt.get('/device-tree/arm-io/pmp/iop-pmp-nub','soc-device')))
        self.assertEqual([(i,r[0]) for i,r in enumerate(pmp) if r[0]==6],[(10,6)])
        full=xb.build_devicetree(include_deferred=True)
        self.assertNotIn('/device-tree/arm-io/ane',self.dt.nodes)
        self.assertEqual(full.get(self.spec.node,'devices'),raw)
        for key in ('clock-gates','power-gates'):
            self.assertEqual(full.get('/device-tree/arm-io/ane',key),struct.pack('<2I',291,338))
        banks=[m for m in self.dt.device_models if m.node=='/device-tree/arm-io/dart-ane']
        self.assertEqual([(m.base,m.span,m.config) for m in banks],
            [(0x401800000,0xc000,(16,812,656,36,1)),
             (0x401820000,0x20000,(16,812,656,36,1)),
             (0x401840000,0x20000,(16,812,656,36,1))])
        self.assertFalse(any(m.node=='/device-tree/arm-io/ane' or m.node.startswith('/device-tree/arm-io/ane/')
                             for m in self.dt.device_models))
        self.assertIn(b'DAPF',self.dt.get('/device-tree/arm-io/dart-ane','instance'))

    def test_avd_physical_pmp_state_and_dart_ownership(self):
        raw=self.dt.get(self.spec.node,'devices');rows={}
        for pos in range(0,len(raw),48):
            row=raw[pos:pos+48];rows[struct.unpack_from('<H',row,26)[0] or row[3]]=row
        self.assertEqual((rows[56][0],rows[56][3]),(2,12))
        self.assertEqual(struct.unpack_from('<2H',rows[56],4),(46,0))
        self.assertEqual(struct.unpack_from('<I',rows[56],16)[0],0x270)
        self.assertEqual(struct.unpack_from('<I',rows[46],16)[0],0x220)
        self.assertEqual({i for i,r in rows.items() if 56 in struct.unpack_from('<2H',r,4)},{290})
        self.assertEqual((rows[290][0],rows[290][3]),(16,0))
        for ident in (250,251):self.assertEqual((rows[ident][0],rows[ident][3]),(18,12))
        pmp=list(struct.iter_unpack('<31I',self.dt.get('/device-tree/arm-io/pmp/iop-pmp-nub','soc-device')))
        self.assertEqual([(i,r[0]) for i,r in enumerate(pmp) if r[0]==12],[(17,12)])
        for key in ('clock-gates','power-gates'):
            self.assertEqual(self.dt.get('/device-tree/arm-io/avd',key),struct.pack('<3I',290,250,251))
        self.assertEqual(self.dt.get('/device-tree/arm-io/avd','iommu-parent'),struct.pack('<3I',242,243,244))
        banks=[m for m in self.dt.device_models if m.node=='/device-tree/arm-io/dart-avd']
        self.assertEqual([(m.base,m.span,m.config) for m in banks],
                         [(0x381020000,0x20000,(16,44,943,36,16))])
        self.assertFalse(any(m.node=='/device-tree/arm-io/avd' or m.node.startswith('/device-tree/arm-io/avd/')
                             for m in self.dt.device_models))
        binary=ROOT/'build/test-pmgr-avd';self.assertTrue(binary.exists())
        output=subprocess.run([str(binary),'--topology'],check=True,capture_output=True,text=True).stdout
        self.assertEqual(tuple(map(int,output.split())),(0x270,0x220,17))

    def test_isp_system_physical_pmp_state_and_dart_ownership(self):
        raw=self.dt.get(self.spec.node,'devices');rows={}
        for pos in range(0,len(raw),48):
            row=raw[pos:pos+48];rows[struct.unpack_from('<H',row,26)[0] or row[3]]=row
        self.assertEqual((rows[55][0],rows[55][3]),(2,7))
        self.assertEqual(struct.unpack_from('<2H',rows[55],4),(46,0))
        self.assertEqual(struct.unpack_from('<I',rows[55],16)[0],0x268)
        self.assertEqual(struct.unpack_from('<I',rows[46],16)[0],0x220)
        self.assertEqual({i for i,r in rows.items() if 55 in struct.unpack_from('<2H',r,4)},
                         {106,109,295})
        self.assertEqual((rows[295][0],rows[295][3]),(16,0))
        self.assertEqual({struct.unpack_from('<I',rows[i],16)[0] for i in (106,109)},
                         {0x4000,0x4018})
        pmp=list(struct.iter_unpack('<31I',self.dt.get('/device-tree/arm-io/pmp/iop-pmp-nub','soc-device')))
        self.assertEqual([(i,r[0]) for i,r in enumerate(pmp) if r[0]==7],[(11,7)])
        full=xb.build_devicetree(include_deferred=True)
        self.assertNotIn('/device-tree/arm-io/isp',self.dt.nodes)
        self.assertEqual(full.get(self.spec.node,'devices'),raw)
        for key in ('clock-gates','power-gates'):
            self.assertEqual(full.get('/device-tree/arm-io/isp',key),struct.pack('<4I',295,27,28,254))
        self.assertEqual(full.get('/device-tree/arm-io/isp','iommu-parent'),
                         struct.pack('<7I',250,251,252,253,254,255,256))
        banks=[m for m in self.dt.device_models if m.node=='/device-tree/arm-io/dart-isp']
        self.assertEqual([(m.base,m.span,m.config) for m in banks],
                         [(base,0xc000,(16,44,341,36,0))
                          for base in (0x3228c0000,0x3228e0000,0x322900000)])
        self.assertIn(b'DAPF',self.dt.get('/device-tree/arm-io/dart-isp','instance'))
        self.assertIn(b'SMMU',self.dt.get('/device-tree/arm-io/dart-isp','instance'))
        self.assertFalse(any(m.node=='/device-tree/arm-io/isp' or m.node.startswith('/device-tree/arm-io/isp/')
                             for m in self.dt.device_models))
        binary=ROOT/'build/test-pmgr-isp-system';self.assertTrue(binary.exists())
        output=subprocess.run([str(binary),'--topology'],check=True,capture_output=True,text=True).stdout
        self.assertEqual(tuple(map(int,output.split())),(0x268,0x220,11))

    def test_prores_system_apr_dart_and_physical_pmp_binding(self):
        raw=self.dt.get(self.spec.node,'devices');rows={}
        for pos in range(0,len(raw),48):
            row=raw[pos:pos+48];rows[struct.unpack_from('<H',row,26)[0] or row[3]]=row
        self.assertEqual((rows[52][0],rows[52][3]),(2,15))
        self.assertEqual(struct.unpack_from('<2H',rows[52],4),(45,0))
        self.assertEqual(struct.unpack_from('<I',rows[52],16)[0],0x250)
        self.assertEqual(struct.unpack_from('<I',rows[45],16)[0],0x218)
        self.assertFalse(any(52 in struct.unpack_from('<2H',r,4) for r in rows.values()))
        for ident in (260,261):self.assertEqual((rows[ident][0],rows[ident][3]),(18,15))
        pmp=list(struct.iter_unpack('<31I',self.dt.get('/device-tree/arm-io/pmp/iop-pmp-nub','soc-device')))
        self.assertEqual([(i,r[0]) for i,r in enumerate(pmp) if r[0]==15],[(14,15)])
        self.assertEqual(self.dt.get('/device-tree/arm-io/apr','clock-gates'),struct.pack('<3I',52,260,261))
        self.assertEqual(self.dt.get('/device-tree/arm-io/apr','iommu-parent'),struct.pack('<I',247))
        self.assertEqual(self.dt.get('/device-tree/arm-io/dart-apr/mapper-apr','AAPL,phandle'),struct.pack('<I',247))
        banks=[m for m in self.dt.device_models if m.node=='/device-tree/arm-io/dart-apr']
        self.assertEqual([(m.base,m.span,m.config) for m in banks],
                         [(0x295020000,0x20000,(1,44,1257,36,8))])
        self.assertFalse(any(m.node=='/device-tree/arm-io/apr' or m.node.startswith('/device-tree/arm-io/apr/')
                             for m in self.dt.device_models))
        binary=ROOT/'build/test-pmgr-prores';self.assertTrue(binary.exists())
        output=subprocess.run([str(binary),'--topology'],check=True,capture_output=True,text=True).stdout
        self.assertEqual(tuple(map(int,output.split())),(0x250,0x218,14))

    def test_encoder_systems_and_shared_pmc_cluster(self):
        raw=self.dt.get(self.spec.node,'devices');rows={}
        for pos in range(0,len(raw),48):
            row=raw[pos:pos+48];rows[struct.unpack_from('<H',row,26)[0] or row[3]]=row
        pmp=list(struct.iter_unpack('<31I',self.dt.get('/device-tree/arm-io/pmp/iop-pmp-nub','soc-device')))
        for unit in range(2):
            row=rows[50+unit]
            self.assertEqual((row[0],row[3]),(2,10+unit))
            self.assertEqual(struct.unpack_from('<2H',row,4),(45,322))
            self.assertEqual(struct.unpack_from('<I',row,16)[0],0x240+8*unit)
            self.assertEqual({i for i,r in rows.items() if 50+unit in struct.unpack_from('<2H',r,4)},
                             {119+5*unit,306+unit})
            self.assertEqual([(i,r[0]) for i,r in enumerate(pmp) if r[0]==10+unit],[(15+unit,10+unit)])
            name='ave'+('1' if unit else '')
            banks=[m for m in self.dt.device_models if m.node=='/device-tree/arm-io/dart-'+name]
            self.assertEqual([(m.base,m.span,m.config) for m in banks],
                [(0x285080000+unit*0x4000000+bank*0x20000,0xc000,(16,44,955+unit*12,36,0))
                 for bank in range(2)])
            self.assertFalse(any(m.node=='/device-tree/arm-io/'+name for m in self.dt.device_models))
            self.assertIn(b'DAPF',self.dt.get('/device-tree/arm-io/dart-'+name,'instance'))
        self.assertEqual((rows[322][0],rows[322][3],rows[322][25]),(16,0,3))
        self.assertEqual(struct.unpack_from('<2H',rows[322],4),(0,0))
        self.assertEqual({i for i,r in rows.items() if 322 in struct.unpack_from('<2H',r,4)},{50,51})
        agent=self.dt.get(self.spec.node,'cluster-agent')
        self.assertEqual(agent,bytes.fromhex('030000014201000041564500000000000000000000000000'))
        self.assertEqual(self.dt.get(self.spec.node,'soc-cluster-power-gating'),struct.pack('<I',8))
        binary=ROOT/'build/test-pmgr-venc-system';self.assertTrue(binary.exists())
        output=subprocess.run([str(binary),'--topology'],check=True,capture_output=True,text=True).stdout
        self.assertEqual([tuple(map(int,line.split())) for line in output.splitlines()],
                         [(0x240,0x218,322,15),(0x248,0x218,322,16),(0x5c18,0x5c1c,8)])

    def test_scaler_jpeg_systems_and_distinct_dma_banks(self):
        raw=self.dt.get(self.spec.node,'devices');rows={}
        for pos in range(0,len(raw),48):
            row=raw[pos:pos+48];rows[struct.unpack_from('<H',row,26)[0] or row[3]]=row
        pmp=list(struct.iter_unpack('<31I',self.dt.get('/device-tree/arm-io/pmp/iop-pmp-nub','soc-device')))
        for ident,offset,pmp_id,pmp_row,children in ((49,0x238,13,18,{61,294}),
                                                   (48,0x230,14,19,{292,293})):
            row=rows[ident]
            self.assertEqual((row[0],row[3]),(2,pmp_id))
            self.assertEqual(struct.unpack_from('<2H',row,4),(45,0))
            self.assertEqual(struct.unpack_from('<I',row,16)[0],offset)
            self.assertEqual({i for i,r in rows.items() if ident in struct.unpack_from('<2H',r,4)},children)
            self.assertEqual([(i,r[0]) for i,r in enumerate(pmp) if r[0]==pmp_id],[(pmp_row,pmp_id)])
        self.assertEqual(struct.unpack_from('<I',rows[45],16)[0],0x218)
        self.assertEqual((rows[61][0],rows[61][3]),(0,0))
        self.assertEqual(struct.unpack_from('<I',rows[61],16)[0],0x298)
        for ident in (292,293,294):self.assertEqual((rows[ident][0],rows[ident][3]),(16,0))
        for ident,pmp_id in ((252,14),(253,14),(262,13),(263,13)):
            self.assertEqual((rows[ident][0],rows[ident][3]),(18,pmp_id))
        consumers=[('scaler0',(294,61,262,263),(221,222)),
                   ('jpeg0-h17a',(292,252,253),(226,)),('jpeg1-h17a',(293,252,253),(227,)),
                   ('jpeg0-h17p',(292,252,253),(231,)),('jpeg1-h17p',(293,252,253),(233,))]
        for name,gates,mappers in consumers:
            path='/device-tree/arm-io/'+name
            for key in ('clock-gates','power-gates'):
                self.assertEqual(self.dt.get(path,key),struct.pack('<'+'I'*len(gates),*gates))
            self.assertEqual(self.dt.get(path,'iommu-parent'),struct.pack('<'+'I'*len(mappers),*mappers))
            self.assertFalse(any(m.node==path or m.node.startswith(path+'/') for m in self.dt.device_models))
        banks=[m for m in self.dt.device_models if 'dart-jpeg' in m.node or 'dart-scaler' in m.node]
        self.assertEqual([(m.base,m.span,m.config) for m in banks],
                         [(0x28d020000,0xc000,(2,44,1041,36,3<<13)),
                          (0x28d080000,0xc000,(1,44,1044,36,1<<15)),
                          (0x291260000,0x20000,(16,44,1087,36,1<<19))])
        binary=ROOT/'build/test-pmgr-image-systems';self.assertTrue(binary.exists())
        output=subprocess.run([str(binary),'--topology'],check=True,capture_output=True,text=True).stdout
        self.assertEqual([tuple(map(int,line.split())) for line in output.splitlines()],
                         [(0x238,0x218,61,18),(0x230,0x218,0,19)])

    def test_gfx_physical_power_and_external_uat_ownership(self):
        # The backing power contract is derived before the software-display
        # publication policy omits the absent Apple GPU nub.
        source=xb.build_devicetree(include_deferred=True)
        self.assertNotIn('/device-tree/arm-io/sgx',self.dt.nodes)
        raw=self.dt.get(self.spec.node,'devices');rows={}
        for pos in range(0,len(raw),48):
            row=raw[pos:pos+48];rows[struct.unpack_from('<H',row,26)[0] or row[3]]=row
        self.assertEqual((rows[40][0],rows[40][3]),(130,5))
        self.assertEqual(struct.unpack_from('<2H',rows[40],4),(29,31))
        self.assertEqual(struct.unpack_from('<I',rows[40],16)[0],0x1f0)
        for ident,offset,name in ((29,0x198,b'AFIMCCNI0'),(31,0x1a8,b'PIOGW')):
            self.assertEqual(rows[ident][32:].split(b'\0')[0],name)
            self.assertEqual(struct.unpack_from('<I',rows[ident],16)[0],offset)
        self.assertEqual({i for i,r in rows.items() if 40 in struct.unpack_from('<2H',r,4)},
                         {235,237,321})
        for ident in (235,236,237,321):self.assertEqual((rows[ident][0],rows[ident][3]),(16,0))
        self.assertEqual(struct.unpack_from('<2H',rows[236],4),(0,0))
        pmp=list(struct.iter_unpack('<31I',self.dt.get('/device-tree/arm-io/pmp/iop-pmp-nub','soc-device')))
        self.assertEqual([(i,r[0]) for i,r in enumerate(pmp) if r[0]==5],[(9,5)])
        for node,gates in (('sgx',(235,236)),('gfx-asc',(237,)),('gfx1-asc',(321,))):
            path='/device-tree/arm-io/'+node
            self.assertEqual(source.get(path,'clock-gates'),struct.pack('<'+'I'*len(gates),*gates))
            for base,span in xb.device_windows(source,node,'/device-tree/arm-io'):
                self.assertGreaterEqual(base,0x480000000)
                self.assertLessEqual(base+span,0x484000000)
            if node!='sgx':self.assertEqual(self.dt.get(path,'iommu-parent'),struct.pack('<I',275))
        self.assertEqual(xb.device_windows(source,'sgx','/device-tree/arm-io')[0],(0x480000000,0x4000000))
        mapper='/device-tree/arm-io/mapper-gfx-asc'
        self.assertEqual(self.dt.get(mapper,'AAPL,phandle'),struct.pack('<I',275))
        self.assertEqual(self.dt.get(mapper,'compatible'),b'iommu-mapper,gfx\0')
        within=[m for m in self.dt.device_models if m.base<0x484000000 and m.base+m.span>0x480000000]
        self.assertEqual([(m.kind,m.base,m.span,m.config) for m in within],
                         [(29,0x481000000,0x1000,(0,0,0,0,0))])
        binary=ROOT/'build/test-pmgr-gfx';self.assertTrue(binary.exists())
        output=subprocess.run([str(binary),'--topology'],check=True,capture_output=True,text=True).stdout
        self.assertEqual(tuple(map(int,output.split())),(0x1f0,0x198,0x1a8,9))

    def test_independent_misc_leaves_have_no_pmp_or_execution_consumers(self):
        raw=self.dt.get(self.spec.node,'devices');rows={}
        for pos in range(0,len(raw),48):
            row=raw[pos:pos+48];rows[struct.unpack_from('<H',row,26)[0] or row[3]]=row
        leaves={24,26,30};expected={0x170:0,0x180:0,0x1a0:0}
        for ident,name,off in ((24,b'SOC_RC',0x170),(26,b'PMGR_SOC_OCLA',0x180),(30,b'AP_TMM',0x1a0)):
            row=rows[ident]
            self.assertEqual(row[32:].split(b'\0')[0],name)
            self.assertEqual(row[:16],bytes(16))
            self.assertEqual(struct.unpack_from('<I',row,16)[0],off)
            self.assertEqual(struct.unpack_from('<2H',row,4),(0,0))
        self.assertFalse(any(set(struct.unpack_from('<2H',r,4))&leaves for r in rows.values()))
        consumers=[]
        for path,props in self.dt.nodes.items():
            for key in ('clock-gates','power-gates'):
                if key in props and leaves&{v[0] for v in struct.iter_unpack('<I',self.dt.get(path,key))}:
                    consumers.append((path,key))
        self.assertEqual(consumers,[])
        # The implemented sampler-shaped interfaces remain the two AON
        # configuration banks; they do not implement these leaf engines.
        self.assertEqual([(m.base,m.config[0]) for m in self.dt.device_models if m.kind==22],
                         [(0x30827b000,6),(0x3082b4000,7)])
        binary=ROOT/'build/test-pmgr-misc';self.assertTrue(binary.exists())
        output=subprocess.run([str(binary),'--topology'],check=True,capture_output=True,text=True).stdout
        self.assertEqual(dict(tuple(map(int,line.split())) for line in output.splitlines()),expected)

    def test_sep_aon_dart_and_virtual_vote_ownership(self):
        raw=self.dt.get(self.spec.node,'devices');rows={}
        for pos in range(0,len(raw),48):
            row=raw[pos:pos+48];rows[struct.unpack_from('<H',row,26)[0] or row[3]]=row
        self.assertEqual(rows[9][:16],bytes(16))
        self.assertEqual(rows[9][32:].split(b'\0')[0],b'SEP_AON')
        self.assertEqual(struct.unpack_from('<I',rows[9],16)[0],0x60)
        self.assertFalse(any(9 in struct.unpack_from('<2H',r,4) for r in rows.values()))
        self.assertEqual((rows[105][0],rows[105][3]),(9,0))
        self.assertEqual(struct.unpack_from('<2H',rows[105],4),(45,0))
        self.assertEqual(struct.unpack_from('<I',rows[105],16)[0],0xc00)
        self.assertEqual((rows[296][0],rows[296][3]),(18,28))
        self.assertEqual(struct.unpack_from('<2H',rows[296],4),(0,0))
        pmp=list(struct.iter_unpack('<31I',self.dt.get('/device-tree/arm-io/pmp/iop-pmp-nub','soc-device')))
        self.assertEqual([(i,r[0]) for i,r in enumerate(pmp) if r[0]==28],[(27,28)])
        self.assertFalse(0xffb80&(1<<27))
        for path,props in self.dt.nodes.items():
            for key in ('clock-gates','power-gates'):
                if key in props:
                    self.assertNotIn(9,[v[0] for v in struct.iter_unpack('<I',self.dt.get(path,key))])
        for key in ('clock-gates','power-gates'):
            self.assertEqual(self.dt.get('/device-tree/arm-io/sep',key),b'')
        self.assertEqual(self.dt.get('/device-tree/arm-io/sep','iommu-parent'),struct.pack('<2I',123,124))
        for name,phandle,sid in [('mapper-sep',123,0),('mapper-sep-mpm',124,1),('mapper-sep-exclave',125,2)]:
            node='/device-tree/arm-io/dart-sep/'+name
            self.assertEqual(self.dt.get(node,'AAPL,phandle'),struct.pack('<I',phandle))
            self.assertEqual(self.dt.get(node,'reg'),struct.pack('<I',sid))
        banks=[m for m in self.dt.device_models if m.node=='/device-tree/arm-io/dart-sep']
        self.assertEqual([(m.kind,m.base,m.span,m.config) for m in banks],
                         [(17,0x280b80000,0x20000,(3,556,353,36,1<<20))])
        windows=xb.device_windows(self.dt,'sep','/device-tree/arm-io')
        self.assertEqual(windows,[(0x282600000,0x88000),(0x282050000,0x60000)])
        for i,(base,span) in enumerate(windows):
            overlapping=[m.words() for m in self.dt.device_models if m.base<base+span and base<m.base+m.span]
            self.assertEqual(overlapping,[(45,0x282600000,0x9000,8,0,0,0,0)] if i==0 else [])
        self.assertEqual([m.kind for m in self.dt.device_models
                          if m.node=='/device-tree/arm-io/sep' or m.node.startswith('/device-tree/arm-io/sep/')],[45])
        binary=ROOT/'build/test-pmgr-sep';self.assertTrue(binary.exists())
        output=subprocess.run([str(binary),'--topology'],check=True,capture_output=True,text=True).stdout
        self.assertEqual(output.strip(),'96 0')

    def test_cpu_boot_requests_are_distinct_from_actual_power(self):
        from devicemodel import pmgr_cpu_boot_policy
        self.assertEqual(pmgr_cpu_boot_policy(self.dt),1)
        expected={0:(0,15),8:(0,0),0x10:(0,0),0x18:(0,0),0x30:(0,0),0x38:(0,0),0x50:(0,15),0x58:(0,15)}
        binary=ROOT/'build/test-pmgr-cpu-boot';self.assertTrue(binary.exists())
        output=subprocess.run([str(binary),'--topology'],check=True,capture_output=True,text=True).stdout
        self.assertEqual({r[0]:tuple(r[1:]) for r in (list(map(int,l.split())) for l in output.splitlines())},expected)
        for cpu in range(6):
            node=f'/device-tree/cpus/cpu{cpu}'
            for key in ('reg','cpu-id','cluster-id','cluster-type','state'):
                prop=self.dt.nodes[node][key];original=prop.value
                for mode in ('missing','changed','unresolved'):
                    if mode=='missing':self.dt.nodes[node].pop(key)
                    elif mode=='changed':prop.value=bytes([original[0]^1])+original[1:]
                    else:prop.placeholder=True
                    before=self.dt.serialize()
                    with self.assertRaises(ValueError):pmgr_power_models(self.dt,self.spec,self.windows)
                    self.assertEqual(self.dt.serialize(),before)
                    prop.value=original;prop.placeholder=False;self.dt.nodes[node][key]=prop
        self.dt.nodes['/device-tree/cpus/cpu6']={}
        with self.assertRaises(ValueError):pmgr_cpu_boot_policy(self.dt)

    def test_cpu_restore_uses_requested_state_for_the_unchanged_path(self):
        # Bind the native caller analysis to the unmodified pinned binary.
        # _setPS compares bits 0..3, not actual bits 4..7, then checks control
        # and automatic policy before its no-write path to 9793a6c.
        import importlib.util
        spec=importlib.util.spec_from_file_location('cpu_boot_kc',ROOT/'tools/kc-load.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        image=module.Image((ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes())
        def words(va,count):
            _,base,_,off,_=next(s for s in image.segments if s[1]<=va and va+count*4<=s[1]+s[4])
            return struct.unpack_from('<'+str(count)+'I',image.data,off+va-base)
        self.assertEqual(words(0xfffffe0009793644,6),
            (0x12000c1c,0x6b19039f,0x12165008,0x12023108,0x7a400900,0x540008a0))
        self.assertEqual(words(0xfffffe000979376c,5),
            (0x12040368,0x4a4872e8,0x3707f748,0x39442288,0x36081788))
        self.assertEqual(words(0xfffffe0009793864,1),(0x531c6f24,))
        self.assertEqual(words(0xfffffe000979389c,1),(0x52801e03,))

    def test_ave_tvm_and_cluster_resources(self):
        models=pmgr_power_models(self.dt,self.spec,self.windows)
        self.assertEqual(models[11].words(),(26,0x300780000,0x1000,1,0,0,0,0))
        self.assertEqual(models[27].words(),(33,0x300760000,0x1000,0,0,0,0,0))
        rows=self.dt.get(self.spec.node,'soc-clusters')
        self.assertEqual(rows[56:84],bytes.fromhex('02020503640000000000000b41564500000000000000000000000000'))
        for index in (11,27):
            for bad in (None,replace(models[index],base=models[index].base+0x1000)):
                changed=list(models)
                if bad is None:changed.pop(index)
                else:changed[index]=bad
                with self.assertRaises(ValueError):device_model_words(changed)
        for node in ('ave','ave1','dart-ave','dart-ave1'):
            props=self.dt.nodes['/device-tree/arm-io/'+node]
            prop=props['reg'];original=prop.value
            for mode in ('missing','changed','unresolved'):
                if mode=='missing':props.pop('reg')
                elif mode=='changed':prop.value=bytes([original[0]^1])+original[1:]
                else:prop.placeholder=True
                with self.assertRaisesRegex(ValueError,'AVE execution/APF'):
                    pmgr_power_models(self.dt,self.spec,self.windows)
                prop.value=original;prop.placeholder=False;props['reg']=prop

    def test_ave_tvm_pinned_rmw_and_busy_contract(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('ave_kc',ROOT/'tools/kc-load.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        image=module.Image((ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes())
        def word(va):
            _,base,_,off,_=next(s for s in image.segments if s[1]<=va< s[1]+s[4])
            return struct.unpack_from('<I',image.data,off+va-base)[0]
        # enableTVM(domain 11): bit-zero RMW at 400 and busy bit-one at 7e0.
        for va,expected in ((0x9beac48,0x52808001),(0x9beac54,0x121f7808),
                (0x9beac58,0x2a140102),(0x9beac60,0x52808001),
                (0x9beac78,0x5280fc01),(0x9beac84,0x370fff80),
                (0x97a9234,0x0b190919),(0x97a9270,0x121c6c08),
                (0x97a92f0,0x52800203),(0x97a92f4,0x52800004)):
            self.assertEqual(word(0xfffffe0000000000+va),expected)

    def test_placement_and_serialization(self):
        models=pmgr_power_models(self.dt,self.spec,self.windows)
        self.assertEqual([(m.base,m.span,m.config) for m in models],
            [(0x300700000,0x11000,(0,1,0,0,0)),(0x308280000,0x9000,(1,0,0,0,0)),
             (0x3082c8000,0x4000,(0,0,0,0,0)),
             (0x210e78000,0x1000,(0,0,0,0,0)),(0x211e78000,0x1000,(1,0,0,0,0)),
             (0x210e70000,0x1000,(0,0,0,0,0)),(0x211e70000,0x1000,(1,0,0,0,0)),
             (0x30827b000,0x1000,(6,0,0,0,0)),(0x3082b4000,0x1000,(7,0,0,0,0)),
             (0x308004000,0x1000,(0,0,0,0,0)),
             (0x3003d8000,0x1000,(0,0,0,0,0)),
             (0x300780000,0x1000,(1,0,0,0,0)),
             (0x300724000,0x1000,(0,0,0,0,0)),
             (0x30020a000,0x3000,(0,0,0,0,0))]+
             [(base,0x1000,(0,0,0,0,0)) for _,base,_ in AXI2AF_BANKS_V1]+
             [(0x3028ac000,0x1000,(0,0,0,0,0)),
              (0x302860000,0x1000,(0,0,0,0,0)),
              (0x3028a4000,0x6000,(0,0,0,0,0)),
              (0x300760000,0x1000,(0,0,0,0,0))]+
             [(base,span,(group,0,0,0,0)) for group,base,span in (
                 (0,0x30006d000,0x2000),(1,0x300720000,0x3000),
                 (2,0x300778000,0x1000),(3,0x30077c000,0x1000),
                 (4,0x3007a0000,0x1000),(5,0x302900000,0x1000))]+
             [(0x210e20000+i*0x1000000,0x2000,(i,0,0,0,0)) for i in range(2)]+
             [(base,0x1000,(0,0,0,0,0)) for base in (
                 0x210059000,0x210159000,0x210259000,0x210359000,
                 0x211059000,0x211159000,0x210e48000,0x211e48000)]+
             [(0x210e44000+i*0x1000000,0x1000,(i,0,0,0,0)) for i in range(2)]+
             [(0x300740000,0x1000,(0,0,0,0,0))])
        self.assertEqual(models[2].kind,PMGR_AON_FUSES_V1)
        start=self.dt.device_models.index(models[0])
        self.assertEqual(self.dt.device_models[start:start+len(models)],models)
        self.assertEqual(device_model_words(self.dt.device_models)[0],120)

    def test_pmc_dvmr_configuration_binding(self):
        model=pmgr_power_models(self.dt,self.spec,self.windows)[26]
        self.assertEqual((model.kind,model.base,model.span),(32,0x3028a4000,0x6000))
        for bad in (replace(model,span=0x1000),
                    *(replace(model,config=tuple(int(i==j) for i in range(5))) for j in range(5))):
            with self.assertRaises(ValueError):device_model_words((bad,))
        prop=self.dt.nodes[self.spec.node]['dvmr-agent'];original=prop.value
        for mode in ('missing','unresolved','changed'):
            if mode=='missing':self.dt.nodes[self.spec.node].pop('dvmr-agent')
            elif mode=='unresolved':prop.placeholder=True
            else:prop.value=bytes([original[0]^1])+original[1:]
            before=self.dt.serialize()
            with self.assertRaises(ValueError):pmgr_power_models(self.dt,self.spec,self.windows)
            self.assertEqual(self.dt.serialize(),before)
            prop.value=original;prop.placeholder=False;self.dt.nodes[self.spec.node]['dvmr-agent']=prop
        rows=[original[i:i+24] for i in range(0,len(original),24)]
        self.assertEqual([(r[1],r[2],struct.unpack_from('<I',r,4)[0]) for r in rows],
                         [(0,0,58),(0,1,59)])
        expected=sum(1<<r[2] for r in rows)
        binary=ROOT/'build/test-pmc-dvmr'
        if not binary.exists():self.skipTest('build tools/test-pmc-dvmr.c for native comparison')
        output=subprocess.run([str(binary),'--mask'],check=True,capture_output=True,text=True).stdout
        self.assertEqual(int(output),expected)

    def test_rmbs_request_descriptor_is_strict(self):
        model=pmgr_power_models(self.dt,self.spec,self.windows)[25]
        self.assertEqual((model.kind,model.base,model.span),(31,0x302860000,0x1000))
        for bad in (replace(model,span=0x4000),
                    *(replace(model,config=tuple(int(i==j) for i in range(5))) for j in range(5))):
            with self.assertRaises(ValueError):device_model_words((bad,))

    def test_venc_dependencies_and_pmp_boundary(self):
        self.check_media_dependencies(0x8000,10,set(range(119,129)),{50:10,51:11},'venc')

    def test_isp_dependencies_and_pmp_boundary(self):
        self.check_media_dependencies(0x4000,13,set(range(106,119)),{55:7},'isp')

    def check_media_dependencies(self,base,count,identifiers,system_pmp_ids,suffix):
        raw=self.dt.get(self.spec.node,'devices');rows={}
        for pos in range(0,len(raw),48):
            row=raw[pos:pos+48]
            ident=struct.unpack_from('<H',row,26)[0] or row[3]
            rows[ident]=row
        expected={};venc_ids=set()
        for ident,row in rows.items():
            address=struct.unpack_from('<I',row,16)[0]
            if row[0]&16 or not base<=address<base+count*8:continue
            first,second=struct.unpack_from('<2H',row,4)
            self.assertEqual(second,0)
            if first:self.assertFalse(rows[first][0]&16)
            expected[address]=struct.unpack_from('<I',rows[first],16)[0] if first else 0
            venc_ids.add(ident)
        self.assertEqual(venc_ids,identifiers)
        self.assertEqual(set(expected),set(range(base,base+count*8,8)))
        pmp=self.dt.get('/device-tree/arm-io/pmp/iop-pmp-nub','soc-device')
        pmp_ids={row[0] for row in struct.iter_unpack('<31I',pmp)}
        # PMP IDs are the separate byte-3 namespace, not PMGR's u16 IDs.
        covered={ident for ident,row in rows.items()
                 if not row[0]&16 and row[3] and row[3] in pmp_ids}
        self.assertFalse(venc_ids&covered)
        self.assertTrue(set(system_pmp_ids)<=covered)
        self.assertEqual({ident:rows[ident][3] for ident in system_pmp_ids},system_pmp_ids)
        self.assertTrue(all(rows[ident][3]==0 for ident in venc_ids))
        binary=ROOT/f'build/test-pmgr-{suffix}'
        if not binary.exists():self.skipTest(f'build tools/test-pmgr-{suffix}.c for native comparison')
        output=subprocess.run([str(binary),'--topology'],check=True,capture_output=True,text=True).stdout
        self.assertEqual(dict(tuple(map(int,line.split())) for line in output.splitlines()),expected)

    def test_pmc_enable_binding_and_native_masks(self):
        model=pmgr_power_models(self.dt,self.spec,self.windows)[24]
        self.assertEqual((model.kind,model.base,model.span),(30,0x3028ac000,0x1000))
        for bad in (replace(model,span=0x4000),
                    *(replace(model,config=tuple(int(i==j) for i in range(5))) for j in range(5))):
            with self.assertRaises(ValueError):device_model_words((bad,))
        for pair in ((0x302001000,0x1000000),(0x302000000,0x1000)):
            windows=list(self.windows);windows[43]=pair
            with self.assertRaisesRegex(ValueError,'PMC'):
                pmgr_power_models(self.dt,self.spec,tuple(windows))
        for name in ('pmc','pmc-pmgr','pmc-ltr-ka','voter-rail-data','voter-agent',
                     'boost-agent','bwr-agent'):
            prop=self.dt.nodes[self.spec.node][name];original=prop.value
            for mode in ('missing','unresolved','changed'):
                if mode=='missing':self.dt.nodes[self.spec.node].pop(name)
                elif mode=='unresolved':prop.placeholder=True
                else:prop.value=bytes([original[0]^1])+original[1:]
                before=self.dt.serialize()
                with self.assertRaises(ValueError):pmgr_power_models(self.dt,self.spec,self.windows)
                self.assertEqual(self.dt.serialize(),before)
                prop.value=original;prop.placeholder=False;self.dt.nodes[self.spec.node][name]=prop
        rails=self.dt.get(self.spec.node,'voter-rail-data')
        voters=self.dt.get(self.spec.node,'voter-agent');expected={0x24:3}
        for off in range(0,len(rails),24):
            index,domain=struct.unpack_from('<HH',rails,off);mask=0
            for row in range(0,len(voters),24):
                kind,domains,bit=struct.unpack_from('<3B',voters,row)
                self.assertIn(kind,(1,2));self.assertLess(bit,32)
                if domains&domain:mask|=1<<bit
            expected[index*4]=mask
        for name,offset in (('boost-agent',0x28),('bwr-agent',0x20)):
            agents=self.dt.get(self.spec.node,name);mask=0
            for pos in range(0,len(agents),24):
                kind,_,bit=struct.unpack_from('<3B',agents,pos)
                self.assertLess(bit,32)
                if name=='boost-agent' or kind:mask|=1<<bit
            expected[offset]=mask
        self.assertEqual(expected,{0:15,4:15,8:15,12:15,0x24:3,0x28:63,0x20:7})
        binary=Path(os.environ.get('SNAP_PMC_ENABLE_TEST',ROOT/'build/test-pmc-enable'))
        if not binary.exists():self.skipTest('build tools/test-pmc-enable.c for native comparison')
        output=subprocess.run([str(binary),'--masks'],check=True,capture_output=True,text=True).stdout
        native=dict(tuple(map(int,line.split())) for line in output.splitlines())
        self.assertEqual(native,expected)

    def test_axi2af_domains_match_stock_table_and_control_words(self):
        models=pmgr_power_models(self.dt,self.spec,self.windows)[14:24]
        self.assertEqual(len(models),10)
        for model in models:
            self.assertEqual(model.kind,29)
            for bad in (replace(model,span=0x4000),
                        *(replace(model,config=tuple(int(i==j) for i in range(5))) for j in range(5))):
                with self.assertRaises(ValueError):device_model_words((bad,))
        prop=self.dt.nodes[self.spec.node]['axi2af-hack'];original=prop.value
        for mode in ('missing','unresolved','changed','partial'):
            if mode=='missing':self.dt.nodes[self.spec.node].pop('axi2af-hack')
            elif mode=='unresolved':prop.placeholder=True
            else:prop.value=struct.pack('<I',0 if mode=='changed' else 0x3fe)
            before=self.dt.serialize()
            with self.assertRaisesRegex(ValueError,'AXI2AF'):
                pmgr_power_models(self.dt,self.spec,self.windows)
            self.assertEqual(self.dt.serialize(),before)
            prop.value=original;prop.placeholder=False;self.dt.nodes[self.spec.node]['axi2af-hack']=prop
        image=(ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes()
        command=32;target=0xfffffe000c925c40;table=None
        for _ in range(struct.unpack_from('<I',image,16)[0]):
            kind,size=struct.unpack_from('<II',image,command)
            if kind==0x19:
                va,span,offset,length=struct.unpack_from('<4Q',image,command+24)
                if va<=target and target+400<=va+length:
                    table=image[offset+target-va:offset+target-va+400]
            command+=size
        self.assertIsNotNone(table)
        stock=[]
        for i in range(10):
            reg,ps,base,a,b,mode,pad=struct.unpack_from('<IIQQQII',table,40*i)
            self.assertEqual((reg,a,b,pad),(0,0,0,0))
            stock.append((ps,base,mode))
        self.assertEqual(tuple(stock),AXI2AF_BANKS_V1)
        binary=Path(os.environ.get('SNAP_PMGR_AXI2AF_TEST',ROOT/'build/test-pmgr-axi2af'))
        if not binary.exists():self.skipTest('build tools/test-pmgr-axi2af.c for native comparison')
        native=tuple(map(int,subprocess.run([str(binary),'--registers'],check=True,
            capture_output=True,text=True).stdout.split()))
        self.assertEqual(native,(0x104,0x108))

    def test_cpu_cluster_and_gate_aliases_are_bound(self):
        models=pmgr_power_models(self.dt,self.spec,self.windows)[11:13]
        self.assertEqual([(m.kind,m.base) for m in models],
                         [(26,0x300780000),(27,0x300724000)])
        for model in models:
            for bad in (replace(model,span=0x4000),
                        *(replace(model,config=tuple(int(i==j) for i in range(5))) for j in range(5))):
                with self.assertRaises(ValueError):device_model_words((bad,))
        for index in (22,25,28,37):
            for delta,size in ((0x1000,0x4000),(0,0x1000)):
                windows=list(self.windows)
                windows[index]=(windows[index][0]+delta,size)
                before=self.dt.serialize()
                with self.assertRaisesRegex(ValueError,'cluster/gate'):
                    pmgr_power_models(self.dt,self.spec,tuple(windows))
                self.assertEqual(self.dt.serialize(),before)
        # Even changing both aliases together must not move the audited bank.
        windows=list(self.windows);windows[28]=windows[37]=(0x300784000,0x4000)
        with self.assertRaises(ValueError):pmgr_power_models(self.dt,self.spec,tuple(windows))

    def test_dpe_geometry_and_native_words_match_stock_table(self):
        model=pmgr_power_models(self.dt,self.spec,self.windows)[13]
        self.assertEqual((model.kind,model.base,model.span),(28,0x30020a000,0x3000))
        for bad in (replace(model,span=0x1000),replace(model,span=0x8000),
                    *(replace(model,config=tuple(int(i==j) for i in range(5))) for j in range(5))):
            with self.assertRaises(ValueError):device_model_words((bad,))
        for base,span in ((0x30020a000,0x8000),(0x300208000,0x3000)):
            windows=list(self.windows);windows[32]=(base,span)
            before=self.dt.serialize()
            with self.assertRaisesRegex(ValueError,'SOC DPE'):
                pmgr_power_models(self.dt,self.spec,tuple(windows))
            self.assertEqual(self.dt.serialize(),before)
        binary=Path(os.environ.get('SNAP_PMGR_DPE_TEST',ROOT/'build/test-pmgr-dpe'))
        if not binary.exists():self.skipTest('build tools/test-pmgr-dpe.c for native comparison')
        native=set(map(int,subprocess.run([str(binary),'--topology'],check=True,
            capture_output=True,text=True).stdout.split()))
        image=(ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes()
        command=32;target=0xfffffe00076f3fb0;bases=None
        for _ in range(struct.unpack_from('<I',image,16)[0]):
            kind,size=struct.unpack_from('<II',image,command)
            if kind==0x19:
                va,span,offset,length=struct.unpack_from('<4Q',image,command+24)
                if va<=target and target+40<=va+length:
                    bases=struct.unpack_from('<10I',image,offset+target-va)
            command+=size
        self.assertIsNotNone(bases)
        expected={base+delta for i,base in enumerate(bases)
                  for delta in ((0x200,0x300) if i==7 else (0x200,0,0x300))}
        self.assertEqual(len(expected),29)
        self.assertEqual(native,expected)
        self.assertNotIn(0x4000,native)

    def test_native_whitelist_matches_every_physical_device(self):
        binary=Path(os.environ.get('SNAP_PMGR_TEST',ROOT/'build/test-pmgr'))
        if not binary.exists():self.skipTest('build tools/test-pmgr.c for native topology comparison')
        output=subprocess.run([str(binary),'--topology'],check=True,capture_output=True,text=True).stdout
        native={tuple(map(int,line.split())) for line in output.splitlines()}
        raw=self.dt.get(self.spec.node,'devices');expected=set()
        for off in range(0,len(raw),48):
            row=raw[off:off+48]
            if row[0]&16:continue
            value=struct.unpack_from('<I',row,16)[0]
            expected.add((value>>24,value&0xffffff))
        self.assertEqual(len(expected),138)
        self.assertEqual(native,expected)

    def test_mutated_or_unresolved_topology_refused_without_mutation(self):
        for name in ('devices','reg','ps-groups','compatible','perf-groups','perf-counters',
                      'ap-wake-sources','ap-wake-source-flags','voter-rail-data','voter-agent',
                      'boost-agent','bwr-agent','cluster-agent','soc-clusters','soc-cluster-power-gating'):
            prop=self.dt.nodes[self.spec.node][name]
            original=prop.value
            self.dt.put(self.spec.node,name,bytes([original[0]^1])+original[1:])
            before=self.dt.serialize()
            with self.assertRaises(ValueError):pmgr_power_models(self.dt,self.spec,self.windows)
            self.assertEqual(self.dt.serialize(),before)
            self.dt.put(self.spec.node,name,original)
            self.dt.nodes[self.spec.node][name].placeholder=True
            with self.assertRaises(ValueError):pmgr_power_models(self.dt,self.spec,self.windows)
            self.dt.nodes[self.spec.node][name].placeholder=False

    def test_descriptors_and_windows_refused(self):
        model=pmgr_power_models(self.dt,self.spec,self.windows)[0]
        for bad in (replace(model,span=0x12000),replace(model,config=(2,0,0,0,0)),
                    replace(model,config=(0,2,0,0,0)),replace(model,config=(1,1,0,0,0)),
                    *(replace(model,config=tuple(int(j==i) for j in range(5))) for i in range(2,5))):
            with self.assertRaises(ValueError):device_model_words((bad,))
        with self.assertRaises(ValueError):pmgr_power_models(self.dt,self.spec,self.windows[:-1])

    def test_fuse_descriptor_and_placement_are_strict(self):
        model=pmgr_power_models(self.dt,self.spec,self.windows)[2]
        for bad in (replace(model,span=0x8000),replace(model,span=0x1000),
                    *(replace(model,config=tuple(int(j==i) for j in range(5))) for i in range(5))):
            with self.assertRaises(ValueError):device_model_words((bad,))
        for pair in ((0x3082c9000,0x4000),(0x3082c8000,0x8000)):
            windows=list(self.windows);windows[30]=pair
            before=self.dt.serialize()
            with self.assertRaises(ValueError):pmgr_power_models(self.dt,self.spec,tuple(windows))
            self.assertEqual(self.dt.serialize(),before)

    def test_dvmr_cpu_states_and_windows_are_bound(self):
        for domain in (1,5):
            name=f'voltage-states{domain}';old=self.dt.get(self.spec.node,name)
            for value in (b'',old*2,struct.pack('<II',65536,1)):
                self.dt.put(self.spec.node,name,value);before=self.dt.serialize()
                with self.assertRaises(ValueError):pmgr_power_models(self.dt,self.spec,self.windows)
                self.assertEqual(self.dt.serialize(),before)
            self.dt.put(self.spec.node,name,old)
            self.dt.nodes[self.spec.node][name].placeholder=True
            with self.assertRaises(ValueError):pmgr_power_models(self.dt,self.spec,self.windows)
            self.dt.nodes[self.spec.node][name].placeholder=False
        for index in (8,9,17,18):
            windows=list(self.windows);b,n=windows[index];windows[index]=(b+0x1000,n)
            with self.assertRaises(ValueError):pmgr_power_models(self.dt,self.spec,tuple(windows))
        model=pmgr_power_models(self.dt,self.spec,self.windows)[3]
        for bad in (replace(model,span=0x4000),replace(model,config=(2,0,0,0,0)),
                    *(replace(model,config=tuple(int(j==i) for j in range(5))) for i in range(1,5))):
            with self.assertRaises(ValueError):device_model_words((bad,))

    def test_fane_indices_require_backed_active_ane_state(self):
        name='voltage-states8';old=self.dt.get(self.spec.node,name)
        for value in (b'',old*2,struct.pack('<II',0,0),struct.pack('<II',1,0),
                      struct.pack('<II',0,1),struct.pack('<II',1000,0),
                      struct.pack('<II',1_000_000_000,0),struct.pack('<II',1000,1000),
                      struct.pack('<II',1_000_000_000,1000)):
            self.dt.put(self.spec.node,name,value);before=self.dt.serialize()
            with self.assertRaisesRegex(ValueError,'FANE'):pmgr_power_models(self.dt,self.spec,self.windows)
            self.assertEqual(self.dt.serialize(),before)
        self.dt.put(self.spec.node,name,old)
        self.dt.nodes[self.spec.node][name].placeholder=True
        with self.assertRaisesRegex(ValueError,'FANE'):pmgr_power_models(self.dt,self.spec,self.windows)
        del self.dt.nodes[self.spec.node][name]
        with self.assertRaisesRegex(ValueError,'FANE'):pmgr_power_models(self.dt,self.spec,self.windows)

    def test_weight_table_descriptors_are_strict(self):
        model=pmgr_power_models(self.dt,self.spec,self.windows)[6]
        for bad in (replace(model,span=0x4000),replace(model,config=(2,0,0,0,0)),
                    *(replace(model,config=(1,)+tuple(int(j==i) for j in range(1,5))) for i in range(1,5))):
            with self.assertRaises(ValueError):device_model_words((bad,))

    def test_aon_counter_configuration_is_strict(self):
        for model in pmgr_power_models(self.dt,self.spec,self.windows)[7:9]:
            for bad in (replace(model,span=0x4000),
                        *(replace(model,config=(g,0,0,0,0)) for g in (0,5,8,1<<32)),
                        *(replace(model,config=(model.config[0],)+tuple(int(j==i) for j in range(1,5))) for i in range(1,5))):
                with self.assertRaises(ValueError):device_model_words((bad,))
        for i in (1,3):
            for b,n in ((self.windows[i][0]+0x1000,self.windows[i][1]),
                        (self.windows[i][0],self.windows[i][1]+0x1000)):
                windows=list(self.windows);windows[i]=(b,n)
                with self.assertRaises(ValueError):pmgr_power_models(self.dt,self.spec,tuple(windows))
        for name in ('perf-groups','perf-counters'):
            prop=self.dt.nodes[self.spec.node].pop(name)
            with self.assertRaises(ValueError):pmgr_power_models(self.dt,self.spec,self.windows)
            self.dt.nodes[self.spec.node][name]=prop

    def test_native_counter_controls_match_primary_and_secondary_dt_records(self):
        binary=Path(os.environ.get('SNAP_PMGR_COUNTER_TEST',ROOT/'build/test-pmgr-counter'))
        if not binary.exists():self.skipTest('build tools/test-pmgr-counter.c for native comparison')
        output=subprocess.run([str(binary),'--topology'],check=True,capture_output=True,text=True).stdout
        native={tuple(map(int,line.split())) for line in output.splitlines()}
        groups=list(struct.iter_unpack('<9I',self.dt.get(self.spec.node,'perf-groups')))
        expected={(g,groups[g][1]&0xfff) for g in (6,7)}
        raw=self.dt.get(self.spec.node,'perf-counters')
        for off in range(0,len(raw),64):
            row=raw[off:off+64];kind,flags,group=row[0],row[1],row[4]
            if not groups[group][2]&2 or kind==3:continue
            expected.add((group,(groups[group][1]&0xfff)+struct.unpack_from('<I',row,8)[0]))
            if kind==1 and flags&2:
                second=row[5]
                expected.add((second,(groups[second][1]&0xfff)+struct.unpack_from('<I',row,12)[0]))
        self.assertEqual(len(expected),77)
        self.assertEqual(native,expected)

    def test_ptd_irq_descriptor_and_dependencies_are_strict(self):
        model=pmgr_power_models(self.dt,self.spec,self.windows)[10]
        self.assertEqual((model.kind,model.base,model.span),(24,0x3003d8000,0x1000))
        for bad in (replace(model,span=0x4000),
                    *(replace(model,config=tuple(int(i==j) for i in range(5))) for j in range(5))):
            with self.assertRaises(ValueError):device_model_words((bad,))
        for pair in ((0x3003d0000,0x30000),(0x3003c0000,0x14000)):
            windows=list(self.windows);windows[34]=pair
            with self.assertRaises(ValueError):pmgr_power_models(self.dt,self.spec,tuple(windows))
        for path,name in ((self.spec.node,'ptd-ranges'),
                         ('/device-tree/arm-io/pmp/iop-pmp-nub','ptd-range'),
                         ('/device-tree/arm-io/pmp/iop-pmp-nub','ptd-driver-version')):
            prop=self.dt.nodes[path][name];original=prop.value
            for mode in ('mutated','unresolved','missing'):
                if mode=='mutated':prop.value=bytes([original[0]^1])+original[1:]
                elif mode=='unresolved':prop.placeholder=True
                else:self.dt.nodes[path].pop(name)
                before=self.dt.serialize()
                with self.assertRaises(ValueError):pmgr_power_models(self.dt,self.spec,self.windows)
                self.assertEqual(self.dt.serialize(),before)
                prop.value=original;prop.placeholder=False;self.dt.nodes[path][name]=prop

    def test_wake_mask_descriptor_and_metadata_are_strict(self):
        model=pmgr_power_models(self.dt,self.spec,self.windows)[9]
        for bad in (replace(model,span=0x4000),
                    *(replace(model,config=tuple(int(i==j) for i in range(5))) for j in range(5))):
            with self.assertRaises(ValueError):device_model_words((bad,))
        for pair in ((0x308005000,0x1000),(0x308004000,0x4000)):
            windows=list(self.windows);windows[4]=pair
            with self.assertRaises(ValueError):pmgr_power_models(self.dt,self.spec,tuple(windows))
        for name in ('ap-wake-sources','ap-wake-source-flags'):
            prop=self.dt.nodes[self.spec.node].pop(name)
            before=self.dt.serialize()
            with self.assertRaises(ValueError):pmgr_power_models(self.dt,self.spec,self.windows)
            self.assertEqual(self.dt.serialize(),before)
            self.dt.nodes[self.spec.node][name]=prop

    def test_wake_valid_masks_match_stock_kernel_and_all_declared_sources(self):
        binary=Path(os.environ.get('SNAP_PMGR_WAKE_TEST',ROOT/'build/test-pmgr-wake'))
        if not binary.exists():self.skipTest('build tools/test-pmgr-wake.c for native comparison')
        native=tuple(map(int,subprocess.run([str(binary),'--valid-masks'],check=True,
                        capture_output=True,text=True).stdout.split()))
        image=(ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes()
        command=32;target=0xfffffe00076f3fd8;stock=None
        for _ in range(struct.unpack_from('<I',image,16)[0]):
            kind,size=struct.unpack_from('<II',image,command)
            if kind==0x19:
                va,span,offset,length=struct.unpack_from('<4Q',image,command+24)
                if va<=target and target+32<=va+length:
                    stock=struct.unpack_from('<8I',image,offset+target-va)
            command+=size
        self.assertIsNotNone(stock)
        self.assertEqual(native,stock)
        raw=self.dt.get(self.spec.node,'ap-wake-sources');seen=set()
        for off in range(0,len(raw),36):
            source,=struct.unpack_from('<I',raw,off)
            self.assertNotIn(source,seen);seen.add(source)
            self.assertLess(source,256)
            self.assertTrue(native[source//32]&(1<<(source%32)))
        self.assertEqual(len(seen),20)


if __name__=='__main__':unittest.main()
