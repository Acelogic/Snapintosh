#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from dataclasses import replace
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
from appledt import DeviceTree, Property
from devicemodel import DeviceModel, device_model_words, mcc_models, mcc_ptd_models, aic_models, watchdog_models, dart_models, MODEL_MAX, MODEL_WORDS
from iommu import DARTDevice
from guestprofile import J700_26A428
from devicemodel import gpio_models, aes_key_models, spmi_models, dock_models, dock_fifo_models, mcc_error_models, socni_error_models, platform_error_models, aop_timebase_models

SPEC = J700_26A428.mcc_boot
WINDOWS = ((0x1000, 0x1000), (0x2000, 0x1000), (0x220000000, 0x140000),
           *((0x220400000+i*0x200000, 0x8000) for i in range(4)),
           *((0x24f008000+i*0x1000000, 0x8000) for i in range(3)))


def fixture():
    dt = DeviceTree.__new__(DeviceTree)
    dt.nodes = {SPEC.node: {k: Property(k, v) for k, v in {
        'compatible': b'mcc,t8140\0', 'amcc-count': struct.pack('<I', 1),
        'dcs-count-per-amcc': struct.pack('<I', 4), 'amcc-reg-idx': struct.pack('<I', 2),
        'dcs-reg-idx': struct.pack('<I', 3),
        'socni-reg-idx': struct.pack('<I', 7), 'socni-count': struct.pack('<I', 3),
    }.items()}}
    return dt


def aic_fixture():
    spec = J700_26A428.aic_boot
    dt = DeviceTree.__new__(DeviceTree)
    props = {'rev-offset': 0, 'cap0-offset': 4, 'maxnumirq-offset': 12, 'extint-baseaddress': 0x10000,
             'aicglbcfg-offset': 0x14, 'extintrcfg-stride': 0x4a00,
             'intmaskset-stride': 0x4a00, 'intmaskclear-stride': 0x4a00,
             'hwintmon-stride': 0x4a00, 'cap0_max_interrupt_umask': 0xffff,
             'max_irq_interrupt_umask': 0xffff, '#interrupt-cells': 1, 'AAPL,phandle': 0x45}
    dt.nodes = {spec.node: {k: Property(k, struct.pack('<I',v)) for k,v in props.items()}}
    dt.put(spec.node, 'compatible', b'aic,3\0')
    dt.nodes['/device-tree/arm-io/test'] = {
        'interrupt-parent': Property('interrupt-parent', struct.pack('<I',0x45)),
        'interrupts': Property('interrupts', struct.pack('<II',1,1260))}
    return dt


class DeviceTests(unittest.TestCase):
    def dart_fixture(self):
        node='/device-tree/arm-io/dart-test'
        dt=DeviceTree.__new__(DeviceTree);dt.nodes={node:{}}
        # Record order is the reg order even when logical indices differ.
        records=b''.join(struct.pack('<4sI4sI',kind,index,b'TEST',0)
                         for kind,index in [(b'UMMS',3),(b'TRAD',0),(b'FPAD',2),(b'TRAD',1)])
        dt.put(node,'instance',records);dt.put(node,'interrupts',struct.pack('<I',1120))
        dev=DARTDevice(0,node,b'dart,t8110',tuple((0x385000000+i*0x20000,0x20000) for i in range(4)),19,0x4000)
        return dt,dev

    def test_dart_instance_order_and_strict_properties(self):
        dt,dev=self.dart_fixture()
        models=dart_models(dt,(dev,))
        self.assertEqual([m.base for m in models],[dev.windows[1][0],dev.windows[3][0]])
        self.assertTrue(all(m.config==(19,44,1120,36,0) and m.kind==17 for m in models))
        for prop,values in [('instance',[b'',b'bad',b'BAD!'+dt.get(dev.path,'instance')[4:]]),
                            ('interrupts',[b'',bytes(8),struct.pack('<I',4096)])]:
            old=dt.get(dev.path,prop)
            for value in values:
                dt.put(dev.path,prop,value)
                with self.assertRaises(ValueError):dart_models(dt,(dev,))
            dt.put(dev.path,prop,old)
            dt.nodes[dev.path][prop].placeholder=True
            with self.assertRaises(ValueError):dart_models(dt,(dev,))
            dt.nodes[dev.path][prop].placeholder=False
        for changes in [dict(compatible=b'dart,t8020'),dict(page_size=4096),dict(sid_count=0),dict(sid_count=257),dict(device_id=32)]:
            with self.assertRaises(ValueError):dart_models(dt,(replace(dev,**changes),))

    def test_dart_alias_only_for_audited_jpeg_pair(self):
        dt,dev=self.dart_fixture()
        raw=struct.pack('<4sI4sI',b'TRAD',0,b'JPEG',0)
        a='/device-tree/arm-io/dart-jpeg-h17a';b='/device-tree/arm-io/dart-jpeg0-h17p'
        for node in (a,b):
            dt.nodes[node]={};dt.put(node,'instance',raw);dt.put(node,'interrupts',struct.pack('<I',1041))
        da=replace(dev,path=a,sid_count=2,windows=((0x28d020000,0xc000),))
        db=replace(da,path=b,sid_count=1,device_id=1)
        self.assertEqual(dart_models(dt,(da,db))[0].config,(2,44,1041,36,3))
        self.assertEqual(len(dart_models(dt,(db,da))),1)
        with self.assertRaises(ValueError):dart_models(dt,(da,da))
        dt.put(b,'interrupts',struct.pack('<I',1042))
        with self.assertRaises(ValueError):dart_models(dt,(da,db))

    def test_dart_actual_registry_and_capacity(self):
        import xnuboot as xb
        dt=xb.build_devicetree();models=dart_models(dt,dt.dart_devices)
        self.assertEqual((MODEL_MAX,len(models),len(dt.device_models)),(128,29,120))
        self.assertEqual(len({m.base for m in models}),29)
        self.assertIn((17,0x385060000,0x20000,16,300,1120,36,1<<21),[m.words() for m in models])
        for device in dt.dart_devices:
            raw=dt.get(device.path,'instance')
            pure=all(raw[i:i+4]==b'TRAD' for i in range(0,len(raw),16))
            self.assertEqual(any(m.config[4]&(1<<device.device_id) for m in models),
                             pure or device.path=='/device-tree/arm-io/dart-ane')
        for m in models:
            for i,value in [(0,257),(1,48),(2,4096),(3,48),(4,1<<32)]:
                config=list(m.config);config[i]=value
                with self.assertRaises(ValueError):device_model_words((replace(m,config=tuple(config)),))

    def test_dart_sio_boot_policy_requires_exact_topology(self):
        import xnuboot as xb
        dt=xb.build_devicetree()
        dev=next(d for d in dt.dart_devices if d.path.endswith('/dart-sio'))
        original=dart_models(dt,(dev,))
        self.assertEqual(original[0].config,(16,300,1120,36,1<<21))
        for key in list(dt.nodes[dev.path]):
            if key=='dart-id':continue
            old=dt.get(dev.path,key)
            dt.nodes[dev.path][key].placeholder=True
            with self.assertRaises(ValueError):dart_models(dt,(dev,))
            dt.nodes[dev.path][key].placeholder=False
            dt.put(dev.path,key,old+b'\0')
            with self.assertRaises(ValueError):dart_models(dt,(dev,))
            dt.put(dev.path,key,old)
        for key in ('no-sleep','reset-on-wake','bypass-0','enable-perf-counters'):
            dt.put(dev.path,key,b'')
            with self.assertRaises(ValueError):dart_models(dt,(dev,))
            del dt.nodes[dev.path][key]
        for changes in (dict(sid_count=17),dict(windows=((0x385080000,0x20000),))):
            with self.assertRaises(ValueError):dart_models(dt,(replace(dev,**changes),))
        for index,value in ((0,17),(1,301),(4,0),(4,3)):
            cfg=list(original[0].config);cfg[index]=value
            with self.assertRaises(ValueError):device_model_words((replace(original[0],config=tuple(cfg)),))
        self.assertEqual(dart_models(dt,(dev,)),original)

    def test_dart_sep_boot_policy_requires_exact_topology(self):
        import xnuboot as xb
        dt=xb.build_devicetree()
        dev=next(d for d in dt.dart_devices if d.path.endswith('/dart-sep'))
        original=dart_models(dt,(dev,))
        self.assertEqual(original[0].config,(3,556,353,36,1<<20))
        for key in list(dt.nodes[dev.path]):
            if key=='dart-id':continue
            old=dt.get(dev.path,key)
            dt.nodes[dev.path][key].placeholder=True
            with self.assertRaises(ValueError):dart_models(dt,(dev,))
            dt.nodes[dev.path][key].placeholder=False
            dt.put(dev.path,key,old+b'\0')
            with self.assertRaises(ValueError):dart_models(dt,(dev,))
            dt.put(dev.path,key,old)
        for key in ('no-sleep','reset-on-wake','bypass-0','enable-perf-counters','clock-gates'):
            dt.put(dev.path,key,b'')
            with self.assertRaises(ValueError):dart_models(dt,(dev,))
            del dt.nodes[dev.path][key]
        for changes in (dict(sid_count=4),dict(device_id=21),dict(windows=((0x280ba0000,0x20000),))):
            with self.assertRaises(ValueError):dart_models(dt,(replace(dev,**changes),))
        for index,value in ((0,4),(1,557),(2,354),(4,0),(4,1<<21)):
            cfg=list(original[0].config);cfg[index]=value
            with self.assertRaises(ValueError):device_model_words((replace(original[0],config=tuple(cfg)),))
        self.assertEqual(dart_models(dt,(dev,)),original)

    def test_dart_ane_init_requires_complete_audited_topology(self):
        import xnuboot as xb
        dt=xb.build_devicetree()
        dev=next(d for d in dt.dart_devices if d.path.endswith('/dart-ane'))
        original=dart_models(dt,(dev,))
        self.assertEqual([(m.base,m.span,m.config) for m in original],
            [(0x401800000,0xc000,(16,812,656,36,1)),
             (0x401820000,0x20000,(16,812,656,36,1)),
             (0x401840000,0x20000,(16,812,656,36,1))])
        # Fingerprint covers DAPF and its DRAM slices even though INIT only
        # visits the three DART records. No APF MMIO model is created.
        for key in list(dt.nodes[dev.path]):
            if key=='dart-id':continue
            old=dt.get(dev.path,key)
            dt.nodes[dev.path][key].placeholder=True
            with self.assertRaises(ValueError):dart_models(dt,(dev,))
            dt.nodes[dev.path][key].placeholder=False
            dt.put(dev.path,key,old+b'\0')
            with self.assertRaises(ValueError):dart_models(dt,(dev,))
            dt.put(dev.path,key,old)
        for key in ('no-sleep','reset-on-wake','clock-gates','new-apf-policy'):
            dt.put(dev.path,key,b'')
            with self.assertRaises(ValueError):dart_models(dt,(dev,))
            del dt.nodes[dev.path][key]
        for changes in (dict(sid_count=17),dict(device_id=1),
                        dict(windows=dev.windows[:3]),dict(windows=dev.windows[::-1])):
            with self.assertRaises(ValueError):dart_models(dt,(replace(dev,**changes),))
        for m in original:
            for index,value in ((0,17),(1,813),(2,657),(3,48),(4,0),(4,2),(4,3)):
                cfg=list(m.config);cfg[index]=value
                with self.assertRaises(ValueError):device_model_words((replace(m,config=tuple(cfg)),))
            for changes in (dict(base=m.base+0x10000),
                            dict(span=0x20000 if m.span==0xc000 else 0xc000)):
                with self.assertRaises(ValueError):device_model_words((replace(m,**changes),))
        self.assertEqual(dart_models(dt,(dev,)),original)

    def test_dart_ane_init_tracks_real_guest_placement(self):
        import xnuboot as xb
        node='/device-tree/arm-io/dart-ane';key='allow-dram-apf-slices-0'
        with patch.dict(xb.__dict__,xb.__dict__.copy()):
            xb.place(0x8c0000000,29696<<20,guest_span=8192<<20)
            dt=xb.build_devicetree();dev=next(d for d in dt.dart_devices if d.path==node)
            self.assertIsNone(dt.get(node,key))
            self.assertEqual([m.config for m in dart_models(dt,(dev,))],[(16,812,656,36,1)]*3)
            for value in (b'',struct.pack('<I',0),struct.pack('<4I',0,1,2,3)):
                dt.put(node,key,value)
                with self.assertRaises(ValueError):dart_models(dt,(dev,))
            del dt.nodes[node][key]
            for value in (b'',struct.pack('<Q',0),struct.pack('<Q',1<<36),
                          struct.pack('<Q',0xd9e00000)):
                dt.put('/device-tree/chosen','dram-base',value)
                with self.assertRaises(ValueError):dart_models(dt,(dev,))
            dt.put('/device-tree/chosen','dram-base',struct.pack('<Q',0x8c0000000))
            dt.nodes['/device-tree/chosen']['dram-base'].placeholder=True
            with self.assertRaises(ValueError):dart_models(dt,(dev,))
        dt=xb.build_devicetree();dev=next(d for d in dt.dart_devices if d.path==node)
        self.assertEqual(dt.get(node,key),struct.pack('<4I',0,1,2,3))
        del dt.nodes[node][key]
        with self.assertRaises(ValueError):dart_models(dt,(dev,))

    def test_aop_timebase_contract(self):
        import xnuboot as xb
        dt=xb.build_devicetree();spec=J700_26A428.aop_timebase_boot
        windows=xb.device_windows(dt,'aop','/device-tree/arm-io')
        models=aop_timebase_models(dt,spec,windows,24000000)
        self.assertEqual(models[0].words(),(16,0x3082a8000,0x1000,24000000,0,0,0,0))
        nub=spec.node+'/iop-aop-nub'
        for prop,value in [('aop-fr-timebase',b'\0'*4),
                           ('aop-timesync-reg-index',struct.pack('<I',2)),
                           ('compatible',b'iop-nub,unknown\0')]:
            old=dt.get(nub,prop);dt.put(nub,prop,value)
            with self.assertRaises(ValueError):aop_timebase_models(dt,spec,windows,24000000)
            if old is None:del dt.nodes[nub][prop]
            else:dt.put(nub,prop,old)
        dt.put(nub,'aop-timesync-reg-index',struct.pack('<I',3))
        self.assertEqual(aop_timebase_models(dt,spec,windows,24000000),models)
        for rate in (0,19200000,24000001):
            with self.assertRaises(ValueError):aop_timebase_models(dt,spec,windows,rate)
        bad=list(windows);bad[3]=(windows[3][0],16)
        with self.assertRaises(ValueError):aop_timebase_models(dt,spec,bad,24000000)
        for i in range(5):
            config=list(models[0].config);config[i]+=1
            with self.assertRaises(ValueError):device_model_words([replace(models[0],config=tuple(config))])
        with self.assertRaises(ValueError):device_model_words([replace(models[0],span=0x2000)])

    def test_platform_policy_windows(self):
        import xnuboot as xb
        dt=xb.build_devicetree();node=J700_26A428.mcc_error_node
        windows=xb.device_windows(dt,'error-handler','/device-tree/arm-io')
        models=platform_error_models(dt,node,windows)
        self.assertEqual([m.words() for m in models],
                         [(15,0x25300a000,0x1000,0x104,1,0,0,0),
                          (15,0x254000000,0x20000,0x4084,0,0,0,0)])
        for index in (15,16):
            bad=list(windows);base,size=bad[index];bad[index]=(base,size+4)
            with self.assertRaises(ValueError):platform_error_models(dt,node,bad)
        for config in [(0x104,0,0,0,0),(0x108,1,0,0,0),(0x104,1,1,0,0),
                       (0x104,1,0,1,0),(0x104,1,0,0,1)]:
            with self.assertRaises(ValueError):device_model_words([replace(models[0],config=config)])

    def test_socni_policy_geometry(self):
        import xnuboot as xb
        dt=xb.build_devicetree();node=J700_26A428.mcc_error_node
        windows=xb.device_windows(dt,'error-handler','/device-tree/arm-io')
        models=socni_error_models(dt,node,windows)
        self.assertEqual([m.words() for m in models],
                         [(14,base,0x4000,i,0,0,0,0) for i,base in enumerate(
                          (0x24f000000,0x250000000,0x251000000,0x252000000,0x25f000000,0x26f000000))])
        for i in range(9,15):
            bad=list(windows);pa,size=bad[i];bad[i]=(pa+0x1000,size)
            with self.assertRaises(ValueError):socni_error_models(dt,node,bad)
            bad[i]=(pa,size-0x1000)
            with self.assertRaises(ValueError):socni_error_models(dt,node,bad)
        for config in [(6,0,0,0,0),(0,1,0,0,0),(0,0,1,0,0),(0,0,0,1,0),(0,0,0,0,1)]:
            with self.assertRaises(ValueError):device_model_words([replace(models[0],config=config)])

    def test_uart_tx_pad_binding(self):
        import xnuboot as xb
        dt=xb.build_devicetree(include_deferred=True);spec=replace(J700_26A428.gpio_boot[0],idle_i2c=())
        tx,=spec.idle_tx
        model,=gpio_models(dt,spec,[(0x31a000000,0x100000)])
        self.assertEqual(model.config[4],0x10051)
        original=dt.get(tx.peripheral,'function-tx')
        for value in [original[:-1],struct.pack('<4I',0x4c,0x4750494f,80,2),
                      struct.pack('<4I',0x4c,0x4750494f,81,0x102),
                      struct.pack('<4I',0x4c,0x4750494f,80,0x103)]:
            dt.put(tx.peripheral,'function-tx',value)
            with self.assertRaises(ValueError):gpio_models(dt,spec,[(0x31a000000,0x100000)])
        dt.put(tx.peripheral,'function-tx',original)
        with self.assertRaises(ValueError):
            gpio_models(dt,replace(spec,idle_tx=(tx,tx)),[(0x31a000000,0x100000)])

    def test_dcs_errors_require_platform_aperture(self):
        import xnuboot as xb
        dt=xb.build_devicetree();node=J700_26A428.mcc_error_node
        windows=xb.device_windows(dt,'error-handler','/device-tree/arm-io')
        models=mcc_models(dt,SPEC,xb.device_windows(dt,'mcc','/device-tree/arm-io'))
        expanded=mcc_error_models(dt,node,windows,models)
        self.assertEqual([m.span for m in expanded if m.kind==2],[0x39000]*4)
        for bad in [(), ((windows[0][0]+0x1000,windows[0][1]),),
                    ((windows[0][0],0x140000),)]:
            with self.assertRaises(ValueError):mcc_error_models(dt,node,bad,models)
        dt.put(node,'compatible',b'error-handler,unknown\0')
        with self.assertRaises(ValueError):mcc_error_models(dt,node,windows,models)

    def test_dock_fifo_placement_and_interrupt_binding(self):
        import xnuboot as xb
        dt=xb.build_devicetree();spec=J700_26A428.dock_fifo_boot
        windows=xb.device_windows(dt,'dockchannel-mtp','/device-tree/arm-io')
        model,=dock_fifo_models(dt,spec,windows)
        self.assertEqual(model.words(),(13,0x314b00000,0x35000,0x14000,0x28000,1137,2048,0))
        for key,value in [('compatible',b'dockchannel,unknown\0'),
                          ('channel-number',struct.pack('<I',1)),
                          ('fifo-size',struct.pack('<I',4096)),
                          ('dock-wstat-mask',struct.pack('<I',0x7ff)),
                          ('interrupt-parent',struct.pack('<I',0)),
                          ('interrupts',struct.pack('<II',1137,1138)),
                          ('interrupts',struct.pack('<I',4096))]:
            original=dt.get(spec.node,key);dt.put(spec.node,key,value)
            with self.assertRaises(ValueError):dock_fifo_models(dt,spec,windows)
            dt.put(spec.node,key,original)
        for i in range(6):
            bad=list(windows);pa,size=bad[i];bad[i]=(pa+0x1000,size)
            with self.assertRaises(ValueError):dock_fifo_models(dt,spec,bad)
        for config in [(0x10000,0x28000,1137,2048,0),(0x14000,0x30000,1137,2048,0),
                       (0x14000,0x28000,4096,2048,0),(0x14000,0x28000,1137,2047,0),
                       (0x14000,0x28000,1137,2048,1)]:
            with self.assertRaises(ValueError):device_model_words([replace(model,config=config)])

    def test_gpio_idle_rx_follows_uart_function(self):
        spec=replace(J700_26A428.gpio_boot[0],idle_clkreq=(),idle_tx=(),idle_i2c=())
        dt=fixture();dt.nodes[spec.node]={}
        for k,v in {'compatible':b'gpio,t8101\0','#gpio-pins':struct.pack('<I',216),
                    '#gpio-int-groups':struct.pack('<I',7),'AAPL,phandle':struct.pack('<I',0x4c)}.items():
            dt.put(spec.node,k,v)
        for rx in spec.idle_rx:
            dt.nodes[rx.peripheral]={}
            for k,v in {'compatible':b'uart-1,samsung\0','uart-version':struct.pack('<I',1),
                        'function-rx':struct.pack('<4I',0x4c,0x4750494f,rx.pin,rx.mux+1)}.items():
                dt.put(rx.peripheral,k,v)
        uart=spec.idle_rx[1].peripheral
        m,=gpio_models(dt,spec,[(0x31a000000,0x100000)])
        self.assertEqual(m.words(),(11,0x31a000000,0x100000,216,7,0x7f,0x10056,0x200aa))
        for key,value in [('compatible',b'unknown\0'),('uart-version',struct.pack('<I',2)),
                          ('function-rx',struct.pack('<4I',0x4d,0x4750494f,169,3)),
                          ('function-rx',struct.pack('<4I',0x4c,0x4750494f,168,3)),
                          ('function-rx',struct.pack('<4I',0x4c,0x4750494f,169,2))]:
            original=dt.get(uart,key);dt.put(uart,key,value)
            with self.assertRaises(ValueError):gpio_models(dt,spec,[(0x31a000000,0x100000)])
            dt.put(uart,key,original)
        for routes in [(spec.idle_rx[0],)*2, spec.idle_rx*2]:
            with self.assertRaises(ValueError):
                gpio_models(dt,replace(spec,idle_rx=routes),[(0x31a000000,0x100000)])

    def test_gpio_clkreq_binding_and_packed_routes(self):
        import xnuboot as xb
        dt=xb.build_devicetree(include_deferred=True);spec=replace(J700_26A428.gpio_boot[0],idle_i2c=())
        model,=gpio_models(dt,spec,[(0x31a000000,0x100000)])
        self.assertEqual(model.words(),(12,0x31a000000,0x100000,216,7,0x7f,
                                       0x10056 | (0x200aa<<18) | (0x10066<<36),0x10051))
        clk,=spec.idle_clkreq
        for key,value in [('compatible',b'unknown\0'),
                          ('function-clkreq',struct.pack('<4I',0x4d,0x4750494f,101,2)),
                          ('function-clkreq',struct.pack('<4I',0x4c,0x4750494f,102,2)),
                          ('function-clkreq',struct.pack('<4I',0x4c,0x4750494f,101,3))]:
            original=dt.get(clk.bridge,key);dt.put(clk.bridge,key,value)
            with self.assertRaises(ValueError):gpio_models(dt,spec,[(0x31a000000,0x100000)])
            dt.put(clk.bridge,key,original)
        for config in [(216,7,0x7f,1<<54,0),(216,7,0x7f,0,0x10001),
                       (216,7,0x7f,0x10056,0x20056),(216,7,0x7f,0x100d9,0)]:
            with self.assertRaises(ValueError):device_model_words((replace(model,config=config),))

    def test_dock_root_word_and_refusals(self):
        spec = J700_26A428.dock_boot
        dt = fixture()
        dt.nodes[spec.node] = {}
        props = {'compatible': b'dock,connect,aic\0',
                 'reg': struct.pack('<2Q',0x3082d8008,4),
                 'dock-connect-mask': struct.pack('<Q',1 << 22)}
        for key,value in props.items(): dt.put(spec.node,key,value)
        model, = dock_models(dt,spec)
        self.assertEqual(model.words(),(10,0x3082d8000,0x1000,8,1 << 22,0,0,0))
        for key,value in [('compatible',b'dock,unknown\0'),
                          ('dock-connect-mask',struct.pack('<I',1 << 22)),
                          ('reg',b''),('reg',struct.pack('<2Q',0x3082d8008,8)),
                          ('reg',struct.pack('<2Q',0x3082d8009,4)),
                          ('reg',struct.pack('<2Q',1 << 36,4))]:
            dt.put(spec.node,key,value)
            with self.assertRaises(ValueError): dock_models(dt,spec)
            dt.put(spec.node,key,props[key])
        with self.assertRaises(ValueError):
            dock_models(dt,replace(spec,node='/device-tree/arm-io/dock-connect'))
        dt.put(spec.node,'reg',struct.pack('<2Q',0x100ffc,4))
        self.assertEqual(dock_models(dt,spec)[0].base,0x100000)
        for cfg in [(8,0,0,0,0),(8,3,0,0,0),(8,1<<32,0,0,0),
                    (0x1000,1,0,0,0),(1,1,0,0,0),(8,1,1,0,0)]:
            with self.assertRaises(ValueError):
                device_model_words((replace(model,config=cfg),))

    def test_spmi_windows_and_parent_irq(self):
        spec = J700_26A428.spmi_boot[1]
        dt = fixture()
        dt.nodes[spec.node] = {}
        dt.nodes[spec.aic_node] = {}
        dt.put(spec.aic_node,'AAPL,phandle',struct.pack('<I',0x45))
        properties = {'compatible': b'aapl,spmi\0', 'gen': struct.pack('<I',3),
                      'queue-depth': struct.pack('<2I',256,256),
                      'AAPL,phandle': struct.pack('<I',0xa7),
                      'interrupt-parent': struct.pack('<3I',0xa7,0x45,0xa7),
                      'interrupts': struct.pack('<3I',256,492,281)}
        for name,value in properties.items(): dt.put(spec.node,name,value)
        windows = ((0x500014000,0x4000),(0x500004000,0x4000),(0x500000000,0x4000))
        model = spmi_models(dt,spec,windows)[0]
        self.assertEqual(model.words(),(9,0x500000000,0x18000,0x14000,0x4000,492,256,256))
        for name,value in [('gen',struct.pack('<I',4)),('queue-depth',struct.pack('<2I',64,64)),
                           ('interrupt-parent',struct.pack('<3I',0xa7,0xa7,0xa7)),
                           ('interrupts',struct.pack('<3I',256,4096,281)),
                           ('interrupts',b'\0'*11)]:
            dt.put(spec.node,name,value)
            with self.assertRaises(ValueError): spmi_models(dt,spec,windows)
            dt.put(spec.node,name,properties[name])
        for bad in ((),windows[:2],windows[::-1],(windows[1],windows[1],windows[2]),
                    (windows[0],(windows[2][0]+0x1000,0x4000),windows[2])):
            with self.assertRaises(ValueError): spmi_models(dt,spec,bad)
        for config in ((0x14000,0x4000,492,0,256), (0x14000,0x4000,492,256,257),
                       (0x14000,0x14000,492,256,256), (0x14000,0x4000,4096,256,256)):
            with self.assertRaises(ValueError): device_model_words((replace(model,config=config),))

    def test_gpio_geometry_and_relocation(self):
        spec = J700_26A428.gpio_boot[1]
        dt = fixture()
        dt.nodes[spec.node] = {}
        dt.put(spec.node, 'compatible', b'gpio,t8101\0')
        dt.put(spec.node, '#gpio-pins', struct.pack('<I', 10))
        dt.put(spec.node, '#gpio-int-groups', struct.pack('<I', 7))
        dt.put(spec.node, 'supported-int-groups', struct.pack('<3I', 4, 5, 6))
        windows = ((0x500000000, 0x4000),)
        model = gpio_models(dt, spec, windows)[0]
        self.assertEqual(model.words(), (7, 0x500000000, 0x4000, 10, 7, 0x70, 0, 0))
        for bad in ((), windows*2, ((0x500000004, 0x4000),)):
            with self.assertRaises(ValueError): gpio_models(dt, spec, bad)
        for groups in (b'', b'\0', struct.pack('<3I', 4, 4, 6), struct.pack('<3I', 4, 5, 7)):
            dt.put(spec.node, 'supported-int-groups', groups)
            with self.assertRaises(ValueError): gpio_models(dt, spec, windows)
        for config in ((0,7,0x70,0,0), (257,7,0x70,0,0), (10,7,0x80,0,0),
                       (10,8,0x70,0,0), (10,7,0x70,1,0)):
            with self.assertRaises(ValueError): device_model_words((replace(model, config=config),))

    def test_aes_key_controls_are_explicit(self):
        spec = J700_26A428.aes_keys_boot
        dt = fixture()
        dt.nodes[spec.node] = {}
        dt.put(spec.node, 'compatible', b'aes,s8000\0')
        dt.put(spec.node, 'aes-version', struct.pack('<I', 5))
        dt.put(spec.node, 'address-width', struct.pack('<I', 42))
        mapper='/device-tree/arm-io/dart-sio/mapper-aes'
        dt.nodes[mapper]={}
        dt.nodes['/device-tree/arm-io/dart-sio']={}
        dt.put(spec.node,'interrupts',struct.pack('<I',1107))
        dt.put(spec.node,'iommu-parent',struct.pack('<I',0x84))
        dt.put(mapper,'AAPL,phandle',struct.pack('<I',0x84))
        dt.put(mapper,'compatible',b'iommu-mapper\0')
        dt.put('/device-tree/arm-io/dart-sio','sid',struct.pack('<II',0,1))
        names = ('sioaesdisable-offset', 'sioaesdisableuid1-offset',
                 'sioaesdisablegid0-offset', 'sioaesdisablegid1-offset')
        for key, value in zip(names, spec.offsets): dt.put(spec.node, key, struct.pack('<I', value))
        windows = ((0x500000000,0x4000), (0x500010000,0x8000), (0x500020000,0x4000))
        model = aes_key_models(dt, spec, windows)[0]
        self.assertEqual(model.words(), (8,0x500010000,0x8000,0,0x40,0x44,0x48,0))
        engine = aes_key_models(dt, spec, windows)[1]
        self.assertEqual(engine.words(), (47,0x500000000,0x4000,5,42,1107,21,1))
        self.assertEqual(aes_key_models(dt,replace(spec,software_dma=False),windows)[1].kind,46)
        self.assertEqual(len(aes_key_models(dt,replace(spec,engine_version=None,software_dma=False),windows)),1)
        for node,prop in ((spec.node,'interrupts'),(spec.node,'iommu-parent'),
                          (mapper,'AAPL,phandle'),(mapper,'compatible'),('/device-tree/arm-io/dart-sio','sid')):
            original=dt.get(node,prop);dt.put(node,prop,b'')
            with self.assertRaises(ValueError): aes_key_models(dt,spec,windows)
            dt.put(node,prop,original)
        for name in ('aes-version', 'address-width'):
            original=dt.get(spec.node,name)
            for bad in (b'', struct.pack('<I',0), struct.pack('<I',4), original+b'\0'):
                dt.put(spec.node,name,bad)
                with self.assertRaises(ValueError): aes_key_models(dt,spec,windows)
            dt.put(spec.node,name,original)
        for version in (0,2,4,6):
            with self.assertRaises(ValueError): aes_key_models(dt,replace(spec,engine_version=version),windows)
        for config in ((4,0,0,0,0),(5,1,0,0,0),(5,0,1,0,0),(5,0,0,1,0),(5,0,0,0,1)):
            with self.assertRaises(ValueError): device_model_words((replace(engine,config=config),))
        with self.assertRaises(ValueError): device_model_words((replace(engine,span=0x8000),))
        for bad in ((), windows[:2]):
            with self.assertRaises(ValueError): aes_key_models(dt,spec,bad)
        for key in names:
            original = dt.get(spec.node,key)
            dt.put(spec.node,key,struct.pack('<I',0x100))
            with self.assertRaises(ValueError): aes_key_models(dt,spec,windows)
            dt.put(spec.node,key,original)
        for config in ((0,0,0x44,0x48,0), (0,0x41,0x44,0x48,0),
                       (0,0x8000,0x44,0x48,0), (0,0x40,0x44,0x48,1)):
            with self.assertRaises(ValueError): device_model_words((replace(model,config=config),))

    def test_mcc_ptd_directory_and_relocation(self):
        spec = J700_26A428.mcc_ptd_boot
        dt = fixture()
        props = {'pmp_ptd_db_reg_idx': 0, 'pmp_ptd_update_reg_idx': 1,
                 'ptd-range-drv2ctrl': 14, 'ptd-range-ctrl2drv': 30}
        for k, v in props.items(): dt.put(spec.node, k, struct.pack('<I', v))
        dt.nodes[spec.pmp_node] = {}
        directory = (struct.pack('<IIII16s', 14, 0x1a8, 10, 0, b'MC-DRV-TO-CTRL') +
                     struct.pack('<IIII16s', 30, 0x1b8, 9, 0, b'MC-CTRL-TO-DRV'))
        dt.put(spec.pmp_node, 'ptd-range', directory)
        windows = ((0x500000000, 0x4000), (0x500020000, 0x4000))
        models = mcc_ptd_models(dt, spec, windows)
        self.assertEqual(models[0].words(), (6, 0x500000000, 0x24000, 0x20000,
                                            0x1a8, 0x1b8, 8, 0))
        # Different PTD indices are part of placement, not hard-coded in C.
        relocated = (struct.pack('<IIII16s', 14, 20, 10, 0, b'MC-DRV-TO-CTRL') +
                     struct.pack('<IIII16s', 30, 60, 9, 0, b'MC-CTRL-TO-DRV'))
        dt.put(spec.pmp_node, 'ptd-range', relocated)
        self.assertEqual(mcc_ptd_models(dt, spec, windows)[0].config, (0x20000,20,60,8,0))
        for bad in (b'', directory[:-1], directory+directory[:32],
                    struct.pack('<IIII16s',14,0x1a8,11,0,b'MC-DRV-TO-CTRL')+directory[32:],
                    struct.pack('<IIII16s',14,0x1a8,10,1,b'MC-DRV-TO-CTRL')+directory[32:],
                    directory[:32]+struct.pack('<IIII16s',30,0x1a9,9,0,b'MC-CTRL-TO-DRV')):
            dt.put(spec.pmp_node, 'ptd-range', bad)
            with self.assertRaises(ValueError): mcc_ptd_models(dt,spec,windows)
        dt.put(spec.pmp_node, 'ptd-range', directory)
        for bad in ((), windows[:1], windows[::-1], (windows[0], windows[0]),
                    ((windows[0][0],0x8000),windows[1])):
            with self.assertRaises(ValueError): mcc_ptd_models(dt,spec,bad)
        for config in ((0x1000,20,60,8,0), (0x20000,20,60,9,0),
                       (0x20000,20,60,0,0), (0x20000,20,21,8,0),
                       (0x20000,1015,60,8,0), (0x20000,20,1016,8,0),
                       (0x20000,20,60,8,1)):
            with self.assertRaises(ValueError):
                device_model_words((replace(models[0],config=config),))

    def test_watchdog_contract_and_relocation(self):
        spec = J700_26A428.watchdog_boot
        dt = DeviceTree.__new__(DeviceTree)
        dt.nodes = {spec.node: {k: Property(k,v) for k,v in {
            'compatible': b'wdt,t8101\0wdt,s5l8960x\0',
            'wdt-version': struct.pack('<I',2), 'clock-ids': struct.pack('<I',4),
        }.items()}}
        windows = ((0x4082b0000,0x4000),(0x4082bc224,4),(0x4082b8008,4),
                   (0x4082b802c,4),(0x4082b8020,4))
        models = watchdog_models(dt,spec,windows,24000000)
        self.assertEqual(models[0].words(),(5,0x4082b0000,0x4000,24000000,0,0,0,0))
        self.assertEqual(models[1].words(),(44,0x4082b8000,0x1000,8,0,0,0,0))
        for i in range(1,5):
            changed=list(windows);b,n=changed[i];changed[i]=(b+4,n)
            with self.assertRaisesRegex(ValueError,'auxiliary'):watchdog_models(dt,spec,tuple(changed),24000000)
        for bad in (replace(models[1],span=0x4000),replace(models[1],config=(4,0,0,0,0)),
                    *(replace(models[1],config=tuple(8 if j==0 else int(i==j) for j in range(5))) for i in range(1,5))):
            with self.assertRaises(ValueError):device_model_words((bad,))
        for hz in (0,19200000,25000000):
            with self.assertRaises(ValueError): watchdog_models(dt,spec,windows,hz)
        for prop,value in [('compatible',b'wdt,new\0'),('wdt-version',struct.pack('<I',3)),
                           ('clock-ids',struct.pack('<I',5))]:
            original=dt.get(spec.node,prop); dt.put(spec.node,prop,value)
            with self.assertRaises(ValueError): watchdog_models(dt,spec,windows,24000000)
            dt.put(spec.node,prop,original)
        for bad in ((), windows[:1], ((windows[0][0],0x1000),*windows[1:])):
            with self.assertRaises(ValueError): watchdog_models(dt,spec,bad,24000000)

    def test_aic_identity_and_event_agree(self):
        spec = J700_26A428.aic_boot
        dt = aic_fixture()
        models = aic_models(dt, spec, ((0x501000000,0x1cc000),))
        self.assertEqual(models[0].words(), (3,0x501000000,0x1cc000,1280,4096,0x40000,0xa,0))
        self.assertEqual(dt.get(spec.node, 'aic-iack-offset'), struct.pack('<Q',0x40000))
        self.assertEqual(aic_models(dt,spec,((0x501000000,0x1cc000),)), models)

    def test_aic_rejects_conflicting_tree_before_adding_property(self):
        spec = J700_26A428.aic_boot
        for prop,value in [('rev-offset',struct.pack('<I',4)),
                           ('aic-rev',struct.pack('<I',0xb)),
                           ('aic-numdies',struct.pack('<I',1)),
                           ('aic-numdies-per-die',struct.pack('<I',1)),
                           ('aic-die-offset-stride',struct.pack('<Q',0x10000)),
                           ('aic-soc-offset-stride',struct.pack('<Q',0x100000)),
                           ('max-extint-num',struct.pack('<I',4096)),
                           ('cap0-offset',struct.pack('<I',8)), ('compatible',b'aic,2\0'),
                           ('aic-iack-offset',struct.pack('<Q',0xc000))]:
            dt = aic_fixture(); dt.put(spec.node,prop,value)
            with self.assertRaises(ValueError): aic_models(dt,spec,((0x301000000,0x1cc000),))
            if prop != 'aic-iack-offset': self.assertNotIn('aic-iack-offset',dt.nodes[spec.node])
        dt = aic_fixture()
        dt.put('/device-tree/arm-io/test','interrupts',struct.pack('<I',1280))
        with self.assertRaises(ValueError): aic_models(dt,spec,((0x301000000,0x1cc000),))
        dt.put('/device-tree/arm-io/test','interrupts',b'\0')
        with self.assertRaises(ValueError): aic_models(dt,spec,((0x301000000,0x1cc000),))
        for windows in [(), ((0x301000000,0x40000),), ((0x301000000,0x1cc000),)*2]:
            with self.assertRaises(ValueError): aic_models(aic_fixture(),spec,windows)

    def test_profile_geometry_and_serialized_abi(self):
        dt = fixture()
        models = mcc_models(dt, SPEC, WINDOWS)
        blob = struct.pack(f'<{1+MODEL_MAX*MODEL_WORDS}Q', *device_model_words(models))
        count, kind, base, span, banks = struct.unpack_from('<5Q', blob)
        self.assertEqual((count, kind, base, span, banks), (8, 1, 0x220000000, 0x140000, 4))
        self.assertEqual(blob[40:72], bytes(32))
        for i in range(4):
            self.assertEqual(struct.unpack_from('<8Q', blob, 72+i*64),
                             (2, WINDOWS[3+i][0], 0x8000, 0, 0, 0, 0, 0))
        for i in range(3):
            self.assertEqual(struct.unpack_from('<8Q', blob, 328+i*64),
                             (4, WINDOWS[7+i][0], 0x8000, SPEC.socni_counters[i], 0, 0, 0, 0))
        self.assertEqual(blob[520:], bytes(len(blob)-520))
        self.assertNotIn('cache-size', dt.nodes[SPEC.node])

    def test_relocation_comes_from_the_tree(self):
        models = mcc_models(fixture(), SPEC, tuple((b+0x200000000,n) for b,n in WINDOWS))
        self.assertEqual(models[0].base, 0x420000000)
        self.assertEqual(models[4].base, 0x420a00000)
        self.assertEqual(models[-1].base, 0x451008000)

    def test_unknown_geometry_is_rejected(self):
        for key, value in [('compatible', b'mcc,new\0'), ('amcc-count', struct.pack('<I', 2)),
                           ('dcs-count-per-amcc', struct.pack('<I', 5)), ('amcc-reg-idx', b'\2'),
                           ('amcc-reg-idx', struct.pack('<I', 8)),
                           ('dcs-reg-idx', struct.pack('<I', 5)), ('dcs-reg-idx', b''),
                           ('socni-reg-idx', struct.pack('<I', 9)),
                           ('socni-count', struct.pack('<I', 2))]:
            with self.subTest(key=key, value=value):
                dt = fixture(); dt.set(SPEC.node, key, value)
                with self.assertRaises(ValueError):
                    mcc_models(dt, SPEC, WINDOWS)

    def test_registry_rejects_aliases_and_owned_memory(self):
        d = DeviceModel(SPEC.node, 1, 0x220000000, 0x140000, (4, 0, 0, 0, 0))
        for models, excluded in [((d, d), ()), ((d,), ((d.base+0x2c, 4),)),
                                 ((d,)*(MODEL_MAX+1), ()), ((d,), ((-1, 1),))]:
            with self.assertRaises(ValueError): device_model_words(models, excluded)
        self.assertEqual(device_model_words((d, replace(d, base=d.base+d.span)))[0], 2)
        for kwargs in [dict(kind=2), dict(span=0), dict(base=1<<36), dict(span=0xc0000),
                       dict(config=(0,0,0,0,0)), dict(config=(4,1,0,0,0)), dict(base=d.base+1)]:
            with self.assertRaises(ValueError): device_model_words((replace(d, **kwargs),))


if __name__ == '__main__': unittest.main()
