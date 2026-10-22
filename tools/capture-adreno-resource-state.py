#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inspect retained generation47 IOGPU resource maps through a verified stopped reader.

Failure inventory: docs/ADRENO-RESOURCE-PREPARE-20260927.md. No guest calls,
writes, MMIO, reset or boot. The captured namespace belongs to the native
IOGPUDeviceUserClient already named by the stopped IOService registry.
"""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import struct
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
TRACE_SHA='1290c17eec30048acb8291ceb36196f69f81f113c9d974ae3b725d32157ced73'

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device',required=True)
    ap.add_argument('--prefix',default='installed-metal-clear-threshold-2400s-20260927')
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--dry-run',action='store_true')
    args=ap.parse_args()
    assert args.prefix=='installed-metal-clear-threshold-2400s-20260927'
    assert not args.output.exists()
    path=lambda suffix:ROOT/'build'/(args.prefix+suffix)
    launch_path=path('-launch.json');launch=json.loads(launch_path.read_text())
    assert launch['exit_code']==7 and launch['finished']
    for name,digest in launch['source_sha256'].items():assert sha(Path(name))==digest,name
    registry_path=path('-kernel-waits.json');registry=json.loads(registry_path.read_text())
    assert registry['ioreg_state']['complete']
    clients=[row for row in registry['ioreg_state']['entries']
             if row['class_name']=='IOGPUDeviceUserClient']
    assert len(clients)==1
    trace_path=ROOT/'build/adreno-resource-state-native-20260927.json'
    assert sha(trace_path)==TRACE_SHA
    trace=json.loads(trace_path.read_text())
    assert trace['images'][0]['uuid']=='6172533f-b127-35e2-90b8-f7b3b1f2c5b7'
    reader_path=ROOT/'tools/port-receiver.py'
    tool=runpy.run_path(str(reader_path))
    if args.dry_run:
        print(json.dumps({'hardware_access':False,'generation':47,'client':clients[0],
                          'native_functions':len(trace['images'][0]['functions'])}));return
    stopped=tool['open_stopped'](SimpleNamespace(prefix=args.prefix,device=args.device,page_budget=1024))
    result=None
    try:
        info=stopped['proxy'].bootinfo();assert info['stage_generation']==47
        kernel=stopped['kernel']
        for function in trace['images'][0]['functions']:
            expected=bytes.fromhex(function['bytes_hex']);at=kernel.va2off(int(function['kc'],0))
            assert kernel.data[at:at+len(expected)]==expected,function['symbol']
        reads=[]
        def ptr(value):
            if not value:return 0
            address=value|0xffff000000000000
            assert address>=0xffff800000000000 and address&7==0,hex(value)
            return address
        def read(address,size):
            assert address and 0<size<=0x8000
            raw=b''.join(stopped['va_read'](address+i,min(size-i,0x4000))
                         for i in range(0,size,0x4000))
            reads.append({'address':hex(address),'bytes':size,'data_hex':raw.hex()})
            return raw
        u64=lambda raw,off:struct.unpack_from('<Q',raw,off)[0]
        u32=lambda raw,off:struct.unpack_from('<I',raw,off)[0]
        client_address=int(clients[0]['address'],0);client=read(client_address,304)
        assert ptr(u64(client,0))==int(clients[0]['vtable'],0)
        device_address=ptr(u64(client,0x120));device=read(device_address,0x58)
        namespace_address=ptr(u64(device,0x10));namespace=read(namespace_address,0x30)
        capacity=u32(namespace,0x28);assert 0<capacity<=4096
        table_address=ptr(u64(namespace,0x10));table=read(table_address,capacity*8)
        resources=[]
        for index in range(1,capacity):
            address=ptr(u64(table,index*8))
            if not address:continue
            assert len(resources)<128,'resource bound exceeded'
            raw=read(address,160);map_address=ptr(u64(raw,0x20))
            row={'id':index,'address':hex(address),'vtable':hex(ptr(u64(raw,0))),
                 'native_refs':u32(raw,0xc),'type':u32(raw,0x10)&0xff,
                 'flags_word':hex(u32(raw,0x10)),'map':hex(map_address),
                 'memory_field':hex(ptr(u64(raw,0x28))),
                 'related_field':hex(u64(raw,0x30))}
            if map_address:
                mapping=read(map_address,72)
                row['map_base']={'vtable':hex(ptr(u64(mapping,0))),
                    'allocated_flags':struct.unpack_from('<H',mapping,0x10)[0],
                    'memory':hex(ptr(u64(mapping,0x18))),'data_hex':mapping.hex()}
            resources.append(row)
        stopped['recheck']()
        assert stopped['proxy'].bootinfo()['stage_generation']==47
        result={'status':'STOPPED_ADRENO_NAMESPACE_CAPTURED','generation':47,
            'prefix':args.prefix,'hardware_writes':False,'guest_calls':False,
            'kernel_sha256':registry['kernel_sha256'],'monitor_sha256':launch['monitor_sha256'],
            'client':clients[0],'device':hex(device_address),'namespace':hex(namespace_address),
            'capacity':capacity,'resources':resources,'reads':reads,
            'pages_read':len(stopped['pages']),'stop_rechecked':True,
            'inputs_sha256':{str(p):sha(p) for p in [launch_path,registry_path,trace_path,path('-audit.json')]},
            'source_sha256':{str(p):sha(p) for p in [Path(__file__),reader_path,
                  ROOT/'tools/trace-adreno-resource-state.py',ROOT/'tools/trace-adreno-memory-map.py']},
            'boundary':'Read-only retained namespace objects, not preparation or pixels. PAC stripped for lookup, not authenticated; resource type and map fields bound to original native code.'}
    finally:
        stopped['proxy'].link.close()
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':result['status'],'resources':result['resources'],
                      'pages_read':result['pages_read'],'output':str(args.output)}))

if __name__=='__main__':main()
