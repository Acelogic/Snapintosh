#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Decode the captured CPSN assertion and retain its UUID-bound native contract.

Read-only/offline. Fail on a changed stop, argument block, process, KDK UUID or
instruction witness. Static code is not proof that an endpoint request ran.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy
import struct
import subprocess
import capstone

ROOT=Path(__file__).resolve().parents[1]
KDK=Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk/System/Library/Extensions/AppleSEPManager.kext/Contents/MacOS/AppleSEPManager')

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--prefix',required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();assert re.fullmatch('[a-z0-9-]+',args.prefix)
    assert not args.output.exists()
    base=ROOT/'build'/args.prefix
    def read(s):return Path(str(base)+s).read_bytes()
    stop_raw=read('-cpu1-stop.json');stop=json.loads(stop_raw)
    audit=json.loads(read('-audit.json'));waits=json.loads(read('-kernel-waits.json'))
    assert audit['runtime_stop_qualified'] and audit['user_mapping_qualified']
    assert stop['monitor_sha256']==audit['monitor_sha256']==waits['monitor_sha256']
    assert audit['panic_state']['owner']==stop['cpu']==1 and audit['panic_state']['triggered']==1
    assert stop['registers']['2']=='0xfffffe0007685e78'
    obj=stop['object'];assert obj['register']==3 and obj['size']==256
    assert obj['va']==stop['registers']['3']
    words=struct.unpack('<32Q',bytes.fromhex(obj['data_hex']))
    assert words[0]==int(obj['va'],16)+24 and words[2]==0xfffffe00099dcfa0
    assert words[5]==words[8]==2499
    metadata=runpy.run_path(str(ROOT/'tools/kc-symbolicate.py'))['macho_segments']
    raw=KDK.read_bytes()
    slices=[struct.unpack_from('>5I',raw,8+i*20) for i in range(struct.unpack_from('>I',raw,4)[0])]
    _,_,off,size,_=next(v for v in slices if v[0]==0x100000c and v[1]&0xffffff==2)
    thin=raw[off:off+size];ks,uid=metadata(thin)
    kc=runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](
        ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p',scope='com.apple.driver.AppleSEPManager')
    _,_,entry=next(v for v in kc.entries if v[0]==kc.scope);cs,cuid=metadata(kc.data,entry)
    assert uid==cuid and str(uid)=='d4c978c0-c954-30a3-ae95-0f0f25aa5aac'
    def translate(a):
        name,start=next((n,b) for n,(b,s) in ks.items() if b<=a<b+s)
        return cs[name][0]+a-start
    condition=kc.cstr(words[3]);function=kc.cstr(words[4]);filename=kc.cstr(words[7])
    assert condition=='!booted' and 'DispatchUserClientLynxGetCPSN' in function
    assert filename=='AppleSEPUserClient.cpp'
    thread=waits['cpu_topology']['cpu_data_entries'][1]['thread']
    owners=[p for p in waits['user_processes']['processes'] if any(t['thread']==thread for t in p['threads'])]
    assert len(owners)==1 and owners[0]['name']=='corerepaird'
    symbols=[]
    for line in subprocess.check_output(['nm','-arch','arm64e','-n',str(KDK)],text=True).splitlines():
        parts=line.split()
        if len(parts)==3:
            try:symbols.append((int(parts[0],16),parts[2]))
            except ValueError:pass
    md=capstone.Cs(capstone.CS_ARCH_ARM64,capstone.CS_MODE_ARM)
    functions=[]
    for symbol in ('__ZN18AppleSEPUserClient29DispatchUserClientLynxGetCPSNEPS_PvP25IOExternalMethodArguments',
                   '__ZN15AppleSEPManager14xartSEPSlaveEPEj',
                   '__ZN12AppleSEPXART13lynx_get_cpsnEPvPm'):
        start,=tuple(a for a,n in symbols if n==symbol)
        end=min(a for a,n in symbols if a>start);va=translate(start);at=kc.va2off(va)
        code=kc.data[at:at+end-start]
        functions.append(dict(symbol=symbol,kdk=hex(start),kc=hex(va),bytes_hex=code.hex(),
            instructions=[f'{i.address:#x} {i.mnemonic} {i.op_str}' for i in md.disasm(code,va)]))
    witnesses=[]
    for a in (0x31d30,0x31d40,0x31d88,0x31d8c,0x31d98):
        word=struct.unpack_from('<I',thin,a)[0];assert word==kc.u32(translate(a))
        witnesses.append(dict(kdk=hex(a),kc=hex(translate(a)),word=hex(word)))
    sha=lambda b:hashlib.sha256(b).hexdigest()
    out=dict(prefix=args.prefix,monitor_sha256=stop['monitor_sha256'],stop_sha256=sha(stop_raw),
        kernel_sha256=sha(kc.data),kdk_sha256=sha(thin),kext_uuid=str(uid),
        process=dict(pid=owners[0]['pid'],name=owners[0]['name'],thread=thread),
        assertion=dict(condition=condition,function=function,file=filename,line=2499),
        functions=functions,stable_witnesses=witnesses,
        boundary='Captured CPU1 assertion and process; static native service lookup/query code. No xars request was submitted in this run.')
    args.output.write_text(json.dumps(out,indent=2)+'\n')
    print(json.dumps(dict(output=str(args.output),assertion=out['assertion'],process=out['process'])))

if __name__=='__main__':main()
