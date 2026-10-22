# SPDX-License-Identifier: MIT
"""Read bounded argv through byte-qualified 26A428 libSystem accessors.

No guest code is called. The caller first binds a stopped, independently audited
process address space and verifies a captured 64-byte shared-cache slide witness.
Only argv is read; environment variables are outside this reader's scope.
"""
import hashlib
import json
from pathlib import Path
import struct

ACCESSOR=0x18071b7c0
ACCESSOR_BYTES=bytes.fromhex('88e721d000f146f9c0035fd688e721d000d946f9c0035fd6')
ARGV_SLOT=0x1c440dde0
ARGC_SLOT=0x1c440ddb0
USER_LIMIT=1<<47

def collect(read,slide):
    if not isinstance(slide,int) or not 0<=slide<1<<32 or slide&0x3fff:
        raise ValueError('invalid shared-cache slide')
    if read(ACCESSOR+slide,24)!=ACCESSOR_BYTES:
        raise ValueError('native argument accessor differs')
    consumed=0
    def get(address,size,alignment=1):
        nonlocal consumed
        if not 0<address<address+size<=USER_LIMIT or address&(alignment-1):
            raise ValueError('invalid argument pointer')
        consumed+=size
        if consumed>8192:raise ValueError('argument read budget exhausted')
        raw=read(address,size)
        if len(raw)!=size:raise ValueError('short argument read')
        return raw
    def q(address):return struct.unpack('<Q',get(address,8,8))[0]
    argc_pointer=q(ARGC_SLOT+slide);argv_pointer=q(ARGV_SLOT+slide)
    argc,=struct.unpack('<I',get(argc_pointer,4,4))
    if not 1<=argc<=64:raise ValueError('invalid or uninitialized argc')
    argv=q(argv_pointer)
    pointers=struct.unpack(f'<{argc+1}Q',get(argv,8*(argc+1),8))
    if pointers[-1]:raise ValueError('argv is not terminated at argc')
    strings=[];raw_strings=[]
    for pointer in pointers[:-1]:
        value=bytearray()
        while len(value)<512:
            # Never require bytes past a 16K page boundary for a short string.
            size=min(64,512-len(value),0x4000-((pointer+len(value))&0x3fff))
            part=get(pointer+len(value),size)
            end=part.find(b'\0')
            value.extend(part if end<0 else part[:end])
            if end>=0:break
        else:raise ValueError('unterminated or oversized argument')
        raw_strings.append(value.hex())
        strings.append(value.decode('utf-8','strict'))
    return dict(argc=argc,argv=strings,raw_arguments_hex=raw_strings,
        argc_pointer=hex(argc_pointer),argv_pointer=hex(argv_pointer),argv_vector=hex(argv),
        slide=hex(slide),accessor=hex(ACCESSOR+slide),accessor_hex=ACCESSOR_BYTES.hex(),
        bytes_read=consumed+24,
        boundary='Native NSGetArgc/NSGetArgv instruction witnesses and bounded process-local '
                 'indirections. No guest code call or environment read; pointers are not PAC authenticated.')

def load_hints(path,root,kernel_sha,monitor_sha):
    data=json.loads(Path(path).read_bytes());capture=Path(data['capture'])
    if not capture.is_absolute():capture=Path(root)/capture
    raw=capture.read_bytes();source=json.loads(raw)
    if (hashlib.sha256(raw).hexdigest()!=data['capture_sha256'] or
            any(x['kernel_sha256']!=kernel_sha or x['monitor_sha256']!=monitor_sha
                for x in (data,source))):raise ValueError('argument slide evidence identity differs')
    origins={p['pid']:p for p in source['user_processes']['processes']};hints={}
    if len(origins)!=len(source['user_processes']['processes']):
        raise ValueError('duplicate captured process identity')
    for process in data['processes']:
        match=process.get('code_match')
        if not match:continue
        origin=origins.get(process['pid'])
        if (not origin or origin['name']!=process['name'] or
                origin.get('user_address_space')!=process.get('address_space') or
                match.get('matched_bytes')!=64 or process['pid'] in hints):
            raise ValueError('argument slide process differs')
        patterns=set()
        for thread in origin['threads']:
            if thread['tid']!=match['tid']:continue
            state=thread.get('saved_user_state') or {}
            if match['kind']=='saved_pc' and int(state.get('pc','0'),16)==match['runtime_pc']:
                patterns.add(state.get('instruction_hex',''))
            if match['kind']=='frame_return_site':
                for frame in thread.get('user_frame_chain',{}).get('frames',[]):
                    if int(frame.get('return_site_va','0'),16)==match['runtime_pc']:
                        patterns.add(frame.get('return_site_hex',''))
        if len(patterns)!=1:raise ValueError('no unique captured slide witness')
        code=bytes.fromhex(patterns.pop())
        if len(code)!=64:raise ValueError('short captured slide witness')
        hints[process['pid']]=dict(name=process['name'],task=origin['task'],
            address_space=process['address_space'],slide=match['slide'],
            witness_address=match['runtime_pc'],witness=code)
    return hints
