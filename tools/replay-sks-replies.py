#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Execute native SKS reply serialization and rejection paths with bounded fixtures."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import struct

ROOT = Path(__file__).resolve().parents[1]
PRIOR = ROOT/'build/sks-native-roundtrip-20260928-v4.json'
PRIOR_SHA = '75c557511e984af54a817b588c73705671700e271a6a6c69604ba4faed792e44'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
assert sha(PRIOR) == PRIOR_SHA
prior = json.loads(PRIOR.read_text())
for path, digest in prior['inputs_sha256'].items():
    assert sha(path) == digest, path
spec = importlib.util.spec_from_file_location('sks_request', ROOT/'tools/replay-sks-native.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


class ReplyNative(base.Native):
    def __init__(self):
        self.allocations = []
        self.next_allocation = base.DATA+0x30000
        super().__init__()
        self.put(0x5a468,'<Q',base.DATA+0x18a00)  # Native _kernel_task import.
        self.put(base.DATA+0x18a00,'<Q',base.DATA+0x18900)

    def hook(self, u, pc, size, unused):
        name = self.imports.get(pc)
        if name == '_current_task':
            self.events.append(dict(name=name,result=hex(base.DATA+0x18800)))
            self.result(base.DATA+0x18800)
            return
        if name == '_IOLog':
            address = self.x(0)
            message = bytearray()
            for offset in range(1024):
                value = bytes(u.mem_read(address+offset,1))
                if value == b'\0':
                    break
                message.extend(value)
            else:
                raise AssertionError('unterminated native log format')
            self.events.append(dict(name=name,format=message.decode('utf-8')))
            self.result()
            return
        if name == '_IOMallocZeroData':
            size = self.x(0)
            assert 0 < size <= 0x4000, f'allocation size {size:#x}'
            pointer = self.next_allocation+16
            self.next_allocation += (size+47)&~15
            assert self.next_allocation < base.DATA+0xe0000
            u.mem_write(pointer-16, b'\xa5'*16+bytes(size)+b'\x5a'*16)
            self.allocations.append(dict(pointer=hex(pointer), bytes=size))
            self.events.append(dict(name=name, bytes=size, result=hex(pointer)))
            self.result(pointer)
            return
        super().hook(u, pc, size, unused)

    def check_allocations(self):
        for allocation in self.allocations:
            pointer, size = int(allocation['pointer'],16), allocation['bytes']
            assert bytes(self.u.mem_read(pointer-16,16)) == b'\xa5'*16
            assert bytes(self.u.mem_read(pointer+size,16)) == b'\x5a'*16


def rejected_decode(native, message, length):
    native.u.mem_write(base.REPLY, message+b'\x6d'*32)
    native.u.mem_write(base.DECODE, bytes(0xf8))
    expected_tail = bytes(native.u.mem_read(base.REPLY+length,32))
    result = native.invoke(base.CODE,0,0,base.REPLY,length,base.DECODE)
    assert result == 0xffffffff, f'accepted malformed length {length}: {result:#x}'
    assert bytes(native.u.mem_read(base.REPLY+length,32)) == expected_tail
    assert bytes(native.u.mem_read(base.REPLY,length)) == bytes(length)
    native.check_allocations()
    return dict(supplied_bytes=length, result=hex(result), guard_intact=True, input_cleared=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    assert not args.output.exists()
    record = dict(status='RUNNING',hardware_access=False,prior_sha256=PRIOR_SHA,
        image_sha256=base.IMAGE_SHA,image_uuid=base.IMAGE_UUID,
        inputs_sha256={str(p):sha(p) for p in [Path(__file__),ROOT/'docs/SKS-REPLY-REPLAY-20260928.md']},
        cases=[],boundary='Native reply serialization and malformed-message rejection; synthetic blob, bounded allocation and inherited explicit fixtures. No device-state semantics, startup or hardware proof.')
    try:
        for case in prior['cases']:
            record['current_case']=dict(version=case['version'],stage='positive')
            native = ReplyNative()
            block = bytes.fromhex(case['callback']['args_hex'])
            native.u.mem_write(base.ARGS,block)
            payload = bytes(range(0xa0,0xb3))
            native.u.mem_write(base.PAYLOAD,payload)
            native.put(base.ARGS+0x68,'<Q',base.PAYLOAD)
            native.put(base.ARGS+0x70,'<I',len(payload))
            length = native.invoke(base.CODE,1,1,base.REPLY,0x1000,base.ARGS)
            assert 0 < length <= 0x1000
            reply = bytes(native.u.mem_read(base.REPLY,length))
            decoded = native.invoke(base.CODE,0,0,base.REPLY,length,base.DECODE)
            assert decoded == length
            pointer = struct.unpack('<Q',native.u.mem_read(base.DECODE+0x68,8))[0]
            count = struct.unpack('<I',native.u.mem_read(base.DECODE+0x70,4))[0]
            assert count == len(payload)
            assert bytes(native.u.mem_read(pointer,count)) == payload
            assert native.allocations[-1] == dict(pointer=hex(pointer),bytes=count)
            native.check_allocations()
            # Native decoding clears even a successfully consumed input buffer.
            assert bytes(native.u.mem_read(base.REPLY,length)) == bytes(length)
            negative=[]
            for short in range(length):
                record['current_case']['stage']=f'truncated-{short}'
                negative.append(dict(name='truncated',**rejected_decode(native,reply,short)))
            for name,offset in [('digest',4),('payload',length-3)]:
                record['current_case']['stage']=name
                corrupt=bytearray(reply);corrupt[offset]^=0x80
                negative.append(dict(name=name,**rejected_decode(native,bytes(corrupt),length)))
            record['current_case']['stage']='trailing-byte'
            negative.append(dict(name='trailing-byte',**rejected_decode(native,reply+b'\x7e',length+1)))
            for capacity in [0,4,length-1]:
                record['current_case']['stage']=f'encode-capacity-{capacity}'
                native.u.mem_write(base.REPLY,b'\xcc'*(length+32))
                result=native.invoke(base.CODE,1,1,base.REPLY,capacity,base.ARGS)
                assert result == 0xffffffff
                assert bytes(native.u.mem_read(base.REPLY,capacity)) == bytes(capacity)
                assert bytes(native.u.mem_read(base.REPLY+capacity,32)) == b'\xcc'*32
                negative.append(dict(name='encode-capacity',capacity=capacity,result=hex(result),guard_intact=True))
            record['current_case']['stage']='invalid-discriminator'
            native.put(base.ARGS+0x50,'<I',2)
            native.u.mem_write(base.REPLY,b'\xcc'*(length+32))
            result=native.invoke(base.CODE,1,1,base.REPLY,length,base.ARGS)
            assert result == 0xffffffff
            assert bytes(native.u.mem_read(base.REPLY,length)) == bytes(length)
            assert bytes(native.u.mem_read(base.REPLY+length,32)) == b'\xcc'*32
            negative.append(dict(name='invalid-discriminator',value=2,result=hex(result)))
            native.check_allocations()
            record['cases'].append(dict(version=case['version'],reply_hex=reply.hex(),reply_bytes=length,
                payload_hex=payload.hex(),decoded_bytes=decoded,negative=negative,allocations=native.allocations,
                fixture_calls=native.events,executed_pcs=[hex(x) for x in sorted(native.executed)]))
        record['status']='NATIVE_SKS_REPLY_AND_REJECTION_QUALIFIED'
        del record['current_case']
    except Exception as error:
        record.update(status='FAILED',error=repr(error))
        if 'native' in locals():
            record['last_pc']=hex(native.u.reg_read(base.reg.UC_ARM64_REG_PC))
            record['last_fixture_calls']=native.events[-20:]
        raise
    finally:
        with args.output.open('x') as stream:
            json.dump(record,stream,indent=2);stream.write('\n')
    print(json.dumps(dict(status=record['status'],output=str(args.output),sha256=sha(args.output))))


if __name__=='__main__':
    main()
