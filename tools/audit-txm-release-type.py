#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independently validate the retained Image4 release-type record."""
import struct


def audit(raw, *, stacks_pa, stack_count):
    if len(raw)!=184 or stacks_pa&0x3fff or not 1<=stack_count<=256:
        raise ValueError('release type audit geometry')
    calls,sets,rejections,status,input_va,stack_pa,length=struct.unpack_from('<7Q',raw)
    original,value=raw[56:120],raw[120:184]
    if not calls:
        if any(raw):raise ValueError('unused release type state not empty')
        return dict(calls=0,sets=0,rejections=0,initialized=False,value=None)
    if (sets!=1 or calls!=sets+rejections or length>62 or
        status!=(0 if calls==1 else (37<<32)|5) or
        stack_pa&0x3fff or not stacks_pa<=stack_pa<stacks_pa+stack_count*0x4000 or
        not input_va or input_va>(1<<64)-65):
        raise ValueError('release type counters or request geometry differ')
    prefix=original[:62].split(b'\0',1)[0]
    if length!=len(prefix) or value!=prefix+bytes(64-len(prefix)):
        raise ValueError('release type differs from native truncation/copy rule')
    return dict(calls=calls,sets=sets,rejections=rejections,last_status=hex(status),
                initialized=True,input_va=hex(input_va),stack_pa=hex(stack_pa),
                length=length,first_input_hex=original.hex(),value_hex=value.hex(),
                value=prefix.decode('utf-8','backslashreplace'),
                boundary='owned set-once metadata; does not establish signature verification')
