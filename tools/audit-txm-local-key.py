#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Validate the bounded one-time local-signing record, without logging it."""
import hashlib
import struct


def audit(raw, *, stacks_pa, stack_count):
    if len(raw)!=128 or stacks_pa&0x3fff or not 1<=stack_count<=256:
        raise ValueError('local key audit geometry')
    sets,input_va,stack_pa=struct.unpack_from('<3Q',raw)
    if not sets:
        if any(raw):raise ValueError('unused local key state not empty')
        return dict(sets=0,initialized=False)
    if (sets!=1 or input_va<0xffff800000000000 or input_va>(1<<64)-98 or
            stack_pa&0x3fff or not stacks_pa<=stack_pa<stacks_pa+stack_count*0x4000 or
            any(raw[121:])):
        raise ValueError('local key state or request geometry differs')
    value=raw[24:121]
    return dict(sets=sets,initialized=True,input_va=hex(input_va),stack_pa=hex(stack_pa),
                bytes=97,sha256=hashlib.sha256(value).hexdigest(),all_ff=value==b'\xff'*97,
                boundary='retained public-key record; signature verification and getter not established')
