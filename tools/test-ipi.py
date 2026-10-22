#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin the shipped boot CPU self-IPI and guest-owned signal-enable path."""
import importlib.util
from pathlib import Path
import struct
import unittest
ROOT=Path(__file__).resolve().parents[1]

class StockIPI(unittest.TestCase):
    def test_self_request_fiq_ack_and_signal_enable(self):
        spec=importlib.util.spec_from_file_location('kc',ROOT/'tools/kc-load.py')
        kc=importlib.util.module_from_spec(spec);spec.loader.exec_module(kc)
        im=kc.Image((ROOT/'downloads/extracted/j700ap/kernelcache.release.mac17p').read_bytes())
        def word(low):
            va=0xfffffe0000000000+low
            _,base,_,off,_=next(s for s in im.segments if s[1]<=va<s[1]+s[4])
            return struct.unpack_from('<I',im.data,off+va-base)[0]
        # PE_cpu_machine_init chooses local/global self request from MPIDR.
        self.assertEqual(word(0xc1ebfe0),0xd51df008)
        self.assertEqual(word(0xc1ebff0),0xd51df028)
        # The observed SMP path uses the same local request encoding.
        self.assertEqual(word(0xba7e310),0xd51df008)
        # The fast FIQ path reads pending, W1C-acks, and calls the signal handler(0).
        self.assertEqual(word(0xba8591c),0xd53df134)
        self.assertEqual(word(0xba85930),0xd51df133)
        self.assertEqual(word(0xba85938),0x52800000)
        branch=word(0xba8593c)
        self.assertEqual(branch>>26,0x25)
        imm=branch&0x3ffffff
        if imm&(1<<25):imm-=1<<26
        self.assertEqual(0xba8593c+4*imm,0xba7e788)
        # Signal handler clears SIGPdisabled in cpu_data+0x48 with a real guest atomic.
        self.assertEqual(word(0xba7e804),0x910122a8)
        self.assertEqual(word(0xba7e808),0x52b00009)
        self.assertEqual(word(0xba7e80c),0xb8e91116)

if __name__=='__main__':unittest.main()
