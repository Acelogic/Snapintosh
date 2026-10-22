#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'probes'))
from clockcontract import validate_counter_image


class ClockContractTests(unittest.TestCase):
    def test_direct_frequency_all_registers_and_directions(self):
        for base in (0xd53be000, 0xd51be000):
            for rt in range(32):
                data = struct.pack('<II', 0xd503201f, base | rt)
                segs = [('code', 0x1000, len(data), 0, len(data))]
                with self.assertRaisesRegex(ValueError, 'CNTFRQ_EL0 at 0x1004'):
                    validate_counter_image(data, segs, 19200000, 24000000)
                self.assertEqual(validate_counter_image(data, segs, 24000000, 24000000), 2)

    def test_only_executable_file_ranges(self):
        data = struct.pack('<IIII', 0xd53be000, 0xd53be040, 0xd53be020, 0xd503201f)
        segs = [('counter-code', 0x2000, 64, 4, 12)]
        self.assertEqual(validate_counter_image(data, segs, 19200000, 24000000), 3)
        for bad in [[], [('bad', 0, 4, 0, 8)], [('bad', 0, 16, 4, 16)],
                    [('bad', 0, 4, 0, 3)], [('bad', 1, 4, 0, 4)],
                    [('bad', 0, 4, -4, 4)]]:
            with self.assertRaises(ValueError):
                validate_counter_image(data, bad, 19200000, 24000000)
        for hz in (0, -1, 1 << 32, 19.2, None):
            with self.assertRaises(ValueError):
                validate_counter_image(data, segs, hz, 24000000)
            with self.assertRaises(ValueError):
                validate_counter_image(data, segs, 19200000, hz)

    def test_macho_protection_selects_code_without_name_assumptions(self):
        spec = importlib.util.spec_from_file_location('kc_load', ROOT / 'tools/kc-load.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        data = bytearray(256)
        struct.pack_into('<IiiII', data, 0, 0xfeedfacf, 0, 0, 2, 2)
        for i, (name, prot) in enumerate([(b'odd-code-name', 5), (b'__TEXT_EXEC', 1)]):
            pos = 32 + i * 72
            struct.pack_into('<II16sQQQQiiII', data, pos, 0x19, 72, name,
                             0x1000 + i * 0x1000, 4, 240 + i * 4, 4, 7, prot, 0, 0)
        image = module.Image(bytes(data))
        self.assertEqual([s[0] for s in image.executable_segments], ['odd-code-name'])


if __name__ == '__main__':
    unittest.main()
