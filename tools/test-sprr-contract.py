#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Check the binary witness reader, including corrupt and incomplete evidence."""
import runpy
from pathlib import Path
import unittest

contract = runpy.run_path(str(Path(__file__).with_name('inspect-sprr-contract.py')))


class ContractTests(unittest.TestCase):
    def test_selected_shipped_images(self):
        result = contract['inspect']()
        self.assertEqual(result['registers']['UPERM'], '2010002030100000')
        self.assertEqual(result['registers']['PPERM'], '2020a52a302abae6')
        self.assertEqual(result['registers']['PMPRR'], '0000000000040010')
        self.assertEqual([row['index'] for row in result['classes']
                          if row['umprr_field_flag8']], [9])
        self.assertEqual([row['index'] for row in result['classes']
                          if row['pmprr_field']], [2, 9])
        self.assertEqual(result['classes'][9]['uperm_nibble'], 2)
        self.assertEqual(result['classes'][9]['pperm_nibble'], 2)
        self.assertEqual(result['classes'][2]['pperm_nibble'], 10)
        copy = result['kernel_data_copy']
        self.assertEqual(int(copy['changed_pperm'], 16) ^
                         int(result['registers']['PPERM'], 16), 0x100)
        self.assertEqual((copy['selector'], copy['before_nibble'],
                          copy['write_nibble'], copy['restored_nibble']), (2, 10, 11, 10))
        aperture = result['rozone_aperture']
        self.assertEqual((aperture['frame_type'], aperture['name'],
                          aperture['file_selector'], aperture['initialized_selector']),
                         (25, 'XNU_ROZONE', 0, 2))
        self.assertEqual(aperture['runtime_selector_offset'], 0x79)
        self.assertEqual(aperture['retype_permission_argument'], 3)

    def test_each_corrupt_witness_is_rejected(self):
        for name, base in [('SPTM_WORDS', contract['SPTM_BASE']),
                           ('KERNEL_WORDS', contract['KERNEL_BASE'])]:
            witnesses = contract[name]
            words = {base | address: word for address, word in witnesses}
            for address in words:
                for bit in range(32):
                    corrupted = dict(words)
                    corrupted[address] ^= 1 << bit
                    with self.subTest(image=name, address=hex(address), bit=bit):
                        with self.assertRaisesRegex(ValueError, 'instruction mismatch'):
                            contract['require_words'](corrupted.__getitem__, base, witnesses)

    def test_movk_requires_complete_incoming_independence(self):
        # MOVK x0,#0x1234 leaves three unknown halfwords. All four halfwords
        # or an initial MOVZ are required before calling the result a constant.
        words = [0xf2824680]
        with self.assertRaisesRegex(ValueError, 'unobserved incoming'):
            contract['mov_wide'](lambda address: words[address // 4], 0, 1, 0)
        words = [0xd2824680, 0xf2aacf00]
        self.assertEqual(contract['mov_wide'](lambda address: words[address // 4], 0, 2, 0),
                         0x56781234)
        with self.assertRaisesRegex(ValueError, 'expected register'):
            contract['mov_wide'](lambda address: words[address // 4], 0, 2, 1)
        with self.assertRaisesRegex(ValueError, 'expected register'):
            contract['mov_wide'](lambda address: 0xd503201f, 0, 1, 0)


if __name__ == '__main__':
    unittest.main()
