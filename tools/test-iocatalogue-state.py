#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Publication reader bounds, type and identity checks; no target access."""
from pathlib import Path
import runpy
import struct
import unittest

API = runpy.run_path(str(Path(__file__).with_name('iocatalogue-state.py')))


class CatalogueTests(unittest.TestCase):
    def setUp(self):
        self.words = dict(API['WITNESSES'])
        self.memory = {}
        self.reads = []
        self.next = 0xfffffe0010000000
        self.vtables = {0xfffffe0008000000+i*0x100: name for i, name in enumerate(
            ('IOCatalogue', 'OSDictionary', 'OSArray', 'OSString', 'OSSymbol', 'OSNumber'))}
        self.addresses = {name: address for address, name in self.vtables.items()}
        personality = self.dictionary([
            ('CFBundleIdentifier', self.string('com.apple.iokit.IOGraphicsFamily')),
            ('IOClass', self.string('IOBootFramebuffer')),
            ('IOProviderClass', self.string('AppleARMIODevice')),
            ('IONameMatch', self.array([self.string('snapintosh,boot-framebuffer')]))])
        other = self.dictionary([('IOClass', self.string('AppleCLCD2'))])
        self.bucket = self.array([personality, other])
        self.matching = self.dictionary([('AppleARMIODevice', self.bucket)])
        self.catalogue = self.object('IOCatalogue')
        self.put(self.catalogue+24, struct.pack('<I', 7))
        self.q(self.catalogue+32, self.matching)
        self.q(API['SLOT'], self.catalogue)

    def alloc(self, size=0x40):
        address = self.next
        self.next += (size+15) & ~15
        self.put(address, bytes(size))
        return address

    def put(self, address, raw):
        self.memory.update((address+i, value) for i, value in enumerate(raw))

    def q(self, address, value):
        self.put(address, struct.pack('<Q', value))

    def object(self, name):
        address = self.alloc()
        self.q(address, self.addresses[name])
        return address

    def string(self, text):
        obj = self.object('OSString')
        raw = text.encode()+b'\0'
        # Native no-copy strings may point at unaligned string-pool bytes.
        storage = self.alloc(len(raw)+3)+3
        self.put(storage, raw)
        self.put(obj+12, struct.pack('<I', len(raw) << 14))
        self.q(obj+16, storage)
        return obj

    def collection(self, name, raw, count):
        obj = self.object(name)
        storage = self.alloc(max(1, len(raw)))
        self.put(storage, raw)
        self.put(obj+20, struct.pack('<2I', count, count))
        self.q(obj+32, storage)
        return obj

    def array(self, values):
        return self.collection('OSArray', b''.join(struct.pack('<Q', value) for value in values), len(values))

    def dictionary(self, entries):
        pairs = [(self.string(key), value) for key, value in entries]
        return self.collection('OSDictionary', b''.join(struct.pack('<2Q', *pair) for pair in pairs), len(pairs))

    def read(self, address, size):
        self.reads.append((address, size))
        return bytes(self.memory[address+i] for i in range(size))

    def collect(self, **kwargs):
        return API['collect'](self.read, self.words.__getitem__, self.vtables, **kwargs)

    def test_published_personalities_and_unaligned_text_storage(self):
        result = self.collect()
        self.assertTrue(result['complete'])
        self.assertEqual(result['generation'], 7)
        self.assertEqual(result['personality_count'], 2)
        self.assertEqual(result['selected_personalities'][0]['fields']['IOClass'], 'IOBootFramebuffer')
        self.assertEqual(result['selected_personalities'][0]['fields']['IONameMatch'],
                         ['snapintosh,boot-framebuffer'])
        self.assertEqual(result['unclassified_io_class'], [])

    def test_all_native_witnesses_fail_before_read(self):
        for address, word in API['WITNESSES']:
            self.words[address] = word ^ 1
            with self.assertRaisesRegex(ValueError, 'witness'):
                self.collect()
            self.words[address] = word
        self.assertEqual(self.reads, [])

    def test_large_native_name_match_array(self):
        names = [f'compatible-{i}' for i in range(96)]
        personality = self.dictionary([
            ('IOClass', self.string('IOBootFramebuffer')),
            ('IONameMatch', self.array([self.string(name) for name in names]))])
        self.q(self.catalogue+32, self.dictionary([
            ('AppleARMIODevice', self.array([personality]))]))
        result = self.collect()
        self.assertTrue(result['complete'])
        self.assertEqual(result['selected_personalities'][0]['fields']['IONameMatch'], names)

    def test_missing_catalogue_is_incomplete(self):
        self.q(API['SLOT'], 0)
        self.assertFalse(self.collect()['complete'])

    def test_wrong_collection_type_and_count_refused(self):
        self.q(self.catalogue+32, self.bucket)
        with self.assertRaisesRegex(ValueError, 'OSDictionary'):
            self.collect()
        self.q(self.catalogue+32, self.matching)
        self.put(self.bucket+20, struct.pack('<2I', 20000, 20000))
        with self.assertRaisesRegex(ValueError, 'bounds'):
            self.collect()

    def test_duplicate_text_key_refused(self):
        duplicate = self.dictionary([('AppleARMIODevice', self.bucket), ('AppleARMIODevice', self.bucket)])
        self.q(self.catalogue+32, duplicate)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            self.collect()

    def test_personality_and_byte_budgets(self):
        with self.assertRaisesRegex(ValueError, 'personality count'):
            self.collect(max_personalities=1)
        huge = self.dictionary([('IOClass', self.string('X'*4094))])
        self.q(self.catalogue+32, self.dictionary([('AppleARMIODevice', self.array([huge]))]))
        with self.assertRaisesRegex(ValueError, 'byte budget'):
            self.collect(max_bytes=4096)

    def test_unknown_class_value_preserved_as_unclassified(self):
        personality = self.dictionary([('IOClass', self.object('OSNumber'))])
        self.q(self.catalogue+32, self.dictionary([('AppleARMIODevice', self.array([personality]))]))
        result = self.collect()
        self.assertEqual(result['selected_personalities'], [])
        self.assertEqual(result['unclassified_io_class'], [hex(personality)])


if __name__ == '__main__':
    unittest.main()
