#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Which q1n1 stage build the launch binds (probes/stagebind.py), and the native
Image4 install that depends on it (probes/txmnative.py). No hardware.

Generation70 stopped in the loader with "native Image4 refused: resident stage
differs from its ELF". The resident stage was the early-stop pair, and the loader
only knew the regular pair's ELF. These tests use the real regular build
(../q1n1/build/uefi) and consistent copies of it that stand in for a pair built
elsewhere. They check four things:

- each pair binds only to its own build, named in SNAP_STAGE_BUILDS;
- every text byte but the patched configuration word counts;
- a build's binary must be exactly its ELF's image;
- two different builds never bind at once.

The real early-stop pair (../q1n1-early-stop/build/uefi), when present, is checked
the same way. The install runs against a model of the proxy's memory.

    python3 tools/test-stagebind.py
"""
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import stagebind                                               # noqa: E402
import txmnative                                               # noqa: E402

REGULAR = ROOT.parent / 'q1n1/build/uefi'
EARLY_STOP = ROOT.parent / 'q1n1-early-stop/build/uefi'
STAGE_BASE, STAGE_SIZE = 0xb0000000, 0x1000000
SLOTS = {'': STAGE_BASE, '-alt': STAGE_BASE + STAGE_SIZE // 2}


def info_for(image_base, stage_base=STAGE_BASE):
    return dict(stage_base=stage_base, stage_size=STAGE_SIZE, image_base=image_base, current_el=2,
                stage_generation=72, heap_base=0xb9e1f000, heap_size=64 << 20)


class Memory:
    """The target as the proxy shows it: a build's text chainloaded into its slot
    (configuration word patched), plus whatever the host writes."""

    def __init__(self, build, suffix, word=b'\x5a' * 8):
        text = bytearray(stagebind.image(build, suffix)['text'])
        text[stagebind.CONFIG_WORD] = word
        self.base, self.text, self.written, self.calls = SLOTS[suffix], text, {}, []

    def readmem(self, address, size):
        if address == self.base and size <= len(self.text):
            return bytes(self.text[:size])
        for start, data in self.written.items():
            if start <= address and address + size <= start + len(data):
                return data[address - start:address - start + size]
        return bytes(size)

    def writemem(self, address, data):
        self.written[address] = bytes(data)

    def flush_code(self, address, size):
        pass

    def set_exc_guard(self, mode):
        pass

    def call(self, address, *args, timeout=None):
        self.calls.append(address)
        return 0

    def get_exc_count(self):
        return 0

    def stage_features(self):
        return 1

    def serror_state(self):
        return dict(before=0, during=0, unconsumed=0)


def clone(into, text_flip=None, rodata_flip=None, bin_flip=None):
    """A copy of the regular build changed consistently in its ELF and binary, as a
    build of other sources would be; `bin_flip` breaks only the binary."""
    for suffix in ('', '-alt'):
        elf = bytearray((REGULAR / f'stage/hardware{suffix}.elf').read_bytes())
        flat = bytearray((REGULAR / f'q1n1-stage{suffix}.bin').read_bytes())
        sections = stagebind.elf_sections(bytes(elf))
        base = sections['.text'][3]
        for name, offset in (('.text', text_flip), ('.rodata', rodata_flip)):
            if offset is not None:
                section = sections[name]
                elf[section[4] + offset] ^= 0xff
                flat[section[3] - base + offset] ^= 0xff
        if bin_flip is not None:
            flat[bin_flip] ^= 0xff
        (into / 'stage').mkdir(parents=True, exist_ok=True)
        (into / f'stage/hardware{suffix}.elf').write_bytes(elf)
        (into / f'q1n1-stage{suffix}.bin').write_bytes(flat)
    return into


@unittest.skipUnless((REGULAR / 'stage/hardware-alt.elf').exists(), 'no regular q1n1 stage build')
class Binding(unittest.TestCase):
    def setUp(self):
        self.scratch = Path(tempfile.mkdtemp(prefix='stagebind-'))
        self.addCleanup(shutil.rmtree, self.scratch)
        environment = mock.patch.dict(os.environ, {stagebind.ENVIRONMENT: ''})
        environment.start()
        self.addCleanup(environment.stop)
        self.other = clone(self.scratch / 'other/build/uefi', text_flip=0x400)

    def test_regular_pair_binds_in_both_slots(self):
        for suffix, base in SLOTS.items():
            bound = stagebind.bind(Memory(REGULAR, suffix).readmem, info_for(base))
            self.assertEqual(bound['build'], REGULAR.resolve())
            self.assertEqual(bound['bin_path'].name, f'q1n1-stage{suffix}.bin')

    def test_another_pair_binds_only_through_its_own_build(self):
        memory = Memory(self.other, '-alt')
        with self.assertRaisesRegex(ValueError, 'resident stage differs from its ELF.*text differs'):
            stagebind.bind(memory.readmem, info_for(SLOTS['-alt']))
        self.assertEqual(stagebind.bind(memory.readmem, info_for(SLOTS['-alt']), [self.other])['build'],
                         self.other.resolve())
        with mock.patch.dict(os.environ, {stagebind.ENVIRONMENT: os.pathsep.join(['/nonexistent', str(self.other)])}):
            self.assertEqual(stagebind.bind(memory.readmem, info_for(SLOTS['-alt']))['build'], self.other.resolve())
            # Naming the other pair does not stop the regular one from binding.
            regular = Memory(REGULAR, '-alt')
            self.assertEqual(stagebind.bind(regular.readmem, info_for(SLOTS['-alt']))['build'], REGULAR.resolve())

    def test_every_text_byte_but_the_configuration_word_counts(self):
        for offset in (0, 23, 32, 0x400):
            memory = Memory(self.other, '-alt')
            memory.text[offset] ^= 0x01
            with self.assertRaises(ValueError, msg=offset):
                stagebind.bind(memory.readmem, info_for(SLOTS['-alt']), [self.other])
        for word in (bytes(8), b'\xff' * 8):
            memory = Memory(self.other, '-alt', word)
            self.assertEqual(stagebind.bind(memory.readmem, info_for(SLOTS['-alt']), [self.other])['build'],
                             self.other.resolve())

    def test_the_binary_must_be_its_elf(self):
        broken = clone(self.scratch / 'broken/build/uefi', text_flip=0x400, bin_flip=0x20000)
        with self.assertRaisesRegex(ValueError, 'is not the image of'):
            stagebind.bind(Memory(self.other, '-alt').readmem, info_for(SLOTS['-alt']), [self.other, broken])

    def test_two_different_builds_never_bind_at_once(self):
        twin = clone(self.scratch / 'twin/build/uefi', text_flip=0x400, rodata_flip=0x10)
        memory = Memory(self.other, '-alt')
        with self.assertRaisesRegex(ValueError, 'matches different stage builds'):
            stagebind.bind(memory.readmem, info_for(SLOTS['-alt']), [self.other, twin])
        self.assertEqual(stagebind.bind(memory.readmem, info_for(SLOTS['-alt']), [self.other, self.other / '.'])['build'],
                         self.other.resolve())

    def test_slot_and_link_address(self):
        with self.assertRaisesRegex(ValueError, 'unknown resident stage slot'):
            stagebind.bind(Memory(REGULAR, '').readmem, info_for(STAGE_BASE + 0x1000))
        with self.assertRaises(ValueError):          # the primary slot binds hardware.elf only
            stagebind.bind(Memory(REGULAR, '-alt').readmem, info_for(STAGE_BASE))
        with self.assertRaisesRegex(ValueError, 'linked for 0xb0000000'):
            stagebind.bind(Memory(REGULAR, '').readmem, info_for(0x4c000000, stage_base=0x4c000000))

    @unittest.skipUnless((EARLY_STOP / 'stage/hardware-alt.elf').exists(), 'no early-stop q1n1 stage build')
    def test_the_real_early_stop_pair(self):
        # Generation70's resident stage: refused without its build, bound with it.
        for suffix, base in SLOTS.items():
            memory = Memory(EARLY_STOP, suffix)
            with self.assertRaisesRegex(ValueError, 'resident stage differs from its ELF'):
                stagebind.bind(memory.readmem, info_for(base))
            with mock.patch.dict(os.environ, {stagebind.ENVIRONMENT: str(EARLY_STOP)}):
                self.assertEqual(stagebind.bind(memory.readmem, info_for(base))['build'], EARLY_STOP.resolve())


@unittest.skipUnless((REGULAR / 'stage/hardware-alt.elf').exists(), 'no regular q1n1 stage build')
class NativeImage4(unittest.TestCase):
    """txmnative.install with a stand-in helper image of the qualified size."""

    def setUp(self):
        self.scratch = Path(tempfile.mkdtemp(prefix='stagebind-install-'))
        self.addCleanup(shutil.rmtree, self.scratch)
        self.other = clone(self.scratch / 'other/build/uefi', text_flip=0x400)
        self.helper = self.scratch / 'image4.bin'
        self.helper.write_bytes(bytes(range(256)) * (txmnative.IMAGE_BYTES // 256) +
                                bytes(txmnative.IMAGE_BYTES % 256))
        for name, value in (('IMAGE_SHA', hashlib.sha256(self.helper.read_bytes()).hexdigest()),):
            patch = mock.patch.object(txmnative, name, value)
            patch.start()
            self.addCleanup(patch.stop)

    def install(self, memory, environment=''):
        with mock.patch.dict(os.environ, {stagebind.ENVIRONMENT: environment}):
            return txmnative.install(memory, info_for(memory.base), self.helper, b'tree' * 64, 0xae1000000)

    def test_another_pair_needs_its_build_named(self):
        memory = Memory(self.other, '-alt')
        with self.assertRaisesRegex(ValueError, 'resident stage differs from its ELF'):
            self.install(memory)
        self.assertEqual(memory.calls, [], 'nothing was executed before the refusal')
        _, record = self.install(memory, str(self.other))
        self.assertEqual(Path(record['stage_build']), self.other.resolve())
        self.assertEqual(record['stage_bin_sha256'], stagebind.image(self.other, '-alt')['bin_sha256'])
        self.assertEqual(memory.calls, [txmnative.HELPER_BASE])
        self.assertEqual(memory.written[txmnative.HELPER_BASE], self.helper.read_bytes())

    def test_regular_pair_unchanged(self):
        memory = Memory(REGULAR, '-alt')
        _, record = self.install(memory)
        self.assertEqual(Path(record['stage_build']), REGULAR.resolve())
        self.assertEqual(record['stage_elf_sha256'], stagebind.image(REGULAR, '-alt')['elf_sha256'])

    def test_helper_may_not_overlap_the_bound_stage(self):
        memory = Memory(REGULAR, '')
        with mock.patch.object(txmnative, 'HELPER_BASE', STAGE_BASE + 0x4000):
            with self.assertRaisesRegex(ValueError, 'overlaps resident stage'):
                self.install(memory)
        self.assertEqual(memory.calls, [])


if __name__ == '__main__':
    unittest.main()
