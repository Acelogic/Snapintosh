# SPDX-License-Identifier: MIT
"""Which local q1n1 build is the resident stage? Bind it by its text.

Snapintosh puts native code into the q1n1 stage reservation (txmnative.py at
launch; the SSD write-back and TXM Image4 qualification probes by hand). Before
doing so it has to know the resident stage exactly. The stage's .text must equal
the .text of a local ELF linked for the slot it runs in, in every byte except the
configuration word that the chainload client patches after upload (text bytes
24..32).

Each candidate is one make-uefi output directory, holding q1n1-stage[-alt].bin
and stage/hardware[-alt].elf. The regular pair, ../q1n1/build/uefi, is always
tried first. A stage pair built elsewhere, such as the early-stop pair in
../q1n1-early-stop/build/uefi, is bound through its own directory: either a
caller names it, or it is listed in SNAP_STAGE_BUILDS (os.pathsep separated).
The launch sets SNAP_STAGE_BUILDS from the candidate manifest's environment.

A directory binds only if its stage binary is exactly its ELF's loaded image.
If two different builds both match the resident text, nothing binds. These are
the same rules as q1n1's tools/nvme_hash.py bind_stage.
"""
import hashlib
import os
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT = 'SNAP_STAGE_BUILDS'
SHF_ALLOC, SHT_NOBITS = 2, 8
CONFIG_WORD = slice(24, 32)


def builds(extra=()):
    """The regular pair, then the caller's, then SNAP_STAGE_BUILDS, each once."""
    named = [ROOT.parent / 'q1n1/build/uefi', *extra,
             *(p for p in os.environ.get(ENVIRONMENT, '').split(os.pathsep) if p)]
    found = []
    for path in named:
        path = Path(path).resolve()
        if path not in found:
            found.append(path)
    return found


def elf_sections(elf):
    """{name: (name index, type, flags, address, offset, size, ...)} of an ELF64 LE image."""
    if elf[:6] != b'\x7fELF\x02\x01':
        raise ValueError('invalid stage ELF')
    shoff = struct.unpack_from('<Q', elf, 40)[0]
    stride, count, strings_index = struct.unpack_from('<3H', elf, 58)
    sections = [struct.unpack_from('<IIQQQQIIQQ', elf, shoff + i * stride) for i in range(count)]
    names = sections[strings_index]
    strings = elf[names[4]:names[4] + names[5]]
    return {strings[s[0]:].split(b'\0', 1)[0].decode(): s for s in sections}


def image(build, suffix):
    """One build's ELF for a slot, tied to the stage binary that build chainloads:
    the binary must be the ELF's loaded sections laid out flat from .text."""
    elf_path, bin_path = build / f'stage/hardware{suffix}.elf', build / f'q1n1-stage{suffix}.bin'
    elf, flat_bin = elf_path.read_bytes(), bin_path.read_bytes()
    sections = elf_sections(elf)
    text = sections.get('.text')
    if text is None:
        raise ValueError(f'{elf_path}: no .text')
    loaded = [s for s in sections.values() if s[2] & SHF_ALLOC and s[1] != SHT_NOBITS]
    base = text[3]
    if min(s[3] for s in loaded) != base:
        raise ValueError(f'{elf_path}: .text is not the first loaded section')
    flat = bytearray(max(s[3] + s[5] for s in loaded) - base)
    for s in loaded:
        flat[s[3] - base:s[3] - base + s[5]] = elf[s[4]:s[4] + s[5]]
    if flat_bin != bytes(flat):
        raise ValueError(f'{bin_path} is not the image of {elf_path}')
    allocated = [(name, s[2], s[3], s[5]) for name, s in sections.items() if s[2] & SHF_ALLOC]
    return dict(build=build, elf_path=elf_path, bin_path=bin_path, elf_sha256=hashlib.sha256(elf).hexdigest(),
                bin_sha256=hashlib.sha256(flat_bin).hexdigest(), text=elf[text[4]:text[4] + text[5]],
                text_address=text[3], allocated=allocated,
                allocated_end=max(address + size for _, _, address, size in allocated))


def bind(read, info, extra=()):
    """The build the resident stage came from, or ValueError.

    `read(address, size)` reads target memory (proxy.readmem); `info` is q1n1's
    bootinfo. The slot picks each build's ELF: hardware.elf at stage_base, and
    hardware-alt.elf in the upper half. A build that is absent, or linked for
    another image, is passed over."""
    slot = info['stage_size'] // 2
    if info['image_base'] not in (info['stage_base'], info['stage_base'] + slot):
        raise ValueError('unknown resident stage slot')
    suffix = '' if info['image_base'] == info['stage_base'] else '-alt'
    tried, matched, resident = [], [], {}
    for build in builds(extra):
        try:
            candidate = image(build, suffix)
        except FileNotFoundError:
            tried.append(f'{build}: no hardware{suffix} build')
            continue
        if candidate['text_address'] != info['image_base']:
            tried.append(f'{build}: linked for {candidate["text_address"]:#x}')
            continue
        size = len(candidate['text'])
        if size not in resident:
            resident[size] = bytes(read(info['image_base'], size))
        live = resident[size]
        expected = bytearray(candidate['text'])
        expected[CONFIG_WORD] = live[CONFIG_WORD]   # Named host-patched stage configuration word.
        if live != expected:
            tried.append(f'{build}: text differs')
            continue
        matched.append(dict(candidate, slot=slot, resident_text_sha256=hashlib.sha256(live).hexdigest()))
    if not matched:
        raise ValueError('resident stage differs from its ELF in every local stage build (' + '; '.join(tried) + ')')
    if len({m['bin_sha256'] for m in matched}) > 1 or len({m['allocated_end'] for m in matched}) > 1:
        raise ValueError('resident stage matches different stage builds: ' + ', '.join(str(m['build']) for m in matched))
    return matched[0]


def overlaps(stage, low, high):
    """Does [low, high) meet any allocated section of the bound stage?"""
    return any(address < high and low < address + size for _, _, address, size in stage['allocated'])
