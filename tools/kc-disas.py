#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Disassemble a range of a kernelcache by virtual address.

Reading the boot path is how the entry contract gets established, and doing it
by hand through a hex dump is where mistakes come from. This resolves VA to file
offset through the segment table, runs llvm-mc, and puts the address back on
every line -- plus the resolved target of every branch and `adrp`, which is the
part that actually matters when the question is "what memory does this touch".

    tools/kc-disas.py <kernelcache> 0xfffffe000c264000 --count 48
    tools/kc-disas.py <kernelcache> 0xfffffe000c26858c --until-ret
"""
import argparse
import pathlib
import struct
import subprocess
import sys

LLVM_MC = '/opt/homebrew/opt/llvm/bin/llvm-mc'
LC_SEGMENT_64 = 0x19
RET = 0xD65F03C0
RETAB = 0xD65F0FFF
# llvm-mc has no idea what these are and decodes genter as `b #0x8`, which is
# actively misleading in a listing of the boot path.
APPLE = {0x00201420: 'genter', 0x00201400: 'gexit', 0xD4E00000: '<apple alt-call>'}


def segments(data):
    _, _, _, _, ncmds = struct.unpack_from('<IiiII', data, 0)
    out, off = [], 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, off)
        if cmd == LC_SEGMENT_64:
            name = data[off + 8:off + 24].rstrip(b'\0').decode()
            out.append((name,) + struct.unpack_from('<QQQQ', data, off + 24))
        off += size
    return out


def locate(segs, va):
    for name, vmaddr, vmsize, fileoff, filesize in segs:
        if vmaddr <= va < vmaddr + min(vmsize, filesize):
            return name, fileoff + (va - vmaddr)
    return None, None


def targets(word, va):
    """Where this instruction points, if anywhere. Branches and adrp only."""
    top = word >> 26
    if top in (0x05, 0x25):                                  # b / bl
        imm = word & 0x3FFFFFF
        if imm & (1 << 25):
            imm -= 1 << 26
        return va + imm * 4
    if (word & 0x7C000000) == 0x14000000:
        return None
    if (word & 0xFF000000) in (0x54000000,):                 # b.cond
        imm = (word >> 5) & 0x7FFFF
        if imm & (1 << 18):
            imm -= 1 << 19
        return va + imm * 4
    if (word & 0x7E000000) == 0x34000000:                    # cbz / cbnz
        imm = (word >> 5) & 0x7FFFF
        if imm & (1 << 18):
            imm -= 1 << 19
        return va + imm * 4
    if (word & 0x9F000000) == 0x90000000:                    # adrp
        immlo, immhi = (word >> 29) & 3, (word >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        return (va & ~0xFFF) + (imm << 12)
    return None


def decode(words):
    """One text line per word, always -- which llvm-mc does not guarantee.

    An encoding it cannot decode produces a warning on stderr and *nothing* on
    stdout, so a single batch call returns fewer lines than instructions and
    every line after the first bad one is attributed to the wrong address. That
    is worse than no listing: the bytes are right there in the output, so the
    mistake reads as a real instruction at a real address, and this file's whole
    purpose is establishing what the boot path does.

    Decoding one instruction per process would be correct and slow. Bisecting
    the range instead isolates each bad encoding in O(k log n) calls, and in
    practice k is small enough that the first call usually succeeds outright."""
    if not words:
        return []
    text = ' '.join(f'0x{b:02x}' for w in words for b in struct.pack('<I', w))
    proc = subprocess.run([LLVM_MC, '--disassemble', '--triple=aarch64',
                           # apple-m1 for the PAC encodings the boot path is
                           # full of; without it `paciza` is simply dropped.
                           '--mcpu=apple-m1', '--print-imm-hex'],
                          input=text, capture_output=True, text=True)
    lines = [l.strip() for l in proc.stdout.splitlines()
             if l.strip() and not l.strip().startswith('.')]
    if len(lines) == len(words):
        return lines
    if len(words) == 1:
        return [f'<unknown {words[0]:#010x}>']
    mid = len(words) // 2
    return decode(words[:mid]) + decode(words[mid:])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('kernelcache')
    ap.add_argument('address', type=lambda v: int(v, 0))
    ap.add_argument('--count', type=int, default=32)
    ap.add_argument('--until-ret', action='store_true',
                    help='stop at the first ret/retab instead of after --count')
    args = ap.parse_args()

    data = pathlib.Path(args.kernelcache).read_bytes()
    segs = segments(data)
    name, offset = locate(segs, args.address)
    if offset is None:
        raise SystemExit(f'{args.address:#x} is not inside any segment')

    words, va = [], args.address
    limit = 4096 if args.until_ret else args.count
    for i in range(limit):
        word = struct.unpack_from('<I', data, offset + i * 4)[0]
        words.append(word)
        if args.until_ret and word in (RET, RETAB):
            break

    lines = decode(words)

    print(f'{args.address:#018x}  ({name}, file {offset:#x}, {len(words)} instructions)')
    for i, word in enumerate(words):
        here = va + i * 4
        text = APPLE.get(word) or lines[i]
        tail = ''
        target = None if word in APPLE else targets(word, here)
        if target is not None:
            segment, _ = locate(segs, target)
            tail = f'   ; {target:#x}' + (f' ({segment})' if segment else ' (unmapped)')
        print(f'  {here:#018x}  {word:08x}  {text:<40}{tail}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
