# SPDX-License-Identifier: MIT
"""Image-pinned admission for native monitor calls in J700 26A428.

The parameter ABI retains eight page slots: five call pages followed by the
two pages containing physical EL1 exception-register writes. The high count bit
opts into the matching monitor build. Stock mode never patches instructions;
the separately admitted HVC experiment replaces only the 348 private call words.
"""
import hashlib
import struct

FLAG = 1 << 63
HVC_FLAG = 1 << 62
HVC_IMMEDIATE = 0x5350
HVC_WORD = 0xd4000002 | HVC_IMMEDIATE << 5
KERNEL_SHA256 = 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
CALL_WORDS = (0x00201420, 0xd4e00000)
WRITER_WORDS = (0xd5184000, 0xd5184020)


def contract(image, data, image_pa, *, hvc=False):
    if type(hvc) is not bool:
        raise ValueError('HVC admission must be an explicit boolean')
    if hashlib.sha256(image.data).hexdigest() != KERNEL_SHA256 or len(data) != len(image.data):
        raise ValueError('native calls require the unchanged J700 26A428 kernel')
    calls, writers = {}, {}
    for name, va, _, off, size in image.executable_segments:
        if not size:
            continue
        if (va | off | size) & 3 or off + size > len(data):
            raise ValueError('unaligned/incomplete native-call text scan')
        expected = bytearray(image.data[off:off+size])
        if hvc:
            for delta in range(0, size, 4):
                if struct.unpack_from('<I', expected, delta)[0] in CALL_WORDS:
                    struct.pack_into('<I', expected, delta, HVC_WORD)
        if data[off:off+size] != expected:
            raise ValueError('native-call executable bytes were modified')
        for delta in range(0, size, 4):
            word = struct.unpack_from('<I', image.data, off + delta)[0]
            address = va + delta
            if word in CALL_WORDS:
                calls[address] = word
            if word & ~31 in WRITER_WORDS:
                writers[address] = word
    call_pages = sorted({va & ~4095 for va in calls})
    writer_pages = sorted({va & ~4095 for va in writers})
    if (len(call_pages), len(writer_pages), len(calls), len(writers)) != (5, 2, 348, 10):
        raise ValueError('native-call/writer closure differs from qualified firmware')
    if set(call_pages) & set(writer_pages):
        raise ValueError('native-call and exception-writer pages overlap')
    return dict(kernel_sha256=KERNEL_SHA256, mode='hvc' if hvc else 'private',
                loaded_data_sha256=hashlib.sha256(data).hexdigest(),
                hvc_immediate=HVC_IMMEDIATE if hvc else None,
                hvc_word=HVC_WORD if hvc else None,
                call_sites=calls, writer_sites=writers,
                call_pages=call_pages, writer_pages=writer_pages,
                pages=[image_pa + va - image.vmin for va in call_pages + writer_pages])


def patch_hvc_calls(image, data, image_pa):
    """Patch a validated stock-derived loaded image; never modify the source file."""
    admitted = contract(image, data, image_pa)
    for _, va, _, off, size in image.executable_segments:
        for address in admitted['call_sites']:
            if va <= address < va + size:
                struct.pack_into('<I', data, off + address - va, HVC_WORD)
    return contract(image, data, image_pa, hvc=True)


def count_word(stubs, enabled, hvc=False):
    if type(enabled) is not bool or type(hvc) is not bool:
        raise ValueError('native-call admission must be an explicit boolean')
    if hvc and not enabled:
        raise ValueError('HVC calls require native-call admission')
    if not 0 <= len(stubs) <= 8 or len(set(stubs)) != len(stubs) or any(p & 4095 for p in stubs):
        raise ValueError('invalid monitor/exception page list')
    if enabled and len(stubs) != 7:
        raise ValueError('native-call mode requires the complete seven-page contract')
    return len(stubs) | (FLAG if enabled else 0) | (HVC_FLAG if hvc else 0)
