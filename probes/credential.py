# SPDX-License-Identifier: MIT
"""Select the pinned AppleCredentialManager's existing software command path.

This is a virtual-board boot policy, not SEP emulation or hardware-backed
credentials. The caller has already hash-qualified the complete kernelcache.
"""
import struct

WITNESSES = (
    (0xfffffe0008f60608, 0x90ff2280),
    (0xfffffe0008f6060c, 0x91265400),
    (0xfffffe0008f60610, 0x12800001),
    (0xfffffe0008f60614, 0x97fffde7),
    (0xfffffe0008f60634, 0x3100067f),
    (0xfffffe0008f60638, 0x1a930008),
    (0xfffffe0008f6063c, 0x7100051f),
    (0xfffffe0008f60640, 0x1a9f17e9),
    (0xfffffe0008f60644, 0x392946a9),
    (0xfffffe0008f60788, 0x97ffff95),
    (0xfffffe0008f6078c, 0x52000000),
    (0xfffffe0008f5a760, 0x94001806),
    (0xfffffe0008f5a78c, 0x36000575),
    (0xfffffe0008f5b8b0, 0x940013b2),
    (0xfffffe0008f5b8b4, 0x340001c0),
    (0xfffffe0008f5b974, 0x97fe9569),
)


def software_cmdline(image, tree, cmdline):
    """Require the no-SEP RAM-image policy and audited native dispatch branch."""
    if any(arg.split('=', 1)[0] == 'acm_fastsim' for arg in cmdline.split()):
        raise ValueError('credential mode must be selected only by the guest profile')
    for name in ('protected-data-access', 'sepfw-load-at-boot'):
        if tree.get('/device-tree/chosen', name) != bytes(4):
            raise ValueError('software credentials require the explicit no-SEP boot policy')

    def read(va, size):
        matches = [(offset+va-base, name) for name, base, _, offset, length in image.segments
                   if base <= va and va+size <= base+length]
        if len(matches) != 1:
            raise ValueError('credential witness has no unique file-backed segment')
        offset, _ = matches[0]
        data = image.data[offset:offset+size]
        if len(data) != size:
            raise ValueError('truncated credential witness')
        return data

    for va, word in WITNESSES:
        if read(va, 4) != struct.pack('<I', word):
            raise ValueError(f'credential software-path witness differs at {va:#x}')
    literal = b'acm_fastsim\0'
    if read(0xfffffe00073b0995, len(literal)) != literal:
        raise ValueError('credential boot-argument literal differs')
    return cmdline+' acm_fastsim=1'
