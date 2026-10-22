# SPDX-License-Identifier: MIT
"""Virtual SEP ROM capture geometry, separate from SEPOS and biometrics."""
from dataclasses import dataclass
import struct


@dataclass(frozen=True)
class SEPBootSpec:
    node: str
    compatible: bytes
    nub: str
    nub_compatible: bytes
    rom_panic_bytes: int


def populate_sep_boot(dt, spec):
    """Publish bounded storage capacity for AppleSEPBooter's ROM messages.

    The stock 26A428 consumer requires a four-byte, 8-byte-aligned byte count
    and allocates its own word array. 424 bytes is a virtual-device capacity
    corroborated by a read-only Mac15,9 ADT capture. It is not the separate
    32 KiB CINP shared-memory buffer, SEP firmware, or authentication success.
    The separately bound ASC frontend can retain mailbox requests. SEPOS
    services and authenticated replies remain unimplemented.
    """
    size=spec.rom_panic_bytes
    if type(size) is not int or not 8<=size<=0x4000 or size%8:
        raise ValueError('SEP ROM capture must be a nonempty bounded array of u64 words')
    if spec.nub!=spec.node+'/iop-sep-nub':
        raise ValueError('unsupported SEP provider topology')
    for node,compatible in ((spec.node,spec.compatible),(spec.nub,spec.nub_compatible)):
        prop=dt.nodes.get(node,{}).get('compatible')
        if prop is None or prop.placeholder or compatible not in prop.value.split(b'\0'):
            raise ValueError(f'{node}: unsupported SEP binding')
    previous=dt.nodes[spec.nub].get('rom-panic-bytes')
    encoded=struct.pack('<I',size)
    if previous is not None and (previous.placeholder or previous.value!=encoded):
        raise ValueError('conflicting SEP ROM capture capacity')
    dt.put(spec.nub,'rom-panic-bytes',encoded)
    return size
