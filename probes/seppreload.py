# SPDX-License-Identifier: MIT
"""Profile-bound SEP firmware bytes for the native IOKit preload entry.

This supplies memory owned by the guest boot handoff. It does not authenticate
or execute SEP firmware, publish endpoints, or change native driver state.
"""
from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct

MEMORY_MAP = '/device-tree/chosen/memory-map'
WITNESSES = (
    (0xfffffe00099b3d74, 0x91202021),  # sepfw-loaded literal
    (0xfffffe00099b3d88, 0xd73f0931),  # provider property search
    (0xfffffe00099b3d8c, 0xb40000a0),  # absent property skips preload
    (0xfffffe00099b3d94, 0x52800001),  # native payload type 0
    (0xfffffe00099b3d98, 0x94003e3d),  # fromPreload(mapper, type)
    (0xfffffe00099b3d9c, 0xf9007260),  # manager firmware object
    (0xfffffe00099c3724, 0x94000153),  # SEPFW descriptor/mapping
    (0xfffffe00099c372c, 0x94000167),  # paired optional TBM inputs
    (0xfffffe00099c377c, 0x1400041a),  # native DMA preparation
)


@dataclass(frozen=True)
class SEPPreloadSpec:
    node: str
    compatible: bytes
    filename: str
    sha256: str
    size: int


def dma_contract(built, spec, expected_base):
    """Bind the monitor's separate DMA resource to the exact uploaded payload.

    It is never part of allocator/disposable boot memory. Neither a tree
    descriptor alone nor an arbitrary lower physical bound grants ownership.
    """
    extent=built.get('sep_preload_range')
    tree=built.get('dt')
    descriptor=tree.get(MEMORY_MAP,'SEPFW') if tree is not None else None
    if spec is None:
        if extent is not None or descriptor is not None:
            raise ValueError('unselected SEP DMA resource')
        return [0,0]
    if (not isinstance(extent,(tuple,list)) or len(extent)!=2 or
            any(type(v) is not int for v in extent)):
        raise ValueError('missing SEP DMA resource extent')
    pa,size=extent
    if (pa!=expected_base or size!=spec.size or not 0<size<=0x1000000 or
            (pa|size)&0x3fff or not built['frame_low']<=pa<pa+size<=built['alloc_low'] or
            built['alloc_low']>built['frame_high']):
        raise ValueError('SEP DMA resource outside exact preload reservation')
    disk=built.get('ramdisk_range')
    if disk is not None and pa+size>disk[0]:
        raise ValueError('SEP DMA resource overlaps root media')
    payload=built['chunks'].get(pa)
    if (payload is None or len(payload)!=size or hashlib.sha256(payload).hexdigest()!=spec.sha256 or
            descriptor!=struct.pack('<QQ',pa,size) or tree.get(spec.node,'sepfw-loaded')!=b''):
        raise ValueError('SEP DMA resource differs from verified payload/tree')
    return [pa,size]


def prepare(tree, image, spec, directory, base, end):
    """Validate all inputs before adding the presence flag and physical extent.

The caller places this after fixed reservations and before its root media,
and includes the returned chunk before computing topOfKernelData. The two
optional TBM regions are absent together, matching the native non-TBM branch.
"""
    if type(base) is not int or type(end) is not int or base < 0 or base % 0x4000:
        raise ValueError('invalid SEP preload physical placement')
    if not 0 < spec.size <= 0x1000000 or spec.size % 0x4000:
        raise ValueError('invalid SEP preload size')
    if not base < base+spec.size <= end-0x8000000 or end > 1 << 36:
        raise ValueError('SEP preload leaves insufficient owned allocator memory')
    if Path(spec.filename).name != spec.filename:
        raise ValueError('SEP preload filename must stay in its firmware bundle')
    prop = tree.nodes.get(spec.node, {}).get('compatible')
    if prop is None or prop.placeholder or spec.compatible not in prop.value.split(b'\0'):
        raise ValueError('unsupported SEP preload provider')
    if MEMORY_MAP not in tree.nodes:
        raise ValueError('SEP preload requires the chosen memory map')
    for node, name in [(spec.node, 'sepfw-loaded')] + [
            (MEMORY_MAP, n) for n in ('SEPFW', 'SEPPatches', 'uStuff')]:
        if name in tree.nodes[node]:
            raise ValueError(f'conflicting SEP preload property {name}')
    for address, word in WITNESSES:
        matches = [off+address-va for _, va, _, off, size in image.segments
                   if va <= address and address+4 <= va+size]
        if len(matches) != 1 or image.data[matches[0]:matches[0]+4] != struct.pack('<I', word):
            raise ValueError(f'SEP preload witness differs at {address:#x}')
    with (Path(directory)/spec.filename).open('rb') as stream:
        payload = stream.read(spec.size+1)
    if len(payload) != spec.size or hashlib.sha256(payload).hexdigest() != spec.sha256:
        raise ValueError('SEP preload payload does not match the selected profile')
    tree.add(MEMORY_MAP, 'SEPFW', struct.pack('<QQ', base, len(payload)))
    tree.add(spec.node, 'sepfw-loaded', b'')
    return payload
