# SPDX-License-Identifier: MIT
"""Bounded stopped-state IOService graph capture for native J700 26A428.

No guest functions are called. Class names come from exact vtable symbols,
not guesses based on property strings. This proves registry state only.
"""
from collections import deque
import re
import struct

WITNESSES = (
    (0xfffffe000c0cf10c, 0xd0003b08),  # registry root
    (0xfffffe000c0cf110, 0xf943cd00),
    (0xfffffe000c0cf544, 0xf9400c00),  # fRegistryTable
    (0xfffffe000c0cf548, 0xf9401021),  # plane child-links key
    (0xfffffe000c0cf588, 0xf9401000),  # fPropertyTable
    (0xfffffe000c0c8cd4, 0xf9401681),  # plane name key
    (0xfffffe000c0c8d24, 0xf9464901),  # gIONameKey
    (0xfffffe000c04a370, 0xb9401408),  # OSArray count
    (0xfffffe000c04a37c, 0xf8420c10),  # OSArray storage
    (0xfffffe000c050d44, 0xb9401409),  # OSDictionary count
    (0xfffffe000c050d5c, 0xf8420c10),  # OSDictionary storage
    (0xfffffe000c050d78, 0xd37c7d6c),  # 16-byte dictionary entries
    (0xfffffe000c0856f8, 0xb9400c08),  # OSString length word
    (0xfffffe000c0856fc, 0x530e7d08),  # length includes NUL, shifted14
    (0xfffffe000c08565c, 0xf8410c10),  # OSString storage
    (0xfffffe000c0e32e4, 0xb9404800),  # IOService state
    (0xfffffe000c0dcd04, 0xb9404e9a),  # startMatching reads state[1]
    (0xfffffe000c0dcd08, 0x52b00048),  # NeedConfig | ConfigRunning
    (0xfffffe000c0dcd0c, 0x6a08035f),
    (0xfffffe000c0da3cc, 0xb9404c08),  # getBusyState: state[1]
    (0xfffffe000c0da3d0, 0x12002500),  # native busy-count mask
)
ROOT_SLOT = 0xfffffe000c831798
PLANE_SLOT = 0xfffffe000c787c88
NAME_KEY_SLOT = 0xfffffe000c787c90
DISPLAY_CLASSES = frozenset(('IOBootFramebuffer', 'IOFramebuffer', 'AppleCLCD2',
    'IOFramebufferUserClient', 'IOFramebufferSharedUserClient',
    'IODisplayWrangler', 'AppleDisplay', 'AppleBacklightDisplay'))
DISPLAY_PROVIDER_NAMES = frozenset(('disp0', 'dispext0', 'snapintosh-boot-display'))
STARTUP_CLASSES = frozenset(('IOPlatformExpertDevice', 'AppleARMPE',
                            'IOResources', 'IOUserResources', 'IOPMrootDomain'))


def vtable_names(symbols):
    result = {}
    for address, name in symbols:
        match = re.fullmatch(r'__ZTV(\d+)([A-Za-z_][A-Za-z_0-9]*)', name)
        if match and int(match[1]) == len(match[2]):
            # Itanium address point follows offset-to-top and RTTI pointer.
            result[address+16] = match[2]
    return result


def collect(read, instruction, vtables, *, max_nodes=4096, max_bytes=16 << 20,
            detail_classes=frozenset()):
    """detail_classes adds state bits for extra classes, e.g. a linked AuxKC's."""
    for address, word in WITNESSES:
        if instruction(address) != word:
            raise ValueError(f'IORegistry native witness differs at {address:#x}')
    if not 1 <= max_nodes <= 8192 or not 4096 <= max_bytes <= 32 << 20:
        raise ValueError('invalid registry capture bounds')
    consumed = 0

    def data(address, size):
        nonlocal consumed
        if not 0xfffffe0000000000 <= address < address+size <= 1 << 64 or size <= 0:
            raise ValueError('registry read outside kernel virtual addresses')
        consumed += size
        if consumed > max_bytes:
            raise ValueError('registry byte budget exhausted; graph incomplete')
        return b''.join(read(address+i, min(0x4000, size-i))
                        for i in range(0, size, 0x4000))

    def q(address):
        return struct.unpack('<Q', data(address, 8))[0]

    def pointer(value):
        return value | 0xffff000000000000 if value else 0

    def ptr(address):
        return pointer(q(address))

    def kind(obj):
        return vtables.get(ptr(obj))

    strings = {}

    def string(obj):
        if not obj:
            return None
        if obj in strings:
            return strings[obj]
        if kind(obj) not in ('OSString', 'OSSymbol'):
            raise ValueError('registry name is not an OSString/OSSymbol')
        length = struct.unpack('<I', data(obj+12, 4))[0] >> 14
        if not 1 <= length <= 1024:
            raise ValueError('registry string exceeds capture bounds')
        raw = data(ptr(obj+16), length)
        if raw[-1:] != b'\0' or b'\0' in raw[:-1]:
            raise ValueError('invalid registry string termination')
        strings[obj] = raw[:-1].decode('utf-8', errors='replace')
        return strings[obj]

    dictionaries = {}

    def dictionary(obj):
        if obj in dictionaries:
            return dictionaries[obj]
        if not obj or kind(obj) != 'OSDictionary':
            raise ValueError('registry table is not an OSDictionary')
        count, capacity = struct.unpack('<II', data(obj+20, 8))
        if not 0 <= count <= capacity <= 8192:
            raise ValueError('registry dictionary exceeds capture bounds')
        raw = data(ptr(obj+32), count*16) if count else b''
        pairs = [(pointer(k), pointer(v)) for k, v in struct.iter_unpack('<QQ', raw)]
        if any(not k or not v for k, v in pairs) or len({k for k, _ in pairs}) != count:
            raise ValueError('invalid or duplicate registry dictionary key')
        dictionaries[obj] = dict(pairs)
        return dictionaries[obj]

    def array(obj):
        if not obj:
            return []
        if kind(obj) != 'OSArray':
            raise ValueError('registry child links are not an OSArray')
        count, capacity = struct.unpack('<II', data(obj+20, 8))
        if not 0 <= count <= capacity <= 8192:
            raise ValueError('registry child array exceeds capture bounds')
        raw = data(ptr(obj+32), count*8) if count else b''
        values = [pointer(v[0]) for v in struct.iter_unpack('<Q', raw)]
        if any(not v for v in values) or len(set(values)) != count:
            raise ValueError('invalid or duplicate registry child')
        return values

    root, plane, name_key = ptr(ROOT_SLOT), ptr(PLANE_SLOT), ptr(NAME_KEY_SLOT)
    if not root or not plane or not name_key:
        raise ValueError('IOService registry not initialized')
    child_key, plane_name = ptr(plane+32), ptr(plane+40)
    queue = deque([root])
    seen = set()
    rows, edges = [], []
    while queue:
        obj = queue.popleft()
        if obj in seen:
            continue
        if len(seen) >= max_nodes:
            raise ValueError('registry node budget exhausted; graph incomplete')
        seen.add(obj)
        table = dictionary(ptr(obj+24))
        children = array(table.get(child_key, 0))
        class_name = kind(obj)
        name = string(table.get(plane_name, table.get(name_key, 0)))
        row = dict(address=hex(obj), vtable=hex(ptr(obj)), class_name=class_name,
                   name=name, children=len(children))
        is_display_provider = (class_name == 'AppleARMIODevice'
                               and name in DISPLAY_PROVIDER_NAMES)
        if (class_name in DISPLAY_CLASSES or class_name in STARTUP_CLASSES or
                class_name in detail_classes or is_display_provider):
            state, state1 = struct.unpack('<II', data(obj+0x48, 8))
            row.update(state=hex(state), state1=hex(state1),
                       registered=bool(state & 2), matched=bool(state & 4),
                       matching_pending_or_running=bool(state1 & 0x80020000),
                       busy_count=state1 & 0x3ff)
            props = dictionary(ptr(obj+32))
            row['property_names'] = sorted(string(key) for key in props)
        rows.append(row)
        for child in children:
            edges.append((hex(obj), hex(child)))
            if child not in seen:
                queue.append(child)
    return dict(root=hex(root), plane=hex(plane), child_key=string(child_key),
                complete=True, entries=rows, edges=edges,
                display_entries=[r for r in rows if r['class_name'] in DISPLAY_CLASSES],
                display_providers=[r for r in rows
                                   if r['class_name'] == 'AppleARMIODevice'
                                   and r['name'] in DISPLAY_PROVIDER_NAMES],
                startup_entries=[r for r in rows if r['class_name'] in STARTUP_CLASSES],
                detail_entries=[r for r in rows if r['class_name'] in detail_classes],
                bytes_read=consumed,
                boundary='Stopped IOService graph and native state bits; no rendering inferred')
