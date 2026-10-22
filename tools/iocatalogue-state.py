# SPDX-License-Identifier: MIT
"""Bounded read-only IOCatalogue personality inventory for native J700 26A428.

Requires a stopped audited kernel reader and vtable identities from its exact
image. Catalogue publication does not imply probe, start, attachment or GUI.
"""
import struct

WITNESSES = (
    (0xfffffe000ba4066c, 0xf0006a28),  # gIOCatalogue page
    (0xfffffe000ba40670, 0xf942e500),  # slot +0x5c8
    (0xfffffe000c112c5c, 0xaa0003f5),  # findDrivers: x21 = this
    (0xfffffe000c112d24, 0xf94012a0),  # personalities dictionary at +0x20
    (0xfffffe000c112e4c, 0xb9401800),  # generation at +0x18
    (0xfffffe000c04a370, 0xb9401408),  # OSArray count
    (0xfffffe000c04a37c, 0xf8420c10),  # OSArray storage
    (0xfffffe000c050d44, 0xb9401409),  # OSDictionary count
    (0xfffffe000c050d5c, 0xf8420c10),  # OSDictionary storage
    (0xfffffe000c050d78, 0xd37c7d6c),  # 16-byte dictionary entries
    (0xfffffe000c0856f8, 0xb9400c08),  # OSString length word
    (0xfffffe000c0856fc, 0x530e7d08),  # includes NUL, shifted14
    (0xfffffe000c08565c, 0xf8410c10),  # OSString storage
)
SLOT = 0xfffffe000c7875c8
FIELDS = ('CFBundleIdentifier', 'IOPersonalityPublisher', 'IOClass',
          'IOProviderClass', 'IONameMatch', 'IOMatchCategory')
DISPLAY_CLASSES = frozenset(('IOBootFramebuffer', 'IODisplayWrangler',
                            'AppleDisplay', 'AppleBacklightDisplay', 'AppleCLCD2'))


def collect(read, instruction, vtables, *, max_personalities=8192, max_bytes=8 << 20):
    for address, word in WITNESSES:
        if instruction(address) != word:
            raise ValueError(f'IOCatalogue native witness differs at {address:#x}')
    if not 1 <= max_personalities <= 16384 or not 4096 <= max_bytes <= 16 << 20:
        raise ValueError('invalid catalogue capture bounds')
    consumed = 0

    def data(address, size):
        nonlocal consumed
        if not 0xfffffe0000000000 <= address < address+size <= 1 << 64:
            raise ValueError('catalogue read outside kernel virtual addresses')
        consumed += size
        if consumed > max_bytes:
            raise ValueError('catalogue byte budget exhausted')
        raw = b''.join(read(address+i, min(0x4000, size-i))
                       for i in range(0, size, 0x4000))
        if len(raw) != size:
            raise ValueError('short catalogue read')
        return raw

    def pointer(raw):
        value = raw | 0xffff000000000000 if raw else 0
        if value and value < 0xfffffe0000000000:
            raise ValueError('invalid catalogue object pointer')
        return value

    def ptr(address):
        return pointer(struct.unpack('<Q', data(address, 8))[0])

    def kind(obj):
        if not obj or obj & 7:
            raise ValueError('invalid catalogue object alignment')
        return vtables.get(ptr(obj))

    strings = {}

    def string(obj):
        if obj in strings:
            return strings[obj]
        if not obj or kind(obj) not in ('OSString', 'OSSymbol'):
            raise ValueError('catalogue text is not an OSString/OSSymbol')
        length = struct.unpack('<I', data(obj+12, 4))[0] >> 14
        if not 1 <= length <= 4096:
            raise ValueError('catalogue text exceeds capture bounds')
        raw = data(ptr(obj+16), length)
        if raw[-1:] != b'\0' or b'\0' in raw[:-1]:
            raise ValueError('invalid catalogue string termination')
        strings[obj] = raw[:-1].decode('utf-8', errors='replace')
        return strings[obj]

    def collection(obj, expected, stride):
        if not obj or kind(obj) != expected:
            raise ValueError(f'catalogue collection is not an {expected}')
        count, capacity = struct.unpack('<II', data(obj+20, 8))
        if not 0 <= count <= capacity <= 16384:
            raise ValueError('catalogue collection exceeds capture bounds')
        return data(ptr(obj+32), count*stride) if count else b''

    def dictionary(obj):
        rows = {}
        for key, value in struct.iter_unpack('<QQ', collection(obj, 'OSDictionary', 16)):
            key, value = pointer(key), pointer(value)
            name = string(key)
            if name in rows or not value:
                raise ValueError('duplicate or null catalogue dictionary entry')
            rows[name] = value
        return rows

    def array(obj):
        values = [pointer(value) for value, in struct.iter_unpack('<Q', collection(obj, 'OSArray', 8))]
        if any(not value for value in values):
            raise ValueError('null catalogue array member')
        return values

    def text_value(obj):
        if kind(obj) in ('OSString', 'OSSymbol'):
            return string(obj)
        if kind(obj) == 'OSArray':
            values = array(obj)
            # Native IONameMatch lists can exceed 64 entries. The shared
            # collection-count and total-byte limits still bound this read.
            return [string(value) for value in values]
        return dict(address=hex(obj), class_name=kind(obj))

    catalogue = ptr(SLOT)
    if not catalogue:
        return dict(catalogue='0x0', complete=False, reason='catalogue not initialized')
    if kind(catalogue) != 'IOCatalogue':
        raise ValueError('catalogue slot does not contain an IOCatalogue')
    generation = struct.unpack('<I', data(catalogue+24, 4))[0]
    matching = ptr(catalogue+32)
    count, buckets, selected, undecoded = 0, [], [], []
    for provider, entries in dictionary(matching).items():
        personalities = array(entries)
        count += len(personalities)
        if count > max_personalities:
            raise ValueError('catalogue personality count exceeds capture bounds')
        buckets.append(dict(provider_class=provider, count=len(personalities)))
        for personality in personalities:
            values = dictionary(personality)
            fields = {name: text_value(values[name]) for name in FIELDS if name in values}
            io_class = fields.get('IOClass')
            if not isinstance(io_class, str):
                undecoded.append(hex(personality))
            if (isinstance(io_class, str) and io_class in DISPLAY_CLASSES or
                    any(isinstance(value, str) and 'snapintosh' in value.lower()
                        for value in fields.values())):
                selected.append(dict(address=hex(personality), provider_bucket=provider,
                                     fields=fields, property_names=sorted(values)))
    return dict(catalogue=hex(catalogue), generation=generation, matching=hex(matching),
                complete=True, personality_count=count, provider_buckets=buckets,
                selected_personalities=selected, unclassified_io_class=undecoded,
                bytes_read=consumed,
                boundary='Stopped catalogue publication only; selected fields are typed native '
                         'objects. Unclassified IOClass values prevent a complete class-absence '
                         'claim. No probe/start, driver attachment or GUI is inferred.')
