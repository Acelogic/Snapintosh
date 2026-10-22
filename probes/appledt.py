#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Apple device trees: parse, look up, patch, extend, write back out.

An Apple ADT is a flat tree of nodes, each `{u32 nprops; u32 nchildren}`
followed by its properties and then its children. A property is a 32-byte name,
a u32 length whose top bit marks a placeholder, and the value padded to four
bytes. There is no length field anywhere and nothing is relocatable -- the tree
is walked by stepping over what it declares -- so its total size is carried
outside it, in `boot_args.deviceTreeLength`.

The tree Apple ships is not finished, and it is unfinished in two different
ways. Some properties are present but empty: `clock-frequency` at the root is a
zero that iBoot replaces with the real counter rate, and 51 more carry a
placeholder flag and a recipe (`syscfg/SrNm/0x20`) for iBoot to look up. Others
are not there at all -- `/chosen/dram-base` and `/chosen/dram-size` are added by
iBoot, and XNU panics in arm_init without them. So a loader cannot just patch in
place; it has to be able to add, which means being able to write the tree back
out. That is why values are held here rather than referenced: once a property
can change length, every offset after it is wrong, and a parser built on offsets
quietly hands out stale ones.

    python3 probes/appledt.py downloads/extracted/j700ap/DeviceTree.j700ap
    python3 probes/appledt.py ... --path /device-tree/chosen
    python3 probes/appledt.py ... --grep pmgr
"""
import argparse
import pathlib
import struct
import sys

PLACEHOLDER = 1 << 31
NAME_LENGTH = 32


class Property:
    __slots__ = ('name', 'value', 'placeholder')

    def __init__(self, name, value, placeholder=False):
        self.name = name
        self.value = bytearray(value)
        self.placeholder = placeholder

    def __len__(self):
        return len(self.value)


class DeviceTree:
    def __init__(self, blob):
        self.nodes = {}                 # path -> {name: Property}
        self.children = {}              # path -> [paths]
        self._parse(bytes(blob), 0, '')

    # --- parsing ---------------------------------------------------------
    def _parse(self, blob, off, parent):
        nprops, nkids = struct.unpack_from('<II', blob, off)
        off += 8
        props, name = {}, None
        for _ in range(nprops):
            pname = blob[off:off + NAME_LENGTH].rstrip(b'\0').decode('utf-8', 'replace')
            off += NAME_LENGTH
            raw = struct.unpack_from('<I', blob, off)[0]
            length = raw & ~PLACEHOLDER
            off += 4
            props[pname] = Property(pname, blob[off:off + length], bool(raw & PLACEHOLDER))
            if pname == 'name':
                name = blob[off:off + length].rstrip(b'\0').decode('utf-8', 'replace')
            off += (length + 3) & ~3

        path = f'{parent}/{name}' if name else f'{parent}/?'
        # Siblings can share a name (cpu0, cpu0 ...); keep the first and index
        # the rest by position so nothing is silently lost.
        if path in self.nodes:
            n = 2
            while f'{path}@{n}' in self.nodes:
                n += 1
            path = f'{path}@{n}'
        self.nodes[path] = props
        self.children[path] = []
        if parent in self.children:
            self.children[parent].append(path)

        for _ in range(nkids):
            off = self._parse(blob, off, path)
        return off

    # --- writing back out ------------------------------------------------
    def serialize(self, path='/device-tree'):
        out = bytearray()
        self._emit(path, out)
        return bytes(out)

    def _emit(self, path, out):
        props = self.nodes[path]
        kids = self.children[path]
        out += struct.pack('<II', len(props), len(kids))
        for prop in props.values():
            name = prop.name.encode()
            if len(name) > NAME_LENGTH:
                raise ValueError(f'{prop.name!r} does not fit in {NAME_LENGTH} bytes')
            out += name.ljust(NAME_LENGTH, b'\0')
            length = len(prop.value)
            out += struct.pack('<I', length | (PLACEHOLDER if prop.placeholder else 0))
            out += prop.value
            out += b'\0' * ((-length) % 4)
        for kid in kids:
            self._emit(kid, out)

    @property
    def blob(self):
        return self.serialize()

    # --- lookup and change -----------------------------------------------
    def get(self, path, prop):
        entry = self.nodes.get(path, {}).get(prop)
        return None if entry is None else bytes(entry.value)

    def set(self, path, prop, value):
        """Overwrite a property. The length may change; the tree is rebuilt."""
        node = self.nodes.get(path)
        if node is None:
            raise KeyError(f'no node {path}')
        if prop not in node:
            raise KeyError(f'{path} has no property {prop}')
        node[prop] = Property(prop, value)

    def add(self, path, prop, value):
        """Add a property iBoot would have added. Refuses to shadow an existing
        one, because that is always a mistake rather than an intent."""
        node = self.nodes.get(path)
        if node is None:
            raise KeyError(f'no node {path}')
        if prop in node:
            raise KeyError(f'{path} already has {prop}')
        node[prop] = Property(prop, value)

    def put(self, path, prop, value):
        """Set it whether or not it is already there."""
        node = self.nodes.get(path)
        if node is None:
            raise KeyError(f'no node {path}')
        node[prop] = Property(prop, value)

    def set_u32(self, path, prop, value):
        self.set(path, prop, struct.pack('<I', value))

    def set_u64(self, path, prop, value):
        self.set(path, prop, struct.pack('<Q', value))

    def put_u64(self, path, prop, value):
        self.put(path, prop, struct.pack('<Q', value))

    def set_all(self, prop, value, under=''):
        """Set `prop` on every node that has it. Returns how many were changed.

        The per-CPU properties exist once per core and all of them have to
        agree, so setting them one path at a time is a way to miss one."""
        n = 0
        for path, props in self.nodes.items():
            if prop in props and path.startswith(under):
                props[prop] = Property(prop, value)
                n += 1
        return n

    def resolve_placeholders(self, fill=0):
        """Clear every placeholder flag, the way the boot loader would.

        Apple ships properties whose length has bit 31 set and whose value is a
        recipe -- `syscfg/SrNm/0x20` -- for iBoot to look up and substitute.
        XNU does not mask that bit when it walks the tree: it adds the length
        straight to its cursor and panics the moment one survives --

            panic: Device tree pointer outside of device tree region:
                   pointer 0xfffffe008e37003d ... @device_tree.c:98

        the pointer being exactly 0x80000000 past where it should be. So
        resolving them is not cosmetic; the tree is unwalkable until it is
        done. The values become zeros, which is what an unprovisioned unit of
        the same board would have."""
        resolved = 0
        for props in self.nodes.values():
            for prop in props.values():
                if prop.placeholder:
                    prop.placeholder = False
                    prop.value = bytearray([fill]) * len(prop.value)
                    resolved += 1
        return resolved

    def describe(self, path):
        out = []
        for name, prop in sorted(self.nodes.get(path, {}).items()):
            value, length = bytes(prop.value), len(prop.value)
            text = value.rstrip(b'\0').decode('utf-8', 'replace') \
                if length <= 48 and all(32 <= b < 127 or b == 0 for b in value) else None
            if text is None and length in (4, 8):
                text = str(int.from_bytes(value, 'little'))
            out.append((name, length, text or value[:24].hex()))
        return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('devicetree')
    ap.add_argument('--path', default='/device-tree')
    ap.add_argument('--grep', help='show every node whose path contains this')
    args = ap.parse_args()

    dt = DeviceTree(pathlib.Path(args.devicetree).read_bytes())
    print(f'{len(dt.nodes)} nodes, {len(dt.blob):,} bytes')
    if args.grep:
        for path in sorted(dt.nodes):
            if args.grep in path:
                print(f'  {path}')
        return 0
    for name, length, text in dt.describe(args.path):
        print(f'  {name:<32} len {length:<6} {text}')
    kids = dt.children.get(args.path, [])
    if kids:
        print('  children: ' + ' '.join(k.rsplit('/', 1)[-1] for k in kids))
    return 0


if __name__ == '__main__':
    sys.exit(main())
