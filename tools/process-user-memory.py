# SPDX-License-Identifier: MIT
"""Bounded user-memory reads from a stopped, audited native process root.

Native J700 26A428 witnesses bind task -> vm_map -> pmap -> root PA.
PAC stripping identifies captured pointers; it does not authenticate them.
Only roots independently admitted by the stopped runtime audit are used.
No guest function is called and no mapping is installed or modified.
"""
import struct

WITNESSES = (
    (0xfffffe000b985050, 0xf8428c10),  # get_task_map: task+0x28
    (0xfffffe000b985060, 0xdac11a30),  # authenticated map pointer
    (0xfffffe000ba6d384, 0xf8458e30),  # pmap_find_phys: vm_map+0x58
    (0xfffffe000ba6d390, 0xdac11a30),  # authenticated pmap pointer
    (0xfffffe000ba69498, 0xf9400400),  # pmap -> root physical address
    (0xfffffe000ba6949c, 0x52800001),
    (0xfffffe000ba694a0, 0x52800002),
    (0xfffffe000ba694b0, 0x141f0881),  # SWITCH_ROOT tailcall
)
PA_MASK = 0x0000ffffffffc000
USER_LIMIT = 1 << 47


def make_reader(kernel_read, physical_read, instruction, audited_roots,
                ram_low, ram_high, *, max_bytes=1 << 20, ownership_audit=None):
    for address, word in WITNESSES:
        if instruction(address) != word:
            raise ValueError(f'process user root witness differs at {address:#x}')
    if not 4096 <= max_bytes <= 4 << 20 or not 0 < ram_low < ram_high <= 1 << 48:
        raise ValueError('invalid process user read bounds')
    roots = {}
    for row in audited_roots:
        root = int(row['root'], 16)
        if root in roots:
            raise ValueError('duplicate audited user root')
        roots[root] = row

    owned_roots = set()
    geometry = None
    if ownership_audit is not None:
        audit = ownership_audit
        geometry = audit['geometry']
        if (audit.get('runtime_stop_qualified') is not True or
                audit.get('user_mapping_qualified') is not True or
                audit.get('ownership', {}).get('mismatches') != [] or
                audit['ownership'].get('audited_tables', 0) <= 0 or
                (geometry['ram_low'], geometry['ram_high']) != (ram_low, ram_high)):
            raise ValueError('ownership user audit is incomplete or geometry differs')
        low, high = geometry['frame_low'], geometry['frame_high']
        start, end = geometry['alloc_low'], geometry['alloc_high']
        frame_map = geometry['frame_map']
        if (not 0 <= low <= start < end <= high <= 1 << 48 or
                (low | high | start | end) & 0x3fff or frame_map & 15 or
                not ram_low <= frame_map < frame_map+((high-low)>>14)*16 <= ram_high):
            raise ValueError('invalid ownership metadata geometry')
        owned_roots = set(geometry['user_roots'])
        shared = geometry['shared_roots']
        if (len(owned_roots) != len(geometry['user_roots']) or
                len(set(shared)) != len(shared) or len(shared) > 255 or
                any(root & 0x3fff or not start <= root < end
                    for root in owned_roots | set(shared))):
            raise ValueError('invalid ownership root inventory')

    def metadata(root):
        address = geometry['frame_map']+((root-geometry['frame_low'])>>14)*16
        raw = physical_read(address, 16)
        if len(raw) != 16:
            raise ValueError('short process root metadata read')
        return dict(root=hex(root), address=hex(address), raw=raw.hex()), raw

    def kernel_q(address):
        if not 0xfffffe0000000000 <= address <= (1 << 64)-8 or address & 7:
            raise ValueError('invalid process kernel pointer')
        raw = kernel_read(address, 8)
        if len(raw) != 8:
            raise ValueError('short process kernel read')
        return struct.unpack('<Q', raw)[0]

    def pointer(raw):
        value = raw | 0xffff000000000000 if raw else 0
        if not 0xfffffe0000000000 <= value < 1 << 64 or value & 7:
            raise ValueError('invalid process kernel pointer')
        return value

    def bind(task):
        task = pointer(task)
        map_ = pointer(kernel_q(task+0x28))
        pmap = pointer(kernel_q(map_+0x58))
        root = kernel_q(pmap+8)
        row = roots.get(root)
        provenance = {}
        observed = []
        # Reached CONFIGURE_ROOT states enable UMPRR18/TPRO and UMPRR11.
        # Native replay and generation40's independent root audit establish
        # that 0xa -> 0xb preserves the 16K/47-bit geometry. This is a raw
        # stopped-table read; keep the actual saved flags in its metadata.
        if row is None and root in owned_roots:
            root_meta, raw = metadata(root)
            flags = int.from_bytes(raw[10:12], 'little')
            if (raw[:2] != b'\0\0' or raw[2] != 18 or not int.from_bytes(raw[4:6], 'little')
                    or raw[9] or any(raw[12:]) or flags not in (2, 0xa, 0xb)):
                raise ValueError('unsupported process root metadata')
            provenance = dict(admission='ownership-audit', root_metadata=root_meta)
            observed.append(root_meta)
            if raw[8] != 255:
                matches = []
                for shared_root in geometry['shared_roots']:
                    shared_meta, shared_raw = metadata(shared_root)
                    if (shared_raw[:2] != b'\0\0' or shared_raw[2] != 19 or
                            shared_raw[8] == 255 or any(shared_raw[9:12]) or
                            shared_raw[12] not in (0, 1) or any(shared_raw[13:])):
                        raise ValueError('invalid shared binding metadata')
                    if shared_raw[8] == raw[8]:
                        if not 0 < int.from_bytes(shared_raw[4:6], 'little') <= 0xfff9 or shared_raw[12]:
                            raise ValueError('invalid shared binding metadata')
                        matches.append(shared_meta)
                if len(matches) != 1:
                    raise ValueError('process root shared binding is not audited')
                provenance['shared_metadata'] = matches[0]
                observed.append(matches[0])
        elif (not row or row['format'] != 0 or int(row['flags'], 16) not in (2, 0xa, 0xb)
                or not row['mappings_equal'] or root & 0x3fff):
            raise ValueError(f'process root {root:#x} is not an audited 16K user root '
                             f'(flags={row.get("flags") if row else None})')
        else:
            flags = int(row['flags'], 16)
        consumed = 0

        def physical(address, size):
            nonlocal consumed
            if not ram_low <= address < address+size <= ram_high:
                raise ValueError('process user read outside guest RAM')
            consumed += size
            if consumed > max_bytes:
                raise ValueError('process user read budget exhausted')
            raw = physical_read(address, size)
            if len(raw) != size:
                raise ValueError('short process physical read')
            return raw

        def read(address, size):
            if not 0 < size <= 0x4000 or not 0 < address < address+size <= USER_LIMIT:
                raise ValueError('invalid process user address or size')
            if observed:
                if (pointer(kernel_q(task+0x28)) != map_ or
                        pointer(kernel_q(map_+0x58)) != pmap or kernel_q(pmap+8) != root):
                    raise ValueError('process root binding changed')
                for entry in observed:
                    if physical(int(entry['address'], 16), 16).hex() != entry['raw']:
                        raise ValueError('process root metadata changed')
            result = bytearray()
            while size:
                table = root
                for shift in (36, 25, 14):
                    descriptor, = struct.unpack('<Q', physical(
                        table+8*((address >> shift) & 2047), 8))
                    # This reader intentionally refuses block and absent entries.
                    if descriptor & 3 != 3:
                        raise ValueError('user page is absent or not a 16K page mapping')
                    table = descriptor & PA_MASK
                take = min(size, 0x4000-(address & 0x3fff))
                result.extend(physical(table+(address & 0x3fff), take))
                address += take
                size -= take
            return bytes(result)

        return read, dict(task=hex(task), vm_map=hex(map_), pmap=hex(pmap),
                          root=hex(root), format=0, flags=hex(flags), virtual_address_bits=47,
                          **provenance,
                          boundary='Stopped native user page tables; pointer PAC not authenticated')
    return bind
