# SPDX-License-Identifier: MIT
"""Read-only native AuxKC handoff/registration state for pinned J700 26A428."""
import struct

WITNESSES = (
    (0xfffffe000ba7ae98, 0xf9408108),  # copied SPTMArgs
    (0xfffffe000ba7ae9c, 0xf9417109),  # auxkc_mh at +0x2e0
    (0xfffffe000ba7aea8, 0xf9416d09),  # auxkc_base at +0x2d8
    (0xfffffe000ba7aeb4, 0xf9417508),  # auxkc_end at +0x2e8
    (0xfffffe000c07b340, 0x90fdf228),  # auxiliary header pointer
    (0xfffffe000c07b344, 0xf9403108),
    (0xfffffe000c07b354, 0xb0003db5),  # deferredAuxKCXML
    (0xfffffe000c07b358, 0xf9444aa8),
    (0xfffffe000c07b4b0, 0xd0003813),  # AuxKC UUID
    (0xfffffe000c07b4b4, 0x9119a273),
    (0xfffffe000c07b4d8, 0xd0003809),  # auxiliary UUID valid
    (0xfffffe000c07b4dc, 0xb906a128),
    (0xfffffe000c07b4e8, 0xf9044aa0),  # save deferred dictionary
    (0xfffffe000c078458, 0xd00032e8),  # sLoadEnabled page
    (0xfffffe000c07845c, 0x39782108),  # byte at +0xe08
    (0xfffffe000c078460, 0x36000408),  # reject collection load if disabled
    (0xfffffe000c078564, 0x90003dd9),  # daemon_ready page
    (0xfffffe000c0785ac, 0x395a2328),  # byte at +0x688
    (0xfffffe000c0785b0, 0x7100051f),
    (0xfffffe000c078abc, 0x52800028),  # mark daemon ready at load-path exit
    (0xfffffe000c078ac0, 0x391a2328),
)


def collect(read, instruction):
    for va, word in WITNESSES:
        if instruction(va) != word:
            raise ValueError(f'AuxKC native witness differs at {va:#x}')

    def q(va):
        return struct.unpack('<Q', read(va, 8))[0]

    def pointer(value):
        return (value | 0xffff000000000000) if value else 0

    def boolean(va):
        raw = read(va, 1)
        if raw not in (b'\0', b'\1'):
            raise ValueError('invalid native collection-loader boolean')
        return bool(raw[0])

    args = pointer(q(0xfffffe0007ebf100))
    header = pointer(q(0xfffffe0007ebf060))
    result = dict(sptm_args=hex(args),
                  handoff=dict(zip(('base', 'header', 'end'),
                      map(hex, struct.unpack('<3Q', read(args+0x2d8, 24))))),
                  registered_header=hex(header),
                  deferred_info=hex(pointer(q(0xfffffe000c830890))),
                  uuid_valid=struct.unpack('<I', read(0xfffffe000c77d6a0, 4))[0],
                  uuid=read(0xfffffe000c77d668, 16).hex(),
                  load_enabled=boolean(0xfffffe000c6d6e08),
                  daemon_ready=boolean(0xfffffe000c830688),
                  boundary='Header/UUID/deferred input and native loader control state; '
                           'daemon_ready does not establish successful driver loading or GUI')
    if header:
        magic, cpu, subtype, kind, count, size, flags, reserved = struct.unpack('<8I', read(header, 32))
        result['mach_header'] = dict(magic=hex(magic), cpu=hex(cpu), subtype=subtype,
                                    kind=kind, commands=count, command_bytes=size)
        if magic != 0xfeedfacf or kind != 12 or not 0 < count <= 32 or not 0 < size <= 0x1000:
            raise ValueError('invalid registered AuxKC header')
        commands = read(header+32, size)
        pos = 0
        segments = []
        for _ in range(count):
            if pos+8 > size:
                raise ValueError('AuxKC command header outside bounds')
            cmd, length = struct.unpack_from('<II', commands, pos)
            if length < 8 or pos+length > size:
                raise ValueError('AuxKC command outside bounds')
            if cmd == 0x19:
                if length < 72:
                    raise ValueError('short AuxKC segment')
                name, va, span, off, filebytes, maximum, initial, sections, _ = struct.unpack_from('<16sQQQQiiII', commands, pos+8)
                segments.append(dict(name=name.rstrip(b'\0').decode('ascii'),
                                     va=hex(va), size=span, maxprot=maximum, initprot=initial))
            pos += length
        if pos != size:
            raise ValueError('AuxKC command count/size mismatch')
        result['segments'] = segments
    return result


PAC_ADDRESS_MASK = (1 << 47) - 1
S_MOD_INIT_FUNC_POINTERS, S_MOD_TERM_FUNC_POINTERS = 9, 10


def structor_slots(collection):
    """File offsets of __mod_init_func/__mod_term_func pointers.

    arm_auxkc_init ends with OSRuntimeSignStructorsInFileset, which re-signs
    every nonzero structor with the IA key after kernel_collection_slide
    wrote it as a plain (isAuth=0) pointer. Those slots legitimately hold
    PAC bits above the address that their chain word does not describe.
    """
    data = collection.data
    headers = [0] + [off for _, _, off in collection.entries]
    slots = set()
    for header in headers:
        if header + 32 > len(data):
            raise ValueError('AuxKC entry header outside the file')
        count, size = struct.unpack_from('<II', data, header + 16)
        pos, end = header + 32, header + 32 + size
        for _ in range(count):
            cmd, length = struct.unpack_from('<II', data, pos)
            if length < 8 or pos + length > end:
                raise ValueError('AuxKC command outside bounds')
            if cmd == 0x19:
                for n in range(struct.unpack_from('<I', data, pos + 64)[0]):
                    sect = pos + 72 + 80 * n
                    _, size_, off = struct.unpack_from('<QQI', data, sect + 32)
                    flags, = struct.unpack_from('<I', data, sect + 64)
                    if flags & 0xff in (S_MOD_INIT_FUNC_POINTERS, S_MOD_TERM_FUNC_POINTERS):
                        slots.update(range(off, off + size_ - size_ % 8, 8))
            pos += length
    return slots


def resident(read, collection, base_va, base_pa, primary_vmin, primary_vmax):
    """Physical readback of a linked AuxKC after a stopped run.

    `read(pa, size)` reads guest RAM. The loader placed segment bytes at
    base_pa + vmaddr unfixed; what XNU did to them afterwards is the
    evidence: arm_auxkc_init rewrites every chained-fixup slot (sliding and
    PAC-signing) and kernel_collection_adjust_mh_addrs adds base_va to every
    load-command vmaddr. Executable bytes carry no fixups and must be exact.
    A half-applied walk (kernel_collection_slide stopped) is reported, not
    guessed at; a slot holding neither its raw chain word nor its target is
    an error.
    """
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'probes'))
    import auxkc

    class Primary:
        vmin, vmax = primary_vmin, primary_vmax

    text = 0
    for name, va, vmsize, off, filesize, _, initprot in collection.segments:
        if initprot & auxkc.VM_PROT_EXECUTE and filesize:
            got = b''.join(read(base_pa + va + i, min(0x4000, filesize - i))
                           for i in range(0, filesize, 0x4000))
            if got != collection.data[off:off + filesize]:
                raise ValueError(f'resident AuxKC {name} bytes differ from the pinned collection')
            text += filesize
    header_pa = base_pa + collection.mh_vmaddr
    commands = read(header_pa, 32 + struct.unpack_from('<I', collection.data, 20)[0])
    if commands[:32] != collection.data[:32]:
        raise ValueError('resident AuxKC mach header differs')
    unslid = slid = 0
    pos = 32
    for _ in range(struct.unpack_from('<I', commands, 16)[0]):
        cmd, length = struct.unpack_from('<II', commands, pos)
        if cmd == auxkc.LC_SEGMENT_64:
            file_va, = struct.unpack_from('<Q', collection.data, pos + 24)
            live_va, = struct.unpack_from('<Q', commands, pos + 24)
            if live_va == file_va:
                unslid += 1
            elif live_va == file_va + base_va:
                slid += 1
            else:
                raise ValueError('resident AuxKC segment address is neither unslid nor slid by base')
        pos += length
    if unslid and slid:
        raise ValueError('resident AuxKC header is partly slid')
    bases = {auxkc.LEVEL_PRIMARY: primary_vmin, auxkc.LEVEL_AUXILIARY: base_va}
    structors = structor_slots(collection)
    applied = raw = resigned = 0
    rewritten = []
    for off, level, target, auth in auxkc.chained_fixups(collection, Primary):
        seg = next(s for s in collection.segments if s[3] <= off < s[3] + s[4])
        live, = struct.unpack('<Q', read(base_pa + seg[1] + off - seg[3], 8))
        original, = struct.unpack_from('<Q', collection.data, off)
        want = bases[level] + target
        same_address = (live & PAC_ADDRESS_MASK) == (want & PAC_ADDRESS_MASK)
        if live == original:
            raw += 1
        elif same_address and (auth or live == want):
            applied += 1
        elif same_address and off in structors:
            applied += 1
            resigned += 1
        else:
            # Neither the chain word nor its target: kext code (or anything
            # else) stored to an initialized pointer after the slide. Report
            # it; the stopped-state audit must not die on a kext's globals.
            rewritten.append(dict(file_offset=hex(off), live=hex(live),
                                  raw=hex(original), target=hex(want)))
    state = ('slid' if slid and not raw else 'unslid' if not slid and not applied
             else 'partial')
    return dict(executable_bytes_verified=text, header_segments_slid=slid,
                header_segments_unslid=unslid, fixups_applied=applied, fixups_raw=raw,
                structors_resigned=resigned, fixups_rewritten=len(rewritten),
                rewritten_examples=rewritten[:8],
                state=state, base=hex(base_va), header_pa=hex(header_pa),
                boundary='Resident bytes only: slid means arm_auxkc_init ran on this '
                         'collection, not that any kext started')
