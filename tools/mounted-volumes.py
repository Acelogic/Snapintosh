# SPDX-License-Identifier: MIT
"""Bounded native mount-list capture using the matching KDK's DWARF layout."""
import hashlib
import json
from pathlib import Path
import runpy
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def layout():
    symbols = runpy.run_path(str(ROOT / 'tools/kc-symbolicate.py'))
    mapper = symbols['Symbolicator']()  # Refuses mismatching KC/KDK UUIDs.
    program = (
        "import json; "
        "m=lldb.target.FindFirstType('mount'); "
        "v=lldb.target.FindFirstType('vfsstatfs'); "
        "g=lldb.target.FindFirstGlobalVariable('mountlist'); "
        "print('MOUNT_LAYOUT='+json.dumps(dict("
        "mount_size=m.GetByteSize(),stat_size=v.GetByteSize(),"
        "mountlist=g.GetAddress().GetFileAddress(),"
        "mount={m.GetFieldAtIndex(i).name:m.GetFieldAtIndex(i).GetOffsetInBytes() "
        "for i in range(m.GetNumberOfFields())},"
        "stat={v.GetFieldAtIndex(i).name:v.GetFieldAtIndex(i).GetOffsetInBytes() "
        "for i in range(v.GetNumberOfFields())})))"
    )
    output = subprocess.run(['xcrun', 'lldb', '-b', '-o',
        'target create ' + str(symbols['KDK_KERNEL']), '-o', 'script ' + program,
        '-o', 'quit'], capture_output=True, text=True, check=True).stdout
    rows = [s.removeprefix('MOUNT_LAYOUT=') for s in output.splitlines()
            if s.startswith('MOUNT_LAYOUT=')]
    if len(rows) != 1:
        raise ValueError('KDK mount layout unavailable')
    d = json.loads(rows[0])
    if d['mount_size'] != 2592 or any(d['mount'].get(k) != v for k, v in
            dict(mnt_list=0, mnt_flag=112, mnt_vfsstat=132).items()) or any(
            d['stat'].get(k) != v for k, v in
            dict(f_flags=72, f_fstypename=80, f_mntonname=96, f_mntfromname=1120).items()):
        raise ValueError('native mount layout changed')
    matches = [(name, base) for name, (base, size) in mapper.kdk_segs.items()
               if base <= d['mountlist'] < base + size and name in mapper.kc_segs]
    if len(matches) != 1:
        raise ValueError('mountlist segment is ambiguous')
    name, base = matches[0]
    d['mountlist_kc'] = mapper.kc_segs[name][0] + d['mountlist'] - base
    d['kernel_uuid'] = str(symbols['KERNEL_UUID'])
    d['dwarf_sha256'] = hashlib.sha256(symbols['KDK_DSYM'].read_bytes()).hexdigest()
    return d


def collect(read, root_mount):
    d = layout()
    canonical = lambda n: n | 0xffff000000000000 if n else 0
    q = lambda b, off=0: struct.unpack_from('<Q', b, off)[0]
    head = d['mountlist_kc']
    header = read(head, 16)
    current, tail = [canonical(n) for n in struct.unpack('<2Q', header)]
    previous = head
    rows, seen = [], set()
    while current:
        if current in seen or len(seen) >= 64 or current & 3:
            raise ValueError('mount list cycle, bound or alignment failure')
        seen.add(current)
        raw = read(current, d['mount_size'])
        if canonical(q(raw, 8)) != previous:
            raise ValueError('mount list reciprocal link differs')
        stat = d['mount']['mnt_vfsstat']
        def string(offset, size):
            value = raw[offset:offset+size]
            if b'\0' not in value:
                raise ValueError('unterminated mount string')
            return value.split(b'\0', 1)[0].decode('utf-8')
        fs = string(stat+d['stat']['f_fstypename'], 16)
        # The existing root_mount capture independently qualifies mnt_vtable+0x30.
        config = canonical(q(raw, 0x30))
        native_name = read(config+8, 16)
        if b'\0' not in native_name or native_name.split(b'\0', 1)[0].decode('ascii') != fs:
            raise ValueError('mount stat name differs from native VFS configuration')
        flags = struct.unpack_from('<I', raw, d['mount']['mnt_flag'])[0]
        rows.append(dict(address=hex(current), filesystem=fs,
            target=string(stat+d['stat']['f_mntonname'], 1024),
            source=string(stat+d['stat']['f_mntfromname'], 1024),
            flags=hex(flags), readonly=bool(flags & 1),
            stat_flags=hex(q(raw, stat+d['stat']['f_flags'])), raw_hex=raw.hex()))
        previous, current = current, canonical(q(raw))
    if tail != previous or read(head, 16) != header:
        raise ValueError('mount list tail or stable head differs')
    if not root_mount or root_mount['mount'] not in {r['address'] for r in rows}:
        raise ValueError('audited root mount absent from list')
    return dict(layout=d, header_hex=header.hex(), complete=True, mounts=rows,
        boundary='Native stopped mount list and flags; not successful writeback or persistence.')
