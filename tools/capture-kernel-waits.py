#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inspect the stopped J700 kernel task's thread queue; never resume the guest.

Only the measured 26A428 layout is accepted. Queue geometry is discovered
inside kernel_task, then checked with reciprocal links and its thread count.
Saved continuations and bounded frame-pointer chains identify blocked work.
Nearest symbols are labelled as such because many native functions are stripped.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import runpy
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import run
import xnuboot as xb

KERNEL_SHA = 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'


def private_copies(records, owner_id, owners, owned_index, live_tables, pages, columns):
    """Add one cache slot's private copy pages (allocation indices) to `pages`.
    Every source table is the slot's own. Each of its `columns` copies -- six per
    CPU, or two shared permission variants whose other four slots are zero -- is
    owned by the slot, is no live canonical page and aliases no other copy."""
    if columns not in (2, 6):
        raise ValueError('invalid private copy layout')
    for off in range(0, len(records), 64):
        source, *copies, level = struct.unpack_from('<8Q', records, off)
        if level > 3 or owners[owned_index(source)] != owner_id:
            raise ValueError('private source allocation owner mismatch')
        if any(copies[columns:]):
            raise ValueError('nonzero unused private copy slots')
        for copy in copies[:columns]:
            index = owned_index(copy)
            if owners[index] != owner_id or index in live_tables or index in pages:
                raise ValueError('private table alias or allocation owner mismatch')
            pages.add(index)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device', required=True)
    ap.add_argument('--prefix', required=True)
    ap.add_argument('--output-suffix', default='kernel-waits',
                    help='separate JSON artifact suffix for an additional stopped capture')
    ap.add_argument('--processes', action='store_true',
                    help='also inspect bounded PIDs after native process startup')
    ap.add_argument('--auxkc', type=Path,
                    help='pinned linked AuxKC: name its classes in --ioreg and report its evidence')
    ap.add_argument('--ioreg', action='store_true',
                    help='also capture the bounded native IOService registry graph')
    ap.add_argument('--catalogue', action='store_true',
                    help='also inspect bounded native IOCatalogue personality publication')
    ap.add_argument('--topology', action='store_true',
                    help='also capture guest CPU topology and both boot command lines')
    ap.add_argument('--mounts', action='store_true',
                    help='capture the bounded native mount list using UUID-matched KDK DWARF')
    ap.add_argument('--nvme-driver', action='store_true',
                    help='with --ioreg, capture the native NVMe controller and free request pool')
    ap.add_argument('--saved-user-states', action='store_true',
                    help='include native saved EL0 registers with --processes')
    ap.add_argument('--ownership-user-roots', action='store_true',
                    help='also admit uncached user roots from the full stopped ownership audit')
    ap.add_argument('--user-frames-for', action='append', default=[], metavar='NAME',
                    help='capture bounded saved user frames for a captured process name; repeat up to 8 times')
    ap.add_argument('--arguments-from',type=Path,
                    help='read bounded argv using this capture-bound shared-cache attribution JSON')
    ap.add_argument('--initial-arguments-for',action='append',default=[],metavar='NAME',
                    help='read pinned initial argument strings before libSystem initialization; up to 8 names')
    ap.add_argument('--device-open-waits',action='store_true',
                    help='capture native device-open queue owners and byte-qualified sleepers')
    ap.add_argument('--ipc-receivers',action='store_true',
                    help='bind blocked IPC-send destinations to native receiver tasks')
    ap.add_argument('--scheduler-state',action='store_true',
                    help='decode pinned native thread state for kernel and selected processes')
    ap.add_argument('--table-density-for',action='append',default=[],metavar='NAME',
                    help='read audited canonical table density for up to4 named processes')
    ap.add_argument('--pid-limit',type=int,default=64,metavar='1..256',
                    help='highest PID to inspect with --processes (default: 64)')
    args = ap.parse_args()
    if args.nvme_driver and not args.ioreg:
        ap.error('--nvme-driver requires --ioreg')
    if args.saved_user_states and not args.processes:
        ap.error('--saved-user-states requires --processes')
    if args.ownership_user_roots and not args.processes:
        ap.error('--ownership-user-roots requires --processes')
    if args.arguments_from and not args.processes:
        ap.error('--arguments-from requires --processes')
    if args.initial_arguments_for and not args.processes:
        ap.error('--initial-arguments-for requires --processes')
    if len(args.initial_arguments_for)>8 or any(not re.fullmatch(r'[A-Za-z0-9 _.-]{1,17}',x) for x in args.initial_arguments_for):
        ap.error('invalid initial argument process selection')
    if args.device_open_waits and not args.processes:
        ap.error('--device-open-waits requires --processes')
    if args.ipc_receivers and not args.processes:
        ap.error('--ipc-receivers requires --processes')
    if args.table_density_for and not args.processes:
        ap.error('--table-density-for requires --processes')
    if len(args.table_density_for)>4 or any(not re.fullmatch(r'[A-Za-z0-9 _.-]{1,17}',x) for x in args.table_density_for):
        ap.error('invalid density process selection')
    if args.user_frames_for and not args.saved_user_states:
        ap.error('--user-frames-for requires --saved-user-states and --processes')
    if len(args.user_frames_for) > 8 or any(
            not re.fullmatch(r'[A-Za-z0-9 _.-]{1,17}', name) for name in args.user_frames_for):
        ap.error('invalid or excessive --user-frames-for process names')
    if not 1<=args.pid_limit<=256:ap.error('--pid-limit must be 1..256')
    if not re.fullmatch(r'[a-z0-9-]+', args.prefix):
        raise ValueError('invalid prefix')
    if not re.fullmatch(r'[a-z0-9-]+', args.output_suffix):
        raise ValueError('invalid output suffix')
    base = ROOT / 'build' / args.prefix
    output=Path(f'{base}-{args.output_suffix}.json')
    if output.exists():raise ValueError('capture output already exists; preserve it and choose a fresh suffix')
    audit_path = Path(f'{base}-audit.json')
    audit = json.loads(audit_path.read_text())
    service = audit['service']
    owner = (service[1] & 0xffffffff) - 1
    if service[1] >> 32 != 1 or not 0 <= owner < 6:
        raise ValueError('requires an audited normal stop owner')
    stop = json.loads(Path(f'{base}-cpu{owner}-stop.json').read_text())
    # All three terminal paths store their registers in vcpu.async_regs:
    # watchdog (1), unsupported monitor request (2), and stage-2 fault (3).
    if stop['cpu'] != owner or stop['snapshot_kind'] not in (1, 2, 3, 4):
        raise ValueError('requires a terminal stop owner register snapshot')
    # A terminal guest exception (4) instead uses last_exc with no async flag.
    register_field = 'last_exc' if stop['snapshot_kind'] == 4 else 'async_regs'
    resident_kind = 0 if stop['snapshot_kind'] == 4 else stop['snapshot_kind']
    kernel = runpy.run_path(str(ROOT / 'tools/kc-xref.py'))['Kernelcache'](xb.DEFAULT_KERNELCACHE)
    if hashlib.sha256(kernel.data).hexdigest() != KERNEL_SHA:
        raise ValueError('kernel identity differs')
    scheduler_state = None
    scheduler_binding = None
    if args.scheduler_state:
        scheduler = runpy.run_path(str(ROOT/'tools/thread-scheduler.py'))
        scheduler_state = scheduler['make_reader'](kernel.u32)
        scheduler_binding = dict(state_offset=hex(scheduler['STATE_OFFSET']),
            witnesses=[dict(address=hex(a),word=hex(w)) for a,w in scheduler['WITNESSES']],
            boundary=scheduler['BOUNDARY'])
    # Native thread fields, context switch, OSString storage, and the three
    # matching symbols loaded by IOFindBSDRoot before its initial wait.
    for va, word in ((0xfffffe000b95d648, 0xf9428800),
                     (0xfffffe000b95e214, 0xf9445008),
                     (0xfffffe000b92ff28, 0xa90e5e75),
                     (0xfffffe000b972830, 0xf9000e99),
                     (0xfffffe000b870408, 0x91056004),
                     (0xfffffe000b870430, 0xa905787d),
                     (0xfffffe000c08565c, 0xf8410c10),
                     (0xfffffe000c1a9694, 0xf942ed00),
                     (0xfffffe000c1a96ac, 0xf942f101),
                     (0xfffffe000c1a96b4, 0xf942f502),
                     (0xfffffe000b5033e8, 0xf000aaf3),
                     (0xfffffe000b5033ec, 0x39654268),
                     (0xfffffe000b503414, 0x94000099),
                     (0xfffffe000b50341c, 0x39254268),
                     # Native Exclave stage reader used by exclaves_get_status.
                     (0xfffffe000b8caa00, 0xd0007614),
                     (0xfffffe000b8caa04, 0x910b2294),
                     (0xfffffe000b8caa08, 0xb8bfc288),
                     (0xfffffe000b8caa24, 0xd0007609),
                     (0xfffffe000b8caa28, 0xf9416929),
                     # Native EXCLAVES startup reads SPTMArgs+0x180, bit0.
                     (0xfffffe000c235008, 0xd0fde448),
                     (0xfffffe000c23500c, 0xf9408108),
                     (0xfffffe000c235010, 0x39460108),
                     (0xfffffe000c235014, 0x7200011f),
                     (0xfffffe000c235018, 0x52800028),
                     (0xfffffe000c23501c, 0x1a880508),
                     (0xfffffe000c235020, 0xf0002aa9),
                     (0xfffffe000c235024, 0xb902c928)):
        if kernel.u32(va) != word:
            raise ValueError(f'native capture witness differs at {va:x}')
    symbols = []
    for line in subprocess.run(['nm', '-n', str(xb.DEFAULT_KERNELCACHE)],
                               capture_output=True, text=True, check=True).stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and re.fullmatch(r'[0-9a-f]{16}', parts[0]):
            symbols.append((int(parts[0], 16), parts[2]))
    symbols.sort()
    addresses = [x[0] for x in symbols]
    layout = subprocess.run([
        'clang', '--target=aarch64-unknown-none-elf', '-ffreestanding',
        '-mgeneral-regs-only', '-Ishadow', '-Icompat', '-Xclang',
        '-fdump-record-layouts', '-fsyntax-only', 'probes/xnuboot.c'],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    def record_layout(kind):
        blocks = [b for b in layout.split('*** Dumping AST Record Layout')
                  if re.search(r'^\s*0 \| struct '+kind+r'\n', b)]
        if len(blocks) != 1:
            raise ValueError(f'ambiguous monitor layout for {kind}')
        return blocks[0]
    def field_offset(kind, field):
        matches = re.findall(r'^\s*(\d+) \|   .+ '+field+r'$', record_layout(kind), re.M)
        if len(matches) != 1:
            raise ValueError(f'ambiguous monitor field {kind}.{field}')
        return int(matches[0])
    sizes = re.findall(r'\[sizeof=(\d+),', record_layout('vcpu'))
    if len(sizes) != 1:
        raise ValueError('ambiguous monitor vcpu stride')
    cpu_offset = field_offset('context', 'vcpus') + owner * int(sizes[0])
    register_address_offset = cpu_offset + field_offset('vcpu', register_field)
    params_offset = field_offset('context', 'params')

    def canonical(value):
        return value | 0xffff000000000000 if value else 0

    def describe(value):
        value = canonical(value)
        owner = kernel.owner(value)
        if not owner or owner[1] != '__TEXT_EXEC':
            return None
        i = bisect.bisect_right(addresses, value) - 1
        return dict(va=hex(value), owner=owner[0],
                    nearest_symbol=symbols[i][1], offset=hex(value-addresses[i]))

    proxy = run.connect(args.device, tries=1)
    try:
        info = proxy.bootinfo()
        work, work_size = run.resident_work(proxy, info)
        def read(pa, size):
            if not 0 < size <= 0x200000:
                raise ValueError('invalid physical read size')
            return b''.join(proxy.readmem(pa+i, min(65536, size-i), live=True)
                            for i in range(0, size, 65536))
        monitor = (ROOT / 'build/xnuboot.bin').read_bytes()
        if (hashlib.sha256(monitor).hexdigest() != audit['monitor_sha256'] or
                read(info['heap_base']+run.CODE_AT, len(monitor)) != monitor):
            raise ValueError('resident monitor differs')
        resident_service = struct.unpack('<8Q', read(work+field_offset('context', 'services'), 64))
        kind, = struct.unpack('<Q', read(work+cpu_offset+field_offset('vcpu', 'async_captured'), 8))
        acquired, = struct.unpack('<Q', read(work+cpu_offset+field_offset('vcpu', 'service_acquires'), 8))
        owner_audit = next(row for row in audit['cpu_rows'] if row['slot'] == owner)
        if (list(resident_service) != service or kind != resident_kind or
                acquired != owner_audit['service_acquires']):
            raise ValueError('resident owner state differs from audited stop')
        if stop['snapshot_kind'] == 4:
            exceptions, = struct.unpack('<Q', read(work+cpu_offset+field_offset('vcpu', 'exceptions'), 8))
            if not exceptions:
                raise ValueError('terminal guest snapshot has no recorded exception')
        current = struct.unpack('<36Q', read(work+register_address_offset, 288))
        if tuple(current[31:]) != tuple(int(stop[k], 16) for k in ('sp', 'pstate', 'pc', 'esr', 'far')) or any(
                current[i] != int(stop['registers'][str(i)], 16) for i in range(31)):
            raise ValueError('resident stop differs')
        g = audit['geometry']
        params_pa, = struct.unpack('<Q', read(work+params_offset, 8))
        params = struct.unpack(f'<{xb.PARAMS_WORDS}Q', read(params_pa, xb.PARAMS_WORDS*8))
        if (params[0], params[30], params[31]) != (g['root'], g['ram_low'], g['ram_high']):
            raise ValueError('resident geometry differs')
        pages = {}
        def ram(pa, size):
            if not g['ram_low'] <= pa < pa+size <= g['ram_high']:
                raise ValueError('read outside guest RAM')
            out = bytearray()
            while size:
                page, off = pa & ~0xfff, pa & 0xfff
                if page not in pages:
                    if len(pages) >= 4096:
                        raise ValueError('capture page budget exceeded')
                    pages[page] = read(page, 4096)
                take = min(size, 4096-off)
                out += pages[page][off:off+take]
                pa += take
                size -= take
            return bytes(out)
        def va_read(va, size):
            if not 0 < size <= 0x4000:
                raise ValueError('invalid virtual read size')
            out = bytearray()
            while size:
                table = g['root']
                for shift in (36, 25, 14):
                    desc, = struct.unpack('<Q', ram(table+8*((va >> shift) & 2047), 8))
                    if desc & 3 != 3:
                        raise ValueError('unmapped guest RAM')
                    table = desc & 0x0000ffffffffc000
                take = min(size, 0x4000-(va & 0x3fff))
                out += ram(table+(va & 0x3fff), take)
                va += take
                size -= take
            return bytes(out)
        def q(va):
            return struct.unpack('<Q', va_read(va, 8))[0]
        # Exported VFS globals and the exact APFS root-hash importer globals.
        # This reports raw state; a non-null pointer is not mount/validation proof.
        root_state = dict(rootdev=hex(struct.unpack('<I', va_read(0xfffffe000c77c9f4, 4))[0]),
                          rootvp=hex(q(0xfffffe000c77ca58)),
                          rootvnode=hex(q(0xfffffe000c787648)),
                          apfs_imported_payload=hex(q(0xfffffe000ca62cf0)),
                          apfs_imported_payload_size=q(0xfffffe000ca62cf8),
                          apfs_global_payload=hex(q(0xfffffe000ca62d00)),
                          apfs_global_payload_size=q(0xfffffe000ca62d08),
                          apfs_external_resources_initialized=va_read(0xfffffe000ca62950, 1)[0])
        for prefix in ('apfs_imported_payload','apfs_global_payload'):
            pointer=canonical(int(root_state[prefix],16))
            size=root_state[prefix+'_size']
            if pointer and 0 < size <= 0x4000:
                payload=va_read(pointer,size)
                root_state[prefix+'_sha256']=hashlib.sha256(payload).hexdigest()
                root_state[prefix+'_hex']=payload.hex()
        root_mount = None
        root = canonical(int(root_state['rootvnode'],16))
        if root:
            # Pinned vnode_mount/vnode_vtype/vnode_isvroot and vfs_name/
            # vfs_typenum accessors establish the layout independently.
            for va,word in ((0xfffffe000bb7a030,0xf84d8c10),
                            (0xfffffe000bb7a138,0x3941c400),
                            (0xfffffe000bb7a178,0xb9405408),
                            (0xfffffe000bb77d8c,0xf8430c10),
                            (0xfffffe000bb77d9c,0x91002201),
                            (0xfffffe000bb77dc4,0xb9401a00),
                            (0xfffffe000bb77de8,0xb9407008)):
                if kernel.u32(va)!=word:
                    raise ValueError(f'root mount witness differs at {va:x}')
            mount=canonical(q(root+0xd8));config=canonical(q(mount+0x30))
            name=va_read(config+8,16)
            if b'\0' not in name:raise ValueError('unterminated filesystem name')
            flags=struct.unpack('<I',va_read(root+0x54,4))[0]
            root_mount=dict(vnode=hex(root),mount=hex(mount),vfs_config=hex(config),
                filesystem=name.split(b'\0',1)[0].decode('ascii'),
                vtype=va_read(root+0x71,1)[0],vnode_flags=hex(flags),is_vroot=bool(flags&1),
                filesystem_type=struct.unpack('<I',va_read(config+0x18,4))[0],
                mount_flags=hex(struct.unpack('<I',va_read(mount+0x70,4))[0]))
        mounted_volumes = None
        if args.mounts:
            mounted_volumes = runpy.run_path(str(ROOT/'tools/mounted-volumes.py'))['collect'](
                va_read, root_mount)
        # The shipped initializer reads the two physical RoRgn bounds and
        # expands the upper 4K page base to an inclusive byte address.
        for va,word in ((0xfffffe000ba87c08,0xd538b148),
                        (0xfffffe000ba87c14,0xd538b168),
                        (0xfffffe000ba87c18,0x913ffd08)):
            if kernel.u32(va)!=word:raise ValueError('RoRgn initializer witness differs')
        const_region=dict(begin=hex(q(0xfffffe0007e2c020)),
                          end_inclusive=hex(q(0xfffffe0007e2c028)))
        address_space_switch = None
        user_page_request = None
        user_unmap_request = None
        user_condemn_request = None
        user_table_request = None
        initial_user_page = None
        commpage_roots=[]
        def table_metadata(pa):
            frame=pa&~0x3fff
            if not g['alloc_low']<=frame<g['alloc_high']:
                raise ValueError('commpage inventory frame outside allocator')
            raw=ram(g['frame_map']+((frame-g['frame_low'])>>14)*16,16)
            return dict(pa=hex(frame),metadata=raw.hex(),type=raw[2])
        for root_pa in g['user_roots']:
            header=table_metadata(root_pa);meta=bytes.fromhex(header['metadata'])
            flags=int.from_bytes(meta[10:12],'little');fmt=meta[12]
            # CONFIGURE_ROOT bits0/1/3 select UMPRR/PA, not table geometry.
            # This inventory includes inactive roots, unlike the active-shadow audit.
            geometry_flags=(flags|2)&~9
            if (fmt not in (0,1) or geometry_flags not in (2,6,0x22) or
                    (geometry_flags==6 and fmt!=1)):
                raise ValueError('unsupported commpage inventory root geometry')
            shift=12 if fmt else 14;size=1<<shift
            va=(1<<(47 if geometry_flags==6 else 32 if geometry_flags==0x22 else 36))-size
            table=root_pa;walk=[];attached=False
            for level in range(0 if fmt else 1,4):
                index=(va>>(shift+(3-level)*(shift-3)))&(size//8-1)
                desc=struct.unpack('<Q',ram(table+8*index,8))[0]
                walk.append(dict(level=level,slot=hex(table+8*index),descriptor=hex(desc)))
                if level==3:
                    child=table_metadata(table)
                    attached=child['type']==23
                    break
                if not desc&1:break
                if desc&3!=3:raise ValueError('unexpected commpage inventory block')
                table=desc&((1<<48)-size)
            if attached:
                words=struct.unpack('<2048Q',ram(table&~0x3fff,0x4000))
                commpage_roots.append(dict(root=header,asid=int.from_bytes(meta[4:6],'little'),
                    flags=hex(flags),format=fmt,child=child,walk=walk,
                    leaves=[dict(index=i,pte=hex(v),data=table_metadata(v&0x0000ffffffffc000))
                            for i,v in enumerate(words) if (v&3)==3]))
        retype_request=None
        if current[16]==1 and int(stop['pc'],16)==0xfffffe000c22b3c8:
            retype_request=dict(frame=table_metadata(current[0]),old_type=current[1],
                new_type=current[2],options=hex(current[3]),
                nonzero_words=sum(v!=0 for v in struct.unpack('<2048Q',ram(current[0],0x4000))))
        for entry in audit['root_switch']['roots']:
            if entry['asid']!=6 or entry['format']!=0:continue
            table=int(entry['root'],16);va=0x4000;mapped=True
            for shift in (36,25,14):
                desc=struct.unpack('<Q',ram(table+((va>>shift)&2047)*8,8))[0]
                if not desc&1:mapped=False;break
                if desc&3!=3:raise ValueError('initial user page has unexpected block')
                table=desc&0x0000ffffffffc000
            initial_user_page=dict(root=entry['root'],va=hex(va),mapped=mapped)
            if mapped:
                payload=ram(table,16)
                initial_user_page.update(pa=hex(table),
                    launchd_path_copied=payload.startswith(b'/sbin/launchd\0'))
        is_user_map=(current[16]==2 and int(stop['pc'],16)==0xfffffe000c22b404)
        is_user_unmap=(current[16]==7 and int(stop['pc'],16)==0xfffffe000c22b530)
        is_user_condemn=(current[16]==43 and int(stop['pc'],16)==0xfffffe000c22bcb0)
        is_user_table=(current[16]==3 and int(stop['pc'],16)==0xfffffe000c22b440)
        if (is_user_map or is_user_unmap or is_user_condemn or is_user_table) and current[0]!=g['root']:
            target,va,pte,options=current[:4]
            if is_user_unmap and (pte!=1 or va&0x3fff or options&~1):
                raise ValueError('unmap capture requires one aligned page, options0/1')
            if target&0x3fff or not g['alloc_low']<=target<g['alloc_high']:
                raise ValueError('MAP_PAGE root outside owned user tables')
            def frame_info(pa):
                if pa&0x3fff or not g['alloc_low']<=pa<g['alloc_high']:
                    raise ValueError('MAP_PAGE frame outside allocator')
                raw=ram(g['frame_map']+((pa-g['frame_low'])>>14)*16,16)
                return dict(pa=hex(pa),metadata=raw.hex(),type=raw[2])
            header=frame_info(target)
            if header['type']!=18:raise ValueError('MAP_PAGE root is not USER_ROOT')
            meta=bytes.fromhex(header['metadata'])
            if meta[12]!=0:raise ValueError('capture currently requires16K format')
            walk=[];table=target
            for level,shift in ((1,36),(2,25),(3,14)):
                slot=table+((va>>shift)&2047)*8
                desc=struct.unpack('<Q',ram(slot,8))[0]
                walk.append(dict(level=level,slot=hex(slot),descriptor=hex(desc),
                                 frame=frame_info(table)))
                if not desc&1 or level==3:break
                if desc&3!=3:raise ValueError('unexpected user block descriptor')
                table=desc&0x0000ffffffffc000
            active=[i for i,r in enumerate(audit['root_switch']['active']) if int(r,16)==target]
            if is_user_table:
                if current[2]!=2:raise ValueError('table capture requires an L3 attachment')
                child=current[3]&0x0000ffffffffc000
                words=struct.unpack('<2048Q',ram(child,0x4000))
                leaves=[dict(index=i,pte=hex(v),data=frame_info(v&0x0000ffffffffc000))
                        for i,v in enumerate(words) if (v&3)==3]
                user_table_request=dict(root=header,va=hex(va),level=current[2],
                    tte=hex(current[3]),child=frame_info(child),walk=walk,
                    nonzero_entries=sum(v!=0 for v in words),leaves=leaves,active_cpus=active)
            elif is_user_condemn:
                if level!=3:raise ValueError('condemn capture expected attached L3 table')
                words=struct.unpack('<2048Q',ram(table,0x4000))
                user_condemn_request=dict(root=header,va=hex(va),walk=walk,
                    leaf_table=frame_info(table),nonzero_leaf_entries=sum(v!=0 for v in words),
                    valid_leaf_entries=sum((v&3)==3 for v in words),active_cpus=active)
            elif is_user_unmap:
                if level!=3 or desc&3!=3:raise ValueError('unmap capture expected a valid L3 leaf')
                user_unmap_request=dict(root=header,va=hex(va),count=current[2],
                    options=hex(options),old_pte=hex(desc),
                    data=frame_info(desc&0x0000ffffffffc000),walk=walk,active_cpus=active)
            else:
                user_page_request=dict(root=header,va=hex(va),pte=hex(pte),options=hex(options),
                    data=frame_info(pte&0x0000ffffffffc000),walk=walk,active_cpus=active)
        if current[16]==13 and int(stop['pc'],16)==0xfffffe000c22b6d4:
            for va,word in ((0xfffffe000c22b6c4,0xd28001b0),
                            (0xfffffe000ba69498,0xf9400400),
                            (0xfffffe000ba694b0,0x141f0881)):
                if kernel.u32(va)!=word:raise ValueError('root-switch witness differs')
            target=current[0]
            if target&0x3fff or not g['frame_low']<=target<g['frame_high']:
                raise ValueError('invalid root-switch frame')
            meta=ram(g['frame_map']+((target-g['frame_low'])>>14)*16,16)
            words=struct.unpack('<2048Q',ram(target,0x4000))
            entries=[dict(index=i,descriptor=hex(v)) for i,v in enumerate(words) if v]
            address_space_switch=dict(endpoint=13,root_pa=hex(target),
                arguments=[hex(v) for v in current[:3]],frame_type=meta[2],
                asid=int.from_bytes(meta[4:6],'little'),
                root_links=int.from_bytes(meta[6:8],'little'),
                flags=hex(int.from_bytes(meta[10:12],'little')),format=meta[12],
                nonzero_root_entries=len(entries),root_entries=entries[:16])
        image4_boot_uuid = None
        if current[16]==0x200000000002d and current[1]==6:
            if current[3]!=16 or any(current[4:8]):
                raise ValueError('unexpected Image4 boot UUID arguments')
            # cs_syscall_kmod_set_boot_uuid copies exactly 16 input bytes.
            for va,word in ((0xfffffe00094b5888,0x3dc00020),
                            (0xfffffe00094b58a4,0x52800203),
                            (0xfffffe000befeccc,0x528005a8)):
                if kernel.u32(va)!=word:raise ValueError('Image4 UUID witness differs')
            image4_boot_uuid=dict(endpoint=45,operation=6,stack_pa=hex(current[0]),
                uuid_va=hex(current[2]),uuid_hex=va_read(current[2],16).hex())
        image4_nonce_set = None
        image4_v2_nonce_digest = None
        if current[16]==0x2000000000034:
            domain=current[1]&0xffffffff
            if domain>=17 or not 1<=current[3]<=48 or any(current[4:8]):
                raise ValueError('unexpected Image4 v2 nonce digest arguments')
            if kernel.u32(0xfffffe000befc7fc)!=0x52800689:
                raise ValueError('nonce digest selector witness differs')
            image4_v2_nonce_digest=dict(endpoint=52,domain_index=domain,
                input_va=hex(current[2]),length=current[3],
                input_readable=len(va_read(current[2],current[3]))==current[3])
        if current[16]==0x200000000002d and current[1]==3:
            if current[3]!=44 or any(current[4:8]):
                raise ValueError('unexpected Image4 nonce-set arguments')
            for va,word in ((0xfffffe00094b5978,0xb9400828),
                            (0xfffffe00094b597c,0xf9002fe8),
                            (0xfffffe00094b5980,0xb90063e2)):
                if kernel.u32(va)!=word:raise ValueError('Image4 nonce witness differs')
            # Capture only the public domain/flags header, never nonce material.
            domain,flags=struct.unpack('<QI',va_read(current[2],12))
            image4_nonce_set=dict(endpoint=45,operation=3,stack_pa=hex(current[0]),
                input_va=hex(current[2]),input_size=44,domain_id=domain,flags=hex(flags))
        aes_startup = None
        if int(stop['pc'], 16) == 0xfffffe00099339b4:
            # Exact stopped _enableAES read, plus the native cached key-disable
            # fields and special-key table count. Capture metadata only: do not
            # read key material, submit a command or acknowledge an interrupt.
            for va, word in ((0xfffffe00099339b0, 0xf940be88),
                             (0xfffffe00099339b4, 0xb9400d08),
                             (0xfffffe0009934688, 0x3947a008),
                             (0xfffffe0009934618, 0xb941ec09),
                             (0xfffffe0009934660, 0xb941f009),
                             (0xfffffe00099345fc, 0xb941f409),
                             (0xfffffe000a7d5a60, 0xb940daa9)):
                if kernel.u32(va) != word:
                    raise ValueError(f'AES capture witness differs at {va:x}')
            obj = canonical(current[20])
            aes_startup = dict(
                object_va=hex(obj),
                registers_va=hex(q(obj+0x178)),
                special_key_count=struct.unpack('<I', va_read(obj+0xd8, 4))[0],
                dedicated_disable_words=list(va_read(obj+0x1d4, 3)),
                cached_disable_values=[hex(v) for v in
                    struct.unpack('<4I', va_read(obj+0x1e8, 16))])
            if int(aes_startup['registers_va'], 16)+12 != int(stop['far'], 16):
                raise ValueError('AES object does not match faulting register')
        root_match_symbols = []
        for address in (0xfffffe000c7875d8, 0xfffffe000c7875e0, 0xfffffe000c7875e8):
            obj = canonical(q(address))
            text = None
            storage = 0
            if obj:
                storage = canonical(q(obj+0x10))
                raw = va_read(storage, 64)
                if b'\0' not in raw:
                    raise ValueError('root matching symbol exceeds capture bound')
                text = raw.split(b'\0', 1)[0].decode('ascii')
            root_match_symbols.append(dict(global_va=hex(address), object_va=hex(obj),
                                           storage_va=hex(storage), text=text))
        task = q(0xfffffe0007ebeb60)
        task_raw = va_read(task, 0x100)
        candidates = []
        for off in range(0, 0xc0, 8):
            head = task+off
            first, last = struct.unpack_from('<2Q', task_raw, off)
            count, = struct.unpack_from('<I', task_raw, off+0x28)
            if not 1 <= count <= 512 or first < 0xffff000000000000 or last < 0xffff000000000000:
                continue
            try:
                rows, seen, previous, node = [], set(), head, first
                while node != head:
                    if node in seen or len(rows) >= count:
                        raise ValueError('cyclic or oversized task thread queue')
                    seen.add(node)
                    raw = va_read(node, 0x8c0)
                    next_, prev = struct.unpack_from('<2Q', raw, 0x410)
                    tid, = struct.unpack_from('<Q', raw, 0x510)
                    if prev != previous or not 0 < tid < 1 << 32:
                        raise ValueError('thread queue reciprocity or identity mismatch')
                    rows.append((node, raw))
                    previous, node = node, next_
                if len(rows) != count or previous != last:
                    raise ValueError('task thread count or tail mismatch')
                candidates.append((off, rows))
            except ValueError:
                continue
        if len(candidates) != 1:
            raise ValueError(f'expected one reciprocal task thread queue, got {len(candidates)}')
        off, records = candidates[0]
        cpu_topology = None
        if args.topology:
            cpu_topology = runpy.run_path(str(ROOT / 'tools/cpu-topology.py'))['collect'](
                va_read, ram, kernel.u32,
                loader_bootargs_pa=int(audit['firmware']['bootargs_pa'], 16),
                result_area_va=params[29])
            topology = cpu_topology
        else:
            topology = json.loads(Path(f'{base}-cpu-topology.json').read_text())
        on_cpu = {int(cpu['thread'], 16) for cpu in topology['cpu_data_entries']
                  if cpu.get('thread')}
        processor_scheduler = None
        if args.scheduler_state:
            processor_scheduler=runpy.run_path(str(ROOT/'tools/processor-scheduler.py'))['collect'](
                topology,va_read,kernel.u32)
        threads = []
        for node, raw in records:
            get = lambda offset: struct.unpack_from('<Q', raw, offset)[0]
            name = None
            if get(0x8a0):
                name = va_read(canonical(get(0x8a0)), 64).split(b'\0', 1)[0].decode('utf-8', 'replace')
            row = dict(thread=hex(node), tid=get(0x510), name=name,
                       wait_event=hex(get(0x18)), waitq=hex(get(0x28)),
                       on_cpu_at_stop=node in on_cpu,
                       continuation=describe(get(0xe0)),
                       continuation_raw=hex(get(0xe0)), parameter=hex(get(0xe8)),
                       kernel_stack=hex(get(0xf0)), raw_hex=raw.hex())
            if scheduler_state is not None:
                row['scheduler_state'] = scheduler_state(raw)
            ctx, stack = canonical(get(0x158)), canonical(get(0xf0))
            if not get(0xe0) and node not in on_cpu and stack and stack <= ctx < ctx+0xb8 <= stack+0x4000:
                saved = va_read(ctx, 0xb8)
                fp, lr, sp = struct.unpack_from('<3Q', saved, 0x50)
                row['saved_context'] = dict(va=hex(ctx), fp=hex(fp), lr=hex(lr),
                                            sp=hex(sp), raw_hex=saved.hex())
                frames = []
                while stack <= fp < fp+16 <= stack+0x4000 and not fp & 15 and len(frames) < 48:
                    next_fp, return_pc = struct.unpack('<2Q', va_read(fp, 16))
                    frames.append(dict(fp=hex(fp), raw_lr=hex(return_pc),
                                       return_to=describe(return_pc)))
                    if next_fp <= fp:
                        break
                    fp = next_fp
                row['frames'] = frames
            threads.append(row)
        if len({t['tid'] for t in threads}) != len(threads):
            raise ValueError('duplicate thread IDs')
        rtbuddy_route_waits = runpy.run_path(str(ROOT / 'tools/rtbuddy-route-state.py'))['collect'](
            threads, va_read, kernel.u32)
        user_processes = None
        if args.processes:
            if kernel.u32(0xfffffe000bec01c8) != 0xb9402020:
                raise ValueError('native proc_ppid layout witness differs')
            user_state = None
            if args.saved_user_states:
                user_state = runpy.run_path(str(ROOT / 'tools/user-state.py'))['make_reader'](
                    va_read, kernel.u32)
            user_processes = runpy.run_path(str(ROOT / 'tools/process-waits.py'))['collect'](
                va_read, describe, on_cpu, args.pid_limit, user_state=user_state,
                scheduler_state=scheduler_state)
            if args.user_frames_for or args.arguments_from or args.table_density_for or args.initial_arguments_for:
                bind_user = runpy.run_path(str(ROOT / 'tools/process-user-memory.py'))['make_reader'](
                    va_read, read if args.ownership_user_roots else ram, kernel.u32,
                    audit['root_switch']['roots'], g['ram_low'], g['ram_high'],
                    ownership_audit=audit if args.ownership_user_roots else None)
                user_frames = runpy.run_path(str(ROOT / 'tools/user-frame-chain.py'))['collect']
                argument_reader=runpy.run_path(str(ROOT/'tools/process-arguments.py'))
                argument_hints=(argument_reader['load_hints'](args.arguments_from,ROOT,
                    KERNEL_SHA,audit['monitor_sha256']) if args.arguments_from else {})
                initial_reader=(runpy.run_path(str(ROOT/'tools/process-initial-arguments.py'))['make_reader'](
                    va_read,kernel.u32) if args.initial_arguments_for else None)
                for process in user_processes['processes']:
                    hint=argument_hints.get(process['pid'])
                    want_frames=process['name'] in args.user_frames_for
                    want_initial=process['name'] in args.initial_arguments_for
                    if (not want_frames and not want_initial and hint is None and process['name'] not in args.table_density_for) or not process.get('task_present'):
                        continue
                    try:
                        read_user, metadata = bind_user(int(process['task'], 16))
                        process['user_address_space'] = metadata
                    except ValueError as error:
                        process['user_address_space_error'] = str(error)
                        continue
                    if want_initial:
                        try:
                            process['initial_arguments']=initial_reader(int(process['proc'],16),process['pid'],read_user)
                        except (ValueError,UnicodeError) as error:
                            process['initial_arguments_error']=str(error)
                    if hint is not None:
                        try:
                            if (hint['name']!=process['name'] or hint['task']!=process['task'] or
                                    hint['address_space']!=metadata or
                                    read_user(hint['witness_address'],64)!=hint['witness']):
                                raise ValueError('resident argument slide witness differs')
                            process['arguments']=argument_reader['collect'](read_user,hint['slide'])
                        except (ValueError,UnicodeError) as error:
                            process['arguments_error']=str(error)
                    if not want_frames:continue
                    for thread in process['threads']:
                        state = thread.get('saved_user_state')
                        if not state:
                            continue
                        thread['user_frame_chain'] = user_frames(read_user, int(state['fp'], 16))
                        try:
                            state['instruction_hex'] = read_user(int(state['pc'], 16), 64).hex()
                        except ValueError as error:
                            state['instruction_error'] = str(error)
        ipc_send_waits = runpy.run_path(str(ROOT / 'tools/ipc-send-waits.py'))['collect'](
            (user_processes or {}).get('processes', []), va_read, kernel.u32,
            receivers=args.ipc_receivers)
        device_open_waits = (runpy.run_path(str(ROOT / 'tools/device-open-waits.py'))['collect'](
            va_read,kernel.u32,threads,user_processes['processes']) if args.device_open_waits else None)
        bootpolicy_waits = []
        for process in (user_processes or {}).get('processes', []):
            for thread in process['threads']:
                for frame in thread.get('frames', []):
                    if int(frame['raw_lr'], 16) != 0xfffffe0009ef5ea0:
                        continue
                    # getSEPEndpoint saves its caller's x20/length and
                    # x19/buffer at FP-16/FP-8. Pin both prologues and the call.
                    for va, word in ((0xfffffe0009ef6070, 0xd10143ff),
                                     (0xfffffe0009ef6078, 0xa9034ff4),
                                     (0xfffffe0009ef607c, 0xa9047bfd),
                                     (0xfffffe0009ef6080, 0x910103fd),
                                     (0xfffffe0009ef5e84, 0xaa0203f4),
                                     (0xfffffe0009ef5e88, 0xaa0103f3),
                                     (0xfffffe0009ef5e9c, 0x94000073)):
                        if kernel.u32(va) != word:
                            raise ValueError('BootPolicy saved-argument witness differs')
                    fp = int(frame['fp'], 16)
                    size, buffer = struct.unpack('<2Q', va_read(fp-16, 16))
                    buffer = canonical(buffer)
                    if not 8 <= size <= 0x1c000:
                        raise ValueError('BootPolicy request length outside native buffer contract')
                    header = va_read(buffer, min(size, 128))
                    if int.from_bytes(header[:4], 'little') != 0x42506368:
                        raise ValueError('BootPolicy pending request magic differs')
                    bootpolicy_waits.append(dict(pid=process['pid'], tid=thread['tid'],
                        frame=hex(fp), buffer=hex(buffer), size=size,
                        header_hex=header.hex(), header_truncated=size>len(header)))
        table_arena = {field: struct.unpack('<Q', read(work+field_offset('context', field), 8))[0]
                       for field in ('work_base', 'next_table', 'work_end')}
        table_end=work+work_size
        if audit.get('txm_native',{}).get('enabled'):
            base=field_offset('params','txm_native')//8
            native=params[base:base+4]
            if native[2]!=0x300000 or native[1]+native[2]!=table_end:
                raise ValueError('native Image4 reservation disagrees with monitor arena')
            table_end=native[1]
        if (not work <= table_arena['work_base'] <= table_arena['next_table'] <=
                table_arena['work_end'] == table_end or
                any(value & 4095 for value in table_arena.values())):
            raise ValueError('invalid monitor table arena bounds')
        table_arena['remaining_pages'] = (table_arena['work_end']-table_arena['next_table'])//4096
        # Independent stopped readback of the allocator's ownership and free
        # list. Canonical table walks must stay in one allocation domain and
        # cannot point at a page that the allocator considers available.
        pool_base = work+field_offset('context', 'table_pool')
        capacity = field_offset('table_pool', 'next') - field_offset('table_pool', 'owner')
        if not 0 < capacity <= 65535:
            raise ValueError('invalid table-pool index capacity')
        owners = read(pool_base+field_offset('table_pool', 'owner'), capacity)
        links = struct.unpack(f'<{capacity}H',
            read(pool_base+field_offset('table_pool', 'next'), capacity * 2))
        pool = {}
        for name in ('head', 'count', 'reused', 'released', 'releases'):
            size = 4 if name in ('head', 'count') else 8
            pool[name] = int.from_bytes(read(pool_base+field_offset('table_pool', name), size), 'little')
        used = (table_arena['next_table']-table_arena['work_base'])//4096
        if used > capacity or pool['count'] > used or any(owners[used:]):
            raise ValueError('invalid table-pool ownership extent')
        free, node = set(), pool['head']
        for _ in range(pool['count']):
            if node >= used or node in free or owners[node] != 255:
                raise ValueError('invalid table-pool free list')
            free.add(node)
            node = links[node]
        if node != capacity or free != {i for i in range(used) if owners[i] == 255}:
            raise ValueError('table-pool free list differs from ownership')
        domains = {}
        for owner_id in owners[:used]:
            domains[str(owner_id)] = domains.get(str(owner_id), 0)+1
        roots = audit['root_switch']['roots']
        live_tables, root_domains = set(), set()
        cached = struct.unpack('<448Q', read(work+field_offset('context', 'user_roots')+
                               field_offset('sptm_root_state', 'cache'), 64*56))
        cache_owners = {cached[i*7+1]: i+1 for i in range(64) if cached[i*7+6]}
        def owned_index(pa):
            if pa & 4095 or not table_arena['work_base'] <= pa < table_arena['next_table']:
                raise ValueError('owned table outside monitor arena')
            return (pa-table_arena['work_base'])//4096
        # Shared-region groups (SNAP_NATIVE_SHARED): 4K level-3 tables that
        # every nesting root's tree reaches. They form their own allocation
        # domain, exactly the live groups' pages (checked in full, content and
        # links, by the runtime audit); a tree may reach one only at level 3.
        group_pages, shared_enabled = set(), False
        if re.search(r' native_shared$', record_layout('context'), re.M):
            shared_size = int(re.findall(r'\[sizeof=(\d+),', record_layout('native_shared'))[0])
            shared_raw = read(work+field_offset('context', 'native_shared'), shared_size)
            if any(shared_raw):
                shared_enabled = True
                shared_api = runpy.run_path(str(ROOT / 'tools/native_shared_audit.py'))
                _, groups, _ = shared_api['decode'](shared_raw, field_offset('native_shared', 'group'),
                    field_offset('native_shared', 'index'))
                listed = [owned_index(p) for g in groups.values() for p in g['pages'] if p]
                group_pages = set(listed)
                domain = {i for i in range(used) if owners[i] == shared_api['OWNER']}
                if domain != group_pages or len(group_pages) != len(listed):
                    raise ValueError('shared group allocation domain differs from its groups')
        if shared_enabled != bool(audit.get('native_shared', {}).get('enabled')):
            raise ValueError('shared groups differ between the stopped context and the audit')
        def walk_owned(pa, level, owner_id):
            index = owned_index(pa)
            if level == 3 and index in group_pages:
                return
            if index in live_tables or owners[index] != owner_id:
                raise ValueError('live canonical table alias or owner mismatch')
            live_tables.add(index)
            if level == 3:
                return
            for pte in struct.unpack('<512Q', read(pa, 4096)):
                if pte & 3 == 3:
                    walk_owned(pte & 0x0000fffffffff000, level+1, owner_id)
        for root in roots:
            pa = int(root['shadow'], 16)
            owner_id = owners[owned_index(pa)]
            if (not 1 <= owner_id <= 64 or owner_id in root_domains or
                    cache_owners.get(pa) != owner_id):
                raise ValueError('invalid or shared root allocation domain')
            root_domains.add(owner_id)
            walk_owned(pa, 0, owner_id)
        # Private CPU copies may refer to shared canonical branches. Check the
        # allocation inventory separately, so no copy can be on the free list
        # or owned by a different cache slot even when its contents still match.
        # Native page tables (SNAP_NATIVE_TABLES) keep two permission variants
        # per source, shared by every CPU, in copy[0..1]; copy[2..5] stay zero.
        # Which layout applies is read from the stopped context (a native
        # monitor counts every install) and must agree with the audit.
        native_tables = False
        if re.search(r' native_stats$', record_layout('context'), re.M):
            names = re.findall(r'^\s*\d+ \|   uint64_t (\w+)$', record_layout('native_table_stats'), re.M)
            if 'installs' not in names:
                raise ValueError('native table counters without an install count')
            installs, = struct.unpack('<Q', read(work+field_offset('context', 'native_stats')+
                                               field_offset('native_table_stats', 'installs'), 8))
            native_tables = installs > 0
        if native_tables != bool(audit.get('native_tables', {}).get('enabled')):
            raise ValueError('native page tables differ between the stopped context and the audit')
        columns = 2 if native_tables else 6
        view_size = int(re.findall(r'\[sizeof=(\d+),', record_layout('sprr_views'))[0])
        private_pages = set()
        for root in roots:
            pa = int(root['shadow'], 16)
            owner_id = cache_owners[pa]
            state = work+field_offset('context', 'user_views')+(owner_id-1)*view_size
            canonical_root, count = struct.unpack('<2Q', read(state, 16))
            if canonical_root != pa or not 1 <= count <= 128:
                raise ValueError('invalid private table allocation inventory')
            records = read(state+field_offset('sprr_views', 'tables'), count*64)
            private_copies(records, owner_id, owners, owned_index, live_tables, private_pages, columns)
        if len(private_pages) != sum(r['private_copy_pages'] for r in audit['user_permissions']['roots']):
            raise ValueError('private table count differs from runtime audit')
        pool.update(owned_pages=domains, live_canonical_pages=len(live_tables),
                    canonical_domains_verified=True,
                    live_private_pages=len(private_pages), private_domains_verified=True,
                    native_tables=native_tables, private_copy_columns=columns,
                    shared_group_pages=len(group_pages),
                    available_pages=table_arena['remaining_pages']+pool['count'])
        table_arena['pool'] = pool
        # Arena pressure reclaim (monitors that have it): the low-water mark of
        # free pages at monitor-call entry and the cache slots given back.
        if re.search(r' arena_reclaim$', record_layout('context'), re.M):
            names = ('checks', 'low_water', 'clock', 'reclaims', 'slots', 'pages', 'retired',
                     'invalid', 'valid', 'alloc_failures', 'build_retries', 'flush_failures')
            reclaim = dict(zip(names, struct.unpack(f'<{len(names)}Q',
                read(work+field_offset('context', 'arena_reclaim'), 8*len(names)))))
            if (reclaim['flush_failures'] or reclaim['slots'] !=
                    reclaim['retired']+reclaim['invalid']+reclaim['valid'] or
                    (reclaim['checks'] and reclaim['low_water'] > capacity)):
                raise ValueError('invalid table-arena reclaim state')
            table_arena['reclaim'] = reclaim
        # These cached booleans belong to the pinned native ACM functions:
        # isFastSimTarget and isSEPAvailable. The boot argument changes native
        # dispatch policy; it does not populate SEP endpoints or keys.
        flags = va_read(0xfffffe000c8a3a50, 4)
        if any(value not in (0, 1) for value in flags):
            raise ValueError('invalid native credential policy booleans')
        credential_policy = dict(zip(('fastsim_initialized', 'fastsim_enabled',
                                      'sep_availability_initialized', 'sep_available'), flags))
        sep_state = runpy.run_path(str(ROOT / 'tools/sep-state.py'))['collect'](
            va_read, kernel.u32)
        # Record raw native startup state without calling into XNU or assigning
        # an unverified meaning to its private stage enum. In particular, a
        # status query alone would not prove that Exclave firmware executes.
        exclave_stage, = struct.unpack('<I', va_read(0xfffffe000c78c2c8, 4))
        exclave_boot_thread, = struct.unpack('<Q', va_read(0xfffffe000c78c2d0, 8))
        sptm_args = canonical(q(0xfffffe0007ebf100))
        sk_boot_byte = va_read(sptm_args+0x180, 1)[0]
        exclave_startup = dict(raw_stage=exclave_stage,
                              stage_va='0xfffffe000c78c2c8',
                              boot_thread=hex(exclave_boot_thread),
                              boot_thread_va='0xfffffe000c78c2d0',
                              sptm_args=hex(sptm_args),
                              sk_boot_byte=sk_boot_byte,
                              sk_bootstrapped_flag=bool(sk_boot_byte & 1),
                              boundary='Raw native startup state; no firmware execution inferred')
        auxkc_state = runpy.run_path(str(ROOT / 'tools/auxkc-state.py'))['collect'](
            va_read, kernel.u32)
        ioreg_state = None
        iocatalogue_state = None
        kernel_messages = None
        linked_auxkc = None
        aux_vtables = {}
        if args.auxkc:
            import auxkc as auxkc_format
            aux_data, aux_manifest = auxkc_format.load(args.auxkc, KERNEL_SHA)
            aux_collection = auxkc_format.Collection(aux_data)
            aux_base = int(auxkc_state['handoff']['base'], 16)
            if aux_base != xb.kc_load.Image(kernel.data).vmax:
                raise ValueError('resident AuxKC base is not the linked placement')
            ioreg_api = runpy.run_path(str(ROOT / 'tools/ioreg-state.py'))
            aux_vtables = ioreg_api['vtable_names'](
                [(aux_base + va, name) for va, name in auxkc_format.symbols(aux_collection)])
            linked_auxkc = dict(sha256=aux_manifest['sha256'], bundles=aux_manifest['bundles'],
                                base=hex(aux_base), classes=sorted(set(aux_vtables.values())))
        if args.ioreg or args.catalogue:
            ioreg = runpy.run_path(str(ROOT / 'tools/ioreg-state.py'))
            vtables = ioreg['vtable_names'](symbols)
            vtables.update(aux_vtables)
        if args.ioreg:
            ioreg_state = ioreg['collect'](va_read, kernel.u32, vtables,
                                           detail_classes=frozenset(aux_vtables.values()))
            kernel_messages = runpy.run_path(str(ROOT / 'tools/msgbuf-state.py'))['collect'](
                va_read, kernel.u32)
            if linked_auxkc is not None:
                # Registry rows whose vtable lies inside the AuxKC are its
                # instances even when kmutil stripped their symbols.
                top = aux_base + ((aux_collection.top + 0x3fff) & ~0x3fff)
                linked_auxkc['registry_entries'] = [
                    r for r in ioreg_state['entries'] if aux_base <= int(r['vtable'], 16) < top]
                names = [b.split('.')[-1] for b in aux_manifest['bundles']]
                linked_auxkc['kernel_messages'] = [
                    line for line in kernel_messages['text'].splitlines()
                    if any(name in line for name in names) or 'AuxKC' in line][-64:]
        if args.catalogue:
            try:
                iocatalogue_state = runpy.run_path(str(ROOT / 'tools/iocatalogue-state.py'))['collect'](
                    va_read, kernel.u32, vtables)
            except ValueError as error:
                # Preserve the other stopped evidence if this optional reader
                # encounters an unqualified native object shape or bound.
                iocatalogue_state = dict(complete=False, error=str(error))
        nvme_driver = None
        if args.nvme_driver:
            nvme_driver = runpy.run_path(str(ROOT/'tools/nvme-driver-state.py'))['collect'](
                va_read,kernel,ioreg_state['entries'])
        table_density = None
        if args.table_density_for:
            context_size=int(re.search(r'\[sizeof=(\d+),',record_layout('context'))[1])
            table_density=runpy.run_path(str(ROOT/'tools/table-density.py'))['collect'](
                user_processes['processes'],args.table_density_for,audit['user_permissions']['roots'],
                (work+context_size+4095)&~4095,table_arena['next_table'],read)
        if proxy.exceptions:
            raise ValueError('proxy exception during capture')
        ownership_user_roots_binding = None
        if args.ownership_user_roots:
            # Use uncached physical reads above and recheck the exact stopped
            # context after collection. Ownership is distinct from shadow equality.
            if (struct.unpack('<8Q', read(work+field_offset('context', 'services'), 64)) != resident_service or
                    struct.unpack('<36Q', read(work+register_address_offset, 288)) != current or
                    struct.unpack('<Q', read(work+cpu_offset+field_offset('vcpu', 'async_captured'), 8))[0] != kind or
                    struct.unpack('<Q', read(work+cpu_offset+field_offset('vcpu', 'service_acquires'), 8))[0] != acquired or
                    struct.unpack(f'<{xb.PARAMS_WORDS}Q', read(params_pa, xb.PARAMS_WORDS*8)) != params):
                raise ValueError('resident stop changed during ownership user capture')
            ownership_user_roots_binding = dict(
                audit_sha256=hashlib.sha256(audit_path.read_bytes()).hexdigest(),
                audited_roots=len(g['user_roots']), stop_identity_rechecked=True,
                boundary='Raw stopped user tables admitted by full ownership audit; uncached roots have no shadow-equivalence claim')
        result = dict(kernel_sha256=KERNEL_SHA, monitor_sha256=audit['monitor_sha256'],
                      guest_profile=audit.get('guest_profile'), stop_owner=owner,
                      ownership_user_roots_binding=ownership_user_roots_binding,
                      cpu_topology=cpu_topology,
                      scheduler_binding=scheduler_binding,
                      processor_scheduler=processor_scheduler,
                      root_match_symbols=root_match_symbols, root_state=root_state,
                      root_mount=root_mount,const_region=const_region,image4_boot_uuid=image4_boot_uuid,
                      mounted_volumes=mounted_volumes,
                      nvme_driver=nvme_driver,
                      image4_nonce_set=image4_nonce_set,image4_v2_nonce_digest=image4_v2_nonce_digest,
                      address_space_switch=address_space_switch,
                      user_page_request=user_page_request,
                      user_unmap_request=user_unmap_request,
                      user_condemn_request=user_condemn_request,
                      user_table_request=user_table_request,
                      commpage_roots=commpage_roots,retype_request=retype_request,
                      initial_user_page=initial_user_page,
                      aes_startup=aes_startup,
                      kernel_task=hex(task),
                      task_queue_offset=hex(off), task_count_offset=hex(off+0x28),
                      thread_queue_offset='0x410', threads=threads,
                      user_processes=user_processes, ipc_send_waits=ipc_send_waits,
                      device_open_waits=device_open_waits,
                      table_arena=table_arena,
                      table_density=table_density,
                      credential_policy=credential_policy,
                      sep_state=sep_state,
                     exclave_startup=exclave_startup,
                     auxkc_state=auxkc_state,
                     linked_auxkc=linked_auxkc,
                     ioreg_state=ioreg_state,
                     iocatalogue_state=iocatalogue_state,
                     kernel_messages=kernel_messages,
                     rtbuddy_route_waits=rtbuddy_route_waits,
                      bootpolicy_waits=bootpolicy_waits,
                      pages_read=len(pages))
    finally:
        proxy.link.close()
    output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(dict(kernel_task=result['kernel_task'], threads=len(threads),
                          queue_offset=result['task_queue_offset'], pages_read=result['pages_read'])))
    for row in threads:
        target = row['continuation']
        print(row['tid'], row['name'], row['wait_event'],
              target['nearest_symbol']+'+'+target['offset'] if target else row['continuation_raw'])


if __name__ == '__main__':
    main()
