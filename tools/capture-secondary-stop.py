#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture a selected CPU's stopped frames without resuming it.

The main xnuboot log's register dump belongs to CPU0. A later global event
can belong to a different CPU; never combine that event with CPU0's registers.
This reader binds the saved secondary snapshot to resident code, descriptor
and output bytes before walking its own stack through the shared guest root.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import run
import xnuboot as xb


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device', required=True)
    ap.add_argument('--prefix', required=True)
    ap.add_argument('--cpu', required=True, type=int, choices=range(6))
    ap.add_argument('--user-frames',action='store_true',
                    help='also read bounded user frame candidates through this CPU active root')
    ap.add_argument('--resident-stop', action='store_true',
                    help='capture audited CPU0 after a host timeout; verify stable resident registers instead of a missing run report')
    ap.add_argument('--object-register', type=int, choices=range(31),
                    help='also read the stopped native object addressed by this x register')
    ap.add_argument('--object-size', type=lambda value: int(value, 0), default=0x200,
                    help='bounded object read size, default 0x200; must fit one guest page')
    args = ap.parse_args()
    if not 0 < args.object_size <= 0x1000:
        raise ValueError('object read must be between 1 and 4096 bytes')
    if not re.fullmatch(r'[a-z0-9-]+', args.prefix):
        raise ValueError('invalid artifact prefix')
    base = ROOT / 'build' / args.prefix
    audit = json.loads(Path(f'{base}-audit.json').read_text())
    if args.resident_stop:
        if args.cpu or not audit.get('runtime_stop_qualified'):
            raise ValueError('resident-only capture requires audited CPU0 terminal state')
        admission = json.loads(Path(f'{base}-admission.json').read_text())
        result = dict(post_inventory=admission['inventory'])
    else:
        result = json.loads(Path(f'{base}-result.json').read_text())
    if args.cpu:
        row = next(r for r in result['cpus'] if r['slot'] == args.cpu)
        if not (row['phase'] == 4 and row['cleanup'] == 1 and
                row['affinity_result'] == 1 and row['entered'] == 1):
            raise ValueError('selected CPU has no completed, powered-off run')
        snapshot = row['output_words']
        if len(snapshot) != 44 or not snapshot[6]:
            raise ValueError('selected CPU has no captured registers')
        regs = snapshot[8:]
    else:
        if audit['service'][1] != 0x100000001:
            raise ValueError('primary CPU was not the audited normal stop owner')
        row = dict(affinity=int(result['post_inventory']['boot_mpidr'], 16))
    secondary = runpy.run_path(str(ROOT / 'tools/secondary-runtime.py'))
    kernel = runpy.run_path(str(ROOT / 'tools/kc-xref.py'))['Kernelcache'](
        ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p')
    if hashlib.sha256(kernel.data).hexdigest() != (
            'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'):
        raise ValueError('capture requires the audited J700 26A428 kernelcache')
    proxy = run.connect(args.device, tries=1)
    try:
        def read(pa, size):
            if not 0 < size <= 0x200000:
                raise ValueError('invalid read size')
            return b''.join(proxy.readmem(pa + i, min(65536, size - i), live=True)
                            for i in range(0, size, 65536))

        info = proxy.bootinfo()
        work, work_size = run.resident_work(proxy, info)
        blob = (ROOT / 'build/xnuboot.bin').read_bytes()
        if (hashlib.sha256(blob).hexdigest() != audit['monitor_sha256'] or
                read(info['heap_base'] + run.CODE_AT, len(blob)) != blob):
            raise ValueError('resident monitor differs from audited build')
        if args.cpu:
            descriptor = int(result['base'], 16) + args.cpu * 4096
            if not work <= descriptor <= work + work_size - 4096:
                raise ValueError('descriptor outside monitor arena')
            expected = struct.pack('<37Q', *(row[k] for k in secondary['FIELDS']))
            if read(descriptor, len(expected)) != expected:
                raise ValueError('resident secondary descriptor changed')
            if row['cpu'] != work + secondary['VCPUS_OFFSET'] + args.cpu * secondary['VCPU_SIZE']:
                raise ValueError('CPU pointer differs from pinned monitor layout')
            output, = struct.unpack('<Q', read(row['cpu'] + 8, 8))
            if output & 4095 or not work <= output <= work + work_size - 4096:
                raise ValueError('output outside monitor arena')
            if read(output, 352) != struct.pack('<44Q', *snapshot):
                raise ValueError('resident secondary snapshot changed')
        else:
            # Pinned vcpu layout, independently checked by the runtime auditor.
            cpu = work + secondary['VCPUS_OFFSET']
            kind, = struct.unpack('<Q', read(cpu + 1128, 8))
            exceptions, = struct.unpack('<Q', read(cpu + 1112, 8))
            if kind in (1,2,3):
                resident_register_address = cpu + 2000
                regs = list(struct.unpack('<36Q', read(resident_register_address, 288)))
            elif kind==0 and exceptions:
                # A normal terminal guest exception uses last_exc, not the
                # separate asynchronous/stage-2 snapshot. Verify it against
                # this run's printed final exception before reading its stack.
                resident_register_address = cpu + 1424
                regs = list(struct.unpack('<36Q', read(resident_register_address, 288)))
                kind=4
            else:
                raise ValueError('primary CPU has no terminal register snapshot')
            service = struct.unpack('<8Q', read(work + secondary['SERVICES_OFFSET'], 64))
            acquired, = struct.unpack('<Q', read(cpu + 2352, 8))
            audited = next(r for r in audit['cpu_rows'] if r['slot'] == 0)
            if (list(service) != audit['service'] or
                    acquired != audited['service_acquires']):
                raise ValueError('primary snapshot is not from the audited stop')
            if not args.resident_stop:
                log = Path(f'{base}.log').read_text()
                if kind==4:
                    matches=list(re.finditer(
                        r'  PC (0x[0-9a-f]+)   ESR_EL1 (0x[0-9a-f]+)[^\n]*'
                        r'   FAR_EL1 (0x[0-9a-f]+)\n'
                        r'  SP (0x[0-9a-f]+)   SPSR_EL1 (0x[0-9a-f]+)(?: \(last\))?\n'
                        r'((?:    x[^\n]*\n)+)',log))
                    matched=matches[-1] if matches else None
                    if not matched:raise ValueError('no final primary exception in log')
                    pc,esr,far,sp,pstate=map(lambda v:int(v,16),matched.groups()[:5])
                    if (pc,esr,far,sp,pstate)!=(regs[33],regs[34],regs[35],regs[31],regs[32]):
                        raise ValueError('live exception header differs from captured log')
                    stop=matched[6]
                    header_ok=True
                else:
                    stop = re.split(r'  (?:stage-2|asynchronous|monitor) stop PC ', log, maxsplit=1)[1]
                    stop = stop.split('  exception return', 1)[0]
                    header = re.match(r'(0x[0-9a-f]+), SP (0x[0-9a-f]+), PSTATE (0x[0-9a-f]+)', stop)
                    header_ok=bool(header and tuple(map(lambda v:int(v,16),header.groups()))==
                                   (regs[33],regs[31],regs[32]))
                expected = {int(k): int(v, 16) for k, v in
                            re.findall(r'x(\d+)\s+(0x[0-9a-f]+)', stop)}
                if (len(expected) != 31 or any(regs[i] != expected[i] for i in range(31)) or
                        not header_ok):
                    raise ValueError('live primary registers differ from the captured log')
            else:
                # A timeout means the host never printed its report. Bind this
                # capture to the independently audited terminal service token,
                # then require the full snapshot to remain byte-identical.
                if (read(resident_register_address, 288) != struct.pack('<36Q', *regs) or
                        list(struct.unpack('<8Q', read(work + secondary['SERVICES_OFFSET'], 64))) != audit['service']):
                    raise ValueError('resident terminal snapshot changed during capture')
            snapshot = [0]*6 + [kind, 0] + regs
        params_pa, = struct.unpack('<Q', read(work, 8))
        params = struct.unpack(f'<{xb.PARAMS_WORDS}Q', read(params_pa, xb.PARAMS_WORDS * 8))
        geometry = audit['geometry']
        if (params[0], params[30], params[31]) != (
                geometry['root'], geometry['ram_low'], geometry['ram_high']):
            raise ValueError('resident guest geometry differs from audited run')

        def ram(pa, size):
            if not geometry['ram_low'] <= pa < pa + size <= geometry['ram_high']:
                raise ValueError('translation or frame outside guest RAM')
            return read(pa, size)

        def translation(va):
            table = params[0]
            if va < (1 << 47):
                roots=[r for r in audit['root_switch']['roots']
                       if args.cpu in r['active_cpus']]
                if len(roots)!=1 or roots[0]['format']!=0:
                    raise ValueError('no audited active 16K userspace root')
                table=int(roots[0]['root'],16)
            elif va < 0xffff800000000000:
                raise ValueError('noncanonical virtual address')
            root=table
            for shift in (36, 25, 14):
                slot=table + 8 * ((va >> shift) & 2047)
                desc, = struct.unpack('<Q', ram(slot, 8))
                if desc & 3 != 3:
                    raise ValueError(f'non-page translation for {va:#x} at level {shift}')
                table = desc & 0x0000ffffffffc000
            return dict(root=root,slot=slot,pte=desc,pa=table+(va&0x3fff),
                        selector=((desc>>4)&12)|((desc>>53)&3))

        def translate(va):
            return translation(va)['pa']

        def va_read(va, size):
            if not 0 < size <= 0x4000 - (va & 0x3fff):
                raise ValueError('read crosses guest page')
            return ram(translate(va), size)

        frames = []
        fp = regs[29]
        reason = 'frame limit'
        for _ in range(32):
            if fp & 15:
                reason = 'unaligned frame pointer'
                break
            try:
                previous, lr = struct.unpack('<2Q', va_read(fp, 16))
            except ValueError as exc:
                reason = str(exc)
                break
            canonical = lr if fp < (1 << 47) or lr < (1 << 47) else (lr & ((1 << 48) - 1)) | 0xffff000000000000
            frames.append(dict(fp=hex(fp), previous_fp=hex(previous),lr=hex(lr), canonical_lr=hex(canonical),
                               owner=kernel.owner(canonical)))
            if not previous or previous <= fp or previous - fp > 0x4000:
                reason = 'end or non-monotonic frame chain'
                break
            fp = previous
        capture = dict(cpu=args.cpu, physical_affinity=hex(row['affinity']),
                       capture_source='audited-resident-stop' if args.resident_stop else 'run-report',
                       user_mapping_qualified=audit.get('user_mapping_qualified', True),
                       snapshot_kind=snapshot[6], pc=hex(regs[33]),
                       pc_owner=kernel.owner(regs[33]), esr=hex(regs[34]),
                       far=hex(regs[35]), sp=hex(regs[31]), pstate=hex(regs[32]),
                       registers={str(i): hex(v) for i, v in enumerate(regs[:31])},
                       frame_chain=frames, frame_chain_end=reason,
                       monitor_sha256=audit['monitor_sha256'])
        if args.user_frames:
            user_fp=regs[29] if not regs[32]&31 else 0
            bridge=None
            if not user_fp and frames:
                last=frames[-1]
                candidate=int(last['previous_fp'],16)
                if (int(last['fp'],16)>=0xffff800000000000 and
                    0<candidate<(1<<47) and not candidate&15 and
                    0<int(last['lr'],16)<(1<<47)):
                    user_fp=candidate
                    bridge=dict(kernel_fp=last['fp'],user_fp=hex(candidate),
                                saved_user_lr=last['lr'],inferred_from_frame_boundary=True)
            if user_fp:
                collect=runpy.run_path(str(ROOT/'tools/user-frame-chain.py'))['collect']
                capture['user_frame_candidates']=collect(va_read,user_fp)
                if bridge:capture['user_frame_candidates']['bridge']=bridge
            else:capture['user_frame_candidates']=dict(unavailable='no bounded user frame entry')
        try:
            pc=regs[33]
            capture['instruction']=dict(pa=hex(translate(pc)),
                data_hex=va_read(pc,min(64,0x4000-(pc&0x3fff))).hex())
        except ValueError as exc:
            capture['instruction_error']=str(exc)
        if regs[33]==0xfffffe000c22c29c and regs[16]==0x300000002:
            device,sid,iova,pointer,size,options=regs[:6]
            count=((iova&0x3fff)+size+0x3fff)>>14
            if (not 0<size<=0x2000000 or not 0<count<=2048 or pointer&7 or
                    (pointer&0x3fff)+count*8>0x4000):
                raise ValueError('invalid native DART page-list capture')
            payload=ram(pointer,count*8)
            preload=audit['firmware'].get('sep_preload')
            entries=[]
            for index,(pa,) in enumerate(struct.iter_unpack('<Q',payload)):
                if pa&0x3fff or not geometry['frame_low']<=pa<geometry['frame_high']:
                    raise ValueError('native DART list contains an invalid frame')
                metadata=ram(geometry['frame_map']+((pa-geometry['frame_low'])>>14)*16,16)
                allocated=geometry['alloc_low']<=pa<geometry['alloc_high']
                boot=any(base<=pa<base+pages*0x4000
                         for _,base,pages in geometry.get('boot_ranges',[]))
                sep=bool(preload and int(preload['pa'],16)<=pa<
                         int(preload['pa'],16)+preload['bytes'])
                entries.append(dict(index=index,pa=hex(pa),metadata_hex=metadata.hex(),
                                    allocator=allocated,disposable_boot=boot,sep_preload=sep))
            capture['dart_map_request']=dict(device=device,sid=sid,iova=hex(iova),
                pointer=hex(pointer),bytes=size,options=hex(options),count=count,
                list_sha256=hashlib.sha256(payload).hexdigest(),entries=entries)
        if regs[33]==0xfffffe000ba7ce0c:
            operands=[]
            for register in (0,1):
                address=regs[register]
                detail=translation(address)
                pa=detail['pa'];frame=pa&~0x3fff
                meta=geometry['frame_map']+((frame-geometry['frame_low'])>>14)*16
                operands.append(dict(register=register,va=hex(address),
                    **{key:(value if key=='selector' else hex(value))
                       for key,value in detail.items()},
                    metadata=ram(meta,16).hex()))
            capture['permission_copy']=dict(bytes=regs[2],requested_pperm=hex(regs[8]),
                                             operands=operands)
        if regs[33]==0xfffffe000c22b56c and regs[16]==8:
            target,pointer,count=regs[:3]
            if target&16383 or not 1<=count<=64 or (pointer&16383)+count*24>16384:
                raise ValueError('invalid UNMAP_DISJOINT request')
            def disjoint_meta(pa):
                if not geometry['frame_low']<=pa<geometry['frame_high']:
                    raise ValueError('disjoint metadata address outside frame map')
                return ram(geometry['frame_map']+((pa-geometry['frame_low'])>>14)*16,16)
            entries=[]
            for root,va,template in struct.iter_unpack('<QQQ',ram(pointer,count*24)):
                meta=disjoint_meta(root)
                item=dict(root=hex(root),va=hex(va),template=hex(template),
                          root_metadata=meta.hex())
                if not root&16383 and meta[2] in (18,19) and meta[12]==0:
                    table=root
                    for level in range(1,4):
                        slot=table+8*((va>>(14+(3-level)*11))&2047)
                        pte,=struct.unpack('<Q',ram(slot,8))
                        if level==3 or pte&3!=3:break
                        table=pte&0x0000ffffffffc000
                    item.update(slot=hex(slot),level=level,pte=hex(pte),
                        table_metadata=disjoint_meta(slot&~16383).hex(),
                        target_matches=level==3 and pte&3==3 and
                            (pte&0x0000ffffffffc000)==target)
                entries.append(item)
            capture['unmap_disjoint_request']=dict(target_pa=hex(target),
                target_metadata=disjoint_meta(target).hex(),input_pa=hex(pointer),
                input_metadata=disjoint_meta(pointer).hex(),count=count,stride=24,
                entries=entries)
        if regs[33]==0xfffffe000c22bc74 and regs[16]==40:
            pointer,count=regs[:2]
            if pointer&7 or not 1<=count<=64:raise ValueError('invalid BATCH_SIGN_USER_POINTER request')
            records=ram(pointer,count*24);entries=[]
            for n,(value,modifier,key,padding) in enumerate(struct.iter_unpack('<QQII',records)):
                entries.append(dict(index=n,pointer=hex(value),modifier=hex(modifier),
                    key_selector=key,padding=hex(padding)))
            capture['batch_sign_user_pointer']=dict(input_pa=hex(pointer),count=count,
                stride=24,key_selectors=sorted({r['key_selector'] for r in entries}),entries=entries)
        if regs[33]==0xfffffe000c22b4b8 and regs[16]==5:
            root,va,count,templates,options=regs[:5]
            if not 0<count<=64 or templates&7:raise ValueError('invalid UPDATE_REGION request')
            def update_meta(pa):
                return ram(geometry['frame_map']+((pa-geometry['frame_low'])>>14)*16,16).hex()
            root_meta=bytes.fromhex(update_meta(root))
            if root_meta[2] not in (18,19) or root_meta[12]:raise ValueError('UPDATE_REGION capture requires a typed 16K root')
            requested=struct.unpack(f'<{count}Q',ram(templates,count*8));entries=[]
            for n,value in enumerate(requested):
                addr=va+n*0x4000;table=root
                for level in range(1,4):
                    slot=table+8*((addr>>(14+(3-level)*11))&2047)
                    pte,=struct.unpack('<Q',ram(slot,8))
                    if level==3 or pte&3!=3:break
                    table=pte&0x0000ffffffffc000
                entry=dict(va=hex(addr),slot=hex(slot),level=level,old=hex(pte),
                    requested=hex(value),table_metadata=update_meta(slot&~0x3fff))
                if level==3 and pte&3==3:
                    entry['data_metadata']=update_meta(pte&0x0000ffffffffc000)
                entries.append(entry)
            capture['update_region_request']=dict(root=hex(root),root_metadata=root_meta.hex(),
                root_kind='shared' if root_meta[2]==19 else 'user',
                va=hex(va),count=count,templates=hex(templates),options=hex(options),entries=entries)
        if regs[33]==0xfffffe000c22b47c and regs[16]==4:
            root,va,level=regs[:3]
            def unmap_metadata(pa):
                return ram(geometry['frame_map']+((pa-geometry['frame_low'])>>14)*16,16)
            root_meta=unmap_metadata(root)
            if root_meta[12] or root_meta[2] not in (18,19) or level not in (1,2):
                raise ValueError('UNMAP_TABLE capture requires a typed 16K root')
            table=root
            for current in range(1,level+1):
                shift=14+(3-current)*11;slot=table+8*((va>>shift)&2047)
                pte,=struct.unpack('<Q',ram(slot,8))
                if pte&3!=3:raise ValueError('UNMAP_TABLE source descriptor is absent')
                table=pte&0x0000ffffffffc000
            data=ram(table,0x4000)
            capture['unmap_table_request']=dict(root=hex(root),va=hex(va),level=level,
                root_metadata=root_meta.hex(),slot=hex(slot),descriptor=hex(pte),
                parent_metadata=unmap_metadata(slot&~0x3fff).hex(),
                child=hex(table),child_metadata=unmap_metadata(table).hex(),
                child_nonzero_entries=sum(bool(v) for v, in struct.iter_unpack('<Q',data)))
        if regs[33]==0xfffffe000c22b65c and regs[16]==11:
            root,shared,start,pages=regs[:4]
            def frame_metadata(pa):
                address=geometry['frame_map']+((pa-geometry['frame_low'])>>14)*16
                return ram(address,16)
            user_meta=frame_metadata(root);shared_meta=frame_metadata(shared)
            if (user_meta[2]!=18 or shared_meta[2]!=19 or
                    user_meta[12] or shared_meta[12] or start&0x1ffffff or
                    not 0<pages<=64*2048 or pages%2048):
                raise ValueError('unnest capture requires bounded, whole 16K L3 tables')
            def l2_slot(root,va):
                desc,=struct.unpack('<Q',ram(root+8*((va>>36)&2047),8))
                if desc&3!=3:raise ValueError('unnest root entry is not a table')
                slot=(desc&0x0000ffffffffc000)+8*((va>>25)&2047)
                desc,=struct.unpack('<Q',ram(slot,8))
                return slot,desc
            tables=[]
            for page in range(0,pages,2048):
                va=start+(page<<14)
                user_slot,user_desc=l2_slot(root,va)
                shared_slot,shared_desc=l2_slot(shared,va)
                if user_desc!=shared_desc or user_desc&3!=3:
                    raise ValueError('stopped unnest does not target a current nested table')
                child=user_desc&0x0000ffffffffc000
                data=ram(child,0x4000);meta=frame_metadata(child)
                if meta[2]!=21 or meta[4]!=3:
                    raise ValueError('unnest child is not a typed shared L3')
                leaves=[dict(va=hex(va+(i<<14)),pte=hex(value))
                        for i,(value,) in enumerate(struct.iter_unpack('<Q',data)) if value]
                tables.append(dict(va=hex(va),user_slot=hex(user_slot),
                    shared_slot=hex(shared_slot),descriptor=hex(user_desc),
                    table=hex(child),metadata=meta.hex(),nonzero_leaves=leaves))
            capture['unnest_request']=dict(root=hex(root),shared=hex(shared),
                start=hex(start),pages=pages,page_shift=14,end=hex(start+(pages<<14)),
                user_metadata=user_meta.hex(),shared_metadata=shared_meta.hex(),
                tables=tables,requested_alias=next(r for r in audit['root_switch']['roots']
                    if int(r['root'],16)==root))
            populated=[e for e in audit['shared_table_state']['entries']
                       if e['level']==3 and e['child_references']]
            if len(populated)<=64:
                leaves=[]
                for entry in populated:
                    table=int(entry['pa'],16)
                    for i,(pte,) in enumerate(struct.iter_unpack('<Q',ram(table,0x4000))):
                        if pte&3==3:
                            leaves.append(dict(slot=hex(table+8*i),pte=hex(pte),
                                data_metadata=frame_metadata(pte&0x0000ffffffffc000).hex()))
                capture['audited_shared_leaves']=leaves
        if regs[33]==0xfffffe000c22b404 and regs[16]==2 and regs[0]!=params[0]:
            roots=[r for r in audit['root_switch']['roots']
                   if int(r['root'],16)==regs[0]]
            root=regs[0]
            if root&0x3fff or not geometry['frame_low']<=root<geometry['frame_high']:
                raise ValueError('MAP_PAGE root outside frame map')
            rm=ram(geometry['frame_map']+((root-geometry['frame_low'])>>14)*16,16)
            if rm[2] not in (18,19) or rm[12]!=0:
                raise ValueError('MAP_PAGE capture requires typed 16K user/shared root')
            va=regs[1];table=regs[0];slot=0;old=0
            if not 0<=va<(1<<47) or va&0x3fff:
                raise ValueError('invalid MAP_PAGE user address')
            for shift in (36,25,14):
                slot=table+8*((va>>shift)&2047)
                old,=struct.unpack('<Q',ram(slot,8))
                if shift==14 and not old:
                    table=0;break
                if old&3!=3:raise ValueError('MAP_PAGE existing source is not a page')
                table=old&0x0000ffffffffc000
            source_pa=table
            table_frame=slot&~0x3fff
            tm=ram(geometry['frame_map']+((table_frame-geometry['frame_low'])>>14)*16,16)
            # A shared-root request has no directly installed canonical root.
            # Find actual cached roots aliasing this exact source slot, then
            # independently verify each corresponding canonical view.
            mirrors=list(roots)
            if rm[2]==19:
                for candidate in audit['root_switch']['roots']:
                    if candidate['format']!=0:continue
                    t=int(candidate['root'],16);candidate_slot=0
                    for shift in (36,25,14):
                        candidate_slot=t+8*((va>>shift)&2047)
                        d,=struct.unpack('<Q',ram(candidate_slot,8))
                        if shift==14 or d&3!=3:break
                        t=d&0x0000ffffffffc000
                    if candidate_slot==slot:mirrors.append(candidate)
            leaves=[]
            aliases=[]
            for mirror in mirrors:
                parts=[]
                for part in range(4):
                    table=int(mirror['shadow'],16)
                    for shift in (39,30,21,12):
                        if table&4095 or not work<=table<=work + work_size-4096:
                            raise ValueError('MAP_PAGE shadow outside arena')
                        desc,=struct.unpack('<Q',read(table+8*(((va+part*4096)>>shift)&511),8))
                        if not desc:
                            table=0;break
                        if desc&3!=3:raise ValueError('MAP_PAGE shadow is not a page')
                        table=desc&0x0000fffffffff000
                    if ((not old and desc) or (old and (not desc or desc&(3<<58) or
                        table!=source_pa+part*4096 or
                        (desc&(0xfff|(3<<53)))!=(old&(0xfff|(3<<53)))))):
                        raise ValueError('MAP_PAGE old source and shadow disagree')
                    parts.append(hex(desc))
                if mirror in roots:leaves=parts
                aliases.append(dict(root=mirror['root'],shadow=mirror['shadow'],
                    active_cpus=mirror['active_cpus'],leaves=parts))
            metadata={}
            for name,pa in [('old',source_pa),('new',regs[2]&0x0000ffffffffc000)]:
                if name=='old' and not old:continue
                if not geometry['frame_low']<=pa<geometry['frame_high']:
                    raise ValueError('MAP_PAGE frame outside metadata map')
                address=geometry['frame_map']+((pa-geometry['frame_low'])>>14)*16
                metadata[name]=dict(pa=hex(pa),bytes_hex=ram(address,16).hex())
            capture['map_request']=dict(root=hex(regs[0]),va=hex(va),
                source_slot=hex(slot),old_pte=hex(old),new_pte=hex(regs[2]),
                options=hex(regs[3]),shadow_leaves=leaves,metadata=metadata,
                root_kind='shared' if rm[2]==19 else 'user',root_metadata=rm.hex(),
                table_metadata=tm.hex(),canonical_aliases=aliases,
                shadow_kind='canonical source mirror' if roots else 'shared aliases only')
        if regs[33]==0xfffffe000c22b4f4 and regs[16]==6:
            target,list_pa,count,options=regs[:4]
            if target&0x3fff or list_pa&7 or not 1<=count<=64:
                raise ValueError('invalid UPDATE_DISJOINT request geometry')
            if not geometry['frame_low']<=target<geometry['frame_high']:
                raise ValueError('UPDATE_DISJOINT target outside metadata map')
            records=[]
            for root,va,template in struct.iter_unpack('<3Q',ram(list_pa,count*24)):
                roots=[r for r in audit['root_switch']['roots'] if int(r['root'],16)==root]
                if root&0x3fff or not geometry['frame_low']<=root<geometry['frame_high']:
                    raise ValueError('UPDATE_DISJOINT root outside frame map')
                rm=ram(geometry['frame_map']+((root-geometry['frame_low'])>>14)*16,16)
                if root==params[0]:
                    kind='kernel';shadow=int(audit['kernel_permissions']['canonical_root'],16)
                    active_cpus=list(range(6))
                    if va<0xffff800000000000:raise ValueError('noncanonical kernel update VA')
                else:
                    if rm[2] not in (18,19) or rm[12]!=0 or va>=1<<47:
                        raise ValueError('UPDATE_DISJOINT capture requires a typed 16K record')
                    kind='user' if rm[2]==18 else 'shared'
                    shadow=int(roots[0]['shadow'],16) if roots else None
                    active_cpus=roots[0]['active_cpus'] if roots else []
                if va&0x3fff:raise ValueError('unaligned UPDATE_DISJOINT VA')
                table=root
                for shift in (36,25,14):
                    slot=table+8*((va>>shift)&2047)
                    old,=struct.unpack('<Q',ram(slot,8))
                    if old&3!=3:
                        raise ValueError('UPDATE_DISJOINT source is not a populated page')
                    table=old&0x0000ffffffffc000
                source_pa=table;leaves=[]
                for part in range(4) if shadow is not None else ():
                    table=shadow;at=(va&((1<<47)-1))+part*4096
                    for shift in (39,30,21,12):
                        if table&4095 or not work<=table<=work + work_size-4096:
                            raise ValueError('UPDATE_DISJOINT shadow outside arena')
                        desc,=struct.unpack('<Q',read(table+8*((at>>shift)&511),8))
                        if desc&3!=3:raise ValueError('UPDATE_DISJOINT shadow is not populated')
                        table=desc&0x0000fffffffff000
                    if (table!=source_pa+part*4096 or desc&(1<<59) or
                            (desc&(0xfff|(3<<53)))!=(old&(0xfff|(3<<53)))):
                        raise ValueError('UPDATE_DISJOINT source/shadow mismatch')
                    leaves.append(hex(desc))
                records.append(dict(root=hex(root),va=hex(va),template=hex(template),
                    old_pte=hex(old),source_slot=hex(slot),source_pa=hex(source_pa),
                    target_matches=source_pa==target,canonical_leaves=leaves,
                    active_cpus=active_cpus,root_kind=kind,root_metadata=rm.hex(),
                    canonical_shadow=None if shadow is None else hex(shadow)))
            meta=geometry['frame_map']+((target-geometry['frame_low'])>>14)*16
            capture['update_disjoint_request']=dict(target=hex(target),list_pa=hex(list_pa),
                count=count,options=hex(options),target_metadata=ram(meta,16).hex(),records=records)
        try:
            capture['stack_hex']=va_read(regs[31],0x4000-(regs[31]&0x3fff)).hex()
        except ValueError as exc:
            # A parked peer can have SP at the unmapped end of an empty
            # stack. Retain its register snapshot and explicit read failure
            # instead of losing all evidence from this otherwise valid stop.
            capture['stack_hex']=''
            capture['stack_error']=str(exc)
        if args.object_register is not None:
            va = regs[args.object_register]
            capture['object'] = dict(register=args.object_register, va=hex(va),
                                    size=args.object_size,
                                    data_hex=va_read(va, args.object_size).hex())
        conflict=next((r for r in audit.get('user_map_conflict',{}).get('rows',[])
                       if r['cpu']==args.cpu and r['count'] and not r['options']),None)
        if conflict:
            # This historical result must remain distinct from the current
            # slot: XNU may have removed/replaced it since receiving status6.
            try:
                actual,=struct.unpack('<Q',va_read(conflict['pointer'],8))
                capture['last_conflict_slot']=dict(va=hex(conflict['va']),
                    root=hex(conflict['root']),pointer=hex(conflict['pointer']),
                    old_pte=hex(conflict['old']),wanted_pte=hex(conflict['wanted']),
                    current_pte=hex(actual),retry_installed_requested_pte=actual==conflict['wanted'])
            except ValueError as exc:
                capture['last_conflict_slot_error']=str(exc)
    finally:
        proxy.link.close()
    path = Path(f'{base}-cpu{args.cpu}-stop.json')
    path.write_text(json.dumps(capture, indent=2) + '\n')
    print(json.dumps({k: capture[k] for k in ('cpu', 'physical_affinity', 'pc', 'pc_owner', 'esr', 'far')}))
    print(f'{len(frames)} frames; {path}')


if __name__ == '__main__':
    main()
