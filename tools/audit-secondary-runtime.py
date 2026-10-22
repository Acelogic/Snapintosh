#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read-only ownership, private-map and runtime audit after an SMP boot slice.

Unlike the historical CPU0-only device checkpoint, this permits a secondary
to have executed. It reconstructs CPU/DMA references and validates unused
runtime banks separately from the executor that actually ran.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy
import struct
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'probes'),str(ROOT/'tools')]
import run
import xnuboot as xb
from appledt import DeviceTree
from stage2audit import audit_private_stage2
from ramdisk import ROOT_HASH_NODE
from audit_sep_rom import audit_history as audit_rom_history, audit_buffers as audit_rom_buffers, audit_bootstrap
from audit_sep_pnon import audit_buffers as audit_pnon_buffers
from audit_sep_xars import audit_buffers as audit_xars_buffers
from audit_sep_sks import decode as decode_sks, STATE_BYTES as SKS_STATE_BYTES
# Loader-side arena extent; the compiled registry layout must agree (checked below).
TXM_ARENA_BYTES=xb.TXM_ASPACE_PAGES*0x4000
TXM_ASPACE_LIMIT=TXM_ARENA_BYTES//256

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device',required=True);ap.add_argument('--prefix',required=True)
    ap.add_argument('--guest-profile',default='j700ap-26A428',
                    help='profile used for the resident boot, including board policy')
    ap.add_argument('--expect-deferred',action='store_true',
                    help='verify resident firmware omits the selected absent-device subtrees')
    ap.add_argument('--expect-ramdisk',action='store_true',
                    help='require a reserved raw APFS RAMDisk and its selected boot contract')
    ap.add_argument('--expect-isc',action='store_true',
                    help='require both GPT copies and a separate ISC APFS partition')
    ap.add_argument('--ramdisk-mode', choices=('md0', 'iokit'), default='md0',
                    help='expected resident RAMDisk firmware contract')
    ap.add_argument('--expect-root-hash',action='store_true',
                    help='require the profile-bound active-root hash payload in resident firmware')
    ap.add_argument('--allow-unlaunched',action='store_true',
                    help='audit an early CPU0 stop with no secondaries launched')
    ap.add_argument('--diagnose-primary-timeout',action='store_true',
                    help='retain memory evidence after CPU0 service timeout; does not qualify a clean runtime stop')
    ap.add_argument('--diagnose-user-mapping-mismatches',action='store_true',
                    help='record user mapping/PTE mismatches for stopped-state diagnosis; still exits unsuccessfully on mismatches')
    ap.add_argument('--auxkc',help='the pinned linked AuxKC the run loaded (linked-collection profiles)')
    ap.add_argument('--trust-additions',help='the CDHash rows an augmented trust-cache run appended')
    args=ap.parse_args()
    xb.configure_guest(args.guest_profile)
    if bool(args.auxkc)!=xb.GUEST_PROFILE.aux_collection_linked:
        ap.error('--auxkc is required exactly for linked-collection profiles')
    trust_spec=xb.trust_cache_spec(args.trust_additions)
    if not re.fullmatch(r'[a-z0-9-]+',args.prefix):raise ValueError('invalid artifact prefix')
    layout=subprocess.run(['clang','--target=aarch64-unknown-none-elf','-ffreestanding',
        '-mgeneral-regs-only','-Ishadow','-Icompat','-Xclang','-fdump-record-layouts',
        '-fsyntax-only','probes/xnuboot.c'],cwd=ROOT,capture_output=True,text=True,check=True).stdout
    def offset(kind,field,nested=False):
        block=next(b for b in layout.split('*** Dumping AST Record Layout')
                   if re.search(r'^\s*0 \| struct '+kind+r'\n',b))
        indent=r'\s+' if nested else '   '
        matches=re.findall(r'^\s*(\d+) \|'+indent+r'\S.* '+field+r'$',block,re.M)
        assert len(matches)==1, (kind,field,matches)
        return int(matches[0])
    refs=runpy.run_path(str(ROOT/'tools/audit-sptm-refs.py'))
    darts=runpy.run_path(str(ROOT/'tools/audit-dart-tables.py'))
    secondary=runpy.run_path(str(ROOT/'tools/secondary-runtime.py'))
    proxy=run.connect(args.device,tries=1)
    try:
        info=proxy.bootinfo();work, work_size = run.resident_work(proxy, info)
        end=work + work_size
        table_end=end
        def read(pa,n):
            if not n>=0:raise ValueError('invalid length')
            return b''.join(proxy.readmem(pa+i,min(65536,n-i),live=True) for i in range(0,n,65536))
        def q(pa):return struct.unpack('<Q',read(pa,8))[0]
        # Bind the running monitor to the just-built executable, not a stale log.
        blob=(ROOT/'build/xnuboot.bin').read_bytes()
        assert read(info['heap_base']+run.CODE_AT,len(blob))==blob
        param_pa=q(work);words=struct.unpack(f'<{xb.PARAMS_WORDS}Q',read(param_pa,xb.PARAMS_WORDS*8))
        def param(name):return words[offset('params',name)//8]
        txm_native_report=dict(enabled=False)
        txm_dynamic_expected=None
        if re.search(r' txm_native$',layout,re.M):
            at=offset('params','txm_native')//8
            native_params=words[at:at+4]
            if native_params[0]:
                import txmnative
                assert native_params[0]==txmnative.HELPER_BASE and native_params[2]==txmnative.WORK_BYTES
                assert native_params[1]+native_params[2]==end and not native_params[1]&0x3fff
                table_end=native_params[1]
                assert q(work+offset('context','work_end'))==table_end
                native_record=json.loads((ROOT/'build'/f'{args.prefix}-txm-native.json').read_text())
                assert native_record['image_sha256']==txmnative.IMAGE_SHA
                assert native_record['generation']==info['stage_generation']
                assert int(native_record['work'],16)==table_end
                assert native_record['source_sha256']==hashlib.sha256((ROOT/'probes/txmnative.py').read_bytes()).hexdigest()
                for segment in native_record['code']:
                    assert hashlib.sha256(read(native_params[0]+segment['offset'],segment['bytes'])).hexdigest()==segment['sha256']
                native_keys=('phase','calls','loads','auth_failures','last_entry','last_status','panic_code','panic_arg','payload_size','manifest_size')
                ns=dict(zip(native_keys,struct.unpack('<10Q',read(work+offset('context','txm_native'),80))))
                ls=dict(zip(('calls','successes','failures','last_status','payload_pa','manifest_pa','copied_bytes'),
                    struct.unpack('<7Q',read(work+offset('context','txm_load'),56))))
                assert ns['phase']==1 and ns['calls']==ns['loads']+1 and not ns['panic_code'] and not ns['panic_arg']
                assert ls['calls']==ns['loads']==ls['successes']+ls['failures']
                assert ls['successes'] in (0,1,2,3)
                if ls['successes']:
                    txm_dynamic_expected=[]
                    for typ,prefix,digest in [
                        (13,'installed-image4-identity-300s-20260926','da62f681a539e4384dd815f84dec898c3e570cbccd00318d6d9e5e0a03bdb111'),
                        (14,'installed-txm-load-300s-20260926','3713854a229f36e7d79640c0c5c0c3f9158fdc2d6189c33904b9e754756f0f7d'),
                        (27,'installed-txm-dual-300s-20260926','8613fd4e512d91c94ef09283c6891b84f6b2df3ffb13a6db74628ad41901fac7')][:ls['successes']]:
                        captured=json.loads((ROOT/f'build/{prefix}-txm12-input.json').read_text())
                        original=bytes.fromhex(captured['payload']['hex'])
                        assert captured['cache_type']==typ and hashlib.sha256(original).hexdigest()==digest
                        txm_dynamic_expected.append((typ,original[23:]))
                    assert ls['copied_bytes']==sum(len(data) for _,data in txm_dynamic_expected)
                txm_native_report=dict(enabled=True,params=[hex(v) for v in native_params],state=ns,load=ls,
                    executable_bytes_verified=True,workspace_outside_table_pool=True)
        def aux_range():
            if not re.search(r' auxkc$',layout,re.M):return (0,0,0,0)
            base=offset('params','auxkc')//8
            return tuple(words[base:base+4])
        import nativecalls as native_api
        native_mode=bool(param('stub_count')&native_api.FLAG)
        hvc_mode=bool(param('stub_count')&native_api.HVC_FLAG)
        assert not hvc_mode or native_mode
        native_report=dict(enabled=native_mode,mode='hvc' if hvc_mode else 'private')
        writer_enabled=q(work+offset('context','writer_breakpoints_enabled'))
        assert writer_enabled in (0,1) and (not writer_enabled or native_mode)
        writer_api=runpy.run_path(str(ROOT/'tools/audit-native-writers.py'))
        writer_report=dict(enabled=bool(writer_enabled),cpus=[])
        native_pages=[]
        if native_mode:
            assert param('stub_count')==(native_api.FLAG|(native_api.HVC_FLAG if hvc_mode else 0)|7)
            image=xb.kc_load.Image(xb.DEFAULT_KERNELCACHE.read_bytes())
            image_pa=param('vbar')-(param('vbar_va')-image.vmin)
            admitted=bytearray(image.data)
            if hvc_mode:
                native_api.patch_hvc_calls(image,admitted,image_pa)
            native_contract=native_api.contract(image,admitted,image_pa,hvc=hvc_mode)
            native_pages=list(words[8:15])
            assert native_pages==native_contract['pages'] and words[15]==0
            resident_pages={pa:read(pa,4096) for pa in native_pages}
            for va,word in native_contract['call_sites'].items():
                pa=image_pa+va-image.vmin
                if hvc_mode:word=native_api.HVC_WORD
                assert struct.unpack_from('<I',resident_pages[pa&~4095],pa&4095)[0]==word
            for va,word in native_contract['writer_sites'].items():
                pa=image_pa+va-image.vmin
                assert struct.unpack_from('<I',resident_pages[pa&~4095],pa&4095)[0]==word
            native_report.update(kernel_sha256=native_contract['kernel_sha256'],
                resident_call_and_writer_words_verified=True,
                call_pages=[hex(p) for p in native_pages[:5]],
                writer_pages=[hex(p) for p in native_pages[5:]],cpus=[])
        assert param('write_watch_pa')==0
        geometry=dict(root=words[0],frame_map=words[43],frame_low=words[44],frame_high=words[45],
            alloc_low=words[46],alloc_high=words[47],aperture_va=words[48],
            aperture_size=words[47]-words[30],ram_low=words[30],ram_high=words[31])
        # Inspect the uploaded firmware through the resident handoff geometry
        # and declared tree length, not a locally regenerated tree. x1 is VA.
        bootargs_va=param('x1');handoff_pa=param('watch_pa')
        bootargs_pa=handoff_pa+0x1000
        assert geometry['ram_low']<=bootargs_pa<geometry['ram_high']-xb.BOOT_ARGS_SIZE
        bootargs=read(bootargs_pa,xb.BOOT_ARGS_SIZE)
        assert struct.unpack_from('<HH',bootargs)==(xb.BOOT_ARGS_REVISION,xb.BOOT_ARGS_VERSION)
        virt_base=struct.unpack_from('<Q',bootargs,8)[0]
        assert bootargs_va==virt_base-xb.HANDOFF_SPAN+0x1000
        tree_va,tree_len=struct.unpack_from('<QI',bootargs,0x60)
        tree_pa=handoff_pa+tree_va-(virt_base-xb.HANDOFF_SPAN)
        tree_offset=0x18000 if xb.GUEST_PROFILE.boot_framebuffer_aux else 0x10000
        assert tree_pa==handoff_pa+tree_offset and 0<tree_len<=xb.HANDOFF_SPAN-tree_offset
        assert geometry['ram_low']<=tree_pa<tree_pa+tree_len<=geometry['ram_high']
        tree_blob=read(tree_pa,tree_len);tree=DeviceTree(tree_blob)
        if txm_native_report['enabled']:
            assert native_params[3]==tree_len
            assert read(native_params[1]+0x200000,tree_len)==tree_blob
            assert hashlib.sha256(tree_blob).hexdigest()==native_record['tree_sha256']
        assert tree.serialize()==tree_blob
        if xb.GUEST_PROFILE.boot_framebuffer_aux:
            import bootfb
            assert tree.get(bootfb.NODE,'compatible')==bootfb.MATCH.encode()+b'\0'
            if xb.GUEST_PROFILE.boot_framebuffer_nub:
                assert tree.get(bootfb.NODE,'AAPL,boot-display') is None
                assert tree.get(bootfb.NUB_NODE,'compatible')==bootfb.NUB_MATCH.encode()+b'\0'
                assert tree.get(bootfb.NUB_NODE,'AAPL,boot-display')==b''
                assert tree.children[bootfb.NUB_PARENT].count(bootfb.NUB_NODE)==1
            else:
                assert tree.get(bootfb.NODE,'AAPL,boot-display')==b''
                assert bootfb.NUB_NODE not in tree.nodes
            if not xb.GUEST_PROFILE.aux_collection_linked:
                image=xb.kc_load.Image(xb.DEFAULT_KERNELCACHE.read_bytes())
                assert hashlib.sha256(image.data).hexdigest()==bootfb.KERNEL_SHA256
                values=struct.unpack('<3Q',read(handoff_pa+bootfb.HANDOFF_BASE,24))
                assert values==bootfb.handoff_values(virt_base-xb.HANDOFF_SPAN,image.vmax)
        linked_auxkc=None
        if xb.GUEST_PROFILE.aux_collection_linked:
            # With or without the boot framebuffer bundle: one handoff slot.
            import auxkc as auxkc_format
            import bootfb
            image=xb.kc_load.Image(xb.DEFAULT_KERNELCACHE.read_bytes())
            assert hashlib.sha256(image.data).hexdigest()==bootfb.KERNEL_SHA256
            values=struct.unpack('<3Q',read(handoff_pa+bootfb.HANDOFF_BASE,24))
            collection,admission=xb.linked_auxkc(image,args.auxkc)
            # The VA placement and handoff words are a pure function of the
            # pinned collection; the PA comes from the resident params (the
            # run's place() moved the layout) and must be loader-owned memory.
            aux_base=image.vmax;span=(collection.top+0x3fff)&~0x3fff
            aux_va_base,aux_va_end,aux_pa,aux_pa_end=aux_range()
            assert values==auxkc_format.handoff_values(collection,aux_base,image.vmax)
            assert (aux_va_base,aux_va_end,aux_pa_end)==(aux_base,aux_base+span,aux_pa+span)
            assert not aux_pa&0x3fff and geometry['ram_low']<=aux_pa<aux_pa+span<=geometry['alloc_low']
            assert not (aux_pa<tree_pa+tree_len and aux_pa+span>tree_pa)
            linked_auxkc=dict(admission=admission,resident=runpy.run_path(
                str(ROOT/'tools/auxkc-state.py'))['resident'](read,collection,aux_base,aux_pa,
                image.vmin,image.vmax))
        deferred_roots=[s.node for s in xb.GUEST_PROFILE.deferred_subtrees]
        published_deferred=sorted(n for n in tree.nodes if any(
            n==root or n.startswith(root+'/') for root in deferred_roots))
        published_functions=[(s.node,s.name) for s in xb.GUEST_PROFILE.deferred_functions
                             if tree.get(s.node,s.name) is not None]
        if args.expect_deferred:
            assert not published_deferred
            assert not published_functions
            expected=xb.build_devicetree()
            assert set(expected.nodes)<=set(tree.nodes)
        cmdline=bootargs[0x6c:0x478].split(b'\0',1)[0].decode('ascii')
        disk_property=tree.get('/device-tree/chosen/memory-map','RAMDisk')
        installed=xb.GUEST_PROFILE.installed_root
        spec=installed or xb.GUEST_PROFILE.root_hash
        extent_property=tree.get('/device-tree/chosen','boot-ramdmg-extents')
        if installed is not None:
            assert not args.expect_ramdisk and not args.expect_isc, 'installed boot has no RAM media'
            assert disk_property is None and extent_property is None, 'installed boot published RAM media'
            assert tree.get('/device-tree/chosen','boot-uuid')==installed.volume_group_uuid.encode('ascii')+b'\0'
            assert tree.get('/device-tree/chosen','apfs-preboot-uuid')==installed.volume_group_uuid.encode('ascii')+b'\0'
            assert tree.get('/device-tree/chosen','root-snapshot-name')==installed.root_snapshot_name.encode('ascii')+b'\0'
            assert not any(w.startswith(('rd=','rootdev=','boot-uuid=')) for w in cmdline.split())
        elif args.ramdisk_mode=='iokit':
            assert disk_property is None, 'IOKit image must not also publish an md0 device'
            disk_property=extent_property
            assert disk_property is not None and len(disk_property)==16
            assert spec is not None and spec.boot_uuid
            assert tree.get('/device-tree/chosen','boot-uuid')==spec.boot_uuid.encode('ascii')+b'\0'
            assert tree.get('/device-tree/chosen','apfs-preboot-uuid')==spec.boot_uuid.encode('ascii')+b'\0'
            assert tree.get('/device-tree/chosen','boot-ramdmg-size')==disk_property[8:]
            assert not any(w.startswith(('rd=','rootdev=','boot-uuid=')) for w in cmdline.split())
        else:
            assert extent_property is None, 'unexpected IOKit RAM image in md0 capture'
        if args.expect_ramdisk:
            assert disk_property is not None, 'resident RAMDisk property missing'
        ramdisk=None
        if disk_property is not None:
            assert len(disk_property)==16, 'invalid RAMDisk descriptor size'
            disk_pa,disk_size=struct.unpack('<QQ',disk_property)
            assert not (disk_pa|disk_size)&0x3fff and disk_size>=0x4000
            assert geometry['ram_low']<=disk_pa<disk_pa+disk_size<=geometry['alloc_low']
            assert disk_pa>=tree_pa+tree_len
            assert struct.unpack_from('<Q',bootargs,32)[0]==geometry['alloc_low']
            if args.ramdisk_mode=='md0':
                assert [w for w in cmdline.split() if w.startswith(('rd=','rootdev='))]==['rd=md0']
            header=read(disk_pa,48)
            media_layout=None
            root_pa,root_size=disk_pa,disk_size
            if header[32:36]!=b'NXSB':
                assert args.ramdisk_mode=='iokit', 'GPT RAM disk requires IOKit mode'
                import bootmedia
                media_layout=bootmedia.inspect(lambda off,size: read(disk_pa+off,size),disk_size)
                root_offset,root_size=media_layout['root']
                root_pa=disk_pa+root_offset
                isc_offset,isc_size=media_layout['isc']
                isc_header=read(disk_pa+isc_offset,48)
                assert isc_header[32:36]==b'NXSB', 'ISC partition is not raw APFS'
                assert struct.unpack_from('<IQ',isc_header,36)==(4096,isc_size//4096)
                header=read(root_pa,48)
            assert header[32:36]==b'NXSB', 'resident root partition is not raw APFS'
            block_size,blocks=struct.unpack_from('<IQ',header,36)
            assert block_size==4096 and block_size*blocks==root_size
            ramdisk=dict(mode=args.ramdisk_mode,pa=hex(disk_pa),bytes=disk_size,end=hex(disk_pa+disk_size),
                         block_size=block_size,blocks=blocks,header_hex=header.hex(),
                         root_pa=hex(root_pa),root_bytes=root_size,gpt=media_layout,
                         reserved_before_allocator=True,full_payload_verified=False)
        auth_blob=tree.get(ROOT_HASH_NODE,spec.property_name) if spec is not None else None
        if args.expect_isc:
            assert ramdisk is not None and ramdisk.get('gpt') is not None, 'ISC GPT layout missing'
        if args.expect_root_hash:
            assert auth_blob is not None, 'resident root-hash property missing'
        root_hash=None
        if auth_blob is not None:
            assert ramdisk is not None or installed is not None, 'root-hash capture requires a bound root'
            assert len(auth_blob)==spec.payload_bytes
            digest=hashlib.sha256(auth_blob).hexdigest()
            assert digest==spec.payload_sha256, 'resident root-hash payload differs from profile'
            root_hash=dict(node=ROOT_HASH_NODE,property=spec.property_name,
                           bytes=len(auth_blob),sha256=digest,
                           expected_root_image_sha256=spec.image_sha256 if installed is None else None,
                           root_source='installed-ssd' if installed is not None else 'ramdisk',
                           root_image_readback_verified=False)
            if spec.no_protected_data_recipe is not None:
                assert tree.get('/device-tree/chosen','protected-data-access')==bytes(4), \
                    'ephemeral BaseSystem incorrectly advertises protected-data access'
                root_hash['protected_data_access']=False
            if spec.no_sep_firmware_recipe is not None:
                assert tree.get('/device-tree/chosen','sepfw-load-at-boot')==bytes(4), \
                    'ephemeral BaseSystem incorrectly requests SEP firmware loading'
                root_hash['sepfw_load_at_boot']=False
        sep_preload=None
        sep_contract=(param('sep_firmware_pa'),param('sep_firmware_size'))
        geometry['sep_firmware']=sep_contract
        # The monitor's rule (probes/xnuboot.c sep_firmware_released): once
        # the SEP ROM model took the bootstrap handoff, XNU may free the
        # SEPFW extent to the VM, and its bytes are no longer the payload.
        sep_released=False
        for index in range(words[90]):
            model=words[91+index*8:99+index*8]
            if model[0]==45 and model[7] and sep_contract[1]:
                address=work+offset('context','model_state')+index*13000
                sep_released=struct.unpack('<Q',read(address+offset('device_sep_asc','service_ready'),8))[0]!=0
        geometry['sep_released']=sep_released
        sep_spec=xb.GUEST_PROFILE.sep_preload
        sep_descriptor=tree.get('/device-tree/chosen/memory-map','SEPFW')
        if sep_spec is not None:
            assert tree.get(sep_spec.node,'sepfw-loaded')==b''
            assert sep_descriptor is not None and len(sep_descriptor)==16
            sep_pa,sep_size=struct.unpack('<QQ',sep_descriptor)
            assert sep_contract==(sep_pa,sep_size), 'SEP DMA resource differs from resident preload'
            assert not (sep_pa|sep_size)&0x3fff and sep_size==sep_spec.size
            assert geometry['ram_low']<=sep_pa<sep_pa+sep_size<=geometry['alloc_low']
            if ramdisk is not None:
                assert sep_pa+sep_size<=int(ramdisk['pa'],16)
            sep_digest=hashlib.sha256(read(sep_pa,sep_size)).hexdigest()
            assert sep_released or sep_digest==sep_spec.sha256, 'resident SEP payload differs from profile'
            assert all(tree.get('/device-tree/chosen/memory-map',name) is None
                       for name in ('SEPPatches','uStuff'))
            sep_preload=dict(pa=hex(sep_pa),bytes=sep_size,sha256=sep_digest,
                             full_payload_verified=sep_digest==sep_spec.sha256,
                             released_to_xnu=sep_released,firmware_execution_verified=False)
        else:
            assert sep_descriptor is None, 'unexpected SEP preload in selected profile'
            assert sep_contract==(0,0), 'unexpected SEP DMA resource in selected profile'
        firmware=dict(bootargs_pa=hex(bootargs_pa),bootargs_va=hex(bootargs_va),
            tree_pa=hex(tree_pa),tree_va=hex(tree_va),
            tree_bytes=tree_len,tree_sha256=hashlib.sha256(tree_blob).hexdigest(),
            node_count=len(tree.nodes),deferred_roots=deferred_roots,
            command_line=cmdline,ramdisk=ramdisk,expected_ramdisk=args.expect_ramdisk,
            root_hash=root_hash,expected_root_hash=args.expect_root_hash,sep_preload=sep_preload,
            withdrawn_functions=[(s.node,s.name) for s in xb.GUEST_PROFILE.deferred_functions],
            published_functions=published_functions,
            published_deferred=published_deferred,expected_deferred=args.expect_deferred)
        slide=offset('params','slide')//8;config=words[slide:slide+30]
        assert config[5]<=8
        boot=[tuple(config[6+i*3:9+i*3]) for i in range(config[5])]
        state=read(work+offset('context','slide'),32+50*24)
        count=struct.unpack_from('<Q',state,8)[0];assert count<=50
        aliases=[struct.unpack_from('<3Q',state,32+i*24) for i in range(count)] if count else boot
        geometry.update(boot_ranges=boot,boot_aliases=aliases,
                        moved=[r for r in aliases if count and config[3]<=r[0]<config[4]])
        managed=refs['ManagedFrames'](**{k:geometry[k] for k in
            ('frame_map','frame_low','frame_high','alloc_low','alloc_high','boot_ranges','boot_aliases')},
            released=sep_contract if sep_released else (0,0))
        fm=read(geometry['frame_map'],((geometry['frame_high']-geometry['frame_low'])>>14)*16)
        users=[];retained=[];shared=[]
        for pa in managed.frames():
            i=((pa-geometry['frame_low'])>>14)*16;meta=fm[i:i+16]
            if meta[2]==18:users.append(pa)
            elif meta[2]==19:shared.append(pa)
            elif meta[2]==23 and meta[6:8]==b'\0\0':retained.append(pa)
        geometry.update(user_roots=users,detached_commpages=retained,shared_roots=shared)
        roots=[];qspi=[];dwi=[];i2c=[];pmp=[];spmi=[];watchdog_smc=[]
        sep_aon=[];sep_asc=[];dart_runtime=[];cpu_perf_reads=[];acc_sampler=[];aes_idle=[];aes_software=[];aes_key_disable=[]
        ans=[];ans_references=[]
        for index in range(words[90]):
            model=words[91+index*8:99+index*8]
            if model[0]==8:
                assert model==(8,0x3082dc000,0x8000,0,0x40,0x44,0x48,0)
                address=work+offset('context','model_state')+index*13000+offset('device_state','aes_key_disable_writes',nested=True)
                writes=struct.unpack('<4I',read(address,16))
                aes_key_disable.append(dict(index=index,writes=list(writes),hardware_keys_available=False))
            if model[0]==50:
                # Virtual ANS2 (docs/ANS2-M2-20260925.md): the reservation sits
                # directly above the work arena; its state page is read only.
                import ansstate
                spec=xb.GUEST_PROFILE.ans_boot
                assert spec is not None
                from answindow import WINDOW_MODE
                assert model==(50,0x38dcc0000,0x60000,end,spec.disk_bytes,1039,
                               WINDOW_MODE if spec.window else 0,0)
                # The IOP firmware state the guest was handed, read back from its
                # own device tree (docs/ANS2-FIRMWARE-STATE-20260925.md). Recorded,
                # not asserted: a mismatch must not cost the rest of the collection.
                from devicemodel import ANS_FIRMWARE_PROPERTIES,ans_firmware_state
                nub=spec.node+'/iop-ans-nub'
                published=tuple((name,tree.get(nub,name)) for name in ANS_FIRMWARE_PROPERTIES)
                # With SNAP_ANS_ASYNC the async block follows (agents/nvme-async); without it the extra
                # bytes carry no magic and decode as before.
                raw_state=read(end,ansstate.SIZE+ansstate.ASYNC_SIZE)
                # The DMA references the model holds (queue bases, mapped command ids,
                # SART regions) are SPTM references like the DART's: the ownership audit
                # below counts both (docs/ANS2-QUEUES-20260925.md).
                ans_references=ansstate.references(raw_state)
                physical_nvme = None
                if spec.window:
                    from answindow import WINDOW_NVMEH, decode_nvmeh
                    physical_nvme = decode_nvmeh(read(end+WINDOW_NVMEH,0x120))
                    launched = json.loads((ROOT/'build'/f'{args.prefix}-launch.json').read_text())
                    adopted = json.loads((ROOT/'build'/f'{args.prefix}-nvme-adopt.json').read_text())
                    assert physical_nvme['writable'] == ('--ans-writable' in launched['arguments'])
                    assert physical_nvme['params_hex'] == adopted['guest_params_hex']
                ans.append(dict(index=index,reservation=hex(end),disk_bytes=model[4],
                                backend=('ssd-window-readwrite' if physical_nvme['writable'] else
                                         'ssd-window-readonly') if spec.window else 'ramdisk',
                                physical_nvme=physical_nvme,
                                state=ansstate.decode(raw_state),dma_references=ans_references,
                                firmware_state={name:None if value is None else value.hex()
                                                for name,value in published},
                                firmware_state_published=published==ans_firmware_state(end)))
            if model[0]==47:
                assert model==(47,0x38500c000,0x4000,5,42,1107,21,1)
                address=work+offset('context','model_state')+index*13000+offset('device_state','aes',nested=True)
                # Never collect software key bytes, expanded round keys or IVs.
                ready,running,mask,threshold,irq,tag=struct.unpack('<6I',read(address,24))
                header=struct.unpack('<I',read(address+offset('aes_engine','header'),4))[0]
                used,need=struct.unpack('<2I',read(address+offset('aes_engine','used'),8))
                commands,transfers,nbytes,barriers,exports=struct.unpack('<5Q',read(address+offset('aes_engine','commands'),40))
                assert ready==1 and running<=1 and not mask&~0x3efff and not irq&~0x20
                assert threshold in (0,64) and tag<=255 and used<=7 and need<=8
                assert not need or used<need
                pmgr=[i for i in range(words[90])
                      if words[91+i*8:95+i*8]==(18,0x300700000,0x11000,0)]
                assert len(pmgr)==1
                gate=struct.unpack('<I',read(work+offset('context','model_state')+
                    pmgr[0]*13000+offset('device_state','pmgr_aes',nested=True),4))[0]
                assert gate&~0x300 in (0,4,15)
                assert gate&15==15 or not (running or mask or irq or header or used or need)
                aes_software.append(dict(index=index,ready=ready,running=running,
                    irq_enable=hex(mask),irq_status=hex(irq),fifo_threshold=threshold,
                    completed_tag=tag,pending_header=hex(header),pending_used=used,pending_need=need,
                    commands=commands,transfers=transfers,bytes=nbytes,barriers=barriers,iv_exports=exports,
                    command_backend=True,dma_backend=True,power_gate=hex(gate)))
            if model[0]==46:
                assert model==(46,0x38500c000,0x4000,5,0,0,0,0)
                address=work+offset('context','model_state')+index*13000
                raw=struct.unpack('<8I',read(address+offset('device_state','aes_idle',nested=True),32))
                ready,running,mask,threshold,starts,stops,reads,writes=raw
                assert ready==1 and running<=1 and not mask&~0x3effe
                assert threshold in (0,0x40) and not reads&~0x248 and not writes&~0x1c4
                aes_idle.append(dict(index=index,ready=ready,running=running,
                    irq_enable=hex(mask),fifo_threshold=threshold,starts=starts,stops=stops,
                    reads=hex(reads),writes=hex(writes),command_backend=False,dma_backend=False))
            if model[0]==20:
                assert model[1] in (0x210e78000,0x211e78000)
                assert model[2:]==(0x1000,int(model[1]==0x211e78000),0,0,0,0)
                data=read(work+offset('context','model_state')+index*13000+
                          offset('device_state','cpu_perf_reads',nested=True),128)
                for row in range(2):
                    raw=struct.unpack_from('<8Q',data,row*64)
                    if not raw[0]:
                        assert not any(raw)
                        continue
                    assert raw[2]==model[1]+0x48+row*8 and raw[7]<6
                    cpu_perf_reads.append(dict(index=index,offset=hex(0x48+row*8),
                        count=raw[0],pc=hex(raw[1]),ipa=hex(raw[2]),esr=hex(raw[3]),
                        supplied=hex(raw[4]),restored=hex(raw[5]),lr=hex(raw[6]),cpu=raw[7]))
            if model[0]==18 and model[1]==0x300700000:
                assert model==(18,0x300700000,0x11000,0,1,0,0,0)
                level,=struct.unpack('<I',read(work+offset('context','model_state')+
                    index*13000+offset('device_state','pmgr_sep_aon',nested=True),4))
                sep_aon.append(dict(index=index,state=hex(level),level=level&15))
            if model[0]==44:
                assert model==(44,0x3082b8000,0x1000,8,0,0,0,0)
                disarms,=struct.unpack('<I',read(work+offset('context','model_state')+
                    index*13000+offset('device_state','watchdog_smc_disarms',nested=True),4))
                watchdog_smc.append(dict(index=index,base=hex(model[1]),disarms=disarms))
            if model[0]==37:
                assert model==(37,0x210e44000+model[3]*0x1000000,0x1000,model[3],0,0,0,0)
                assert model[3] in (0,1)
                address=work+offset('context','model_state')+index*13000
                restored,=struct.unpack('<Q',read(address+offset('device_state','acc_boot_policy',nested=True),8))
                selectors=struct.unpack('<10Q',read(address+offset('device_state','acc_selectors',nested=True),80))
                written,=struct.unpack('<Q',read(address+offset('device_state','acc_selector_written',nested=True),8))
                expected=(0x8a0f,0x800f,0x8c0f,0x9c0f,0x9e0f,0x810f,0xb90f,0xbe0f,0xbf0f,0xd40f)
                assert restored<=1 and written&~0x3ff==0
                assert restored or not written
                assert all(v in (0,expected[i]) and (written&(1<<i) or not v)
                           for i,v in enumerate(selectors))
                acc_sampler.append(dict(index=index,base=hex(model[1]),cluster=model[3],
                    restored=restored,written=hex(written),
                    selectors={hex(0x18+i*16):hex(v) for i,v in enumerate(selectors)},
                    counter_producer=False))
            if model[0]==45:
                assert model in ((45,0x282600000,0x9000,8,0,0,0,0),
                                 (45,0x282600000,0x9000,8,1,346,343,0),
                                 (45,0x282600000,0x9000,8,1,346,343,1),
                                 (45,0x282600000,0x9000,8,1,346,343,3),
                                 (45,0x282600000,0x9000,8,1,346,343,7),
                                 (45,0x282600000,0x9000,8,1,346,343,11),
                                 (45,0x282600000,0x9000,8,1,346,343,15),
                                 (45,0x282600000,0x9000,8,1,346,343,19),
                                 (45,0x282600000,0x9000,8,1,346,343,27),
                                 (45,0x282600000,0x9000,8,1,346,343,59))
                reply_transport=bool(model[4])
                address=work+offset('context','model_state')+index*13000
                data=read(address,offset('device_sep_asc','xars')+16*8)
                def asc_field(name,fmt):
                    return struct.unpack_from(fmt,data,offset('device_sep_asc',name))
                ready,=asc_field('ready','<I');enable=asc_field('enable','<2I')
                count,=asc_field('count','<I');staged_valid,=asc_field('staged_valid','<I')
                staged,=asc_field('staged','<Q');submitted,=asc_field('submitted','<Q')
                requests=asc_field('request','<16Q')
                replies=asc_field('reply','<16Q')
                consumed,=asc_field('consumed','<Q')
                published,=asc_field('published','<Q')
                delivered,=asc_field('delivered','<Q')
                reply_count,=asc_field('reply_count','<I')
                status_replies,=asc_field('rom_status_replies','<Q')
                last_request,=asc_field('rom_last_request','<Q')
                last_reply,=asc_field('rom_last_reply','<Q')
                rom_buffers={k:asc_field(k,'<Q')[0] for k in
                    ('rom_stage','rom_firmware_iova','rom_firmware_size','rom_shared_iova','rom_shared_size')}
                service={k:asc_field(k,'<Q')[0] for k in ('service_ready','service_notifications')}
                service['service_resources']=list(asc_field('bootstrap','<8I'))
                service['entropy_words']=asc_field('entropy_words','<Q')[0]
                service['entropy_last_request']=hex(asc_field('entropy_last_request','<Q')[0])
                service['status_queries']=asc_field('status_queries','<Q')[0]
                service['status_last_request']=hex(asc_field('status_last_request','<Q')[0])
                service['virtual_effective_status']=0 if model[7]&12 else None
                pnon_words=asc_field('pnon','<26Q')
                service['pnon']=dict(zip(('ready','advertisements','negotiations','queries','last_request','last_reply'),pnon_words[:6]))
                service['pnon'].update(stage=list(pnon_words[6:8]),size=list(pnon_words[8:10]),
                    iova=list(pnon_words[10:12]),physical=[list(pnon_words[12:19]),list(pnon_words[19:26])])
                xars_words=asc_field('xars','<16Q')
                service['xars']=dict(zip(('ready','advertisements','negotiations','queries','last_request','last_reply'),xars_words[:6]))
                service['xars'].update(stage=list(xars_words[6:8]),size=list(xars_words[8:10]),
                    iova=list(xars_words[10:12]),physical=[list(xars_words[12:14]),list(xars_words[14:16])])
                if model[7]&32:
                    assert offset('sep_sks_endpoint','wire')==128
                    assert offset('sep_sks_wire_state','environment')==12
                    service['sks']=decode_sks(read(address+offset('device_sep_asc','sks'),SKS_STATE_BYTES))
                assert ready==1 and all(e<=1 for e in enable) and count<=8 and staged_valid<=1
                assert submitted>=consumed and submitted-consumed==count and not any(requests[count*2:])
                assert reply_count<=8 and published>=delivered and published-delivered==reply_count
                assert not any(replies[reply_count*2:])
                assert reply_transport or not (consumed or published or delivered or reply_count)
                assert staged_valid or not staged
                assert not staged_valid or count<8
                sep_asc.append(dict(index=index,base=hex(model[1]),ready=ready,
                    enable=list(enable),count=count,submitted=submitted,
                    consumed=consumed,published=published,delivered=delivered,reply_count=reply_count,
                    reply_transport=reply_transport,
                    rom_status_producer=bool(model[7]),rom_status_replies=status_replies,
                    rom_last_request=hex(last_request),rom_last_reply=hex(last_reply),**rom_buffers,**service,
                    service_bootstrap=bool(model[7]&2),
                    pnon_recovery=bool(model[7]&4),
                    xars_refusal=bool(model[7]&8),
                    pnon_refusal=bool(model[7]&16),
                    sks_startup=bool(model[7]&32),
                    staged=hex(staged),staged_valid=staged_valid,
                    control_reads=list(asc_field('reads','<2Q')),
                    control_writes=list(asc_field('writes','<2Q')),
                    requests=[[hex(requests[2*i]),hex(requests[2*i+1])] for i in range(count)],
                    replies=[[hex(replies[2*i]),hex(replies[2*i+1])] for i in range(reply_count)],
                    receive_producer=bool(published),firmware_running=False))
                audit_rom_history(sep_asc[-1])
                # Validate raw wire shape, then discard queued random DATA from
                # the serialized audit. Counts/tags suffice for reconstruction.
                for pair in sep_asc[-1]['replies']:
                    if int(pair[0],16)&0xffff00ff==0x360000:
                        pair[0]=hex(int(pair[0],16)&0xffffffff)
                        sep_asc[-1]['entropy_payload_redacted']=True
            if model[0] in (9,48):
                raw=struct.unpack('<283I',read(work+offset('context','model_state')+
                    index*13000+offset('device_state','spmi'),1132))
                head,count,tx_words,tx_need=raw[279:283]
                assert head<256 and count<=256 and tx_words<=tx_need<=5
                recovery=struct.unpack('<3I',read(work+offset('context','model_state')+
                    index*13000+offset('device_state','spmi_recovery',nested=True),12))
                spmi.append(dict(index=index,base=hex(model[1]),
                    command=hex(raw[274]),payload=list(raw[275:279]),
                    rx_head=head,rx_count=count,tx_words=tx_words,tx_need=tx_need,
                    reply=[raw[(head+i)%256] for i in range(count)],
                    enable=list(raw[256:265]),flags=list(raw[265:274]),
                    recovery=dict(zip(('config_reads','config_writes','fifo_clears'),recovery))))
                if model[0]==48:
                    assert model[:6]==(48,0x308700000,0x18000,0x14000,0x4000,487)
                    assert model[7]==0xf715f704f802000e
                    seed=json.loads((ROOT/'build'/f'{args.prefix}-rtc-seed.json').read_text())
                    assert model[6]==seed['epoch_us'] and seed['after_upload'] is True
                    assert hashlib.sha256(struct.pack(f'<{len(words)}Q',*words)).hexdigest()==seed['parameter_sha256']
                    address=work+offset('context','model_state')+index*13000+offset('device_state','pmu_rtc',nested=True)
                    rtc_raw=read(address,112)
                    header=struct.unpack_from('<4I',rtc_raw)
                    names=('epoch_us','start','frequency','last_now','last_ticks',
                           'counter_reads','offset_reads','offset_writes','rejected','last_command','last_length')
                    rtc=dict(zip(names,struct.unpack_from('<11Q',rtc_raw,16)))
                    assert header[:3]==recovery and header[3]==1
                    assert rtc['epoch_us']==seed['epoch_us'] and rtc['frequency']==param('clock_guest_hz')
                    assert rtc['last_now']>=rtc['start'] and rtc['last_length']<=8
                    if rtc['counter_reads']:
                        us=rtc['epoch_us'];delta=rtc['last_now']-rtc['start'];hz=rtc['frequency']
                        expected_ticks=(us//1000000)*32768+(us%1000000)*32768//1000000
                        expected_ticks+=(delta//hz)*32768+(delta%hz)*32768//hz
                        assert rtc['last_ticks']==expected_ticks<1<<47
                    else:assert rtc['last_ticks']==0
                    rtc['offset_hex']=rtc_raw[104:110].hex()
                    rtc['seed_sha256']=hashlib.sha256((ROOT/'build'/f'{args.prefix}-rtc-seed.json').read_bytes()).hexdigest()
                    rtc['boundary']='Virtual UTC counter plus volatile guest-written offset; no PMU power or alarm service'
                    spmi[-1]['rtc']=rtc
            if model[0]==25:
                assert model==(25,0x3003c0000,0x14000,0x10000,0x1a8,0x1b8,8,0xffb80)
                raw=struct.unpack('<2Q5I',read(work+offset('context','model_state')+index*13000,36))
                assert raw[4]==1 and all(v<=1 for v in raw[2:6])
                pmp.append(dict(index=index,request=raw[0],ack=raw[1],
                    request_updated=raw[2],ack_updated=raw[3],ready=raw[4],
                    ready_updated=raw[5],status_reads=raw[6]))
            if model[0]==43:
                assert model==(43,0x385018000,0x4000,2,6,1110,0,0)
                raw=struct.unpack('<32I',read(work+offset('context','model_state')+index*13000,128))
                assert raw[22]<=16 and raw[23]<=1 and not raw[24]&~0x08200000 and raw[25]==1 and raw[31]<=1
                i2c.append(dict(index=index,control=raw[0],mask=raw[1],address=raw[2],
                    timing=list(raw[3:6]),tx_words=list(raw[6:22]),tx_count=raw[22],
                    blocked=raw[23],status=raw[24],ready=raw[25],resets=raw[26],
                    nacks=raw[27],last_address=raw[28],shadow_command=raw[29],shadow_writes=raw[30],halt=raw[31]))
            if model[0]==42:
                assert model==(42,0x300200000,0x4000,0,0,0,0,0)
                raw=struct.unpack('<7I',read(work+offset('context','model_state')+index*13000,28))
                expected=(1,192000,120,0,0x41)
                assert raw[6]==1 and not raw[5]&~31
                assert all(v==(expected[i] if raw[5]&(1<<i) else 0) for i,v in enumerate(raw[:5]))
                dwi.append(dict(index=index,ready=raw[6],written_mask=raw[5],values=list(raw[:5])))
            if model[0]==41:
                assert model==(41,0x385110000,0x5000,0,0,0,0,0)
                raw=struct.unpack('<36I',read(work+offset('context','model_state')+index*13000,144))
                # This revision has no admitted transfer producer. All real
                # queues remain empty; a reset is counted only on a served
                # guest reset write, not merely on device initialization.
                assert not any(raw[:34]) and raw[34]==1
                qspi.append(dict(index=index,ready=raw[34],resets=raw[35],
                                 tx_words=raw[32],rx_words=raw[33]))
            if model[0]!=17:continue
            state=read(work+offset('context','model_state')+index*13000,2184)
            initialized,powered=struct.unpack_from('<2I',state)
            assert not initialized&~model[7] and not powered&~initialized
            enabled=struct.unpack_from('<8I',state,offset('dart_state','enabled'))
            tcr=struct.unpack_from('<256I',state,offset('dart_state','tcr'))
            ttbr=struct.unpack_from('<256I',state,offset('dart_state','ttbr'))
            dart_runtime.append(dict(index=index,base=hex(model[1]),
                policy=model[4],streams=model[3],enabled=[hex(v) for v in enabled],
                tcr={str(i):hex(v) for i,v in enumerate(tcr) if v},
                ttbr={str(i):hex(v) for i,v in enumerate(ttbr) if v},
                initialized_ids=hex(initialized),powered_ids=hex(powered),
                runtime_zero=not any(state[8:]),state_sha256=hashlib.sha256(state).hexdigest()))
            if not (initialized or powered):continue
            if model[4] not in (300,556,1068):continue # SIO, normal SEP and Adreno
            assert initialized==powered and initialized.bit_count()==1
            if model[4]==1068:
                assert model[1]==0x710000000 and model[3]==16 and initialized==1<<31
            ttbr=struct.unpack_from('<256I',state,1064)
            roots.extend((initialized.bit_length()-1,sid,t,tcr[sid])
                         for sid,t in enumerate(ttbr) if t)
        dart=darts['audit'](read,roots=roots,**{k:geometry[k] for k in
            ('frame_map','frame_low','frame_high','alloc_low','alloc_high','boot_ranges','boot_aliases',
             'sep_firmware','sep_released')})
        for asc in sep_asc:
            asc['rom_buffer_audit']=audit_rom_buffers(asc,dart['leaves'],geometry)
            asc['service_resource_audit']=audit_bootstrap(asc,dart['leaves'],read)
            asc['pnon_buffer_audit']=audit_pnon_buffers(asc,dart['leaves'],geometry,read)
            asc['xars_buffer_audit']=audit_xars_buffers(asc,dart['leaves'],geometry)
        user_state=work+offset('context','user_roots')
        active_roots=list(struct.unpack('<6Q',read(user_state,48)))
        cached=[];trees={}
        for index in range(64):
            values=struct.unpack('<7Q',read(user_state+48+index*56,56))
            entry=dict(zip(('root','shadow','leaves','asid','format','flags','valid'),values))
            entry['index']=index
            assert entry['valid'] in (0,1)
            if entry['root']:cached.append(entry)
            # Every slot that still has a tree (valid or not) may link groups.
            if entry['shadow']:trees[index]=entry['shadow']
        root_counts=struct.unpack('<5Q',read(user_state+3632,40))
        assert root_counts[0]==root_counts[1]+root_counts[2]
        assert not q(work+offset('context','root_install_failures'))
        root_auditor=runpy.run_path(str(ROOT/'tools/audit-user-roots.py'))
        sprr_fields=('uperm','pperm','umprr','pmprr','resets','reads','writes','rejected','last_reg','last_value')
        sprr_states=[dict(zip(sprr_fields,struct.unpack('<10Q',read(user_state+3672+80*cpu,80))))
                     for cpu in range(6)]
        assert sum(s['resets'] for s in sprr_states)==root_counts[0]+6
        loaded_roots=[dict(zip(('root','flags','resets'),values)) for values in
                      struct.iter_unpack('<3Q',read(work+offset('context','root_loaded'),144))]
        private_audit=runpy.run_path(str(ROOT/'tools/audit-user-permissions.py'))
        view_states=[dict(zip(private_audit['STATE_FIELDS'],values)) for values in
            struct.iter_unpack('<9Q',read(work+offset('context','user_view_state'),432))]
        assert not q(work+offset('context','user_view_failed'))
        # Native page tables (SNAP_NATIVE_TABLES). The context area exists in
        # every build: a monitor that runs user roots on shared permission
        # variants counts each install, any other leaves the area all zero.
        native_fields=runpy.run_path(str(ROOT/'tools/kernel_ops_perf.py'))['RECORDS']['native_stats'][1]
        native_raw=read(work+offset('context','native_stats'),8*len(native_fields))
        native_stats=dict(zip(native_fields,struct.unpack(f'<{len(native_fields)}Q',native_raw)))
        cpu_bytes=private_audit['NATIVE_CPU_BYTES']
        native_cpu_raw=read(work+offset('context','native_cpu'),6*cpu_bytes)
        native_cpus=[private_audit['native_cpu'](native_cpu_raw[n*cpu_bytes:(n+1)*cpu_bytes]) for n in range(6)]
        sources_start=offset('context','native_sources')
        native_sources_raw=read(work+sources_start,offset('context','native_stats')-sources_start)
        native_tables=native_stats['installs']>0
        if not native_tables:
            assert not any(native_raw+native_cpu_raw+native_sources_raw),'native table state without native installs'
        else:
            # Every page whose stores reach variant copies is a retained source
            # of some slot's views, and every such source is marked.
            arena_base=q(work+offset('context','work_base'))
            marked={arena_base+4096*(8*i+b) for i,byte in enumerate(native_sources_raw)
                    for b in range(8) if byte>>b&1}
            sources=set()
            for view in range(64):
                base=work+offset('context','user_views')+8256*view
                count=struct.unpack('<Q',read(base+8,8))[0]
                assert count<=128,'invalid retained view count'
                if count:sources.update(r[0] for r in struct.iter_unpack('<8Q',read(base+64,64*count)))
            assert marked==sources,'native source bitmap differs from retained variant sources'
            assert not native_stats['refused'] and not native_stats['audit_failures'] and not native_stats['reuse_failures']
        # Shared-region groups (SNAP_NATIVE_SHARED; the area exists in every
        # build and is all zero without it): exact translations of their guest
        # tables, the whole allocation domain, links as recorded.
        shared_block=next(b for b in layout.split('*** Dumping AST Record Layout')
                          if re.search(r'^\s*0 \| struct native_shared\n',b))
        shared_raw=read(work+offset('context','native_shared'),
                        int(re.search(r'\[sizeof=(\d+),',shared_block)[1]))
        native_shared=dict(enabled=False,pages=[])
        if any(shared_raw):
            assert native_tables,'shared groups without native page tables'
            shared_audit=runpy.run_path(str(ROOT/'tools/native_shared_audit.py'))
            pool=work+offset('context','table_pool')
            capacity=offset('table_pool','next')-offset('table_pool','owner')
            arena_base=q(work+offset('context','work_base'))
            used=(q(work+offset('context','next_table'))-arena_base)//4096
            owners=read(pool+offset('table_pool','owner'),capacity)[:used]
            summary=shared_audit['audit'](read,shared_raw,owners,arena_base,trees,
                group_offset=offset('native_shared','group'),index_offset=offset('native_shared','index'))
            native_shared=dict(enabled=True,header=summary['header'],groups=summary['groups'],
                               leaves=summary['leaves'],links=summary['links'],
                               pages=sorted(hex(p) for p in summary['pages']))
        user_permissions=[];user_storage=set()
        for entry in cached:
            if not entry['valid']:continue
            views=dict(state=read(work+offset('context','user_views')+8256*entry['index'],8256),
                entry=entry,active=active_roots,sprr=sprr_states,modes=view_states,loaded=loaded_roots,
                frame_map=fm,frame_low=geometry['frame_low'],work_low=work,
                work_high=q(work+offset('context','next_table')),
                diagnose_mismatches=args.diagnose_user_mapping_mismatches)
            audit=(private_audit['audit_native'](read,native=native_cpus,**views) if native_tables else
                   private_audit['audit'](read,**views))
            storage=set(audit.pop('private_storage'))
            assert not storage&user_storage;user_storage|=storage
            user_permissions.append(audit)
        root_switch=root_auditor['audit'](read,cache=cached,active=active_roots,
            ram_low=geometry['ram_low'],ram_high=geometry['ram_high'],work_low=work,work_high=table_end,
            sprr=sprr_states,translated_tpro=True,loaded=loaded_roots,
            diagnose_mismatches=args.diagnose_user_mapping_mismatches,
            shared_pages=frozenset(int(p,16) for p in native_shared['pages']))
        user_mapping_qualified=(all(a['private_descriptors_verified'] for a in user_permissions)
                                and root_switch['mappings_equal']
                                and root_switch['cached_leaf_counts_equal'])
        update_auditor=runpy.run_path(str(ROOT/'tools/audit-user-update.py'))
        update_states=[dict(zip(update_auditor['FIELDS'],values)) for values in
            struct.iter_unpack('<16Q',read(work+offset('context','user_updates'),768))]
        user_updates=update_auditor['audit'](read,states=update_states,cache=cached,
            ram_low=geometry['ram_low'],ram_high=geometry['ram_high'])
        region_states=[dict(zip(update_auditor['FIELDS'],values)) for values in
            struct.iter_unpack('<16Q',read(work+offset('context','user_regions'),768))]
        user_regions=update_auditor['audit'](read,states=region_states,cache=cached,
            ram_low=geometry['ram_low'],ram_high=geometry['ram_high'],region=True)
        shared_region_auditor=runpy.run_path(str(ROOT/'tools/audit-shared-region.py'))
        shared_region_states=[dict(zip(shared_region_auditor['FIELDS'],values)) for values in
            struct.iter_unpack('<16Q',read(work+offset('context','shared_regions_updates'),1536))]
        shared_regions_updates=shared_region_auditor['audit'](read,
            states=[shared_region_states[i:i+2] for i in range(0,12,2)],
            ram_low=geometry['ram_low'],ram_high=geometry['ram_high'],
            frame_map=geometry['frame_map'],frame_low=geometry['frame_low'])
        disjoint_auditor=runpy.run_path(str(ROOT/'tools/audit-unmap-disjoint.py'))
        disjoint_states=[dict(zip(disjoint_auditor['FIELDS'],values)) for values in
            struct.iter_unpack('<16Q',read(work+offset('context','user_disjoint_unmaps'),1536))]
        user_disjoint_unmaps=disjoint_auditor['audit'](read,
            states=[disjoint_states[i:i+2] for i in range(0,12,2)],
            ram_low=geometry['ram_low'],ram_high=geometry['ram_high'],
            frame_map=geometry['frame_map'],frame_low=geometry['frame_low'])
        kernel_disjoint_unmaps=None
        if re.search(r' kernel_disjoint_unmaps$',layout,re.M):
            kernel_disjoint_states=[dict(zip(disjoint_auditor['FIELDS'],values)) for values in
                struct.iter_unpack('<16Q',read(work+offset('context','kernel_disjoint_unmaps'),1536))]
            kernel_disjoint_unmaps=disjoint_auditor['audit'](read,
                states=[kernel_disjoint_states[i:i+2] for i in range(0,12,2)],
                ram_low=geometry['ram_low'],ram_high=geometry['ram_high'],
                frame_map=geometry['frame_map'],frame_low=geometry['frame_low'],
                kernel_root=geometry['root'])
        replacement_auditor=runpy.run_path(str(ROOT/'tools/audit-user-map-replace.py'))
        replacement_states=[dict(zip(replacement_auditor['FIELDS'],values)) for values in
            struct.iter_unpack('<16Q',read(work+offset('context','user_map_replacements'),768))]
        user_map_replacements=replacement_auditor['audit'](read,states=replacement_states,
            ram_low=geometry['ram_low'],ram_high=geometry['ram_high'],
            frame_map=geometry['frame_map'],frame_low=geometry['frame_low'])
        shared_page_auditor=runpy.run_path(str(ROOT/'tools/audit-shared-page.py'))
        shared_page_state=dict(zip(shared_page_auditor['FIELDS'],
            struct.unpack('<16Q',read(work+offset('context','shared_map_calls'),128))))
        root_switch.update(zip(('switches','user_switches','kernel_switches','builds','invalidations'),root_counts))
        # Monitors built before cache eviction have no counter; report None.
        if re.search(r' root_evictions$',layout,re.M):
            root_switch['evictions']=q(work+offset('context','root_evictions'))
            assert root_switch['evictions']<=root_switch['invalidations'],'evictions are invalidations'
        else:root_switch['evictions']=None
        # EL0 crash evidence: the fatal-exception delivery counters and, with
        # SNAP_USER_CRASH_RING, the last crash-class events per vCPU. Fields
        # an older monitor lacks decode as None.
        el0_crashes=runpy.run_path(str(ROOT/'tools/user_crash_ring.py'))['read_context'](
            read,work,offset,layout)
        # PV self-checks (struct sptm_pv_audit); None for older monitors.
        pv_audit=runpy.run_path(str(ROOT/'tools/pv_counters.py'))['read_context'](
            read,work,offset,layout)
        # Linked-AuxKC MAP_PAGE/UPDATE/RETYPE observation; None when unused.
        auxkc_exec=runpy.run_path(str(ROOT/'tools/auxkc_counters.py'))['read_context'](
            read,work,offset,layout,lambda name:aux_range())
        assert (auxkc_exec is None)==(linked_auxkc is None),'AuxKC counters disagree with the profile'
        if linked_auxkc is not None:linked_auxkc['monitor_counters']=auxkc_exec
        root_installed=struct.unpack('<12Q',read(work+offset('context','root_installed'),96))
        import ansstate
        ownership=refs['audit'](read,dma_references=ansstate.merge_references(
                                    dart['data_references'],ans_references),
            active_user_roots=[root for root in active_roots if root],**geometry)
        nest_audit=runpy.run_path(str(ROOT/'tools/audit-nest-region.py'))
        unnest_audit=runpy.run_path(str(ROOT/'tools/audit-unnest-region.py'))
        detach_audit=runpy.run_path(str(ROOT/'tools/audit-shared-detach.py'))
        shared_detaches=detach_audit['audit_shared_detaches'](read,
            read(work+offset('context','shared_detaches'),8+4096*64),
            frame_map=geometry['frame_map'],frame_low=geometry['frame_low'])
        unnesting=unnest_audit['audit_unnesting'](read,read(work+offset('context','unnest_calls'),368),
            frame_map=geometry['frame_map'],frame_low=geometry['frame_low'],
            detachments=shared_detaches['records'])
        nesting=nest_audit['audit_nesting'](read,read(work+offset('context','nest_state'),64),
            frame_map=geometry['frame_map'],frame_low=geometry['frame_low'],ownership=ownership,
            removed=unnesting['descriptors'],detachments=shared_detaches['records'])
        service=struct.unpack('<8Q',read(work+offset('context','services'),64))
        service_budget_stops=list(struct.unpack('<6Q',read(work+offset('context','service_budget_stops'),48)))
        assert all(v in (0,1) for v in service_budget_stops) and sum(service_budget_stops)<=1
        if any(service_budget_stops):
            assert service[1]==0x100000001+service_budget_stops.index(1)
        assert service[0]==0 and service[2]==0x8000000000000003 and not any(service[3:])
        assert service[1]>>32 in (1,2) and 1<=service[1]&0xffffffff<=6
        # Early stop (compat/early-stop.h): why the run ended before its budget,
        # when it did. A stop it caused is the normal stop of the CPU that fired.
        early_stop=dict(present=False)
        if re.search(r'^\s*\d+ \|   struct early_stop_state early_stop$',layout,re.M):
            names=runpy.run_path(str(ROOT/'tools/early_stop.py'))
            early_stop=dict(present=True,**names['decode'](
                read(work+offset('context','early_stop'),names['SIZE'])))
            assert early_stop['state'] in (0,2,3) and early_stop['outcome'] in (0,1,2,3)
            if early_stop['outcome']==1:
                assert early_stop['state']==3 and service[1]==(1<<32)|early_stop['fire_cpu']
            early_stop['summary']=names['summary'](early_stop,info.get('timer_hz'))
        cpu_rows=[];banks=[];runtime_pages=set();canonical_roots=[]
        for slot in range(6):
            address=work+offset('context','vcpus')+slot*2368;raw=read(address,2368)
            def field(name):return struct.unpack_from('<Q',raw,offset('vcpu',name))[0]
            assert field('context')==work and field('slot')==slot
            canonical_roots.append(field('shadow_root'))
            assert field('vmpidr')==0x80000000|(slot if slot<4 else slot-4+0x100)
            fault=field('service_fault')
            if args.diagnose_primary_timeout and slot==0:
                assert fault==6 and service[1]==0x200000001
            else:assert fault==0
            installed_ttbr,installed_tcr=root_installed[slot*2:slot*2+2]
            if active_roots[slot]:
                cached_root=next(e for e in cached if e['root']==active_roots[slot] and e['valid'])
                assert field('guest_ttbr0')==active_roots[slot]|(cached_root['asid']<<48)
                if native_tables:
                    # Installed for the reset state at EL1 (PPERM governs), in
                    # this slot's own ASID; later flips are TTBR0 writes that
                    # audit_native checked against the CPU's SPRR state.
                    reset_w=(private_audit['PPERM']>>36)&1
                    assert installed_ttbr==native_cpus[slot]['ttbr0'][reset_w][0]
                else:
                    assert installed_ttbr==view_states[slot]['shadow']|(cached_root['asid']<<48)
            elif installed_ttbr:
                assert installed_ttbr==field('low_root') and field('guest_ttbr0')==geometry['root']
            if native_tables and not active_roots[slot]:
                assert not native_cpus[slot]['installed'] and not native_cpus[slot]['errors']
            if installed_ttbr:
                assert installed_tcr&0x3f==17 and not installed_tcr&(3<<14)
                assert (installed_tcr>>30)&3==2 and not installed_tcr&(1<<7)
            root=field('stage2_root');n=field('guard_count');assert 0<n<=12
            assert field('open_guards')==0
            guards=[struct.unpack_from('<4Q',raw,offset('vcpu','guards')+i*32) for i in range(n)]
            if native_mode:
                expected_guards=set(([] if writer_enabled else native_pages[5:])+[param('vbar')])
                expected_guards.update(param('watch_pa')+i*4096 for i in range(param('watch_count')))
                assert {g[0] for g in guards}==expected_guards
                assert all(g[0] not in native_pages[:5] for g in guards)
                state=struct.unpack('<12Q',read(work+offset('context','native_calls')+slot*96,96))
                ready,calls,restores,rejected=state[:4]
                assert ready==int(field('prepared')==1) and calls==restores and rejected==0
                hvc_calls,hvc_rejected,hvc_pc=struct.unpack('<3Q',
                    read(work+offset('context','sptm_hvc')+slot*24,24))
                assert hvc_rejected==0
                if hvc_mode:
                    assert calls==0
                    if hvc_calls:assert hvc_pc in native_contract['call_sites'] and ready
                else:
                    assert (hvc_calls,hvc_rejected,hvc_pc)==(0,0,0)
                if calls:
                    assert state[9] in native_api.CALL_WORDS and (state[10]&31) in (8,9)
                    assert state[11]==((state[10]&~12)|4)
                    assert native_contract['call_sites'].get(state[8])==state[9]
                native_report['cpus'].append(dict(slot=slot,ready=ready,calls=calls,
                    restores=restores,rejected=rejected,last_pc=hex(state[8]),
                    hvc_calls=hvc_calls,hvc_rejected=hvc_rejected,hvc_last_pc=hex(hvc_pc),
                    last_word=hex(state[9]),saved_spsr=hex(state[10]),physical_spsr=hex(state[11])))
            banks.append(dict(root=root,vttbr=root|((slot+1)<<48),guards=guards))
            vncr=field('vncr_va');lo=vncr;hi=vncr+4096 if not slot else field('el2_sp')
            assert not (lo|hi)&4095 and work<=lo<hi<=table_end
            pages=set(range(lo,hi,4096));assert not runtime_pages&pages;runtime_pages|=pages
            seed=bytearray(4096);struct.pack_into('<Q',seed,0x78,xb.GUEST_PROFILE.kernel_hcr)
            page=read(vncr,4096);assert struct.unpack_from('<Q',page,0x78)[0]==xb.GUEST_PROFILE.kernel_hcr
            active=field('prepared')==1
            writer_row=writer_api['audit'](
                read(work+offset('context','writer_debug')+slot*writer_api['SIZE'],writer_api['SIZE']),
                enabled=bool(writer_enabled),prepared=active)
            writer_report['cpus'].append(dict(writer_row,slot=slot))
            row=dict(slot=slot,prepared=active,service_acquires=field('service_acquires'),
                vncr=hex(vncr),vncr_seed_unchanged=page==seed,closed_guards=n)
            ipi=struct.unpack_from('<6Q',raw,offset('vcpu','ipi'))
            assert ipi[0]<=1 and ipi[1]==ipi[0]+ipi[3]+ipi[4]
            if not active:assert not any(ipi)
            row['ipi']=dict(zip(('pending','received','reads','acks','coalesced','last_request'),ipi))
            row['ipi'].update(request_pc=hex(field('ipi_request_pc')),ack_pc=hex(field('ipi_ack_pc')))
            row['timer_irqs']=field('timer_irqs')
            if slot:
                out=field('out_ptr');stack=field('el2_sp')-65536
                assert out==vncr+4096 and stack==out+4096
                stack_bytes=read(stack,65536);output=read(out,4096)
                row.update(stack_sha256=hashlib.sha256(stack_bytes).hexdigest(),
                    output_sha256=hashlib.sha256(output).hexdigest())
                if not active:
                    assert not any(stack_bytes) and not any(output) and page==seed
                    assert field('service_acquires')==0
                else:assert field('service_acquires')>0
            cpu_rows.append(row)
        kernel_audit=runpy.run_path(str(ROOT/'tools/audit-kernel-permissions.py'))
        kernel_permissions=kernel_audit['audit'](read,
            state=read(work+offset('context','kernel_views'),8256),
            installed=struct.unpack('<6Q',read(work+offset('context','kernel_installed'),48)),
            prepared=[row['prepared'] for row in cpu_rows],canonical=canonical_roots,
            pperm=[s['pperm'] for s in sprr_states],
            work_low=work,work_high=q(work+offset('context','next_table')))
        assert not q(work+offset('context','kernel_view_failed'))
        kernel_update_states=[dict(zip(update_auditor['FIELDS'],values)) for values in
            struct.iter_unpack('<16Q',read(work+offset('context','kernel_updates'),768))]
        kernel_updates=update_auditor['audit_kernel'](read,states=kernel_update_states,
            root=geometry['root'],canonical=int(kernel_permissions['canonical_root'],16),
            ram_low=geometry['ram_low'],ram_high=geometry['ram_high'])
        kernel_permissions.update(kernel_audit['audit_aperture'](read,
            protected=kernel_permissions.pop('protected'),root=geometry['root'],
            readonly=kernel_permissions.pop('readonly'),
            txm_apertures=kernel_permissions.pop('txm_apertures'),
            frame_map=fm,frame_low=geometry['frame_low'],aperture_low=geometry['ram_low'],
            aperture_va=geometry['aperture_va'],aperture_size=geometry['aperture_size'],
            moved=geometry['moved']))
        for name in ('papt_protects','papt_releases','kernel_permission_changes',
                     'user_exec_protects','user_exec_releases','user_exec_cache_syncs'):
            kernel_permissions[name]=q(work+offset('context',name))
        assert kernel_permissions['user_exec_protects']==kernel_permissions['user_exec_cache_syncs']
        if re.search(r' txm_donations$',layout,re.M):
            kernel_permissions['txm_donations']=q(work+offset('context','txm_donations'))
            imports=releases=0
            if re.search(r' txm_imports$',layout,re.M):
                imports=q(work+offset('context','txm_imports'));releases=q(work+offset('context','txm_releases'))
                assert imports==releases
            kernel_permissions.update(txm_imports=imports,txm_releases=releases)
            assert kernel_permissions['txm_donations']-imports==kernel_permissions['txm_default_frames']
            if txm_native_report['enabled']:assert imports==2*txm_native_report['load']['calls']
        assert kernel_permissions['user_exec_protects']-kernel_permissions['user_exec_releases']==kernel_permissions['user_exec_frames']
        user_execution_audit=runpy.run_path(str(ROOT/'tools/audit-user-execution.py'))
        user_execution=user_execution_audit['audit'](
            read(work+offset('context','user_execution'),6*23*8))
        pan_entry_audit=runpy.run_path(str(ROOT/'tools/audit-pan-entry.py'))
        pan_entry=pan_entry_audit['audit'](read(work+offset('context','pan_entry'),6*8*8))
        user_clock_audit=runpy.run_path(str(ROOT/'tools/audit-user-clock.py'))
        user_clock=user_clock_audit['audit'](read(work+offset('context','user_clock'),6*11*8))
        conflict_audit=runpy.run_path(str(ROOT/'tools/audit-user-map-conflict.py'))
        user_map_conflict=conflict_audit['audit'](read(work+offset('context','user_map_conflict'),384))
        user_sprr_audit=runpy.run_path(str(ROOT/'tools/audit-user-sprr.py'))
        user_sprr=user_sprr_audit['audit'](read(work+offset('context','user_sprr'),384))
        uperm_audit=runpy.run_path(str(ROOT/'tools/audit-uperm-write.py'))
        uperm_write=uperm_audit['audit'](read(work+offset('context','sprr_uperm_update'),672),
                                      translated_tpro=True)
        pperm_audit=runpy.run_path(str(ROOT/'tools/audit-pperm-copy.py'))
        pperm_copy=pperm_audit['audit'](read(work+offset('context','sprr_pperm_update'),720),
                                       [s['pperm'] for s in sprr_states],translated_tpro=True)
        tpro_protects=q(work+offset('context','user_tpro_protects'))
        tpro_releases=q(work+offset('context','user_tpro_releases'))
        tpro_live=sum(fm[off+2]==17 for off in range(0,len(fm),16))
        assert tpro_protects-tpro_releases==tpro_live
        const_begin,const_end=param('const_begin'),param('const_end')
        image=xb.kc_load.Image(Path(xb.DEFAULT_KERNELCACHE).read_bytes())
        expected=xb.const_region_contract(image,const_begin)
        assert expected==(const_begin,const_end)
        assert const_begin==struct.unpack_from('<Q',bootargs,16)[0]
        assert param('mem_low')<=const_begin<const_end<=param('alloc_low')
        sealed=q(work+offset('context','const_sealed_cpus'))
        lockdowns=q(work+offset('context','lockdowns'))
        invalidations=q(work+offset('context','const_tlb_invalidations'))
        reads=struct.unpack('<2Q',read(work+offset('context','const_reads'),16))
        assert sealed in (0,63) and bool(sealed)==bool(lockdowns)
        assert invalidations==lockdowns*6
        table_start=q(work+offset('context','work_base'))
        context_block=next(b for b in layout.split('*** Dumping AST Record Layout')
                           if re.search(r'^\s*0 \| struct context\n',b))
        context_size=int(re.search(r'\[sizeof=(\d+),',context_block)[1])
        assert table_start==((work+context_size+4095)&~4095)
        assert work<table_start<table_end
        ranges=[(param('mem_low'),param('mem_high'),0x7fc,0),(table_start,table_end,0x77c,1<<54)]
        if sealed:
            ranges=[(lo,hi,attrs,0) for lo,hi,attrs in (
                (param('mem_low'),const_begin,0x7fc),(const_begin,const_end,0x77c),
                (const_end,param('mem_high'),0x7fc)) if lo<hi]+[(table_start,table_end,0x77c,1<<54)]
        # Independently verify the explicit virtual TXM capability. The
        # negative endpoint7 reply must not conceal any published backing.
        txm_ro=read(param('txm_ro_pa'),0x4000)
        channel_descriptor=struct.unpack_from('<3Q',txm_ro,0x38)
        assert txm_ro[0xa]==0 and channel_descriptor==(0,0,0)
        assert tree.get('/device-tree/arm-io/dart-sep','txm-secure-channel-base') is None
        txm_sep_channel=dict(platform_class=txm_ro[0xa],available=False,
            descriptor=list(channel_descriptor),device_tree_iova=None,
            expected_txm_status=0x29)
        trust_word=offset('params','trust_cache')//8
        trust_cache=words[trust_word:trust_word+3]
        trust_audit=runpy.run_path(str(ROOT/'tools/audit-static-trust.py'))
        static_trust=trust_audit['audit_static_trust'](read,trust_cache,
            read(work+offset('context','trust_state'),616),trust_spec,txm_dynamic_expected)
        if trust_cache[0]:
            tc_lo=trust_cache[0]
            tc_hi=tc_lo+0x4000+((trust_cache[2]+0x3fff)&~0x3fff)
            window=param('txm_aspace_pa')+TXM_ARENA_BYTES+3*0x4000<=tc_lo<tc_hi<=param('scratch_pa')-0x4000
            payload=(installed is not None and
                     param('scratch_pa')+6*0x8000<=tc_lo<tc_hi<=param('alloc_low'))
            assert window or payload, 'trust cache outside loader reservations'
            assert not (tc_lo&0x3fff)
            assert param('mem_low')<=tc_lo<tc_hi<=param('mem_high')
            if payload:
                assert tc_hi<=tree_pa or tree_pa+tree_len<=tc_lo
                if linked_auxkc:
                    assert tc_hi<=aux_pa or aux_pa_end<=tc_lo
                sep_lo=param('sep_firmware_pa');sep_hi=sep_lo+param('sep_firmware_size')
                assert sep_lo==sep_hi or tc_hi<=sep_lo or sep_hi<=tc_lo
            static_trust['placement']='payload' if payload else 'window'
            split=[];covered=False
            for lo,hi,attrs,upper in ranges:
                if lo<=tc_lo<tc_hi<=hi:
                    assert not covered and attrs==0x7fc and not upper
                    covered=True
                    split += [(a,b,attr,upper) for a,b,attr in
                        ((lo,tc_lo,attrs),(tc_lo,tc_hi,0x77c),(tc_hi,hi,attrs)) if a<b]
                else:split.append((lo,hi,attrs,upper))
            assert covered
            ranges=split
        panic_lo=param('scratch_pa')-0x4000;panic_hi=param('scratch_pa')
        assert param('txm_aspace_pa')+TXM_ARENA_BYTES+3*0x4000<=panic_lo<panic_hi<=param('mem_high')
        panic_va=param('ram_aperture_va')+panic_lo-param('mem_low')
        panic_audit=runpy.run_path(str(ROOT/'tools/audit-panic-state.py'))
        panic_state=panic_audit['audit'](read(panic_lo,0x4000),
            read(work+offset('context','panic_state'),88),q(param('watch_pa')+0x198),panic_va)
        panic_state['pa']=hex(panic_lo)
        def kernel_pa(va):
            table=geometry['root']
            for shift in (36,25,14):
                assert geometry['ram_low']<=table<=geometry['ram_high']-16384 and not table&16383
                desc=q(table+8*((va>>shift)&2047))
                assert desc&3==3
                table=desc&0x0000ffffffffc000
            pa=table+(va&16383)
            assert geometry['ram_low']<=pa<=geometry['ram_high']-8
            return pa
        assert kernel_pa(panic_va)==panic_lo
        if user_execution['returns']:
            # Exact 26A428 initialization copy and the EL0 handler's global.
            copied=q(kernel_pa(0xfffffe0007da0278+0x198))
            global_pointer=q(kernel_pa(0xfffffe0007da05d0))
            assert copied==global_pointer==panic_va
            panic_state.update(kernel_copy=hex(copied),kernel_global=hex(global_pointer))
        split=[];covered=False
        for lo,hi,attrs,upper in ranges:
            if lo<=panic_lo<panic_hi<=hi:
                assert not covered and attrs==0x7fc and not upper
                covered=True
                split += [(a,b,attr,xn) for a,b,attr,xn in
                    ((lo,panic_lo,attrs,upper),(panic_lo,panic_hi,0x77c,1<<54),
                     (panic_hi,hi,attrs,upper)) if a<b]
            else:split.append((lo,hi,attrs,upper))
        assert covered
        ranges=split
        const_region=dict(begin=hex(const_begin),end_exclusive=hex(const_end),
                          sealed_cpu_mask=hex(sealed),lockdowns=lockdowns,
                          tlb_invalidations=invalidations,register_reads=list(reads))
        user_mapping=dict(live_tables=q(work+offset('context','user_live_tables')),
                          live_pages=q(work+offset('context','user_live_pages')),
                          missing_tables=q(work+offset('context','user_missing_tables')),
                          unmap_calls=q(work+offset('context','user_unmap_calls')),
                          unmap_pages=q(work+offset('context','user_unmap_pages')),
                          condemn_calls=q(work+offset('context','user_condemn_calls')),
                          uncondemn_calls=q(work+offset('context','user_uncondemn_calls')),
                          detach_calls=q(work+offset('context','user_detach_calls')),
                          comm_attach_calls=q(work+offset('context','user_comm_attach_calls')),
                          comm_attach_leaves=q(work+offset('context','user_comm_attach_leaves')))
        if param('fb_span'):ranges.append((param('fb_pa'),param('fb_pa')+param('fb_span'),0x7fc,1<<54))
        # Stage 4: an Adreno profile's device passthrough (vcpu_stage2_prepare, probes/adreno.py).
        if re.search(r'^\s*\d+ \|   struct adreno_params gpu$',layout,re.M):
            import adreno
            ranges+=adreno.stage2_audit_ranges(param('gpu'))
        # --input: the keyboard's GENI page (vcpu_stage2_prepare, compat/i2c-input.h), from the block a
        # -DSNAP_I2C_INPUT=1 monitor reads right after struct params; words that are not a valid block
        # (any other monitor) add nothing, as that monitor maps nothing.
        import i2cinput
        i2c_rows=i2cinput.stage2_audit_ranges(list(struct.unpack(f'<{i2cinput.PARAMS_WORDS}Q',
            read(param_pa+xb.PARAMS_WORDS*8,i2cinput.PARAMS_WORDS*8))))
        ranges+=i2c_rows
        # --qcc2072-wifi: the five QCC2072 windows (vcpu_stage2_prepare, compat/qcc2072-wifi.h), from the
        # block a -DSNAP_QCC2072_WIFI=1 monitor reads right after struct params and any input block;
        # words that are not a valid block (any other monitor) add nothing, as that monitor maps nothing.
        import qcc2072wifi
        qcc_at=param_pa+(xb.PARAMS_WORDS+(i2cinput.PARAMS_WORDS if i2c_rows else 0))*8
        qcc_rows=qcc2072wifi.stage2_audit_ranges(list(struct.unpack(f'<{qcc2072wifi.PARAMS_WORDS}Q',
            read(qcc_at,qcc2072wifi.PARAMS_WORDS*8))))
        ranges+=qcc_rows
        # --present-beam: the DPU INTF_5 page, read-only (vcpu_stage2_prepare, compat/display-timing.h), from the
        # block a -DSNAP_DISPLAY_TIMING=1 monitor reads after struct params and any QCC2072 block; words that are not
        # a valid block (any other monitor) add nothing, as that monitor maps nothing.
        import displaytiming
        dt_at=qcc_at+(qcc2072wifi.PARAMS_WORDS*8 if qcc_rows else 0)
        ranges+=displaytiming.stage2_audit_ranges(list(struct.unpack(f'<{displaytiming.PARAMS_WORDS}Q',
            read(dt_at,displaytiming.PARAMS_WORDS*8))))
        stage2=audit_private_stage2(read,banks,ranges,table_start,table_end)
        stage2['private_context_unmapped']=True
        stage2['private_context_range']=[hex(work),hex(table_start)]
        assert not runtime_pages&{int(x,16) for x in stage2['table_addresses']}
        base=q(work+offset('context','secondary_base'));assert work<=base<table_end-6*4096
        physical=[];launched=0
        for slot in range(1,6):
            record=struct.unpack('<37Q',read(base+slot*4096,37*8))
            row=dict(zip(secondary['FIELDS'],record));row['slot']=slot
            if cpu_rows[slot]['prepared']:
                assert row['phase']==4 and row['cleanup']==1 and row['affinity_result']==1
                assert row['on_result']==row['prepare_result']==row['finish_result']==row['error']==0
                assert row['entered']==1 and row['active_vmpidr']==0x80000000|(slot if slot<4 else slot-4+0x100)
                assert row['active_vncr']==int(cpu_rows[slot]['vncr'],16)
                assert row['active_vttbr']==banks[slot]['vttbr']
                assert tuple(record[:4])==tuple(record[26:30])
                launched|=1<<slot
            else:assert row['phase']==row['entered']==0
            physical.append(row)
        armed,issued=struct.unpack('<2Q',read(work+offset('context','cpu_release'),16))
        assert issued==launched and armed&launched==launched
        assert launched or args.allow_unlaunched
        cpu_release=dict(armed=armed,issued=issued,launched=launched,
                         secondary_execution_verified=bool(launched))
        assert not proxy.exceptions
        nonce_base=work+offset('context','txm_nonces')
        nonce_entries=[]
        for index in range(12):
            # Header only: never export the two sixteen-byte material fields.
            domain,flags,initialized=struct.unpack('<QII',read(nonce_base+48*index,16))
            assert initialized in (0,1) and not flags&~0x7f
            if initialized:nonce_entries.append(dict(index=index,domain_id=hex(domain),flags=hex(flags)))
        nonce_sets,nonce_rejections=struct.unpack('<2Q',read(nonce_base+12*48,16))
        assert nonce_sets==len(nonce_entries)
        digest_base=work+offset('context','txm_nonce_digests')
        digest_entries=[]
        for index in range(17):
            # Read only the length: digest material remains inside the monitor.
            length=q(digest_base+index*56+48)
            assert length<=48
            if length:digest_entries.append(dict(domain_index=index,length=length))
        digest_sets=q(digest_base+952)
        assert digest_sets==len(digest_entries)
        # Reconstruct identities independently from the typed frame map and
        # guest-visible TXM objects. Never infer conversion success from its
        # counter alone: object handle, packed class/id and mapping pointer
        # must agree, with unique roots and class-specific identifiers.
        registry_base=work+offset('context','txm_registry')
        registry_count=struct.unpack('<I',read(registry_base+offset('txm_registry','count'),4))[0]
        L=TXM_ASPACE_LIMIT
        assert offset('txm_registry','asid')==8*L and offset('txm_registry','shared')-offset('txm_registry','count')>=4
        assert registry_count<=L
        registry_roots=struct.unpack(f'<{L}Q',read(registry_base,8*L))
        registry_ids=struct.unpack(f'<{L}H',read(registry_base+8*L,2*L))
        registry_shared=read(registry_base+offset('txm_registry','shared'),L)
        registry_starts=struct.unpack(f'<{L}Q',read(registry_base+offset('txm_registry','region_start'),8*L))
        registry_ends=struct.unpack(f'<{L}Q',read(registry_base+offset('txm_registry','region_end'),8*L))
        region_sets=q(registry_base+offset('txm_registry','region_sets'))
        registry_bound=struct.unpack(f'<{L}Q',read(registry_base+offset('txm_registry','bound_shared'),8*L))
        binding_sets=q(registry_base+offset('txm_registry','bindings'))
        binding_releases=q(registry_base+offset('txm_registry','unbindings'))
        arena_pa=words[offset('params','txm_aspace_pa')//8]
        arena_va=geometry['aperture_va']+arena_pa-geometry['ram_low']
        txm_objects=[];identities=set();object_roots=set()
        for i in range(registry_count):
            pa=registry_roots[i];identity=registry_ids[i];kind=registry_shared[i]
            region_start,region_end=registry_starts[i],registry_ends[i]
            assert kind in (0,1)
            if not pa:
                assert identity==kind==0
                assert region_start==region_end==registry_bound[i]==0
                continue
            if region_start or region_end:
                assert kind==1 and 0<region_start<region_end<=0xffffffffffffffff
                assert not (region_start|region_end)&0x3fff
            assert pa not in object_roots and (kind,identity) not in identities
            object_roots.add(pa);identities.add((kind,identity))
            assert pa in (shared if kind else users)
            f=fm[((pa-geometry['frame_low'])>>14)*16:((pa-geometry['frame_low'])>>14)*16+16]
            assert identity==(f[8] if kind else int.from_bytes(f[4:6],'little'))
            handle=arena_va+i*256
            obj=read(arena_pa+i*256,256)
            expected=bytearray(256);expected[0x11]=expected[0x91]=1
            struct.pack_into('<HH',expected,0x22,identity,kind)
            struct.pack_into('<Q',expected,0x38,handle+0x80)
            struct.pack_into('<2Q',expected,0x58,region_start,region_end)
            references=sum(bool(registry_roots[j]) and registry_bound[j]==pa for j in range(registry_count))
            assert not references or kind==1
            struct.pack_into('<I',expected,0x68,references)
            if kind:
                assert not registry_bound[i]
            else:
                assert (f[8]==255)==(registry_bound[i]==0)
            if registry_bound[i]:
                parent=registry_roots.index(registry_bound[i])
                assert parent<registry_count and registry_shared[parent]==1
                assert registry_ids[parent]==f[8]
                pf=fm[((registry_bound[i]-geometry['frame_low'])>>14)*16:((registry_bound[i]-geometry['frame_low'])>>14)*16+16]
                assert pf[12]==f[12] and int.from_bytes(pf[4:6],'little')>0
                assert registry_starts[parent]<registry_ends[parent] and registry_starts[parent]>0
                struct.pack_into('<Q',expected,0x28,handle+0x80)
                struct.pack_into('<Q',expected,0x38,0)
                struct.pack_into('<Q',expected,0x48,handle+0x80)
                expected[0x92]=1
                struct.pack_into('<Q',expected,0x98,arena_va+parent*256)
                struct.pack_into('<2Q',expected,0xa8,registry_starts[parent],registry_ends[parent])
            assert obj==expected, 'TXM object disagrees with its registered identity'
            txm_objects.append(dict(registry_slot=i,root=hex(pa),identity=identity,
                shared=bool(kind),handle=hex(handle),metadata=f.hex(),
                region_start=hex(region_start),region_end=hex(region_end),
                bound_shared=hex(registry_bound[i]),binding_references=references))
        assert region_sets>=sum(bool(registry_ends[i]) for i in range(registry_count))
        assert binding_sets-binding_releases==sum(bool(registry_bound[i]) for i in range(registry_count))
        shared_root_state=dict(converts=q(work+offset('context','shared_root_converts')),
            releases=q(work+offset('context','shared_root_releases')),region_sets=region_sets,
            bindings=binding_sets,unbindings=binding_releases,objects=txm_objects)
        root_config_audit=runpy.run_path(str(ROOT/'tools/audit-root-configuration.py'))
        root_configuration=root_config_audit['audit_root_configuration'](
            read(work+offset('context','root_configuration'),64),
            {pa:fm[((pa-geometry['frame_low'])>>14)*16:((pa-geometry['frame_low'])>>14)*16+16] for pa in users})
        shared_base=work+offset('context','shared_regions')
        shared_metadata={pa:fm[((pa-geometry['frame_low'])>>14)*16:
            ((pa-geometry['frame_low'])>>14)*16+16] for pa in shared}
        shared_audit=runpy.run_path(str(ROOT/'tools/audit-shared-regions.py'))
        sptm_shared_regions=shared_audit['audit_shared_regions'](
            read(shared_base,255*32),
            q(shared_base+offset('sptm_shared_registry','configurations')),shared_metadata)
        shared_pages=shared_page_auditor['audit'](read,state=shared_page_state,cache=cached,
            regions=sptm_shared_regions['entries'],ram_low=geometry['ram_low'],ram_high=geometry['ram_high'],
            work_low=work,work_high=q(work+offset('context','next_table')))
        shared_tables=[]
        for pa in managed.frames():
            i=((pa-geometry['frame_low'])>>14)*16;f=fm[i:i+16]
            if f[2]==21:
                shared_tables.append(dict(pa=hex(pa),level=f[4],
                    parent_links=int.from_bytes(f[6:8],'little'),
                    child_references=int.from_bytes(f[8:10],'little')))
        shared_table_state=dict(tables=len(shared_tables),
            levels={str(level):sum(t['level']==level for t in shared_tables) for level in range(4)},
            entries=shared_tables)
        release_auditor=runpy.run_path(str(ROOT/'tools/audit-txm-release-type.py'))
        txm_release_type=release_auditor['audit'](
            read(work+offset('context','txm_release_type'),184),
            stacks_pa=param('txm_stacks_pa'),stack_count=param('txm_stack_count'))
        key_auditor=runpy.run_path(str(ROOT/'tools/audit-txm-local-key.py'))
        txm_local_key=key_auditor['audit'](
            read(work+offset('context','txm_local_key'),128),
            stacks_pa=param('txm_stacks_pa'),stack_count=param('txm_stack_count'))
        result=dict(guest_profile=xb.PROFILE_NAME,
            native_calls=native_report,
            native_writers=writer_report,
            runtime_stop_qualified=not args.diagnose_primary_timeout,
            user_mapping_qualified=user_mapping_qualified,
            service_budget_stops=service_budget_stops,
            early_stop=early_stop,
            monitor_sha256=hashlib.sha256(blob).hexdigest(),geometry=geometry,
            txm_image4_uuid_rejections=struct.unpack('<Q',read(work+offset('context','txm_image4_uuid_rejections'),8))[0],
            txm_release_type=txm_release_type,
            txm_local_key=txm_local_key,
            txm_native=txm_native_report,
            txm_nonces=dict(sets=nonce_sets,rejections=nonce_rejections,entries=nonce_entries),
            txm_nonce_digests=dict(sets=digest_sets,entries=digest_entries),
            shared_root_state=shared_root_state,
            root_configuration=root_configuration,
            sptm_shared_regions=sptm_shared_regions,
            shared_table_state=shared_table_state,
            nesting=nesting,
            unnesting=unnesting,shared_detaches=shared_detaches,user_regions=user_regions,
            shared_regions_updates=shared_regions_updates,
            user_disjoint_unmaps=user_disjoint_unmaps,
            kernel_disjoint_unmaps=kernel_disjoint_unmaps,
            user_map_replacements=user_map_replacements,
            static_trust=static_trust,
            txm_sep_channel=txm_sep_channel,
            root_switch=root_switch,el0_crashes=el0_crashes,pv_audit=pv_audit,
            linked_auxkc=linked_auxkc,
            const_region=const_region,user_mapping=user_mapping,
            kernel_permissions=kernel_permissions,user_execution=user_execution,panic_state=panic_state,
            pan_entry=pan_entry,
            user_clock=user_clock,
            user_map_conflict=user_map_conflict,
            user_sprr=user_sprr,
            uperm_write=uperm_write,
            pperm_copy=pperm_copy,
            user_permissions=dict(roots=user_permissions,cpu_state=view_states,
                protects=tpro_protects,releases=tpro_releases,live_frames=tpro_live),
            native_tables=dict(enabled=native_tables,stats=native_stats,cpus=native_cpus,
                source_pages=sum(bin(b).count('1') for b in native_sources_raw)),
            native_shared=native_shared,
            user_updates=user_updates,
            kernel_updates=kernel_updates,
            shared_pages=shared_pages,
            ownership=ownership,dart=dart,service=list(service),cpu_rows=cpu_rows,
            stage2=stage2,physical_secondaries=physical,cpu_release=cpu_release,
            qspi=qspi,dwi=dwi,i2c=i2c,pmp=pmp,spmi=spmi,watchdog_smc=watchdog_smc,aes_idle=aes_idle,aes_software=aes_software,aes_key_disable=aes_key_disable,
            sep_aon=sep_aon,sep_asc=sep_asc,dart_runtime=dart_runtime,acc_sampler=acc_sampler,ans=ans,
            cpu_perf_reads=cpu_perf_reads,firmware=firmware)
    finally:proxy.link.close()
    output=ROOT/'build'/f'{args.prefix}-audit.json'
    output.write_text(json.dumps(result,indent=2)+'\n')
    summary={k:v for k,v in ownership.items() if k!='mismatches'}
    summary['mismatch_count']=len(ownership['mismatches'])
    summary['first_mismatches']=ownership['mismatches'][:8]
    print(json.dumps(dict(ownership=summary,dma_mismatches=dart['mismatches'][:8],
        user_mapping_qualified=user_mapping_qualified,
        private_table_pages=stage2['disjoint_table_pages'],pv_audit=pv_audit,
        linked_auxkc=linked_auxkc,
        active_cpu_slots=[r['slot'] for r in cpu_rows if r['prepared']],qspi=qspi,dwi=dwi,i2c=i2c,pmp=pmp,output=str(output))))
    return bool(ownership['mismatches'] or dart['mismatches'] or not user_mapping_qualified)

if __name__=='__main__':raise SystemExit(main())
