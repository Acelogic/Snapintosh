#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Prepare/boot the SKS candidate on generation53, preserving the installed image.

--check-inputs performs no hardware access. --prepare runs the established GPU
sequence after verified generation52 retirement. --boot uses a 2100-second guest
watchdog and retains launch/capture inputs. Never interrupt an in-flight P_CALL.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import runpy
import shutil
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
RUNTIME=ROOT.parent/'Snapintosh-adreno-sks'
Q=ROOT.parent/'q1n1'
PREVIOUS='installed-metal-virtual-ethernet-2100s-20260927'
PREFIX='installed-metal-sks-2100s-20260928'
QUAL=ROOT/'build/sks-gpu-candidate-20260928-v2/qualification.json'
QUAL_SHA='584a9d202198870a783dd0e48c298849fa2de2007a057c9f64c988ad660fffd3'
STEPS=[('guard',['guard']),('cx',['cx-on','--write']),('arena',['arena','--write']),
    ('smmu',['gmu-smmu','--write']),('gmu',['gmu-boot','--write']),('hfi',['hfi','--write']),
    ('oob',['oob','--write']),('c3',['cp-fence','--write','--stop-after','C3']),
    ('c3s',['cp-fence','--write','--stop-after','C3S']),
    ('c5',['cp-fence','--write','--stop-after','C5']),('fence',['cp-fence','--write'])]
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
read=lambda p:json.loads(Path(p).read_text())
path=lambda suffix:ROOT/'build'/(PREFIX+suffix)


def validate():
    assert sha(QUAL)==QUAL_SHA
    candidate=read(QUAL);assert candidate['status']=='GPU_BASELINE_SKS_CANDIDATE_BUILT'
    assert candidate['runtime_root']==str(RUNTIME)
    for name,digest in candidate['inputs_sha256'].items():assert sha(name)==digest,name
    old=read(ROOT/'build'/(PREVIOUS+'-launch.json'))
    saved=ROOT/'build/sks-gpu-candidate-20260928-v1/preserved-gen52-v1/preservation.json'
    assert sha(saved)=='2b6b00b420b608b431f8dc690a9a59b33e81cccc1cab68749d4fe73d1b573b39'
    assert sha(ROOT/'build'/(PREVIOUS+'-launch.json'))==read(saved)['launch_sha256']
    assert old['exit_code']==9 and old['finished']
    assert candidate['request_scratch_offset']==old['context_bytes']
    assert candidate['context_bytes']==old['context_bytes']+16384
    for name,digest in old['source_sha256'].items():assert sha(name)==digest,name
    assert sha(candidate['monitor']['path'])==candidate['monitor']['sha256']
    sys.path[:0]=[str(RUNTIME/'probes'),str(Q/'tools')]
    from guestprofile import get_profile
    from trustcache import load_additions
    import auxkc
    profile=get_profile(candidate['guest_profile'])
    runpy.run_path(str(RUNTIME/'tools/secondary-runtime.py'))['validate_guest_profile'](profile.name)
    assert profile.apfs_without_sep and profile.sep_asc.sks_startup
    assert profile.sep_asc.pnon_refusal and profile.sep_asc.xars_refusal and not profile.sep_asc.pnon_recovery
    assert profile.chip_id_boot.board_id==0x64 and profile.chip_id_boot.security_domain==1
    assert profile.chip_id_boot.certificate_production_status and profile.sip_lp_sip0==2
    args=list(old['arguments']);args[args.index('--guest-profile')+1]=profile.name
    firmware=Path(args[args.index('--firmware-dir')+1]);additions=Path(args[args.index('--trust-additions')+1])
    assert sha(old['root_hash'])==profile.installed_root.payload_sha256
    assert sha(additions)==old['trust_additions_sha256']
    trust=profile.trust_cache.bind(load_additions(additions)).load(firmware)
    image=read(ROOT.parent/'Snapintosh-adreno-pipeline/build/adreno-console-release-20260927/image-v1/qualification.json')
    assert hashlib.sha256(trust).hexdigest()==image['trust_cache_sha256']
    assert sha(old['auxkc'])==old['auxkc_sha256']
    _,pin=auxkc.load(Path(old['auxkc']),sha(firmware/'kernelcache.release.mac17p'))
    assert pin['sha256']==old['auxkc_sha256'] and pin['bundles']==['org.snapintosh.driver.AdrenoX2']
    raw=read(ROOT/'build/pauth-native-sign-20260927/launch-qualification-v1.json')
    image4=Path(old['environment']['SNAP_TXM_NATIVE'])
    assert sha(image4)==raw['artifacts_sha256'][str(image4.relative_to(ROOT))]
    assert '--ans-writable' in args and args[args.index('--console')+1]=='serial'
    assert '--graphics-boot' not in args
    settings=dict(old['environment'],SNAP_SMP_REPORT_PREFIX=PREFIX,SNAP_WATCHDOG='2100',
        SNAP_ADRENO_ADOPT=str(path('-adopt.json')))
    return candidate,old,args,settings


def idle():
    retired=ROOT/'build'/(PREVIOUS+'-retirement-v1.json')
    record=read(retired)
    assert record['status']=='GENERATION53_IDLE' and record['quiesce']=='graceful'
    assert record['after']['stage_generation']==53
    assert record['preservation_sha256']=='2b6b00b420b608b431f8dc690a9a59b33e81cccc1cab68749d4fe73d1b573b39'
    import q1n1proxy
    proxy=q1n1proxy.connect('udp://en5',wait=10)
    try:
        info=proxy.bootinfo();assert info['current_el']==2 and info['stage_generation']==53
        assert info['image_base']==0xb0000000
        status,battery=proxy.live_battery()
        assert status==0 and battery['plausible'] and (battery['ac'] or battery['percent']>=80)
        return info,battery
    finally:proxy.link.close()


def prepare():
    idle()
    environment=dict(os.environ,A16_GPU_FW_DIR=str(ROOT/'gpu/adreno/gpu-bringup-q1n1/fw'))
    for name,arguments in STEPS:
        out=Q/'build/a16-gpu'/f'{PREFIX}-{name}.json';log=out.with_suffix('.log')
        assert not out.exists() and not log.exists(),name
        with log.open('x') as stream:
            result=subprocess.run([sys.executable,'tools/a16gpu.py','--device','udp://en5',
                '--out',str(out),*arguments],cwd=Q,env=environment,stdout=stream,stderr=subprocess.STDOUT)
        assert result.returncode==0,(name,result.returncode)
        record=read(out);assert record.get('stopped') is None,(name,record.get('stopped'))
        if name=='guard':assert record['serror_guard']['present']
        print(json.dumps(dict(step=name,stopped=None,output=str(out))),flush=True)


def boot(candidate,old,arguments,settings):
    import adreno
    import nvme_m3
    import run
    assert Path(run.__file__).resolve()==RUNTIME/'probes/run.py'
    assert not path('-launch.json').exists() and not any((RUNTIME/'build').glob(PREFIX+'-*'))
    for name,_ in STEPS:assert read(Q/'build/a16-gpu'/f'{PREFIX}-{name}.json').get('stopped') is None
    assert not path('-adopt.json').exists() and not path('-adopt-log.json').exists()
    info,battery=idle()
    subprocess.run([sys.executable,str(Q/'tools/a16gpu.py'),'--device','udp://en5',
        '--out',str(path('-adopt-log.json')),'adopt','--record',str(path('-adopt.json'))],cwd=Q,check=True)
    adoption=read(path('-adopt.json'));adreno.load_adoption(adoption,info)
    source_pins={}
    baseline=Path(old['runtime_root'])
    for name in old['source_sha256']:
        p=Path(name);p=RUNTIME/p.relative_to(baseline) if p.is_relative_to(baseline) else p
        source_pins[str(p)]=sha(p)
    for name in candidate['inputs_sha256']:
        p=Path(name)
        if p.suffix in ('.c','.h','.py','.S','.ld'):source_pins[str(p)]=sha(p)
    record=dict(pid=os.getpid(),started=time.time(),arguments=arguments,environment=settings,
        runtime_root=str(RUNTIME),hardware_owner=str(ROOT),observer_root=str(RUNTIME),
        guest_profile=candidate['guest_profile'],source_sha256=source_pins,
        monitor_path=candidate['monitor']['path'],monitor_sha256=candidate['monitor']['sha256'],
        build_defines=candidate['flags'],context_fields=old['context_fields']+1,context_bytes=candidate['context_bytes'],
        previous_stopped_prefix=PREVIOUS,transport='udp://en5',root_hash=old['root_hash'],
        auxkc=old['auxkc'],auxkc_sha256=old['auxkc_sha256'],kext_sha256=old['kext_sha256'],
        trust_additions_sha256=old['trust_additions_sha256'],guest_writable=True,
        expected_window_header_sha256=old['expected_window_header_sha256'],
        ssd_apply_record=old['ssd_apply_record'],ssd_apply_record_sha256=old['ssd_apply_record_sha256'],
        reservation=old['reservation'],adreno_record=adoption,adreno_record_sha256=sha(path('-adopt.json')),
        secondary_runtime_sha256=sha(RUNTIME/'tools/secondary-runtime.py'),battery=battery,
        launcher_sha256=sha(Path(__file__)),qualification_sha256=QUAL_SHA,
        reused_installed_image=True,fresh_filesystem_report=False,storage_snapshot_generation=old['storage_snapshot_generation'],
        boot_argument_additions=['-timesync_bringup'],
        comparison='Generation53: explicit SKS startup on the generation52 GPU/clock baseline. Test endpoint startup, HID cleanup and WindowServer; no desktop success inferred.')
    def save():path('-launch.json').write_text(json.dumps(record,indent=2)+'\n')
    save()
    for key in tuple(os.environ):
        if key.startswith('SNAP_'):del os.environ[key]
    os.environ.update(settings)
    original_build,original_arm=run.build,nvme_m3.arm_window
    def checked_build(name,output):
        if name!='xnuboot':return original_build(name,output)
        validate()
        for suffix in ['.bin','.elf']:
            source=Path(candidate['monitor']['path']).with_suffix(suffix)
            for dest in [output/('xnuboot'+suffix),ROOT/'build'/('xnuboot'+suffix)]:
                shutil.copy2(source,dest);assert sha(dest)==sha(source)
        return Path(candidate['monitor']['path']).read_bytes()
    def checked_arm(nvme,guid,report):
        first,last=original_arm(nvme,guid,report)
        raw=nvme.read(first+nvme_m3.HEADER_OFF//nvme.lba_bytes,4096//nvme.lba_bytes)
        assert hashlib.sha256(raw).hexdigest()==old['expected_window_header_sha256']
        report['window_armed']['header_sha256']=old['expected_window_header_sha256']
        checkpoints=runpy.run_path(str(ROOT/'tools/apfs-checkpoints.py'))['capture'](
            nvme,first,report['window_armed']['header'],path('-apfs-before.json'))
        report['window_armed']['apfs_before']={n:x['latest_xid'] for n,x in checkpoints['containers'].items()}
        return first,last
    run.build,nvme_m3.arm_window=checked_build,checked_arm
    policy=ROOT/'build/run-installed-metal-timesync-20260927.py'
    assert sha(policy)=='10077ad882ac9986a9ea7d559dbf1cde5a245c0abafa66d124f21bf47a34bad8'
    helper=policy.read_text().split('\nbase = Path(__file__)',1)[0]
    scope={'__file__':str(policy),'ORIGINAL':ROOT,'PIPELINE':RUNTIME}
    exec(compile(helper,str(policy),'exec'),scope)
    sys.argv=['probes/run.py',*arguments]
    try:
        result=scope['run_with_timesync_argument'](run,record);record['exit_code']=result;return result
    except BaseException as error:record['exception']=repr(error);raise
    finally:
        record['finished']=time.time();copied={}
        for p in sorted((RUNTIME/'build').glob(PREFIX+'-*')):
            if not p.is_file():continue
            target=ROOT/'build'/p.name;assert not target.exists(),target
            shutil.copy2(p,target);assert sha(target)==sha(p);copied[str(p)]=sha(target)
        record['runtime_artifacts_copied_sha256']=copied;save()


def main():
    parser=argparse.ArgumentParser();group=parser.add_mutually_exclusive_group(required=True)
    for option in ['check-inputs','prepare','boot']:group.add_argument('--'+option,action='store_true')
    args=parser.parse_args();os.chdir(ROOT);sys.stdout.reconfigure(line_buffering=True);sys.dont_write_bytecode=True
    candidate,old,arguments,settings=validate()
    if args.check_inputs:
        print(json.dumps(dict(status='SKS_LAUNCH_INPUTS_VERIFIED',hardware_access=False,
            arguments=arguments,environment=settings,monitor=candidate['monitor'],runtime_root=str(RUNTIME))))
        return 0
    if args.prepare:prepare();return 0
    return boot(candidate,old,arguments,settings)


if __name__=='__main__':raise SystemExit(main())
