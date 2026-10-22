#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preserve generation63 (composite CA plug-in) before retirement.

Failure inventory: live/reused launcher ambiguity, changed pinned inputs,
incomplete captures, mismatched bindings, changed binaries and reused output.
This copies saved evidence, not all physical RAM, and does not contact the A16.
--check runs every admission check and writes nothing.

Generation63's collectors were run in sequence by hand, without the generation61
coordinator, so there is no -collection-sequence-v1.json. Completion is taken
from the three sequence logs instead: the primary collector's final line is
printed only after its ring capture (check=True) returns, and each native
observer's final line names its CAPTURED binding, whose hash must match.
"""
from pathlib import Path
from datetime import datetime, timezone
import argparse
import hashlib
import json
import os
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TEXTURES = ROOT.parent/'Snapintosh-adreno-buffer-textures'
COMPOSITE = ROOT.parent/'Snapintosh-adreno-composite'
RUNTIME = ROOT.parent/'Snapintosh-adreno-sks'
PREFIX = 'installed-metal-ca-composite-2400s-20260928'
OUT = ROOT/'build/metal-ca-composite-gen63-preserved-20260928-v1'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
path = lambda suffix: ROOT/'build'/(PREFIX+suffix)


def host_absent(launch):
    p = subprocess.run(['ps','-p',str(launch['pid']),'-o','lstart='],
                       env=dict(os.environ,TZ='UTC',LC_ALL='C'),capture_output=True,text=True)
    if p.stdout.strip():
        started = datetime.strptime(p.stdout.strip(),'%a %b %d %H:%M:%S %Y').replace(tzinfo=timezone.utc).timestamp()
        assert started > launch['finished'], 'original launcher or ambiguous reused PID remains'
    else:
        assert p.returncode == 1 and not p.stderr.strip(), p.stderr


def last_line(p):
    lines = [x for x in Path(p).read_text().splitlines() if x.strip()]
    assert lines, p
    return lines[-1]


def validate():
    launch = json.loads(path('-launch.json').read_text())
    assert launch['pid'] == 96731 and launch['started'] == 1790611903.126976
    assert launch.get('finished') and launch['exit_code'] == 9 and launch['finished'] > launch['started']
    assert launch['adreno_record']['stage_generation'] == 63
    assert launch['runtime_root'] == launch['observer_root'] == str(RUNTIME)
    assert launch['context_bytes'] == 5124736 and launch['context_fields'] == 217
    assert len(launch['source_sha256']) == 453
    for name,digest in launch['source_sha256'].items(): assert sha(name) == digest, name
    assert sha(launch['monitor_path']) == launch['monitor_sha256'] == sha(RUNTIME/'build/xnuboot.bin')
    assert sha(launch['auxkc']) == launch['auxkc_sha256'] == '1f22aed6ba8b817e95c9fdca92c2e57a8669076c717c2c3e8e22137e0c1ea606'
    assert launch['monitor_sha256'] == '340bae8fa6cdfc26f65d96003551e79298698ff98b256c25b316f32f3c0ec934'
    host_absent(launch)
    audit_path = path('-audit.json')
    audit = json.loads(audit_path.read_text())
    assert audit['runtime_stop_qualified'] and audit['user_mapping_qualified']
    assert audit['monitor_sha256'] == launch['monitor_sha256']
    assert audit['service'] == [0,0x100000001,0x8000000000000003,0,0,0,0,0]
    for name,status in [('native-startup-state','NATIVE_STARTUP_STATE_CAPTURED'),('crash-retention','CRASH_RETENTION_CAPTURED')]:
        b = json.loads(path('-'+name+'-v1-binding.json').read_text())
        assert b['status'] == status and b['generation'] == 63 and not b['writes'] and not b['guest_resumed']
        assert b['verification_sha256'] == sha(audit_path) and b['monitor_sha256'] == launch['monitor_sha256']
        assert b['output_sha256'] == sha(path('-'+name+'-v1.json'))
    ring = json.loads(path('-gpu-ring.json').read_text())
    assert ring['status'] == 'STOPPED_GPU_RING_CAPTURED' and ring['generation'] == 63
    assert ring['launch_sha256'] == sha(path('-launch.json')) and ring['audit_sha256'] == sha(audit_path)
    assert ring['ring_sha256'] == sha(path('-gpu-ring.bin')) and ring['fence_sha256'] == sha(path('-gpu-fence.bin'))
    assert ring['repeated_reads_equal'] and not ring['writes']
    profile = json.loads(path('-service-profile.json').read_text())
    assert profile['monitor_sha256'] == launch['monitor_sha256'] and profile['audit_sha256'] == sha(audit_path)
    for suffix in ['-cpu0-stop.json','-kernel-waits.json','-mounts.json','-metal-probe.json','-ans.json',
                   '-console-tail.json','-panel.png']:
        assert path(suffix).stat().st_size > 0, suffix
    assert not path('-collection-sequence-v1.json').exists()
    primary = path('-sequence-primary-v1.log').read_text()
    assert 'all required pre-reset captures complete' in primary
    assert last_line(path('-sequence-primary-v1.log')) == \
        'GUI stopped diagnostics and ring/fence captured; pixels and panel still require verification'
    for step,name,status in [('native','native-startup-state','NATIVE_STARTUP_STATE_CAPTURED'),
                             ('crashes','crash-retention','CRASH_RETENTION_CAPTURED')]:
        final = json.loads(last_line(path('-sequence-'+step+'-v1.log')))
        binding = path('-'+name+'-v1-binding.json')
        assert final == dict(status=status,binding=str(binding),sha256=sha(binding)), step
    return launch


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--check',action='store_true')
    args = ap.parse_args()
    launch = validate()
    assert not OUT.exists() and not path('-pre-reset-verification.json').exists()
    artifacts = sorted(p for p in (ROOT/'build').glob(PREFIX+'*') if p.is_file())
    assert len(artifacts) >= 40
    diagnosis = [ROOT/'docs/GEN62-COMPOSITE-DEPLOYMENT-20260928.md', ROOT/'docs/HANDOFF.md',
                 ROOT/'docs/GEN57-STARTUP-TIMING-20260928.md',
                 ROOT/'build/capture-native-startup-gen63-20260928.py',
                 ROOT/'build/capture-crash-retention-gen63-20260928.py',
                 ROOT/'build/ca-composite-deploy-gen62-20260928/apply-v1.json',
                 COMPOSITE/'build/ca-composite-deploy-20260928/image-v1/qualification.json',
                 TEXTURES/'build/ca-network-auxkc-20260928-v1/adreno.kc.json']
    for p in diagnosis: assert p.is_file(), p
    if args.check:
        print(json.dumps(dict(status='GEN63_PRESERVATION_INPUTS_VERIFIED',writes=False,
                              sources=len(launch['source_sha256']),artifacts=len(artifacts),
                              diagnosis=len(diagnosis),output=str(OUT))))
        return
    OUT.mkdir()
    def save_group(paths,kind):
        folder = OUT/kind
        folder.mkdir()
        saved = {}
        for i,raw in enumerate(paths):
            p = Path(raw); digest = sha(p); dest = folder/f'{i:04d}-{p.name}'
            shutil.copy2(p,dest)
            assert sha(dest) == sha(p) == digest, p
            saved[str(p)] = dict(copy=str(dest),sha256=digest)
        return saved

    monitor = Path(launch['monitor_path'])
    record = dict(status='GEN63_STOPPED_EVIDENCE_PRESERVED',generation=63,prefix=PREFIX,
                  source_sha256=sha(__file__),launch_sha256=sha(path('-launch.json')),
                  original_host_exit_available=True,exit_code=launch['exit_code'],finished=launch['finished'],
                  monitor_sha256=launch['monitor_sha256'],
                  runtime_sources=save_group(sorted(launch['source_sha256']),'sources'),
                  artifacts=save_group(artifacts,'artifacts'),
                  binaries=save_group([monitor,monitor.with_suffix('.elf'),Path(launch['auxkc'])],'binaries'),
                  diagnosis=save_group(diagnosis,'diagnosis'),
                  artifacts_sha256={p.name[len(PREFIX):]:sha(p) for p in artifacts},
                  boundary='Saved stopped evidence preserved; not a complete physical RAM image or desktop proof')
    for target in [OUT/'preservation.json',path('-pre-reset-verification.json')]:
        with target.open('x') as f: f.write(json.dumps(record,indent=2)+'\n')
    print(json.dumps(dict(status=record['status'],sources=len(record['runtime_sources']),artifacts=len(artifacts),
                         output=str(OUT/'preservation.json'),sha256=sha(OUT/'preservation.json'))))


if __name__ == '__main__': main()
