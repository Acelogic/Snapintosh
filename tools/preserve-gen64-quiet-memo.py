#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preserve generation64 (quiet profile, SWITCH_ROOT memo) after its exit-6 stop.

Derived from preserve-gen63-composite.py. Generation64 stopped with a guest
exception (launcher exit 6) 27 s after launch, so the evidence contract is the
exit-6 capture record (build/capture-exit6-gen64-20260928.py), not a watchdog
stop. The sequencer's required steps (audit, owner-CPU stop, console tail,
panel, GPU ring) must have passed with bound outputs. Recorded-only steps (kernel
waits, mounts, service profile, verdict, native startup, crash retention) must
have a logged exit status, and every output they produced is checked.

Living documents (docs/*.md) are copied into a separate `documents` group that
retirement does not re-verify; only immutable sources, artifacts, binaries and
records are in the re-verified groups.

--check verifies everything available now and reports the exit-6 capture as
pending while its record is absent. It writes nothing. The copying run requires
the completed capture. Failure inventory: live or reused launcher PID, changed
pins/monitor/firmware link, missing or unbound captures, reused output.
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
QUIET = ROOT.parent/'Snapintosh-quiet'
RUNTIME = ROOT.parent/'Snapintosh-gen64'
PREFIX = 'installed-metal-ca-quiet-memo-1800s-20260928'
OUT = ROOT/'build/metal-ca-quiet-memo-gen64-preserved-20260928-v1'
IMAGE = RUNTIME/'build/ca-composite-quiet-image-20260928-v1/qualification.json'
IMAGE_SHA = '87b6743a50422366d9e4c34533c4a715ec9c3315c332d0742a63ad60ca3079c6'
SEQUENCER = ROOT/'build/capture-exit6-gen64-20260928.py'
REQUIRED = ('audit', 'console-tail', 'panel', 'ring')
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


def captured(launch):
    """The completed exit-6 capture; returns the diagnosis files it adds."""
    record = json.loads(path('-exit6-capture-v1.json').read_text())
    assert record['status'] == 'EXIT6_STOPPED_STATE_CAPTURED' and record['exit_code'] == 6
    assert record['launch_sha256'] == sha(path('-launch.json')) and record['source_sha256'] == sha(SEQUENCER)
    steps = {s['name']: s for s in record['steps']}
    owner = record['owner_cpu']
    assert 0 <= owner < 6 and set(REQUIRED) | {f'cpu{owner}-stop'} <= set(steps)
    for step in steps.values():
        assert 'exit_code' in step and sha(step['log']) == step['log_sha256'], step['name']
        assert not step['required'] or step['exit_code'] == 0, step['name']
    for name in [*REQUIRED, f'cpu{owner}-stop']: assert steps[name]['required'] and steps[name]['exit_code'] == 0, name
    audit_path = path('-audit.json')
    audit = json.loads(audit_path.read_text())
    assert audit['runtime_stop_qualified'] and audit['user_mapping_qualified']
    assert audit['monitor_sha256'] == launch['monitor_sha256'] and audit['service'] == record['service']
    assert (audit['service'][1] & 0xffffffff) - 1 == owner
    for suffix, digest in record['outputs_sha256'].items(): assert sha(path(suffix)) == digest, suffix
    for suffix in [f'-cpu{owner}-stop.json', '-console-tail.json', '-panel.png']:
        assert path(suffix).stat().st_size > 0, suffix
    ring = json.loads(path('-gpu-ring.json').read_text())
    assert ring['status'] == 'STOPPED_GPU_RING_CAPTURED' and ring['generation'] == 64
    assert ring['launch_sha256'] == sha(path('-launch.json')) and ring['audit_sha256'] == sha(audit_path)
    assert ring['ring_sha256'] == sha(path('-gpu-ring.bin')) and ring['fence_sha256'] == sha(path('-gpu-fence.bin'))
    assert ring['repeated_reads_equal'] and not ring['writes']
    optional = {'kernel-waits': '-kernel-waits.json', 'mounts': '-mounts.json', 'service-profile': '-service-profile.json'}
    for name, suffix in optional.items():
        assert not steps[name]['required']
        if steps[name]['exit_code'] == 0: assert path(suffix).stat().st_size > 0, suffix
    if steps['service-profile']['exit_code'] == 0:
        profile = json.loads(path('-service-profile.json').read_text())
        assert profile['monitor_sha256'] == launch['monitor_sha256'] and profile['audit_sha256'] == sha(audit_path)
    for name, status in [('native-startup', 'NATIVE_STARTUP_STATE_CAPTURED'), ('crash-retention', 'CRASH_RETENTION_CAPTURED')]:
        stem = 'native-startup-state' if name == 'native-startup' else name
        binding = path(f'-{stem}-exit6-v1-binding.json')
        if steps[name]['exit_code'] == 0:
            b = json.loads(binding.read_text())
            assert b['status'] == status and b['generation'] == 64 and not b['writes'] and not b['guest_resumed']
            assert b['verification_sha256'] == sha(audit_path) and b['monitor_sha256'] == launch['monitor_sha256']
            assert b['output_sha256'] == sha(path(f'-{stem}-exit6-v1.json'))
    return dict(steps={n: s['exit_code'] for n, s in steps.items()}, owner=owner)


def validate(require_capture=True):
    launch = json.loads(path('-launch.json').read_text())
    assert launch['pid'] == 23491 and launch['started'] == 1790616785.249491
    assert launch.get('finished') and launch['exit_code'] == 6 and launch['finished'] > launch['started']
    assert launch['adreno_record']['stage_generation'] == 64
    assert launch['runtime_root'] == launch['observer_root'] == str(RUNTIME)
    assert launch['context_bytes'] == 5190400 and launch['context_fields'] == 218
    assert len(launch['source_sha256']) == 693
    for name,digest in launch['source_sha256'].items(): assert sha(name) == digest, name
    assert sha(launch['monitor_path']) == launch['monitor_sha256'] == sha(RUNTIME/'build/xnuboot.bin')
    assert launch['monitor_sha256'] == '0149a8e9f95dd3889f608c85046e36ab0160b987542a9d25e330e3269a0ada8c'
    assert sha(launch['auxkc']) == launch['auxkc_sha256'] == '1f22aed6ba8b817e95c9fdca92c2e57a8669076c717c2c3e8e22137e0c1ea606'
    assert launch['qualification_sha256'] == IMAGE_SHA == sha(IMAGE)
    image = json.loads(IMAGE.read_text())
    assert launch['guest_profile'] == image['guest_profile']
    firmware = RUNTIME/'downloads/extracted/j700ap'
    assert firmware.resolve() == Path(image['firmware']).resolve()
    for name, digest in image['firmware_sha256'].items(): assert sha(firmware/name) == digest, name
    assert sha(ROOT/'tools/run-ca-quiet-memo-candidate.py') == launch['launcher_sha256']
    host_absent(launch)
    if not require_capture and not path('-exit6-capture-v1.json').exists():
        return launch, None
    return launch, captured(launch)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--check',action='store_true')
    args = ap.parse_args()
    launch, capture = validate(require_capture=not args.check)
    assert not OUT.exists() and not path('-pre-reset-verification.json').exists()
    artifacts = sorted(p for p in (ROOT/'build').glob(PREFIX+'*') if p.is_file())
    diagnosis = [SEQUENCER, ROOT/'tools/run-ca-quiet-memo-candidate.py', IMAGE,
                 RUNTIME/'build/gen64-monitor-v1/build.json',
                 QUIET/'build/ca-composite-quiet-image-20260928-v1/qualification.json',
                 ROOT/'build/ca-composite-deploy-gen62-20260928/apply-v1.json',
                 TEXTURES/'build/ca-network-auxkc-20260928-v1/adreno.kc.json']
    documents = [ROOT/'docs/GEN64-QUIET-MEMO-BOOT-20260928.md', ROOT/'docs/HANDOFF.md']
    for p in diagnosis + documents: assert p.is_file(), p
    if args.check:
        print(json.dumps(dict(status='GEN64_PRESERVATION_INPUTS_VERIFIED',writes=False,exit_code=launch['exit_code'],
                              sources=len(launch['source_sha256']),artifacts_now=len(artifacts),
                              exit6_capture=capture or 'PENDING: run build/capture-exit6-gen64-20260928.py first',
                              output=str(OUT))))
        return
    assert len(artifacts) >= 30
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
    record = dict(status='GEN64_STOPPED_EVIDENCE_PRESERVED',generation=64,prefix=PREFIX,
                  source_sha256=sha(__file__),launch_sha256=sha(path('-launch.json')),
                  original_host_exit_available=True,exit_code=launch['exit_code'],finished=launch['finished'],
                  monitor_sha256=launch['monitor_sha256'],exit6_capture=capture,
                  exit6_capture_sha256=sha(path('-exit6-capture-v1.json')),
                  service=json.loads(path('-audit.json').read_text())['service'],
                  runtime_sources=save_group(sorted(launch['source_sha256']),'sources'),
                  artifacts=save_group(artifacts,'artifacts'),
                  binaries=save_group([monitor,monitor.with_suffix('.elf'),Path(launch['auxkc'])],'binaries'),
                  diagnosis=save_group(diagnosis,'diagnosis'),
                  documents=save_group(documents,'documents'),
                  artifacts_sha256={p.name[len(PREFIX):]:sha(p) for p in artifacts},
                  boundary='Saved exit-6 stopped evidence; documents are copied but not re-verified at retirement; '
                           'not a complete physical RAM image')
    for target in [OUT/'preservation.json',path('-pre-reset-verification.json')]:
        with target.open('x') as f: f.write(json.dumps(record,indent=2)+'\n')
    print(json.dumps(dict(status=record['status'],sources=len(record['runtime_sources']),artifacts=len(artifacts),
                         output=str(OUT/'preservation.json'),sha256=sha(OUT/'preservation.json'))))


if __name__ == '__main__': main()
