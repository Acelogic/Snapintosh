#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preserve qualified generation54 before replacing its loader-supplied AuxKC."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'installed-metal-sks-transport-2100s-20260928'
OUT = ROOT / 'build/panel-mode-gen54-preserved-20260928-v1'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
path = lambda suffix: ROOT / 'build' / (PREFIX + suffix)
launch = json.loads(path('-launch.json').read_text())
audit = json.loads(path('-audit.json').read_text())
assert launch['exit_code'] == 9 and launch['finished']
assert launch['adreno_record']['stage_generation'] == 54
assert audit['runtime_stop_qualified'] and audit['user_mapping_qualified']
assert audit['monitor_sha256'] == launch['monitor_sha256']
process = subprocess.run(['ps', '-p', str(launch['pid']), '-o', 'lstart=', '-o', 'command='],
    env=dict(os.environ, TZ='UTC', LC_ALL='C'), capture_output=True, text=True)
pid_observation = dict(pid=launch['pid'], ps_exit=process.returncode, current=process.stdout.strip())
if process.stdout.strip():
    fields = process.stdout.split(None, 5)
    started = datetime.strptime(' '.join(fields[:5]), '%a %b %d %H:%M:%S %Y').replace(tzinfo=timezone.utc).timestamp()
    assert started > launch['finished'], 'original launcher may still be present'
    pid_observation.update(reused=True, current_started=started)
else:
    assert process.returncode == 1 and not process.stderr.strip(), process.stderr
    pid_observation['reused'] = False
for name, digest in launch['source_sha256'].items():
    assert sha(name) == digest, name
for suffix in ['-cpu0-stop.json', '-kernel-waits.json', '-gpu-ring.json', '-mounts.json',
               '-metal-probe.json', '-console-tail.bin', '-result.json', '-panel.png',
               '-native-startup-state-v1.json', '-crash-retention-v1.json']:
    assert path(suffix).is_file(), suffix
assert not path('-pre-reset-verification.json').exists()
artifacts = sorted(p for p in (ROOT / 'build').glob(PREFIX + '*') if p.is_file())
OUT.mkdir(exist_ok=False)


def save_group(paths, kind):
    folder = OUT / kind
    folder.mkdir()
    saved = {}
    for i, raw in enumerate(paths):
        p = Path(raw)
        digest = sha(p)
        dest = folder / f'{i:04d}-{p.name}'
        shutil.copy2(p, dest)
        assert sha(dest) == sha(p) == digest, p
        saved[str(p)] = dict(copy=str(dest), sha256=digest)
    return saved


sources = save_group(sorted(launch['source_sha256']), 'sources')
retained = save_group(artifacts, 'artifacts')
monitor = Path(launch['monitor_path'])
assert sha(monitor) == launch['monitor_sha256']
binaries = save_group([monitor, monitor.with_suffix('.elf'), Path(launch['auxkc'])], 'binaries')
diagnosis = save_group([ROOT / 'build' / p for p in [
    'a16-ic20-survey-gen54-20260928-v1.json',
    'metal-probe-gen54-symbols-20260928-v2.json',
    'panel-mode-installed-replay-20260928-v3.json',
    'panel-mode-candidate-replay-20260928-v2.json']], 'diagnosis')
verification = dict(status='PANEL_MODE_GEN54_STOPPED_EVIDENCE_PRESERVED', generation=54,
    prefix=PREFIX, launch_sha256=sha(path('-launch.json')), monitor_sha256=launch['monitor_sha256'],
    source_sha256=sha(Path(__file__)), runtime_sources=sources, artifacts=retained,
    launcher_pid_observation=pid_observation,
    binaries=binaries, diagnosis=diagnosis,
    artifacts_sha256={p.name[len(PREFIX):]: sha(p) for p in artifacts},
    boundary='Stopped source/artifact preservation; not a full RAM or filesystem image; no desktop qualification')
for target in [OUT / 'preservation.json', path('-pre-reset-verification.json')]:
    with target.open('x') as stream:
        stream.write(json.dumps(verification, indent=2) + '\n')
print(json.dumps(dict(status=verification['status'], sources=len(sources), artifacts=len(retained),
    output=str(OUT / 'preservation.json'), sha256=sha(OUT / 'preservation.json'))))
