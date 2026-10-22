#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preserve source-bound generation53 evidence before a corrected boot."""
from pathlib import Path
import hashlib
import json
import os
import shutil

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'installed-metal-sks-2100s-20260928'
OUT = ROOT/'build/sks-gen53-preserved-20260928-v1'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
path = lambda suffix: ROOT/'build'/(PREFIX+suffix)
launch = json.loads(path('-launch.json').read_text())
audit = json.loads(path('-audit.json').read_text())
assert launch['exit_code'] == 6 and launch['finished']
assert audit['runtime_stop_qualified'] and audit['user_mapping_qualified']
assert audit['monitor_sha256'] == launch['monitor_sha256']
try:
    os.kill(launch['pid'], 0)
except ProcessLookupError:
    pass
else:
    raise RuntimeError('launcher still present')
for name, digest in launch['source_sha256'].items():
    assert sha(name) == digest, name
dma = json.loads(path('-sks-dma-capture-v1.json').read_text())
assert dma['generation'] == 53 and dma['repeated_reads_equal']
assert dma['audit_sha256'] == sha(path('-audit.json'))
for item in dma['buffers']:
    assert sha(item['path']) == item['sha256']
for suffix in ['-cpu3-stop.json','-kernel-waits.json','-gpu-ring.json','-mounts.json',
        '-metal-probe.json','-console-tail.bin','-result.json']:
    assert path(suffix).is_file()
artifacts = sorted(p for p in (ROOT/'build').glob(PREFIX+'*') if p.is_file())
OUT.mkdir(exist_ok=False)
def save_group(paths, kind):
    directory = OUT/kind
    directory.mkdir()
    saved = {}
    for i, p in enumerate(paths):
        p = Path(p)
        digest = sha(p)
        dest = directory/f'{i:04d}-{p.name}'
        shutil.copy2(p, dest)
        assert sha(dest) == sha(p) == digest
        saved[str(p)] = dict(copy=str(dest), sha256=digest)
    return saved
sources = save_group(sorted(launch['source_sha256']), 'sources')
retained = save_group(artifacts, 'artifacts')
monitor = Path(launch['monitor_path'])
assert sha(monitor) == launch['monitor_sha256']
binaries = save_group([monitor, monitor.with_suffix('.elf')], 'monitor')
verification = dict(status='SKS_GEN53_STOPPED_EVIDENCE_PRESERVED', generation=53,
    prefix=PREFIX, launch_sha256=sha(path('-launch.json')), monitor_sha256=launch['monitor_sha256'],
    source_sha256=sha(Path(__file__)), runtime_sources=sources, artifacts=retained, monitor=binaries,
    artifacts_sha256={p.name[len(PREFIX):]:sha(p) for p in artifacts},
    boundary='Source and stopped capture preservation; not a full RAM or filesystem image, and not GUI qualification.')
with (OUT/'preservation.json').open('x') as f:
    f.write(json.dumps(verification, indent=2)+'\n')
with path('-pre-reset-verification.json').open('x') as f:
    f.write(json.dumps(verification, indent=2)+'\n')
print(json.dumps(dict(status=verification['status'], sources=len(sources), artifacts=len(retained),
    output=str(OUT/'preservation.json'), sha256=sha(OUT/'preservation.json'))))
