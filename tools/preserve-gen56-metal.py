#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preserve recovered generation56 evidence before the compiler deployment.

Failure inventory: stale sources, incomplete capture, a live/reused launcher,
changed binaries, lost recovery provenance, and output reuse must fail closed.
This preserves files, not a full physical RAM image or working desktop proof.
"""
from pathlib import Path
import hashlib
import json
import runpy
import shutil

ROOT = Path(__file__).resolve().parents[1]
PIPE = ROOT.parent / 'Snapintosh-adreno-pipeline'
PREFIX = 'installed-metal-panel-arguments-3600s-20260928'
OUT = ROOT / 'build/metal-pipeline-gen56-preserved-20260928-v1'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
path = lambda suffix: ROOT / 'build' / (PREFIX + suffix)
recovery_tool = ROOT / 'tools/recover-gen56-stop.py'
assert sha(recovery_tool) == '25b67bcde22f08efdac0c371c3499ffcf56f999c4e0affbb017bccfbf2ac9433'
launch = runpy.run_path(str(recovery_tool))['validate']()
proof_path = path('-capture-completion-v1.json')
assert sha(proof_path) == '3ac970b937a6fc3728bb9c17937b58ed8534a42f842aaded0a9204cbe6a16265'
proof = json.loads(proof_path.read_text())
assert proof['status'] == 'GEN56_STOPPED_CAPTURES_AND_MODE_VERIFIED'
assert proof['generation'] == 56 and proof['primary_capture_complete'] and proof['native_capture_complete']
assert proof['original_primary_status'] == 'FAILED' and not proof['original_host_exit_available']
for group in ['artifacts_sha256', 'completed_adapter_records_sha256']:
    for name, digest in proof[group].items():
        assert sha(name) == digest, name
audit = json.loads(path('-audit.json').read_text())
assert audit['runtime_stop_qualified'] and audit['user_mapping_qualified']
assert audit['monitor_sha256'] == launch['monitor_sha256']
recovery = json.loads(path('-host-recovery-v1.json').read_text())
assert recovery['status'] == 'NATIVE_STOP_PREFLIGHT_RECOVERED'
assert sha(path('-host-recovery-v1.json')) == proof['recovery_sha256']
assert sha(path('-launch.json')) == proof['launch_sha256'] == recovery['launch_sha256']
assert sha(launch['auxkc']) == launch['auxkc_sha256']
diagnosis_inputs = {
    ROOT / 'build/a16-hid-descriptor-gen56-20260928-v1.json': '3a8895c73445ad76141a9bf825a45a7b2e9f2220ab94f1c73711a7d92a811ff6',
    PIPE / 'build/qc-pipelines-20260928-v2.json': '9593f160d4004857dc6d568237cd52073426890dae9a2df1bf0f6c95c6062d8d',
    PIPE / 'build/qc-pipelines-sampler-20260928-v1.json': '7a80cbcc6ec5fa74dab44e65bbf2b822eb14b1190e0b6177c8001f5b940a8154',
    PIPE / 'build/qc-compiler-sampler-20260928-v1/qualification.json': 'db1eb1380e90d3a1c39ba4bd7bb6a90e094af24f607ac3ee1bb994c5ebbe3cb8',
}
for name, digest in diagnosis_inputs.items():
    assert sha(name) == digest, name
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


monitor = Path(launch['monitor_path'])
verification = dict(status='GEN56_STOPPED_EVIDENCE_PRESERVED', generation=56,
    prefix=PREFIX, source_sha256=sha(__file__), launch_sha256=sha(path('-launch.json')),
    recovery_sha256=proof['recovery_sha256'], capture_completion_sha256=sha(proof_path),
    original_host_exit_available=False, monitor_sha256=launch['monitor_sha256'],
    runtime_sources=save_group(sorted(launch['source_sha256']), 'sources'),
    artifacts=save_group(artifacts, 'artifacts'),
    binaries=save_group([monitor, monitor.with_suffix('.elf'), Path(launch['auxkc'])], 'binaries'),
    diagnosis=save_group(list(diagnosis_inputs) + [ROOT / 'docs/GEN56-METAL-PIPELINE-20260928.md',
        PIPE / 'docs/ADRENO-QC-PIPELINES-20260928.md'], 'diagnosis'),
    artifacts_sha256={p.name[len(PREFIX):]: sha(p) for p in artifacts},
    boundary='Stopped evidence preserved; original launcher exit unavailable; no full RAM image or desktop proof')
for target in [OUT / 'preservation.json', path('-pre-reset-verification.json')]:
    with target.open('x') as stream:
        stream.write(json.dumps(verification, indent=2) + '\n')
print(json.dumps(dict(status=verification['status'], sources=len(verification['runtime_sources']),
    artifacts=len(artifacts), output=str(OUT / 'preservation.json'), sha256=sha(OUT / 'preservation.json'))))
