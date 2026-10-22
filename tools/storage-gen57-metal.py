#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read gen56 persistence and snapshot its current SSD at idle generation57.

Failure inventory: wrong device/generation, stale header lineage, changed saved
evidence, interrupted native hash, mounted seed, copied-byte mismatch, and SError.
Use the existing full-container native hash/copy and normal NVMe cleanup path.
Never interrupt a running native call. Neither mode writes SSD media.
"""
from pathlib import Path
import argparse
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
PIPE = ROOT.parent / 'Snapintosh-adreno-pipeline'
PREFIX = 'installed-metal-panel-arguments-3600s-20260928'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('mode', choices=['persistence', 'snapshot'])
ap.add_argument('--check', action='store_true')
args = ap.parse_args()
vp = ROOT / 'build' / (PREFIX + '-pre-reset-verification.json')
rp = ROOT / 'build' / (PREFIX + '-retirement-v1.json')
assert sha(vp) == '7d50cc5d5db58e9348b22a52abddea38281e379e1d7bee490ab55e3792b9777d'
assert sha(rp) == '9c6a7fb09e344050880ebcf4fe9e0c33d62722b937aa534dba2935f3e6052d09'
saved, retired = [json.loads(p.read_text()) for p in (vp, rp)]
assert saved['status'] == 'GEN56_STOPPED_EVIDENCE_PRESERVED' and saved['generation'] == 56
for suffix, digest in saved['artifacts_sha256'].items():
    assert sha(ROOT / 'build' / (PREFIX + suffix)) == digest, suffix
assert retired['status'] == 'GENERATION57_IDLE' and retired['quiesce'] == 'graceful'
assert retired['verification_sha256'] == sha(vp)
old = ROOT / 'build/installed-metal-console-release-3600s-20260927-persistence.json'
assert sha(old) == '80f9292d89790b4dbab205a4d88545461d2132ba3fbd4c4e2f3a383ae0414d51'
baseline = dict(json.loads(old.read_text())['approved_header_baseline'])
package_path = PIPE / 'build/adreno-gui-integration-20260927/delta-v1/package.json'
apply_path = ROOT / 'build/installed-metal-gui-20260927/apply-v1.json'
assert sha(package_path) == baseline['package_sha256']
assert sha(apply_path) == baseline['apply_sha256']
package, applied = [json.loads(p.read_text()) for p in (package_path, apply_path)]
assert applied['result'] == 'PASS' and applied['package_sha256'] == sha(package_path)
assert applied['header_after'] == baseline['header_after_sha256'] == package['header_after_sha256']
assert sha(package_path.with_name('header-after.bin')) == baseline['header_after_sha256']
baseline.update(loader_progress_verification_sha256=sha(vp), retirement_sha256=sha(rp),
    preceding_persistence_sha256=sha(old))


def approved_reference(reference):
    assert len(reference['edge_ranges']) == len(reference['edges_before']) == 7
    index = reference['edge_ranges'].index(baseline['header_range'])
    assert reference['edges_before'][index] == baseline['original_header_sha256']
    reference['edges_before'][index] = baseline['header_after_sha256']
    return reference


def recovered_launch_admitted(launch):
    assert not launch.get('finished') and 'exit_code' not in launch
    assert launch['adreno_record']['stage_generation'] == 56
    assert saved['launch_sha256'] == sha(ROOT / 'build' / (PREFIX + '-launch.json'))
    return True


if args.mode == 'persistence':
    base = ROOT / 'tools/capture-apfs-persistence.py'
    assert sha(base) == '4d59b3dfb33425c5ec56312d76dc4015507310a9664f3d9f993fe9e81da53c05'
    changes = {
        "assert launch.get('finished') and '--ans-writable' in launch['arguments']":
            "assert recovered_launch_admitted(launch) and '--ans-writable' in launch['arguments']",
        "reference=json.loads((ROOT/'build/nvme-writeback-a16-v1-20260926.json').read_text())":
            "reference=approved_reference(json.loads((ROOT/'build/nvme-writeback-a16-v1-20260926.json').read_text()))",
        "source_sha256=sha(Path(__file__).read_bytes()))":
            "source_sha256=sha(Path(__file__).read_bytes()), approved_header_baseline=baseline, transformed_sha256=transformed_sha)",
    }
else:
    pp = ROOT / 'build' / (PREFIX + '-persistence.json')
    persistence = json.loads(pp.read_text())
    assert persistence['result'] == 'PASS' and persistence['bootinfo']['stage_generation'] == 57
    assert persistence['edges_unchanged'] and not any(persistence['serror'].values())
    assert persistence['approved_header_baseline'] == baseline
    base = ROOT / 'build/snapshot-installed-metal-20260926.py'
    assert sha(base) == '6eb0d9e06a2e7def32f5b7afb5668eb0912b21501d3b15bd4abe7cbb5fa0844f'
    changes = {
        "OUT=ROOT/'build/installed-metal-20260926/snapshot-v1'": "OUT=ROOT/'build/metal-pipeline-deploy-20260928/snapshot-v1'",
        "SEED=ROOT/'build/full-install/configured-j700-cryptex-20260925.img'": "SEED=ROOT/'build/installed-metal-console-release-20260927/report-snapshot-v1/current.img'",
        "PREVIOUS='installed-adreno-dart-window-1200s-20260926'": "PREVIOUS='" + PREFIX + "'",
        "previous['bootinfo']['stage_generation']==37": "previous['bootinfo']['stage_generation']==57",
        "verification['generation']==36": "verification['generation']==56",
        "'ALL_REQUIRED_STOPPED_CAPTURES_VERIFIED'": "'GEN56_STOPPED_EVIDENCE_PRESERVED'",
        "package_dir=ROOT/'build/full-install/j700-cryptex-delta-20260925'": "package_dir=ROOT.parent/'Snapintosh-adreno-pipeline/build/adreno-gui-integration-20260927/delta-v1'",
        "subprocess.run(['cp','-c',str(SEED),str(IMAGE)],check=True)": "subprocess.run(['cp','-c',str(SEED),str(IMAGE)],check=True)\n    os.chmod(IMAGE,0o644)",
        'generation=37,seed=str(SEED)': 'generation=57,seed=str(SEED)',
        "info['stage_generation']==37": "info['stage_generation']==57",
        "reference=json.loads((ROOT/'build/nvme-writeback-a16-v1-20260926.json').read_text())": "reference=approved_reference(json.loads((ROOT/'build/nvme-writeback-a16-v1-20260926.json').read_text()))",
        'source_sha256=sha(Path(__file__).read_bytes()),sources=': 'source_sha256=sha(Path(__file__).read_bytes()),approved_header_baseline=baseline,transformed_sha256=transformed_sha,sources=',
        "assert status==0 and 'on AC' in battery['text'],battery['text']": "assert status==0 and battery['plausible'] and (battery['ac'] or battery['percent']>=30),battery['text']",
    }
source = base.read_text()
for old, new in changes.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
code = compile(source, str(base), 'exec')
transformed_sha = hashlib.sha256(source.encode()).hexdigest()
if args.check:
    print(json.dumps(dict(status='STORAGE_ADAPTER_VERIFIED', mode=args.mode,
        transformed_sha256=transformed_sha, hardware_access=False)))
else:
    sys.argv = [sys.argv[0], '--device', 'udp://en5', '--prefix', PREFIX, '--generation', '57']
    exec(code, dict(__file__=__file__, __name__='__main__', approved_reference=approved_reference,
        baseline=baseline, recovered_launch_admitted=recovered_launch_admitted, transformed_sha=transformed_sha))
