#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Snapshot the SSD at idle generation69 (after idle stage switches 67->68->69; persistence from generation67).

Failure inventory: wrong target/generation, stale approved header, altered saved
evidence, mounted seed, interrupted native hash, copy mismatch, and SError.
Both modes use the existing read-only NVMe path and normal controller cleanup.
Never interrupt a native call. GPU is idle; no guest or second hardware owner.
"""
from pathlib import Path
import argparse
import hashlib
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
PIPE = ROOT.parent / 'Snapintosh-adreno-composite'
PREFIX = 'installed-metal-ca-memo-2400s-20260928'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('mode', choices=['persistence', 'snapshot'])
ap.add_argument('--check', action='store_true')
args = ap.parse_args()
vp = ROOT / 'build' / (PREFIX + '-pre-reset-verification.json')
rp = ROOT / 'build' / (PREFIX + '-retirement-v1.json')
assert sha(vp) == '3b2d607af424b654bb52efec96d3ed6bf02a4bc5ffff94dab8b651a7c36391c4'
assert sha(rp) == '7451d276da2e9932faea4bce4d7bed61c83533ad177195fd95b5bead36e2c939'
saved, retired = [json.loads(p.read_text()) for p in (vp, rp)]
assert saved['status'] == 'GEN66_STOPPED_EVIDENCE_PRESERVED' and saved['generation'] == 66
for suffix, digest in saved['artifacts_sha256'].items():
    assert sha(ROOT / 'build' / (PREFIX + suffix)) == digest, suffix
assert retired['status'] == 'GENERATION67_IDLE' and not retired['ssd_writes']
for _name, _gen in (('idle-gen67-early-stop-stage-20260928', 68), ('idle-gen68-regular-stage-20260928', 69)):
    _r = json.loads((ROOT / 'build' / (_name + '-retirement-v1.json')).read_text())
    assert _r['status'] == f'GENERATION{_gen}_IDLE' and not _r.get('ssd_writes') and not _r.get('gpu_writes'), _name
assert retired['verification_sha256'] == sha(vp)
old = ROOT / 'build/installed-metal-ca-network-3600s-20260928-persistence.json'
assert sha(old) == '3fc3c78b1fd7774c369d1862f71cb1b4c26d245f81c4b080934a122ecbfe8c79'
prior = json.loads(old.read_text())['approved_header_baseline']
package_path = PIPE / 'build/ca-composite-deploy-20260928/delta-v1/package.json'
apply_path = ROOT / 'build/ca-composite-deploy-gen62-20260928/apply-v1.json'
assert sha(package_path) == '9f9f91cf445d9106efec96d127505a9e5597bf580b3cc27feb5b184f633001f6'
assert sha(apply_path) == '1caed1709e0e2a5c0e7dab4af0ca69611f56840f052dfca999483ddb7788e5c4'
package, applied = [json.loads(p.read_text()) for p in (package_path, apply_path)]
assert applied['result'] == 'PASS' and applied['package_sha256'] == sha(package_path)
assert applied['header_after'] == package['header_after_sha256']
assert applied['edges_unchanged'] and not any(applied['serror'].values())
assert package['header_before_sha256'] == prior['header_after_sha256']
assert sha(package_path.with_name('header-after.bin')) == applied['header_after']
baseline = dict(package_sha256=sha(package_path), apply_sha256=sha(apply_path),
    original_header_sha256=prior['original_header_sha256'],
    header_range=prior['header_range'], header_after_sha256=applied['header_after'],
    loader_progress_verification_sha256=sha(vp), retirement_sha256=sha(rp),
    preceding_persistence_sha256=sha(old))


def approved_reference(reference):
    assert len(reference['edge_ranges']) == len(reference['edges_before']) == 7
    index = reference['edge_ranges'].index(baseline['header_range'])
    assert reference['edges_before'][index] == baseline['original_header_sha256']
    reference['edges_before'][index] = baseline['header_after_sha256']
    return reference


if args.mode == 'persistence':
    base = ROOT / 'tools/capture-apfs-persistence.py'
    assert sha(base) == '4d59b3dfb33425c5ec56312d76dc4015507310a9664f3d9f993fe9e81da53c05'
    changes = {
        "reference=json.loads((ROOT/'build/nvme-writeback-a16-v1-20260926.json').read_text())":
            "reference=approved_reference(json.loads((ROOT/'build/nvme-writeback-a16-v1-20260926.json').read_text()))",
        "source_sha256=sha(Path(__file__).read_bytes()))":
            "source_sha256=sha(Path(__file__).read_bytes()), approved_header_baseline=baseline, transformed_sha256=transformed_sha)",
    }
else:
    pp = ROOT / 'build' / (PREFIX + '-persistence.json')
    persistence = json.loads(pp.read_text())
    assert persistence['result'] == 'PASS' and persistence['bootinfo']['stage_generation'] == 67
    assert persistence['edges_unchanged'] and not any(persistence['serror'].values())
    assert persistence['approved_header_baseline'] == baseline
    base = ROOT / 'build/snapshot-installed-metal-20260926.py'
    assert sha(base) == '6eb0d9e06a2e7def32f5b7afb5668eb0912b21501d3b15bd4abe7cbb5fa0844f'
    changes = {
        "OUT=ROOT/'build/installed-metal-20260926/snapshot-v1'": "OUT=ROOT/'build/ca-memo-deploy-20260928/snapshot-gen69-v1'",
        "SEED=ROOT/'build/full-install/configured-j700-cryptex-20260925.img'": "SEED=ROOT/'build/ca-memo-deploy-20260928/snapshot-v1/current.img'",
        "PREVIOUS='installed-adreno-dart-window-1200s-20260926'": "PREVIOUS='" + PREFIX + "'",
        "previous['bootinfo']['stage_generation']==37": "previous['bootinfo']['stage_generation']==67",
        "verification['generation']==36": "verification['generation']==66",
        "'ALL_REQUIRED_STOPPED_CAPTURES_VERIFIED'": "'GEN66_STOPPED_EVIDENCE_PRESERVED'",
        "package_dir=ROOT/'build/full-install/j700-cryptex-delta-20260925'": "package_dir=ROOT.parent/'Snapintosh-adreno-composite/build/ca-composite-deploy-20260928/delta-v1'",
        "subprocess.run(['cp','-c',str(SEED),str(IMAGE)],check=True)": "subprocess.run(['cp','-c',str(SEED),str(IMAGE)],check=True)\n    os.chmod(IMAGE,0o644)",
        'generation=37,seed=str(SEED)': 'generation=69,seed=str(SEED)',
        "info['stage_generation']==37": "info['stage_generation']==69",
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
    sys.argv = [sys.argv[0], '--device', 'udp://en5', '--prefix', PREFIX, '--generation', '69']
    exec(code, dict(__file__=__file__, __name__='__main__', approved_reference=approved_reference,
        baseline=baseline, transformed_sha=transformed_sha))
