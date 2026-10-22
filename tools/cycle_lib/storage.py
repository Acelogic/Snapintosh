# SPDX-License-Identifier: MIT
"""Read a retired run's SSD persistence, then snapshot the SSD, at the idle generation after it.

Generalises tools/storage-gen61-network.py and storage-gen66-memo.py. The values those
adapters pinned come from records: the run's preservation and retirement, the SSD
apply record its launch booted (launch 'ssd_apply_record'), that apply's package (the
delta-v1 beside the launch's image-v1, or --package), the preceding persistence (the
PASS record whose approved header is the package's header-before), and the seed image
(current.img of the latest snapshot taken before this generation). The pinned base
tools run with the same substitutions the adapters made. Both modes use the existing
read-only NVMe path. Never interrupt a native call.
"""
from pathlib import Path
import hashlib
import json
import sys

from .common import PINS, need, sha, matches, read, require_exclusive

PERSISTENCE_CHANGES = {
    "reference=json.loads((ROOT/'build/nvme-writeback-a16-v1-20260926.json').read_text())":
        "reference=approved_reference(json.loads((ROOT/'build/nvme-writeback-a16-v1-20260926.json').read_text()))",
    "source_sha256=sha(Path(__file__).read_bytes()))":
        "source_sha256=sha(Path(__file__).read_bytes()), approved_header_baseline=baseline, transformed_sha256=transformed_sha)",
}


def pinned_tool(ws, mode):
    entry = PINS['storage'][mode]
    path = ws.path(entry['path'])
    need(matches(path, entry['sha256']), f'{entry["path"]} changed')
    return path


def chain(ws, prefix, package=None):
    """The approved-header chain for this retired run, verified. No hardware access."""
    vp, rp = ws.prefixed(prefix, '-pre-reset-verification.json'), ws.prefixed(prefix, '-retirement-v1.json')
    need(vp.is_file() and rp.is_file(), f'{prefix} is not preserved and retired')
    saved, retired = read(vp), read(rp)
    generation = saved['generation']
    need(saved['status'] == f'GEN{generation}_STOPPED_EVIDENCE_PRESERVED', 'preservation status')
    for suffix, digest in saved['artifacts_sha256'].items():
        need(matches(ws.prefixed(prefix, suffix), digest), f'preserved artifact {suffix} changed')
    need(retired['status'] == f'GENERATION{generation + 1}_IDLE' and not retired['ssd_writes'], 'retirement status')
    need(retired['verification_sha256'] == sha(vp), 'retirement is bound to another preservation')
    launch = read(ws.prefixed(prefix, '-launch.json'))
    apply_path = ws.local(launch['ssd_apply_record'])
    need(matches(apply_path, launch['ssd_apply_record_sha256']), 'SSD apply record changed')
    deployment = launch.get('compiler_deployment') or {}
    if package:
        package_path = Path(package).resolve()
    elif deployment.get('package'):
        package_path = ws.local(deployment['package'])
    else:
        package_path = ws.local(deployment['image']).parent.parent / 'delta-v1/package.json'
    applied = read(apply_path)
    need(matches(package_path, applied['package_sha256']) and applied['package_sha256'] == deployment.get('package_sha256'),
         f'{package_path} is not the package the apply record and launch name (pass --package)')
    package_record = read(package_path)
    need(applied['result'] == 'PASS' and applied['header_after'] == package_record['header_after_sha256'], 'apply result')
    need(applied['edges_unchanged'] and not any(applied['serror'].values()), 'apply edges or SError')
    need(matches(package_path.with_name('header-after.bin'), applied['header_after']), 'header-after.bin')
    persisted = []
    for path in ws.build.glob('*-persistence.json'):
        record = read(path)
        baseline = record.get('approved_header_baseline') or {}
        if record.get('result') == 'PASS' and baseline.get('header_after_sha256') == package_record['header_before_sha256']:
            persisted.append((record['bootinfo']['stage_generation'], path))
    need(persisted, 'no PASS persistence record approves the package\'s header-before')
    persisted.sort()
    need(len(persisted) == 1 or persisted[-1][0] != persisted[-2][0], 'two preceding persistence records at one generation')
    old = persisted[-1][1]
    prior = read(old)['approved_header_baseline']
    need(package_record['header_before_sha256'] == prior['header_after_sha256'], 'header chain')
    baseline = dict(package_sha256=sha(package_path), apply_sha256=sha(apply_path),
                    original_header_sha256=prior['original_header_sha256'], header_range=prior['header_range'],
                    header_after_sha256=applied['header_after'], loader_progress_verification_sha256=sha(vp),
                    retirement_sha256=sha(rp), preceding_persistence_sha256=sha(old))
    return dict(generation=generation, idle=generation + 1, baseline=baseline, package=package_path, old=old,
                apply=apply_path, verification=vp, retirement=rp)


def seed_snapshot(ws, before_generation):
    """current.img of the latest PASS snapshot taken before this generation."""
    found = []
    for path in list(ws.build.glob('*/snapshot-v1/snapshot.json')) + list(ws.build.glob('*-snapshot-v1/snapshot.json')):
        record = read(path)
        if record.get('result') == 'PASS' and record.get('generation', 1 << 30) < before_generation:
            found.append((record['generation'], path))
    need(found, 'no earlier PASS snapshot to seed from')
    found.sort()
    need(len(found) == 1 or found[-1][0] != found[-2][0], 'two snapshots at the latest generation')
    seed = found[-1][1].parent / 'current.img'
    need(seed.is_file(), f'{seed} is missing')
    return seed


def render(ws, prefix, mode, out=None, package=None):
    """(transformed base source, base path, facts). No hardware access."""
    c = chain(ws, prefix, package)
    base = pinned_tool(ws, mode)
    if mode == 'persistence':
        changes = dict(PERSISTENCE_CHANGES)
        facts = {}
    else:
        pp = ws.prefixed(prefix, '-persistence.json')
        need(pp.is_file(), f'{pp.name} does not exist: run `storage --prefix {prefix} persistence` first')
        persistence = read(pp)
        need(persistence['result'] == 'PASS' and persistence['bootinfo']['stage_generation'] == c['idle'],
             'persistence did not pass at the idle generation')
        need(persistence['edges_unchanged'] and not any(persistence['serror'].values()), 'persistence edges or SError')
        need(persistence['approved_header_baseline'] == c['baseline'], 'persistence was taken against another baseline')
        out = Path(out).resolve() if out else ws.prefixed(prefix, '-snapshot-v1')
        seed = seed_snapshot(ws, c['idle'])
        rel = lambda p: str(Path(p).relative_to(ws.root))
        changes = {
            "OUT=ROOT/'build/installed-metal-20260926/snapshot-v1'": f"OUT=ROOT/{rel(out)!r}",
            "SEED=ROOT/'build/full-install/configured-j700-cryptex-20260925.img'": f"SEED=ROOT/{rel(seed)!r}",
            "PREVIOUS='installed-adreno-dart-window-1200s-20260926'": "PREVIOUS='" + prefix + "'",
            "previous['bootinfo']['stage_generation']==37": f"previous['bootinfo']['stage_generation']=={c['idle']}",
            "verification['generation']==36": f"verification['generation']=={c['generation']}",
            "'ALL_REQUIRED_STOPPED_CAPTURES_VERIFIED'": f"'GEN{c['generation']}_STOPPED_EVIDENCE_PRESERVED'",
            "package_dir=ROOT/'build/full-install/j700-cryptex-delta-20260925'":
                f"package_dir=ROOT.parent/{ws.relative(c['package'].parent)!r}",
            "subprocess.run(['cp','-c',str(SEED),str(IMAGE)],check=True)":
                "subprocess.run(['cp','-c',str(SEED),str(IMAGE)],check=True)\n    os.chmod(IMAGE,0o644)",
            'generation=37,seed=str(SEED)': f"generation={c['idle']},seed=str(SEED)",
            "info['stage_generation']==37": f"info['stage_generation']=={c['idle']}",
            "reference=json.loads((ROOT/'build/nvme-writeback-a16-v1-20260926.json').read_text())":
                "reference=approved_reference(json.loads((ROOT/'build/nvme-writeback-a16-v1-20260926.json').read_text()))",
            'source_sha256=sha(Path(__file__).read_bytes()),sources=':
                'source_sha256=sha(Path(__file__).read_bytes()),approved_header_baseline=baseline,transformed_sha256=transformed_sha,sources=',
            "assert status==0 and 'on AC' in battery['text'],battery['text']":
                "assert status==0 and battery['plausible'] and (battery['ac'] or battery['percent']>=30),battery['text']",
        }
        facts = dict(out=str(out), seed=str(seed), persistence=str(pp))
    source = base.read_text()
    for old, new in changes.items():
        need(source.count(old) == 1, f'{base.name} no longer contains exactly one {old!r}')
        source = source.replace(old, new)
    facts.update(generation=c['generation'], idle_generation=c['idle'], package=str(c['package']),
                 apply_record=str(c['apply']), preceding_persistence=str(c['old']), baseline=c['baseline'])
    return source, base, facts, c


def main(ws, args):
    out = getattr(args, 'out', None)
    source, base, facts, c = render(ws, args.prefix, args.mode, out, getattr(args, 'package', None))
    if args.mode == 'snapshot':
        need(not Path(facts['out']).exists(), f'{facts["out"]} already exists (reused output)')
    else:
        need(not ws.prefixed(args.prefix, '-persistence.json').exists(), 'persistence record already exists')
    code = compile(source, str(base), 'exec')
    transformed = hashlib.sha256(source.encode()).hexdigest()
    if args.check:
        print(json.dumps(dict(status='STORAGE_ADAPTER_VERIFIED', mode=args.mode, transformed_sha256=transformed,
                              hardware_access=False, **facts), indent=2), flush=True)
        return 0
    require_exclusive(ws)
    baseline = c['baseline']

    def approved_reference(reference):
        need(len(reference['edge_ranges']) == len(reference['edges_before']) == 7, 'edge reference shape')
        index = reference['edge_ranges'].index(baseline['header_range'])
        need(reference['edges_before'][index] == baseline['original_header_sha256'], 'edge reference header')
        reference['edges_before'][index] = baseline['header_after_sha256']
        return reference

    sys.argv = [str(ws.tool), '--device', ws.device, '--prefix', args.prefix, '--generation', str(c['idle'])]
    exec(code, dict(__file__=str(ws.tool), __name__='__main__', approved_reference=approved_reference,
                    baseline=baseline, transformed_sha=transformed))
    return 0
