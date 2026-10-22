#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""compare_compilers.py - prove two libAdrenoCompiler.dylib builds produce the same output for the whole corpus.

Both libraries compile the same job list through the C API (tests/corpus_compile.c, arm64e): every sweep group
(tools/sweep.py generators: SkyLight, CoreDisplay, QuartzCore, function-constant sweeps, XR targets/textures), the
AIR inputs CoreAnimation handed the plug-in in real scenes (--air-dir, files <sha256>-<entry>.bc) as vertex and
as fragment/BGRA8, and each job's safe_constlen variant where the sidecar asks for it. Per job the blob, code,
program export and sidecar are hashed (compiler identity blanked); the report lists every difference.

  python3 tools/compare_compilers.py --old OLD.dylib --new NEW.dylib --cli build/air2ir3 [--air-dir DIR ...] --output DIR
                                     [--threads 8] [--groups skylight_base,...]
"""
import argparse, hashlib, importlib.util, json, os, re, subprocess, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sha = lambda p: hashlib.sha256(open(p, 'rb').read()).hexdigest()


def sweep_jobs(groups=None, cli=None):
    os.environ.setdefault('AIR2IR3_SCRATCH', os.path.join(os.path.dirname(os.path.dirname(ROOT)), '..', 'Snapintosh', 'gpu'))
    sys.path.insert(0, os.path.join(ROOT, 'tools'))
    spec = importlib.util.spec_from_file_location('sweep_for_compare', os.path.join(ROOT, 'tools', 'sweep.py'))
    m = importlib.util.module_from_spec(spec)
    argv, sys.argv = sys.argv, ['sweep.py']
    try:
        spec.loader.exec_module(m)
    finally:
        sys.argv = argv
    ix = m.load_index()
    out, skipped = [], {}
    for name in sorted(n for n in dir(m) if n.startswith('g_')):
        if groups is not None and name[2:] not in groups:
            continue
        try:
            out += getattr(m, name)(ix, cli)
        except (FileNotFoundError, OSError) as e:      # a group whose inputs this tree lacks (templates)
            skipped[name] = repr(e)
    return out, skipped


def line(j):
    consts = [f'{k}={",".join(str(float(x)) for x in (v if isinstance(v, list) else [v]))}' for k, v in sorted(j['fc'].items())]
    consts += [f'{k}={",".join(str(float(x)) for x in (v if isinstance(v, list) else [v]))}' for k, v in sorted(j['fcname'].items())]
    rt = [0] * 8
    for i, f in enumerate(j['rt_formats']):
        rt[i] = f
    tex = [0] * 16
    for t, c in j['tex_classes'].items():
        tex[int(t)] = c
    blends = []
    for i in range(8):
        b = j['blend'].get(i) or j['blend'].get(str(i)) or {}
        blends.append(','.join(str(b.get(k, 0)) for k in ('enabled', 'rgb_op', 'alpha_op', 'src_rgb', 'dst_rgb', 'src_alpha', 'dst_alpha')))
    return '\t'.join([j['id'], j['bc'], j.get('entry') or '-', j.get('stage') or 'any',
                      ','.join(map(str, rt)) if any(rt) else '-', ';'.join(consts) or '-',
                      ','.join(map(str, tex)) if any(tex) else '-', ';'.join(blends) if j['blend'] else '-'])


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--old', required=True)
    ap.add_argument('--new', required=True)
    ap.add_argument('--air-dir', action='append', default=[])
    ap.add_argument('--output', required=True)
    ap.add_argument('--threads', type=int, default=8)
    ap.add_argument('--groups', help='comma list of sweep groups (default: all)')
    ap.add_argument('--cli', help='an air2ir3 CLI of these sources (--list-fcs metadata for the structured sweeps)')
    args = ap.parse_args()
    out = os.path.abspath(args.output)
    os.makedirs(out, exist_ok=False)
    jobs, skipped = sweep_jobs(set(args.groups.split(',')) if args.groups is not None else None, args.cli)
    lines = [line(j) for j in jobs]
    ca = 0
    for d in args.air_dir:
        for f in sorted(os.listdir(d)):
            if not f.endswith('.bc'):
                continue
            digest, entry = f[:-3].split('-', 1)
            p = os.path.join(d, f)
            assert sha(p) == digest, p
            stage = 'fragment' if entry != 'air.vertexFetchFunction' and not entry.startswith('Vfx') else 'vertex'
            rt = '80,0,0,0,0,0,0,0' if stage == 'fragment' else '-'
            lines.append('\t'.join([f'ca_air/{digest[:12]}-{entry}', p, entry, stage, rt, '-', '-', '-']))
            ca += 1
    ids = [l.split('\t', 1)[0] for l in lines]
    assert len(ids) == len(set(ids)), 'duplicate job ids'
    jobs_path = os.path.join(out, 'jobs.tsv')
    open(jobs_path, 'w').write('\n'.join(lines) + '\n')
    harness = os.path.join(out, 'corpus_compile')
    subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-mmacosx-version-min=27.0', '-std=c11', '-O1', '-I', os.path.join(ROOT, 'src'),
                    os.path.join(ROOT, 'tests', 'corpus_compile.c'), '-o', harness], check=True)
    subprocess.run(['codesign', '-f', '-s', '-', harness], check=True, capture_output=True)
    results, timing = {}, {}
    for name, lib in (('old', args.old), ('new', args.new)):
        t = time.time()
        r = subprocess.run([harness, lib, jobs_path, os.path.join(out, name + '.tsv'), str(args.threads)],
                           capture_output=True, text=True)
        timing[name] = round(time.time() - t, 1)
        open(os.path.join(out, name + '.log'), 'w').write(r.stdout + r.stderr)
        assert r.returncode == 0, (name, r.stderr[-2000:])
        rows = {}
        compiler = None
        for l in open(os.path.join(out, name + '.tsv')):
            if l.startswith('# compiler '):
                compiler = l.split(' ', 2)[2].strip()
                continue
            f = l.rstrip('\n').split('\t')
            rows[f[0]] = f[1:]
        results[name] = dict(compiler=compiler, rows=rows)
    old, new = results['old']['rows'], results['new']['rows']
    # A refusal names the first unset function constant it meets; which one is not stable from run to run
    # (the same library differs from itself), so such refusals compare by class. Every other field is exact.
    unset = re.compile(r'unset function constant \S+ \(index \d+\) decides a branch.*')
    def norm(row):
        if row is None or row[0] == '0':
            return row
        return row[:-1] + [unset.sub('unset function constant <c> decides a branch', row[-1])]
    differences = [dict(id=k, old=old.get(k), new=new.get(k)) for k in sorted(set(old) | set(new)) if norm(old.get(k)) != norm(new.get(k))]
    normalized = sum(1 for k in set(old) & set(new) if old[k] != new[k] and norm(old[k]) == norm(new[k]))
    compiled = sum(1 for v in old.values() if v[0] == '0')
    report = dict(status='COMPILER_OUTPUTS_IDENTICAL' if not differences else 'COMPILER_OUTPUTS_DIFFER',
                  old=dict(path=args.old, sha256=sha(args.old), compiler_id=results['old']['compiler']),
                  new=dict(path=args.new, sha256=sha(args.new), compiler_id=results['new']['compiler']),
                  jobs=len(lines), results=len(old), compiled=compiled, not_compiled=len(old) - compiled,
                  safe_constlen_variants=sum(1 for k in old if k.endswith('/safe')), ca_air_jobs=ca,
                  skipped_groups=skipped, differences=differences[:200], difference_count=len(differences),
                  refusals_equal_by_class=normalized,
                  wall_seconds=timing, jobs_sha256=sha(jobs_path), source_sha256=sha(os.path.abspath(__file__)),
                  harness_source_sha256=sha(os.path.join(ROOT, 'tests', 'corpus_compile.c')))
    open(os.path.join(out, 'report.json'), 'w').write(json.dumps(report, indent=1) + '\n')
    print(json.dumps({k: report[k] for k in ('status', 'jobs', 'results', 'compiled', 'not_compiled', 'safe_constlen_variants',
                                              'ca_air_jobs', 'difference_count', 'refusals_equal_by_class', 'wall_seconds',
                                              'skipped_groups')}))


if __name__ == '__main__':
    main()
