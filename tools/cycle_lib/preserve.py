# SPDX-License-Identifier: MIT
"""Copy a stopped run's evidence aside before the A16 is retired to the next generation.

Re-verified at retirement: the launch's source pins, every build/PREFIX* file, the
monitor/ELF/AuxKC binaries and the diagnosis group (image qualification, launcher,
SSD apply record, the collector programs that actually ran, the pinned observer
bases). Copied but not re-verified: living documents (docs/*.md) and this tool's own
sources. Nothing here contacts the A16.
"""
from pathlib import Path
import shutil

from .common import PINS, STOPPED_EXITS, need, sha, read, write_new, now
from .evidence import Run, assess, programs

REVERIFIED = ('runtime_sources', 'artifacts', 'binaries', 'diagnosis')
# Copied but not re-verified: living documents, this tool's sources, and decoders or
# readers from other checkouts that re-read the stopped A16 (commit and hash recorded),
# with accepted runtime-root readers and the manifest amendment that declared them.
COPIED_ONLY = ('documents', 'tool', 'decoders', 'readers')


def output_dir(ws, prefix):
    return ws.prefixed(prefix, '-preserved-v1')


def pending(report):
    return [f'{s["name"]}:{s["state"]}' for s in report['steps']
            if (s['state'] != 'complete' if s['required'] else s['state'] not in ('complete', 'refused'))]


def validate(ws, prefix, capture_set=None, check_host=True):
    """The run and its capture evidence, or a refusal naming what is missing."""
    run = Run(ws, prefix, check_host)
    report = assess(run, capture_set)
    need(report['complete'], f'capture incomplete ({report["set"]} set): {", ".join(pending(report))}; '
         f'run: python3 tools/cycle.py capture --prefix {prefix}')
    return run, report


def groups(ws, run, report, documents=(), manifest=None):
    """{group: [paths]} to copy. Paths are absolute and local to this workspace."""
    launch = run.launch
    artifacts = sorted(p for p in ws.build.glob(run.prefix + '*') if p.is_file())
    # Step outputs written only in the runtime root (a service-profile redecode that was
    # not copied back yet) are artifacts too.
    names = {p.name for p in artifacts}
    artifacts += sorted(Path(f) for s in report['steps'] for f in s.get('files', []) if Path(f).name not in names)
    diagnosis = [run.image_path]
    if run.launcher:
        diagnosis.append(run.launcher)
    for key in ('ssd_apply_record',):
        if launch.get(key):
            diagnosis.append(ws.local(launch[key]))
    for key in ('monitor_build', 'retirement'):
        if run.deployment.get(key):
            diagnosis.append(ws.local(run.deployment[key]))
    if manifest:
        diagnosis.append(Path(manifest))
    diagnosis += [Path(p) for p in programs(run)]
    diagnosis += [ws.path(PINS['base_launcher']['path'])]
    diagnosis += [ws.path(o['path']) for o in PINS['observers'].values() if 'path' in o]
    in_artifacts = set(map(str, artifacts))
    diagnosis = [p for p in dict.fromkeys(map(Path, diagnosis)) if str(p) not in in_artifacts]
    docs = [ws.docs / 'HANDOFF.md'] + [p for p in sorted(ws.docs.glob('*.md'))
                                         if run.prefix in p.read_text(errors='replace')]
    docs += [Path(d) for d in documents]
    tool = [Path(p) for p in ws.tool_sources()]
    decoders = [Path(s['redecode']['decoder']) for s in report['steps'] if s.get('redecode')]
    readers = [ws.local(b['file']) for b in report.get('substitutions', [])]
    for b in report.get('readers', []):
        readers.append(ws.local(b['runtime_root']) / b['path'])
        if b.get('amendment'):
            readers.append(ws.local(b['amendment']['manifest']))
    readers = list(dict.fromkeys(readers))
    binaries = [run.monitor, run.monitor.with_suffix('.elf'), ws.local(launch['auxkc'])]
    return dict(runtime_sources=[ws.local(n) for n in sorted(launch['source_sha256'])], artifacts=artifacts,
                binaries=binaries, diagnosis=diagnosis,
                documents=[p for p in dict.fromkeys(docs) if p.is_file()], tool=tool, decoders=decoders,
                readers=readers)


def preserve(ws, prefix, check=False, capture_set=None, documents=(), manifest=None, unqualified=False):
    stop = None
    if unqualified:
        # A stop whose audit correctly refused it (unqualified.py): its recorded refusal,
        # terminal event, evidence and witness stand where the complete capture would.
        from . import unqualified as unq
        run = Run(ws, prefix, True)
        report = assess(run, capture_set)
        stop = unq.validate(ws, run, report)
    else:
        run, report = validate(ws, prefix, capture_set)
    out = output_dir(ws, prefix)
    verification = run.path('-pre-reset-verification.json')
    need(not out.exists() and not verification.exists(), f'{out} or {verification.name} already exists (reused output)')
    plan = groups(ws, run, report, documents, manifest)
    if stop:
        # Evidence outside build/PREFIX* is re-verified at retirement with the diagnosis.
        known = {str(p) for group in ('artifacts', 'diagnosis') for p in plan[group]}
        plan['diagnosis'] += [ws.local(e['path']) for e in stop['evidence'] if str(ws.local(e['path'])) not in known]
    for name, paths in plan.items():
        for p in paths:
            need(Path(p).is_file(), f'{name}: {p} is missing')
    counts = {k: len(v) for k, v in plan.items()}
    if check:
        return dict(status='PRESERVATION_INPUTS_VERIFIED', writes=False, **run.summary(), capture_set=report['set'],
                    steps={s['name']: s['state'] for s in report['steps']}, groups=counts, output=str(out),
                    qualified=not stop)
    out.mkdir()

    def save_group(paths, kind):
        folder = out / kind
        folder.mkdir()
        saved = {}
        for i, raw in enumerate(paths):
            p = Path(raw)
            digest = sha(p)
            dest = folder / f'{i:04d}-{p.name}'
            shutil.copy2(p, dest)
            need(sha(dest) == sha(p) == digest, f'copy of {p} differs')
            saved[str(p)] = dict(copy=str(dest), sha256=digest)
        return saved

    audit = report['audit'] or {}
    if stop:
        service = stop['witness']['service']
        audit = dict(service=service, owner=(service[1] & 0xffffffff) - 1, sha256=None)
    record = dict(status=f'GEN{run.generation}_{"UNQUALIFIED_STOP" if stop else "STOPPED_EVIDENCE"}_PRESERVED',
                  schema='snapintosh-cycle-preservation-v1', qualified=not stop,
                  unqualified=stop and {k: stop[k] for k in ('record', 'record_sha256', 'refusal', 'terminal',
                                                             'evidence', 'witness')},
                  generation=run.generation, prefix=prefix, created=now(),
                  source_sha256=sha(Path(__file__)), tool_sha256=ws.tool_sources(),
                  launch_sha256=run.launch_sha256, original_host_exit_available=True,
                  exit_code=run.exit_code, stop=STOPPED_EXITS[run.exit_code], finished=run.launch['finished'],
                  monitor_sha256=run.launch['monitor_sha256'], image_base=run.image_base,
                  service=audit['service'], owner_cpu=audit['owner'], audit_sha256=audit['sha256'],
                  capture=dict(set=report['set'], steps={s['name']: dict(state=s['state'], required=s['required'],
                               exit_codes=[a['exit_code'] for a in s['attempts']], outputs=s['outputs'],
                               **({'redecode': s['redecode']} if s.get('redecode') else {}))
                               for s in report['steps']}, sources=report['sources'],
                               substitutions=report.get('substitutions', []), readers=report.get('readers', [])),
                  early_stop=run.early_stop and dict(path=run.early_stop['path'], sha256=run.early_stop['sha256']),
                  **{kind: save_group(paths, kind) for kind, paths in plan.items()},
                  artifacts_sha256={p.name[len(prefix):]: sha(p) for p in plan['artifacts']},
                  reverified_groups=list(REVERIFIED), copied_only_groups=list(COPIED_ONLY),
                  boundary='Saved stopped evidence; documents and tool sources are copied but not re-verified at '
                           'retirement; not a complete physical RAM image or desktop proof')
    for target in (out / 'preservation.json', verification):
        write_new(target, record)
    return dict(status=record['status'], generation=run.generation, exit_code=run.exit_code, groups=counts,
                output=str(out / 'preservation.json'), sha256=sha(out / 'preservation.json'))


def verify_saved(ws, prefix, preservation_sha256):
    """The preservation record, re-verified: every re-verified file still matches its
    copy and recorded hash; copied-only files match their copies."""
    path = output_dir(ws, prefix) / 'preservation.json'
    need(path.is_file(), f'{path} does not exist; run: python3 tools/cycle.py preserve --prefix {prefix}')
    need(sha(path) == preservation_sha256 == sha(ws.prefixed(prefix, '-pre-reset-verification.json')),
         'preservation hash differs from --preservation-sha256 or from -pre-reset-verification.json')
    saved = read(path)
    need(saved.get('schema') == 'snapintosh-cycle-preservation-v1' and saved['prefix'] == prefix, 'not a cycle preservation')
    for group in REVERIFIED:
        for name, entry in saved[group].items():
            need(sha(ws.local(name)) == sha(ws.local(entry['copy'])) == entry['sha256'], f'{group}: {name} changed')
    for group in COPIED_ONLY:
        for name, entry in saved.get(group, {}).items():
            need(sha(ws.local(entry['copy'])) == entry['sha256'], f'{group}: preserved copy of {name} changed')
    return saved
