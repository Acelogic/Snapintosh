# SPDX-License-Identifier: MIT
"""A stop whose required audit correctly refused it: recorded as evidence, never qualified.

Generation78's monitor failed (SWITCH_ROOT refused: its shared-region group records ran
out), and the runtime root's own audit then refused the stop ("native shared counters
disagree"). The refusal is the finding: nothing is relaxed or replaced. The standard
capture can never complete such a stop, while preservation and retirement need a
complete one. `capture --unqualified --evidence FILE[@COMMIT] ...` records instead:

- the refused audit: the recorded attempt that ran the runtime root's audit on this
  stop and exited nonzero (its source and step logs by hash, and the log's last line),
  with no audit output present;
- the boot log's terminal event (the launcher's "last event" line and its exit verdict);
- each evidence file by hash (FILE@COMMIT must be exactly that commit's file);
- a read-only witness of the stopped A16: generation, EL and image base, zero SError
  before and after, and the monitor's parked service words, read twice and equal.

`preserve --unqualified` preserves the run with `qualified: false` and the witness's
service words where an audit's would be, and `retire` verifies the live stop against
them. The record is re-verified on every read. A launch refuses a baseline that was
recorded unqualified.
"""
import re
import struct

from .common import (PARKED_SERVICE_WORD, need, sha, matches, read, write_new, rewrite, serror_clear,
                     context_layout, load_proxy, load_module, require_exclusive, now)

KIND = 'unqualified'
STATUS = 'UNQUALIFIED_STOP_RECORDED'


def refused_audit(run, report):
    """The newest recorded audit attempt on this stop that exited nonzero."""
    need(not report['audit'], 'the audit qualified this stop: capture it normally')
    step = next(s for s in report['steps'] if s['name'] == 'audit')
    need(step['state'] == 'retry' and not step['outputs'], f'the audit step is {step["state"]}, not a refusal')
    tries = [t for t in step['attempts'] if t['exit_code'] and t['log']]
    need(tries, 'no recorded audit attempt with its own log exited nonzero')
    attempt = tries[-1]
    log, source = run.ws.local(attempt['log']), run.ws.local(attempt['source'])
    need(log.is_file() and source.is_file(), 'the refused audit\'s logs are missing')
    lines = [line.strip() for line in log.read_text(errors='replace').splitlines() if line.strip()]
    need(lines, f'{log.name} is empty')
    return dict(step='audit', exit_code=attempt['exit_code'], log=str(log), log_sha256=sha(log),
                source=str(source), source_sha256=sha(source), refusal=lines[-1])


def boot_terminal(run):
    """The launcher log's terminal event and exit verdict, which must name this exit."""
    log = run.path('-boot.log')
    need(log.is_file(), f'{log.name} (the launcher output) is missing')
    lines = [line.strip() for line in log.read_text(errors='replace').splitlines()]
    marks = [i for i, line in enumerate(lines) if line.startswith('last event (outside the log')]
    verdicts = [i for i, line in enumerate(lines) if re.fullmatch(r'== .+ \(exit (\d+)\) ==', line)]
    need(len(marks) == 1 and len(verdicts) == 1 and marks[0] < verdicts[0] and verdicts[0] + 1 < len(lines),
         f'{log.name} has no single terminal event and exit verdict')
    verdict = lines[verdicts[0]]
    need(int(re.fullmatch(r'== .+ \(exit (\d+)\) ==', verdict)[1]) == run.exit_code,
         f'{log.name} ends with another exit than the launch record\'s {run.exit_code}')
    return dict(boot_log=str(log), boot_log_sha256=sha(log), last_event=lines[marks[0] + 1], verdict=verdict,
                detail=lines[verdicts[0] + 1])


def evidence_files(ws, specs):
    """[{path, sha256[, commit]}] for FILE or FILE@COMMIT (exactly that commit's file)."""
    from pathlib import Path
    from .evidence import _committed
    out = []
    for spec in specs:
        path, commit = (spec.rsplit('@', 1) + [None])[:2] if '@' in spec else (spec, None)
        file = Path(path).resolve()
        need(file.is_file(), f'evidence {file} is missing')
        entry = dict(path=str(file), sha256=sha(file))
        if commit:
            need(_committed(file, commit, entry['sha256']), f'evidence {file} is not the committed {commit[:12]}')
            entry['commit'] = commit
        out.append(entry)
    need(out, 'an unqualified stop needs --evidence (the diagnosis of the refusal)')
    need(len({e['path'] for e in out}) == len(out), 'evidence named twice')
    return out


def witness(ws, run):
    """Read-only: the stopped A16 is this run's generation, parked, without SError."""
    q = load_proxy(ws)
    proxy = q.connect(ws.device)
    try:
        info = proxy.bootinfo()
        need(info['current_el'] == 2 and info['stage_generation'] == run.generation and
             info['image_base'] == run.image_base,
             f'A16 is at generation {info["stage_generation"]}/EL{info["current_el"]}/{info["image_base"]:#x}, '
             f'expected {run.generation}/EL2/{run.image_base:#x}')
        before = proxy.serror_state()
        need(serror_clear(before), 'SError before the witness read')
        layout, _ = context_layout(run.runtime)
        need(layout.size('context') == run.launch['context_bytes'], 'context layout changed')
        work_module = load_module('cycle_monitor_work', run.runtime / 'probes/monitor_work.py')
        work, size = work_module.resident_work(proxy, info)
        at = work + layout.offset('context', 'services')
        raw = proxy.readmem(at, 64, live=True)
        need(proxy.readmem(at, 64, live=True) == raw, 'service words changed between two reads')
        service = list(struct.unpack('<8Q', raw))
        need(service[2] == PARKED_SERVICE_WORD, 'the monitor\'s service word is not a parked stop')
        after = proxy.serror_state()
        need(serror_clear(after), 'SError after the witness read')
    finally:
        proxy.link.close()
    return dict(bootinfo=info, work=work, bytes=size, service=service, service_hex=raw.hex(),
                serror_before=before, serror_after=after)


def record(ws, prefix, evidence, capture_set=None, check=False):
    """capture --unqualified: the refusal, terminal event and evidence, then the witness."""
    from .capture import attempt_name
    from .evidence import Run, assess
    run = Run(ws, prefix)
    report = assess(run, capture_set)
    need(not recorded(ws, prefix), f'{prefix} already has a recorded unqualified stop')
    rec = dict(status='RUNNING', kind=KIND, qualified=False, prefix=prefix, generation=run.generation,
               exit_code=run.exit_code, launch_sha256=run.launch_sha256, tool_sha256=ws.tool_sources(),
               refusal=refused_audit(run, report), terminal=boot_terminal(run),
               evidence=evidence_files(ws, evidence), steps=[])
    attempt = attempt_name(ws, prefix)
    path = run.path(f'-cycle-capture-{attempt[len("cycle-"):]}.json')
    if check:
        return dict(rec, status='UNQUALIFIED_PLAN', hardware_access=False, record=str(path))
    require_exclusive(ws)
    rec.update(started=now(), attempt=attempt)
    write_new(path, rec)
    try:
        rec['witness'] = witness(ws, run)
        rec['status'] = STATUS
    except BaseException as error:
        rec.update(status='FAILED', error=repr(error))
        raise
    finally:
        rec['finished'] = now()
        rewrite(path, rec)
    return dict(status=rec['status'], record=str(path), sha256=sha(path))


def recorded(ws, prefix):
    """The newest recorded unqualified-stop capture record of this run, or None."""
    found = None
    for path in sorted(ws.build.glob(f'{prefix}-cycle-capture-v*.json'),
                       key=lambda p: int(p.name[len(prefix) + len('-cycle-capture-v'):-5])):
        rec = read(path)
        if rec.get('kind') == KIND and rec.get('status') == STATUS:
            found = (path, rec)
    return found


def validate(ws, run, report):
    """The run's unqualified-stop record, re-verified against the files and the report."""
    found = recorded(ws, run.prefix)
    need(found, f'{run.prefix} has no recorded unqualified stop; run: python3 tools/cycle.py capture '
                f'--prefix {run.prefix} --unqualified --evidence FILE')
    path, rec = found
    what = path.name
    need(rec['launch_sha256'] == run.launch_sha256 and rec['qualified'] is False, f'{what} is for another launch')
    need(not report['complete'] and not report['audit'], f'{run.prefix} has a qualified capture since {what}')
    refusal = refused_audit(run, report)
    need(refusal == rec['refusal'], f'{what}: the refused audit attempt or its logs changed since')
    need(boot_terminal(run) == rec['terminal'], f'{what}: the boot log changed since')
    from .evidence import _committed
    for entry in rec['evidence']:
        file = ws.local(entry['path'])
        need(matches(file, entry['sha256']), f'{what}: evidence {file} changed since')
        need(not entry.get('commit') or _committed(file, entry['commit'], entry['sha256']),
             f'{what}: evidence {file} is not the committed {entry.get("commit", "")[:12]}')
    service = rec['witness']['service']
    need(len(service) == 8 and service[2] == PARKED_SERVICE_WORD, f'{what}: the witness is not a parked stop')
    return dict(rec, record=str(path), record_sha256=sha(path))
