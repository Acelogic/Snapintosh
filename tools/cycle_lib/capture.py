# SPDX-License-Identifier: MIT
"""Run the stopped-state steps a finished launch still needs, and nothing it already has.

Standard set (exits 7, 9, 12): when nothing has run yet, the whole rendered standard
collector runs as one step, then the two native observers; all required. Early-boot
set (exit 6), or any set continued after a partial run: the steps run one by one with
the collector's own arguments, required steps first. A step already complete is
never re-run. A recorded-only step that failed on a qualified stop is final; any other
failed step runs again with new log names. --check prints the plan; no hardware.
"""
from pathlib import Path
import json
import os
import shutil
import subprocess
import sys

from .common import PINS, need, sha, matches, read, write_new, rewrite, require_exclusive, hardware_clients, now
from .evidence import Run, assess, SETS, OBSERVERS
from . import observers, substitute

COLLECTOR_STEPS = ('audit', 'cpu-stop', 'service-profile', 'kernel-waits', 'verdict', 'panel', 'mounts',
                   'metal-probe', 'console-tail', 'ring')
RUNTIME_STEPS = ('audit', 'cpu-stop', 'service-profile', 'kernel-waits', 'mounts', 'metal-probe', 'console-tail')


def attempt_name(ws, prefix):
    taken = [int(p.name[len(prefix) + len('-cycle-capture-v'):-5]) for p in ws.build.glob(f'{prefix}-cycle-capture-v*.json')]
    return f'cycle-v{max(taken, default=0) + 1}'


def manifest_for(ws, path):
    if not path:
        return None
    from .launch import Manifest
    return Manifest(ws, path)


def preflight_plan(ws, run):
    """What collect-metal-gui copies into the runtime root before its first read
    (the launch record, the launcher's log and three historical inputs), checked."""
    helper = ws.build / Path(PINS['observers']['helper']['runtime_path']).name
    need(matches(helper, PINS['observers']['helper']['sha256']), f'{helper} changed')
    need(matches(run.runtime / PINS['observers']['helper']['runtime_path'], PINS['observers']['helper']['sha256']),
         'runtime root stopped-read helper changed')
    historical = observers.gui_historical(ws)
    for name, digest in historical.items():
        need(matches(ws.build / name, digest), f'historical input {name} changed')
    boot_log = run.path('-boot.log')
    need(boot_log.is_file(), f'{boot_log.name} (the launcher output) is missing')
    for name, digest in run.launch['runtime_artifacts_copied_sha256'].items():
        need(matches(ws.local(name), digest) and matches(ws.build / Path(name).name, digest),
             f'runtime artifact {Path(name).name} differs from the launcher copy')
    copies = []
    for p in (helper, run.launch_path, boot_log, *(ws.build / name for name in historical)):
        target = run.runtime / 'build' / p.name
        if target.exists():
            need(sha(target) == sha(p), f'{target} differs from {p}')
        else:
            copies.append((p, target))
    canonical = run.runtime_path('.log')
    if canonical.exists():
        need(sha(canonical) == sha(boot_log), f'{canonical} differs from the launcher log')
    else:
        copies.append((boot_log, canonical))
    return copies


def copy_back(run):
    for p in sorted((run.runtime / 'build').glob(run.prefix + '*')):
        if not p.is_file():
            continue
        target = run.ws.build / p.name
        if target.exists():
            need(sha(target) == sha(p), f'{target} differs from its runtime copy')
        else:
            shutil.copy2(p, target)
            need(sha(target) == sha(p), f'copy of {p.name} differs')


def plan(ws, prefix, capture_set=None, manifest_path=None, only=None, replace=None):
    """The steps still to run; with `only`, exactly that one step of the set, which must
    be missing (or have failed), and nothing else is run or re-run. With `replace`
    (PATH=FILE@COMMIT, substitute.py), the steps that run PATH run FILE instead."""
    run = Run(ws, prefix)
    substitution = substitute.binding(ws, run, replace) if replace else None
    manifest = manifest_for(ws, manifest_path)
    if manifest:
        need(manifest.prefix == prefix, f'{manifest_path} is for {manifest.prefix}, not {prefix}')
    report = assess(run, capture_set)
    if only:
        chosen = [s for s in report['steps'] if s['name'] == only]
        need(chosen, f'{only} is not a step of the {report["set"]} set: {[s["name"] for s in report["steps"]]}')
        need(chosen[0]['state'] in ('missing', 'retry'),
             f'{only} is {chosen[0]["state"]}; --step runs only a step that is missing or failed')
        todo = chosen
    else:
        blocked = [s['name'] for s in report['steps'] if s['state'] == 'unrecorded']
        need(not blocked, f'outputs exist without a recorded successful run: {blocked}; inspect before capturing')
        todo = [s for s in report['steps'] if s['state'] in ('missing', 'retry')]
    observing = any(s['name'] in OBSERVERS for s in todo)
    display = observers.display_binding(ws, run, manifest) if observing else None
    # Runtime-root readers the candidate declares in place of the observers' pinned ones.
    readers = substitute.accepted(ws, run, manifest) if observing else []
    need(not (substitution and substitution['path'] in {b['path'] for b in readers}),
         f'{substitution and substitution["path"]} is both replaced and accepted')
    params = observers.Params(run, display, readers)
    calls = observers.collector_steps(ws, run, params)
    fresh = not only and report['set'] == 'standard' and all(
        s['state'] == 'missing' for s in report['steps'] if s['name'] in COLLECTOR_STEPS)
    need(not (substitution and fresh), 'a substitution continues a capture; run the standard collector first')
    attempt = attempt_name(ws, prefix)
    steps = []
    candidate = ['--candidate', str(manifest.path)] if manifest else []
    tool = [sys.executable, str(ws.tool)]
    for s in todo:
        name = s['name']
        if fresh and name in COLLECTOR_STEPS:
            if name == 'audit':
                steps.append(dict(name='primary', required=True, covers=list(COLLECTOR_STEPS), cwd=str(ws.root),
                                  command=[*tool, 'observe', 'collector', '--launch', prefix, '--', '--prefix', prefix],
                                  log=str(run.path(f'-primary-{attempt}.log'))))
            continue
        if name in RUNTIME_STEPS:
            script, arguments = calls[name]
            steps.append(dict(name=name, required=s['required'], cwd=str(run.runtime), script=script,
                              arguments=arguments, log=str(run.runtime_path(f'-{name}-{attempt}.log'))))
            if substitution and script == substitution['path']:
                need(name in substitute.RUNTIME_STEPS, f'{name} runs {script}; not a known reader step')
                steps[-1]['substituted'] = True
        elif name == 'panel':
            steps.append(dict(name=name, required=s['required'], cwd=str(run.runtime),
                              command=[PINS['panel_python'], 'tools/capture-panel.py', f'build/{prefix}-panel.png',
                                       '--device', ws.device, '--block-bytes', '65536', '--reconnects', '0'],
                              log=str(run.runtime_path(f'-panel-{attempt}.log'))))
        elif name == 'verdict':
            steps.append(dict(name=name, required=s['required'], cwd=str(run.runtime),
                              command=[sys.executable, '-B', 'tools/auxkc-verdict.py', '--prefix', prefix],
                              log=str(run.runtime_path(f'-verdict-{attempt}.log'))))
        elif name == 'ring':
            steps.append(dict(name=name, required=s['required'], cwd=str(ws.root),
                              command=[*tool, 'observe', 'ring', '--launch', prefix, '--', '--prefix', prefix,
                                       '--device', ws.device], log=str(run.path(f'-ring-{attempt}.log'))))
        else:
            kind = 'native' if name == 'native-startup' else 'crash'
            # The native observers compile the runtime root's kernel-waits reader.
            reader = bool(substitution) and substitution['path'] == 'tools/capture-kernel-waits.py'
            replaced = ['--replace', substitution['spec']] if reader else []
            steps.append(dict(name=name, required=s['required'], cwd=str(ws.root),
                              command=[*tool, 'observe', kind, '--launch', prefix, *candidate, *replaced,
                                       '--', '--attempt', attempt],
                              log=str(run.path(f'-{name}-{attempt}.log')), substituted=reader))
    if report['set'] == 'early-boot' or not fresh:
        order = SETS[report['set']][0]
        steps.sort(key=lambda step: (not step['required'], order.index(step['name'])))
    copies = preflight_plan(ws, run) if any(st['cwd'] == str(run.runtime) for st in steps) else []
    if substitution:
        need(any(st.get('substituted') for st in steps), f'no remaining step runs {substitution["path"]}')
    return dict(run=run, report=report, params=params, steps=steps, attempt=attempt, copies=copies,
                record=run.path(f'-cycle-capture-{attempt[len("cycle-"):]}.json'), manifest=manifest,
                substitution=substitution, readers=readers)


def describe(p):
    run = p['run']
    return dict(status='CAPTURE_PLAN', hardware_access=False, **run.summary(), capture_set=p['report']['set'],
                states={s['name']: s['state'] for s in p['report']['steps']}, attempt=p['attempt'],
                record=str(p['record']), preflight_copies=[str(t) for _, t in p['copies']],
                substitution=p.get('substitution'), readers=p.get('readers'),
                steps=[dict(name=s['name'], required=s['required'], cwd=s['cwd'], log=s['log'],
                            substituted=bool(s.get('substituted')),
                            command=s.get('command') or [*(['<python>', str(run.ws.tool), 'substituted', '--launch',
                                                            run.prefix, '--replace', p['substitution']['spec'], '--']
                                                           if s.get('substituted') else ['<python>']),
                                                         PINS['observers']['helper']['runtime_path'],
                                                         s['script'], '--device', run.ws.device, '--prefix',
                                                         run.prefix, *(s['arguments'] or ['--cpu', '<owner>'])])
                       for s in p['steps']],
                observers=observers.rendered(run.ws, p['params']),
                hardware_clients=hardware_clients(run.ws),
                complete=p['report']['complete'])


def execute(ws, p, runner=None):
    """Run the planned steps. `runner(command, cwd, env, log_path) -> exit code` runs one
    step; the default runs it as a subprocess with its output in the step log."""
    run = p['run']
    runner = runner or default_runner
    require_exclusive(ws)
    env = dict(os.environ, SNAP_STOPPED_EXIT=str(run.exit_code), SNAP_DEVICE=ws.device)
    record = dict(status='RUNNING', started=now(), prefix=run.prefix, generation=run.generation, exit_code=run.exit_code,
                  attempt=p['attempt'], capture_set=p['report']['set'], launch_sha256=run.launch_sha256,
                  tool_sha256=ws.tool_sources(), firmware=str(run.firmware.resolve()),
                  observers=observers.rendered(ws, p['params']), early_stop=run.summary()['early_stop'],
                  before={s['name']: s['state'] for s in p['report']['steps']}, preflight=[], steps=[])
    if p.get('substitution'):
        record['substitution'] = p['substitution']
    if p.get('readers'):
        record['readers'] = p['readers']
    write_new(p['record'], record)
    try:
        for source, target in p['copies']:
            with source.open('rb') as src, target.open('xb') as dst:
                shutil.copyfileobj(src, dst)
            need(sha(target) == sha(source), f'preflight copy {target.name} differs')
            record['preflight'].append(dict(source=str(source), target=str(target), sha256=sha(target)))
        rewrite(p['record'], record)
        owner = None
        audit_path = run.path('-audit.json')
        for step in p['steps']:
            if step['name'] == 'cpu-stop':
                if owner is None:
                    copy_back(run)
                    audit = read(audit_path)
                    owner = (audit['service'][1] & 0xffffffff) - 1
                    need(0 <= owner < 6, f'owner CPU {owner} out of range')
                name = f'cpu{owner}-stop'
                log = str(run.runtime_path(f'-{name}-{p["attempt"]}.log'))
                command = [sys.executable, PINS['observers']['helper']['runtime_path'], step['script'],
                           '--device', ws.device, '--prefix', run.prefix, '--cpu', str(owner)]
            elif 'script' in step:
                name, log = step['name'], step['log']
                command = [sys.executable, PINS['observers']['helper']['runtime_path'], step['script'],
                           '--device', ws.device, '--prefix', run.prefix, *step['arguments']]
                if step.get('substituted'):
                    command = [sys.executable, str(ws.tool), 'substituted', '--launch', run.prefix,
                               '--replace', p['substitution']['spec'], '--', *command[1:]]
            else:
                name, log, command = step['name'], step['log'], step['command']
            if step['name'] in ('ring', 'native-startup', 'crash-retention'):
                copy_back(run)
            entry = dict(name=name, required=step['required'], command=command, cwd=step['cwd'], log=log, started=now())
            if step.get('substituted'):
                entry['substituted'] = p['substitution']['path']
            record['steps'].append(entry)
            rewrite(p['record'], record)
            entry['exit_code'] = runner(command, step['cwd'], env, Path(log))
            entry['finished'] = now()
            entry['log_sha256'] = sha(log)
            rewrite(p['record'], record)
            print(name, 'exit', entry['exit_code'], flush=True)
            if step['required'] and entry['exit_code']:
                raise SystemExit(f'{name} failed with {entry["exit_code"]}; later steps were not run')
            if name == 'audit':
                copy_back(run)
                audit = read(audit_path)
                need(audit['runtime_stop_qualified'] and audit['user_mapping_qualified'],
                     'the audit did not qualify the native stop; later steps were not run')
                need(audit['monitor_sha256'] == run.launch['monitor_sha256'], 'the audit read another monitor')
        copy_back(run)
        final = assess(run, p['report']['set'])
        record['after'] = {s['name']: s['state'] for s in final['steps']}
        record['status'] = 'STOPPED_STATE_CAPTURED' if final['complete'] else 'INCOMPLETE'
    except BaseException as error:
        record.update(status='FAILED', error=repr(error))
        raise
    finally:
        try:
            copy_back(run)
        finally:
            record['finished'] = now()
            record['outputs_sha256'] = {p_.name[len(run.prefix):]: sha(p_) for p_ in sorted(ws.build.glob(run.prefix + '-*'))
                                        if p_.is_file() and p_.suffix in ('.json', '.png', '.bin')
                                        and p_ != p['record']}
            rewrite(p['record'], record)
    return dict(status=record['status'], record=str(p['record']), sha256=sha(p['record']), after=record['after'])


def default_runner(command, cwd, env, log):
    with log.open('x') as stream:
        return subprocess.run(command, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT).returncode


def main(ws, args):
    if getattr(args, 'unqualified', False):
        # A stop whose audit correctly refused it: evidence only (unqualified.py).
        from . import unqualified
        need(not args.step and not args.replace, '--unqualified runs no collector step and replaces nothing')
        result = unqualified.record(ws, args.prefix, args.evidence, args.capture_set, args.check)
        print(json.dumps(result, indent=2), flush=True)
        return 0 if result['status'] in (unqualified.STATUS, 'UNQUALIFIED_PLAN') else 1
    need(not getattr(args, 'evidence', None), '--evidence belongs to --unqualified')
    p = plan(ws, args.prefix, args.capture_set, args.candidate, getattr(args, 'step', None),
             getattr(args, 'replace', None))
    if args.check:
        print(json.dumps(describe(p), indent=2), flush=True)
        return 0
    if not p['steps']:
        print(json.dumps(dict(status='ALREADY_CAPTURED' if p['report']['complete'] else 'NOTHING_TO_RUN',
                              states={s['name']: s['state'] for s in p['report']['steps']})), flush=True)
        return 0 if p['report']['complete'] else 1
    result = execute(ws, p)
    print(json.dumps(result), flush=True)
    return 0 if result['status'] == 'STOPPED_STATE_CAPTURED' else 1
