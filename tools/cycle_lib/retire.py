# SPDX-License-Identifier: MIT
"""Move the A16 from a finished generation N to an idle generation N+1.

Stopped run (default): re-verify the preservation and the run's evidence, verify the
native stop (the parked service words equal the preserved audit's), quiesce the GPU
that the run's preparation initialised (a16gpu quiesce --write must report graceful),
chainload the other stage slot and confirm generation N+1 idle with zero SError.

Idle generation (--idle): no guest ran. If this generation's GPU preparation ran, it
is quiesced as above; otherwise the graceful quiescence recorded by the retirement
that produced this generation is inherited (a quiesce on a GMU already held in reset
never reports graceful).

Loader failure (--loader-failure): the launcher prepared the GPU, then its loader
refused before the image upload, so no P_CALL entered the monitor and no guest ran.
That is proved from the pinned run.py (every loader-failure return precedes the
upload and the call) and from the boot log and records (exactly one LOADER FAILURE
verdict, nothing run.py prints or writes at or after the upload). The launch record,
boot log, GPU preparation and adoption records and the SSD apply record are bound by
hash; the GPU is quiesced gracefully because the preparation initialised it.
Never interrupt an in-flight P_CALL. No SSD writes.
"""
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import time

from .common import (PARKED_SERVICE_WORD, need, sha, read, write_new, rewrite, image_base, alternate,
                     serror_clear, context_layout, gpu_steps, stage_pair, primary_stage, require_exclusive,
                     hardware_clients, host_absent, load_proxy, load_module, now)
from . import preserve


def gpu_records(ws, prefix):
    """{step: path} of the base launcher's GPU preparation records for this prefix."""
    return {step: ws.q / 'build/a16-gpu' / f'{prefix}-{step}.json' for step in gpu_steps(ws)}


def gpu_initialised(ws, prefix):
    """True when every preparation step ran without a stop; False when none ran."""
    records = gpu_records(ws, prefix)
    present = {s: p for s, p in records.items() if p.is_file()}
    need(len(present) in (0, len(records)), f'partial GPU preparation for {prefix}: {sorted(present)} only')
    for step, path in present.items():
        need(read(path).get('stopped') is None, f'GPU preparation step {step} stopped')
    return bool(present), {str(p): sha(p) for p in present.values()}


def quiesce_record(ws, retirement_path, record):
    """(path, record) of the graceful quiescence a retirement record binds, following
    inherited bindings back to the quiesce that actually ran."""
    if record.get('quiesce_sha256'):
        path = ws.local(record['quiesce']) if record.get('quiesce') else \
            Path(str(retirement_path).replace('-retirement-v1.json', '-quiesce-v1.json'))
        need(path.is_file() and sha(path) == record['quiesce_sha256'], f'{path} does not match its retirement')
    else:
        need(record.get('inherited_quiesce') and record.get('inherited_quiesce_sha256'),
             f'{retirement_path.name} binds no quiescence record by path')
        path = ws.local(record['inherited_quiesce'])
        need(path.is_file() and sha(path) == record['inherited_quiesce_sha256'], f'{path} does not match its retirement')
    quiet = read(path)
    need(quiet.get('quiesce') == 'graceful' and not quiet.get('stopped'), f'{path.name}: quiescence was not graceful')
    need(serror_clear(quiet['serror_guard']['after']), f'{path.name}: SError after quiescence')
    return path, quiet


# Launcher exits that happen before any P_CALL into the monitor (run.py EXIT_LOADER:
# "the host could not build or place the image"). Exits 3 (guest preparation failed)
# and 5 (never entered) are not here: the monitor was called for them.
PRE_GUEST_EXITS = {2: 'LOADER FAILURE'}
# What run.py prints at or after the image upload, and the records it writes just
# before or after the P_CALL. A pre-guest retirement requires every one to be absent.
GUEST_MARKERS = ('  uploaded in ', '  stage 2  ', 'q1n1 status drawing paused', 'virtual RTC seeded from host UTC',
                 'physical secondary result', '  virtual ANS2: ', 'framebuffer during guest execution')
GUEST_RECORDS = ('-rtc-seed.json', '-early-stop-launch.json', '-early-stop.json', '-result.json', '-ans.json')
UPLOAD_PRINT = "print(f'  uploaded in "
MONITOR_CALL = 'proxy.call(code, out, work, work_size'


def loader_failure(ws, prefix):
    """Proof that this launch prepared the GPU and then stopped in the loader, before
    the image upload and the P_CALL: no guest ran. Returns the evidence."""
    launch_path = ws.prefixed(prefix, '-launch.json')
    need(launch_path.is_file(), f'{launch_path} does not exist')
    launch = read(launch_path)
    ws.adopt_origin(launch.get('hardware_owner', str(ws.root)))
    need(launch.get('finished') and launch['finished'] > launch.get('started', 0), 'the launcher has not finished')
    code = launch.get('exit_code')
    need(code in PRE_GUEST_EXITS, f'exit {code} is not a pre-guest loader exit {sorted(PRE_GUEST_EXITS)}')
    need(not launch.get('exception'), f'the launcher raised {launch.get("exception")}: not a clean loader verdict')
    host_absent(ws, launch)
    generation = launch['adreno_record']['stage_generation']
    runtime = ws.local(launch['runtime_root'])
    # The launched run.py returns every loader failure before the upload and the call.
    run_py = runtime / 'probes/run.py'
    pinned = launch['source_sha256'].get(str(run_py)) or next(
        (d for n, d in launch['source_sha256'].items() if ws.local(n) == run_py), None)
    need(pinned and sha(run_py) == pinned, f'{run_py} is not the version this launch ran')
    lines = run_py.read_text().splitlines()
    loader = [i for i, line in enumerate(lines) if 'verdict(EXIT_LOADER' in line]
    upload = [i for i, line in enumerate(lines) if UPLOAD_PRINT in line]
    call = [i for i, line in enumerate(lines) if MONITOR_CALL in line]
    need(loader and len(upload) == 1 and len(call) == 1 and max(loader) < upload[0] < call[0],
         'the launched run.py can report a loader failure at or after the upload or the monitor call')
    for marker in GUEST_MARKERS:   # printed text; print() adds the space after a trailing colon
        need(any(marker.rstrip() in line for line in lines[upload[0]:]), f'run.py no longer prints {marker!r} after the upload')
    # The boot log: exactly one verdict, the loader failure, and nothing from the upload on.
    boot_log = ws.prefixed(prefix, '-boot.log')
    need(boot_log.is_file(), f'{boot_log.name} (the launcher output) is missing')
    text = boot_log.read_text(errors='replace')
    verdicts = [(i, line.strip()) for i, line in enumerate(text.splitlines()) if re.fullmatch(r'== .+ \(exit \d+\) ==', line.strip())]
    expected = f'== {PRE_GUEST_EXITS[code]} (exit {code}) =='
    need([v for _, v in verdicts] == [expected], f'boot log verdicts {[v for _, v in verdicts]}, expected only {expected!r}')
    reason = text.splitlines()[verdicts[0][0] + 1].strip() if len(text.splitlines()) > verdicts[0][0] + 1 else ''
    found = [m for m in GUEST_MARKERS if m in text]
    need(not found, f'the boot log shows the upload or the guest run: {found}')
    for suffix in GUEST_RECORDS:
        for where in (ws.build, runtime / 'build'):
            need(not (where / (prefix + suffix)).exists(), f'{prefix + suffix} exists: the run reached the monitor call')
    initialised, gpu = gpu_initialised(ws, prefix)
    need(initialised, f'{prefix} has no GPU preparation records: retire it with --idle')
    adopt = ws.prefixed(prefix, '-adopt.json')
    need(adopt.is_file() and sha(adopt) == launch['adreno_record_sha256'], 'GPU adoption record changed')
    retirement = (launch.get('compiler_deployment') or {}).get('retirement')
    if retirement and ws.local(retirement).is_file():
        after = read(ws.local(retirement)).get('after', {})
        need(after.get('stage_generation') == generation and after.get('image_base') == image_base(generation),
             f'the retirement before this launch left generation {after.get("stage_generation")}, not {generation}')
    bound = {str(p): sha(p) for p in sorted(ws.build.glob(prefix + '*')) if p.is_file()}
    for step_record in gpu_records(ws, prefix).values():
        for p in sorted(step_record.parent.glob(step_record.name[:-len('.json')] + '*')):
            bound[str(p)] = sha(p)
    if launch.get('ssd_apply_record'):
        applied = ws.local(launch['ssd_apply_record'])
        need(applied.is_file() and sha(applied) == launch['ssd_apply_record_sha256'], 'SSD apply record changed')
        bound[str(applied)] = sha(applied)
    return dict(generation=generation, launch=str(launch_path), launch_sha256=sha(launch_path), exit_code=code,
                boot_log=str(boot_log), boot_log_sha256=sha(boot_log), loader_verdict=reason, run_py=str(run_py),
                run_py_sha256=pinned, gpu=gpu, bound=bound,
                no_guest=dict(verdicts=[v for _, v in verdicts], markers_absent=list(GUEST_MARKERS),
                              records_absent=list(GUEST_RECORDS),
                              loader_returns_before_upload_and_call=[max(loader) + 1, upload[0] + 1, call[0] + 1]))


def outputs(ws, label):
    return dict(record=ws.prefixed(label, '-retirement-v1.json'), quiesce=ws.prefixed(label, '-quiesce-v1.json'),
                quiesce_log=ws.prefixed(label, '-quiesce-v1.log'), tool=ws.prefixed(label, '-retirement-v1-tool'))


def plan(ws, prefix, preservation_sha256=None, stages=None, idle=None, binds=(), pre_guest=False):
    """Every offline check. Returns (record, context) for the hardware sequence."""
    out = outputs(ws, prefix)
    for path in out.values():
        need(not path.exists(), f'{path} already exists (reused output)')
    pair = stage_pair(ws, stages)
    bound = {str(Path(p)): sha(p) for p in binds}
    record = dict(status='READY', started=now(), label=prefix, tool_sha256=ws.tool_sources(), ssd_writes=False,
                  stage_sha256={Path(p).name: d for p, d in pair.items()}, stage_paths=pair, bound_sha256=bound)
    if pre_guest:
        need(idle is None and not preservation_sha256, '--loader-failure takes no preservation and is not --idle')
        proof = loader_failure(ws, prefix)
        generation = proof.pop('generation')
        record['bound_sha256'] = dict(proof.pop('bound'), **bound)
        record.update(kind='loader-failure', generation=generation, image_base=image_base(generation),
                      target_base=alternate(image_base(generation)), gpu_preparation_sha256=proof.pop('gpu'),
                      quiesce_plan='graceful quiesce --write (the preparation initialised the GPU; no guest ran)',
                      **proof)
        context = dict(run=None, saved=None, quiesce=True, generation=generation)
    elif idle is None:
        from . import unqualified
        from .evidence import Run, assess
        probe = Run(ws, prefix)
        stop = None
        if unqualified.recorded(ws, prefix) and not assess(probe)['complete']:
            # Recorded unqualified (unqualified.py): its witness stands for the audit.
            run, report = probe, assess(probe)
            stop = unqualified.validate(ws, run, report)
        else:
            run, report = preserve.validate(ws, prefix)
        initialised, gpu = gpu_initialised(ws, prefix)
        need(initialised, f'{prefix} has a launch record but no GPU preparation records')
        adopt = ws.prefixed(prefix, '-adopt.json')
        need(adopt.is_file() and sha(adopt) == run.launch['adreno_record_sha256'], 'GPU adoption record changed')
        saved = None
        if preservation_sha256:
            saved = preserve.verify_saved(ws, prefix, preservation_sha256)
            need(saved['generation'] == run.generation and saved['exit_code'] == run.exit_code, 'preservation is another run')
            if stop:
                need(saved.get('qualified') is False and saved['launch_sha256'] == run.launch_sha256 and
                     saved['unqualified']['record_sha256'] == stop['record_sha256'] and
                     saved['service'] == stop['witness']['service'],
                     'preservation is bound to another launch or unqualified-stop record')
            else:
                need(saved.get('qualified', True) and saved['launch_sha256'] == run.launch_sha256 and
                     saved['audit_sha256'] == report['audit']['sha256'],
                     'preservation is bound to another launch or audit')
            need(saved['service'][2] == PARKED_SERVICE_WORD, 'preserved audit service word is not a parked stop')
        if stop:
            record.update(qualified=False, unqualified_record=stop['record'],
                          unqualified_record_sha256=stop['record_sha256'])
        record.update(kind='stopped-run', generation=run.generation, image_base=run.image_base,
                      target_base=alternate(run.image_base), verification_sha256=preservation_sha256,
                      launch_sha256=run.launch_sha256, exit_code=run.exit_code, gpu_preparation_sha256=gpu,
                      quiesce_plan='graceful quiesce --write (the run initialised the GPU)')
        context = dict(run=run, saved=saved, quiesce=True, generation=run.generation)
    else:
        prior_path = ws.local(idle['after_retirement'])
        need(prior_path.is_file() and sha(prior_path) == idle['retirement_sha256'],
             f'{prior_path} is missing or differs from --retirement-sha256')
        prior = read(prior_path)
        generation = prior['after']['stage_generation']
        need(prior['status'] == f'GENERATION{generation}_IDLE' and not prior['ssd_writes'], f'{prior_path.name} status')
        need(prior['finished'] > prior['started'], f'{prior_path.name} timing')
        need(prior['after']['image_base'] == image_base(generation), f'{prior_path.name} left an unexpected image base')
        need(serror_clear(prior['after_serror']), f'{prior_path.name} recorded SError after its chainload')
        need(not ws.prefixed(prefix, '-launch.json').exists(), f'{prefix} has a launch record: retire it as a stopped run')
        initialised, gpu = gpu_initialised(ws, prefix)
        record.update(kind='idle', generation=generation, image_base=image_base(generation),
                      target_base=alternate(image_base(generation)), prior_retirement=str(prior_path),
                      prior_retirement_sha256=sha(prior_path), gpu_preparation_sha256=gpu,
                      previous_guest_generation=generation - 1)
        if initialised:
            record['quiesce_plan'] = 'graceful quiesce --write (this generation ran the GPU preparation)'
        else:
            path, quiet = quiesce_record(ws, prior_path, prior)
            need('gmu_reset' in quiet['gmu_steps'], f'{path.name}: the inherited quiescence did not reset the GMU')
            record.update(inherited_quiesce=str(path), inherited_quiesce_sha256=sha(path), gpu_writes=False,
                          quiesce_plan='inherited graceful quiescence (the GPU was never initialised here)')
        context = dict(run=None, saved=None, quiesce=initialised, generation=generation)
    return record, context


def native_stop(proxy, context, base):
    run, saved = context['run'], context['saved']
    info = proxy.bootinfo()
    need(info['current_el'] == 2 and info['stage_generation'] == run.generation and info['image_base'] == base,
         f'A16 is at generation {info["stage_generation"]}/EL{info["current_el"]}/{info["image_base"]:#x}, '
         f'expected {run.generation}/EL2/{base:#x}')
    guard = proxy.serror_state()
    need(serror_clear(guard), 'SError before the native-stop read')
    layout, _ = context_layout(run.runtime)
    need(layout.size('context') == run.launch['context_bytes'], 'context layout changed')
    work_module = load_module('cycle_monitor_work', run.runtime / 'probes/monitor_work.py')
    work, size = work_module.resident_work(proxy, info)
    at = work + layout.offset('context', 'services')
    raw = proxy.readmem(at, 64, live=True)
    need(struct.unpack('<8Q', raw) == tuple(saved['service']) and saved['service'][2] == PARKED_SERVICE_WORD,
         'live service words differ from the preserved stop')
    need(proxy.readmem(at, 64, live=True) == raw, 'service words changed between two reads')
    guard = proxy.serror_state()
    need(serror_clear(guard), 'SError after the native-stop read')
    return dict(bootinfo=info, work=work, bytes=size, service_hex=raw.hex(), serror=guard)


def idle_state(proxy, generation, base):
    info = proxy.bootinfo()
    need(info['current_el'] == 2 and info['stage_generation'] == generation and info['image_base'] == base,
         f'A16 is at generation {info["stage_generation"]}/{info["image_base"]:#x}, expected {generation}/{base:#x}')
    guard = proxy.serror_state()
    need(serror_clear(guard), 'SError at the idle generation')
    return dict(bootinfo=info, serror=guard)


def retire(ws, prefix, preservation_sha256=None, check=False, stages=None, idle=None, binds=(), pre_guest=False):
    stopped_run = idle is None and not pre_guest
    if stopped_run and not check:
        need(preservation_sha256, '--preservation-sha256 is required to retire a stopped run')
    record, context = plan(ws, prefix, preservation_sha256, stages, idle, binds, pre_guest)
    if check:
        record.update(status='READY', hardware_access=False, hardware_clients=hardware_clients(ws))
        if stopped_run:
            record['preservation'] = preservation_sha256 or 'PENDING: run cycle.py preserve first'
        return record
    require_exclusive(ws)
    q = load_proxy(ws)
    out = outputs(ws, prefix)
    generation, base = context['generation'], record['image_base']
    tool = out['tool']
    tool.mkdir()
    copies = {}
    for source, digest in record['tool_sha256'].items():
        dest = tool / Path(source).name
        shutil.copy2(source, dest)
        need(sha(dest) == digest, f'copy of {source} differs')
        copies[source] = dict(copy=str(dest), sha256=digest)
    record['tool_copies'] = copies
    write_new(out['record'], record)
    try:
        proxy = q.connect(ws.device)
        try:
            record['before'] = native_stop(proxy, context, base) if context['run'] else idle_state(proxy, generation, base)
        finally:
            proxy.link.close()
        record['status'] = 'NATIVE_STOP_VERIFIED' if context['run'] else f'GENERATION{generation}_VERIFIED'
        rewrite(out['record'], record)
        if context['quiesce']:
            command = [sys.executable, str(ws.q / 'tools/a16gpu.py'), '--device', ws.device,
                       '--out', str(out['quiesce']), 'quiesce', '--write']
            with out['quiesce_log'].open('x') as stream:
                result = subprocess.run(command, cwd=ws.q, stdout=stream, stderr=subprocess.STDOUT)
            need(result.returncode == 0, f'a16gpu quiesce exited {result.returncode}')
            quiet = read(out['quiesce'])
            need(quiet.get('quiesce') == 'graceful' and not quiet.get('stopped'), 'GPU quiescence was not graceful')
            need(serror_clear(quiet['serror_guard']['after']), 'SError after GPU quiescence')
            record.update(status='GPU_QUIESCED', quiesce=str(out['quiesce']), quiesce_sha256=sha(out['quiesce']),
                          gpu_writes=True)
            rewrite(out['record'], record)
        proxy = q.connect(ws.device)
        try:
            need(proxy.bootinfo()['stage_generation'] == generation, 'generation changed before the chainload')
            chosen, data, link = proxy.pick_stage(primary_stage(record['stage_paths']))
            need(record['stage_paths'].get(str(chosen)) == sha(chosen), f'picked stage {chosen} is not the pinned pair')
            need(link == record['target_base'], f'picked stage links at {link:#x}, expected {record["target_base"]:#x}')
            record['chosen_stage'] = dict(path=str(chosen), sha256=sha(chosen))
            record['chainload'] = proxy.chainload(proxy.stage_configure(data, None, False))
        finally:
            proxy.link.close()
        record['status'] = 'CHAINLOAD_RETURNED'
        rewrite(out['record'], record)
        time.sleep(ws.settle_seconds)
        proxy = q.connect(ws.device, wait=30)
        try:
            info = proxy.bootinfo()
            record['after'] = info
            need(info['current_el'] == 2 and info['stage_generation'] == generation + 1 and info['image_base'] == link,
                 f'after chainload: generation {info["stage_generation"]} at {info["image_base"]:#x}')
            guard = proxy.serror_state()
            record['after_serror'] = guard
            need(serror_clear(guard), 'SError after the chainload')
        finally:
            proxy.link.close()
        record['status'] = f'GENERATION{generation + 1}_IDLE'
    except BaseException as error:
        record.update(status='FAILED', error=repr(error))
        raise
    finally:
        record['finished'] = now()
        rewrite(out['record'], record)
    return dict(status=record['status'], output=str(out['record']), sha256=sha(out['record']))
