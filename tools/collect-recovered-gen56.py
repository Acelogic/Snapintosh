#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reuse generation56 collectors with explicit native recovery admission.

The original launch JSON remains incomplete. Only host-terminal admission is
replaced; source pins, monitor, SMP, ownership, candidate and read guards remain.
All compiled overlays are hashed in a separate record. The startup-waits mode
also selects preferences and triangle threads in the existing bounded reader.
No installed source is changed. See docs/GEN56-HOST-INTERRUPTION-20260928.md.
"""
from pathlib import Path
import builtins
import hashlib
import importlib.util
import json
import os
import re
import runpy
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()
RUNTIME = ROOT.parent / 'Snapintosh-adreno-sks'
PREFIX = 'installed-metal-panel-arguments-3600s-20260928'
RECOVERY = ROOT / 'build' / (PREFIX + '-host-recovery-v1.json')
LAUNCH = ROOT / 'build' / (PREFIX + '-launch.json')
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
overlays = []
startup_waits = False


def native_recovery(launch):
    recovery = json.loads(RECOVERY.read_text())
    assert recovery['status'] == 'NATIVE_STOP_PREFLIGHT_RECOVERED'
    assert recovery['host_exit_code'] is None and recovery['host_finished_time'] is None
    assert recovery['launch_sha256'] == sha(LAUNCH)
    assert launch == json.loads(LAUNCH.read_text())
    assert 'exit_code' not in launch and 'finished' not in launch
    assert recovery['generation'] == 56 and recovery['monitor_sha256'] == launch['monitor_sha256']
    assert time.time() >= recovery['observed_stopped_at'] >= 1790577060
    for path, digest in launch['source_sha256'].items():
        assert sha(path) == digest, path
    # Strict process identity check; a later recycled PID is not this launcher.
    module_path = ROOT / 'tools/recover-gen56-stop.py'
    assert sha(module_path) == recovery['source_sha256']
    spec = importlib.util.spec_from_file_location('native_stop_recovery', module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.host_absent(launch)
    return recovery


def recovery_time(launch):
    return native_recovery(launch)['observed_stopped_at']


def copied_runtime(launch):
    native_recovery(launch)
    copied = {}
    for source in (RUNTIME / 'build').glob(PREFIX + '-*'):
        if not source.is_file():
            continue
        target = ROOT / 'build' / source.name
        if target.exists():
            assert sha(target) == sha(source), target
            copied[str(source)] = sha(source)
    return copied


original_compile = builtins.compile


def recovered_compile(source, filename, mode, *args, **kwargs):
    if not isinstance(source, (str, bytes)):
        return original_compile(source, filename, mode, *args, **kwargs)
    text = source.decode() if isinstance(source, bytes) else source
    original = text
    changes = []
    # Only whole executable lines are eligible, never replacement templates
    # inside a wrapper's string literals. Later final compilation sees them.
    replacements = {
        "assert launch.get('finished') and 'exit_code' in launch": "assert snap_native_recovery(launch)",
        "assert launch.get('finished') and 'exit_code' in launch and audit['runtime_stop_qualified']": "assert snap_native_recovery(launch) and audit['runtime_stop_qualified']",
        "assert launch.get('exit_code')==int(os.environ.get('SNAP_STOPPED_EXIT','9')) and launch.get('finished')": "assert snap_native_recovery(launch)",
        "assert record.get('exit_code')==int(os.environ.get('SNAP_STOPPED_EXIT','9')) and record.get('finished')": "assert snap_native_recovery(record)",
        "assert launch['finished'] and isinstance(launch['exit_code'], int)": "assert snap_native_recovery(launch)",
        "assert launch.get('finished') and isinstance(launch.get('exit_code'),int)": "assert snap_native_recovery(launch)",
        "if not launch.get('finished') or 'exit_code' not in launch or not audit['runtime_stop_qualified']:": "if not snap_native_recovery(launch) or not audit['runtime_stop_qualified']:",
    }
    if startup_waits:
        replacements["'--user-frames-for', 'WindowServer', '--user-frames-for', 'loginwindow']"] = (
            "'--user-frames-for', 'WindowServer', '--user-frames-for', 'loginwindow', "
            "'--user-frames-for', 'cfprefsd', '--user-frames-for', 'metal-triangle-p', "
            "'--initial-arguments-for', 'WindowServer', '--initial-arguments-for', 'metal-triangle-p']")
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        clean = line.strip()
        if clean in replacements:
            replacement = replacements[clean]
            lines[i] = line[:len(line)-len(line.lstrip())] + replacement + ('\n' if line.endswith('\n') else '')
            changes.append(dict(line=i+1, old=clean, new=replacement))
        elif clean.startswith('assert started > launch[') and "launch['finished']" in clean:
            lines[i] = line.replace("launch['finished']", 'snap_recovery_time(launch)')
            changes.append(dict(line=i+1, old=clean, new=lines[i].strip()))
        elif clean.startswith('for name, digest in launch[') and "launch['runtime_artifacts_copied_sha256']" in clean:
            lines[i] = line.replace("launch['runtime_artifacts_copied_sha256']", 'snap_copied_runtime(launch)')
            changes.append(dict(line=i+1, old=clean, new=lines[i].strip()))
        elif clean.startswith("result=subprocess.run([sys.executable,'build/run-stopped-cdc-read-20260924.py',script,"):
            lines[i] = line.replace("'build/run-stopped-cdc-read-20260924.py',script,", repr(str(SELF)) + ", '--child', script,")
            changes.append(dict(line=i+1, old=clean, new=lines[i].strip()))
        elif clean.startswith("subprocess.run([sys.executable, str(ROOT / 'build/capture-panel-arguments-ring-20260928.py'),"):
            lines[i] = line.replace("str(ROOT / 'build/capture-panel-arguments-ring-20260928.py')", repr(str(SELF)) + ", '--ring'")
            changes.append(dict(line=i+1, old=clean, new=lines[i].strip()))
        elif clean == "collect(f'cpu{owner}-stop','tools/capture-secondary-stop.py',['--cpu',str(owner)])":
            lines[i] = line.replace("['--cpu',str(owner)]", "['--cpu',str(owner),'--resident-stop']")
            changes.append(dict(line=i+1, old=clean, new=lines[i].strip()))
    text = ''.join(lines)
    if changes:
        path = Path(filename).resolve()
        assert path.is_relative_to(ROOT) or path.is_relative_to(RUNTIME), filename
        overlays.append(dict(filename=str(path), before_sha256=hashlib.sha256(original.encode()).hexdigest(),
            after_sha256=hashlib.sha256(text.encode()).hexdigest(), changes=changes))
    return original_compile(text, filename, mode, *args, **kwargs)


def prepare_host_files(launch):
    native_recovery(launch)
    for source in (RUNTIME / 'build').glob(PREFIX + '-*'):
        if source.is_file():
            target = ROOT / 'build' / source.name
            if not target.exists():
                with source.open('rb') as inp, target.open('xb') as out:
                    shutil.copyfileobj(inp, out)
            assert sha(source) == sha(target)
    for source in [LAUNCH, ROOT / 'build' / (PREFIX + '-boot.log')]:
        target = RUNTIME / 'build' / source.name
        if not target.exists():
            with target.open('xb') as stream:
                stream.write(source.read_bytes())
        assert sha(source) == sha(target)


def main():
    global startup_waits
    arguments = sys.argv[1:]
    assert arguments and arguments[0] in ('--primary','--ring','--native','--startup-waits','--crashes','--child','--input')
    mode, rest = arguments[0], arguments[1:]
    startup_waits = mode == '--startup-waits'
    check_only = rest in (['--check'], ['--syntax-only']) or (mode == '--input' and '--check-inputs' in rest)
    assert mode != '--child' or not check_only
    if mode == '--child':
        assert rest and rest[0] in {'tools/audit-secondary-runtime.py','tools/capture-secondary-stop.py',
            'tools/capture-service-profile.py','tools/capture-kernel-waits.py','tools/capture-console-tail.py'}
        script = RUNTIME / 'build/run-stopped-cdc-read-20260924.py'
        label = Path(rest[0]).stem + '-' + str(os.getpid())
    elif mode == '--input':
        script = ROOT / 'tools/read-a16-hid-descriptor.py'
        label = 'input' + ('-check' if check_only else '') + '-' + str(os.getpid())
    else:
        script = ROOT / 'build' / {'--primary':'collect-panel-arguments-20260928.py',
            '--ring':'capture-panel-arguments-ring-20260928.py','--native':'capture-native-startup-gen56-20260928.py',
            '--startup-waits':'capture-native-startup-gen56-20260928.py',
            '--crashes':'capture-crash-retention-gen56-20260928.py'}[mode]
        label = mode[2:] + ('-check' if check_only else '') + '-' + str(os.getpid())
    launch = json.loads(LAUNCH.read_text())
    if not check_only:
        native_recovery(launch)
        if mode == '--primary':
            prepare_host_files(launch)
        if mode == '--input':
            for stage in ('primary', 'native'):
                candidates = [json.loads(p.read_text()) for p in (ROOT / 'build').glob(PREFIX + '-recovery-adapter-' + stage + '-*.json')]
                completed = any(c['status'] == 'RECOVERED_COLLECTOR_COMPLETED' and c['recovery_sha256'] == sha(RECOVERY) for c in candidates)
                if stage == 'primary' and not completed:
                    proof = json.loads((ROOT / 'build' / (PREFIX + '-capture-completion-v1.json')).read_text())
                    assert proof['status'] == 'GEN56_STOPPED_CAPTURES_AND_MODE_VERIFIED'
                    assert proof['generation'] == 56 and proof['primary_capture_complete']
                    assert proof['recovery_sha256'] == sha(RECOVERY) and proof['launch_sha256'] == sha(LAUNCH)
                    for group in ('artifacts_sha256', 'completed_adapter_records_sha256'):
                        for name, digest in proof[group].items():
                            assert sha(name) == digest, name
                    completed = True
                assert completed, 'required ' + stage + ' capture unfinished'
    output = ROOT / 'build' / (PREFIX + '-recovery-adapter-' + label + '.json')
    assert not output.exists()
    record = dict(status='RUNNING', hardware_access=not check_only, original_host_result_available=False,
        started=time.time(), adapter_sha256=sha(SELF), launch_sha256=sha(LAUNCH), script=str(script),
        script_sha256=sha(script), command=[str(SELF), *arguments], compiled_overlays=overlays,
        recovery_sha256=None if check_only else sha(RECOVERY))
    builtins.snap_native_recovery = native_recovery
    builtins.snap_recovery_time = recovery_time
    builtins.snap_copied_runtime = copied_runtime
    builtins.compile = recovered_compile
    sys.argv = [str(script), *rest]
    os.chdir(RUNTIME if mode == '--child' else ROOT)
    try:
        try:
            runpy.run_path(str(script), run_name='__main__')
        except SystemExit as result:
            assert result.code in (None,0), f'collector exit {result.code}'
        assert overlays, 'expected explicit recovered-stop admission overlay'
        record['status'] = 'OFFLINE_RECOVERY_ADAPTER_COMPILED' if check_only else 'RECOVERED_COLLECTOR_COMPLETED'
    except BaseException as error:
        record.update(status='FAILED', error=repr(error))
        raise
    finally:
        builtins.compile = original_compile
        record['finished'] = time.time()
        with output.open('x') as stream:
            json.dump(record, stream, indent=2)
            stream.write('\n')
    print(json.dumps(dict(status=record['status'], output=str(output), overlays=len(overlays))))


if __name__ == '__main__':
    main()
