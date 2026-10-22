#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Host tests for tools/cycle.py. No A16 access, ever.

Offline equivalence tests read the real workspace and write nothing: the rendered
observers against the per-generation wrappers of generations 61-66, the gen66
candidate manifest against tools/run-ca-memo-candidate.py, and `storage` against
tools/storage-gen66-memo.py.

Record tests run in copied workspaces under a temporary directory: the real records of
generations 61-66 are copied (never modified in place), read-only inputs are symbolic
links, and the only q1n1 hardware entry points present (q1n1proxy.py, a16gpu.py) are
fakes that play the A16's side from a state file. Stopped-state steps are played back
from each generation's real outputs and exit codes; the historical exit-6 sequencer
records are the oracle for which steps must run, in which order.

Run: python3 tools/test-cycle.py [-k NAME]
"""
import sys

sys.dont_write_bytecode = True

import argparse
import json
import os
import shutil
import struct
import subprocess
import tempfile
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
REAL = ROOT.parent
sys.path.insert(0, str(HERE))
from cycle_lib import (capture, common, evidence, launch, observers, preserve, retire, storage,  # noqa: E402
                       substitute, unqualified)
from cycle_lib.common import Refused, Workspace, read, sha, sha_bytes  # noqa: E402

GEN = {
    61: 'installed-metal-ca-network-3600s-20260928',
    63: 'installed-metal-ca-composite-2400s-20260928',
    64: 'installed-metal-ca-quiet-memo-1800s-20260928',
    65: 'installed-metal-ca-quiet-bisect-1800s-20260928',
    66: 'installed-metal-ca-memo-2400s-20260928',
    70: 'installed-metal-integrated-2400s-20260928',
    71: 'installed-metal-integrated-guestes-2400s-20260928',
    76: 'installed-metal-native-tables-1800s-20260929',
    77: 'installed-metal-native-2a-1800s-20260929',
    78: 'installed-metal-native-p3-1800s-20260929',
}
WRAPPERS = {  # generation: (collector, ring, native startup) wrappers written by hand
    61: ('collect-ca-network-20260928.py', 'capture-ca-network-ring-20260928.py', 'capture-native-startup-gen61-20260928.py'),
    63: ('collect-ca-composite-20260928.py', 'capture-ca-composite-ring-20260928.py', 'capture-native-startup-gen63-20260928.py'),
    64: ('collect-ca-quiet-memo-20260928.py', 'capture-ca-quiet-memo-ring-20260928.py', 'capture-native-startup-gen64-20260928.py'),
    65: ('collect-ca-quiet-bisect-20260928.py', 'capture-ca-quiet-bisect-ring-20260928.py', 'capture-native-startup-gen65-20260928.py'),
    66: ('collect-ca-memo-20260928.py', 'capture-ca-memo-ring-20260928.py', 'capture-native-startup-gen66-20260928.py'),
}
GEN66_MANIFEST = ROOT / 'candidates/gen66-memo.json'
HARDWARE_TOOLS = ('q1n1proxy.py', 'udplink.py', 'a16gpu.py', 'a16ctl.py')
BASE_DISPATCH = "exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))"

FAKE_PROXY = r'''"""Fake q1n1proxy for tools/test-cycle.py: the A16 side is a JSON state file."""
import json
import struct
from pathlib import Path

STATE = Path(__file__).resolve().parents[2] / 'fake-a16.json'
STAGE_MAGIC = 0x3147545331314E51


class ProxyError(RuntimeError):
    pass


def _load():
    return json.loads(STATE.read_text())


def _save(state):
    STATE.write_text(json.dumps(state, indent=1))


def _log(event):
    state = _load()
    state['log'].append(event)
    _save(state)


class Link:
    def close(self):
        _log('close')


class Proxy:
    def __init__(self):
        self.link = Link()

    def bootinfo(self):
        return dict(_load()['info'])

    def serror_state(self):
        return dict(_load()['serror'])

    def live_battery(self):
        state = _load()
        return state['battery_status'], dict(state['battery'])

    def readmem(self, address, size, live=False):
        for base, data in _load()['memory']:
            data = bytes.fromhex(data)
            if base <= address and address + size <= base + len(data):
                return data[address - base:address - base + size]
        raise ProxyError(f'unmapped read {address:#x}+{size}')

    @staticmethod
    def stage_configure(data, logo=None, xhci=False):
        return data

    @staticmethod
    def stage_header(data):
        magic, link = struct.unpack('<QQ', data[8:24])
        if magic != STAGE_MAGIC:
            raise ProxyError('not a stage image')
        return link

    def pick_stage(self, path):
        info = self.bootinfo()
        name = Path(path).name
        sibling = name[:-8] + '.bin' if name.endswith('-alt.bin') else name[:-4] + '-alt.bin'
        for candidate in (Path(path), Path(path).with_name(sibling)):
            data = candidate.read_bytes()
            link = self.stage_header(data)
            if link != info['image_base'] and info['stage_base'] <= link < info['stage_base'] + info['stage_size']:
                return candidate, data, link
        raise ProxyError('no free stage slot')

    def chainload(self, data, base=None):
        state = _load()
        base = base or self.stage_header(data)
        before = state['info']['stage_generation']
        if base == state['info']['image_base']:
            raise ProxyError('that stage is linked for the address it would overwrite')
        state['info']['stage_generation'] += 1
        state['info']['image_base'] = base
        state['log'].append(f'chainload {base:#x}')
        _save(state)
        return {'base': base, 'bytes': len(data), 'generation_before': before}


def connect(device=None, serial=None, interface=None, debug=False, wait=0.0):
    state = _load()
    if state.get('offline'):
        raise ProxyError('no responding q1n1 endpoint')
    state['log'].append(f'connect {device}')
    _save(state)
    return Proxy()
'''

FAKE_A16GPU = r'''"""Fake a16gpu for tools/test-cycle.py: quiesce writes the record the state file asks for."""
import json
import sys
from pathlib import Path

STATE = Path(__file__).resolve().parents[2] / 'fake-a16.json'
state = json.loads(STATE.read_text())
args = sys.argv[1:]
out = Path(args[args.index('--out') + 1])
command = [a for a in args if not a.startswith('-') and a != args[args.index('--out') + 1] and a != args[args.index('--device') + 1]]
state['log'].append('a16gpu ' + ' '.join(command))
STATE.write_text(json.dumps(state, indent=1))
record = dict(tool='a16gpu', command=command[0], stopped=None, quiesce=state.get('quiesce', 'graceful'),
              serror_guard=dict(present=True, after=dict(before=0, during=0, unconsumed=0)),
              gmu_steps=['oob_cleared', 'gbif_halted', 'prepare_slumber', 'gmu_reset'])
with out.open('x') as stream:
    json.dump(record, stream)
print('quiesce', record['quiesce'])
'''


# ----------------------------------------------------------------------------- fixture

def link(target, source):
    target.symlink_to(source)


def mirror_dir(target, source, copy_prefixes=(), cutoff=None, skip=()):
    """target becomes a real directory whose entries are links to source's entries,
    except entries named with a tested prefix: files are copied (if older than
    cutoff), directories left out, so every write stays under target."""
    target.mkdir(parents=True, exist_ok=True)
    for entry in source.iterdir():
        if entry.name in skip or entry.name in ('.git', '__pycache__'):
            continue
        if any(entry.name.startswith(p) for p in copy_prefixes):
            if entry.is_file() and not entry.is_symlink() and (cutoff is None or entry.stat().st_mtime < cutoff):
                shutil.copy2(entry, target / entry.name)
            continue
        link(target / entry.name, entry)


def materialize(path):
    """Make every symlinked directory between the workspace and path a real directory
    of links, so one file under it can be replaced without touching the original."""
    parts = []
    probe = path.parent
    while probe.is_symlink() or not probe.exists() or probe.resolve() != probe:
        parts.append(probe)
        probe = probe.parent
    for directory in reversed(parts):
        if directory.is_symlink():
            source = directory.resolve()
            directory.unlink()
            mirror_dir(directory, source)


class Scratch:
    """A copied workspace: tmp/Snapintosh, tmp/<runtime roots>, tmp/q1n1 with fakes."""

    def __init__(self, tmp, generations, cutoff=None, restore_pins=True):
        self.tmp = Path(tmp).resolve()
        self.prefixes = [GEN[g] for g in generations]
        runtimes = {Path(read(ROOT / 'build' / f'{p}-launch.json')['runtime_root']).name for p in self.prefixes}
        snap = self.tmp / 'Snapintosh'
        mirror_dir(snap, ROOT, skip=('build', 'tools', 'candidates'))
        mirror_dir(snap / 'build', ROOT / 'build', self.prefixes, cutoff)
        mirror_dir(snap / 'tools', ROOT / 'tools', skip=('cycle.py', 'cycle_lib'))
        (snap / 'candidates').mkdir()
        for name in runtimes:
            mirror_dir(self.tmp / name, REAL / name, skip=('build', 'downloads'))
            (self.tmp / name / 'downloads').symlink_to(os.readlink(REAL / name / 'downloads'))
            mirror_dir(self.tmp / name / 'build', REAL / name / 'build', self.prefixes, cutoff)
        for entry in REAL.iterdir():
            if entry.name.startswith('Snapintosh-') and entry.name not in runtimes and entry.is_dir():
                link(self.tmp / entry.name, entry)
        mirror_dir(self.tmp / 'q1n1', REAL / 'q1n1', skip=('tools',))
        mirror_dir(self.tmp / 'q1n1/tools', REAL / 'q1n1/tools', skip=HARDWARE_TOOLS)
        (self.tmp / 'q1n1/tools/q1n1proxy.py').write_text(FAKE_PROXY)
        (self.tmp / 'q1n1/tools/a16gpu.py').write_text(FAKE_A16GPU)
        self.ws = Workspace(snap, origin=REAL)
        self.ws.processes = lambda: {}
        self.ws.settle_seconds = 0
        if restore_pins:
            self.restore_drifted_pins()

    def restore_drifted_pins(self):
        """Put back launch-time content of source pins changed since (from the real
        preservation's copies), the way a conductor would before re-collecting."""
        for prefix in self.prefixes:
            launch_record = read(ROOT / 'build' / f'{prefix}-launch.json')
            monitor = Path(launch_record['monitor_path'])
            runtime_build = self.ws.local(launch_record['runtime_root']) / 'build'
            for suffix in ('.bin', '.elf'):
                built = runtime_build / ('xnuboot' + suffix)
                if sha(built) != sha(monitor.with_suffix(suffix)):
                    built.unlink()
                    shutil.copy2(monitor.with_suffix(suffix), built)   # what the launcher copied in at boot
            drift = [n for n, d in launch_record['source_sha256'].items() if not common.matches(n, d)]
            if not drift:
                continue
            saved = next(read(p) for p in (ROOT / 'build').glob('*-preserved-*/preservation.json')
                         if read(p).get('prefix') == prefix)
            for name in drift:
                target = self.ws.local(name)
                materialize(target)
                target.unlink()
                shutil.copy2(saved['runtime_sources'][name]['copy'], target)

    def a16(self, generation, base, battery=(0, True, False, 100), service=None, run=None, quiesce='graceful'):
        """Put the fake A16 at a generation; optionally hold a stopped guest whose
        monitor work locator and service words match the run's records."""
        info = dict(current_el=2, stage_generation=generation, image_base=base, stage_base=0xb0000000,
                    stage_size=0x1000000, heap_base=0xbf0000000, heap_size=0x1000000, memory_map=0xc10000000,
                    memory_map_size=48, memory_map_stride=48)
        memory = []
        if service is not None:
            work_module = common.load_module('test_monitor_work', run.runtime / 'probes/monitor_work.py')
            entry = struct.pack('<IIQQQQ', 7, 0, 0x800000000, 0, 0x400000, 0) + bytes(8)
            memory.append((info['memory_map'], entry.hex()))
            free = work_module.free_spans(entry, 48, info)
            locator = work_module.encode_locator(0xb00000000, work_module.WORK_SIZE, 0x8c0000000, 0xac0000000, info, free)
            memory.append((info['heap_base'] + work_module.LOCATOR_OFFSET, locator.hex()))
            layout, _ = common.context_layout(run.runtime)
            memory.append((0xb00000000 + layout.offset('context', 'services'), struct.pack('<8Q', *service).hex()))
        status, plausible, ac, percent = battery
        state = dict(info=info, memory=memory, serror=dict(before=0, during=0, unconsumed=0),
                     battery_status=status, battery=dict(plausible=plausible, ac=ac, percent=percent,
                                                         text=f'{percent}% {"AC" if ac else "battery"}'),
                     quiesce=quiesce, log=[])
        (self.tmp / 'fake-a16.json').write_text(json.dumps(state))

    def a16_state(self):
        return read(self.tmp / 'fake-a16.json')


class Playback:
    """Runs a capture step by restoring what that step produced in the real run
    (its output files and exit code), without executing anything."""

    RUNTIME_OUTPUTS = {'tools/audit-secondary-runtime.py': ('audit', ['-audit.json']),
                       'tools/capture-secondary-stop.py': ('cpu-stop', None),
                       'tools/capture-service-profile.py': ('service-profile', ['-service-profile.json']),
                       'tools/capture-console-tail.py': ('console-tail', ['-console-tail.json', '-console-tail.bin',
                                                                         '-console-tail.txt'])}

    def __init__(self, scratch, prefix, exits, primary_log=None, stand_in=None):
        self.s, self.prefix, self.exits, self.primary_log = scratch, prefix, exits, primary_log
        self.stand_in = stand_in or {}   # step: real file from another run, when this run has none yet
        self.ran = []

    def outputs(self, command):
        """(step name, [(source file, destination)])."""
        s, p = self.s, self.prefix
        if 'substituted' in command:   # cycle.py substituted ... -- HELPER SCRIPT ARGS: the step itself
            command = [command[0], *command[command.index('--') + 1:]]
        run_root = s.ws.local(read(ROOT / 'build' / f'{p}-launch.json')['runtime_root']) / 'build'
        real = lambda suffix: ROOT / 'build' / f'{p}{suffix}'
        if 'observe' in command:
            kind = command[command.index('observe') + 1]
            if kind == 'ring':
                return 'ring', [(real(x), s.ws.build / f'{p}{x}') for x in ('-gpu-ring.json', '-gpu-ring.bin', '-gpu-fence.bin')]
            if kind == 'collector':
                produced = [x for x in (ROOT / 'build').glob(p + '-*') if x.stat().st_mtime > read(real('-launch.json'))['finished'] + 5
                            and not x.name.startswith(f'{p}-sequence') and 'pre-reset' not in x.name]
                return 'primary', [(x, s.ws.build / x.name) for x in produced]
            attempt = command[command.index('--attempt') + 1]
            stem = 'native-startup-state' if kind == 'native' else 'crash-retention'
            source = sorted((ROOT / 'build').glob(f'{p}-{stem}-*-binding.json'))[-1]
            old = source.name[len(p) + len(stem) + 2:-len('-binding.json')]
            return ('native-startup' if kind == 'native' else 'crash-retention',
                    [(source, s.ws.build / f'{p}-{stem}-{attempt}-binding.json'),
                     (source.with_name(f'{p}-{stem}-{old}.json'), s.ws.build / f'{p}-{stem}-{attempt}.json')])
        if 'tools/capture-panel.py' in command:
            return 'panel', [(real('-panel.png'), run_root / f'{p}-panel.png')]
        if 'tools/auxkc-verdict.py' in command:
            return 'verdict', []
        script = command[2]
        if script == 'tools/capture-kernel-waits.py':
            suffix = command[command.index('--output-suffix') + 1] if '--output-suffix' in command else 'kernel-waits'
            return suffix, [(real(f'-{suffix}.json'), run_root / f'{p}-{suffix}.json')]
        name, suffixes = self.RUNTIME_OUTPUTS[script]
        if name == 'cpu-stop':
            cpu = command[command.index('--cpu') + 1]
            suffixes, name = [f'-cpu{cpu}-stop.json'], f'cpu{cpu}-stop'
        return name, [(real(x), run_root / f'{p}{x}') for x in suffixes]

    def __call__(self, command, cwd, env, log):
        name, files = self.outputs(command)
        code = self.exits.get(name, 0)
        self.ran.append(dict(name=name, command=command, env={k: env[k] for k in ('SNAP_STOPPED_EXIT', 'SNAP_DEVICE')}))
        with log.open('x') as stream:
            if name == 'primary':
                stream.write(self.primary_log.read_text())
            else:
                stream.write(f'played back {name} exit {code}\n')
        if code == 0:
            for source, dest in files:
                source = self.stand_in.get(name, source)
                if source.is_file() and not dest.exists():
                    shutil.copy2(source, dest)
        return code


def historical_steps(prefix):
    """(name, required, command) of the steps a hand-written exit-6 sequencer ran itself."""
    record = read(ROOT / 'build' / f'{prefix}-exit6-capture-v1.json')
    return [(s['name'], s['required'], s['command'], s['exit_code']) for s in record['steps'] if not s.get('prior')]


def cycle_commands_parse(commands, prefix):
    """Every cycle.py command a plan writes (and the ring command inside the rendered
    collector) is one cycle.py's own parser accepts, naming this run."""
    import runpy
    parse = runpy.run_path(str(HERE / 'cycle.py'), run_name='cycle_parse')['parse']
    for command in [c[2:] for c in commands if len(c) > 2 and c[1].endswith('tools/cycle.py')]:
        args = parse(command)
        assert args.command == 'observe' and args.launch == prefix, command
        assert args.rest and args.rest[0] in ('--prefix', '--attempt'), command


def expect_refusal(function, text):
    try:
        function()
    except Refused as refusal:
        assert text in str(refusal), f'refused for another reason: {refusal}'
        return str(refusal)
    raise AssertionError(f'expected a refusal containing {text!r}')


# ----------------------------------------------------------------------------- offline equivalence

def run_record(generation):
    """The attributes observers.Params reads, straight from a launch record."""
    prefix = GEN[generation]
    record = read(ROOT / 'build' / f'{prefix}-launch.json')
    return type('LaunchView', (), dict(prefix=prefix, generation=generation, image_base=common.image_base(generation),
                                       runtime=Path(record['runtime_root']), launch=record))()


def wrapper_source(path, collector=False):
    """The program a per-generation wrapper would run, computed by the wrapper itself
    in its offline mode (collectors: --syntax-only; others: dispatch replaced)."""
    namespace = dict(__file__=str(path), __name__='wrapper_under_test')
    text = path.read_text()
    saved = sys.argv
    if collector:
        sys.argv = [str(path), '--syntax-only']
    else:
        assert text.count(BASE_DISPATCH) == 1, path
        text = text.replace(BASE_DISPATCH, 'GENERATED_SOURCE = source')
    try:
        from contextlib import redirect_stdout
        import io
        with redirect_stdout(io.StringIO()):
            exec(compile(text, str(path), 'exec'), namespace)
    finally:
        sys.argv = saved
    return namespace['source'] if collector else namespace['GENERATED_SOURCE']


def ring_command_in_collector(ws, p):
    """The ring command the rendered standard collector would run, taken from the
    collect-metal-gui program it builds (captured in the collector's --check mode)."""
    import ast
    import builtins
    import io
    from contextlib import redirect_stdout
    gui, base = str(observers.pinned(ws, 'gui_collector')), observers.pinned(ws, 'collector')
    seen, original, saved = [], builtins.compile, sys.argv

    def hook(source, filename, *args, **kwargs):
        if filename == gui:
            seen.append(source)
        return original(source, filename, *args, **kwargs)

    builtins.compile, sys.argv = hook, [str(base), '--check']
    try:
        with redirect_stdout(io.StringIO()):
            exec(original(observers.render_collector(ws, p), str(base), 'exec'), dict(__file__=str(base), __name__='__main__'))
    finally:
        builtins.compile, sys.argv = original, saved
    calls = [n for n in ast.walk(ast.parse(seen[0])) if isinstance(n, ast.Call) and ast.unparse(n.func) == 'subprocess.run'
             and isinstance(n.args[0], ast.List) and "'observe'" in ast.unparse(n.args[0])]
    assert len(calls) == 1
    return eval(compile(ast.Expression(calls[0].args[0]), 'ring-command', 'eval'),
                dict(sys=sys, os=os, ROOT=ws.root, PREFIX=p.prefix))


def test_rendered_observers_equal_generation_wrappers():
    """Collector, ring and native observers rendered from records equal the hand-written
    wrappers of generations 61, 63, 64, 65 and 66 (collector: except its one ring entry)."""
    ws = Workspace(ROOT)
    display = launch.Manifest(ws, GEN66_MANIFEST).observers['display']
    for generation, (collector, ring, native) in WRAPPERS.items():
        p = observers.Params(run_record(generation), display)
        theirs = wrapper_source(ROOT / 'build' / collector, collector=True)
        ring_entry = observers.RING_ENTRY.replace('capture-panel-mode-ring-20260928.py', ring)
        assert theirs.count(ring_entry) == 1, generation
        mine = observers.render_collector(ws, p)
        assert mine.count(observers.CYCLE_RING_ENTRY) == 1, generation
        assert mine.replace(observers.CYCLE_RING_ENTRY, '') == theirs.replace(ring_entry, ''), f'collector {generation}'
        assert observers.render_ring(ws, p) == wrapper_source(ROOT / 'build' / ring), f'ring {generation}'
        cycle_commands_parse([ring_command_in_collector(ws, p)], p.prefix)
        assert observers.render_native(ws, p) == wrapper_source(ROOT / 'build' / native), f'native {generation}'


def test_gen66_manifest_reproduces_run_ca_memo_candidate():
    """Acceptance: the gen66 manifest passes run-sks-transport-candidate.py the same
    arguments and environment as tools/run-ca-memo-candidate.py (and as the real gen66
    launch record), through a byte-identical transformed launcher."""
    command = [sys.executable, str(HERE / 'cycle.py'), 'launch', '--candidate', str(GEN66_MANIFEST), '--check-inputs']
    compare = subprocess.run(command + ['--compare-adapter', str(HERE / 'run-ca-memo-candidate.py')],
                             capture_output=True, text=True, cwd=ROOT)
    report = json.loads(compare.stdout)
    assert compare.returncode == 0 and report['status'] == 'EQUIVALENT', report
    assert report['launch_record_arguments_identical'] and report['launch_record_environment_identical']
    assert report['inputs_digest_mismatch'] == []
    mine = subprocess.run(command, capture_output=True, text=True, cwd=ROOT)
    theirs = subprocess.run([sys.executable, str(HERE / 'run-ca-memo-candidate.py'), '--check-inputs'],
                            capture_output=True, text=True, cwd=ROOT)
    assert mine.returncode == theirs.returncode == 0
    assert mine.stdout == theirs.stdout, 'check-inputs output differs'
    return dict(only_here=len(report['inputs_only_here']), only_in_adapter=len(report['inputs_only_in_adapter']))


def test_storage_reproduces_gen66_adapter():
    """`storage` derives the approved-header chain, package, preceding persistence and
    seed from records and renders the same programs as tools/storage-gen66-memo.py."""
    ws = Workspace(ROOT)
    adapter = HERE / 'storage-gen66-memo.py'
    for mode in ('persistence', 'snapshot'):
        namespace = dict(__file__=str(adapter), __name__='adapter_under_test')
        saved = sys.argv
        sys.argv = [str(adapter), mode, '--check']
        try:
            from contextlib import redirect_stdout
            import io
            with redirect_stdout(io.StringIO()):
                exec(compile(adapter.read_text(), str(adapter), 'exec'), namespace)
        finally:
            sys.argv = saved
        out = ROOT / 'build/ca-memo-deploy-20260928/snapshot-v1' if mode == 'snapshot' else None
        source, _, facts, chain = storage.render(ws, GEN[66], mode, out)
        assert source == namespace['source'], mode
        assert chain['baseline'] == namespace['baseline'], mode


# ----------------------------------------------------------------------------- capture

def test_capture_continues_gen65_like_its_completion_sequencer():
    """Gen65 stopped (exit 6) after the standard collector ran audit and CPU1 stop and was
    refused at the service profile, and the native observers completed. Capture must run
    exactly what build/capture-exit6-gen65-20260928.py ran: console tail, panel, ring,
    then kernel waits, mounts, verdict - and nothing already done."""
    prefix = GEN[65]
    started = read(ROOT / 'build' / f'{prefix}-exit6-capture-v1.json')['started']
    with tempfile.TemporaryDirectory() as tmp:
        s = Scratch(tmp, [65], cutoff=started)
        history = historical_steps(prefix)
        manifest = write_manifest(s, 65)
        plan = capture.plan(s.ws, prefix, manifest_path=manifest)
        assert {st['name']: st['state'] for st in plan['report']['steps']}['service-profile'] == 'refused'
        runner = Playback(s, prefix, {n: c for n, _, _, c in history})
        result = capture.execute(s.ws, plan, runner)
        assert [r['name'] for r in runner.ran] == [n for n, _, _, _ in history], runner.ran
        by_name = {r['name']: r['command'] for r in runner.ran}
        for name, _, command, _ in history:
            if 'run-stopped-cdc-read' in ' '.join(command):
                assert by_name[name][2:] == command[2:], name
        assert all(r['env']['SNAP_STOPPED_EXIT'] == '6' for r in runner.ran)
        assert result['status'] == 'STOPPED_STATE_CAPTURED', result
        assert capture.plan(s.ws, prefix, manifest_path=manifest)['steps'] == []


def test_capture_runs_gen64_early_boot_set_after_failed_collector():
    """Gen64 (exit 6): the standard collector's audit failed and both native observers
    failed for lack of an audit. Capture must rerun all of them in the early-boot order
    build/capture-exit6-gen64-20260928.py used, required steps first."""
    prefix = GEN[64]
    started = read(ROOT / 'build' / f'{prefix}-exit6-capture-v1.json')['started']
    with tempfile.TemporaryDirectory() as tmp:
        s = Scratch(tmp, [64], cutoff=started)
        history = historical_steps(prefix)
        plan = capture.plan(s.ws, prefix, manifest_path=write_manifest(s, 64))
        assert plan['report']['set'] == 'early-boot'
        assert plan['copies'] == [], 'the failed standard collector already copied its inputs'
        runner = Playback(s, prefix, {n: c for n, _, _, c in history})
        result = capture.execute(s.ws, plan, runner)
        assert [(r['name']) for r in runner.ran] == [n for n, _, _, _ in history], runner.ran
        cycle_commands_parse([r['command'] for r in runner.ran], prefix)
        assert [st['required'] for st in read(Path(result['record']))['steps']] == [r for _, r, _, _ in history]
        assert result['status'] == 'STOPPED_STATE_CAPTURED', result


def test_capture_exit9_runs_the_standard_collector_then_native_observers():
    """Gen63 (exit 9, nothing collected yet): the whole standard collector runs as one
    step with SNAP_STOPPED_EXIT=9, then native startup and crash retention, all required."""
    prefix = GEN[63]
    finished = read(ROOT / 'build' / f'{prefix}-launch.json')['finished']
    with tempfile.TemporaryDirectory() as tmp:
        s = Scratch(tmp, [63], cutoff=finished + 5)
        plan = capture.plan(s.ws, prefix, manifest_path=write_manifest(s, 63))
        assert [(st['name'], st['required']) for st in plan['steps']] == \
            [('primary', True), ('native-startup', True), ('crash-retention', True)]
        assert plan['copies'] == [], 'the standard collector does its own preflight'
        runner = Playback(s, prefix, {}, primary_log=ROOT / 'build' / f'{prefix}-sequence-primary-v1.log')
        result = capture.execute(s.ws, plan, runner)
        assert [r['name'] for r in runner.ran] == ['primary', 'native-startup', 'crash-retention']
        cycle_commands_parse([r['command'] for r in runner.ran], prefix)
        assert runner.ran[0]['env']['SNAP_STOPPED_EXIT'] == '9'
        assert result['status'] == 'STOPPED_STATE_CAPTURED', result


def test_exit12_needs_its_early_stop_record():
    """An early stop (exit 12) is a normal stopped guest, but only with the launcher's
    PREFIX-early-stop.json; capture records it."""
    prefix = GEN[66]
    with tempfile.TemporaryDirectory() as tmp:
        s = Scratch(tmp, [66])
        path = s.ws.prefixed(prefix, '-launch.json')
        record = read(path)
        record['exit_code'] = 12
        path.write_text(json.dumps(record))
        expect_refusal(lambda: evidence.Run(s.ws, prefix), 'early stop')
        stop = s.ws.prefixed(prefix, '-early-stop.json')
        stop.write_text(json.dumps(dict(outcome='stopped', source='guest', reason=1)))
        run = evidence.Run(s.ws, prefix)
        assert run.summary()['early_stop']['sha256'] == sha(stop) and run.summary()['stop'] == 'early stop'


# ----------------------------------------------------------------------------- preserve / retire

def gen66_before_preservation(tmp):
    cutoff = (ROOT / 'build' / f'{GEN[66]}-pre-reset-verification.json').stat().st_mtime
    return Scratch(tmp, [66], cutoff=cutoff)


def test_gen66_exit7_preserve_then_retire_with_graceful_quiesce():
    """The standard collectors completed after a monitor-refusal stop (exit 7): preserve
    binds them, retire verifies the parked stop, quiesces the GPU the run initialised,
    chainloads 0xb0800000 -> 0xb0000000 and confirms generation 67 idle - the same end
    state as the real gen66 retirement. Both outputs refuse reuse."""
    prefix = GEN[66]
    real = read(ROOT / 'build' / f'{prefix}-retirement-v1.json')
    with tempfile.TemporaryDirectory() as tmp:
        s = gen66_before_preservation(tmp)
        done = preserve.preserve(s.ws, prefix)
        saved = read(done['output'])
        assert saved['exit_code'] == 7 and saved['capture']['set'] == 'standard'
        assert all(v['state'] == 'complete' for v in saved['capture']['steps'].values())
        programs = {Path(p).name for p in saved['diagnosis']}
        assert {'collect-ca-memo-20260928.py', 'capture-ca-memo-ring-20260928.py',
                'capture-native-startup-gen66-20260928.py', 'capture-crash-retention-gen66-20260928.py'} <= programs
        assert 'GEN66-RESULT-20260928.md' in {Path(p).name for p in saved['documents']}
        expect_refusal(lambda: preserve.preserve(s.ws, prefix), 'reused output')
        ready = retire.retire(s.ws, prefix, done['sha256'], check=True)
        assert ready['status'] == 'READY' and ready['target_base'] == 0xb0000000
        run = evidence.Run(s.ws, prefix)
        s.a16(66, 0xb0800000, service=saved['service'], run=run)
        result = retire.retire(s.ws, prefix, done['sha256'])
        record = read(result['output'])
        log = s.a16_state()['log']
        assert log.count('a16gpu quiesce') == 1 and 'chainload 0xb0000000' in log
        assert record['status'] == real['status'] == 'GENERATION67_IDLE'
        assert record['after']['image_base'] == real['after']['image_base'] == 0xb0000000
        assert Path(record['chosen_stage']['path']).name == Path(real['chosen_stage']['path']).name
        assert record['quiesce_sha256'] == sha(s.ws.prefixed(prefix, '-quiesce-v1.json'))
        expect_refusal(lambda: retire.retire(s.ws, prefix, done['sha256'], check=True), 'reused output')


def test_idle_generation_inherits_the_graceful_quiesce():
    """Gen62 never initialised the GPU: retiring it must not run a16gpu (a quiesce of a
    GMU held in reset never reports graceful) and must bind gen61's graceful quiesce -
    the same bindings the hand-written retire-gen62-composite.py recorded."""
    prefix = GEN[61]
    real = read(ROOT / 'build/ca-composite-deploy-gen62-20260928/retirement-gen62-v1.json')
    with tempfile.TemporaryDirectory() as tmp:
        s = Scratch(tmp, [61])
        prior = s.ws.prefixed(prefix, '-retirement-v1.json')
        idle = dict(after_retirement=str(prior), retirement_sha256=sha(prior))
        label = 'ca-composite-deploy-gen62-20260928'
        apply_record = s.ws.build / label / 'apply-v1.json'
        plan = retire.retire(s.ws, label, check=True, idle=idle, binds=[apply_record])
        assert plan['kind'] == 'idle' and plan['gpu_writes'] is False
        s.a16(62, 0xb0800000)
        record = read(retire.retire(s.ws, label, idle=idle, binds=[apply_record])['output'])
        log = s.a16_state()['log']
        assert not any(e.startswith('a16gpu') for e in log) and 'chainload 0xb0000000' in log
        assert record['status'] == real['status'] == 'GENERATION63_IDLE'
        assert record['prior_retirement_sha256'] == real['prior_retirement_sha256']
        assert record['inherited_quiesce_sha256'] == real['inherited_quiesce_sha256']
        assert record['bound_sha256'][str(apply_record)] == real['apply_sha256']


def test_refusals():
    """Each refusal happens before any hardware write (no quiesce, no chainload)."""
    prefix = GEN[66]
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        s = gen66_before_preservation(tmp)
        done = preserve.preserve(s.ws, prefix)
        saved = read(done['output'])
        run = evidence.Run(s.ws, prefix)

        def untouched():
            log = s.a16_state()['log']
            assert not any(e.startswith(('a16gpu', 'chainload')) for e in log), log

        s.a16(65, 0xb0800000, service=saved['service'], run=run)
        rows.append(('wrong generation', expect_refusal(lambda: retire.retire(s.ws, prefix, done['sha256']),
                                                        'expected 66')))
        untouched()
        failed = s.ws.prefixed(prefix, '-retirement-v1.json')
        assert read(failed)['status'] == 'FAILED'
        for leftover in (failed, s.ws.prefixed(prefix, '-retirement-v1-tool')):
            shutil.rmtree(leftover) if leftover.is_dir() else leftover.unlink()
        s.a16(66, 0xb0000000, service=saved['service'], run=run)
        rows.append(('image base not the alternating slot',
                     expect_refusal(lambda: retire.retire(s.ws, prefix, done['sha256']), 'expected 66/EL2/0xb0800000')))
        untouched()
        for leftover in (failed, s.ws.prefixed(prefix, '-retirement-v1-tool')):
            shutil.rmtree(leftover) if leftover.is_dir() else leftover.unlink()
        s.ws.processes = lambda: {4242: (0.0, 1, 'python3 tools/run-ca-next-candidate.py --boot')}
        rows.append(('another hardware client', expect_refusal(lambda: retire.retire(s.ws, prefix, done['sha256']),
                                                               'another hardware client')))
        s.ws.processes = lambda: {}
        untouched()
        artifact = s.ws.prefixed(prefix, '-console-tail.json')
        original = artifact.read_bytes()
        artifact.write_bytes(original + b' ')
        rows.append(('changed input hash', expect_refusal(lambda: retire.retire(s.ws, prefix, done['sha256'], check=True),
                                                          f'{prefix}-console-tail.json changed')))
        artifact.write_bytes(original)
        rows.append(('wrong preservation hash', expect_refusal(
            lambda: retire.retire(s.ws, prefix, '0' * 64, check=True), 'preservation hash differs')))
        link_path = s.ws.local(run.launch['runtime_root']) / 'downloads'
        link_path.unlink()
        rows.append(('missing downloads link', expect_refusal(lambda: preserve.validate(s.ws, prefix),
                                                              'downloads is missing or not a symbolic link')))
        link_path.symlink_to('../Snapintosh/downloads')
    return sorted(name for name, _ in rows)


# ----------------------------------------------------------------------------- launch admission

def write_manifest(scratch, run_generation, **changes):
    """A manifest in the scratch workspace for an existing run (capture needs its display
    binding) or, with changes, for the next candidate."""
    data = read(GEN66_MANIFEST)
    previous = read(ROOT / 'build' / f'{GEN[run_generation]}-launch.json')['previous_stopped_prefix']
    data.update(prefix=GEN[run_generation], name=f'gen{run_generation}-test',
                predecessor=dict(data['predecessor'], prefix=previous))
    data.update(changes)
    path = scratch.ws.root / 'candidates' / f'{data["prefix"]}.json'
    path.write_text(json.dumps(data, indent=2))
    return path


def test_launch_admission_battery_generation_and_stage_pair():
    """The admission a candidate passes before any GPU write: the predecessor's cycle
    retirement and graceful quiesce, the live generation, and the battery policy
    (50% without AC by default since 2026-10-19, --battery-minimum between the floor of 50 and 100)."""
    prefix = GEN[66]
    with tempfile.TemporaryDirectory() as tmp:
        s = gen66_before_preservation(tmp)
        done = preserve.preserve(s.ws, prefix)
        run = evidence.Run(s.ws, prefix)
        s.a16(66, 0xb0800000, service=read(done['output'])['service'], run=run)
        retire.retire(s.ws, prefix, done['sha256'])
        predecessor = dict(prefix=prefix, retirement=s.ws.relative(s.ws.prefixed(prefix, '-retirement-v1.json')),
                           preservation=s.ws.relative(Path(done['output'])))
        manifest = launch.Manifest(s.ws, write_manifest(s, 66, prefix='installed-metal-ca-next-2400s-20260928',
                                                        generation=67, predecessor=predecessor))
        scope = dict(deployment_binding={})
        s.a16(67, 0xb0000000, battery=(0, True, False, 45))
        expect_refusal(lambda: launch.admit(s.ws, manifest, scope, common.battery_minimum(None)), 'battery below 50%')
        s.a16(67, 0xb0000000, battery=(0, True, False, 72))
        expect_refusal(lambda: launch.admit(s.ws, manifest, scope, common.battery_minimum(80)), 'battery below 80%')
        info, battery = launch.admit(s.ws, manifest, scope, common.battery_minimum(70))
        assert info['stage_generation'] == 67 and battery['required_minimum_without_ac'] == 70
        assert scope['deployment_binding']['preservation_sha256'] == done['sha256']
        expect_refusal(lambda: common.battery_minimum(40), 'outside 50..100')
        s.a16(66, 0xb0800000)
        expect_refusal(lambda: launch.admit(s.ws, manifest, scope, 50), 'expected 67')
        early = dict(read(manifest.path), stages={
            'q1n1-early-stop/build/uefi/q1n1-stage.bin': '31682994ea7df1858fab7247a82453818d63a0df1a0e118f3809880733775301',
            'q1n1-early-stop/build/uefi/q1n1-stage-alt.bin': 'e5de280843597c0318b688450cbc82a6a0bbe6c409dc616cc260c1d4b6c6d405'})
        manifest.path.write_text(json.dumps(early))
        expect_refusal(lambda: launch.admit(s.ws, launch.Manifest(s.ws, manifest.path), scope, 50), 'stage pair')


GEN70_MANIFEST = ROOT / 'candidates/gen70-integrated.json'


def validate_candidate(data):
    """launch.validate() and the offline admission for a manifest dict, in process,
    against the real workspace. validate() imports guestprofile and its siblings
    from the runtime root; they are dropped before and after so no other root's
    copies are reused."""
    runtime_modules = ('guestprofile', 'trustcache', 'auxkc', 'nvram', 'adreno', 'appledt')
    saved = list(sys.path)
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'candidate.json'
        path.write_text(json.dumps(data))
        for name in runtime_modules:
            sys.modules.pop(name, None)
        try:
            ws = Workspace(ROOT)
            manifest = launch.Manifest(ws, path)
            scope = {}
            candidate, old, arguments, settings = launch.validate(ws, manifest, scope)
            idle = launch.admit_records(ws, manifest, scope)
            return dict(old=old, binding=scope['deployment_binding'], arguments=arguments, settings=settings,
                        candidate=candidate, idle=idle)
        finally:
            sys.path[:] = saved
            for name in runtime_modules:
                sys.modules.pop(name, None)


def test_gen70_explicit_auxkc_and_ssd_installed_after_baseline():
    """A candidate whose AuxKC and installed SSD differ from its baseline launch's names
    both explicitly (`auxkc`, `ssd.after_baseline`); the launch record then carries
    what this boot loads and expects. Each explicit fact is checked: dropping or
    bending one refuses instead of falling back to the baseline's values."""
    if not GEN70_MANIFEST.is_file():
        return dict(skipped='no candidates/gen70-integrated.json')
    good = read(GEN70_MANIFEST)
    result = validate_candidate(good)
    ws = Workspace(ROOT)
    old, binding = result['old'], result['binding']
    package = read(ws.path(good['ssd']['package']))
    assert result['idle'] == 70
    assert (old['auxkc'], old['auxkc_sha256'], old['kext_sha256']) == \
        (str(ws.path(good['auxkc']['path'])), good['auxkc']['sha256'], good['kext_sha256'])
    assert old['expected_window_header_sha256'] == package['header_after_sha256'] != binding['baseline_window_header_sha256']
    assert old['ssd_apply_record'] == str(ws.path(good['ssd']['apply_record']))
    assert old['storage_snapshot_generation'] == 69
    assert (binding['collection_sha256'], binding['kext_sha256'], binding['network_qualification_sha256']) == \
        (good['auxkc']['sha256'], good['auxkc']['kext_sha256'], good['auxkc']['qualification_sha256'])
    assert binding['staged_collection_sha256'] != binding['collection_sha256']
    assert result['settings']['SNAP_EARLY_STOP'] == 'guest,host'

    def refused(change, text):
        data = json.loads(json.dumps(good))
        change(data)
        expect_refusal(lambda: validate_candidate(data), text)

    def drop_auxkc(d):
        del d['auxkc']
    refused(drop_auxkc, 'AuxKC differs')
    refused(lambda d: d['auxkc'].update(sha256='0' * 64), 'is missing or not')
    network = 'Snapintosh-adreno-buffer-textures/build/ca-network-qualification-20260928-v2.json'
    refused(lambda d: d['auxkc'].update(qualification=network, qualification_sha256=sha(ws.path(network))),
            'name another collection')
    refused(lambda d: d['arguments'].pop('--auxkc'), 'argument AuxKC')

    def drop_after(d):
        del d['ssd']['after_baseline']
    refused(drop_after, 'SSD package differs')
    earlier = 'Snapintosh-shaders/build/shader-cache-deploy-20260928/local-stage-v1/stage.json'
    refused(lambda d: d['ssd']['after_baseline'].update(local_stage=earlier), 'named snapshot and stage')
    refused(lambda d: d['ssd'].update(apply_generation=70), 'SSD apply generation')
    # Admission: the idle generation must have been reached after that apply and
    # its retirement must bind the apply record.
    from types import SimpleNamespace
    manifest = launch.Manifest(ws, GEN70_MANIFEST)
    other = 'Snapintosh/build/ca-composite-deploy-gen62-20260928/apply-v1.json'
    for ssd, text in ((dict(manifest.ssd, apply_generation=70), 'not before the idle generation'),
                      (dict(manifest.ssd, apply_record=other), 'does not bind the SSD apply record')):
        bent = SimpleNamespace(**dict(vars(manifest), ssd=ssd))
        expect_refusal(lambda: launch.admit_records(ws, bent, dict(deployment_binding={})), text)
    return dict(refusals=9)


GEN71_MANIFEST = ROOT / 'candidates/gen71-integrated-regular.json'


def before_retirement(prefix):
    """Copy cutoff that leaves out a real retirement of this prefix (and anything after it)."""
    real = ROOT / 'build' / f'{prefix}-retirement-v1.json'
    return read(real)['started'] if real.is_file() else None


def test_loader_failure_before_the_guest_is_retired_with_a_graceful_quiesce():
    """Generation70 prepared the GPU, then its loader refused native Image4 (exit 2)
    before the upload: no guest ran. --loader-failure binds the launch record, boot log,
    GPU preparation and SSD apply records, quiesces the GPU gracefully, chainloads the
    regular pair and confirms generation 71 idle; the gen71 candidate's admission
    accepts that retirement (stage pair and SSD apply binding included)."""
    prefix = GEN[70]
    with tempfile.TemporaryDirectory() as tmp:
        s = Scratch(tmp, [70], cutoff=before_retirement(prefix))
        expect_refusal(lambda: retire.retire(s.ws, prefix, check=True), 'not a stopped guest')
        ready = retire.retire(s.ws, prefix, check=True, pre_guest=True)
        assert ready['kind'] == 'loader-failure' and ready['exit_code'] == 2
        assert ready['loader_verdict'] == 'native Image4 refused: resident stage differs from its ELF'
        assert ready['no_guest']['verdicts'] == ['== LOADER FAILURE (exit 2) ==']
        s.a16(70, 0xb0800000)
        record = read(retire.retire(s.ws, prefix, pre_guest=True)['output'])
        log = s.a16_state()['log']
        assert log.count('a16gpu quiesce') == 1 and 'chainload 0xb0000000' in log
        assert record['status'] == 'GENERATION71_IDLE' and record['after']['image_base'] == 0xb0000000
        assert record['chosen_stage']['sha256'] == common.PINS['stages']['q1n1/build/uefi/q1n1-stage.bin']
        assert record['quiesce_sha256'] == sha(s.ws.prefixed(prefix, '-quiesce-v1.json'))
        bound = {Path(k).name: v for k, v in record['bound_sha256'].items()}
        for suffix in ('-launch.json', '-boot.log', '-prepare.log', '-adopt.json'):
            assert bound[prefix + suffix] == sha(ROOT / 'build' / (prefix + suffix)), suffix
        assert bound[f'{prefix}-fence.json'] == sha(REAL / 'q1n1/build/a16-gpu' / f'{prefix}-fence.json')
        assert bound['apply-v1.json'] == read(ROOT / 'build' / f'{prefix}-launch.json')['ssd_apply_record_sha256']
        manifest = launch.Manifest(s.ws, GEN71_MANIFEST)
        assert launch.admit_records(s.ws, manifest, dict(deployment_binding={})) == 71


def test_loader_failure_refusals():
    """A loader-failure retirement refuses a boot log that reached the upload, a record
    written at the monitor call, an exit that is not a loader failure, a wrong live
    generation (before any GPU write) and a quiesce that is not graceful (before the
    chainload)."""
    prefix = GEN[70]
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        s = Scratch(tmp, [70], cutoff=before_retirement(prefix))
        attempt = lambda: retire.retire(s.ws, prefix, check=True, pre_guest=True)
        boot_log = s.ws.prefixed(prefix, '-boot.log')
        original = boot_log.read_text()
        boot_log.write_text(original.replace('\n== LOADER FAILURE', '\n  uploaded in 11.2s\n== LOADER FAILURE'))
        rows.append(('boot log reached the upload', expect_refusal(attempt, 'shows the upload or the guest run')))
        boot_log.write_text(original)
        entered = s.ws.prefixed(prefix, '-result.json')
        entered.write_text('{}')
        rows.append(('record written at the monitor call', expect_refusal(attempt, 'reached the monitor call')))
        entered.unlink()
        path = s.ws.prefixed(prefix, '-launch.json')
        text = path.read_text()
        path.write_text(json.dumps(dict(json.loads(text), exit_code=9)))
        rows.append(('not a loader exit', expect_refusal(attempt, 'not a pre-guest loader exit')))
        path.write_text(text)
        out = retire.outputs(s.ws, prefix)

        def clear():
            for leftover in out.values():
                shutil.rmtree(leftover) if leftover.is_dir() else leftover.unlink(missing_ok=True)

        s.a16(71, 0xb0000000)
        rows.append(('wrong generation', expect_refusal(lambda: retire.retire(s.ws, prefix, pre_guest=True),
                                                        'expected 70/0xb0800000')))
        assert not any(e.startswith(('a16gpu', 'chainload')) for e in s.a16_state()['log'])
        assert read(out['record'])['status'] == 'FAILED'
        clear()
        s.a16(70, 0xb0800000, quiesce='graceful path failed (Q1): forcing off')
        rows.append(('quiesce not graceful', expect_refusal(lambda: retire.retire(s.ws, prefix, pre_guest=True),
                                                            'not graceful')))
        log = s.a16_state()['log']
        assert log.count('a16gpu quiesce') == 1 and not any(e.startswith('chainload') for e in log)
        clear()
    return sorted(name for name, _ in rows)


def test_gen71_redecode_completes_service_profile_and_step_runs_only_metal_probe():
    """Gen71 (exit 9): the standard collector's service profile failed in the runtime
    root's old decoder, a newer committed decoder re-read it (redecode binding), and the
    early-boot set captured the rest but not metal-probe. The verified redecode completes
    the service profile and names its decoder; `--step metal-probe` runs that step and
    nothing else; preserve records the decoder; retire reaches generation72."""
    prefix = GEN[71]
    with tempfile.TemporaryDirectory() as tmp:
        s = Scratch(tmp, [71], cutoff=before_retirement(prefix))
        run = evidence.Run(s.ws, prefix)
        states = {st['name']: st for st in evidence.assess(run)['steps']}
        binding = read(REAL / 'Snapintosh-gen70/build' / f'{prefix}-service-profile-redecode-v1-binding.json')
        assert states['service-profile']['state'] == 'complete'
        assert states['service-profile']['redecode']['decoder_commit'] == binding['decoder_commit']
        assert [n for n, st in states.items() if st['state'] != 'complete'] == ['metal-probe']
        expect_refusal(lambda: preserve.validate(s.ws, prefix), 'metal-probe:missing')
        for done in ('audit', 'service-profile', 'console-tail'):
            expect_refusal(lambda done=done: capture.plan(s.ws, prefix, only=done), f'{done} is complete')
        expect_refusal(lambda: capture.plan(s.ws, prefix, only='no-such-step'), 'is not a step of the standard set')
        plan = capture.plan(s.ws, prefix, only='metal-probe')
        assert [st['name'] for st in plan['steps']] == ['metal-probe']
        runner = Playback(s, prefix, {}, stand_in={'metal-probe': ROOT / 'build' / f'{GEN[66]}-metal-probe.json'})
        result = capture.execute(s.ws, plan, runner)
        assert [r['name'] for r in runner.ran] == ['metal-probe'] and runner.ran[0]['env']['SNAP_STOPPED_EXIT'] == '9'
        assert result['status'] == 'STOPPED_STATE_CAPTURED', result
        assert s.ws.prefixed(prefix, '-service-profile-redecode-v1-binding.json').is_file(), 'copied back'
        done = preserve.preserve(s.ws, prefix)
        saved = read(done['output'])
        assert saved['capture']['steps']['service-profile']['redecode']['decoder_sha256'] == binding['decoder_sha256']
        assert [Path(p).name for p in saved['decoders']] == ['kernel_ops_perf.py']
        assert f'{prefix}-service-profile-redecode-v1.json' in {Path(p).name for p in saved['artifacts']}
        s.a16(71, 0xb0000000, service=saved['service'], run=run)
        record = read(retire.retire(s.ws, prefix, done['sha256'])['output'])
        assert record['status'] == 'GENERATION72_IDLE' and record['after']['image_base'] == 0xb0800000
        assert s.a16_state()['log'].count('a16gpu quiesce') == 1


def test_redecode_binding_refusals():
    """A redecode completes the service profile only when its binding names this run's
    audit, its output is unchanged, it used the standard service-profile arguments and
    its decoder is exactly the committed version it names."""
    prefix = GEN[71]
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        s = Scratch(tmp, [71])
        path = s.ws.local(REAL / 'Snapintosh-gen70/build' / f'{prefix}-service-profile-redecode-v1-binding.json')
        original = path.read_text()
        attempt = lambda: evidence.assess(evidence.Run(s.ws, prefix))
        for name, change, text in (
                ('another audit', lambda b: b.update(audit_sha256='0' * 64), 'bound to another audit'),
                ('other arguments', lambda b: b['arguments'].remove('--user-tree-memo'),
                 'did not use the standard service-profile arguments'),
                ('decoder not at its commit', lambda b: b.update(decoder_commit='d2e4731'), 'not the committed')):
            bent = json.loads(original)
            change(bent)
            path.write_text(json.dumps(bent))
            rows.append((name, expect_refusal(attempt, text)))
            path.write_text(original)
        output = path.with_name(f'{prefix}-service-profile-redecode-v1.json')
        kept = output.read_bytes()
        output.write_bytes(kept + b' ')
        rows.append(('output changed', expect_refusal(attempt, 'changed or missing')))
        output.write_bytes(kept)
        assert {st['name']: st['state'] for st in attempt()['steps']}['service-profile'] == 'complete'
    return sorted(name for name, _ in rows)


def test_reader_substitution_interposer():
    """install() serves the committed text for exactly one runtime file: run_path runs it
    compiled as that file, read_text returns it; read_bytes (hash pins) and every other
    file stay the originals."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / 'tools').mkdir()
        target, other = tmp / 'tools/reader.py', tmp / 'tools/other.py'
        target.write_text("MARK = 'old'\n")
        other.write_text("MARK = 'other'\n")
        uses = substitute.install(target, "MARK = 'new'\nSEEN = __file__\n")
        try:
            import runpy
            ran = runpy.run_path(str(target), run_name='__main__')
            assert ran['MARK'] == 'new' and ran['SEEN'] == str(target.resolve()) and ran['__name__'] == '__main__'
            assert runpy.run_path(str(other))['MARK'] == 'other'
            assert target.read_text() == "MARK = 'new'\nSEEN = __file__\n" and other.read_text() == "MARK = 'other'\n"
            assert target.read_bytes() == b"MARK = 'old'\n"
            assert (uses['run_path'], uses['read_text']) == (1, 1)
        finally:
            uses['restore']()
        assert target.read_text() == "MARK = 'old'\n"


def test_gen76_reader_substitution():
    """Gen76 (exit 12): the runtime root's capture-kernel-waits.py refused the native
    tables' variant copies. With --replace, the three collector steps and the two
    observers that run that reader run the committed fix; nothing else changes. The
    capture record binds the substitution; assess and preserve re-verify it."""
    prefix = GEN[76]
    fixed = REAL / 'Snapintosh-native-tables-2b/tools/capture-kernel-waits.py'
    commit = subprocess.run(['git', '-C', str(fixed.parent), 'log', '-1', '--format=%H', '--',
                             'capture-kernel-waits.py'], capture_output=True, text=True, check=True).stdout.strip()
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        # The records as they were before the real --replace capture (attempt 4).
        s = Scratch(tmp, [76], cutoff=before_capture(prefix, 4))
        spec = f'tools/capture-kernel-waits.py={fixed}@{commit}'
        plan = capture.plan(s.ws, prefix, replace=spec)
        substituted = sorted(st['name'] for st in plan['steps'] if st.get('substituted'))
        assert substituted == ['crash-retention', 'kernel-waits', 'metal-probe', 'mounts', 'native-startup'], substituted
        b = plan['substitution']
        assert b['replaced_sha256'] == sha(s.ws.local(read(ROOT / 'build' / f'{prefix}-launch.json')['runtime_root'])
                                           / 'tools/capture-kernel-waits.py') and b['commit'] == commit
        described = capture.describe(plan)
        kernel = next(st for st in described['steps'] if st['name'] == 'kernel-waits')
        assert kernel['command'][2:4] == ['substituted', '--launch'] and '--replace' in kernel['command']
        native = next(st for st in described['steps'] if st['name'] == 'native-startup')
        assert native['command'][native['command'].index('--replace') + 1] == spec
        # Refusals before anything runs.
        for name, bad, text in (
                ('not allowed', spec.replace('capture-kernel-waits.py=', 'capture-console-tail.py=', 1), 'may not be replaced'),
                ('other commit', spec.replace(commit, '357b01e'), 'not the committed'),
                ('malformed', spec.replace('@', '#'), 'PATH=FILE@COMMIT'),
                ('the runtime file', f'tools/capture-kernel-waits.py={plan["run"].runtime}/tools/capture-kernel-waits.py@{commit}',
                 'runtime root')):
            rows.append((name, expect_refusal(lambda bad=bad: capture.plan(s.ws, prefix, replace=bad), text)))
        # One substituted step, played back: the record carries the binding.
        only = capture.plan(s.ws, prefix, only='kernel-waits', replace=spec)
        runner = Playback(s, prefix, {}, stand_in={'kernel-waits': ROOT / 'build' / f'{GEN[71]}-kernel-waits.json'})
        result = capture.execute(s.ws, only, runner)
        record = read(result['record'])
        assert record['substitution'] == b and record['steps'][0]['substituted'] == 'tools/capture-kernel-waits.py'
        assert runner.ran[0]['command'][2] == 'substituted'
        report = evidence.assess(evidence.Run(s.ws, prefix))
        assert report['substitutions'] == [b]
        assert {st['name']: st['state'] for st in report['steps']}['kernel-waits'] == 'complete'
        run = evidence.Run(s.ws, prefix)
        assert [Path(p) for p in preserve.groups(s.ws, run, report)['readers']] == [s.ws.local(b['file'])]
        # The binding is re-verified: a changed runtime file or record refuses.
        runtime_file = run.runtime / 'tools/capture-kernel-waits.py'
        materialize(runtime_file)
        kept = runtime_file.read_bytes()
        runtime_file.unlink()
        runtime_file.write_bytes(kept + b'\n')
        rows.append(('runtime file changed', expect_refusal(lambda: evidence.assess(evidence.Run(s.ws, prefix)),
                                                             'runtime root\'s file changed')))
        runtime_file.write_bytes(kept)
        path = Path(result['record'])
        original = path.read_text()
        for name, change, text in (('other audit', lambda r: r['substitution'].update(audit_sha256='0' * 64), 'another audit'),
                                   ('other file hash', lambda r: r['substitution'].update(file_sha256='0' * 64), 'changed since')):
            bent = json.loads(original)
            change(bent)
            path.write_text(json.dumps(bent))
            rows.append((name, expect_refusal(lambda: evidence.assess(evidence.Run(s.ws, prefix)), text)))
        path.write_text(original)
        assert evidence.assess(evidence.Run(s.ws, prefix))['substitutions'] == [b]
    return sorted(name for name, _ in rows)


def before_capture(prefix, attempt):
    """The start of a run's cycle capture attempt `attempt` (a Scratch cutoff that keeps
    the records as they were before it), or None while that attempt does not exist."""
    record = ROOT / 'build' / f'{prefix}-cycle-capture-v{attempt}.json'
    return read(record)['started'] if record.is_file() else None


def launched_manifest(prefix):
    """The launched bytes of a run's candidate manifest, found in git by the launch record's hash."""
    cycle = read(ROOT / 'build' / f'{prefix}-launch.json')['compiler_deployment']['cycle']
    for commit, digest in substitute._history(Path(cycle['manifest']), 'HEAD'):
        if digest == cycle['manifest_sha256']:
            return subprocess.run(['git', '-C', str(ROOT), 'show', f'{commit}:{Path(cycle["manifest"]).relative_to(ROOT)}'],
                                  capture_output=True, check=True).stdout
    raise AssertionError('launched manifest not in git history')


def observe_offline(ws, prefix, kind, manifest):
    """One rendered observer run in-process through its whole chain in --syntax-only
    mode: every pin check and compile, then a return before any hardware access."""
    import io
    from contextlib import redirect_stdout
    args = argparse.Namespace(kind=kind, launch=prefix, candidate=str(manifest), replace=None,
                              rest=['--syntax-only', '--attempt', 'offline'])
    saved, out = (list(sys.argv), list(sys.path)), io.StringIO()
    try:
        with redirect_stdout(out):
            observers.observe(ws, args)
    finally:
        sys.argv[:], sys.path[:] = saved
    return out.getvalue()


def test_gen77_accepted_reader():
    """Gen77 (exit 12): its runtime root's capture-kernel-waits.py is the committed fix,
    which the native observers' chain pins at its older version, so native-startup
    refused before any read. Offline, the chain refuses the same way; with the launched
    manifest amended by observers.readers, both observers pass every pin check and
    compile. The acceptance needs the declared hash, that commit's exact file and descent
    from the pinned version; capture records bind it, assess and preserve re-verify it."""
    prefix = GEN[77]
    runtime = REAL / Path(read(ROOT / 'build' / f'{prefix}-launch.json')['runtime_root']).name
    reader = 'tools/capture-kernel-waits.py'
    commit = subprocess.run(['git', '-C', str(runtime), 'log', '-1', '--format=%H', '--', reader],
                            capture_output=True, text=True, check=True).stdout.strip()
    declared = {reader: dict(sha256=sha(runtime / reader), commit=commit)}
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        # The records as they were after the first capture (attempt 1) refused.
        s = Scratch(tmp, [77], cutoff=before_capture(prefix, 2))
        git = lambda *a: subprocess.run(['git', '-C', str(s.ws.root / 'candidates'), '-c', 'user.name=t',
                                         '-c', 'user.email=t@t', *a], capture_output=True, check=True)
        path = s.ws.root / 'candidates/gen77-native-2a.json'
        path.write_bytes(launched_manifest(prefix))
        git('init', '-q')
        git('add', path.name)
        git('commit', '-q', '-m', 'launched')
        # Without a declaration: nothing is accepted and the chain refuses as gen77 did.
        plan = capture.plan(s.ws, prefix, manifest_path=path)
        assert plan['readers'] == [] and [st['name'] for st in plan['steps']] == ['native-startup', 'crash-retention']
        plain = observers.rendered(s.ws, plan['params'])
        try:
            observe_offline(s.ws, prefix, 'native', path)
        except AssertionError as error:
            assert str(error) == reader, error
        else:
            raise AssertionError('the chain accepted an unpinned reader')
        # The launched manifest amended by exactly observers.readers.
        launched = json.loads(path.read_text())
        amended = json.loads(path.read_text())
        amended['observers']['readers'] = declared
        path.write_text(json.dumps(amended, indent=2) + '\n')
        plan = capture.plan(s.ws, prefix, manifest_path=path)
        b, = plan['readers']
        assert (b['path'], b['sha256'], b['commit'], b['declared_by']) == (reader, declared[reader]['sha256'], commit,
                                                                           'amended manifest')
        assert b['pinned_sha256'] == observers.READER_PINS[reader][2] and b['changed_by'] == [commit]
        assert b['amendment']['launched_manifest_sha256'] == sha_bytes(launched_manifest(prefix))
        assert sha(runtime / reader) != b['pinned_sha256'] and json.loads(json.dumps(capture.describe(plan)))['readers'] == [b]
        rendered = observers.rendered(s.ws, plan['params'])
        # The crash program runs the rendered native text (NATIVE_SOURCE), hashed as 'native'.
        assert {k for k in rendered if rendered[k] != plain[k]} == {'native'}, rendered
        for kind in ('native', 'crash'):
            text = observe_offline(s.ws, prefix, kind, path)
            assert 'Generation77 native startup observer compiles; no hardware access' in text, (kind, text)
        # Refusals before anything runs.
        good = path.read_text()

        def amend(change):
            data = json.loads(good)
            change(data)
            path.write_text(json.dumps(data))
            return lambda: capture.plan(s.ws, prefix, manifest_path=path)
        other = subprocess.run(['git', '-C', str(runtime), 'log', '-1', '--format=%H', f'{commit}~1', '--', reader],
                               capture_output=True, text=True, check=True).stdout.strip()
        for name, change, text in (
                ('other hash', lambda d: d['observers']['readers'][reader].update(sha256='0' * 64), 'not the declared'),
                ('other commit', lambda d: d['observers']['readers'][reader].update(commit=other), 'commit'),
                ('no commit', lambda d: d['observers']['readers'][reader].update(commit='0' * 40), 'not in the runtime root'),
                ('extra key', lambda d: d['observers']['readers'][reader].update(about='x'), 'exactly sha256 and commit'),
                ('unpinned path', lambda d: d['observers']['readers'].update({'tools/capture-console-tail.py': {}}),
                 'pin no reader'),
                ('more than readers', lambda d: d.update(about='amended'), 'changed beyond observers.readers')):
            rows.append((name, expect_refusal(amend(change), text)))
        path.write_text(good)
        pins = observers.READER_PINS[reader]
        observers.READER_PINS[reader] = (*pins[:2], '0' * 64)
        try:
            rows.append(('no descent', expect_refusal(lambda: capture.plan(s.ws, prefix, manifest_path=path),
                                                      'does not descend from the pinned version')))
        finally:
            observers.READER_PINS[reader] = pins
        (s.ws.root / 'candidates/.git').rename(s.ws.root / 'candidates/.git-off')
        rows.append(('launched version unknown', expect_refusal(lambda: capture.plan(s.ws, prefix, manifest_path=path),
                                                                'not in its git history')))
        (s.ws.root / 'candidates/.git-off').rename(s.ws.root / 'candidates/.git')
        # One observer step run (by a stand-in runner): the record binds the acceptance.
        only = capture.plan(s.ws, prefix, manifest_path=path, only='native-startup')
        ran = []

        def runner(command, cwd, env, log):
            ran.append(command)
            log.write_text('stand-in\n')
            return 0
        result = capture.execute(s.ws, only, runner)
        record = read(result['record'])
        assert record['readers'] == [b] and record['observers'] == rendered
        assert ran[0][ran[0].index('--candidate') + 1] == str(path)
        run = evidence.Run(s.ws, prefix)
        report = evidence.assess(run)
        assert report['readers'] == [b]
        assert preserve.groups(s.ws, run, report)['readers'] == [s.ws.local(b['runtime_root']) / reader, path]
        # Re-verified on every read.
        path.write_text(good.replace('"readers"', '"readers" ', 1))
        rows.append(('manifest changed', expect_refusal(lambda: evidence.assess(evidence.Run(s.ws, prefix)),
                                                        'changed since')))
        path.write_text(good)
        record_path = Path(result['record'])
        kept = record_path.read_text()
        bent = json.loads(kept)
        bent['readers'][0]['pinned_commit'] = commit
        record_path.write_text(json.dumps(bent))
        rows.append(('record bent', expect_refusal(lambda: evidence.assess(evidence.Run(s.ws, prefix)),
                                                   'no longer holds')))
        record_path.write_text(kept)
        assert evidence.assess(evidence.Run(s.ws, prefix))['readers'] == [b]
        assert launched['observers'] == read(ROOT / 'build' / f'{prefix}-launch.json')['compiler_deployment']['cycle']['observers']
    return sorted(name for name, _ in rows)


def test_gen78_unqualified_stop_preserved_and_retired():
    """Gen78 (exit 7): the monitor refused SWITCH_ROOT and the runtime root's own audit
    then refused the stop ('native shared counters disagree'), correctly. capture
    --unqualified records that refusal, the boot log's terminal event, the evidence
    (a diagnosis in build/ and the committed tool that wrote it) and a read-only witness
    of the parked stop; preserve --unqualified keeps qualified false with the witness's
    service words; retire verifies the live stop against them and reaches generation 79.
    Each binding is re-verified, and the run can never be a baseline."""
    prefix = GEN[78]
    tool = REAL / 'Snapintosh-native-tables-3b/tools/diagnose-native-shared-stop.py'
    commit = subprocess.run(['git', '-C', str(tool.parent), 'log', '-1', '--format=%H', '--', tool.name],
                            capture_output=True, text=True, check=True).stdout.strip()
    service = [0, 3, common.PARKED_SERVICE_WORD, 0, 0, 0, 0, 0]
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        s = Scratch(tmp, [78], cutoff=before_capture(prefix, 2))
        diagnosis = s.ws.prefixed(prefix, '-native-shared-diagnosis-v1.json')
        diagnosis.write_text(json.dumps(dict(header=dict(live=512, errors=1))))
        evidence_specs = [str(diagnosis), f'{tool}@{commit}']
        # Nothing to record without evidence; the standard capture still cannot complete.
        rows.append(('no evidence', expect_refusal(lambda: unqualified.record(s.ws, prefix, []), '--evidence')))
        plan = unqualified.record(s.ws, prefix, evidence_specs, check=True)
        assert plan['status'] == 'UNQUALIFIED_PLAN' and plan['refusal']['refusal'] == \
            'ValueError: native shared counters disagree' and plan['refusal']['exit_code'] == 1
        assert plan['terminal']['last_event'].startswith('mapping references rejected pc 0xfffffe000c22b6d4')
        assert plan['terminal']['verdict'] == '== UNSUPPORTED OPERATION (exit 7) =='
        run = evidence.Run(s.ws, prefix)
        s.a16(79, 0xb0000000, service=service, run=run)
        rows.append(('witness at another generation', expect_refusal(
            lambda: unqualified.record(s.ws, prefix, evidence_specs), 'expected 78/EL2/0xb0800000')))
        for stale in s.ws.build.glob(f'{prefix}-cycle-capture-v*.json'):
            if read(stale).get('kind') == 'unqualified':
                stale.unlink()      # the refused witness left a FAILED record; start again
        s.a16(78, 0xb0800000, service=service, run=run)
        done = unqualified.record(s.ws, prefix, evidence_specs)
        rec = read(done['record'])
        assert rec['status'] == unqualified.STATUS and rec['qualified'] is False
        assert rec['witness']['service'] == service and [e.get('commit') for e in rec['evidence']] == [None, commit]
        rows.append(('recorded twice', expect_refusal(lambda: unqualified.record(s.ws, prefix, evidence_specs),
                                                      'already has a recorded unqualified stop')))
        # A candidate naming this run as its baseline is refused.
        data = json.loads(launched_manifest(GEN[77]))
        launch78 = read(s.ws.prefixed(prefix, '-launch.json'))
        data.update(prefix='installed-metal-after-unqualified-test', baseline_launch=dict(
            data['baseline_launch'], prefix=prefix, sha256=sha(s.ws.prefixed(prefix, '-launch.json')), generation=78,
            exit_code=7, runtime_root='Snapintosh-native-tables-3', context_bytes=launch78['context_bytes'],
            context_fields=launch78['context_fields'], monitor_sha256=launch78['monitor_sha256']))
        candidate = s.ws.root / 'candidates/after-unqualified.json'
        candidate.write_text(json.dumps(data))
        rows.append(('baseline', expect_refusal(lambda: launch.validate(s.ws, launch.Manifest(s.ws, candidate), {}),
                                                'can never be a baseline')))
        # The standard preservation still refuses; the unqualified one preserves.
        expect_refusal(lambda: preserve.preserve(s.ws, prefix), 'capture incomplete')
        kept = diagnosis.read_bytes()
        diagnosis.write_bytes(kept + b' ')
        rows.append(('evidence changed', expect_refusal(lambda: preserve.preserve(s.ws, prefix, unqualified=True),
                                                        'changed since')))
        diagnosis.write_bytes(kept)
        saved_done = preserve.preserve(s.ws, prefix, unqualified=True)
        saved = read(saved_done['output'])
        assert saved['qualified'] is False and saved['status'] == 'GEN78_UNQUALIFIED_STOP_PRESERVED'
        assert saved['service'] == service and saved['audit_sha256'] is None
        assert saved['unqualified']['record_sha256'] == sha(done['record'])
        assert any(Path(k).resolve() == tool.resolve() for k in saved['diagnosis']), sorted(saved['diagnosis'])[-3:]
        assert any(Path(k).resolve() == diagnosis.resolve() for k in saved['artifacts'])
        # Retirement verifies the live stop against the witness and reaches generation 79.
        ready = retire.retire(s.ws, prefix, saved_done['sha256'], check=True)
        assert ready['status'] == 'READY' and ready['qualified'] is False and ready['target_base'] == 0xb0000000
        s.a16(78, 0xb0800000, service=[0, 4, common.PARKED_SERVICE_WORD, 0, 0, 0, 0, 0], run=run)
        rows.append(('live stop differs', expect_refusal(lambda: retire.retire(s.ws, prefix, saved_done['sha256']),
                                                         'live service words differ')))
        for stale in s.ws.build.glob(f'{prefix}-retirement*'):
            shutil.rmtree(stale) if stale.is_dir() else stale.unlink()
        s.a16(78, 0xb0800000, service=service, run=run)
        result = retire.retire(s.ws, prefix, saved_done['sha256'])
        record = read(result['output'])
        assert record['status'] == 'GENERATION79_IDLE' and record['qualified'] is False
        assert 'chainload 0xb0000000' in s.a16_state()['log']
    return sorted(name for name, _ in rows)


TESTS = [test_rendered_observers_equal_generation_wrappers, test_gen66_manifest_reproduces_run_ca_memo_candidate,
         test_storage_reproduces_gen66_adapter, test_capture_continues_gen65_like_its_completion_sequencer,
         test_capture_runs_gen64_early_boot_set_after_failed_collector,
         test_capture_exit9_runs_the_standard_collector_then_native_observers, test_exit12_needs_its_early_stop_record,
         test_gen66_exit7_preserve_then_retire_with_graceful_quiesce, test_idle_generation_inherits_the_graceful_quiesce,
         test_refusals, test_launch_admission_battery_generation_and_stage_pair,
         test_gen70_explicit_auxkc_and_ssd_installed_after_baseline,
         test_loader_failure_before_the_guest_is_retired_with_a_graceful_quiesce, test_loader_failure_refusals,
         test_gen71_redecode_completes_service_profile_and_step_runs_only_metal_probe, test_redecode_binding_refusals,
         test_reader_substitution_interposer, test_gen76_reader_substitution, test_gen77_accepted_reader,
         test_gen78_unqualified_stop_preserved_and_retired]


def fingerprint():
    """(size, mtime) of every real file the tests copy from: the tested generations'
    records in build/ and in their runtime roots."""
    out = {}
    for prefix in GEN.values():
        runtime = Path(read(ROOT / 'build' / f'{prefix}-launch.json')['runtime_root']) / 'build'
        for directory in (ROOT / 'build', runtime):
            for p in directory.glob(prefix + '*'):
                if p.is_file():
                    st = p.stat()
                    out[str(p)] = (st.st_size, st.st_mtime_ns)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('-k', help='run tests whose name contains this')
    args = ap.parse_args()
    before = fingerprint()
    failures = 0
    for test in TESTS:
        if args.k and args.k not in test.__name__:
            continue
        started = time.time()
        try:
            detail = test()
            print(f'PASS {test.__name__} ({time.time() - started:.1f} s)' + (f' {json.dumps(detail)}' if detail else ''),
                  flush=True)
        except (Exception, SystemExit):
            failures += 1
            print(f'FAIL {test.__name__}', flush=True)
            traceback.print_exc()
    if fingerprint() != before:
        failures += 1
        print('FAIL a real record of a tested generation changed during the tests', flush=True)
    print(f'{len(TESTS) - failures if not args.k else "selected"} passed, {failures} failed', flush=True)
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
