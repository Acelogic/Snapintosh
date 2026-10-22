# SPDX-License-Identifier: MIT
"""A stopped run as its records describe it, and what its collectors already captured.

load_run() checks the launch record against the files it pins. assess() reads every
place a stopped-state step can have left a result (the standard collector's log,
the native observers' logs and bindings, exit-6 sequencer records, earlier cycle
capture records) and says, for each step of the capture set, whether it is
complete, finally refused, or still to run.
"""
from pathlib import Path
import json
import subprocess

from .common import (PINS, STOPPED_EXITS, need, sha, matches, read, image_base, host_absent,
                     downloads_pinned, context_layout)

# The standard collector's order (collect-auxkc -> installed-metal -> metal-gui), then
# the two native observers. Every step but the AuxKC verdict is required.
STANDARD = ['audit', 'cpu-stop', 'service-profile', 'kernel-waits', 'verdict', 'panel', 'mounts',
            'metal-probe', 'console-tail', 'ring', 'native-startup', 'crash-retention']
# Generation64's early-boot set: required steps first, then recorded-only ones, each run
# whatever happened before it (build/capture-exit6-gen64-20260928.py).
EARLY_BOOT = ['audit', 'cpu-stop', 'console-tail', 'panel', 'ring',
              'kernel-waits', 'mounts', 'service-profile', 'verdict', 'native-startup', 'crash-retention']
SETS = {'standard': (STANDARD, set(STANDARD) - {'verdict'}),
        'early-boot': (EARLY_BOOT, {'audit', 'cpu-stop', 'console-tail', 'panel', 'ring'})}
OUTPUTS = {'audit': ['-audit.json'], 'service-profile': ['-service-profile.json'],
           'kernel-waits': ['-kernel-waits.json'], 'panel': ['-panel.png'], 'mounts': ['-mounts.json'],
           'metal-probe': ['-metal-probe.json'], 'console-tail': ['-console-tail.json'],
           'ring': ['-gpu-ring.json', '-gpu-ring.bin', '-gpu-fence.bin'], 'verdict': []}
OBSERVERS = {'native-startup': ('native-startup-state', 'NATIVE_STARTUP_STATE_CAPTURED', 'native'),
             'crash-retention': ('crash-retention', 'CRASH_RETENTION_CAPTURED', 'crashes')}
REDECODED = 'SERVICE_PROFILE_REDECODED'
PRIMARY_DONE = 'all required pre-reset captures complete'
PRIMARY_FINAL = 'GUI stopped diagnostics and ring/fence captured; pixels and panel still require verification'


class Run:
    """A finished launch, checked against everything its record pins."""

    def __init__(self, ws, prefix, check_host=True):
        need(prefix and all(c in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in prefix), f'bad prefix {prefix!r}')
        self.ws, self.prefix = ws, prefix
        self.launch_path = ws.prefixed(prefix, '-launch.json')
        need(self.launch_path.is_file(), f'{self.launch_path} does not exist')
        launch = self.launch = read(self.launch_path)
        self.launch_sha256 = sha(self.launch_path)
        ws.adopt_origin(launch.get('hardware_owner', str(ws.root)))
        need(launch.get('finished') and 'exit_code' in launch, 'the launcher has not finished (no finished/exit_code)')
        need(launch['finished'] > launch['started'], 'launch finished before it started')
        self.exit_code = launch['exit_code']
        need(self.exit_code in STOPPED_EXITS,
             f'exit {self.exit_code} is not a stopped guest; stopped exits are {sorted(STOPPED_EXITS)}')
        self.generation = launch['adreno_record']['stage_generation']
        self.image_base = image_base(self.generation)
        need(launch['runtime_root'] == launch['observer_root'], 'runtime and observer roots differ')
        self.runtime = ws.local(launch['runtime_root'])
        need(self.runtime.parent == ws.parent, f'runtime root {self.runtime} is not beside {ws.root}')
        if check_host:
            host_absent(ws, launch)
        for name, digest in launch['source_sha256'].items():
            need(matches(ws.local(name), digest), f'source pin changed or missing: {name}')
        self.monitor = ws.local(launch['monitor_path'])
        need(matches(self.monitor, launch['monitor_sha256']) and
             matches(self.runtime / 'build/xnuboot.bin', launch['monitor_sha256']),
             'monitor binary differs from the launch record or from the runtime root build output')
        need(matches(ws.local(launch['auxkc']), launch['auxkc_sha256']), 'AuxKC changed or missing')
        layout, fields = context_layout(self.runtime)
        need(layout.size('context') == launch['context_bytes'] and len(fields) == launch['context_fields'],
             f'runtime root context is {layout.size("context")} bytes/{len(fields)} fields, the launch recorded '
             f'{launch["context_bytes"]}/{launch["context_fields"]}')
        self.deployment = launch.get('compiler_deployment') or {}
        need('image' in self.deployment, 'launch record names no image qualification')
        self.image_path = ws.local(self.deployment['image'])
        need(matches(self.image_path, self.deployment.get('image_sha256', launch['qualification_sha256'])),
             'image qualification changed or missing')
        self.image = read(self.image_path)
        if sha(self.image_path) == launch['qualification_sha256']:
            need(self.image['guest_profile'] == launch['guest_profile'], 'image and launch guest profiles differ')
        self.firmware = downloads_pinned(ws, self.runtime, self.image)
        retirement = self.deployment.get('retirement')
        if retirement and ws.local(retirement).is_file():
            before = read(ws.local(retirement)).get('after', {})
            if before.get('stage_generation') == self.generation:
                need(before.get('image_base') == self.image_base,
                     f'predecessor retirement put generation {self.generation} at {before.get("image_base", 0):#x}, '
                     f'not the alternating slot {self.image_base:#x}')
        self.cycle = self.deployment.get('cycle')
        self.launcher = None
        for candidate in sorted((ws.root / 'tools').glob('*.py')):
            if sha(candidate) == launch['launcher_sha256']:
                self.launcher = candidate
                break
        need(self.launcher or self.cycle, 'the launcher that wrote this record is not in tools/ any more')
        self.early_stop = None
        stop = ws.prefixed(prefix, '-early-stop.json')
        if stop.is_file():
            self.early_stop = dict(path=str(stop), sha256=sha(stop), record=read(stop))
        need(self.exit_code != 12 or self.early_stop, 'exit 12 (early stop) without its -early-stop.json record')

    def path(self, suffix):
        return self.ws.prefixed(self.prefix, suffix)

    def runtime_path(self, suffix):
        return self.runtime / 'build' / (self.prefix + suffix)

    def summary(self):
        return dict(prefix=self.prefix, generation=self.generation, exit_code=self.exit_code,
                    stop=STOPPED_EXITS[self.exit_code], image_base=hex(self.image_base),
                    runtime_root=str(self.runtime), monitor_sha256=self.launch['monitor_sha256'],
                    launch_sha256=self.launch_sha256, launcher=str(self.launcher) if self.launcher else 'cycle',
                    early_stop=self.early_stop and dict(path=self.early_stop['path'], sha256=self.early_stop['sha256']))


def _audit(run):
    path = run.path('-audit.json')
    if not path.is_file():
        return None
    audit = read(path)
    need(audit['runtime_stop_qualified'] and audit['user_mapping_qualified'], 'audit did not qualify the stop')
    need(audit['monitor_sha256'] == run.launch['monitor_sha256'], 'audit names another monitor')
    owner = (audit['service'][1] & 0xffffffff) - 1
    need(0 <= owner < 6, f'audit owner CPU {owner} out of range')
    return dict(path=path, sha256=sha(path), service=audit['service'], owner=owner, mtime=path.stat().st_mtime)


def _outputs_ok(run, step, audit):
    """{suffix: sha256} when the step's outputs are present and bound, else None."""
    if step == 'cpu-stop':
        if not audit:
            return None
        suffixes = [f'-cpu{audit["owner"]}-stop.json']
    elif step in OBSERVERS:
        return _binding(run, step, audit)
    else:
        suffixes = OUTPUTS[step]
    if step != 'audit' and suffixes and not audit:
        return None
    if not all(run.path(s).is_file() and run.path(s).stat().st_size > 0 for s in suffixes):
        return None
    if step == 'ring':
        ring = read(run.path('-gpu-ring.json'))
        need(ring['status'] == 'STOPPED_GPU_RING_CAPTURED' and ring['generation'] == run.generation, 'ring record')
        need(ring['launch_sha256'] == run.launch_sha256 and ring['audit_sha256'] == audit['sha256'], 'ring bindings')
        need(ring['ring_sha256'] == sha(run.path('-gpu-ring.bin')) and ring['fence_sha256'] == sha(run.path('-gpu-fence.bin')),
             'ring/fence bytes changed')
        need(ring['repeated_reads_equal'] and not ring['writes'], 'ring capture not read-only and repeatable')
    if step == 'service-profile':
        profile = read(run.path('-service-profile.json'))
        need(profile['monitor_sha256'] == run.launch['monitor_sha256'] and profile['audit_sha256'] == audit['sha256'],
             'service profile bindings')
    return {s: sha(run.path(s)) for s in suffixes}


def _binding(run, step, audit):
    stem, status, _ = OBSERVERS[step]
    if not audit:
        return None
    for binding in sorted(run.ws.build.glob(f'{run.prefix}-{stem}-*-binding.json')):
        b = read(binding)
        output = binding.with_name(binding.name[:-len('-binding.json')] + '.json')
        if b.get('status') != status:
            continue
        need(b['generation'] == run.generation and not b['writes'] and not b['guest_resumed'], f'{binding.name} bindings')
        need(b['verification_sha256'] == audit['sha256'] and b['monitor_sha256'] == run.launch['monitor_sha256'],
             f'{binding.name} is bound to another audit or monitor')
        need(b['output_sha256'] == sha(output), f'{output.name} changed')
        return {binding.name[len(run.prefix):]: sha(binding), output.name[len(run.prefix):]: sha(output)}
    return None


def _canonical(name):
    if name.startswith('cpu') and name.endswith('-stop'):
        return 'cpu-stop'
    return {'native-startup-state': 'native-startup', 'native': 'native-startup',
            'crashes': 'crash-retention'}.get(name, name)


def attempts(run, audit, substitutions=None, readers=None):
    """Every recorded run of every step: {step: [attempt, ...]} plus the files read.
    Reader substitutions and accepted readers that capture records name are re-verified
    (substitute.py) and appended to `substitutions` and `readers`."""
    found, sources = {}, {}

    def add(step, exit_code, source, after_audit, log=None):
        found.setdefault(_canonical(step), []).append(dict(exit_code=exit_code, source=str(source),
            after_audit=after_audit, log=str(log) if log else None))

    def bind(path):
        sources[str(path)] = sha(path)

    ws, prefix = run.ws, run.prefix
    for log in sorted(ws.build.glob(f'{prefix}-sequence-primary-*.log')) + sorted(ws.build.glob(f'{prefix}-primary-*.log')):
        bind(log)
        audit_ok = False
        lines = [x.strip() for x in log.read_text(errors='replace').splitlines() if x.strip()]
        for line in lines:
            words = line.split()
            if len(words) in (3, 4) and words[1] == 'exit' and words[2].lstrip('-').isdigit():
                step, code = _canonical(words[0]), int(words[2])
                if step in OUTPUTS or step == 'cpu-stop':
                    own = run.path(f'-{words[0]}.log')
                    add(step, code, log, audit_ok or step == 'audit', own if own.is_file() else None)
                    audit_ok = audit_ok or (step == 'audit' and code == 0)
        if lines and lines[-1] == PRIMARY_FINAL and PRIMARY_DONE in lines:
            add('ring', 0, log, True, run.path('-gpu-ring.log') if run.path('-gpu-ring.log').is_file() else None)
    for step, (_, status, name) in OBSERVERS.items():
        for log in sorted(ws.build.glob(f'{prefix}-sequence-{name}-*.log')):
            bind(log)
            lines = [x for x in log.read_text(errors='replace').splitlines() if x.strip()]
            try:
                final = json.loads(lines[-1]) if lines else {}
            except ValueError:
                final = {}
            ok = isinstance(final, dict) and final.get('status') == status and \
                ws.local(final.get('binding', '')).is_file() and sha(ws.local(final['binding'])) == final.get('sha256')
            after = bool(audit) and log.stat().st_mtime >= audit['mtime']
            add(step, 0 if ok else 1, log, after, log)
    for record_path in sorted(ws.build.glob(f'{prefix}-exit6-capture-v*.json')) + \
            sorted(ws.build.glob(f'{prefix}-cycle-capture-v*.json')):
        record = read(record_path)
        bind(record_path)
        need(record.get('launch_sha256') == run.launch_sha256, f'{record_path.name} is bound to another launch record')
        if record.get('substitution'):
            from . import substitute
            b = substitute.verify(ws, run, record['substitution'], audit)
            if substitutions is not None and b not in substitutions:
                substitutions.append(b)
        for accepted in record.get('readers', []):
            from . import substitute
            b = substitute.verify_accepted(ws, run, accepted)
            if readers is not None and b not in readers:
                readers.append(b)
        # A step ran on a qualified stop when the audit had passed before it: in an
        # earlier attempt (this record's starting state) or earlier in this record.
        audit_ok = record.get('before', {}).get('audit') == 'complete'
        for step in record.get('steps', []):
            if 'exit_code' not in step:
                continue
            name = _canonical(step['name'])
            if step.get('prior'):   # copied from sources that are read directly above
                audit_ok = audit_ok or (name == 'audit' and step['exit_code'] == 0)
                continue
            log = ws.local(step['log'])
            need(log.is_file() and sha(log) == step['log_sha256'], f'{record_path.name}: log of {step["name"]} changed')
            bind(log)
            add(name, step['exit_code'], record_path, audit_ok or name == 'audit', log)
            audit_ok = audit_ok or (name == 'audit' and step['exit_code'] == 0)
    return found, sources


def _committed(decoder, commit, digest):
    """True when the decoder file at that commit of its own checkout has this hash."""
    try:
        top = subprocess.run(['git', '-C', str(decoder.parent), 'rev-parse', '--show-toplevel'], capture_output=True,
                             text=True, check=True).stdout.strip()
        relative = decoder.resolve().relative_to(Path(top).resolve())
        blob = subprocess.run(['git', '-C', top, 'show', f'{commit}:{relative}'], capture_output=True, check=True).stdout
    except (subprocess.CalledProcessError, ValueError, OSError):
        return False
    import hashlib
    return hashlib.sha256(blob).hexdigest() == digest


def redecodes(run, audit):
    """Verified service-profile redecodes (build/run-stopped-redecode-20260928.py in a newer
    checkout): the stopped A16 re-read by the runtime root's own runner and capture, with
    that checkout's committed kernel-ops-perf decoder. Each binding must name this launch,
    audit, monitor and runtime root, the pinned runner, the runtime root's own capture and
    decoder (as replaced), the standard collector's service-profile arguments, and a
    decoder file that is exactly its commit's. Newest last."""
    if not audit:
        return []
    from . import observers
    ws, found, names = run.ws, [], set()
    expected = None
    for where in (ws.build, run.runtime / 'build'):
        for binding_path in sorted(where.glob(f'{run.prefix}-service-profile-*-binding.json')):
            if binding_path.name in names:
                continue      # the copy in this checkout's build/ wins over the runtime root's
            b = read(binding_path)
            if b.get('status') != REDECODED:
                continue
            what = f'service-profile redecode {binding_path.name}'
            need(b['prefix'] == run.prefix and b['generation'] == run.generation, f'{what} is for another run')
            need(b['launch_sha256'] == run.launch_sha256, f'{what} is bound to another launch record')
            need(b['audit_sha256'] == audit['sha256'], f'{what} is bound to another audit')
            need(b['monitor_sha256'] == run.launch['monitor_sha256'], f'{what} is bound to another monitor')
            need(ws.local(b['runtime_root']) == run.runtime, f'{what} read another runtime root')
            need(b['runner_sha256'] == PINS['observers']['helper']['sha256'], f'{what} ran another stopped-read runner')
            need(matches(run.runtime / 'tools/capture-service-profile.py', b['capture_sha256']),
                 f'{what}: the runtime root\'s capture-service-profile.py changed since')
            need(matches(run.runtime / 'tools/kernel_ops_perf.py', b['replaced_decoder_sha256']),
                 f'{what}: it did not replace the runtime root\'s own decoder')
            output = binding_path.with_name(Path(b['output']).name)
            need(matches(output, b['output_sha256']), f'{what}: {output.name} changed or missing')
            files = [binding_path, output]
            if b.get('inputs_sha256'):
                inputs = binding_path.with_name(Path(b['inputs']).name)
                need(matches(inputs, b['inputs_sha256']), f'{what}: {inputs.name} changed or missing')
                files.append(inputs)
            profile = read(output)
            need(profile['audit_sha256'] == audit['sha256'] and profile['monitor_sha256'] == run.launch['monitor_sha256'],
                 f'{what}: the decoded profile names another audit or monitor')
            if expected is None:
                _, arguments = observers.collector_steps(ws, run, observers.Params(run))['service-profile']
                expected = ['--device', ws.device, '--prefix', run.prefix, *arguments]
            need(b['arguments'] == expected, f'{what} did not use the standard service-profile arguments')
            decoder = ws.local(b['decoder'])
            need(matches(decoder, b['decoder_sha256']), f'{what}: decoder {decoder} changed since; restore its commit')
            need(_committed(decoder, b['decoder_commit'], b['decoder_sha256']),
                 f'{what}: decoder is not the committed {b["decoder_commit"][:12]} version')
            names.add(binding_path.name)
            found.append(dict(tag=b['tag'], binding=str(binding_path), files=[str(f) for f in files],
                              decoder=str(decoder), decoder_sha256=b['decoder_sha256'], decoder_commit=b['decoder_commit'],
                              replaced_decoder_sha256=b['replaced_decoder_sha256']))
    return found


def assess(run, capture_set=None):
    """State of every step of the capture set for this run."""
    set_name = capture_set or PINS['default_capture_set'][str(run.exit_code)]
    need(set_name in SETS, f'unknown capture set {set_name}')
    order, required = SETS[set_name]
    audit = _audit(run)
    substitutions, readers = [], []
    found, sources = attempts(run, audit, substitutions, readers)
    steps = []
    for name in order:
        tries = found.get(name, [])
        outputs = _outputs_ok(run, name, audit)
        redecode = None
        if name == 'service-profile' and not outputs:
            done = redecodes(run, audit)
            if done:
                redecode = done[-1]
                outputs = {Path(f).name[len(run.prefix):]: sha(f) for f in redecode['files']}
                tries = tries + [dict(exit_code=0, source=redecode['binding'], after_audit=True, log=None)]
        succeeded = any(t['exit_code'] == 0 for t in tries)
        if name == 'verdict':
            complete = succeeded
        else:
            complete = bool(outputs) and succeeded
        if complete:
            state = 'complete'
        elif outputs:
            state = 'unrecorded'      # outputs exist, but no recorded successful run produced them
        elif tries and name not in required and any(t['after_audit'] for t in tries):
            state = 'refused'         # recorded-only step that ran on a qualified stop and failed
        elif tries:
            state = 'retry'
        else:
            state = 'missing'
        steps.append(dict(name=name, required=name in required, state=state, attempts=tries, outputs=outputs or {}))
        if redecode:
            steps[-1].update(redecode={k: v for k, v in redecode.items() if k != 'files'}, files=redecode['files'])
    done = all(s['state'] == 'complete' if s['required'] else s['state'] in ('complete', 'refused') for s in steps)
    return dict(set=set_name, complete=done, audit=audit and dict(path=str(audit['path']), sha256=audit['sha256'],
                service=audit['service'], owner=audit['owner']), steps=steps, sources=sources,
                substitutions=substitutions, readers=readers)


def programs(run):
    """The collector programs that actually ran for this run: build/*.py that name its
    prefix, plus any program whose hash a capture record carries."""
    ws, found = run.ws, {}
    wanted = set()
    ring = run.path('-gpu-ring.json')
    if ring.is_file():
        wanted.add(read(ring).get('source_sha256'))
    for stem, _, _ in OBSERVERS.values():
        for binding in ws.build.glob(f'{run.prefix}-{stem}-*-binding.json'):
            wanted.add(read(binding).get('source_sha256'))
    for record in list(ws.build.glob(f'{run.prefix}-exit6-capture-v*.json')):
        wanted.add(read(record).get('source_sha256'))
    for script in sorted(ws.build.glob('*.py')):
        digest = sha(script)
        if digest in wanted or run.prefix in script.read_text(errors='replace'):
            found[str(script)] = digest
    missing = wanted - set(found.values()) - {None}
    for tool in ws.tool_sources().items():
        if tool[1] in missing:
            found[tool[0]] = tool[1]
    # Observers that cycle ran name cycle.py as their program; a later edit of the tool
    # is fine when a cycle capture record of this run carries that version's hash.
    recorded = set()
    for record in ws.build.glob(f'{run.prefix}-cycle-capture-v*.json'):
        recorded.update(read(record).get('tool_sha256', {}).values())
    missing = wanted - set(found.values()) - recorded - {None}
    need(not missing, f'capture records name programs that are no longer present: {sorted(missing)}')
    return found
