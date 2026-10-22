# SPDX-License-Identifier: MIT
"""Fresh RAM-only XNU HVC smoke, separate from historical installed-GUI admission.

Failure inventory predates this implementation in docs/SPTM-CALL-ENTRY-20260930.md.
No SSD, GPU, SMP, external stop service, TXM helper, restoration or retirement.
One definite main P_CALL return is required before stopped-state capture. An
uncertain helper or main P_CALL quarantines the run without further target I/O.
"""
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import sys
import time

from .common import need, Refused

PROFILE = 'j700ap-26A428'
ENV = {'SNAP_NO_FB': '1', 'SNAP_NATIVE_CALLS': '1', 'SNAP_SPTM_HVC_CALLS': '1',
       'SNAP_WATCHDOG': '5', 'SNAP_GUEST_MIB': '384'}
IDENTITY = ('current_el', 'stage_generation', 'image_base', 'image_size',
            'heap_base', 'heap_size', 'stage_base', 'stage_size', 'call_service')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(path):
    return digest(Path(path).read_bytes())


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def write(path, record):
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(record, indent=2) + '\n')
    temporary.replace(path)


@contextlib.contextmanager
def environment(prefix):
    old = dict(os.environ)
    for key in list(os.environ):
        if key.startswith('SNAP_'):
            del os.environ[key]
    os.environ.update(ENV, SNAP_SMP_REPORT_PREFIX=prefix)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(old)


def source_paths(root):
    paths = [root / 'tools/cycle.py', root / 'tools/cycle_lib/bootstrap_smoke.py',
             root / 'tools/cycle_lib/common.py', root / 'tools/monitor_layout.py',
             root / 'tools/probe-sptm-entry.py', root / 'config/monitor-flags.json']
    for folder in ('probes', 'compat', 'shadow', 'tools'):
        paths.extend(p for p in (root / folder).rglob('*') if p.suffix in ('.py', '.c', '.h', '.S', '.ld'))
    paths.extend((root.parent / 'q1n1/tools').glob('*.py'))
    paths.extend([root.parent / 'q1n1/platform/uefi/sha256.c', root.parent / 'q1n1/platform/uefi/sha256.h'])
    return sorted(set(paths))


def modules(root):
    sys.path.insert(0, str(root / 'probes'))
    runner = load('bootstrap_run', root / 'probes/run.py')
    layout = load('bootstrap_layout', root / 'tools/monitor_layout.py').MonitorLayout()
    admission = load('bootstrap_admission', root / 'tools/probe-sptm-entry.py')
    return runner, layout, admission


def prepare(ws, args, dest):
    need(not dest.exists(), f'preserve previous run: {dest}')
    root = ws.root
    runner, layout, _ = modules(root)
    flags = json.loads((root / 'config/monitor-flags.json').read_text())['flags']
    need('-DSNAP_NATIVE_CALLS=1' in flags and '-DSNAP_STEP_ALU=0' in flags, 'native-call recipe mismatch')
    flags = [*flags, '-DSNAP_SPTM_HVC_CALLS=1']
    need(len(flags) == len(set(flags)), 'duplicate build flags')
    sources = {str(p): sha(p) for p in source_paths(root)}
    dest.mkdir()
    runner.FLAGS[:] = flags
    with environment(args.prefix), (dest / 'prepare.log').open('x') as stream, contextlib.redirect_stdout(stream):
        blob = runner.build('xnuboot', dest)
        xb = load('bootstrap_image', root / 'probes/xnuboot.py')
        xb.configure_guest(PROFILE, root / 'downloads/extracted/j700ap')
        need(not xb.check_profile(), 'firmware profile rejected')
        need(xb.GUEST_PROFILE.adreno is None and xb.GUEST_PROFILE.ans_boot is None and
             xb.GUEST_PROFILE.installed_root is None, 'smoke profile accesses devices outside scope')
        built = xb.build(str(xb.DEFAULT_KERNELCACHE))
        need(built['native_calls'] and built['sptm_hvc_calls'], 'offline image lacks HVC admission')
        image = dict(profile=PROFILE, kernel_sha256=sha(xb.DEFAULT_KERNELCACHE),
                     firmware_sha256=xb.GUEST_PROFILE.hashes(root / 'downloads/extracted/j700ap'),
                     native_contract=built['native_call_contract'],
                     entry=hex(built['entry']), chunks=len(built['chunks']),
                     qualification='offline default-placement image only; actual hardware placement captured at upload')
    need(all(sha(p) == h for p, h in sources.items()), 'sources changed during preparation')
    record = dict(schema='snapintosh-bootstrap-smoke-v1', status='OFFLINE_PREPARED_NOT_BOOTED',
                  prefix=args.prefix, device=args.device or ws.device,
                  expected_identity={k: getattr(args, k) for k in ('image_base', 'image_size', 'heap_base', 'heap_size')},
                  profile=PROFILE, watchdog_seconds=5, main_call_deadline_seconds=20,
                  flags=flags, environment=ENV, source_sha256=sources,
                  monitor_sha256=digest(blob), monitor_bytes=len(blob), elf_sha256=sha(dest / 'xnuboot.elf'),
                  context_bytes=layout.size('context'), image=image,
                  qualification='RAM-only single-CPU XNU call-entry integration; no GUI/performance/baseline qualification')
    write(dest / 'qualification.json', record)
    return record


def check(ws, args, dest):
    path = dest / 'qualification.json'
    need(path.is_file(), 'run --prepare first')
    record = json.loads(path.read_text())
    need(record['schema'] == 'snapintosh-bootstrap-smoke-v1' and record['prefix'] == args.prefix, 'wrong qualification')
    need(record['device'] == (args.device or ws.device), 'device differs from preparation')
    need(record['expected_identity'] == {k: getattr(args, k) for k in record['expected_identity']}, 'identity differs from preparation')
    need(record['environment'] == ENV and record['profile'] == PROFILE, 'smoke scope changed')
    for name, expected in record['source_sha256'].items():
        need(sha(name) == expected, f'source changed: {name}')
    need(sha(dest / 'xnuboot.bin') == record['monitor_sha256'] and sha(dest / 'xnuboot.elf') == record['elf_sha256'],
         'prepared monitor changed')
    need(not (dest / 'launch.json').exists(), 'this smoke attempt already has a launch record; never rerun it')
    from guestprofile import get_profile
    need(get_profile(PROFILE).hashes(ws.root / 'downloads/extracted/j700ap') == record['image']['firmware_sha256'],
         'firmware inputs changed')
    return record


class WitnessProxy:
    """Persist successful upload hashes and exact P_CALL lifecycle around real proxy.

    SECONDARIES says whether the main call must carry a physical secondary
    configuration (speed_test) or must not (this smoke); MAIN_TIMEOUT, when
    set, replaces the runner's deadline for the main call."""
    SECONDARIES = False
    MAIN_TIMEOUT = 20

    def __init__(self, proxy, path, record, code):
        self.path, self.record, self.code = path, record, code
        terminal_module = load('cycle_xnuboot_terminal', Path(__file__).resolve().parents[2] / 'probes/xnuboot_terminal.py')
        self._require_terminal = terminal_module.require_xnuboot_terminal
        guard_module = load('cycle_control_guard', Path(__file__).resolve().parents[1] / 'a16-control-guard.py')
        self.control_guard = guard_module.ControlGuard(proxy, record, lambda: write(path, record))
        self.inner = self.control_guard.proxy
        self.unknown = False
        self.quarantined = False
        self.main_returned = False
        self.main_args = None

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def writemem(self, address, data, *args, **kwargs):
        result = self.inner.writemem(address, data, *args, **kwargs)
        self.record['uploads'].append(dict(address=hex(address), bytes=len(data), sha256=digest(data),
                                          transport_acknowledged=True))
        return result

    def call(self, address, *args, **kwargs):
        if self.control_guard.frozen:
            raise RuntimeError(self.control_guard.reason)
        main = address == self.code
        if main:
            need(self.main_args is None, 'refusing a second main guest P_CALL')
            need(len(args) == 5 and bool(args[-1]) == self.SECONDARIES,
                 'main call must carry the physical secondary configuration' if self.SECONDARIES
                 else 'main call must have no physical secondary configuration')
            need(all(sha(path) == expected for path, expected in self.record['source_sha256'].items()),
                 'bound source changed during image upload; refusing guest entry')
            need(digest(self.inner.readmem(self.code, self.record['monitor_bytes'])) == self.record['monitor_sha256'],
                 'uploaded monitor differs before guest entry')
            self.main_args = args
            if self.MAIN_TIMEOUT:
                kwargs['timeout'] = self.MAIN_TIMEOUT
        row = dict(address=hex(address), arguments=list(args), main_guest=main,
                   timeout=kwargs.get('timeout'), started=time.time(), returned=False)
        self.record['calls'].append(row)
        write(self.path, self.record)
        self.unknown = True
        result = self.inner.call(address, *args, **kwargs)
        self.unknown = False
        row.update(returned=True, result=result, finished=time.time())
        if main:
            # An acknowledged native return is not proof of stopped ownership.
            # Freeze before capture/cleanup and preserve the known status as such.
            self.record['native_terminal'] = result
            try:
                self._require_terminal(result)
            except BaseException as error:
                self.quarantined = True
                self.record['status'] = 'NATIVE_QUARANTINE_NO_FURTHER_TARGET_IO'
                self.control_guard.freeze(str(error))
                raise
            self.main_returned = True
        write(self.path, self.record)
        return result


def capture(proxy, info, runner, layout, dest, record):
    out, work, work_size, params, _ = proxy.main_args
    artifacts = {}
    def retain(name, address, size):
        data = proxy.readmem(address, size)
        (dest / name).write_bytes(data)
        artifacts[name] = dict(address=hex(address), bytes=size, sha256=digest(data))
        return data
    report = retain('report.bin', out, runner.OUT_HEADROOM)
    context = retain('context.bin', work, layout.size('context'))
    retain('params.bin', params, layout.size('params'))
    import monitor_work
    locator = retain('work-locator.bin', monitor_work.locator_address(info), monitor_work.LOCATOR_SIZE)
    need(monitor_work.decode_locator(locator, info, monitor_work.firmware_free(proxy, info)) == (work, work_size),
         'stopped work locator differs from actual main-call reservation')
    def words(field, count, offset=0):
        return list(struct.unpack_from('<' + 'Q' * count, context, layout.offset('context', field) + offset))
    native_names = ('ready', 'calls', 'restores', 'rejected', 'elr', 'spsr', 'esr', 'far',
                    'last_pc', 'last_word', 'last_saved', 'last_physical')
    native = [dict(zip(native_names, words('native_calls', 12, cpu * 96))) for cpu in range(6)]
    hvc = [dict(zip(('calls', 'rejected', 'last_pc'), words('sptm_hvc', 3, cpu * 24))) for cpu in range(6)]
    services = words('services', 3)
    flow = list(struct.unpack_from('<16Q', report, runner.SERVICE_FLOW_OFFSET))
    header = list(struct.unpack_from('<10Q', report))
    decoded = dict(header=header, native_calls=native, sptm_hvc=hvc, services=services,
                   service_flow=flow, work=hex(work), work_bytes=work_size,
                   context_host_cpus=words('host_cpus', 1)[0])
    write(dest / 'decoded.json', decoded)
    artifacts['decoded.json'] = dict(sha256=sha(dest / 'decoded.json'))
    # Verify the uploaded monitor is still exactly the admitted binary.
    need(digest(proxy.readmem(info['heap_base'] + runner.CODE_AT, record['monitor_bytes'])) == record['monitor_sha256'],
         'resident monitor changed')
    after = proxy.bootinfo()
    need({k: after[k] for k in IDENTITY} == {k: info[k] for k in IDENTITY}, 'resident firmware identity changed')
    guard = proxy.serror_state()
    record['after_serror'] = guard
    record['after_exception_count'] = proxy.get_exc_count()
    checks = dict(main_returned=proxy.main_returned,
                  watchdog_exit=record.get('exit_code') == runner.EXIT_WATCHDOG,
                  entered=header[0] == 0 and header[1] == 1,
                  hvc_used=sum(x['calls'] for x in hvc) > 0,
                  hvc_rejected=sum(x['rejected'] for x in hvc) == 0,
                  no_legacy_calls=sum(x['calls'] + x['restores'] + x['rejected'] for x in native) == 0,
                  no_secondary=decoded['context_host_cpus'] == 0 and all(x['calls'] == 0 for x in hvc[1:]),
                  service_closed=services[0] == 0 and services[2] == ((1 << 63) | 3),
                  memory_reusable=flow[15] == 1 and not any(flow[3:14:2]),
                  no_host_exception=not record['after_exception_count'] and
                     not any(guard[k] for k in ('before', 'during', 'unconsumed')))
    record.update(captures=artifacts, checks=checks, terminal='STOPPED_PRESERVED_NO_RETIREMENT',
                  integration='PASS' if all(checks.values()) else 'FAIL',
                  hvc_calls=sum(x['calls'] for x in hvc))
    # The run remains resident. These hashes protect its evidence before any
    # later separately reviewed retirement; this is not an old GUI preservation.
    write(dest / 'preservation.json', dict(schema='snapintosh-bootstrap-preservation-v1',
          actual_main_call_return=True, artifacts=artifacts, checks=checks,
          qualified_scope='RAM-only HVC call-entry integration', runtime_retired=False))
    record['preservation_sha256'] = sha(dest / 'preservation.json')


def boot(ws, args, dest, qualification):
    need(args.qualification_sha256 == sha(dest / 'qualification.json'), 'boot needs the exact qualification SHA256')
    runner, layout, admission = modules(ws.root)
    record = dict(schema='snapintosh-bootstrap-smoke-launch-v1', status='PREFLIGHT', started=time.time(),
                  qualification_sha256=args.qualification_sha256,
                  monitor_sha256=qualification['monitor_sha256'], monitor_bytes=qualification['monitor_bytes'],
                  source_sha256=qualification['source_sha256'], uploads=[], calls=[], pid=os.getpid())
    path = dest / 'launch.json'
    write(path, record)
    proxy = None
    witness = None
    try:
        admission.other_clients(args.device or ws.device)
        proxy = runner.connect(args.device or ws.device, tries=1)
        info = proxy.bootinfo()
        record['bootinfo'] = info
        need(info['current_el'] == 2 and info['stage_generation'] == 0 and info['call_service'] == 0,
             'requires fresh generation0 EL2 firmware without guest call service')
        need(proxy.stage_features() == 0 and proxy.get_base() == info['image_base'], 'unexpected firmware identity')
        for key, expected in qualification['expected_identity'].items():
            need(info[key] == expected, f'fresh identity mismatch: {key}')
        import monitor_work
        locator = proxy.readmem(monitor_work.locator_address(info), monitor_work.LOCATOR_SIZE)
        need(locator in (bytes(len(locator)), bytes([0xaf]) * len(locator)), 'a guest locator already occupies this firmware')
        record['initial_locator_sha256'] = digest(locator)
        guard = proxy.serror_state()
        need(not any(guard[k] for k in ('before', 'during', 'unconsumed')) and not proxy.get_exc_count(), 'host exceptions before boot')
        witness = WitnessProxy(proxy, path, record, info['heap_base'] + runner.CODE_AT)
        # Route live-battery P_CALL through the same unknown-outcome discipline.
        need(info['battery_call'] and info['battery_result'], 'firmware has no live battery helper')
        status = witness.call(info['battery_call'], 0, 0, 0, 0, 0, timeout=12)
        battery = proxy.live_battery_record(info['battery_result'])
        record['battery'] = battery
        need(status == 0 and battery['plausible'] and (battery['ac'] or battery['percent'] >= 80), 'battery preflight refused')
        record['status'] = 'BOOTING'
        write(path, record)
        with environment(args.prefix), (dest / 'boot.log').open('x') as stream, contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            record['exit_code'] = runner.run(witness, (dest / 'xnuboot.bin').read_bytes(), 'xnuboot',
                                            args.device or ws.device,
                dict(guest_profile=PROFILE, firmware_dir=str(ws.root / 'downloads/extracted/j700ap'), console_mode='serial'))
    except BaseException as error:
        record['error'] = repr(error)
        record['status'] = 'FAILED'
        raise
    finally:
        try:
            if witness and witness.quarantined:
                record['status'] = 'NATIVE_QUARANTINE_NO_FURTHER_TARGET_IO'
            elif witness and witness.unknown:
                record['status'] = 'UNKNOWN_CALL_OUTCOME_NO_FURTHER_TARGET_IO'
            elif witness and witness.control_guard.frozen:
                record['status'] = 'CONTROL_FAILURE_NO_FURTHER_TARGET_IO'
            elif witness and witness.main_returned:
                capture(witness, info, runner, layout, dest, record)
                record['status'] = 'STOPPED_PRESERVED'
            elif record['status'] != 'FAILED':
                record['status'] = 'NO_GUEST_CALL'
        except BaseException as error:
            record['capture_error'] = repr(error)
            record['status'] = 'STOPPED_CAPTURE_FAILED'
            raise
        finally:
            record['finished'] = time.time()
            write(path, record)
            if proxy:
                proxy.link.close()
    return record


def main(ws, args):
    need(re.fullmatch('[a-z0-9-]+', args.prefix), 'invalid prefix')
    dest = ws.root / 'build' / args.prefix
    sys.path.insert(0, str(ws.root / 'probes'))
    if args.prepare:
        prepare(ws, args, dest)
    record = check(ws, args, dest)
    if args.boot:
        with Path('/tmp/snapintosh-hardware.lock').open('a') as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            record = boot(ws, args, dest, record)
        print(json.dumps({k: record.get(k) for k in ('status', 'integration', 'hvc_calls', 'checks', 'preservation_sha256')}, indent=2))
        return 0 if record.get('integration') == 'PASS' else 1
    print(json.dumps(dict(status='OFFLINE_READY_NOT_BOOTED', qualification=str(dest / 'qualification.json'),
                         sha256=sha(dest / 'qualification.json'), hardware_access=False), indent=2))
    return 0
