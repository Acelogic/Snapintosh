#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""cycle.py installed-fresh, offline, against a real prepared attempt
(docs/INSTALLED-FRESH-ADMISSION-20261016.md, failure modes 1, 3, 7 and 8).

Copies build/PREFIX (default installed-fresh-20261016-v1) to a temporary
workspace view and checks:
  - `check` accepts the untouched copy;
  - it refuses a changed regenerated input (root hash, TXM helper), a changed
    monitor, a changed recipe or scope, a different device, and an attempt that
    already has a launch record;
  - the regenerated inputs equal their independent pins again (root hash from
    the IPSW, TXM helper bytes, AuxKC pin, trust cache, device tree);
  - the GPU gate passes only an unprepared read-only status;
  - the boot hooks append -timesync_bringup exactly once to the one xnuboot
    module run.py loads, refuse a second load, and refuse an SSD window header
    whose hash lacks the recorded prefix (the APFS capture never runs then).
No hardware is contacted. `--predecessors` runs only the --after-quiesce
predecessor checks (a parked v6; v73, refused at its first thermal check).

    python3 tools/test-installed-fresh.py [PREFIX | --predecessors]
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'probes'), str(ROOT.parent / 'q1n1/tools')]
from cycle_lib import installed_fresh as fresh  # noqa: E402
from cycle_lib.common import Refused, Workspace  # noqa: E402

checks = 0


def expect(ok, what):
    global checks
    checks += 1
    if not ok:
        raise AssertionError(what)


def refuses(fn, needle):
    try:
        fn()
    except Refused as error:
        expect(needle in str(error), f'refused for the wrong reason: {error!r}, wanted {needle!r}')
        return
    expect(False, f'not refused: {needle}')


def predecessor_checks():
    """--after-quiesce predecessors, against real retained captures (no hardware)."""
    # --after-quiesce: a parked predecessor's locator, against installed-fresh-20261017-v6's real captures.
    if (ROOT / 'build/installed-fresh-20261017-v6/work-locator.bin').is_file():
        import types
        runner_mod, layout_mod, _ = fresh.modules(ROOT)
        pred = fresh.predecessor_stop(ROOT, 'installed-fresh-20261017-v6', layout_mod)
        expect(pred['words'][2] == fresh.PARKED_SERVICE_WORD and len(pred['locator']) == 80, 'v6 is not a parked stop')
        import monitor_work
        work = 0x200000000

        class FakeProxy:
            def __init__(self, locator, words):
                self.locator, self.words = locator, words
            def bootinfo(self):
                return dict(current_el=2, stage_generation=2, image_base=fresh.image_base(2), heap_base=pred['boot']['heap_base'],
                            heap_size=0x1000000)
            def stage_features(self):
                return 1
            def readmem(self, at, size, live=False):
                if at == monitor_work.locator_address(self.bootinfo()):
                    return self.locator
                need_at = work + pred['services_offset']
                assert at == need_at and size == 64, hex(at)
                return struct.pack('<8Q', *self.words)
            def serror_state(self):
                return dict(before=0, during=0, unconsumed=0, refused=0)
            def get_exc_count(self):
                return 0
        saved_decode, saved_free = monitor_work.decode_locator, monitor_work.firmware_free
        def decode(data, info, free):     # the predecessor's own boot, never the running generation's
            assert (info['image_base'], info['stage_generation']) == (pred['boot']['image_base'],
                                                                       pred['boot']['stage_generation'])
            return work, 0x10000000
        monitor_work.decode_locator = decode
        monitor_work.firmware_free = lambda proxy, info: []
        try:
            rec = {}
            expect(fresh.admit(FakeProxy(bytes(80), pred['words']), rec, 2, runner_mod) and 'predecessor_stop' not in rec,
                   'empty slot refused')
            fresh.admit(FakeProxy(pred['locator'], pred['words']), rec, 2, runner_mod, pred)
            expect(rec['predecessor_stop']['prefix'] == 'installed-fresh-20261017-v6', 'parked predecessor not admitted')
            refuses(lambda: fresh.admit(FakeProxy(pred['locator'], pred['words']), {}, 2, runner_mod), 'already occupies')
            refuses(lambda: fresh.admit(FakeProxy(bytes([1]) * 80, pred['words']), {}, 2, runner_mod, pred),
                    'not installed-fresh-20261017-v6')
            moved = list(pred['words']); moved[2] = 0x8000000000000002
            refuses(lambda: fresh.admit(FakeProxy(pred['locator'], moved), {}, 2, runner_mod, pred), 'parked stop')
        finally:
            monitor_work.decode_locator, monitor_work.firmware_free = saved_decode, saved_free

    # --after-quiesce: a predecessor refused by a thermal check before GPU preparation (the real captures
    # of installed-fresh-20261019-v73, first checkpoint, and -v76, second checkpoint) is admitted without
    # a parked word; any other non-parked predecessor still refuses.
    v73 = 'installed-fresh-20261019-v73'
    if (ROOT / 'build' / v73 / 'report.bin').is_file():
        import a16_thermal
        runner_mod, layout_mod, _ = fresh.modules(ROOT)
        pred = fresh.predecessor_stop(ROOT, v73, layout_mod)
        expect(pred['words'][2] == 0x8000000000000000 and len(pred['locator']) == 80, 'v73 is not its never-parked stop')
        if (ROOT / 'build/installed-fresh-20261019-v76/report.bin').is_file():
            expect(fresh.predecessor_stop(ROOT, 'installed-fresh-20261019-v76', layout_mod)['words'][2] ==
                   0x8000000000000000, 'v76 (second checkpoint, before the GPU) refused')
        names = ('launch.json', 'preservation.json', 'report.bin', 'context.bin', 'work-locator.bin')
        flow_status = runner_mod.GPU_FLOW_OFFSET     # adreno_counters FIELDS[0], 'status'

        def variant(launch=None, words=None, rebind=True, tamper=None):
            tmp = Path(tempfile.mkdtemp())
            dest = tmp / 'build' / v73
            dest.mkdir(parents=True)
            for name in names:
                shutil.copy2(ROOT / 'build' / v73 / name, dest / name)
            record = json.loads((dest / 'launch.json').read_text())
            if words:
                report = bytearray((dest / 'report.bin').read_bytes())
                for at, value in words.items():
                    if isinstance(value, bytes):
                        report[at:at + len(value)] = value
                    else:
                        struct.pack_into('<Q', report, at, value)
                (dest / 'report.bin').write_bytes(report)
                if rebind:
                    preservation = json.loads((dest / 'preservation.json').read_text())
                    preservation['artifacts']['report.bin']['sha256'] = hashlib.sha256(report).hexdigest()
                    (dest / 'preservation.json').write_text(json.dumps(preservation))
                    record['preservation_sha256'] = hashlib.sha256((dest / 'preservation.json').read_bytes()).hexdigest()
            if tamper:
                data = bytearray((dest / tamper).read_bytes()); data[-1] ^= 1
                (dest / tamper).write_bytes(data)
            record.update(launch or {})
            (dest / 'launch.json').write_text(json.dumps(record))
            return tmp

        def refused_variant(what, **kw):
            tmp = variant(**kw)
            try:
                refuses(lambda: fresh.predecessor_stop(tmp, v73, layout_mod), 'not a parked stop')
            finally:
                shutil.rmtree(tmp)

        tmp = variant(words={})
        expect(fresh.predecessor_stop(tmp, v73, layout_mod)['words'] == pred['words'], 'unchanged copy refused')
        shutil.rmtree(tmp)
        refused_variant('exit 4', launch={'exit_code': 4})
        refused_variant('failed launch', launch={'status': 'FAILED'})
        refused_variant('active CPUs', launch={'summary': dict(json.loads((ROOT / 'build' / v73 / 'launch.json').read_text())['summary'], cpus_active=1)})
        refused_variant('another prepare error', words={0: (1 << 64) - 27})
        refused_variant('entered', words={8: 1})
        refused_variant('GPU adopted by the monitor', words={flow_status: 1})
        refused_variant('no thermal report', words={a16_thermal.REPORT_OFFSET: bytes(a16_thermal.SIZE)})
        refused_variant('unbound report', words={flow_status: 1}, rebind=False)
        refused_variant('changed report', words={}, tamper='report.bin')
        refused_variant('changed context', words={}, tamper='context.bin')
        refused_variant('changed preservation', launch={'preservation_sha256': '0' * 64})
        if (ROOT / 'build/installed-fresh-20261018-v48/context.bin').is_file():
            refuses(lambda: fresh.predecessor_stop(ROOT, 'installed-fresh-20261018-v48', layout_mod), 'not a parked stop')
        import monitor_work
        work = 0x200000000

        class PreEntryProxy:
            def __init__(self, words):
                self.words = words
            def bootinfo(self):
                return dict(current_el=2, stage_generation=1, image_base=fresh.image_base(1), heap_base=pred['boot']['heap_base'],
                            heap_size=0x1000000)
            def stage_features(self):
                return 1
            def readmem(self, at, size, live=False):
                if at == monitor_work.locator_address(self.bootinfo()):
                    return pred['locator']
                assert at == work + pred['services_offset'] and size == 64, hex(at)
                return struct.pack('<8Q', *self.words)
            def serror_state(self):
                return dict(before=0, during=0, unconsumed=0, refused=0)
            def get_exc_count(self):
                return 0
        saved_decode, saved_free = monitor_work.decode_locator, monitor_work.firmware_free
        monitor_work.decode_locator = lambda data, info, free: (work, 0x10000000)
        monitor_work.firmware_free = lambda proxy, info: []
        try:
            rec = {}
            fresh.admit(PreEntryProxy(pred['words']), rec, 1, runner_mod, pred)
            expect(rec['predecessor_stop']['prefix'] == v73, 'pre-entry predecessor not admitted')
            moved = list(pred['words']); moved[1] ^= 1
            refuses(lambda: fresh.admit(PreEntryProxy(moved), {}, 1, runner_mod, pred), 'preserved parked stop')
        finally:
            monitor_work.decode_locator, monitor_work.firmware_free = saved_decode, saved_free

    # --quiesce after a control failure: only v75's host-side completion-queue read freeze is admitted.
    v75 = ROOT / 'build/installed-fresh-20261019-v75/launch.json'
    if v75.is_file():
        launch = json.loads(v75.read_text())
        expect(fresh.host_read_freeze(launch), 'v75 host read freeze not admitted for quiesce')
        guard = launch['control_guard']
        for what, change in [
                ('native in flight', dict(control_guard=dict(guard, native_inflight={'operation': 'P_CALL'}))),
                ('SError freeze', dict(control_guard=dict(guard, reason='SError latched before cleanup'))),
                ('failed request', dict(control_guard=dict(guard, reason='proxy.request(0x5) failed: TimeoutError'))),
                ('not frozen', dict(control_guard=dict(guard, frozen=False))),
                ('unknown call', dict(status='UNKNOWN_CALL_OUTCOME_NO_FURTHER_TARGET_IO')),
                ('quarantine', dict(status='NATIVE_QUARANTINE_NO_FURTHER_TARGET_IO')),
                ('guest call', dict(calls=launch['calls'] + [dict(launch['calls'][0], main_guest=True)])),
                ('unreturned call', dict(calls=[dict(launch['calls'][0], returned=False)])),
                ('monitor exit', dict(exit_code=3))]:
            expect(not fresh.host_read_freeze(dict(launch, **change)), f'quiesce admitted with {what}')


def main():
    if sys.argv[1:] == ['--predecessors']:
        predecessor_checks()
        print(f'PASS: {checks} predecessor and quiesce-gate checks (no hardware)')
        return
    prefix = sys.argv[1] if len(sys.argv) > 1 else 'installed-fresh-20261016-v1'
    ws = Workspace(ROOT)
    source = ROOT / 'build' / prefix
    record = json.loads((source / 'qualification.json').read_text())
    # A console attempt (--console, --single-user) records both in its environment and boot arguments.
    addition = record.get('boot_argument_addition', '').split()
    args = argparse.Namespace(prefix=prefix, device=record['device'], console='snapintosh_shell=1' in addition,
                              single_user='-s' in addition)
    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / prefix
        shutil.copytree(source, dest, symlinks=True)
        # Inputs that live in the attempt directory are re-pointed at the copy.
        q = json.loads((dest / 'qualification.json').read_text())
        q['inputs_sha256'] = {str(dest / Path(p).name) if Path(p).parent == source else p: h
                              for p, h in q['inputs_sha256'].items()}
        (dest / 'qualification.json').write_text(json.dumps(q, indent=2) + '\n')
        good = (dest / 'qualification.json').read_text()
        expect(fresh.check(ws, args, dest)['variant'] == record['variant'], 'untouched copy refused')

        def bent(edit, needle, restore=None):
            data = json.loads(good)
            edit(data)
            (dest / 'qualification.json').write_text(json.dumps(data))
            refuses(lambda: fresh.check(ws, args, dest), needle)
            (dest / 'qualification.json').write_text(good)
            if restore:
                restore()
        for name in ('root-hash.payload', 'image4.bin'):
            original = (dest / name).read_bytes()
            (dest / name).write_bytes(bytes([original[0] ^ 1]) + original[1:])
            refuses(lambda: fresh.check(ws, args, dest), 'input changed')
            (dest / name).write_bytes(original)
        original = (dest / 'xnuboot.bin').read_bytes()
        (dest / 'xnuboot.bin').write_bytes(original + b'\0')
        refuses(lambda: fresh.check(ws, args, dest), 'prepared monitor changed')
        (dest / 'xnuboot.bin').write_bytes(original)
        bent(lambda d: d['flags'].append('-DSNAP_EXTRA=1'), 'variant flags differ')
        bent(lambda d: d['environment'].update(SNAP_WATCHDOG='60'), 'scope changed')
        bent(lambda d: d.update(profile='j700ap-26A428'), 'scope changed')
        bent(lambda d: d['gpu_steps'].pop(), 'GPU steps differ')
        bent(lambda d: d.update(prefix='other'), 'wrong qualification')
        refuses(lambda: fresh.check(ws, argparse.Namespace(prefix=prefix, device='udp://en5'), dest), 'device differs')
        (dest / 'launch.json').write_text('{}')
        refuses(lambda: fresh.check(ws, args, dest), 'never rerun')
        (dest / 'launch.json').unlink()
        expect(fresh.check(ws, args, dest)['prefix'] == prefix, 'restored copy refused')

    # Independent pins, re-derived.
    component, payload = fresh.root_hash_payload(ROOT)
    expect(component == record['root_hash_component'] and payload == (source / 'root-hash.payload').read_bytes(),
           'root hash differs from the IPSW')
    import txmnative
    image = (source / 'image4.bin').read_bytes()
    expect(len(image) == txmnative.IMAGE_BYTES and hashlib.sha256(image).hexdigest() == txmnative.IMAGE_SHA,
           'TXM helper differs from the qualified image')
    expect(record['auxkc_pin']['sha256'] == fresh.AUXKC_SHA and record['auxkc_pin']['bundles'] == [fresh.KEXT_BUNDLE],
           'AuxKC pin differs')
    expect(record['image']['trust_cache_sha256'] == fresh.TRUST_SHA, 'trust cache differs')
    expect(record['image']['display_slots'] == [fresh.DISPLAY_SLOT], 'display slot differs')
    tree = hashlib.sha256((source / 'device-tree.bin').read_bytes()).hexdigest()
    expect(tree == record['image']['device_tree_sha256'], 'device tree differs from its record')
    expect(record['gpu_steps'] == [list(s) for s in fresh.gpu_steps(ROOT)], 'GPU steps differ')
    # Exactly the launcher's steps, except the runbooks' first rail vote on gmu-boot.
    launcher = fresh.launcher_steps(ROOT)
    expect([n for n, _ in launcher] == [n for n, _ in record['gpu_steps']], 'step order differs from the launcher')
    for (name, base), (_, ours) in zip(launcher, record['gpu_steps']):
        expect(ours == (list(base) + fresh.COLD_BOOT_VOTE if name == 'gmu' else list(base)), f'{name} differs')
    # --gpu-opp-mhz 915 (USERSPACE-GRAPHICS "Speed batch"): only the hfi step changes, by the stage-3 OPP arguments;
    # without the option the steps are the default ones.
    import types
    plain = fresh.gpu_steps(ROOT, types.SimpleNamespace(gpu_opp_mhz=None))
    opp = fresh.gpu_steps(ROOT, types.SimpleNamespace(gpu_opp_mhz=915))
    expect(plain == fresh.gpu_steps(ROOT), 'an unset --gpu-opp-mhz changes the GPU steps')
    for (name, a), (_, b) in zip(plain, opp):
        expect(b == ([*a, '--max-opps', '6', '--perf-opp', '6'] if name == 'hfi' else a), f'--gpu-opp-mhz changed {name}')

    # The GPU gate: only an unprepared read-only status passes.
    # The shape the A16 reported after a cold boot (installed-fresh-20261016-v2's status):
    # q1n1's EFI arena host record with every token zero, the GMU held in reset.
    zero = {'magic': '0x3353363141314151', 'version': '0x00000001', 'arena_base': '0xb7e00000',
            **{k: '0x00000000' for k in ('gmu_ttbr', 'gpu_ttbr', 'boot_token', 'hfi_token', 'hfi_seq', 'oob_token',
                                         'cp_token', 'rb_wptr', 'fence_seq', 'fence_value', 'hwinit_token')}}
    cold = {'order': ['arena', 'status'], 'stopped': None, 'arena': {'base': '0xb7e00000'},
            'host_record': zero, 'gmu': {'sysreset': '0x00000001', 'live': False}}
    expect(fresh.gpu_unprepared(cold), 'cold-boot GPU refused')
    expect(fresh.gpu_unprepared({'order': ['status'], 'arena': {'missing': 'no arena'}}), 'arena-less GPU refused')
    for token in ('gmu_ttbr', 'boot_token', 'hfi_token', 'cp_token', 'fence_seq'):
        prepared = dict(cold, host_record=dict(zero, **{token: '0x00000001'}))
        expect(not fresh.gpu_unprepared(prepared), f'nonzero {token} admitted')
    expect(not fresh.gpu_unprepared(dict(cold, gmu={'live': True})), 'live GMU admitted')
    expect(not fresh.gpu_unprepared(dict(cold, stopped='T1')), 'stopped status admitted')
    expect(not fresh.gpu_unprepared({}), 'empty status admitted')
    # A second cycle (--after-quiesce): the A16's status after installed-fresh-20261017-v6's graceful quiesce,
    # every live token released, the history counters kept.
    quiesced = dict(cold, host_record=dict(zero, hfi_seq='0x00000006', fence_seq='0x00000001', fence_value='0xf3a00001',
                                            rsc_cx='0x00000006', rsc_mx='0x00000006', tz_ok='0x00000001',
                                            pdc_sleep='0x00000001', sqe_probe='0x00000000', p67_token='0x00000000',
                                            fb_mapped='0x00000000'))
    expect(fresh.gpu_quiesced_after_use(quiesced) and not fresh.gpu_unprepared(quiesced), 'quiesced GPU not recognised')
    for token in fresh.LIVE_TOKENS:
        expect(not fresh.gpu_quiesced_after_use(dict(quiesced, host_record=dict(quiesced['host_record'], **{token: '0x00000001'}))),
               f'live {token} admitted for a second cycle')
        expect(not fresh.gpu_quiesced_after_use(dict(quiesced, host_record={k: v for k, v in quiesced['host_record'].items()
                                                                            if k != token})), f'missing {token} admitted')
    expect(not fresh.gpu_quiesced_after_use(dict(quiesced, gmu={'live': True})), 'live GMU admitted for a second cycle')
    expect(not fresh.gpu_quiesced_after_use(dict(quiesced, stopped='Q1')), 'stopped status admitted for a second cycle')
    expect(not fresh.gpu_quiesced_after_use({'order': ['status']}), 'no host record admitted for a second cycle')

    predecessor_checks()

    # The boot hooks, through the real loader module.
    # The boot appends the attempt's recorded addition: TimeSync, plus the console's flags for a console attempt.
    launch = {'boot_argument_addition': record['boot_argument_addition']}
    expect(record['boot_argument_addition'] == fresh.boot_addition(args), 'recorded boot arguments differ')
    loader = ROOT / 'probes/xnuboot.py'
    with tempfile.TemporaryDirectory() as tmp, fresh.boot_hooks(ROOT, Path(tmp), launch) as injected:
        spec = importlib.util.spec_from_file_location('xnuboot', loader)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        expect(module.BOOT_CMDLINE == fresh.BASE_CMDLINE + ' ' + record['boot_argument_addition'] and
               record['boot_argument_addition'].split()[0] == fresh.TIMESYNC_FLAG, 'flag not appended')
        expect(injected == [module.BOOT_CMDLINE] and launch['boot_cmdline'] == module.BOOT_CMDLINE, 'not recorded')
        refuses(lambda: importlib.util.spec_from_file_location('xnuboot', loader), 'exactly once')

    class Nvme:
        lba_bytes = 4096

        def read(self, lba, count):
            return b'not the applied header'.ljust(4096, b'\0')
    # Header refusal: the hook in front of a stub window that arms at LBA 100.
    with tempfile.TemporaryDirectory() as tmp:
        record_header = {}
        import nvme_m3
        stub = nvme_m3.arm_window
        nvme_m3.arm_window = lambda nvme, guid, report: (100, 200)
        try:
            with fresh.boot_hooks(ROOT, Path(tmp), record_header):
                refuses(lambda: nvme_m3.arm_window(Nvme(), 'guid', {'window_armed': {'header': {}}}),
                        'is not the last applied one')
            expect(record_header['window_header_sha256'] ==
                   hashlib.sha256(b'not the applied header'.ljust(4096, b'\0')).hexdigest(), 'header not recorded')
            expect(not (Path(tmp) / 'apfs-before.json').exists(), 'APFS capture ran after a refused header')
        finally:
            nvme_m3.arm_window = stub
    expect(importlib.util.spec_from_file_location('xnuboot', loader).loader.exec_module.__name__ != 'load_module',
           'loader hook left installed')
    print(f'PASS: {checks} installed-fresh checks on {prefix} (no hardware)')


if __name__ == '__main__':
    main()
