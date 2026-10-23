#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Early stop, host side: the native monitor logic (tools/test-early-stop.c,
sanitized), the report/params/context layouts, SNAP_EARLY_STOP* settings, the
ADT advertisement, classification, and tools/request-stop.py's wire format
against golden vectors shared with q1n1 tools/test-q1n1-call-service.c --
including a loopback exchange with a stand-in stop port. No hardware.

    python3 tools/test-early-stop.py
"""
import importlib.util
import json
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
import zlib
from source_text import read_source

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'probes'), str(ROOT / 'tools')]
import run                                                   # noqa: E402
import early_stop                                            # noqa: E402
import adreno                                                # noqa: E402


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rs = load('request_stop', ROOT / 'tools/request-stop.py')
SESSION = 0x5eed5eed12345678
# Produced by tools/request-stop.py and parsed byte-for-byte by q1n1's
# tools/test-q1n1-call-service.c; GOLDEN_REPLY is what that parser answered.
GOLDEN_QUERY = ('51315352010001004444333322221111' + '00' * 80 + '18cf7ec800000000')
GOLDEN_STOP = ('5131535201000200efcdab896745230178563412ed5eed5e0100000000000000'
               '636f6e647563746f723a2072756e206c6f6f6b7320646f6e65' + '00' * 39 + '4f0c152300000000')
GOLDEN_REPLY = ('5131534101000200efcdab896745230178563412ed5eed5e0000000007000000'
                'efcdab89674523010300000000000000020000000000000074cd0a2000000000')


class Native(unittest.TestCase):
    def test_monitor_logic_under_sanitizers(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = str(Path(directory) / 'early-stop')
            subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-pthread',
                            '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                            '-Wall', '-Wextra', '-Werror', '-Icompat', '-Ishadow',
                            'tools/test-early-stop.c', 'compat/early-stop.c', 'compat/service-lock.c',
                            '-o', binary], cwd=ROOT, check=True, timeout=120)
            result = subprocess.run([binary], capture_output=True, text=True, timeout=120)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('PASS: early stop', result.stdout)


@unittest.skipUnless((ROOT / 'gpu/adreno-kext/kext/src/AdrenoEarlyStop.cpp').is_file(),
                     'this runtime root carries the monitor side only; the kext/plug-in hook is '
                     'ported to the AuxKC sources separately (docs/EARLY-STOP-20260928.md, step 4)')
class Guest(unittest.TestCase):
    """The plug-in report and the kext request build and stay inert without the launch's opt-in."""
    plugin = ROOT / 'gpu/adreno-kext/plugin'

    def test_plugin_report_is_inert_and_raises_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = str(Path(directory) / 'early-stop')
            subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-mmacosx-version-min=27.0', '-fobjc-arc',
                            '-fobjc-arc-exceptions', '-O1', '-g', '-Wall', '-Werror',
                            str(self.plugin / 'harness/early-stop.m'), str(self.plugin / 'AdrenoMetal/AdrenoEarlyStop.m'),
                            '-framework', 'Foundation', '-framework', 'IOKit', '-o', binary], check=True, timeout=300)
            result = subprocess.run([binary], capture_output=True, text=True, timeout=60)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('PASS', result.stdout)

    def test_fill_raises_report_first(self):
        source = (self.plugin / 'AdrenoMetal/AdrenoFillCommands.m').read_text()
        self.assertNotIn('NSException raise', source)
        self.assertEqual(source.count('ADRENO_RAISE_FATAL('), 17)
        self.assertIn('AdrenoEarlyStop.m', (self.plugin / 'build.sh').read_text())

    def test_kext_issues_the_admitted_instruction(self):
        kext = ROOT / 'gpu/adreno-kext/kext'
        self.assertIn('AdrenoEarlyStop.cpp', (kext / 'build.sh').read_text())
        with tempfile.TemporaryDirectory() as directory:
            env = dict(__import__('os').environ, OUT=directory)
            subprocess.run(['sh', str(kext / 'build.sh')], check=True, timeout=600, env=env,
                           capture_output=True)
            binary = Path(directory) / 'AdrenoX2.kext/Contents/MacOS/AdrenoX2'
            text = subprocess.run(['/opt/homebrew/opt/llvm/bin/llvm-objdump', '-d', str(binary)],
                                  capture_output=True, text=True, check=True).stdout
        # hvc #0xad16 is exactly the word compat/early-stop.c admits (HVC_WORD(ADRENO_GUEST_HVC)).
        request = re.search(r'<__Z\d+AdrenoEarlyStopRequest\w*>:\n(.*?)\n\n', text, re.S)[1]
        self.assertIn('d415a2c2', request.replace(' ', ''))
        self.assertIn('#0x6', request)                        # x0 = ADRENO_GUEST_STOP 0x00010006
        self.assertIn('#0x1, lsl #16', request)


class Layout(unittest.TestCase):
    header = (ROOT / 'compat/early-stop.h').read_text()
    monitor = read_source(ROOT / 'probes/xnuboot.c')

    def members(self, name):
        body = re.search(r'struct %s \{(.*?)\n\};' % name, self.header, re.S)[1]
        body = re.sub(r'/\*.*?\*/', '', body, flags=re.S)
        names = []
        for declaration in body.split(';'):
            declaration = declaration.strip()
            if not declaration:
                continue
            fields = declaration.split(None, 1)[1]
            for field in fields.split(','):
                field = field.strip()
                array = re.fullmatch(r'(\w+)\[(\d+)\]', field)
                names += [f'{array[1]}{n}' for n in range(int(array[2]))] if array else [field]
        return names

    def test_decoder_matches_header(self):
        self.assertEqual(self.members('early_stop_state'), early_stop.FIELDS)
        self.assertEqual(len(early_stop.FIELDS), int(re.search(r'EARLY_STOP_STATE_WORDS (\d+)', self.header)[1]))
        self.assertEqual(len(self.members('early_stop_params')), early_stop.PARAMS_WORDS)

    def test_report_offset(self):
        adreno_words = int(re.search(r'#define ADRENO_STATE_WORDS (\d+)',
                                     (ROOT / 'compat/adreno.h').read_text())[1])
        self.assertIn('#define OUT_EARLY_STOP (OUT_GPU_FLOW + ADRENO_STATE_WORDS)', self.monitor)
        self.assertEqual(run.EARLY_STOP_OFFSET, run.GPU_FLOW_OFFSET + adreno_words * 8)
        gpu = load('adreno_counters', ROOT / 'tools/adreno_counters.py')
        self.assertEqual(run.EARLY_STOP_OFFSET, run.GPU_FLOW_OFFSET + gpu.SIZE)
        self.assertLessEqual(run.EARLY_STOP_OFFSET + early_stop.SIZE, 16 + 0x10000)

    def test_params_and_context_are_appended(self):
        import xnuboot as xb
        self.assertEqual(xb.PARAMS_WORDS, int(re.search(r'#define PARAMS_WORDS (\d+)', self.monitor)[1]))
        layout = load('monitor_layout', ROOT / 'tools/monitor_layout.py').MonitorLayout()
        self.assertEqual(layout.size('params'), xb.PARAMS_WORDS * 8)
        self.assertEqual(layout.offset('params', 'early_stop'), (xb.PARAMS_WORDS - 6) * 8)
        # Earlier monitor fields grow independently. Verify actual adjacent
        # compiled layout, not historical generation53 absolute offsets.
        memo_start = layout.offset('context', 'root_memo')
        self.assertEqual(memo_start - layout.offset('context', 'sep_sks_request'), 16384)
        memo_end = memo_start + layout.size('sptm_root_memo')
        self.assertEqual(layout.offset('context', 'attr_updates'), memo_end)
        attr_end = memo_end + layout.size('attr_update_state')
        self.assertEqual(layout.offset('context', 'early_stop'), attr_end)
        stop_end = attr_end + early_stop.SIZE
        self.assertEqual(layout.offset('context', 'inactive_mirror'), stop_end)
        mirror_end = stop_end + layout.size('inactive_mirror_state')
        # Native page tables (present in every build, used with
        # SNAP_NATIVE_TABLES): per-CPU selection, source bitmap, counters.
        self.assertEqual(layout.offset('context', 'native_cpu'), mirror_end)
        sources = mirror_end + 6 * layout.size('native_cpu')
        self.assertEqual(layout.offset('context', 'native_sources'), sources)
        stats = layout.offset('context', 'native_stats')
        self.assertEqual(stats, sources + 61440 // 64 * 8)
        native_end = stats + layout.size('native_table_stats')
        # Shared-region groups (SNAP_NATIVE_SHARED) follow, last.
        self.assertEqual(layout.offset('context', 'native_shared'), native_end)
        shared_end = native_end + layout.size('native_shared')
        # Later features append beyond shared_ranges; require containment and alignment.
        self.assertGreaterEqual(layout.size('context'), (shared_end + 63) & ~63)
        self.assertEqual(layout.size('context') % 64, 0)


class Settings(unittest.TestCase):
    def test_off_unless_named(self):
        self.assertIsNone(early_stop.settings({}))
        self.assertIsNone(early_stop.settings({'SNAP_EARLY_STOP': ' '}))

    def test_triggers_and_bounds(self):
        guest = early_stop.settings({'SNAP_EARLY_STOP': 'guest'})
        self.assertTrue(guest.guest and not guest.host)
        self.assertEqual((guest.delay, guest.max_delay, guest.poll_ms), (20, 120, 200))
        self.assertEqual(guest.params_words(), [1, 120, 0, 0, 0, 0])
        both = early_stop.settings({'SNAP_EARLY_STOP': 'host, guest', 'SNAP_EARLY_STOP_DELAY': '5',
                                    'SNAP_EARLY_STOP_MAX_DELAY': '60', 'SNAP_EARLY_STOP_POLL_MS': '100'})
        self.assertEqual((both.flags, both.delay, both.max_delay, both.poll_ms), (3, 5, 60, 100))
        words = both.params_words(0xb0012340, 0xb0400000)
        self.assertEqual(words[:5], [3, 60, 0xb0012340, 0xb0400000, 100])
        self.assertTrue(words[5] and words[5] == both.session)
        with self.assertRaises(ValueError):
            both.params_words()                      # host needs q1n1's call service
        tight = early_stop.settings({'SNAP_EARLY_STOP': 'guest', 'SNAP_EARLY_STOP_MAX_DELAY': '10'})
        self.assertEqual(tight.delay, 10)            # the default never exceeds the bound
        for bad in ({'SNAP_EARLY_STOP': 'watchdog'},
                    {'SNAP_EARLY_STOP': 'guest', 'SNAP_EARLY_STOP_DELAY': '121'},
                    {'SNAP_EARLY_STOP': 'guest', 'SNAP_EARLY_STOP_MAX_DELAY': '3601'},
                    {'SNAP_EARLY_STOP': 'host', 'SNAP_EARLY_STOP_POLL_MS': '19'},
                    {'SNAP_EARLY_STOP': 'host', 'SNAP_EARLY_STOP_POLL_MS': '5001'},
                    {'SNAP_EARLY_STOP': 'guest', 'SNAP_EARLY_STOP_DELAY': 'soon'}):
            with self.assertRaises(ValueError, msg=bad):
                early_stop.settings(bad)
        record = both.record()
        self.assertEqual(int(record['session'], 16), both.session)
        self.assertTrue(record['host'] and record['guest'])


class HostLink(unittest.TestCase):
    class Proxy:
        def __init__(self, endpoint=None):
            if endpoint is not None:
                self.endpoint = endpoint

    def test_host_trigger_needs_the_ncm_link(self):
        self.assertEqual(run.host_stop_link(self.Proxy('udp://en5')), 'udp://en5')
        for endpoint in (None, '', '/dev/cu.usbmodem1101', 'build/uefi/qemu.sock', 'udp://'):
            with self.assertRaises(ValueError, msg=endpoint):
                run.host_stop_link(self.Proxy(endpoint))


class Tree(unittest.TestCase):
    class Node:
        def __init__(self):
            self.props = {}

        def add(self, path, prop, value):
            if prop in self.props:
                raise KeyError(prop)
            self.props[prop] = (path, value)

    def test_advertisement(self):
        dt = self.Node()
        adreno.advertise_early_stop(dt, 20)
        self.assertEqual(dt.props[adreno.STOP_ABI_PROPERTY], (adreno.GPU_NODE, struct.pack('<I', 1)))
        self.assertEqual(dt.props[adreno.STOP_DELAY_PROPERTY], (adreno.GPU_NODE, struct.pack('<I', 20)))
        with self.assertRaises(KeyError):
            adreno.advertise_early_stop(dt, 20)
        for bad in (-1, 3601):
            with self.assertRaises(ValueError):
                adreno.advertise_early_stop(self.Node(), bad)
        guest = (ROOT / 'compat/adreno-guest.h').read_text()
        self.assertIn(f'#define ADRENO_GUEST_STOP_PROPERTY "{adreno.STOP_ABI_PROPERTY}"', guest)
        self.assertIn(f'#define ADRENO_GUEST_STOP_DELAY_PROPERTY "{adreno.STOP_DELAY_PROPERTY}"', guest)

    def test_real_tree_only_when_opted_in(self):
        """The loader's own device tree for the installed Adreno profile (local firmware)."""
        import contextlib
        import io
        import xnuboot as xb
        if not (ROOT / 'downloads/extracted').exists():
            self.skipTest('local firmware tree absent')
        try:
            for opted in (None, early_stop.settings({'SNAP_EARLY_STOP': 'guest', 'SNAP_EARLY_STOP_DELAY': '15'})):
                xb.EARLY_STOP = opted
                xb.configure_guest('j700ap-26A428-xars-uniform-auxkc-installed-adreno')
                xb.place(0x8c0000000, guest_span=8192 << 20)
                with contextlib.redirect_stdout(io.StringIO()):
                    dt = xb.build_devicetree()
                gpu = dt.nodes[adreno.GPU_NODE]
                if opted:
                    self.assertEqual(gpu[adreno.STOP_ABI_PROPERTY].value, struct.pack('<I', 1))
                    self.assertEqual(gpu[adreno.STOP_DELAY_PROPERTY].value, struct.pack('<I', 15))
                else:
                    self.assertNotIn(adreno.STOP_ABI_PROPERTY, gpu)
                    self.assertNotIn(adreno.STOP_DELAY_PROPERTY, gpu)
                self.assertEqual(gpu['snapintosh,guest-fence-abi'].value, struct.pack('<I', 1))
        finally:
            xb.EARLY_STOP = None
            xb.configure_guest('j700ap-26A428-sep-preload')


def record(**fields):
    words = dict.fromkeys(early_stop.FIELDS, 0)
    words.update(fields)
    raw = struct.pack(f'<{len(early_stop.FIELDS)}Q', *[words[k] for k in early_stop.FIELDS])
    return early_stop.decode(raw)


TALLY = dict(service_owner=0, service_stop=1 << 32 | 3, service_faults=(0,) * 6,
             service_lifecycle=(1 << 63) | 3, service_reusable=1)


class Classification(unittest.TestCase):
    def test_early_stop_event(self):
        log = [(1, 0, 0, 0, 0, 0), (run.EV_EARLY_STOP, 0xfffffe0010000000, 1 << 32 | 1, 0x2a, 20, 0)]
        code, why = run.classify(1, 0, '', log)
        self.assertEqual(code, run.EXIT_EARLY_STOP)
        self.assertIn('first AdrenoDisplay present', why)
        self.assertEqual(run.EXIT_NAMES[code], 'early stop on request')

    def test_record_survives_a_lost_log(self):
        fired = record(state=3, source=2, reason=1, detail=0xabc, outcome=1, fire_cpu=3,
                       text0=int.from_bytes(b'operator', 'little'))
        code, why = run.classify(1, 0, '', [(1, 0, 0, 0, 0, 0)], tally=dict(TALLY, early_stop=fired),
                                 dropped=900)
        self.assertEqual(code, run.EXIT_EARLY_STOP)
        self.assertIn('host request', why)
        self.assertIn('"operator"', why)

    def test_what_outranks_it(self):
        early = (run.EV_EARLY_STOP, 0, 2 << 32 | 1, 0, 0, 0)
        self.assertEqual(run.classify(1, 0, '', [(run.EV_SERROR, 0, 0xbe000000, 0, 0, 0), early])[0],
                         run.EXIT_SERROR)
        self.assertEqual(run.classify(1, 0, '', [(run.EV_DEVICE_RESET, 0, 1, 0, 0, 0), early])[0],
                         run.EXIT_GUEST_RESET)
        self.assertEqual(run.classify(1, 0, 'panic(cpu 1 caller 0x0): x\n', [early])[0], run.EXIT_PANIC)
        faulted = dict(TALLY, service_stop=2 << 32 | 1)
        self.assertEqual(run.classify(1, 0, '', [early], tally=faulted)[0], run.EXIT_EL2_FAULT)

    def test_superseded_request_leaves_the_watchdog(self):
        pending = record(state=2, source=1, reason=2, outcome=3)
        code, _ = run.classify(1, 0, '', [(run.EV_WATCHDOG, 0, 0, 0, 0, 0)],
                               tally=dict(TALLY, early_stop=pending))
        self.assertEqual(code, run.EXIT_WATCHDOG)
        self.assertEqual(run.classify(1, 0, '', [(run.EV_WATCHDOG, 0, 0, 0, 0, 0)],
                                      tally=dict(TALLY, early_stop=record()))[0], run.EXIT_WATCHDOG)

    def test_labels_and_summary(self):
        self.assertIn(run.EV_EARLY_STOP, run.EVENTS)
        self.assertIn(run.EV_EARLY_STOP_REQUEST, run.EVENTS)
        self.assertEqual(early_stop.summary(record()), [])
        lines = early_stop.summary(record(state=3, source=1, reason=2, detail=7, requested_delay=500,
                                          accepted_delay=120, request_ticks=0, fire_ticks=24000000 * 120,
                                          fire_cpu=2, outcome=1, refusals=1,
                                          last_refusal=(1 << 64) - 80, duplicates=3), 24000000)
        text = '\n'.join(lines)
        self.assertIn('AdrenoMetal failure before raise', text)
        self.assertIn('500s asked, 120s accepted', text)
        self.assertIn('fired on CPU1 120.000s after the request', text)
        self.assertIn('caller not admitted', text)
        self.assertIn('3 request(s) did not shorten', text)


class Wire(unittest.TestCase):
    def test_golden_requests(self):
        self.assertEqual(rs.encode(rs.QUERY, 0x1111222233334444).hex(), GOLDEN_QUERY)
        self.assertEqual(rs.encode(rs.STOP, 0x0123456789abcdef, SESSION, 1, 0,
                                   'conductor: run looks done').hex(), GOLDEN_STOP)
        stop = bytes.fromhex(GOLDEN_STOP)
        self.assertEqual(len(stop), 104)
        self.assertEqual(struct.unpack_from('<I', stop, 96)[0], zlib.crc32(stop[:96]))

    def test_golden_reply(self):
        reply = rs.decode(bytes.fromhex(GOLDEN_REPLY))
        self.assertEqual((reply['status'], reply['armed'], reply['latched'], reply['mine']), (0, True, True, True))
        self.assertEqual((reply['nonce'], reply['session'], reply['latch_nonce']),
                         (0x0123456789abcdef, SESSION, 0x0123456789abcdef))
        self.assertEqual((reply['polls'], reply['dropped_proxy_datagrams']), (3, 2))
        raw = bytearray.fromhex(GOLDEN_REPLY)
        for index in (0, 4, 30, 56, 60):
            broken = bytearray(raw)
            broken[index] ^= 1
            with self.assertRaises(ValueError):
                rs.decode(bytes(broken))
        with self.assertRaises(ValueError):
            rs.decode(bytes(raw[:63]))

    def test_text_limits(self):
        self.assertEqual(len(rs.text_field('x' * 200)), 63)
        self.assertEqual(rs.text_field('x' * 62 + 'é'), b'x' * 62)     # never a split character
        with self.assertRaises(ValueError):
            rs.encode(3, 1)
        with self.assertRaises(ValueError):
            rs.encode(rs.STOP, 1, 1, 1, -1)

    def test_arguments(self):
        import contextlib
        import io

        def refused(argv):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = rs.main(argv)
            return code == 1 and json.loads(out.getvalue())['result'] == 'ARGUMENTS'
        for argv in (['--device', 'en5', '--reason', 'x'],
                     ['--device', 'udp://no-such-interface-9', '--reason', 'x'],
                     ['--device', 'udp://lo0', '--reason', 'x', '--delay', '3601']):
            self.assertTrue(refused(argv), argv)
        with tempfile.NamedTemporaryFile('w', suffix='.json') as launch:
            launch.write(json.dumps(dict(host=False, session='0x1')))
            launch.flush()
            self.assertTrue(refused(['--device', 'udp://lo0', '--reason', 'x', '--launch-record', launch.name]))
        with tempfile.NamedTemporaryFile('w', suffix='.json') as launch:
            launch.write(json.dumps(dict(host=True, session=f'{SESSION:#x}')))
            launch.flush()
            self.assertTrue(refused(['--device', 'udp://lo0', '--reason', 'x', '--session', '1',
                                     '--launch-record', launch.name]))


class Loopback(unittest.TestCase):
    """The tool against a stand-in for q1n1's stop port on ::1, same rules as
    call-service.c: QUERY answers the armed session; the first STOP latches."""

    def serve(self, armed_session, replies, lose_first_ack=False, disarm_after_latch=False,
              disarm_after_query=False, latched=None):
        server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        server.bind(('::1', 0))
        server.settimeout(5)
        state = dict(latched=latched, armed=armed_session, lost=False)

        def loop():
            for _ in range(replies):
                try:
                    data, peer = server.recvfrom(256)
                except socket.timeout:
                    return
                magic, version, op, nonce, session, reason, delay, text, crc, zero = rs.REQUEST.unpack(data)
                ok = magic == rs.REQUEST_MAGIC and crc == zlib.crc32(data[:96]) and not zero
                armed = state['armed']
                status, flags = 0, 1 if armed else 0
                if not ok:
                    status = -1
                elif op == rs.STOP:
                    if not armed:
                        status = -2
                    elif session != armed:
                        status = -3
                    elif state['latched'] is None:
                        state['latched'] = (nonce, text.split(b'\0')[0].decode())
                        flags |= 4
                        if disarm_after_latch:        # the monitor takes it and stops
                            state['armed'] = 0
                        if lose_first_ack and not state['lost']:
                            state['lost'] = True      # this acknowledgement never arrives
                            continue
                    else:
                        status = 1
                elif disarm_after_query:
                    state['armed'] = 0
                if state['latched']:
                    flags |= 2
                body = struct.pack('<IHHQQiIQQQ', rs.REPLY_MAGIC, 1, op, nonce,
                                   armed, status, flags,
                                   state['latched'][0] if state['latched'] else 0, 9, 0)
                server.sendto(body + struct.pack('<II', zlib.crc32(body), 0), peer)
        thread = threading.Thread(target=loop)
        thread.start()
        return server, thread, state

    def exchange(self, armed, argv, replies=2, **serve):
        server, thread, state = self.serve(armed, replies, **serve)
        saved = rs.TARGET, rs.PORT
        rs.TARGET, rs.PORT = '::1', server.getsockname()[1]
        try:
            import io
            import contextlib
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = rs.main(['--device', 'udp://lo0', '--timeout', '0.5', '--tries', '2'] + argv)
            return code, json.loads(out.getvalue()), state
        finally:
            rs.TARGET, rs.PORT = saved
            thread.join()
            server.close()

    def test_query_then_stop(self):
        code, result, state = self.exchange(SESSION, ['--reason', 'WindowServer is up'])
        self.assertEqual((code, result['result'], result['first']), (0, 'LATCHED', True))
        self.assertFalse(result['guest_stop_verified'])
        self.assertFalse(result['gpu_quiesce_verified'])
        self.assertEqual(result['evidence'], 'REQUEST_ONLY')
        self.assertEqual(int(result['session'], 16), SESSION)
        self.assertEqual(state['latched'][1], 'WindowServer is up')

    def test_lost_acknowledgement_while_armed(self):
        # The retransmission is answered "already latched" -- by this request.
        code, result, state = self.exchange(SESSION, ['--reason', 'x'], replies=3, lose_first_ack=True)
        self.assertEqual((code, result['result'], result['first']), (0, 'LATCHED', True))
        self.assertEqual((result['reply']['status'], result['reply']['latch_nonce']), (1, state['latched'][0]))

    def test_lost_acknowledgement_after_the_run_stopped(self):
        # By the retransmission the monitor has taken the latch and disarmed:
        # "not armed", but the latch nonce is still this request's.
        code, result, state = self.exchange(SESSION, ['--reason', 'x'], replies=3, lose_first_ack=True,
                                            disarm_after_latch=True)
        self.assertEqual((code, result['result'], result['first']), (0, 'LATCHED', True))
        self.assertEqual((result['reply']['status'], result['reply']['armed']), (-2, False))

    def test_someone_elses_latch_after_disarm_is_refused(self):
        code, result, state = self.exchange(SESSION, ['--reason', 'x'], replies=2, disarm_after_query=True,
                                            latched=(0x5eed, 'earlier'))
        self.assertEqual((code, result['result'], result['first']), (2, 'REFUSED', False))
        self.assertEqual(state['latched'], (0x5eed, 'earlier'))

    def test_not_armed(self):
        code, result, _ = self.exchange(0, ['--reason', 'x'], replies=1)
        self.assertEqual((code, result['result']), (2, 'NOT_ARMED'))

    def test_bound_session_refuses_another_run(self):
        code, result, state = self.exchange(SESSION, ['--reason', 'x', '--session', '1234'], replies=1)
        self.assertEqual((code, result['result']), (2, 'SESSION_MISMATCH'))
        self.assertIsNone(state['latched'])

    def test_query_only(self):
        code, result, _ = self.exchange(SESSION, ['--query'], replies=1)
        self.assertEqual((code, result['result']), (0, 'ARMED'))

    def test_silence(self):
        saved = rs.TARGET, rs.PORT
        rs.TARGET, rs.PORT = '::1', 9          # discard: nothing answers
        try:
            import io
            import contextlib
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = rs.main(['--device', 'udp://lo0', '--reason', 'x', '--timeout', '0.2', '--tries', '1'])
            self.assertEqual((code, json.loads(out.getvalue())['result']), (3, 'NO_ANSWER'))
        finally:
            rs.TARGET, rs.PORT = saved


if __name__ == '__main__':
    unittest.main()
