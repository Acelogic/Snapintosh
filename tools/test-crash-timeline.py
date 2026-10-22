#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Crash timeline: kernel-message parsing, respawn chains and fatal waits."""
from pathlib import Path
import json
import runpy
import unittest

ROOT = Path(__file__).resolve().parents[1]
ct = runpy.run_path(str(ROOT / 'tools/crash-timeline.py'), run_name='crash_timeline')
BUILD = ROOT / 'build'

# Shaped like the retained buffer: records glued together without newlines.
TEXT = ('[ 3181.559321]: Sandbox apply: WindowServer[79] <bytes>6 duplicate reports\n'
        '[ 3182.452126]: evOpen by 79\n'
        '[ 3219.652985]: Sandbox: WindowServer(79) deny(1) system-info vfs.disk-space\n'
        '[ 3277.176429]: AMFI: Denying core dump for pid 79 (WindowServer)WindowServer[79] '
        'Corpse allowed 1 of 5\n'
        '[ 3277.208916]: evClose by 79\n'
        '[ 3281.136779]: Sandbox apply: WindowServer[128] <bytes>5 duplicate rep\n'
        '[ 3290.693794]: Sandbox apply: ReportCrashService[129] <bytes>void Core\n'
        '[ 3300.000000]: Sandbox: Installer Progre(56) deny(1) file-read-metadata /Library\n'
        '[ 3352.486843]: spaceAMFI: Denying core dump for pid 128 (WindowServer)WindowServer[128] '
        'Corpse allowed 2 of 5\n'
        '[ 3392.222674]: scheduler: thread ws_main_thread [60f] in process WindowServer [131] '
        'triggered fail-safe by spinning for at least 1000000us at fixed priority\n'
        '[ 3395.582181]: tail')
REGS = {str(n): '0x0' for n in range(29)}
REGS.update({'1': '0x3b9847e90000001d', '2': '0x3b9847e9', '19': '0x132798222b',
             '21': '0x3b9aca00'})
SLIDE = 316211200
WAIT_CODE = bytes(range(64))
WITNESS = bytes(range(64, 128))


def capture(text=TEXT, threads=None):
    live = [dict(pid=1, name='launchd', threads=[]), dict(pid=56, name='Installer Progre', threads=[]),
            dict(pid=127, name='ReportCrash', threads=[]),
            dict(pid=129, name='ReportCrashServi', threads=[]),
            dict(pid=131, name='WindowServer', threads=threads or [])]
    return dict(kernel_messages=dict(text=text), user_processes=dict(processes=live))


def wait_thread(pc_unslid=ct['SEMAPHORE_TIMEDWAIT_TRAP_PC'], site=0x18708b608):
    frames = [dict(return_site_va=hex(ct['SEMA4_TIMEDWAIT_RETURN'] + SLIDE), return_site_hex=WITNESS.hex()),
              dict(return_site_va=hex(site + SLIDE), return_site_hex=WAIT_CODE.hex()),
              dict(fp='0x0')]
    return dict(tid=1551, saved_user_state=dict(pc=hex(pc_unslid + SLIDE), registers=REGS),
                user_frame_chain=dict(frames=frames))


class FakeCache:
    def __init__(self, wait_bytes=WAIT_CODE):
        self.wait_bytes = wait_bytes

    def match_code(self, pc, code):
        if code == WITNESS:
            return dict(slide=SLIDE)
        raise ValueError('no match')

    def read(self, address, size):
        assert address == 0x18708b608
        return self.wait_bytes[:size]


class TimelineTests(unittest.TestCase):
    def test_entries_split_glued_records(self):
        rows = ct['entries'](TEXT)
        self.assertEqual(rows[0][0], 3181.559321)
        self.assertEqual(len(rows), 11)
        self.assertEqual(ct['entries'](''), [])

    def test_crashes_names_lifetimes_and_chain(self):
        t = ct['timeline'](capture())
        self.assertEqual([(c['pid'], c['name']) for c in t['crashes']],
                         [(79, 'WindowServer'), (128, 'WindowServer')])
        first, second = t['crashes']
        self.assertTrue(first['core_dump_denied'] and second['core_dump_denied'])
        self.assertEqual((first['corpse'], second['corpse']), ('1 of 5', '2 of 5'))
        self.assertEqual(first['lived_at_least_s'], 95.617)
        self.assertEqual(second['lived_at_least_s'], 71.35)
        self.assertEqual(first['hid'], dict(open=3182.452126, close=3277.208916))
        self.assertEqual(t['respawn_chains'],
                         {'WindowServer': dict(crashed=[79, 128], live=[131], respawned=True)})
        self.assertEqual(t['crash_reporters'], [(127, 'ReportCrash'), (129, 'ReportCrashServi')])
        self.assertEqual(t['spin_failsafes'], {'131': 1})
        self.assertEqual(t['message_span'], [3181.559321, 3395.582181])

    def test_names_with_spaces_and_no_false_crash(self):
        t = ct['timeline'](capture(TEXT.replace('Corpse allowed', 'corpse')))
        # AMFI's refusal alone still marks the SA_CORE death; no corpse text.
        self.assertTrue(all('corpse' not in c for c in t['crashes']))
        t = ct['timeline'](capture('[ 1.000000]: Sandbox: Installer Progre(56) deny(1) x'))
        self.assertEqual(t['crashes'], [])

    def test_known_wait_deadline_from_registers(self):
        waits = ct['known_waits'](FakeCache(), capture(threads=[wait_thread()]))
        self.assertEqual(waits['slide'], hex(SLIDE))
        (row,) = waits['waits']
        self.assertEqual((row['pid'], row['tid'], row['timeout_s']), (131, 1551, 30))
        self.assertEqual(row['remaining_at_trap_s'], 29.999836)
        self.assertEqual(row['deadline_guest_s'], 3427.860844)
        self.assertEqual(row['wait_started_guest_s'], 3397.860844)
        self.assertIn('No suitable Metal devices', row['outcome'])

    def test_known_wait_not_blocked_has_no_deadline(self):
        waits = ct['known_waits'](FakeCache(), capture(threads=[wait_thread(pc_unslid=0x180000000)]))
        (row,) = waits['waits']
        self.assertNotIn('deadline_guest_s', row)

    def test_captured_bytes_must_match_cache(self):
        with self.assertRaisesRegex(ValueError, 'captured bytes differ'):
            ct['known_waits'](FakeCache(bytes(64)), capture(threads=[wait_thread()]))

    def test_no_witness_is_reported_not_guessed(self):
        thread = wait_thread()
        thread['user_frame_chain']['frames'][0]['return_site_hex'] = bytes(64).hex()
        waits = ct['known_waits'](FakeCache(), capture(threads=[thread]))
        self.assertIsNone(waits['slide'])
        self.assertEqual(waits['waits'], [])

    @unittest.skipUnless((BUILD / 'bootfb-root-evict-1200s-20260924-kernel-waits.json').is_file(),
                         'root-evict capture not present')
    def test_root_evict_capture(self):
        t = ct['timeline'](json.loads((BUILD / 'bootfb-root-evict-1200s-20260924-kernel-waits.json').read_text()))
        self.assertEqual([(c['pid'], c['name'], c['corpse']) for c in t['crashes']],
                         [(79, 'WindowServer', '1 of 5'), (128, 'WindowServer', '2 of 5')])
        self.assertEqual(t['respawn_chains']['WindowServer']['live'], [131])


if __name__ == '__main__':
    unittest.main()
