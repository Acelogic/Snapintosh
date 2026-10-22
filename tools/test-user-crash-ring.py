#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The Python crash-ring reader against the C ABI and the target layout.

Builds a host program from compat/user-crash.h that records known events,
decodes its bytes, and checks the appended context field in clang's
aarch64 record layout (append-only, per-vCPU, exact size)."""
from pathlib import Path
import os
import re
import runpy
import struct
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ring = runpy.run_path(str(ROOT / 'tools/user_crash_ring.py'))

PROGRAM = r'''
#include <stdio.h>
#include <string.h>
#include "user-crash.h"
static const char *msg = "No suitable Metal devices present after 30 seconds.";
static int reader(void *ctx, uint64_t va, uint64_t *out)
{
    (void)ctx;
    if (va >= 0x16af86b40 && va < 0x16af86c40) {       /* four chained frames */
        uint64_t n = (va - 0x16af86b40) / 16, slot = (va - 0x16af86b40) % 16;
        *out = slot ? 0x199e1b600 + n * 4 : 0x16af86b40 + (n + 1) * 16;
        return 1;
    }
    if (va >= 0x100a3c010 && va < 0x100a3c050) {        /* reason string at +3 */
        unsigned char b[8] = {0};
        for (unsigned i = 0; i < 8; i++) {
            uint64_t a = va + i;
            if (a >= 0x100a3c013 && a - 0x100a3c013 <= strlen(msg)) b[i] = (unsigned char)msg[a - 0x100a3c013];
        }
        memcpy(out, b, 8);
        return 1;
    }
    return 0;
}
int main(void)
{
    static struct user_crash_ring rings[6];
    uint64_t x[31];
    for (unsigned i = 0; i < 31; i++) x[i] = 0x1000 + i;
    x[1] = 6; x[16] = 328; x[29] = 0x16af86b40;
    user_crash_record(&rings[3], USER_CRASH_SELF_SIGNAL, 3, 82268660267ULL, 7, 0x56000080,
                      0x1935db650, 0, x, 0x16af86b00, 0xa23308000ULL | (0x1fULL << 48),
                      0xfffffe1e43a13740ULL, 0x16af87000, reader, 0);
    x[29] = 0; x[4] = 0x100a3c013;
    user_crash_record(&rings[1], USER_CRASH_ABORT_PAYLOAD, 1, 24000000ULL * 100, 8, 0x56000080,
                      0x100, 0, x, 0x16f000000, 0x9000000000ULL, 0, 0, reader, 0);
    for (unsigned n = 0; n < 11; n++)
        user_crash_record(&rings[5], USER_CRASH_EXCEPTION, 5, 1000 + n, n, 0xf200c471ULL,
                          0x180000000 + 4 * n, 0, x, 0x16f000000, 0, 0, 0, 0, 0);
    fwrite(rings, sizeof rings, 1, stdout);
    return 0;
}
'''


def build_rings():
    with tempfile.TemporaryDirectory(prefix='crash-ring-') as d:
        src = Path(d) / 'p.c'
        src.write_text(PROGRAM)
        exe = Path(d) / 'p'
        subprocess.run([os.environ.get('CC', 'cc'), '-std=c11', '-O1', '-Wall', '-Wextra', '-Werror',
                        '-I' + str(ROOT / 'compat'), str(src), '-o', str(exe)], check=True)
        return subprocess.run([str(exe)], check=True, capture_output=True).stdout


class RingTests(unittest.TestCase):
    raw = build_rings()

    def test_sizes(self):
        self.assertEqual(len(self.raw), 6 * ring['RING_BYTES'])
        self.assertEqual(ring['RING_BYTES'], 32 + 8 * 232)

    def reader(self):
        raw = self.raw
        layout = 'x | struct user_crash_ring[6] user_crashes\n'
        return (lambda pa, n: raw[pa - 0x1000:pa - 0x1000 + n], 0x1000,
                lambda kind, field: 0, layout)

    def test_decode_abort_frames_and_payload_reason(self):
        read, work, offset, layout = self.reader()
        result = ring['read_context'](read, work, offset, layout)
        self.assertIsNone(result['guest_user_signal'])
        crashes = result['user_crashes']
        self.assertEqual(crashes['recorded'], [0, 1, 0, 1, 0, 11])
        self.assertEqual(crashes['lost'], [0, 0, 0, 0, 0, 3])
        rows = crashes['rows']
        abort = [r for r in rows if r['kind'] == 'self_signal'][0]
        self.assertEqual((abort['cpu'], abort['signal'], abort['exception']), (3, 'SIGABRT', 'SVC'))
        self.assertEqual(abort['frames'], [0x199e1b600, 0x199e1b604, 0x199e1b608, 0x199e1b60c])
        self.assertEqual((abort['root'], abort['asid']), (0xa23308000, 0x1f))
        self.assertAlmostEqual(abort['guest_s'], 3427.860844458, places=6)
        payload = [r for r in rows if r['kind'] == 'abort_with_payload'][0]
        self.assertEqual(payload['reason'], 'No suitable Metal devices present after 30 seconds.')
        brks = [r for r in rows if r['kind'] == 'fatal_exception']
        self.assertEqual([r['seq'] for r in brks], list(range(4, 12)))
        self.assertTrue(all(r['pac_trap'] and r['brk_immediate'] == 0xc471 for r in brks))
        # Merged by guest time: the payload abort (100 s) precedes the rest.
        self.assertEqual(rows[-1]['kind'], 'self_signal')

    def test_corrupt_ring_refused(self):
        raw = bytearray(self.raw[3 * ring['RING_BYTES']:4 * ring['RING_BYTES']])
        struct.pack_into('<Q', raw, 32, 5)                   # slot 0 claims seq 5
        with self.assertRaisesRegex(ValueError, 'holds sequence'):
            ring['decode_ring'](bytes(raw), 3)
        with self.assertRaisesRegex(ValueError, 'holds a record from CPU'):
            ring['decode_ring'](self.raw[3 * ring['RING_BYTES']:4 * ring['RING_BYTES']], 2)
        with self.assertRaisesRegex(ValueError, 'bytes'):
            ring['decode_ring'](b'\0' * 8)

    def test_attribution(self):
        rows = [dict(root=0xa23308000), dict(root=0x1234000)]
        ring['attribute'](rows, [dict(pid=131, name='WindowServer',
                                      user_address_space=dict(root='0xa23308000'))])
        self.assertEqual([r['process'] for r in rows], [(131, 'WindowServer'), None])

    def test_target_layout_appends(self):
        layout = runpy.run_path(str(ROOT / 'tools/monitor_layout.py'))['MonitorLayout']()
        # Merged after the arena-reclaim append: root_evictions, root_stamp[],
        # arena_reclaim, then the crash ring.
        last = layout.offset('context', 'arena_reclaim')
        crashes = layout.offset('context', 'user_crashes')
        self.assertEqual(crashes, last + layout.size('arena_reclaim_stats'))
        self.assertEqual(layout.size('user_crash_record'), 232)
        self.assertEqual(layout.size('user_crash_ring'), ring['RING_BYTES'])
        # Later appends follow the ring directly (MULTIPAGE counters, then the
        # PV self-checks); nothing is interleaved into it.
        after = crashes + 6 * ring['RING_BYTES']
        self.assertEqual(layout.offset('context', 'multipage_calls'), after)
        self.assertEqual(layout.offset('context', 'kernel_map_conflict'),
                         layout.offset('context', 'multipage_groups') + 8)
        self.assertEqual(layout.offset('context', 'pv_audit'),
                         layout.offset('context', 'kernel_map_conflict') + 40)
        align = int(re.search(r'align=(\d+)', layout.records['context'])[1])
        self.assertEqual(layout.offset('context', 'auxkc_exec'),
                         layout.offset('context', 'pv_audit') + layout.size('sptm_pv_audit'))
        self.assertEqual(layout.offset('context', 'gpu'),
                         layout.offset('context', 'auxkc_exec') + layout.size('auxkc_exec_state'))
        # The retained console ring follows the Adreno state directly, and the
        # context ends with the last append (native shared-region groups)
        # within its alignment.
        self.assertEqual(layout.offset('context', 'console_tail_bytes'),
                         layout.offset('context', 'gpu') + layout.size('adreno_state'))
        pad = layout.size('context') - (layout.offset('context', 'native_shared') +
                                        layout.size('native_shared'))
        self.assertTrue(0 <= pad < align, pad)
        self.assertEqual(layout.offset('user_crash_ring', 'rows'), 32)


if __name__ == '__main__':
    unittest.main()
