#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""speed_test.console_text and milestones (docs/KERNEL-PPERM-VARIANTS-20261016.md).

The kept console is console_log (the first bytes, never overwritten) and then
the console_tail ring's bytes beyond it, with a marked gap. Milestone times
are launchd's own UTC stamps minus the RTC seed. Both console fields are
appended or unchanged, and the decoder takes their sizes from the layout.

    python3 tools/test-speed-test-console.py
"""
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from cycle_lib import speed_test as st  # noqa: E402
from monitor_layout import MonitorLayout  # noqa: E402

GAP = b'\n[... %d console bytes not kept ...]\n'


class Layout:
    def __init__(self, head, ring):
        self.cap = {'console_log': head, 'console_tail': ring}
        self.off = {'console_log': 0, 'console_tail': head}

    def offset(self, kind, field):
        return self.off[field]

    def length(self, kind, field):
        return self.cap[field]


def context_for(stream, head, ring):
    """console_put's stores: the log while it has room, the ring always."""
    ctx = bytearray(head + ring)
    for i, byte in enumerate(stream):
        if i < head:
            ctx[i] = byte
        ctx[head + i % ring] = byte
    return bytes(ctx)


def test_console_text():
    rnd = random.Random(7)
    for head, ring in ((64, 16), (16, 64), (32, 32)):
        for total in range(200):
            stream = bytes(rnd.randrange(256) for _ in range(total))
            text, info = st.console_text(context_for(stream, head, ring), Layout(head, ring), total)
            if total <= head:
                assert text == stream and info == dict(complete=True, kept=total, lost=0)
                continue
            start = max(head, total - ring)
            lost = start - head
            assert text == stream[:head] + (GAP % lost if lost else b'') + stream[start:]
            assert info == dict(complete=False, kept=head + total - start, lost=lost)


def test_milestones():
    seed = 1792193626908720  # 2026-10-16 23:33:46.908720 UTC, v6's seed
    lines = [b'kernel line with no stamp',
             b'com.apple.xpc.launchd|2026-10-16 23:34:16.908720 (system) <Notice>: first',
             b'com.apple.xpc.launchd|2026-10-16 23:35:00.000000 (system/com.apple.WindowServer [88]) '
             b'<Notice>: Successfully spawned WindowServer[88] because ipc',
             b'com.apple.xpc.launchd|2026-10-16 23:43:45.794242 (system) <Warning>: last']
    marks = st.milestones(b'\n'.join(lines) + b'\n', seed)
    assert marks == dict(launchd_first=30.0, windowserver=73.09128, loginwindow=None,
                         launchd_last=598.885522), marks
    assert st.milestones(b'no launchd here\n', seed) == dict(
        launchd_first=None, windowserver=None, loginwindow=None, launchd_last=None)
    # A spawn named on a line without its own stamp is never timed from another line.
    marks = st.milestones(lines[1] + b'\nSuccessfully spawned loginwindow[9] because x\n', seed)
    assert marks['loginwindow'] is None and marks['launchd_first'] == 30.0


def test_layout():
    layout = MonitorLayout()
    assert layout.length('context', 'console_tail') == 65536
    assert layout.length('context', 'console_log') == 4 << 20
    # Appended, so no earlier field moved: after it only the console link
    # (compat/console-link.h), itself appended last, and alignment padding.
    log_end = layout.offset('context', 'console_log') + (4 << 20)
    link = layout.offset('context', 'console_link')
    assert 0 <= link - log_end < 64
    assert 0 <= layout.size('context') - link - layout.size('console_link') < 64
    assert layout.offset('context', 'kernel_variants') > layout.offset('context', 'fast_timer_due')
    try:
        layout.length('context', 'console_tail_bytes')
    except ValueError:
        pass
    else:
        raise AssertionError('a scalar field has no array length')


if __name__ == '__main__':
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for test in tests:
        test()
    print(f'PASS: {len(tests)} speed-test console tests')
