# SPDX-License-Identifier: MIT
"""Decode stopped J700 thread state using pinned native scheduler accesses.

No target writes or guest calls. State bits indicate scheduler intent, not
independent membership in a run queue or proof of eventual scheduling.
"""
import struct

STATE_OFFSET = 0x1f8
RUNQ_OFFSET = 0x20
FLAGS = ('wait', 'suspended', 'run', 'uninterruptible', 'terminate',
         'terminate2', 'wait_report', 'idle', 'waking')
# AST reads current_thread.state, excludes idle/waking threads. Native wakeup
# writes RUN, selection tests WAIT, and stop waits for RUN to clear. The exact
# kernel hash is separately checked by capture-kernel-waits.py.
WITNESSES = (
    (0xfffffe000b8b7178, 0xd538d08a),
    (0xfffffe000b8b717c, 0xb941f94b),
    (0xfffffe000b8b7188, 0x3738012b),
    (0xfffffe000b8b7194, 0x1218016b),
    (0xfffffe000b92db50, 0xb941fa77),
    (0xfffffe000b92db5c, 0x321e0108),
    (0xfffffe000b92db60, 0xb901fa68),
    (0xfffffe000b92db64, 0x361000b7),
    (0xfffffe000b931a9c, 0xb941faa8),
    (0xfffffe000b931aa0, 0x37000848),
    (0xfffffe000b933a34, 0xb941fa68),
    (0xfffffe000b933a38, 0x361000e8),
    # Same native thread-stop path: after testing TH_RUN, acquire-load the
    # thread's runq assignment and branch when it is PROCESSOR_NULL.
    (0xfffffe000b933a48, 0xf9401268),
    (0xfffffe000b933a4c, 0xd50339bf),
    (0xfffffe000b933a50, 0xb40003c8),
    (0xfffffe000b973620, 0xb941fa68),
    (0xfffffe000b973624, 0x3218010a),
    (0xfffffe000b973628, 0xb901fa6a),
)
BOUNDARY = ('Native state offset and RUN/WAIT/IDLE/WAKING accesses are byte-bound. '
            'Other bit names follow the matching public XNU state enum. RUN may '
            'mean running or runnable; neither queue membership nor starvation '
            'is established by this stopped snapshot. The runq pointer records '
            'a processor assignment, not an independently traversed queue.')

def make_reader(instruction):
    for address, word in WITNESSES:
        if instruction(address) != word:
            raise ValueError(f'native scheduler witness differs at {address:#x}')
    def decode(data):
        if len(data) < STATE_OFFSET + 4:
            raise ValueError('short native thread-state record')
        raw = data[STATE_OFFSET:STATE_OFFSET+4]
        state, = struct.unpack('<I', raw)
        runq_raw = data[RUNQ_OFFSET:RUNQ_OFFSET+8]
        runq, = struct.unpack('<Q', runq_raw)
        if state & ~0x1ff:
            raise ValueError('unknown native scheduler state bits')
        return dict(state=hex(state), raw_hex=raw.hex(),
                    runq_assignment=hex(runq), runq_raw_hex=runq_raw.hex(),
                    flags=[name for bit, name in enumerate(FLAGS) if state & (1 << bit)],
                    run=bool(state & 4), waiting=bool(state & 1),
                    idle=bool(state & 0x80), waking=bool(state & 0x100))
    return decode
