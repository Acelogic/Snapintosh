# SPDX-License-Identifier: MIT
"""Decode the virtual ANS2 state the monitor keeps at the reservation base.

struct ans_state (compat/ans.h), little-endian. tools/test-ans-image.py
compiles the header on the host and checks every offset below against
offsetof, so a layout change there fails here instead of misreading."""
import struct

MAGIC = 0x32534e41504e5341
VERSION = 2
SIZE = 133616
OFFSETS = dict(magic=0, outbox=32, out_count=160, iop=172, ap_power=176, allowed=192,
               ioq=204, asq=208, cid=240, sart_active=132848, sart=132856, cc=133240, csts=133244,
               intms=133248, cq=133272, counter=133304, refusal=133512, bad_opcode=133544,
               last_status=133608)
CID_SIZE, CIDS, PRP_OFFSET, PRPS = 2072, 64, 8, 258   # struct ans_cid; ANS_CIDS, ANS_PRPS
SART_SIZE, SART_REGIONS = 24, 16               # struct ans_sart; ANS_SART_REGIONS
IOQ = ('cq', 'sq', 'ien')                      # ANS_IOQ_CQ, _SQ, _IEN
COUNTERS = ('mmio', 'msg_in', 'msg_out', 'sptm6', 'sptm5', 'admin', 'io', 'reads', 'writes',
            'flushes', 'read_bytes', 'write_bytes', 'status_errors', 'invalid_opcode',
            'out_of_range', 'tunnel', 'refusals', 'lba_low', 'lba_high', 'irq_nvme',
            'startep', 'ap_power', 'mapped', 'unmapped', 'max_read_blocks', 'max_write_blocks')
ERRORS = ('ok', 'state', 'width', 'register', 'value', 'mailbox', 'rtkit', 'endpoint',
          'sptm_order', 'sptm_arg', 'address', 'frame', 'cid', 'doorbell', 'sqe', 'cq_full',
          'direction', 'sart', 'backend')
IOP = ('quiesced', 'hello', 'epmap', 'running')
# SNAP_ANS_ASYNC (agents/nvme-async, compat/ans.h struct ans_async): appended at SIZE behind its own magic, so a
# define-free state decodes as before and a reader that reads SIZE + ASYNC_SIZE gets it when present.
ASYNC_MAGIC = 0x31434e595341414e        # "NAASYNC1"
ASYNC_SIZE = 9672
ASYNC_OFFSETS = dict(magic=0, head=8, active=16, op=24, lba=32, seq=48, cur=56, fifo=128, counter=9344,
                     backend=9440, due=9568, owner=9576, sched_seq=9584, start=9592, ewma=9600, sched=9608)
ASYNC_FIFO = 128
ASYNC_COUNTERS = ('queued', 'started', 'completed', 'physical', 'polls', 'pending_polls', 'drains', 'drained',
                  'max_depth', 'requeued', 'abandoned', 'stops')
ASYNC_SCHED = ('tick_polls', 'backstop_polls', 'peeks', 'peek_declines', 'reap_ticks', 'reaped', 'last_ticks',
               'last_reaped')


def decode_async(raw):
    """The async block, or None (a define-free monitor, or a short read)."""
    if len(raw) < SIZE + ASYNC_SIZE:
        return None
    o = SIZE
    if struct.unpack_from('<Q', raw, o)[0] != ASYNC_MAGIC:
        return None
    head, count, active, phys = struct.unpack_from('<4I', raw, o + ASYNC_OFFSETS['head'])
    counters = dict(zip(ASYNC_COUNTERS, struct.unpack_from(f'<{len(ASYNC_COUNTERS)}Q', raw,
                                                           o + ASYNC_OFFSETS['counter'])))
    due, owner, sched_seq, start, ewma = struct.unpack_from('<5Q', raw, o + ASYNC_OFFSETS['due'])
    sched = dict(zip(ASYNC_SCHED, struct.unpack_from('<8Q', raw, o + ASYNC_OFFSETS['sched'])))
    if count > ASYNC_FIFO or head >= ASYNC_FIFO:
        raise ValueError(f'virtual ANS2 async block: FIFO head {head} count {count}')
    return dict(queued_now=count, active=active, physical_in_flight=phys,
                seq=struct.unpack_from('<Q', raw, o + ASYNC_OFFSETS['seq'])[0], counters=counters,
                due=due, owner=owner, ewma_ticks=ewma, schedule=sched)


def decode(raw):
    if len(raw) < SIZE:
        raise ValueError('short virtual ANS2 state')
    magic, version, disk_bytes = struct.unpack_from('<3Q', raw, 0)
    if magic != MAGIC or version != VERSION:
        raise ValueError(f'virtual ANS2 state magic/version {magic:#x}/{version} '
                         '(the monitor never reset it: no ANS model, or prepare failed first)')
    out_count, in_enable, out_enable, iop = struct.unpack_from('<4I', raw, OFFSETS['out_count'])
    ap_power, iop_power, epmap_acked = struct.unpack_from('<3I', raw, OFFSETS['ap_power'])
    allowed, aqa, ioqa, ioq = struct.unpack_from('<4I', raw, OFFSETS['allowed'])
    asq, acq, iosq, iocq = struct.unpack_from('<4Q', raw, OFFSETS['asq'])
    cc, csts, intms, modesel, aqm, ppm, sart_power, aer_cid = struct.unpack_from('<8I', raw, OFFSETS['cc'])
    cq = [dict(zip(('size', 'tail', 'head', 'phase'), struct.unpack_from('<4I', raw, OFFSETS['cq'] + 16 * i)))
          for i in range(2)]
    counters = dict(zip(COUNTERS, struct.unpack_from(f'<{len(COUNTERS)}Q', raw, OFFSETS['counter'])))
    reason, a, b, c = struct.unpack_from('<4Q', raw, OFFSETS['refusal'])
    mapped = sum(raw[OFFSETS['cid'] + CID_SIZE * i] == 3 for i in range(CIDS))
    bad = struct.unpack_from('<8Q', raw, OFFSETS['bad_opcode'])
    bad_opcodes = [[op for op in range(256) if bad[4 * q + op // 64] >> (op % 64) & 1] for q in range(2)]
    last = struct.unpack_from('<Q', raw, OFFSETS['last_status'])[0]
    extra = {}
    async_block = decode_async(raw)
    if async_block is not None:
        extra['async'] = async_block
    return dict(**extra,disk_bytes=disk_bytes, iop=IOP[iop] if iop < len(IOP) else iop,
                outbox=out_count, inbox_enable=in_enable, outbox_enable=out_enable,
                ap_power=ap_power, iop_power=iop_power, epmap_acked=epmap_acked,
                sptm_allowed=allowed, aqa=aqa, ioqa=ioqa, asq=asq, acq=acq, iosq=iosq, iocq=iocq,
                io_queue=[name for bit, name in enumerate(IOQ) if ioq >> bit & 1],
                cc=cc, csts=csts, intms=intms, modesel=modesel, aqm=aqm, ppm=ppm,
                sart_power=sart_power, aer_cid=aer_cid, cq=cq, cids_mapped=mapped,
                counters=counters,
                refusal=dict(reason=ERRORS[reason] if reason < len(ERRORS) else reason,
                             a=a, b=b, c=c),
                invalid_opcodes=dict(admin=bad_opcodes[0], io=bad_opcodes[1]),
                last_status=dict(status=last >> 48, qid=last >> 40 & 0xff, opcode=last >> 32 & 0xff,
                                 cdw10=last & 0xffffffff) if last else None)


def references(raw):
    """The SPTM DMA references the model holds, per 16 KiB frame, named from its state
    (compat/ans.c): one writable reference per registered queue base (ADMIN_QUEUE_REGS,
    IOSQ_REG, IOCQ_REG -- held for the boot, as Apple's SPTM holds them), one per page of
    every mapped command id (writable when its TCB has 0x100) and one per 16 KiB frame of
    every SART region (writable for perm 1). The stopped-state audit adds these to the
    DART's, frame by frame, before it compares the frame map (tools/audit-secondary-runtime.py);
    tools/test-ans.c checks the same rule against the model after every step."""
    decode(raw)
    count = {}
    def name(pa, writable):
        key = (pa & ~0x3fff, 1 if writable else 0)
        count[key] = count.get(key, 0) + 1
    for base in struct.unpack_from('<4Q', raw, OFFSETS['asq']):
        if base:
            name(base, True)
    for i in range(CIDS):
        at = OFFSETS['cid'] + CID_SIZE * i
        state, _, direction, _, pages = struct.unpack_from('<BBHHH', raw, at)
        if state == 3:
            if pages > PRPS:
                raise ValueError(f'virtual ANS2 command id {i} names {pages} pages')
            for pa in struct.unpack_from(f'<{pages}Q', raw, at + PRP_OFFSET):
                name(pa, direction & 0x100)
    for i in range(SART_REGIONS):
        pa, size, perm, _ = struct.unpack_from('<2Q2I', raw, OFFSETS['sart'] + SART_SIZE * i)
        for frame in range(pa, pa + size if size else pa, 0x4000):
            name(frame, perm)
    frames = sorted({pa for pa, _ in count})
    return [dict(pa=hex(pa), readonly=count.get((pa, 0), 0), other=count.get((pa, 1), 0))
            for pa in frames]


def merge_references(*lists):
    """Sum per-frame reference lists (dict(pa=hex, readonly=n, other=n)) into one."""
    total = {}
    for refs in lists:
        for ref in refs:
            pa = int(ref['pa'], 16)
            ro, other = total.get(pa, (0, 0))
            total[pa] = (ro + ref['readonly'], other + ref['other'])
    return [dict(pa=hex(pa), readonly=ro, other=other) for pa, (ro, other) in sorted(total.items())]


def describe(state):
    c = state['counters']
    return (f"iop {state['iop']}, CC {state['cc']:#x} CSTS {state['csts']:#x}, "
            f"admin {c['admin']} io {c['io']} (reads {c['reads']}, writes {c['writes']}, "
            f"flushes {c['flushes']}), {c['read_bytes']} B read, {c['write_bytes']} B written, "
            f"status errors {c['status_errors']}, refusals {c['refusals']}"
            + (f", I/O queue {'+'.join(state['io_queue']) or 'none'}" if 'io_queue' in state else '')
            + (f", invalid opcodes admin {[hex(o) for o in state['invalid_opcodes']['admin']]}"
               f" io {[hex(o) for o in state['invalid_opcodes']['io']]}"
               if state.get('invalid_opcodes', {}).get('admin') or state.get('invalid_opcodes', {}).get('io')
               else '')
            + (f" (first: {state['refusal']['reason']} {state['refusal']['a']:#x} "
               f"{state['refusal']['b']:#x})" if c['refusals'] else ''))
