# SPDX-License-Identifier: MIT
"""Decode the monitor's Stage-4 Adreno state (context.gpu, copied to OUT_GPU_FLOW).

compat/adreno.h struct adreno_state, word by word before its `irq` member;
tools/test-adreno.c pins the order and tools/test-adreno-image.py checks this
list against the header. Counters and last values only: what a stop means is
the event log's (EV_GPU_TRAP, EV_GPU_SMC refused) and the classifier's.
"""
import struct

FIELDS = ('status prepare wptr fences fence_last fence_ticks fence_error '
          'maps map_pages unmaps unmap_pages refused live_pages tlbi tlbi_timeouts '
          'faults fault_fsr fault_far fault_fsynr0 fault_cbfrsynra fault_gfsr '
          'smc_calls smc_refused smc_cached smc_fid smc_x0 smc_resumes '
          'traps trap_ipa trap_esr trap_block '
          'self_irq irq_fired irq_kept irq_resampled irq_spurious '
          'quiesce halt_ack cb0_after serrors ib_submits ib_dwords ring_wraps ib_errors run_at').split()
SIZE = 8 * len(FIELDS)
STATUS = {1: 'adopted', 2: 'attached', 4: 'routed', 8: 'run_fence', 16: 'quiesced',
          32: 'tz_done', 64: 'cb0_hijacked'}
ERRORS = {-60: 'params', -61: 'CX off', -62: 'GX off', -63: 'CB0 not as adopted',
          -64: 'CB0 root entries 1..3 in use', -65: 'SQE not running',
          -66: 'ring pointers or CP_RB_CNTL size disagree / emission too long / fenced write dropped',
          -67: 'SMMU fault already recorded', -68: 'fence not written (or wrap padding not consumed) in 50 ms',
          -69: 'SMMU TLB sync timeout', -70: 'IOVA outside the mirrored window',
          -71: 'GX-side GBIF already halted', -72: 'guest target not mapped as required',
          -73: 'native DART unmap failed', -74: 'FILL32 completion uncertain', -75: 'IB completion uncertain',
          -76: 'IB retired with a GPU error', -77: 'GPU busy before an IB', -78: 'sticky GPU error bit'}
BLOCKS = {1: 'passthrough', 2: 'CX_MISC (read-only)', 3: 'GMU_GX', 4: 'RDVM', 5: 'GMU_AO',
          6: 'RSCC', 7: 'SMMU aperture', 8: 'GX clock controller', 9: 'GMU', 10: 'GPUCC',
          11: 'CX_MISC', 12: 'SMMU', 13: 'hole'}
QUIESCE = {1: 'ran', 2: 'CX off: nothing touched', 4: 'RBBM_GBIF_HALT_ACK timeout',
           8: 'GX-side GBIF halted', 16: 'TLB sync timeout after unlink', 32: 'mirror unlinked',
           64: 'CB0 TTBR0/TCR/SCTLR ownership changed', 128: 'GX power/clock state incomplete'}


def signed(v):
    return v - (1 << 64) if v >> 63 else v


def decode(raw):
    if len(raw) != SIZE:
        raise ValueError(f'adreno_state is {SIZE} bytes, got {len(raw)}')
    v = dict(zip(FIELDS, struct.unpack(f'<{len(FIELDS)}Q', raw)))
    out = {k: v[k] for k in FIELDS}
    out['status_names'] = [n for b, n in STATUS.items() if v['status'] & b]
    for k in ('prepare', 'fence_error'):
        out[k] = signed(v[k])
        out[k + '_name'] = ERRORS.get(out[k]) if out[k] else None
    out['live_pages'] = signed(v['live_pages'])
    out['smc_x0'] = signed(v['smc_x0'])
    out['trap_block_name'] = BLOCKS.get(v['trap_block']) if v['traps'] else None
    out['quiesce_names'] = [n for b, n in QUIESCE.items() if v['quiesce'] & b]
    if v['map_pages'] < v['unmap_pages'] or out['live_pages'] != v['map_pages'] - v['unmap_pages']:
        raise ValueError('inconsistent Adreno mirror counters')
    return out


def summary(d):
    """The lines run.py prints after a run with an Adreno profile."""
    lines = [f'adreno: status {",".join(d["status_names"]) or "none"}; prepare '
             f'{d["prepare"]}{" (" + d["prepare_name"] + ")" if d["prepare_name"] else ""}',
             f'  test ring: {d["fences"]} fences, last {d["fence_last"]:#x} in {d["fence_ticks"]} ticks, '
             f'wptr {d["wptr"]}, error {d["fence_error"]}',
             f'  guest IBs: {d["ib_submits"]} rung, {d["ib_dwords"]} dwords retired, {d["ib_errors"]} errors; '
             f'ring wraps {d["ring_wraps"]}',
             f'  IRQ 0x14C -> AIC 975: fired {d["irq_fired"]}, kept {d["irq_kept"]}, resampled '
             f'{d["irq_resampled"]}, spurious {d["irq_spurious"]}, self-tests {d["self_irq"]}',
             f'  SMMU mirror: {d["maps"]} maps / {d["map_pages"]} pages, {d["unmaps"]} unmaps / '
             f'{d["unmap_pages"]} pages, live {d["live_pages"]}, refused {d["refused"]}, '
             f'TLBI {d["tlbi"]} (timeouts {d["tlbi_timeouts"]})',
             f'  SMMU faults {d["faults"]}' + (f': FSR {d["fault_fsr"]:#x} FSYNR0 {d["fault_fsynr0"]:#x} '
                                              f'FAR {d["fault_far"]:#x} CBFRSYNRA {d["fault_cbfrsynra"]:#x} '
                                              f'sGFSR {d["fault_gfsr"]:#x}' if d['faults'] else ''),
             f'  SMC: {d["smc_calls"]} forwarded, {d["smc_cached"]} answered from q1n1\'s init, '
             f'{d["smc_refused"]} refused, last fid {d["smc_fid"]:#x} -> x0 {d["smc_x0"]}',
             f'  trapped GPU accesses {d["traps"]}' + (f', last IPA {d["trap_ipa"]:#x} ({d["trap_block_name"]}) '
                                                     f'ESR {d["trap_esr"]:#x}' if d['traps'] else ''),
             f'  quiesce: {", ".join(d["quiesce_names"]) or "not run"}; RBBM_GBIF_HALT_ACK '
             f'{d["halt_ack"]:#x}; CB0 TTBR0 after {d["cb0_after"]:#x}; SErrors seen {d["serrors"]}']
    return lines
