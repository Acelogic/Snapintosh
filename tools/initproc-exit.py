#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Why launchd died: the exception path and instruction behind "initproc exited".

The kernel panics on pid 1's exit on the exiting launchd thread, so the first
"Panicked thread" backtrace after "pid 1 exited" is launchd's own way out:
fleh_synchronous from a user PC, sleh_synchronous, the handler of that EL0
exception class, exception_triage, then the AST that delivers the signal and
exits. This names each kernel frame with tools/kc-symbolicate.py (KDK
26A428), reports the handler and the user PC, and, for a PC in the dyld shared
cache, finds the instructions of the handler's class in this Mac's 26A428
cache at the same 16 KiB page offset (the shared region slides in 16 KiB
pages) and names them with lldb. The host must run the guest's build.

  python3 tools/initproc-exit.py CONSOLE.txt [CONSOLE.txt ...]

Read-only; prints one JSON record per console.
"""
import glob
import json
import mmap
import os
import re
import runpy
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DSC = '/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e'
# What each 26A428 sleh handler is entered for, the signal it raises for an EL0 origin (KDK disassembly;
# compat/user-crash.h) and the instruction words it can be entered on.
HANDLERS = {
    'handle_wf_trap': ('EC 0x01 WFI/WFE', 'SIGILL',
                       lambda w: w in (0xd503205f, 0xd503207f) or (w & ~31) in (0xd5031000, 0xd5031020)),
    'handle_simd_trap': ('EC 0x07 SIMD/FP access', 'SIGILL', None),
    'handle_uncategorized': ('EC 0x00 unknown (and the default group)', 'SIGILL', None),
    'handle_pac_fail': ('EC 0x1c FPAC', 'EXC_BAD_ACCESS|EXC_PTRAUTH', None),
    'handle_user_breakpoint': ('EC 0x3c BRK', 'SIGTRAP', lambda w: (w & 0xffe0001f) == 0xd4200000),
    'handle_user_abort': ('EC 0x20/0x24 abort', 'SIGSEGV/SIGBUS', None),
    'handle_pc_align': ('EC 0x22 PC alignment', 'SIGBUS', None),
    'handle_sp_align': ('EC 0x26 SP alignment', 'SIGBUS', None),
    'handle_fp_trap': ('EC 0x2c FP exception', 'SIGFPE', None),
}
SIGNALS = {4: 'SIGILL', 5: 'SIGTRAP', 6: 'SIGABRT', 8: 'SIGFPE', 9: 'SIGKILL', 10: 'SIGBUS', 11: 'SIGSEGV'}


def panic_backtrace(text):
    """(exit line, [lr...]) of the first panicked-thread backtrace after pid 1's exit."""
    at = text.find('pid 1 exited')
    if at < 0:
        return None, []
    line = text[at:text.find('\n', at)].strip()
    block = text.find('Panicked thread', at)
    end = text.find('Kernel Extensions', block)
    return line, re.findall(r'lr: (0x[0-9a-f]+)', text[block:end if end > 0 else None])


def cache_candidates(pc, accept):
    """Shared-cache addresses with pc's 16 KiB page offset whose word accept() admits."""
    found = []
    for path in sorted(glob.glob(DSC + '*')):
        with open(path, 'rb') as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as m:
            if m[:7] != b'dyld_v1':
                continue
            offset, count = struct.unpack_from('<II', m, 16)
            for i in range(count):
                address, size, file_offset, _, init_prot = struct.unpack_from('<QQQII', m, offset + 32 * i)
                if not init_prot & 4:
                    continue
                first = (pc - address) & 0x3fff
                for at in range(first, size - 3, 0x4000):
                    if accept(struct.unpack_from('<I', m, file_offset + at)[0]):
                        found.append(address + at)
    return found


def lldb_names(addresses, binary='/sbin/launchd'):
    """file-address -> 'image`symbol + n' through lldb's static view of the shared cache."""
    if not addresses:
        return {}
    commands = ['-o', f'target create --arch arm64e {binary}']
    for a in addresses:
        commands += ['-o', f'image lookup -a {a:#x}']
    out = subprocess.run(['lldb', '-b', *commands], capture_output=True, text=True, timeout=300).stdout
    names, current = {}, None
    for line in out.splitlines():
        m = re.search(r'image lookup -a (0x[0-9a-f]+)', line)
        if m:
            current = int(m.group(1), 16)
        m = re.search(r'Summary: (.*)$', line)
        if m and current is not None:
            names[current] = m.group(1).strip()
    return names


def explain(path, symbolicator):
    text = Path(path).read_bytes().decode('utf-8', 'replace').replace('\r\n', '\n').replace('\r', '\n')
    line, lrs = panic_backtrace(text)
    record = dict(console=str(path), exit=line)
    if not lrs:
        return dict(record, verdict='no initproc backtrace in this console')
    m = re.search(r'namespace (\d+) subcode (0x[0-9a-f]+)', line or '')
    if m:
        record['namespace'] = int(m.group(1))
        record['signal'] = SIGNALS.get(int(m.group(2), 16), m.group(2)) if m.group(1) == '2' else m.group(2)
    kernel = [int(a, 16) for a in lrs if int(a, 16) >= 0xffff000000000000]
    user = [int(a, 16) for a in lrs if int(a, 16) < 0xffff000000000000]
    frames = symbolicator.resolve(kernel)
    record['kernel_frames'] = frames
    # The handler is the innermost handle_* below the last sleh_synchronous (the frame list runs top-down).
    last_sleh = max((i for i, f in enumerate(frames) if ' sleh_synchronous ' in f), default=None)
    handler = None
    if last_sleh is not None:
        for f in reversed(frames[:last_sleh]):
            name = f.split()[1]
            if name.startswith('handle_'):
                handler = name
                break
    record['handler'] = handler
    record['user_pc'] = hex(user[-1]) if user else None
    if handler in HANDLERS:
        record['exception'], record['raises'], accept = HANDLERS[handler]
        if user and accept and 0x180000000 <= user[-1] < 0x300000000:
            candidates = cache_candidates(user[-1], accept)
            names = lldb_names(candidates)
            record['shared_cache_candidates'] = [dict(unslid=hex(a), slide=hex(user[-1] - a), symbol=names.get(a))
                                                 for a in candidates]
    return record


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    symbolicator = runpy.run_path(str(ROOT / 'tools/kc-symbolicate.py'))['Symbolicator']()
    for path in argv:
        print(json.dumps(explain(path, symbolicator), indent=1))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
