#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Which guest processes crashed, when, and which live ones are about to.

Reads stopped-state kernel-waits captures (tools/capture-kernel-waits.py).
A process that dies of a core-dumping signal (SIGABRT, SIGSEGV, SIGBUS,
SIGILL, SIGTRAP, ...) leaves two kernel messages: AMFI's
"Denying core dump for pid N (name)" and the corpse notice
"name[N] Corpse allowed k of n". The corpse is what launches ReportCrash.
Respawns are the same name under a later pid (launchd KeepAlive).

With --cache (the mounted 26A428 BaseSystem dyld cache) live threads are
also matched against known fatal waits: sites whose timeout ends in abort().
The only one so far is SkyLight's Metal-device wait (see
tools/replay-windowserver-metal.py); its deadline is read from the blocked
thread's own registers. Offline analysis of captured bytes; no target access.
"""
from pathlib import Path
import argparse
import json
import re
import runpy

ROOT = Path(__file__).resolve().parents[1]
GUEST_HZ = 24_000_000          # guest counter (audit user_clock guest_hz)
REPORTERS = ('ReportCrash', 'ReportCrashServi', 'ReportCrashService')

# Unslid 26A428 return sites of blocking calls whose timeout path aborts.
# deadline: how the thread's saved registers at the trap give the deadline.
KNOWN_WAITS = {
    0x18708b608: dict(
        image='SkyLight', site='___WSSystemCanCompositeWithMetal_block_invoke+0x100',
        call='dispatch_semaphore_wait(sem, dispatch_time(NOW, 30 s))',
        timeout_s=30,
        outcome='abort(): "No suitable Metal devices present after 30 seconds." '
                '(SIGABRT via __pthread_kill, corpse, ReportCrash, launchd respawn)',
        cause='no Metal device: MTLCopyAllDevices is empty (no IOAccelerator/AGX)',
        evidence='tools/replay-windowserver-metal.py'),
}
# libdispatch 26A428: _dispatch_sema4_timedwait keeps the dispatch_time
# deadline in x19 and passes {sec = w1, nsec = x1[63:32]} to
# semaphore_timedwait_trap; its return site into _dispatch_semaphore_wait_slow.
SEMA4_TIMEDWAIT_RETURN = 0x1806ceaec
SEMAPHORE_TIMEDWAIT_TRAP_PC = 0x180848bb4   # semaphore_timedwait_trap+8 (svc return)

ENTRY = re.compile(r'\[\s*(\d+\.\d+)\]: ')
CORE = re.compile(r'Denying core dump for pid (\d+) \(([^)]*)\)')
CORPSE = re.compile(r'\[(\d+)\] Corpse allowed (\d+) of (\d+)')
SANDBOX = re.compile(r'Sandbox apply: (.{1,40}?)\[(\d+)\]')
NAMED_PAREN = re.compile(r'([A-Za-z][\w.\- ]{0,39})\((\d+)\) deny')
SPIN = re.compile(r'scheduler: thread (\S+) \[([0-9a-f]+)\] in process (.+?) \[(\d+)\] '
                  r'triggered fail-safe')
EV_OPEN = re.compile(r'evOpen by (\d+)')
EV_CLOSE = re.compile(r'evClose by (\d+)')


def entries(text):
    """Split the retained message buffer into (seconds, body) records."""
    parts = ENTRY.split(text or '')
    return [(float(parts[i]), parts[i + 1]) for i in range(1, len(parts) - 1, 2)]


def timeline(capture):
    rows = entries((capture.get('kernel_messages') or {}).get('text'))
    live = {p['pid']: p['name'] for p in capture['user_processes']['processes']}
    names, first_seen, crashes, spins, hid = dict(live), {}, {}, {}, {}
    for ts, body in rows:
        for match in SANDBOX.finditer(body):
            pid = int(match[2])
            names.setdefault(pid, match[1].split(':')[-1].strip())
            first_seen.setdefault(pid, ts)
        for match in NAMED_PAREN.finditer(body):
            first_seen.setdefault(int(match[2]), ts)
        for match in CORE.finditer(body):
            pid = int(match[1])
            names[pid] = match[2]
            crashes.setdefault(pid, dict(pid=pid, time=ts))['core_dump_denied'] = True
        for match in CORPSE.finditer(body):
            pid = int(match[1])
            row = crashes.setdefault(pid, dict(pid=pid, time=ts))
            row['corpse'] = f'{match[2]} of {match[3]}'
        for match in SPIN.finditer(body):
            spins[int(match[4])] = spins.get(int(match[4]), 0) + 1
            names.setdefault(int(match[4]), match[3])
        for match in EV_OPEN.finditer(body):
            hid.setdefault(int(match[1]), {})['open'] = ts
        for match in EV_CLOSE.finditer(body):
            hid.setdefault(int(match[1]), {})['close'] = ts
    result = []
    for pid, row in sorted(crashes.items(), key=lambda item: item[1]['time']):
        row = dict(row, name=names.get(pid), still_listed=pid in live)
        row.setdefault('core_dump_denied', False)
        started = first_seen.get(pid)
        if started is not None and started <= row['time']:
            row['first_seen'] = started
            row['lived_at_least_s'] = round(row['time'] - started, 3)
        if pid in hid:
            row['hid'] = hid[pid]
        if spins.get(pid):
            row['spin_failsafes'] = spins[pid]
        result.append(row)
    chains = {}
    for row in result:
        chains.setdefault(row['name'], dict(crashed=[], live=[]))['crashed'].append(row['pid'])
    for name, chain in chains.items():
        last = max(chain['crashed'])
        chain['live'] = sorted(pid for pid, n in live.items() if n == name and pid > last)
        chain['respawned'] = bool(chain['live'])
    span = [rows[0][0], rows[-1][0]] if rows else None
    return dict(message_span=span, crashes=result, respawn_chains=chains,
                crash_reporters=sorted((pid, n) for pid, n in live.items() if n in REPORTERS),
                spin_failsafes={str(pid): count for pid, count in spins.items()})


def witness_slide(cache, capture):
    """One shared-cache slide per boot, from a unique 64-byte code match."""
    for process in capture['user_processes']['processes']:
        for thread in process.get('threads', []):
            state = thread.get('saved_user_state') or {}
            sites = [(state.get('pc'), state.get('instruction_hex'))]
            for frame in (thread.get('user_frame_chain') or {}).get('frames', []):
                sites.append((frame.get('return_site_va'), frame.get('return_site_hex')))
            for pc, code in sites:
                if not pc or not code or len(code) < 128:
                    continue
                try:
                    match = cache.match_code(int(pc, 16), bytes.fromhex(code))
                except ValueError:
                    continue
                if match['slide'] >= 0 and not match['slide'] & 0x3fff:
                    return match['slide']
    return None


def known_waits(cache, capture, guest_hz=GUEST_HZ):
    slide = witness_slide(cache, capture)
    if slide is None:
        return dict(slide=None, waits=[], error='no unique 64-byte shared-cache witness')
    found = []
    for process in capture['user_processes']['processes']:
        for thread in process.get('threads', []):
            frames = (thread.get('user_frame_chain') or {}).get('frames', [])
            unslid = [int(f['return_site_va'], 16) - slide for f in frames if f.get('return_site_va')]
            hits = [a for a in unslid if a in KNOWN_WAITS]
            if not hits:
                continue
            for frame in frames:
                if not frame.get('return_site_va'):
                    continue
                va = int(frame['return_site_va'], 16)
                code = bytes.fromhex(frame.get('return_site_hex') or '')
                if va - slide in KNOWN_WAITS and cache.read(va - slide, len(code)) != code:
                    raise ValueError(f'pid {process["pid"]}: captured bytes differ at {va:#x}')
            site = KNOWN_WAITS[hits[0]]
            row = dict(pid=process['pid'], name=process['name'], tid=thread['tid'],
                       unslid_site=hex(hits[0]), **site)
            state = thread.get('saved_user_state') or {}
            regs = state.get('registers') or {}
            blocked = (state.get('pc') and int(state['pc'], 16) - slide == SEMAPHORE_TIMEDWAIT_TRAP_PC
                       and unslid and unslid[0] == SEMA4_TIMEDWAIT_RETURN)
            if blocked and regs:
                x1, x19 = int(regs['1'], 16), int(regs['19'], 16)
                remaining = (x1 & 0xffffffff) + (x1 >> 32) / 1e9
                deadline = x19 / guest_hz
                row.update(blocked_in='semaphore_timedwait_trap',
                           remaining_at_trap_s=round(remaining, 6),
                           deadline_guest_s=round(deadline, 6),
                           wait_started_guest_s=round(deadline - site['timeout_s'], 6))
            found.append(row)
    return dict(slide=hex(slide), waits=found)


def analyze(path, cache=None, guest_now=None):
    capture = json.loads(Path(path).read_text())
    result = dict(capture=str(path), **timeline(capture))
    if cache is not None:
        waits = known_waits(cache, capture)
        if guest_now is not None:
            for row in waits['waits']:
                if 'deadline_guest_s' in row:
                    row['seconds_after_stop'] = round(row['deadline_guest_s'] - guest_now, 3)
        result['known_waits'] = waits
    names = {}
    for row in result['crashes']:
        names[row['name']] = names.get(row['name'], 0) + 1
    verdict = [f'{name} crashed {count}x' for name, count in names.items()]
    for row in result.get('known_waits', {}).get('waits', []):
        verdict.append(f'{row["name"]} pid {row["pid"]} is in {row["site"]} '
                       f'(timeout {row["timeout_s"]} s -> {row["outcome"].split(" (")[0]})')
    result['verdict'] = '; '.join(verdict) or 'no crash recorded in the retained messages'
    return result


def guest_now_from_audit(path):
    audit = json.loads(Path(path).read_text())
    rows = (audit.get('user_clock') or {}).get('rows') or []
    values = [r['value'] / r['guest_hz'] for r in rows if r.get('guest_hz')]
    return max(values) if values else None


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('captures', nargs='+', type=Path)
    parser.add_argument('--cache', type=Path, help='mounted BaseSystem System/Library/dyld')
    parser.add_argument('--audit', action='store_true',
                        help='read guest time at the stop from the matching -audit.json')
    args = parser.parse_args()
    cache = None
    if args.cache:
        cache = runpy.run_path(str(ROOT / 'tools/dyld-cache.py'))['Cache'](args.cache)
    out = []
    for path in args.captures:
        now = None
        if args.audit:
            audit = Path(str(path).replace('-kernel-waits.json', '-audit.json'))
            now = guest_now_from_audit(audit) if audit.is_file() else None
        out.append(analyze(path, cache, now))
    print(json.dumps(out, indent=2))


if __name__ == '__main__':
    main()
