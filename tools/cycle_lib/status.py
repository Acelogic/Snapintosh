# SPDX-License-Identifier: MIT
"""Where the A16 is (status: one read-only proxy query) and what to run next (next)."""
from pathlib import Path

from .common import (Refused, sha, read, image_base, serror_clear, battery_minimum, battery_ok,
                     require_exclusive, hardware_clients, load_proxy, SERROR_KEYS)


def _records(ws, pattern):
    out = []
    for path in ws.build.glob(pattern):
        try:
            out.append((path, read(path)))
        except (OSError, ValueError):
            continue
    return out


def latest(ws):
    """(latest launch, latest idle retirement) by time, each (path, record) or None."""
    launches = sorted(_records(ws, '*-launch.json'), key=lambda r: r[1].get('started', 0))
    retirements = [r for r in _records(ws, '*-retirement-v1.json') + _records(ws, '*/retirement-*.json')
                   if str(r[1].get('status', '')).endswith('_IDLE') and r[1].get('finished')]
    retirements.sort(key=lambda r: r[1]['finished'])
    return (launches[-1] if launches else None), (retirements[-1] if retirements else None)


def expected(ws):
    launch, retirement = latest(ws)
    out = {}
    if retirement:
        after = retirement[1]['after']
        out.update(retirement=str(retirement[0]), generation=after['stage_generation'], image_base=hex(after['image_base']))
    if launch and (not retirement or launch[1].get('started', 0) > retirement[1]['finished']):
        out.update(launch=str(launch[0]), launch_finished=bool(launch[1].get('finished')),
                   exit_code=launch[1].get('exit_code'), generation=launch[1]['adreno_record']['stage_generation'],
                   image_base=hex(image_base(launch[1]['adreno_record']['stage_generation'])))
    return out


def status(ws, check=False, minimum=None):
    minimum = battery_minimum(minimum)
    expect = expected(ws)
    if check:
        return dict(status='STATUS_PLAN', hardware_access=False, expected=expect, battery_minimum_without_ac=minimum,
                    hardware_clients=hardware_clients(ws), query=['bootinfo', 'serror_state', 'live_battery'])
    require_exclusive(ws)
    q = load_proxy(ws)
    proxy = q.connect(ws.device, wait=10)
    try:
        info = proxy.bootinfo()
        guard = proxy.serror_state()
        code, battery = proxy.live_battery()
    finally:
        proxy.link.close()
    matches = 'generation' in expect and info['stage_generation'] == expect['generation'] and \
        hex(info['image_base']) == expect['image_base']
    return dict(status='A16_STATUS', current_el=info['current_el'], stage_generation=info['stage_generation'],
                image_base=hex(info['image_base']), serror={k: guard[k] for k in SERROR_KEYS},
                serror_clear=serror_clear(guard),
                battery=dict(status=code, plausible=battery['plausible'], ac=battery['ac'], percent=battery['percent'],
                             text=battery.get('text'), ok_without_ac_minimum=battery_ok(code, battery, minimum),
                             minimum=minimum),
                expected=expect, matches_records=matches)


def manifests(ws):
    out = []
    for path in sorted((ws.root / 'candidates').glob('*.json')):
        try:
            data = read(path)
        except (OSError, ValueError):
            continue
        if data.get('schema') == 'snapintosh-cycle-candidate-v1':
            out.append((path, data))
    return out


def next_step(ws):
    """The exact next command, from the records alone. No hardware access."""
    launch, retirement = latest(ws)
    rel = lambda p: str(Path(p).relative_to(ws.root))
    cmd = 'python3 tools/cycle.py'
    if launch and (not retirement or launch[1].get('started', 0) > retirement[1]['finished']):
        path, record = launch
        prefix = path.name[:-len('-launch.json')]
        if not record.get('finished'):
            entry = ws.processes().get(record['pid'])
            state = 'running' if entry and entry[0] <= record['started'] + 5 else 'not running (no finished record)'
            return (f'# {prefix}: launcher PID {record["pid"]} {state}; watchdog '
                    f'{record["environment"].get("SNAP_WATCHDOG")} s from {record["started"]:.0f}.\n'
                    f'# Wait for it to exit; start no other hardware client.')
        candidate = [p for p, d in manifests(ws) if d['prefix'] == prefix]
        with_candidate = f' --candidate {rel(candidate[0])}' if candidate else ''
        retired = ws.prefixed(prefix, '-retirement-v1.json')
        if not retired.is_file():
            from .retire import PRE_GUEST_EXITS
            if record.get('exit_code') in PRE_GUEST_EXITS:
                # The loader stopped before the guest: nothing to capture or preserve.
                successor = [p for p, d in manifests(ws) if d.get('predecessor', {}).get('retirement') and
                             ws.path(d['predecessor']['retirement']) == retired]
                stages = f' --stages-from {rel(successor[0])}' if successor else ''
                return (f'# {prefix}: exit {record["exit_code"]} ({PRE_GUEST_EXITS[record["exit_code"]].lower()}) '
                        f'before any guest ran; retire it without a preservation:\n'
                        f'{cmd} retire --prefix {prefix} --loader-failure{stages} --check\n'
                        f'{cmd} retire --prefix {prefix} --loader-failure{stages}')
            from .evidence import Run, assess
            try:
                report = assess(Run(ws, prefix))
            except Refused as refusal:
                return f'# {prefix} (exit {record.get("exit_code")}) cannot be captured as recorded: {refusal}'
            if not report['complete']:
                return f'{cmd} capture --prefix {prefix}{with_candidate} --check\n{cmd} capture --prefix {prefix}{with_candidate}'
            pres = ws.prefixed(prefix, '-preserved-v1') / 'preservation.json'
            if not pres.is_file():
                return f'{cmd} preserve --prefix {prefix} --check\n{cmd} preserve --prefix {prefix}'
            h = sha(pres)
            return (f'{cmd} retire --prefix {prefix} --preservation-sha256 {h} --check\n'
                    f'{cmd} retire --prefix {prefix} --preservation-sha256 {h}')
        retirement = (retired, read(retired))
    if not retirement:
        return '# no idle retirement record found; run: python3 tools/cycle.py status --check'
    path, record = retirement
    if not str(record['status']).endswith('_IDLE'):
        return f'# {path.name} is {record["status"]}: inspect it before anything else'
    generation = record['after']['stage_generation']
    ready = [p for p, d in manifests(ws) if d['generation'] == generation and
             ws.path(d['predecessor']['retirement']) == path and not ws.prefixed(d['prefix'], '-launch.json').exists()]
    if ready:
        m = rel(ready[0])
        return (f'{cmd} launch --candidate {m} --check-inputs\n{cmd} launch --candidate {m} --prepare\n'
                f'{cmd} launch --candidate {m} --boot')
    return (f'# A16 idle at generation {generation} ({hex(record["after"]["image_base"])}) after {path.name}.\n'
            f'# Write candidates/<name>.json with "generation": {generation} and '
            f'"predecessor": {{"retirement": "{ws.relative(path)}", ...}}, then:\n'
            f'{cmd} launch --candidate candidates/<name>.json --check-inputs')
