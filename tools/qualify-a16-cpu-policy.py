#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""CPU0 conservative SCMI policy, bounded PMU evidence, no secondary startup.

Failure inventory: docs/A16-CPU-POLICY-20261018.md. Never use a legacy main()
for hardware here: every proxy operation passes through the session guard.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import runpy
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
perf = runpy.run_path(str(ROOT / 'tools/a16-cpu-perf.py'), run_name='cpu_perf')
clock = perf['clock_tool']
run, need, Refused = perf['run'], perf['need'], perf['Refused']
thermal = runpy.run_path(str(ROOT / 'tools/a16-thermal-survey.py'))
IDENTITY = ('stage_generation', 'image_base', 'heap_base', 'heap_size', 'timer_hz', 'current_el')
SOURCES = ('tools/qualify-a16-cpu-policy.py', 'tools/a16-control-guard.py',
           'tools/a16-cpu-perf.py', 'tools/measure-a16-cpu-clock.py', 'tools/a16-cpu-stub.S',
           'tools/probe-el2-memory.py', 'tools/probe-a16-cpus.py', 'tools/a16-thermal-survey.py',
           '../q1n1/tools/q1n1proxy.py')


def sha(data):
    return hashlib.sha256(data).hexdigest()


class PolicyAccess(perf['Access']):
    def read32(self, address):
        value = super().read32(address)
        shm = perf['TRANSPORTS']['pdp0']['shmem']
        if address == shm + 4:
            need(not value & ~3, 'reserved channel status bits')
        if address == shm + 20:
            need(value % 4 == 0, 'unaligned SCMI payload length')
        return value


class PolicyChannel(perf['Channel']):
    """Preserve matched protocol rejections; freeze malformed/uncertain exchanges."""
    def __init__(self, access, transport, guard, record, save, **kw):
        super().__init__(access, transport, **kw)
        self.guard, self.record, self.save = guard, record, save
        record['transactions'] = self.log

    def xfer(self, protocol, message, payload=(), rx_words=0):
        before = len(self.log)
        self.record['scmi_in_flight'] = dict(protocol=protocol, message=message, payload=list(payload))
        self.save()
        try:
            result = super().xfer(protocol, message, payload, rx_words)
            fixed = ({0: 1, 1: 1, 3: 4, 4: 4, 5: 1} if protocol == perf['BASE'] else
                     {0: 1, 1: 4, 3: 8, 5: 0, 6: 2, 7: 0, 8: 1})
            if message in fixed:
                need(len(result) == fixed[message], 'short mandatory SCMI response')
            self.log[-1].update(payload=list(payload), response=result)
        except BaseException as error:
            # Only a complete, matched reply gets appended by the production channel.
            completed_error = (len(self.log) == before + 1 and
                               self.log[-1]['status'] in tuple(perf['STATUS'].values())[1:])
            if not completed_error:
                self.uncertain = str(error)
                self.guard.freeze('SCMI exchange uncertain: ' + str(error))
            else:
                self.log[-1]['payload'] = list(payload)
                self.record.pop('scmi_in_flight', None)
            self.save()
            raise
        self.record.pop('scmi_in_flight', None)
        self.save()
        return result


class PolicyScmi(perf['Scmi']):
    def domain(self, d, v4):
        need(v4, 'requires PERF4')
        attr = self.c.xfer(perf['PERF'], 3, [d], rx_words=8)
        flags = attr[0]
        info = dict(domain=d, name=perf['text'](attr[4:8]), flags=hex(flags),
                    set_limits=bool(flags & perf['SET_LIMITS']), set_level=bool(flags & perf['SET_LEVEL']),
                    fastchannels=bool(flags & perf['FASTCHANNELS']),
                    level_indexing=bool(flags & perf['LEVEL_INDEXING']), rate_limit_us=attr[1] & 0xfffff,
                    sustained_khz=attr[2], sustained_level=attr[3])
        levels, total = [], None
        for _ in range(32):
            words = self.c.xfer(perf['PERF'], 4, [d, len(levels)], rx_words=81)
            need(words and not words[0] & 0xf000, 'invalid DESCRIBE_LEVELS header')
            returned, remaining = words[0] & 0xfff, words[0] >> 16
            need(returned > 0 and len(words) == 1 + returned * 5, 'incomplete level page')
            current_total = len(levels) + returned + remaining
            if total is None: total = current_total
            need(total == current_total and total <= 128, 'inconsistent or oversized level table')
            for n in range(returned):
                e = words[1 + 5 * n:6 + 5 * n]
                levels.append(dict(perf=e[0], power=e[1], latency_us=e[2] & 0xffff,
                                   indicative_khz=e[3], index=e[4], mhz=e[3] / 1000))
            if not remaining: break
        need(len(levels) == total, 'level enumeration did not finish')
        info['levels'] = levels
        info['limits'] = dict(zip(('max', 'min'), self.c.xfer(perf['PERF'], 6, [d], rx_words=2)))
        info['level'] = self.c.xfer(perf['PERF'], 8, [d], rx_words=1)[0]
        return info


def plan_policy(domain, baseline, ceiling_mhz=2000):
    need(domain['domain'] == 0 and domain['name'] == 'PDP0', 'not PDP0 domain zero')
    need(domain['set_limits'] and domain['set_level'] and domain['level_indexing'],
         'requires indexed PERF4 set-limits/set-level support')
    need(baseline['stable'] and baseline['midr'] == '0x512f0021' and baseline['affinity'] == '0x0',
         'baseline must be stable A16 CPU0')
    levels = domain['levels']
    need(len({x['index'] for x in levels}) == len(levels), 'duplicate indices')
    need(all(x['mhz'] and x['mhz'] > 0 for x in levels), 'invalid indicative frequencies')
    ordered = sorted(levels, key=lambda x: x['index'])
    need(all(a['mhz'] < b['mhz'] for a, b in zip(ordered, ordered[1:])), 'non-monotonic frequency table')
    matches = [x for x in levels if abs(x['mhz'] - 1000 * baseline['ghz_median']) <= x['mhz'] * .01]
    need(len(matches) == 1, 'baseline does not match exactly one enumerated operating point')
    original = dict(domain['limits'])
    need(set(original) == {'min', 'max'}, 'short limits reply')
    baseline_level = matches[0]
    indices = {x['index'] for x in levels}
    need(all(v == 0 or v in indices for v in original.values()), 'limits are not described indices')
    need(original['max'] == 0 or original['min'] <= original['max'], 'inverted limits')
    need(domain['level'] == 0 or domain['level'] == baseline_level['index'],
         'current request differs from measured baseline')
    need(baseline_level['index'] <= domain['sustained_level'], 'baseline is above sustained level')
    choices = [x for x in levels if 0 < x['index'] < baseline_level['index'] and
               x['mhz'] <= ceiling_mhz and x['index'] >= original['min'] and
               (original['max'] == 0 or x['index'] <= original['max'])]
    need(choices, 'no conservative nonzero cap within current limits')
    cap = max(choices, key=lambda x: x['mhz'])
    settle_seconds = max(.02, 2 * max(domain['rate_limit_us'], cap['latency_us'], baseline_level['latency_us']) / 1e6)
    need(settle_seconds <= .5, 'transition/rate bound exceeds short-probe budget')
    # Never raise a fallback maximum above the physical baseline, even if original
    # explicit bounds were higher. This is operating-point fallback, not restoration.
    return dict(domain=0, cap_index=cap['index'], cap_mhz=cap['mhz'],
                baseline_index=baseline_level['index'], baseline_mhz=baseline_level['mhz'], settle_seconds=settle_seconds,
                original_level=domain['level'], original_limits=original,
                minimum_preserved=original['min'], fallback_max=baseline_level['index'],
                fallback_kind='explicit measured-operating-point policy; not original firmware ownership',
                original_policy_recovery='cold boot required for previously unowned 0/0 policy')


def policy_sequence(channel, plan, measure, temperatures, record, save, sleep=time.sleep):
    d = plan['domain']
    def xfer(m, p=(), n=0):
        return channel.xfer(perf['PERF'], m, p, rx_words=n)
    def limits():
        value = xfer(6, [d], 2)
        need(len(value) == 2, 'short limits readback')
        return value
    def request(level):
        xfer(7, [d, level])
        value = xfer(8, [d], 1)
        need(value == [level], f'level request not reflected: {value} vs {level}')
    def set_max(index):
        # Zero means preserve the minimum; never ask for a zero max or 0/0.
        need(index > 0, 'refuse zero maximum')
        xfer(5, [d, index, 0])
        value = limits()
        need(value == [index, plan['minimum_preserved']], f'limits readback mismatch: {value}')
        return value
    def phase(name, index, mhz):
        temperatures(name + '-before')
        row = dict(name=name, started=time.time());record['phases'].append(row);save()
        row['limits'] = set_max(index)
        request(index)
        sleep(plan['settle_seconds'])
        row['measurement'] = measure(name)
        measured = row['measurement']
        need(measured['stable'] and abs(1000 * measured['ghz_median'] - mhz) <= mhz * .02 and
             1000 * measured['ghz_max'] <= mhz * 1.02, name + ' physical frequency mismatch')
        temperatures(name + '-after')
        row['verified'] = True;save()
    record['phases'] = []
    phase('cap', plan['cap_index'], plan['cap_mhz'])
    temperatures('challenge-before')
    row = dict(name='challenge', requested_index=plan['baseline_index']);record['phases'].append(row);save()
    before = len(channel.log)
    try:
        xfer(7, [d, plan['baseline_index']])
        row['response'] = 'SUCCESS'
    except Refused:
        need(len(channel.log) == before + 1 and channel.log[-1]['status'] == 'OUT_OF_RANGE' and
             not channel.uncertain, 'challenge failed without a matched OUT_OF_RANGE reply')
        row['response'] = 'OUT_OF_RANGE'
    row['limits'] = limits()
    need(row['limits'] == [plan['cap_index'], plan['minimum_preserved']], 'challenge changed limits')
    sleep(plan['settle_seconds'])
    row['measurement'] = measure('challenge')
    need(row['measurement']['stable'] and 1000 * row['measurement']['ghz_max'] <= plan['cap_mhz'] * 1.02,
         'physical cap not enforced after over-cap request')
    row['level_get'] = xfer(8, [d], 1);row['verified'] = True;save()
    temperatures('challenge-after')
    request(plan['cap_index'])
    row['high_demand_cleared'] = True;save()
    phase('fallback', plan['baseline_index'], plan['baseline_mhz'])
    phase('final-cap', plan['cap_index'], plan['cap_mhz'])
    record['final_policy'] = dict(max_index=plan['cap_index'], min_index=plan['minimum_preserved'],
                                 requested_index=plan['cap_index'], mhz=plan['cap_mhz'])
    save()


def temperature_snapshot(proxy, record, name, save, guard=None, minimum_valid=90):
    rows = []
    for tm, srot in thermal['BLOCKS']:
        version, control = proxy.read32(srot), proxy.read32(srot + 4)
        if not thermal['known_version'](version):
            if guard: guard.freeze('unknown TSENS revision during guarded control probe')
            raise Refused('unknown TSENS revision')
        ready = proxy.read32(tm + 0xe4)
        statuses = [proxy.read32(tm + 0xa0 + 4 * i) for i in range(16)]
        sensors = [thermal['decode_sensor'](version, control, ready, value, i) for i, value in enumerate(statuses)]
        rows.append(dict(tm=hex(tm), version=version, control=control, ready=ready,
                         statuses=statuses, sensors=sensors))
    valid = [s['millidegrees_c'] for b in rows for s in b['sensors'] if s['millidegrees_c'] is not None]
    result = dict(name=name, time=time.time(), blocks=rows, valid=len(valid), maximum=max(valid) if valid else None)
    record.setdefault('temperatures', []).append(result);save()
    result['serror'] = proxy.serror_state();save()
    if not perf['serror_clear'](result['serror']):
        if guard: guard.freeze('SError during thermal snapshot')
        raise Refused('SError during thermal snapshot')
    need(len(valid) >= minimum_valid and (not valid or max(valid) < 45000),
         f'brief CPU probe requires at least {minimum_valid} valid sensors below 45 C')
    return result


def characterization_history(prior, failed, capped):
    """Admit only the retained, completed cap/readback-deviation experiment."""
    need(prior['status'] == capped['status'] == 'QUERY_VERIFIED' and
         failed['status'] == 'REFUSED_OR_FAILED', 'characterization history status mismatch')
    for receipt in (prior, failed, capped):
        need(not receipt['control_guard']['frozen'] and receipt['control_guard']['closed'] and
             receipt['scratch']['restored'] and not receipt.get('cleanup_errors'),
             'history contains an uncertain or unrestored session')
        need({k: receipt['bootinfo'][k] for k in IDENTITY} ==
             {k: prior['bootinfo'][k] for k in IDENTITY} and
             receipt['resident_code']['sha256'] == prior['resident_code']['sha256'],
             'characterization receipts describe different resident stages')
        need(receipt['domain']['levels'] == prior['domain']['levels'], 'historical level table drift')
    plan = dict(prior['plan'])
    need(plan_policy(prior['domain'], prior['measurements']['baseline']) == plan,
         'historical plan does not match its verified domain and physical baseline')
    need(plan == failed['plan'] and plan['cap_index'] == 8 and plan['cap_mhz'] == 1939.2 and
         plan['baseline_index'] == 16 and plan['baseline_mhz'] == 3072 and
         plan['original_limits'] == {'max': 0, 'min': 0}, 'not the reviewed CPU0 experiment')
    writes = [x for x in failed['transactions'] if x['protocol'] == hex(perf['PERF']) and x['message'] in (5, 7)]
    need(len(writes) == 1 and writes[0]['message'] == 5 and
         writes[0]['payload'] == [0, 8, 0] and writes[0]['status'] == 'SUCCESS',
         'historical mutation was not exactly the reviewed cap request')
    need(failed['error'] == 'Refused: limits readback mismatch: [12, 0]' and
         failed['transactions'][-1]['response'] == [12, 0] and
         capped['domain']['limits'] == {'max': 12, 'min': 0} and capped['domain']['level'] == 0,
         'not the reviewed readback deviation')
    for receipt, mhz in ((prior, 3072), (failed, 3072), (capped, 1939.2)):
        measured_point(receipt['measurements']['baseline'], mhz, 'historical point')
    plan.update(observed_raw_limits=[12, 0], challenge_indices=[9, 12, 16])
    return plan


def measured_point(value, mhz, name):
    need(value['midr'] == '0x512f0021' and value['affinity'] == '0x0' and value['stable'] and
         abs(value['ghz_median'] * 1000 - mhz) <= mhz * .02 and
         value['ghz_max'] * 1000 <= mhz * 1.02, name + ' physical frequency mismatch')


def characterize_sequence(channel, plan, measure, temperatures, record, save, sleep=time.sleep):
    """Finite CPU0 experiment; raw GET values never become a generic index map."""
    record['phases'] = []
    record['final_conservative_policy_verified'] = False
    def xfer(m, payload, count=0):
        result = channel.xfer(perf['PERF'], m, payload, rx_words=count)
        if m in (5, 7):
            record['last_acknowledged_policy_write'] = dict(message=m, payload=payload)
            save()
        return result
    def observe(row, name):
        row['raw_limits'] = xfer(6, [0], 2)
        row['raw_level'] = xfer(8, [0], 1)
        sleep(plan['settle_seconds'])
        row['measurement'] = measure(name); save()
    def lower(name, set_max=False):
        # Called only after a known terminal exchange, never in a finally block.
        need(not channel.guard.frozen and not channel.uncertain, 'containment forbidden after uncertainty')
        temperatures(name + '-before')
        row = dict(name=name);record['phases'].append(row);save()
        if set_max: xfer(5, [0, 8, 0])
        xfer(7, [0, 8]);observe(row, name)
        need(row['raw_limits'] == plan['observed_raw_limits'], 'lower request changed raw bounds')
        measured_point(row['measurement'], plan['cap_mhz'], name)
        row['verified'] = True;save();temperatures(name + '-after')
        return row
    lower('explicit-cap-demand')
    for index in plan['challenge_indices']:
        temperatures('challenge-' + str(index) + '-before')
        row = dict(name='challenge-' + str(index), requested_index=index)
        record['phases'].append(row);save();before = len(channel.log)
        try:
            xfer(7, [0, index]);row['response'] = 'SUCCESS'
        except Refused:
            need(not channel.guard.frozen and not channel.uncertain and
                 len(channel.log) == before + 1 and channel.log[-1]['status'] == 'OUT_OF_RANGE',
                 'challenge lacks a matched terminal OUT_OF_RANGE reply')
            row['response'] = 'OUT_OF_RANGE'
        observe(row, row['name'])
        need(row['raw_limits'] == plan['observed_raw_limits'], 'challenge changed raw bounds')
        try:
            measured_point(row['measurement'], plan['cap_mhz'], row['name'])
        except Refused:
            row['cap_escaped_or_unstable'] = True;save()
            lower('containment-after-' + str(index))
            raise
        row['verified'] = True;save();temperatures(row['name'] + '-after')
    lower('clear-challenge-demand')
    temperatures('fallback-before')
    row = dict(name='fallback');record['phases'].append(row);save()
    xfer(5, [0, 16, 0]);xfer(7, [0, 16]);observe(row, 'fallback')
    need(row['raw_limits'][1] == 0, 'fallback changed minimum')
    try:
        measured_point(row['measurement'], plan['baseline_mhz'], 'fallback')
    except Refused:
        row['fallback_failed'] = True;save();lower('containment-after-fallback', set_max=True)
        raise
    row['verified'] = True;save();temperatures('fallback-after')
    final = lower('final-cap', set_max=True)
    record['final_policy'] = dict(requested_max_index=8, requested_level_index=8,
        raw_limits=final['raw_limits'], raw_level=final['raw_level'], measured_mhz=1939.2,
        qualification='short CPU0/PDP0 demand challenges and measured fallback only',
        limitation='firmware GET deviation unresolved; no generic index translation or SCMI conformance')
    record['final_conservative_policy_verified'] = True
    save()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('mode', choices=('query', 'cap', 'characterize'))
    ap.add_argument('--device', required=True);ap.add_argument('--generation', type=int, required=True)
    ap.add_argument('--image-base', type=lambda x: int(x, 0), required=True)
    ap.add_argument('--heap-base', type=lambda x: int(x, 0), required=True)
    ap.add_argument('--stage', type=Path, required=True)
    ap.add_argument('--idle', action='store_true', required=True)
    ap.add_argument('--baseline', type=Path)
    ap.add_argument('--failed-cap', type=Path)
    ap.add_argument('--capped-query', type=Path)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    need(not args.output.exists(), 'output exists')
    perf['Workspace'](ROOT)
    clock['require_exclusive'](perf['Workspace'](ROOT))
    prior = json.loads(args.baseline.read_text()) if args.baseline else None
    need(args.mode != 'cap' or prior and prior['status'] == 'QUERY_VERIFIED', 'cap requires a verified query receipt')
    history_plan = None
    if args.mode == 'characterize':
        need(prior and args.failed_cap and args.capped_query, 'characterization requires all three history receipts')
        failed = json.loads(args.failed_cap.read_text());capped = json.loads(args.capped_query.read_text())
        need(failed['baseline_receipt']['sha256'] == sha(args.baseline.read_bytes()), 'failed cap baseline hash mismatch')
        history_plan = characterization_history(prior, failed, capped)
    args.output.mkdir(parents=True)
    record = dict(schema='a16-cpu-policy-v1', status='STARTING', mode=args.mode, started=time.time(),
                  scope='CPU0/PDP0 only; no secondary startup, guest, GPU or fan qualification',
                  sources={x: sha((ROOT / x).read_bytes()) for x in SOURCES})
    path = args.output / 'receipt.json'
    def save():
        temporary = path.with_suffix('.tmp')
        with temporary.open('w') as stream:
            stream.write(json.dumps(record, indent=2) + '\n');stream.flush();os.fsync(stream.fileno())
        temporary.replace(path)
    snapshots = args.output / 'sources';snapshots.mkdir()
    for name in SOURCES:
        destination = snapshots / name.replace('../', 'sibling/');destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / name).read_bytes())
    if history_plan:
        record['history'] = {}
        for label, source in (('baseline', args.baseline), ('failed-cap', args.failed_cap), ('capped-query', args.capped_query)):
            data = source.read_bytes();(args.output / (label + '-input.json')).write_bytes(data)
            record['history'][label] = dict(path=str(source), sha256=sha(data))
    save()
    # Build distinct artifacts; do not overwrite historical builds or other agents' outputs.
    stub = clock['build_stub'](args.output / 'native')
    memory = run.build('el2-memory', args.output / 'native')
    psci = run.build('psci-info', args.output / 'native')
    collect = runpy.run_path(str(ROOT / 'tools/probe-el2-memory.py'))['collect']
    cpus = runpy.run_path(str(ROOT / 'tools/probe-a16-cpus.py'))['collect']
    guard_module = runpy.run_path(str(ROOT / 'tools/a16-control-guard.py'))
    record['binaries'] = {n: sha(b) for n, b in [('pmu', stub), ('memory', memory), ('psci', psci)]}
    with Path('/tmp/snapintosh-hardware.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        proxy, guard, scratch, raw = None, None, None, None
        strict_enabled = False
        try:
            raw = run.connect(args.device, tries=1)
            guard = guard_module['ControlGuard'](raw, record, save)
            proxy = guard.proxy
            info = proxy.bootinfo();record['bootinfo'] = info
            need(info['stage_generation'] == args.generation and info['image_base'] == args.image_base and
                 info['heap_base'] == args.heap_base and info['current_el'] == 2 and info['timer_hz'] == 19200000,
                 'resident identity mismatch')
            need(info['heap_size'] >= clock['SCRATCH_TOP'], 'heap too small')
            # Stage header/config is mutable; retain and compare the first code page after it.
            resident = proxy.readmem(info['image_base'] + 0x1000, 4096, live=True)
            reference = args.stage.read_bytes()[0x1000:0x2000]
            record['resident_code'] = dict(address=hex(info['image_base'] + 0x1000), sha256=sha(resident),
                                           reference=str(args.stage), reference_sha256=sha(args.stage.read_bytes()))
            need(len(reference) == 4096 and resident == reference, 'resident immutable code differs from retained stage')
            record['serror_before'] = proxy.serror_state()
            need(perf['serror_clear'](record['serror_before']), 'preexisting SError')
            if prior:
                need({k: info[k] for k in IDENTITY} == {k: prior['bootinfo'][k] for k in IDENTITY} and
                     record['resident_code']['sha256'] == prior['resident_code']['sha256'], 'baseline is from another stage')
                record['baseline_receipt'] = dict(path=str(args.baseline), sha256=sha(args.baseline.read_bytes()))
            proxy.serror_strict(True)
            strict_enabled = True
            status = proxy.call(info['battery_call'], 0, 0, 0, 0, 0, timeout=12)
            battery = proxy.live_battery_record(info['battery_result']);record['battery'] = dict(battery, native_return=status);save()
            need(status == 0 and battery['plausible'] and (battery['ac'] or battery['percent'] >= 80), 'battery admission refused')
            temperatures = lambda n: temperature_snapshot(proxy, record, n, save, guard)
            temperatures('initial')
            scratch = clock['Scratch'](proxy, clock['scratch_ranges'](info['heap_base'], stub, max(len(memory), len(psci))))
            preimage = b''.join(data for _, data in scratch.saved)
            with (args.output / 'scratch-preimage.bin').open('wb') as stream:
                stream.write(preimage);stream.flush();os.fsync(stream.fileno())
            record['scratch_preimage'] = dict(sha256=sha(preimage),
                ranges=[dict(address=hex(a), bytes=len(data), sha256=sha(data)) for a, data in scratch.saved]);save()
            try:
                inventory = cpus(proxy, psci, True)
            except BaseException as error:
                guard.freeze('native CPU inventory not verified: ' + str(error));raise
            record['inventory'] = inventory
            states = clock['cpu_states'](inventory)
            need(inventory['boot_mpidr'] == '0x0' and len(states) == 18 and
                 all(s == (0 if m == 0 else 1) for m, s in states.items()), 'not an idle 18-core A16')
            def regime_collect(target, blob):
                try: return collect(target, blob)
                except BaseException as error:
                    guard.freeze('native regime report not verified: ' + str(error));raise
            surveyed = perf['survey'](proxy, info, memory, regime_collect);record['survey'] = surveyed;save()
            need(surveyed['verdict']['pdp0']['usable'], 'PDP0 survey refuses mailbox')
            kinds = {perf['PAGES'][n]: p['kind'] for n, p in surveyed['pages'].items() if p}
            code, out = info['heap_base'] + clock['CODE_AT'], info['heap_base'] + clock['RESULT_AT']
            clock['upload'](proxy, code, stub)
            def sync(address, length, op):
                value = proxy.call(code + clock['ENTRY_SYNC'], address, length, op, timeout=10)
                if value != 0x5c:
                    guard.freeze('sync returned unexpected value');raise Refused(guard.reason)
            access = PolicyAccess(proxy, kinds, sync, perf['TRANSPORTS']['pdp0'])
            channel = PolicyChannel(access, perf['TRANSPORTS']['pdp0'], guard, record, save)
            scmi = PolicyScmi(channel)
            record['base'] = scmi.base();record['perf'] = scmi.perf();save()
            need(record['base']['vendor'].lower().startswith('qualcomm') and record['perf']['version'] == '0x40000' and
                 record['perf']['domains'] == 3, 'unexpected SCMI provider')
            domain = scmi.domain(0, True);record['domain'] = domain;save()
            def measure(name):
                ticks = info['timer_hz'] // 100
                proxy.writemem(out, bytes(clock['REPORT_BYTES']))
                proxy.call(code + clock['ENTRY_MEASURE'], out, 4, ticks, timeout=10)
                blob = proxy.readmem(out, clock['REPORT_BYTES'], live=True)
                (args.output / (name + '-pmu.bin')).write_bytes(blob)
                try:
                    value = clock['decode'](struct.unpack('<64Q', blob), 4, ticks, info['timer_hz'])
                except BaseException as error:
                    guard.freeze('native PMU report not verified: ' + str(error));raise
                try:
                    need(value['midr'] == '0x512f0021' and value['affinity'] == '0x0', 'CPU identity mismatch')
                    need(perf['serror_clear'](proxy.serror_state()) and not proxy.exceptions and not proxy.get_exc_count(),
                         'native measurement fault')
                except BaseException as error:
                    guard.freeze('native PMU identity/fault state not verified: ' + str(error));raise
                value['raw_sha256'] = sha(blob);record.setdefault('measurements', {})[name] = value;save()
                return value
            baseline = measure('baseline');temperatures('baseline-after')
            if args.mode == 'characterize':
                need(all(domain[k] == capped['domain'][k] for k in domain), 'fresh domain differs from reviewed capped query')
                measured_point(baseline, history_plan['cap_mhz'], 'fresh capped baseline')
                plan = history_plan
            else:
                plan = plan_policy(domain, baseline)
            record['plan'] = plan;save()
            if args.mode == 'cap':
                need(plan == prior['plan'], 'fresh policy/baseline differs from reviewed query plan')
                policy_sequence(channel, plan, measure, temperatures, record, save)
            elif args.mode == 'characterize':
                characterize_sequence(channel, plan, measure, temperatures, record, save)
            record['status'] = {'query': 'QUERY_VERIFIED', 'cap': 'CPU0_CAP_VERIFIED',
                                'characterize': 'CPU0_CHARACTERIZED_CAP_VERIFIED'}[args.mode]
        except BaseException as error:
            record['status'] = 'UNCERTAIN' if guard and guard.frozen else 'REFUSED_OR_FAILED'
            record['error'] = f'{type(error).__name__}: {error}'
            if args.mode == 'characterize':
                record['final_policy_limitation'] = ('No completed final cap qualification. Consult the last acknowledged '
                    'policy write and PMU evidence; thermal refusal or uncertainty prevents automatic containment. '
                    'Unknown completion requires external recovery; known completion requires a fresh guarded state review.')
        finally:
            if proxy:
                try:
                    if guard.frozen:
                        record['scratch'] = dict(restored=False, reserved_because=guard.reason)
                    else:
                        if scratch: record['scratch'] = guard.restore_scratch(scratch)
                        if strict_enabled:
                            state = proxy.serror_state();record['serror_after'] = state
                            need(perf['serror_clear'](state), 'SError at cleanup')
                            proxy.serror_strict(bool(record['serror_before']['flags'] & 1))
                except BaseException as error:
                    record.setdefault('cleanup_errors', []).append(f'{type(error).__name__}: {error}')
                    record['status'] = 'UNCERTAIN' if guard.frozen else 'REFUSED_OR_FAILED'
                finally:
                    guard.close()
            if raw and guard is None:
                raw.link.close()
            record['finished'] = time.time();save()
    print(json.dumps({k: record.get(k) for k in ('status', 'error', 'final_policy', 'cleanup_errors')}))
    return 0 if record['status'] in ('QUERY_VERIFIED', 'CPU0_CAP_VERIFIED', 'CPU0_CHARACTERIZED_CAP_VERIFIED') else 1


if __name__ == '__main__':
    sys.exit(main())
