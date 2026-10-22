#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Inventory structured Adreno omissions and encoding summaries in retained logs.

Legacy deduplicated 'dropped:' text is not a work count. Never interprets a Metal
commit as GPU completion. Each open marker starts a new process session, including
PID reuse after a reboot. Truncated/missing summaries remain explicit.
"""
import argparse
import collections
import json
from pathlib import Path


def inventory(paths):
    buffers = {}
    operations = collections.Counter()
    reasons = collections.Counter()
    problems = []
    legacy = 0
    for path in paths:
        session = 0
        for number, line in enumerate(Path(path).read_text(errors='replace').splitlines(), 1):
            if line.startswith('open pid '):
                session += 1
            if 'work-trace-incomplete:' in line:
                problems.append(f'{path}:{number}: {line.strip()}')
            if 'dropped: ' in line:
                legacy += 1
            start = line.find('{')
            if start < 0:
                continue
            try:
                event = json.loads(line[start:])
            except json.JSONDecodeError:
                problems.append(f'{path}:{number}: malformed JSON')
                continue
            if event.get('event') not in ('omitted', 'commit-encoding'):
                continue
            key = f'{Path(path).resolve()}/session{session}/cb{event["command_buffer"]}'
            state = buffers.setdefault(key, dict(events=[], summary=None))
            if event['event'] == 'omitted':
                if any(prior['ordinal'] == event['ordinal'] for prior in state['events']):
                    problems.append(f'{key}: repeated work ordinal {event["ordinal"]}')
                    continue
                state['events'].append(event)
                operations[event['operation']] += 1
                reasons[event['details'].get('reason', 'unspecified')] += 1
            else:
                if state['summary'] is not None:
                    problems.append(f'{key}: repeated commit summary')
                state['summary'] = event
    outcomes = {}
    for key, state in buffers.items():
        summary = state['summary']
        if summary is None:
            outcomes[key] = dict(status='UNCOMMITTED', omissions=len(state['events']))
            continue
        incomplete = bool(summary['trace_incomplete'])
        if summary['omitted'] != len(state['events']):
            problems.append(f'{key}: omitted count differs from durable events')
            incomplete = True
        if sum(e['omitted'] for e in summary['encoders'].values()) != summary['omitted']:
            problems.append(f'{key}: encoder totals differ from buffer total')
            incomplete = True
        if not all(e['ended'] for e in summary['encoders'].values()):
            problems.append(f'{key}: encoder never ended')
            incomplete = True
        status = ('TRACE_INCOMPLETE' if incomplete else 'ENCODING_FAILED' if summary['encoding_failed']
                  else 'OMITTED_WORK' if summary['omitted'] else 'ENCODING_ONLY')
        outcomes[key] = dict(status=status, encoded=summary['encoded'], omissions=summary['omitted'])
    return dict(schema=1, status='STRUCTURED_TRACE' if buffers else 'NO_STRUCTURED_TRACE', structured_omissions=sum(operations.values()), operations=dict(operations),
                reasons=dict(reasons), command_buffers=outcomes, problems=problems,
                legacy_reason_lines=legacy,
                boundary='Encoding evidence only. Legacy reasons are deduplicated; absence of structured work is not zero omissions.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('logs', type=Path, nargs='+')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = inventory(args.logs)
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(dict(omissions=report['structured_omissions'], buffers=len(report['command_buffers']),
                          problems=len(report['problems']), output=str(args.output))))
