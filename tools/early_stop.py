# SPDX-License-Identifier: MIT
"""Early-stop record (compat/early-stop.h struct early_stop_state) and launch settings.

The record is appended to the monitor context and copied into the report at
OUT_EARLY_STOP (probes/run.py EARLY_STOP_OFFSET). Field order is the C order;
tools/test-early-stop.py checks it against the header. Nothing here touches
hardware: decode() takes bytes, settings() takes an environment mapping.
"""
import os
import secrets
import struct
from a16_thermal import REASONS as THERMAL_REASONS

FIELDS = ('state source reason detail requested_delay accepted_delay '
          'request_ticks deadline fire_ticks request_cpu request_pc fire_cpu '
          'refusals last_refusal duplicates host_polls host_next_poll host_armed '
          'host_status host_errors host_in_call outcome').split() + [f'text{n}' for n in range(8)]
SIZE = 8 * len(FIELDS)

F_GUEST, F_HOST = 1, 2
F_CONSOLE = 4              # EARLY_STOP_F_CONSOLE: the two-way console (compat/console-link.h)
F_THERMAL = 8
F_NET = 16                 # EARLY_STOP_F_NET: the guest network (compat/guest-net-link.h, docs/GUEST-NETWORK-20261019.md)
SOURCES = {1: 'guest', 2: 'host', 3: 'thermal'}
GUEST_REASONS = {1: 'first AdrenoDisplay present', 2: 'AdrenoMetal failure before raise',
                 3: "WindowServer's GPU task ended"}
HOST_REASONS = {1: 'operator request'}
PHASES = {0: 'idle', 1: 'arming', 2: 'pending', 3: 'fired', 4: 'updating'}
OUTCOMES = {0: 'none', 1: 'stopped', 2: 'concurrent', 3: 'superseded'}
RESULTS = {0: 'accepted', 1: 'duplicate', -60: 'disabled', -80: 'caller not admitted',
           -81: 'bad reason', -82: 'bad delay', -83: 'malformed host latch'}

DELAY_LIMIT = 3600          # EARLY_STOP_DELAY_LIMIT
POLL_MIN_MS, POLL_MAX_MS = 20, 5000
POLL_MIN_NET_MS = 2         # EARLY_STOP_POLL_MIN_NET_MS: only a SNAP_GUEST_NET monitor polls this fast
DEFAULT_DELAY, DEFAULT_MAX_DELAY, DEFAULT_POLL_MS = 20, 120, 200
DEFAULT_CONSOLE_POLL_MS = 50   # keystroke to echo is about one poll plus the kernel's 16 ms
DEFAULT_NET_POLL_MS = 5        # one reply datagram (<= 1440 bytes) leaves per poll
PARAMS_WORDS = 6            # struct early_stop_params


def signed(value):
    return value - (1 << 64) if value >> 63 else value


def text(words):
    raw = b''.join(struct.pack('<Q', w) for w in words)
    return raw.split(b'\0', 1)[0].decode('utf-8', 'replace')


def decode(raw):
    if len(raw) != SIZE:
        raise ValueError(f'early_stop_state is {SIZE} bytes, got {len(raw)}')
    values = dict(zip(FIELDS, struct.unpack(f'<{len(FIELDS)}Q', raw)))
    record = {k: v for k, v in values.items() if not k.startswith('text')}
    record['text'] = text([values[f'text{n}'] for n in range(8)])
    record['last_refusal'] = signed(record['last_refusal'])
    record['host_status'] = signed(record['host_status'])
    return record


def reason_name(source, reason):
    table = {1: GUEST_REASONS, 2: HOST_REASONS, 3: THERMAL_REASONS}.get(source, {})
    return table.get(reason, f'reason {reason}')


def summary(record, hz=None):
    """Plain sentences for the transcript; empty when nothing was requested."""
    lines = []
    phase, outcome = record['state'], record['outcome']
    if phase or record['refusals'] or record['host_polls']:
        source = SOURCES.get(record['source'], f'source {record["source"]}')
        what = reason_name(record['source'], record['reason'])
        if phase:
            line = (f'early stop: {source} request "{what}" (detail {record["detail"]:#x}), '
                    f'delay {record["requested_delay"]}s asked, {record["accepted_delay"]}s accepted, '
                    f'phase {PHASES.get(phase, phase)}, outcome {OUTCOMES.get(outcome, outcome)}')
            if record['text']:
                line += f', text {record["text"]!r}'
            if record['fire_cpu']:
                line += f', fired on CPU{record["fire_cpu"] - 1}'
                if hz:
                    line += f' {(record["fire_ticks"] - record["request_ticks"]) / hz:.3f}s after the request'
            lines.append(line)
        if record['refusals']:
            lines.append(f'early stop: {record["refusals"]} request(s) refused, last '
                         f'{RESULTS.get(record["last_refusal"], record["last_refusal"])}')
        if record['duplicates']:
            lines.append(f'early stop: {record["duplicates"]} request(s) did not shorten the pending deadline or arrived after firing')
        if record['host_polls']:
            lines.append(f'early stop: host polled {record["host_polls"]} times, armed '
                         f'{record["host_armed"]}, errors {record["host_errors"]}, last status '
                         f'{record["host_status"]}')
    return lines


class Settings:
    """What SNAP_EARLY_STOP* asks for, validated. None when the feature is off."""

    def __init__(self, flags, delay, max_delay, poll_ms, session):
        self.flags, self.delay, self.max_delay = flags, delay, max_delay
        self.poll_ms, self.session = poll_ms, session

    @property
    def guest(self):
        return bool(self.flags & F_GUEST)

    @property
    def host(self):
        return bool(self.flags & F_HOST)

    @property
    def console(self):
        return bool(self.flags & F_CONSOLE)

    @property
    def thermal(self):
        return bool(self.flags & F_THERMAL)

    @property
    def net(self):
        return bool(self.flags & F_NET)

    def params_words(self, host_call=0, host_state=0):
        if self.host and not host_call:
            raise ValueError('host early stop needs q1n1 call_service')
        return [self.flags, self.max_delay, host_call if self.host else 0,
                host_state if self.host else 0, self.poll_ms if self.host else 0,
                self.session if self.host else 0]

    def record(self):
        return dict(flags=self.flags, guest=self.guest, host=self.host, console=self.console, thermal=self.thermal,
                    net=self.net,
                    delay_s=self.delay,
                    max_delay_s=self.max_delay, poll_ms=self.poll_ms, session=f'{self.session:#018x}')


def settings(environ=None):
    """SNAP_EARLY_STOP: a comma list of guest, host, console, thermal and net (unset or empty: off).
    console is the two-way console (tools/guest-console.py); it rides on the
    host poll, so it implies host, and its poll defaults to 50 ms; net is the
    guest network (tools/guest-net.py), also on the host poll, polled every
    5 ms by default and as often as every 2 ms (a SNAP_GUEST_NET monitor);
    SNAP_EARLY_STOP_DELAY (default 20), SNAP_EARLY_STOP_MAX_DELAY (default 120),
    SNAP_EARLY_STOP_POLL_MS (default 200)."""
    environ = os.environ if environ is None else environ
    mode = environ.get('SNAP_EARLY_STOP', '').strip()
    if not mode:
        return None
    flags = 0
    for word in mode.split(','):
        word = word.strip()
        if word == 'guest':
            flags |= F_GUEST
        elif word == 'host':
            flags |= F_HOST
        elif word == 'thermal':
            flags |= F_HOST | F_THERMAL
        elif word == 'console':
            flags |= F_HOST | F_CONSOLE
        elif word == 'net':
            flags |= F_HOST | F_NET
        else:
            raise ValueError(f'SNAP_EARLY_STOP: unknown trigger {word!r} (guest, host, console, thermal, net)')

    def number(name, default, low, high):
        raw = environ.get(name, '')
        try:
            value = int(raw, 0) if raw.strip() else default
        except ValueError:
            raise ValueError(f'{name} is not an integer: {raw!r}') from None
        if not low <= value <= high:
            raise ValueError(f'{name}={value} outside [{low}, {high}]')
        return value
    max_delay = number('SNAP_EARLY_STOP_MAX_DELAY', DEFAULT_MAX_DELAY, 0, DELAY_LIMIT)
    delay = number('SNAP_EARLY_STOP_DELAY', min(DEFAULT_DELAY, max_delay), 0, max_delay)
    poll = number('SNAP_EARLY_STOP_POLL_MS',
                  DEFAULT_NET_POLL_MS if flags & F_NET else
                  DEFAULT_CONSOLE_POLL_MS if flags & F_CONSOLE else DEFAULT_POLL_MS,
                  POLL_MIN_NET_MS if flags & F_NET else POLL_MIN_MS, POLL_MAX_MS)
    session = 0
    while not session:
        session = secrets.randbits(64)
    return Settings(flags, delay, max_delay, poll, session)
