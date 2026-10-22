#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""A live console into a running Snapintosh guest, from the Mac, while P_CALL runs.

docs/GUEST-SHELL-DESIGN-20261016.md. A launch with SNAP_EARLY_STOP=console makes
the monitor hand q1n1's call-service poll a console view (compat/console-link.h):
its console ring to read and a staging buffer for input, which reaches XNU's
serial input (serial=3, polled every 16 ms) through the DockChannel receive
registers. This tool speaks q1n1's console protocol (magic Q1SC on the stop
port, UDP 4920; q1n1 platform/uefi/call-service.h) to read the console as it is
written and to type into it. With the boot-arg-gated console-shell job on the
guest (config/guest/org.snapintosh.console-shell.plist) that is a root shell.

    python3 tools/guest-console.py --device udp://en6 --launch-record build/PREFIX-early-stop-launch.json
    python3 tools/guest-console.py --device udp://en6 --launch-record R --stream
    python3 tools/guest-console.py --device udp://en6 --launch-record R --run 'log show --last 2m | tail -50'
    python3 tools/guest-console.py --device udp://en6 --launch-record R --query

Interactive (the default on a terminal): raw keys, Ctrl-] quits. --stream only
watches and never types; like --query it never takes the console's owner, so it
can run beside the one tool that types. --run sends one command line to the shell on the
console and prints what it wrote between two markers; the console also carries
kernel and launchd logging, and --run drops launchd's lines unless --keep-noise.
--query makes one exchange and prints it as JSON.

A side client like tools/request-stop.py: it never talks to the proxy port
(4919) and cannot re-point the proxy peer; outside a call q1n1 answers "not
armed". One owner per run: a second tool is refused unless it passes
--takeover. Input is filtered for XNU's 32-byte "Automatic NMI" sequence (the
monitor drops it too). Bulk output belongs in files read from the post-run
snapshot: every console byte costs the guest two locked traps.

Exit status: 0 done (the call ended, the stream was closed, or --run's command
exited 0), 1 bad arguments, 2 refused (session, owner, no console view), 3 no
answer, 4 --run timed out, 5 --run's command exited non-zero.
"""
import argparse
import collections
import json
import os
import secrets
import select
import socket
import struct
import sys
import termios
import time
import tty
import zlib

PORT = 4920
TARGET = 'fe80::4919'                               # q1n1's fixed link-local address
REQUEST = struct.Struct('<IHHQQQQQHHI')             # 56-byte header, then input, then CRC
REPLY = struct.Struct('<IHHQQiIQQQQHHI')            # 72-byte header, then output, then CRC
REQUEST_MAGIC, REPLY_MAGIC, VERSION, EXCHANGE = 0x43533151, 0x44533151, 1, 1
IN_MAX, REPLY_MAX = 1024, 1440
OUT_MAX = REPLY_MAX - REPLY.size - 4
TAKEOVER, PEEK = 1, 2                               # PEEK: watch only, never the owner
F_ARMED, F_VIEW, F_OWNER, F_GAP = 1, 2, 4, 8
OK, MALFORMED, NOT_ARMED, SESSION, OWNER, NO_VIEW = 0, -1, -2, -3, -6, -7
STATUS = {OK: 'ok', MALFORMED: 'malformed', NOT_ARMED: 'not armed', SESSION: 'wrong session',
          OWNER: 'another console owner holds this run (use --takeover)',
          NO_VIEW: 'this run has no console (launch it with SNAP_EARLY_STOP=console)'}
NMI = b'afDIGHr84A84jh19Kphgp428DNPdnapq'           # compat/console-link.h CONSOLE_LINK_NMI
LAUNCHD = b'com.apple.xpc.launchd|'
QUIT = 0x1d                                         # Ctrl-]


def encode(nonce, session, owner, in_offset, out_ack, data=b'', out_max=0, flags=0):
    if len(data) > IN_MAX or not owner:
        raise ValueError('at most IN_MAX input bytes, and a nonzero owner')
    body = REQUEST.pack(REQUEST_MAGIC, VERSION, EXCHANGE, nonce, session, owner, in_offset,
                        out_ack, len(data), out_max, flags) + bytes(data)
    return body + struct.pack('<I', zlib.crc32(body))


def decode(datagram):
    if len(datagram) < REPLY.size + 4:
        raise ValueError('short reply')
    (magic, version, op, nonce, session, status, flags, in_held, out_offset, produced, polls,
     out_length, in_room, zero) = REPLY.unpack_from(datagram)
    end = REPLY.size + out_length
    if (magic != REPLY_MAGIC or version != VERSION or zero or len(datagram) != end + 4 or
            struct.unpack_from('<I', datagram, end)[0] != zlib.crc32(datagram[:end])):
        raise ValueError('not a q1n1 console reply (magic, version, length or CRC)')
    return dict(op=op, nonce=nonce, session=session, status=status,
                status_text=STATUS.get(status, f'status {status}'), armed=bool(flags & F_ARMED),
                view=bool(flags & F_VIEW), owner=bool(flags & F_OWNER), gap=bool(flags & F_GAP),
                in_held=in_held, out_offset=out_offset, produced=produced, polls=polls,
                in_room=in_room, data=datagram[REPLY.size:end])


class NmiGuard:
    """XNU's matcher (advance on a match, zero on anything else) over what we send;
    the byte that would complete the sequence is dropped."""

    def __init__(self):
        self.match = self.dropped = 0

    def filter(self, data):
        out = bytearray()
        for byte in data:
            following = self.match + 1 if byte == NMI[self.match] else 0
            if following == len(NMI):
                self.dropped += 1
                continue
            self.match = following
            out.append(byte)
        return bytes(out)


class LineFilter:
    """Drop whole lines that start with `prefix` from a byte stream, passing every
    other byte through as soon as it is known not to begin one."""

    def __init__(self, prefix, enabled):
        self.prefix, self.enabled, self.state, self.held = prefix, enabled, 'start', bytearray()

    def feed(self, data):
        if not self.enabled:
            return data
        out = bytearray()
        for byte in data:
            if self.state == 'start':
                self.held.append(byte)
                if self.prefix.startswith(bytes(self.held)):
                    if len(self.held) == len(self.prefix):
                        self.state, self.held = 'drop', bytearray()
                    continue
                out += self.held
                self.held = bytearray()
                self.state = 'start' if byte == 10 else 'pass'
            elif self.state == 'pass':
                out.append(byte)
                if byte == 10:
                    self.state = 'start'
            elif byte == 10:
                self.state = 'start'
        return bytes(out)


def interface_of(device):
    if not device.startswith('udp://') or not device[6:]:
        raise ValueError('--device must be udp://INTERFACE (for example udp://en6)')
    return device[6:]


class Link:
    """q1n1's stop port on the NCM link, or HOST:PORT (an offline stand-in)."""

    def __init__(self, device=None, target=None):
        if target:
            host, _, port = target.rpartition(':')
            info = socket.getaddrinfo(host.strip('[]'), int(port), type=socket.SOCK_DGRAM)[0]
            self.family, self.peer, self.scope = info[0], info[4], None
        else:
            self.family, self.scope = socket.AF_INET6, socket.if_nametoindex(interface_of(device))
            self.peer = (TARGET, PORT, 0, self.scope)
        self.socket = socket.socket(self.family, socket.SOCK_DGRAM)
        self.socket.bind(('::', 0) if self.family == socket.AF_INET6 else ('0.0.0.0', 0))
        self.socket.setblocking(False)

    def close(self):
        self.socket.close()

    def send(self, datagram):
        try:
            self.socket.sendto(datagram, self.peer)
        except OSError:
            pass                      # the link is down; the next exchange retries

    def receive(self, timeout):
        """Replies from the peer's port that arrive within `timeout` (at least one
        wait; returns as soon as something arrived and nothing more is queued)."""
        got, deadline = [], time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            ready, _, _ = select.select([self.socket], [], [], max(0.0, left) if not got else 0)
            if not ready:
                return got
            try:
                data, peer = self.socket.recvfrom(2048)
            except (BlockingIOError, ConnectionRefusedError):
                continue
            if peer[1] != self.peer[1] or (self.scope and peer[3] not in (0, self.scope)):
                continue
            try:
                got.append(decode(data))
            except ValueError:
                continue


class Console:
    """One owner's view of the stream. Offsets are absolute, so a reply that is
    lost, repeated or late changes nothing: output merges by offset, and the
    input q1n1 holds only grows."""

    def __init__(self, link, session, owner=None, takeover=False, wait_s=0.15, history=None,
                 sink=None, peek=False):
        self.link, self.session, self.peek = link, session, peek
        self.owner = owner or secrets.randbits(63) + 1
        self.takeover, self.wait_s, self.history, self.sink = takeover, wait_s, history, sink
        self.guard = NmiGuard()
        self.pending, self.in_base, self.out_have = bytearray(), None, None
        self.recent = collections.OrderedDict()
        self.armed_seen = self.ended = False
        self.error = None
        self.last = None
        self.segments = []
        self.stats = dict(requests=0, replies=0, unanswered=0, stale=0, gaps=0, gap_bytes=0,
                          out_bytes=0, in_queued=0, in_acked=0)

    def type(self, data):
        if self.peek:
            raise ValueError('a watcher (--stream, --query) never types')
        data = self.guard.filter(data)
        self.pending += data
        self.stats['in_queued'] += len(data)

    def request(self):
        nonce = secrets.randbits(64)
        self.recent[nonce] = None
        while len(self.recent) > 64:
            self.recent.popitem(last=False)
        data = bytes(self.pending[:IN_MAX]) if self.in_base is not None and not self.peek else b''
        flags = PEEK if self.peek else TAKEOVER if self.takeover and not self.armed_seen else 0
        out_ack = self.out_have if self.out_have is not None else 0
        self.link.send(encode(nonce, self.session, self.owner, self.in_base or 0, out_ack, data,
                              0, flags))
        self.stats['requests'] += 1

    def exchange(self):
        """One request and whatever answers it; the replies processed, or []."""
        self.request()
        replies = [r for r in self.link.receive(self.wait_s) if r['nonce'] in self.recent]
        if not replies:
            self.stats['unanswered'] += 1
        for reply in replies:
            self.process(reply)
        return replies

    def write(self, start, data):
        if self.sink and data:
            self.sink(data)
        if self.segments and self.segments[-1][1] == start:
            self.segments[-1][1] = start + len(data)
        elif data:
            self.segments.append([start, start + len(data)])
        self.stats['out_bytes'] += len(data)

    def process(self, reply):
        self.stats['replies'] += 1
        self.last = reply
        status = reply['status']
        if status == NOT_ARMED:
            if self.armed_seen:
                self.ended = True
            return
        if status != OK:
            self.error = reply
            return
        self.armed_seen = True
        if self.in_base is None:
            self.in_base = reply['in_held']
        acked = reply['in_held'] - self.in_base
        if acked > 0:
            take = min(acked, len(self.pending))
            del self.pending[:take]
            self.in_base = reply['in_held']
            self.stats['in_acked'] += take
        start, data = reply['out_offset'], reply['data']
        if self.out_have is None:
            # The first reply starts where the ring's history starts; --history trims it.
            self.out_have = start
            if self.history is not None:
                self.out_have = max(start, reply['produced'] - self.history)
        if start > self.out_have:
            self.stats['gaps'] += 1
            self.stats['gap_bytes'] += start - self.out_have
            self.out_have = start
        if start + len(data) <= self.out_have:
            if data:
                self.stats['stale'] += 1
            return
        fresh = data[self.out_have - start:]
        self.write(self.out_have, fresh)
        self.out_have += len(fresh)

    def behind(self):
        """More output is waiting, or input is not yet held."""
        last = self.last
        return bool(self.pending) or bool(last and last['status'] == OK and
                                          last['produced'] > (self.out_have or 0))

    def record(self):
        return dict(owner=f'{self.owner:#018x}', session=f'{self.session:#018x}', peek=self.peek,
                    ended=self.ended,
                    error=self.error and {k: v for k, v in self.error.items() if k != 'data'},
                    out_have=self.out_have, in_base=self.in_base, pending=len(self.pending),
                    nmi_dropped=self.guard.dropped, segments=self.segments, **self.stats)


def pump(console, stop, poll_s, give_up_s, keys=None):
    """Exchange until stop() or the call ends. `keys` is a readable fd whose bytes
    are typed. Returns 'ended', 'stopped', 'refused' or 'silent'."""
    last_answer = time.monotonic()
    while True:
        if console.ended:
            return 'ended'
        if console.error:
            return 'refused'
        if stop():
            return 'stopped'
        if console.exchange():
            last_answer = time.monotonic()
        elif time.monotonic() - last_answer > give_up_s:
            return 'silent'
        if console.behind():
            continue
        if keys is None:
            time.sleep(poll_s)
            continue
        ready, _, _ = select.select([keys], [], [], poll_s)
        if ready:
            data = os.read(keys, 4096)
            if not data or QUIT in data:
                if data:
                    console.type(data[:data.index(QUIT)])
                    while console.pending and console.exchange():
                        pass
                return 'stopped'
            console.type(data)


def session_of(args):
    expect = int(args.session, 16) if args.session else None
    if args.launch_record:
        with open(args.launch_record) as handle:
            record = json.load(handle)
        if not record.get('console'):
            raise ValueError('that launch did not enable the console (SNAP_EARLY_STOP=console)')
        bound = int(record['session'], 16)
        if expect is not None and expect != bound:
            raise ValueError('--session differs from the launch record')
        expect = bound
    if expect is None:
        raise ValueError('give --launch-record (or --session HEX)')
    return expect


def run_command(console, command, timeout_s, poll_s, keep_noise):
    """One line to the console's shell between markers; (status, text) or None."""
    tag = secrets.token_hex(4)
    begin, end = f'__SNAP_B_{tag}__'.encode(), f'__SNAP_E_{tag}_'.encode()
    seen = bytearray()
    console.sink = seen.extend
    console.history = 0
    deadline = time.monotonic() + timeout_s
    while console.out_have is None and time.monotonic() < deadline and not console.error:
        console.exchange()
    if console.out_have is None:
        return None
    # The echoed line holds "$S" where the output holds the marker itself.
    console.type((f"S=__SNAP; printf '\\n%s_B_{tag}__\\n' \"$S\"; {command}; "
                  f"printf '%s_E_{tag}_%d__\\n' \"$S\" $?\r").encode())
    while time.monotonic() < deadline and not console.error and not console.ended:
        console.exchange()
        at = seen.find(begin)
        stop = seen.find(end, at + 1) if at >= 0 else -1
        if stop >= 0 and seen.find(b'__', stop + len(end)) >= 0:
            closing = seen.find(b'__', stop + len(end))
            status = int(seen[stop + len(end):closing] or b'-1')
            text = bytes(seen[seen.index(b'\n', at) + 1:stop]).replace(b'\r', b'')
            if not keep_noise:
                text = b''.join(line for line in text.splitlines(keepends=True)
                                if not line.startswith(LAUNCHD))
            return status, text
        if not console.behind():
            time.sleep(poll_s)
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    where = ap.add_mutually_exclusive_group(required=True)
    where.add_argument('--device', help='udp://INTERFACE, the NCM link to the A16')
    where.add_argument('--target', help='HOST:PORT of an offline stand-in (tools/test-console-link.py)')
    ap.add_argument('--launch-record', help="the launch's build/PREFIX-early-stop-launch.json")
    ap.add_argument('--session', help='hex session; must match the launch record if both are given')
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument('--stream', action='store_true', help='watch only; never type')
    mode.add_argument('--run', metavar='COMMAND', help='one command line to the console shell')
    mode.add_argument('--query', action='store_true', help='one exchange, printed as JSON')
    mode.add_argument('--input-file', help='type this file, then keep reading (scripted runs)')
    ap.add_argument('--output-file', help='write the console bytes here (raw) instead of stdout')
    ap.add_argument('--record', help='write a JSON summary of the session here')
    ap.add_argument('--transcript', help='also append every console byte here (raw)')
    ap.add_argument('--history', type=int, help='start at most this many bytes back (default: all the ring holds)')
    ap.add_argument('--quiet-launchd', action='store_true', help="hide launchd's console lines on screen")
    ap.add_argument('--keep-noise', action='store_true', help="--run: keep launchd's lines")
    ap.add_argument('--takeover', action='store_true', help='replace another console owner of this run')
    ap.add_argument('--owner', help='hex owner nonce (default: random)')
    ap.add_argument('--poll-ms', type=int, default=50, help='request pacing when idle (default 50)')
    ap.add_argument('--wait-ms', type=int, default=150, help='how long one request waits (default 150)')
    ap.add_argument('--timeout', type=float, default=60.0, help='--run: seconds; others: give up after this long unanswered')
    ap.add_argument('--duration', type=float, help='stop after this many seconds')
    args = ap.parse_args(argv)
    try:
        session = session_of(args)
        link = Link(device=args.device, target=args.target)
        owner = int(args.owner, 16) if args.owner else None
        if owner == 0:
            raise ValueError('--owner must be nonzero')
    except (OSError, ValueError, KeyError) as error:
        print(json.dumps(dict(result='ARGUMENTS', error=str(error))), file=sys.stderr)
        return 1
    poll_s, wait_s = args.poll_ms / 1000, args.wait_ms / 1000
    out = open(args.output_file, 'wb') if args.output_file else None
    transcript = open(args.transcript, 'ab') if args.transcript else None
    screen = LineFilter(LAUNCHD, args.quiet_launchd and out is None)

    def sink(data):
        if transcript:
            transcript.write(data)
        if out:
            out.write(data)
        else:
            sys.stdout.buffer.write(screen.feed(data))
            sys.stdout.buffer.flush()

    watch = args.stream or args.query
    console = Console(link, session, owner, args.takeover and not watch, wait_s, args.history,
                      None if args.query else sink, peek=watch)
    started = time.monotonic()
    timed_out = (lambda: args.duration is not None and time.monotonic() - started > args.duration)
    status = 0
    try:
        if args.query:
            replies = []
            for _ in range(4):
                replies = console.exchange()
                if replies:
                    break
            if not replies:
                print(json.dumps(dict(result='NO_ANSWER', why='no console reply: the link is down, '
                                      'or the stage predates the console protocol')))
                return 3
            last = dict(replies[-1])
            last['data_bytes'] = len(last.pop('data'))
            print(json.dumps(dict(result=('OK' if last['status'] == OK else 'REFUSED'), reply=last)))
            return 0 if last['status'] in (OK, NOT_ARMED) else 2
        if args.run:
            result = run_command(console, args.run, args.timeout, poll_s, args.keep_noise)
            if result is None:
                why = console.error['status_text'] if console.error else 'no end marker before --timeout'
                print(json.dumps(dict(result='TIMEOUT' if not console.error else 'REFUSED', why=why)),
                      file=sys.stderr)
                return 2 if console.error else 4
            code, text = result
            sys.stdout.buffer.write(text)
            sys.stdout.buffer.flush()
            print(f'guest-console: exit status {code}', file=sys.stderr)
            return 0 if code == 0 else 5
        if args.input_file:
            with open(args.input_file, 'rb') as handle:
                console.type(handle.read())
        keys, saved = None, None
        if not (args.stream or args.input_file) and sys.stdin.isatty():
            keys = sys.stdin.fileno()
            saved = termios.tcgetattr(keys)
            tty.setraw(keys)
            print('guest-console: Ctrl-] quits\r', file=sys.stderr)
        try:
            outcome = pump(console, timed_out, poll_s, args.timeout, keys)
        finally:
            if keys is not None and saved is not None:
                termios.tcsetattr(keys, termios.TCSADRAIN, saved)
        if outcome == 'refused':
            status = 2
        elif outcome == 'silent':
            status = 3 if not console.armed_seen else 0
        reason = {'ended': 'the call ended', 'stopped': 'stopped', 'silent': 'no answer',
                  'refused': console.error and console.error['status_text']}[outcome]
        print(f'\r\nguest-console: {reason}', file=sys.stderr)
        return status
    finally:
        if args.record:
            with open(args.record, 'w') as handle:
                json.dump(console.record(), handle, indent=2)
        for handle in (out, transcript):
            if handle:
                handle.close()
        link.close()


if __name__ == '__main__':
    sys.exit(main())
