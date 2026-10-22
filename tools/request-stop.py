#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Ask a running Snapintosh boot to stop early, from the Mac, while P_CALL runs.

The launcher is blocked in q1n1's P_CALL for the whole run and q1n1 is not
servicing its proxy then. A launch with SNAP_EARLY_STOP=host makes the monitor
poll q1n1's call service from CPU0's timer tick; q1n1 answers UDP port 4920 on
the proxy's own link-local addresses (q1n1 platform/uefi/call-service.h). This
sends QUERY (learn the armed session), then STOP for that session, and waits
for q1n1's acknowledgement. The monitor then ends the run through the
watchdog's own stop (compat/early-stop.h): every CPU quiesces, RAM is kept,
and the launcher's P_CALL returns with exit 12 and this reason recorded.

    python3 tools/request-stop.py --device udp://en5 --reason "WindowServer is up"
    python3 tools/request-stop.py --device udp://en5 --query
    python3 tools/request-stop.py --device udp://en5 --reason TEXT \\
        --launch-record build/PREFIX-early-stop-launch.json

--launch-record refuses to stop anything but that launch's session. Without it
the armed session is whatever run is current. The acknowledgement proves q1n1
latched the request; the launcher's return is what proves the run stopped.
Exit status: 0 latched (by this request or an earlier one), 2 refused or not
armed, 3 no answer, 1 bad arguments. Prints one JSON object.
"""
import argparse
import json
import os
import secrets
import socket
import struct
import sys
import time
import zlib

PORT = 4920
TARGET = 'fe80::4919'                          # q1n1's fixed link-local address
REQUEST = struct.Struct('<IHHQQII64sII')       # 104 bytes
REPLY = struct.Struct('<IHHQQiIQQQII')         # 64 bytes
REQUEST_MAGIC, REPLY_MAGIC, VERSION = 0x52533151, 0x41533151, 1
QUERY, STOP = 1, 2
REASON_OPERATOR = 1
DELAY_LIMIT = 3600
STATUS = {0: 'ok', 1: 'already latched by an earlier request', -1: 'malformed', -2: 'not armed',
          -3: 'wrong session', -4: 'bad reason', -5: 'bad delay'}
FLAG_ARMED, FLAG_LATCHED, FLAG_MINE = 1, 2, 4


def text_field(text):
    """UTF-8, at most 63 bytes (byte 63 stays NUL), cut on a character boundary."""
    raw = text.encode('utf-8')
    while len(raw) > 63:
        text = text[:-1]
        raw = text.encode('utf-8')
    return raw


def encode(op, nonce, session=0, reason=0, delay=0, text=''):
    if op not in (QUERY, STOP) or not 0 <= delay <= 0xffffffff or not 0 <= reason <= 0xffffffff:
        raise ValueError('bad request fields')
    body = REQUEST.pack(REQUEST_MAGIC, VERSION, op, nonce, session, reason, delay,
                        text_field(text), 0, 0)
    return body[:96] + struct.pack('<II', zlib.crc32(body[:96]), 0)


def decode(data):
    if len(data) != REPLY.size:
        raise ValueError(f'reply is {len(data)} bytes, not {REPLY.size}')
    (magic, version, op, nonce, session, status, flags, latch, polls, dropped,
     crc, zero) = REPLY.unpack(data)
    if magic != REPLY_MAGIC or version != VERSION or zero or crc != zlib.crc32(data[:56]):
        raise ValueError('not a q1n1 stop reply (magic, version or CRC)')
    return dict(op=op, nonce=nonce, session=session, status=status,
                status_text=STATUS.get(status, f'status {status}'),
                armed=bool(flags & FLAG_ARMED), latched=bool(flags & FLAG_LATCHED),
                mine=bool(flags & FLAG_MINE), latch_nonce=latch, polls=polls,
                dropped_proxy_datagrams=dropped)


def interface_of(device):
    if not device.startswith('udp://') or not device[6:]:
        raise ValueError('--device must be udp://INTERFACE (for example udp://en5)')
    return device[6:]


class Link:
    def __init__(self, interface, address=None):
        address = address or TARGET
        self.scope = socket.if_nametoindex(interface)
        # A link-local target needs the interface as its scope; nothing else does.
        self.peer = (address, PORT, 0, self.scope if address.lower().startswith('fe80:') else 0)
        self.socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.socket.bind(('::', 0))
        self.socket.settimeout(0.2)

    def close(self):
        self.socket.close()

    def exchange(self, request, nonce, timeout, tries):
        """Send until a reply with our nonce arrives from q1n1's stop port."""
        for _ in range(tries):
            self.socket.sendto(request, self.peer)
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    data, peer = self.socket.recvfrom(256)
                except (socket.timeout, ConnectionRefusedError):
                    continue
                if peer[1] != PORT or peer[3] not in (0, self.scope):
                    continue
                try:
                    reply = decode(data)
                except ValueError:
                    continue
                if reply['nonce'] == nonce:
                    return reply
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--device', required=True, help='udp://INTERFACE, the NCM link to the A16')
    what = ap.add_mutually_exclusive_group(required=True)
    what.add_argument('--reason', help='why, recorded with the stop (UTF-8, up to 63 bytes)')
    what.add_argument('--query', action='store_true', help='only report whether a run is armed')
    ap.add_argument('--delay', type=int, default=0, help='seconds before the stop (monitor clamps)')
    ap.add_argument('--session', help='hex session to stop; refuses any other')
    ap.add_argument('--launch-record', help="the launch's build/PREFIX-early-stop-launch.json")
    ap.add_argument('--timeout', type=float, default=1.5, help='seconds per attempt')
    ap.add_argument('--tries', type=int, default=4)
    args = ap.parse_args(argv)
    try:
        interface = interface_of(args.device)
        if not 0 <= args.delay <= DELAY_LIMIT:
            raise ValueError(f'--delay must be within [0, {DELAY_LIMIT}]')
        expect = int(args.session, 16) if args.session else None
        if args.launch_record:
            with open(args.launch_record) as handle:
                record = json.load(handle)
            if not record.get('host'):
                raise ValueError('that launch did not enable the host trigger')
            bound = int(record['session'], 16)
            if expect is not None and expect != bound:
                raise ValueError('--session differs from the launch record')
            expect = bound
        link = Link(interface)
    except (OSError, ValueError, KeyError) as error:
        print(json.dumps(dict(result='ARGUMENTS', error=str(error))))
        return 1
    try:
        nonce = secrets.randbits(64)
        query = link.exchange(encode(QUERY, nonce), nonce, args.timeout, args.tries)
        if query is None:
            print(json.dumps(dict(result='NO_ANSWER', device=args.device,
                                  why='no q1n1 answered on the stop port; the link is down or '
                                      'this q1n1 stage predates the call service')))
            return 3
        if args.query or not query['armed']:
            result = 'ARMED' if query['armed'] else 'NOT_ARMED'
            print(json.dumps(dict(result=result, query=query, why=None if query['armed'] else
                                  'no run is polling: none is active, or it was launched without '
                                  'SNAP_EARLY_STOP=host')))
            return 0 if args.query else 2
        session = query['session']
        if expect is not None and session != expect:
            print(json.dumps(dict(result='SESSION_MISMATCH', armed_session=f'{session:#018x}',
                                  expected=f'{expect:#018x}')))
            return 2
        nonce = secrets.randbits(64)
        reply = link.exchange(encode(STOP, nonce, session, REASON_OPERATOR, args.delay, args.reason),
                              nonce, args.timeout, args.tries)
        if reply is None:
            print(json.dumps(dict(result='NO_ANSWER', session=f'{session:#018x}',
                                  why='QUERY was answered but STOP was not')))
            return 3
        # Whose latch it is comes from its nonce, not the status: when the first
        # acknowledgement is lost, the retransmission reads "already latched"
        # or, once the monitor has taken the latch and disarmed, "not armed".
        ours = reply['latched'] and reply['latch_nonce'] == nonce
        latched = ours or (reply['status'] in (0, 1) and reply['latched'])
        print(json.dumps(dict(result='LATCHED' if latched else 'REFUSED', session=f'{session:#018x}',
                              reason=args.reason, delay_s=args.delay, first=ours,
                              evidence='REQUEST_ONLY', guest_stop_verified=False, gpu_quiesce_verified=False,
                              next_evidence='Matching launcher terminal capture, then separate GPU quiesce receipt',
                              reply=reply, sent_at=time.time(), pid=os.getpid())))
        return 0 if latched else 2
    finally:
        link.close()


if __name__ == '__main__':
    sys.exit(main())
