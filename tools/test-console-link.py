#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The two-way console, end to end and offline (docs/GUEST-SHELL-DESIGN-20261016.md).

tools/guest-console.py, the real host tool, talks over localhost UDP to
build/test-console-link (tools/test-console-link.c). That stand-in has q1n1's
real console handler, served only during polls, and the monitor's real console
link and DockChannel receive model. Its guest reads the UART as XNU does, and a
real shell can sit on a pty standing in for /dev/console. Loss, duplication and
reordering are injected there. The checks, by the failure modes in section 8 of
the design:

  stream    P5-P7, P11, M1, M2, M4: a recorded console replayed under loss
            arrives byte for byte, and typed input arrives exactly once.
  lapping   P9: a watcher more than a ring behind gets gaps, and every byte it
            does get is the right byte at the right offset.
  shell     the shipped console-shell job's own command line (its boot-arg
            gate fed a stand-in kern.bootargs) on the stand-in console: a
            command comes back between its markers, with its exit status,
            despite launchd noise; without snapintosh_shell=1 the job exits.
  protocol  P1-P4, P6, P8, P10, P12, M6: crafted datagrams (malformed, wrong
            session, owners, takeover, peek, gaps, clamps, the NMI sequence, the
            stop protocol on the same port, not armed).

Writes build/console-link-loopback-STAMP/result.json: hashes, counters, verdicts.

    python3 tools/test-console-link.py [--console FILE] [--keep]
"""
import argparse
import hashlib
import importlib.util
import json
import os
import plistlib
import shlex
import socket
import struct
import subprocess
import sys
import tempfile
import time
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
Q1N1 = ROOT.parent / 'q1n1'
TOOL = ROOT / 'tools' / 'guest-console.py'
PLIST = ROOT / 'config/guest/org.snapintosh.console-shell.plist'
BOOTARGS = '/usr/sbin/sysctl -n kern.bootargs'
SESSION = 0x5eed5eed12345678


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


gc = module('guest_console', TOOL)
rs = module('request_stop', ROOT / 'tools' / 'request-stop.py')
checks = []


def check(name, condition, detail=None):
    checks.append(dict(name=name, passed=bool(condition), detail=detail))
    if not condition:
        print(f'FAIL {name}: {detail}')
    return bool(condition)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def recorded_console():
    """The last installed run's console, from the main checkout (a worktree has no build/)."""
    try:
        common = subprocess.run(['git', 'rev-parse', '--path-format=absolute', '--git-common-dir'],
                                cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    for base in (ROOT, Path(common).parent):
        path = base / 'build/installed-fresh-20261016-v4/console.txt'
        if path.is_file():
            return path
    return None


def build(out):
    binary = out / 'test-console-link'
    subprocess.run(['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                    '-fno-sanitize-recover=all', '-Wall', '-Wextra', '-Werror',
                    f'-I{Q1N1 / "platform/uefi"}', str(ROOT / 'tools/test-console-link.c'),
                    str(ROOT / 'shadow/dockchannel.c'), str(Q1N1 / 'platform/uefi/call-service.c'),
                    '-o', str(binary)], check=True)
    return binary


class Harness:
    def __init__(self, binary, out, name, *extra):
        self.dir = out / name
        self.dir.mkdir()
        self.args = [str(binary), '--session', f'{SESSION:x}', '--port', '0',
                     '--produced', str(self.dir / 'produced.bin'),
                     '--delivered', str(self.dir / 'delivered.bin'),
                     '--result', str(self.dir / 'harness.json'), *map(str, extra)]
        self.process = subprocess.Popen(self.args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True)
        line = self.process.stdout.readline().split()
        if line[:1] != ['port']:
            raise RuntimeError(f'{name}: harness did not start: {self.process.stderr.read()}')
        self.port = int(line[1])

    def tool(self, *args, timeout=60):
        return subprocess.run([sys.executable, str(TOOL), '--target', f'127.0.0.1:{self.port}',
                               '--session', f'{SESSION:x}', *map(str, args)],
                              capture_output=True, timeout=timeout,
                              env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))

    def finish(self):
        _, err = self.process.communicate(timeout=120)
        if self.process.returncode:
            raise RuntimeError(f'harness exited {self.process.returncode}: {err}')
        self.result = json.loads((self.dir / 'harness.json').read_text())
        self.produced = (self.dir / 'produced.bin').read_bytes()
        self.delivered = (self.dir / 'delivered.bin').read_bytes()
        return self.result


def stream(binary, out, console):
    h = Harness(binary, out, 'stream', '--duration', 9, '--quiet', 3, '--noise', console,
                '--noise-rate', 600, '--loss', 0.1, '--reply-loss', 0.1, '--dup', 0.05,
                '--reorder', 0.05, '--seed', 7)
    typed = gc.NmiGuard().filter(os.urandom(6000))
    (h.dir / 'typed.bin').write_bytes(typed)
    run = h.tool('--input-file', h.dir / 'typed.bin', '--output-file', h.dir / 'out.bin',
                 '--record', h.dir / 'record.json', '--poll-ms', 20, '--wait-ms', 60)
    r = h.finish()
    got = (h.dir / 'out.bin').read_bytes()
    record = json.loads((h.dir / 'record.json').read_text())
    check('stream: tool ended with the call', run.returncode == 0 and record['ended'], run.stderr[-300:])
    check('stream: losses were injected', r['dropped_requests'] and r['dropped_replies'] and
          r['duplicated'] and r['reordered'], r)
    check('stream: console arrives byte for byte', got == h.produced,
          dict(got=len(got), produced=len(h.produced), gaps=record['gaps']))
    check('stream: typed input arrives exactly once', h.delivered == typed,
          dict(delivered=len(h.delivered), typed=len(typed), in_held=r['view']['in_held']))
    check('stream: q1n1 holds exactly what was typed', r['view']['in_held'] == len(typed), r['view'])
    check('stream: nothing refused by the receive ring', r['link']['rx_refused'] == 0 and
          r['link']['rx_waiting'] == 0, r['link'])
    check('stream: no NMI entry', r['nmi_entries'] == 0, r)
    return dict(harness=r, record={k: v for k, v in record.items() if k != 'segments'},
                produced_sha256=sha(h.produced), out_sha256=sha(got), typed_sha256=sha(typed),
                delivered_sha256=sha(h.delivered))


def lapping(binary, out, console):
    h = Harness(binary, out, 'lapping', '--duration', 4, '--noise', console, '--noise-rate', 6000,
                '--seed', 11)
    run = h.tool('--stream', '--output-file', h.dir / 'out.bin', '--record', h.dir / 'record.json',
                 '--poll-ms', 20, '--wait-ms', 60)
    r = h.finish()
    got = (h.dir / 'out.bin').read_bytes()
    record = json.loads((h.dir / 'record.json').read_text())
    at, right = 0, True
    for start, end in record['segments']:
        right &= got[at:at + end - start] == h.produced[start:end]
        at += end - start
    check('lapping: watcher ended with the call', run.returncode == 0 and record['ended'], run.stderr[-300:])
    check('lapping: the ring lapped the watcher', record['gaps'] > 0 and r['view']['out_gaps'] > 0,
          dict(gaps=record['gaps'], out_gaps=r['view']['out_gaps']))
    check('lapping: every byte is the right byte at its offset', right and at == len(got),
          dict(segments=len(record['segments']), bytes=len(got)))
    check('lapping: a watcher never takes the owner', record['peek'] and r['view']['owner_changes'] == 0, record)
    return dict(harness=r, record={k: v for k, v in record.items() if k != 'segments'},
                segments=len(record['segments']))


def shell(binary, out, console):
    home = Path(tempfile.mkdtemp(prefix='console-shell-', dir=out))
    noise = out / 'launchd-noise.txt'
    noise.write_bytes(b''.join(line for line in Path(console).read_bytes().splitlines(keepends=True)
                               if line.startswith(gc.LAUNCHD)))
    job = plistlib.loads(PLIST.read_bytes())
    gated = job['ProgramArguments'][2]
    check('shell: the job gates on kern.bootargs', job['ProgramArguments'][:2] == ['/bin/sh', '-c'] and
          BOOTARGS in gated and job['StandardInPath'] == job['StandardOutPath'] == '/dev/console', job)
    closed = subprocess.run(['/bin/sh', '-c', gated.replace(BOOTARGS, "echo 'serial=3 -v'")],
                            stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
    check('shell: without snapintosh_shell=1 the job exits at once', closed.returncode == 0 and
          not closed.stdout, closed)
    opened = gated.replace(BOOTARGS, "echo 'serial=3 snapintosh_shell=1 -v'")
    env = ' '.join(f'{k}={shlex.quote(v)}' for k, v in dict(job['EnvironmentVariables'],
                                                             HOME=str(home), ZDOTDIR=str(home)).items())
    command = f'{env} exec /bin/sh -c {shlex.quote(opened)}'
    h = Harness(binary, out, 'shell', '--duration', 25, '--noise', noise, '--noise-rate', 60,
                '--noise-lines', '--shell', command, '--loss', 0.05, '--reply-loss', 0.05,
                '--seed', 13)
    owner = '1234abcd'
    first = h.tool('--run', 'echo hello-$((6*7)); uname -s', '--owner', owner, '--timeout', 15,
                   '--poll-ms', 20, '--wait-ms', 60)
    second = h.tool('--run', 'sh -c "exit 3"', '--owner', owner, '--timeout', 15, '--poll-ms', 20,
                    '--wait-ms', 60)
    other = h.tool('--run', 'true', '--timeout', 5, '--poll-ms', 20, '--wait-ms', 60)
    r = h.finish()
    check('shell: command output between the markers', first.returncode == 0 and
          first.stdout == b'hello-42\nDarwin\n', dict(rc=first.returncode, out=first.stdout[-200:],
                                                     err=first.stderr[-300:]))
    check('shell: a failing command reports its status', second.returncode == 5 and
          b'exit status 3' in second.stderr, dict(rc=second.returncode, err=second.stderr[-300:]))
    check('shell: another owner is refused', other.returncode == 2, dict(rc=other.returncode,
                                                                         err=other.stderr[-300:]))
    check('shell: launchd noise was interleaved', r['noise_bytes'] > 0 and r['shell_bytes'] > 0, r)
    check('shell: no NMI entry', r['nmi_entries'] == 0, r)
    (h.dir / 'first.stdout').write_bytes(first.stdout)
    return dict(harness=r, first=dict(rc=first.returncode, stdout=first.stdout.decode('utf-8', 'replace')),
                second=dict(rc=second.returncode), other=dict(rc=other.returncode))


def protocol(binary, out):
    h = Harness(binary, out, 'protocol', '--duration', 6, '--linger', 1.5,
                '--noise', ROOT / 'tools/test-console-link.c', '--noise-rate', 64)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.3)
    peer = ('127.0.0.1', h.port)

    def ask(datagram, tries=3):
        for _ in range(tries):
            sock.sendto(datagram, peer)
            try:
                data, _ = sock.recvfrom(2048)
            except socket.timeout:
                continue
            return data
        return None

    def console(owner, in_offset=0, data=b'', out_ack=0, out_max=0, flags=0, session=SESSION):
        reply = ask(gc.encode(int.from_bytes(os.urandom(8), 'little'), session, owner, in_offset,
                              out_ack, data, out_max, flags))
        return gc.decode(reply) if reply else None

    time.sleep(0.3)
    A, B, C = 0xa, 0xb, 0xc
    check('P1: foreign bytes on the port get no reply', ask(b'XXXX' + bytes(60), tries=1) is None)
    bad = bytearray(gc.encode(1, SESSION, A, 0, 0, b'abc'))
    bad[-1] ^= 0xff
    reply = ask(bytes(bad))
    check('P1: a bad CRC is malformed', reply and gc.decode(reply)['status'] == gc.MALFORMED, reply)
    check('P2: a wrong session is refused', console(A, session=SESSION ^ 1)['status'] == gc.SESSION)
    first = console(A, 0, b'abc')
    check('P4: the first owner binds and types', first['status'] == gc.OK and first['owner'] and
          first['in_held'] == 3, first)
    check('P4: a second owner is refused', console(B)['status'] == gc.OWNER)
    peek = console(C, flags=gc.PEEK)
    check('P4: a watcher reads without the owner', peek['status'] == gc.OK and not peek['owner'], peek)
    check('P1: a watcher cannot type', console(C, 0, b'x', flags=gc.PEEK)['status'] == gc.MALFORMED)
    check('P5: an overlap appends only the new suffix', console(A, 0, b'abcdef')['in_held'] == 6)
    check('P6: input after a gap appends nothing', console(A, 10, b'x')['in_held'] == 6)
    check('P5: a duplicate appends nothing', console(A, 3, b'def')['in_held'] == 6)
    beyond = console(A, out_ack=1 << 62)
    check('P8: an ack beyond produced is clamped', beyond['out_offset'] == beyond['produced'] and
          not beyond['data'], beyond)
    small = console(A, out_max=10)
    check('P10: out_max is respected', len(small['data']) <= 10 and small['data'], small)
    taken = console(B, flags=gc.TAKEOVER)
    check('P4: takeover rebinds the owner', taken['status'] == gc.OK and taken['owner'], taken)
    check('P4: the old owner is refused after a takeover', console(A)['status'] == gc.OWNER)
    held = taken['in_held']
    nmi = console(B, held, gc.NMI + b'Z')
    check('M6: the NMI sequence is accepted on the wire', nmi['in_held'] == held + len(gc.NMI) + 1, nmi)
    nonce = 0x1111
    stop = ask(rs.encode(rs.QUERY, nonce))
    check('P12: the stop protocol still answers on the same port',
          stop and rs.decode(stop)['armed'] and rs.decode(stop)['nonce'] == nonce, stop)
    time.sleep(6.3)
    after = console(B)
    check('P2: after the call, not armed', after and after['status'] == gc.NOT_ARMED, after)
    r = h.finish()
    expect = b'abc' + b'def' + gc.NMI[:-1] + b'Z'
    check('M6: the guest never receives the whole NMI sequence', h.delivered == expect and
          r['link']['nmi_dropped'] == 1 and r['nmi_entries'] == 0,
          dict(delivered=h.delivered, nmi_dropped=r['link']['nmi_dropped']))
    check('protocol: counters agree', r['view']['owner_changes'] == 1 and r['view']['in_gaps'] >= 1 and
          r['view']['in_duplicate'] >= 2, r['view'])
    guard = gc.NmiGuard()
    check('host: the tool never sends the NMI sequence', guard.filter(gc.NMI) == gc.NMI[:-1] and
          guard.dropped == 1)
    return dict(harness=r)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--console', help='console bytes to replay (default: the v4 installed run)')
    ap.add_argument('--keep', action='store_true', help='keep the stream files')
    args = ap.parse_args()
    console = Path(args.console) if args.console else recorded_console()
    if not console or not console.is_file():
        print('no recorded console: pass --console FILE')
        return 1
    stamp = time.strftime('%Y%m%d-%H%M%S')
    out = ROOT / 'build' / f'console-link-loopback-{stamp}'
    out.mkdir(parents=True)
    binary = build(out)
    results = dict(console=str(console), console_sha256=sha(console.read_bytes()),
                   harness_sha256=sha(binary.read_bytes()),
                   sources_sha256={str(p.relative_to(ROOT.parent)): sha(p.read_bytes()) for p in (
                       ROOT / 'tools/test-console-link.c', ROOT / 'tools/test-console-link.py', TOOL,
                       ROOT / 'compat/console-link.h', ROOT / 'shadow/dockchannel.c',
                       ROOT / 'shadow/dockchannel.h', Q1N1 / 'platform/uefi/call-service.c',
                       Q1N1 / 'platform/uefi/call-service.h')})
    for name, run in (('stream', lambda: stream(binary, out, console)),
                      ('lapping', lambda: lapping(binary, out, console)),
                      ('shell', lambda: shell(binary, out, console)),
                      ('protocol', lambda: protocol(binary, out))):
        try:
            results[name] = run()
        except Exception as error:                  # a scenario that cannot run fails, visibly
            check(f'{name}: ran', False, repr(error))
    results['checks'] = checks
    results['passed'] = all(c['passed'] for c in checks)
    if not args.keep:
        for path in out.rglob('*.bin'):
            path.unlink()
    (out / 'result.json').write_text(json.dumps(results, indent=2, default=str))
    passed = sum(c['passed'] for c in checks)
    print(f'{"PASS" if results["passed"] else "FAIL"}: {passed}/{len(checks)} console-link loopback checks; '
          f'{out.relative_to(ROOT)}/result.json')
    return 0 if results['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
