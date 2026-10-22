#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Install the guest's console jobs from its own single-user shell.

    python3 tools/install-guest-jobs.py --device udp://en6 --launch-record build/PREFIX-early-stop-launch.json \\
        --record SCRATCH/jobs.json [--continue-boot]

Writes config/guest/org.snapintosh.console-shell.plist (the root shell, now reopening a revoked
/dev/console) and config/guest/org.snapintosh.diag.plist (input-free diagnostics: the AdrenoMetal
log, loginwindow/WindowServer errors, GUI processes and AdrenoDisplay's counters, every line with
a fresh open of /dev/console) into /Library/LaunchDaemons on the Data volume, root:wheel 0644.
Both stay inert without the boot argument snapintosh_shell=1. Each file is typed as base64 in short
printf commands, decoded, checked by SHA-256 against the host copy and by plutil, then installed with
a rename; the previous console-shell plist is kept as *.previous. The console protocol, mounting and
console owner are tools/deploy-guest-plugin.py's (same owner, so both can run in one single-user
session). --continue-boot types `exit` afterwards.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('deploy', ROOT / 'tools/deploy-guest-plugin.py')
assert spec and spec.loader
D = importlib.util.module_from_spec(spec)
spec.loader.exec_module(D)
JOBS = [ROOT / 'config/guest/org.snapintosh.console-shell.plist', ROOT / 'config/guest/org.snapintosh.diag.plist']
DAEMONS = 'System/Volumes/Data/Library/LaunchDaemons'
WORK = 'System/Volumes/Data/private/var/tmp/snapintosh-jobs'
CHUNK = 512
sha = lambda data: hashlib.sha256(data).hexdigest()


def install(shell, root, path, record, chown=True):
    data = path.read_bytes()
    text = base64.b64encode(data).decode()
    work, target = f'{root}{WORK}', f'{root}{DAEMONS}/{path.name}'
    shell.run('work', f'rm -rf {shlex.quote(work)} && mkdir -p {shlex.quote(work)}')
    b64 = f'{work}/{path.name}.b64'
    for at in range(0, len(text), CHUNK):
        shell.run('chunk', f"printf '%s' '{text[at:at + CHUNK]}' >> {shlex.quote(b64)}", timeout=30)
    if shell.digest('base64', b64) != sha(text.encode()):
        raise D.Refused(f'{path.name}: the typed base64 differs')
    staged = f'{work}/{path.name}'
    shell.run('decode', f'base64 -D -i {shlex.quote(b64)} -o {shlex.quote(staged)}')
    if shell.digest('staged', staged) != sha(data):
        raise D.Refused(f'{path.name}: the decoded file differs')
    shell.run('lint', f'plutil -lint {shlex.quote(staged)}')
    shell.run('install', f'mkdir -p {shlex.quote(root + DAEMONS)} && '
                         f'(test ! -e {shlex.quote(target)} || cp -p {shlex.quote(target)} {shlex.quote(target)}.previous) && '
                         f'cp {shlex.quote(staged)} {shlex.quote(target)}.new && ' +
                         (f'chown 0:0 {shlex.quote(target)}.new && ' if chown else '') +
                         f'chmod 644 {shlex.quote(target)}.new && mv -f {shlex.quote(target)}.new {shlex.quote(target)}')
    if shell.digest('installed', target) != sha(data):
        raise D.Refused(f'{path.name}: the installed file differs')
    mode = shell.run('stat', f"stat -f '%u:%g %Lp' {shlex.quote(target)}").split()[-2:]
    if mode[-1:] != ['644'] or (chown and mode[0] != '0:0'):
        raise D.Refused(f'{path.name}: owner/mode {mode}')
    record['installed'].append(dict(file=path.name, sha256=sha(data), bytes=len(data), path=target))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    where = ap.add_mutually_exclusive_group(required=True)
    where.add_argument('--device')
    where.add_argument('--target', help='host:port of a stand-in (offline)')
    ap.add_argument('--launch-record')
    ap.add_argument('--session')
    ap.add_argument('--record', type=Path, required=True)
    ap.add_argument('--owner', default='5eedc0de51')
    ap.add_argument('--continue-boot', action='store_true')
    ap.add_argument('--attempts', type=int, default=40)
    ap.add_argument('--wait-ms', type=int, default=150)
    ap.add_argument('--poll-ms', type=int, default=50)
    ap.add_argument('--guest-root', default='/', help=argparse.SUPPRESS)
    ap.add_argument('--no-mount', action='store_true', help=argparse.SUPPRESS)
    ap.add_argument('--test-no-chown', action='store_true', help=argparse.SUPPRESS)
    args = ap.parse_args(argv)
    root = args.guest_root.rstrip('/') + '/'
    record = dict(status='RUNNING', started=time.time(), installed=[], tool_sha256=sha(Path(__file__).read_bytes()))
    shell = None
    try:
        shell = D.Shell(args)
        record['shell_attempts'] = D.wait_for_shell(shell, args.attempts, 20)
        record['data'] = D.mount_data(shell, args)
        for path in JOBS:
            install(shell, root, path, record, chown=not args.test_no_chown)
        shell.run('sync', 'sync')
        record['status'] = 'INSTALLED'
        if args.continue_boot:
            shell.type_exit()
            record['continued'] = True
    except D.Refused as error:
        record.update(status='REFUSED', error=str(error))
    finally:
        if shell:
            record['steps'] = shell.steps
        record['finished'] = time.time()
        args.record.write_text(json.dumps(record, indent=1))
    print(json.dumps({k: record[k] for k in ('status', 'installed') if k in record} | {'error': record.get('error')}))
    return 0 if record['status'] == 'INSTALLED' else 2


if __name__ == '__main__':
    sys.exit(main())
