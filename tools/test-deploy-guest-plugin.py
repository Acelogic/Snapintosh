#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""tools/deploy-guest-plugin.py end to end and offline, over the real console protocol.

The stand-in is tools/test-console-link.c (q1n1's real console handler, the monitor's real console link and
DockChannel receive model) with a real /bin/sh on a pty standing in for the single-user shell on /dev/console,
and 3% request and reply loss. The guest's paths live under a temporary --guest-root holding the installed
bundle files (each deploy-guest-plugin.FILES base: executable, compiler runtime, CodeResources). The checks:
  install    INSTALLED: every file is the new one (SHA-256, and CDHash for the Mach-Os), owner and mode are kept, each
             backup is its base, every chunk was acknowledged, and runtime chunk 42, withheld on purpose in the first
             round (as one acknowledged chunk once went missing here), was found by the listing and resent
  again      a second run finds them installed and writes nothing
  restore    RESTORED: every backup is put back, byte for byte
  refuse     one installed file that is neither base nor new is refused before any write (no work directory,
             no backup, every file unchanged)

    python3 tools/test-deploy-guest-plugin.py --output NEW-DIR
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / 'tools/deploy-guest-plugin.py'
spec = importlib.util.spec_from_file_location('consolelink', ROOT / 'tools/test-console-link.py')
assert spec and spec.loader
CL = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CL)
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
checks, failures = 0, []


def check(name, condition, detail=None):
    global checks
    checks += 1
    if not condition:
        failures.append(f'{name}: {detail}')
        print(f'FAIL {name}: {str(detail)[:400]}')


def deploy(port, record, guest, *extra):
    run = subprocess.run([sys.executable, str(DEPLOY), '--target', f'127.0.0.1:{port}', '--session', f'{CL.SESSION:x}',
                          '--record', str(record), '--guest-root', str(guest), '--no-mount', '--poll-ms', '20',
                          '--wait-ms', '60', '--attempts', '5', *extra],
                         capture_output=True, timeout=600, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
    data = json.loads(record.read_text()) if record.exists() else {}
    return run.returncode, data


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location('deploy', DEPLOY)
    assert spec and spec.loader
    D = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(D)
    binary = CL.build(out)
    guest = out / 'guest'
    for f in D.FILES:
        target = guest / f['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f['base'], target)
        os.chmod(target, 0o755 if f['cdhash'] else 0o644)
    plugin = guest / D.PLUGIN
    base, new = sha(D.BASE), sha(D.NEW)
    h = CL.Harness(binary, out, 'console', '--duration', 900, '--shell', "PS1='sh-3.2# ' exec /bin/sh -i",
                   '--loss', 0.03, '--reply-loss', 0.03, '--seed', 29, '--poll-ms', 20)
    results = {}
    try:
        rc, r = deploy(h.port, out / 'install.json', guest, '--test-skip-chunk', 'libAdrenoCompiler.dylib/c.00042')
        if (guest / D.WORK).exists():                  # evidence: what the stand-in guest assembled
            shutil.copytree(guest / D.WORK, out / 'install-work')
        results['install'] = dict(rc=rc, status=r.get('status'), error=r.get('error'), seconds=r.get('transfer_seconds'),
                                  chunks=r.get('chunks'))
        check('install: status', rc == 0 and r.get('status') == 'INSTALLED', r.get('error'))
        rows = {f['name']: f for f in r.get('files', [])}
        for f in D.FILES:
            target, row = guest / f['path'], rows.get(f['name'], {})
            check(f'install: {f["name"]} is new', sha(target) == sha(f['new']) and row.get('installed_after') == sha(f['new']),
                  sha(target))
            if f['cdhash']:
                check(f'install: {f["name"]} CDHash', row.get('installed_cdhash') == f['cdhash'], row.get('installed_cdhash'))
            want = '0o755' if f['cdhash'] else '0o644'
            check(f'install: {f["name"]} mode kept', oct(os.stat(target).st_mode & 0o7777) == want, oct(os.stat(target).st_mode))
            saved = guest / D.BACKUP / f'{f["name"]}-{sha(f["base"])[:8]}'
            check(f'install: {f["name"]} backup is its base', saved.is_file() and sha(saved) == sha(f['base']), saved)
            check(f'install: {f["name"]} no temporary file left', not Path(str(target) + '.snapintosh-new').exists())
        chunk_steps = [s for s in r.get('steps', []) if s['step'] == 'chunk']
        check('install: every chunk acknowledged', not chunk_steps and r.get('chunks', 0) > 100, r.get('chunks'))
        rounds = (r.get('transfers') or [{}])[0].get('rounds') or []
        check('install: the skipped chunk was found and resent', len(rounds) >= 2 and 'c.00042' in rounds[0]['names'] and
              rounds[-1]['resend'] == 0, rounds)

        rc, r = deploy(h.port, out / 'again.json', guest)
        results['again'] = dict(rc=rc, status=r.get('status'), already=r.get('already_installed'))
        check('again: already installed, nothing typed', rc == 0 and r.get('already_installed') and
              not any(s['step'] in ('work', 'install', 'backup') for s in r.get('steps', [])), r.get('steps'))

        rc, r = deploy(h.port, out / 'restore.json', guest, '--restore')
        results['restore'] = dict(rc=rc, status=r.get('status'))
        check('restore: every base is back', rc == 0 and r.get('status') == 'RESTORED' and
              all(sha(guest / f['path']) == sha(f['base']) for f in D.FILES), r.get('error'))

        shutil.rmtree(guest / D.WORK)
        shutil.rmtree(guest / D.BACKUP)
        plugin.write_bytes(b'not the plug-in')
        before = sha(plugin)
        rc, r = deploy(h.port, out / 'refuse.json', guest)
        results['refuse'] = dict(rc=rc, status=r.get('status'), error=r.get('error'))
        check('refuse: refused', rc == 1 and r.get('status') == 'REFUSED' and 'neither the base' in (r.get('error') or ''),
              r.get('error'))
        check('refuse: nothing written', sha(plugin) == before and not (guest / D.WORK).exists() and
              not (guest / D.BACKUP).exists() and
              all(sha(guest / f['path']) == sha(f['base']) for f in D.FILES[:-1]))
    finally:
        h.process.terminate()
        h.process.wait(timeout=30)
    (out / 'result.json').write_text(json.dumps(dict(checks=checks, failures=failures, cases=results), indent=2))
    if failures:
        print(f'FAIL: {len(failures)} of {checks} checks; {out / "result.json"}')
        return 1
    print(f'PASS: {checks} deploy checks over the console stand-in with 3% loss '
          f'(transfer {results["install"]["seconds"]} s, {results["install"]["chunks"]} chunks); {out / "result.json"}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
