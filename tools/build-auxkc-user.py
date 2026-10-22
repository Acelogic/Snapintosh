#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build an offline AuxKC without an administrator dialog.

Uses sudo with GNU tar only for temporary root-owned kext copies; sudo asks
for your password unless it holds a cached credential. kmutil, bundle
verification and output writes run as the caller. No sudo policy is changed.
Failure inventory: docs/PASSWORDLESS-AUXKC-BUILDS-20260927.md.
"""
from pathlib import Path
import argparse
import hashlib
import io
import json
import os
import plistlib
import re
import subprocess
import sys
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
TAR = '/opt/homebrew/bin/gtar'

def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('kexts', type=Path, nargs='+')
    parser.add_argument('--boot', type=Path, default=ROOT / 'downloads/extracted/j700ap/kernelcache.release.mac17p')
    parser.add_argument('--kdk', type=Path, default=Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk'))
    args = parser.parse_args()
    assert os.geteuid() == os.getuid() != 0, 'run as your normal user; no sudo is needed on this entry point'
    output, boot, kdk = [p.absolute() for p in (args.output, args.boot, args.kdk)]
    bundles = [p.absolute() for p in args.kexts]
    assert boot.is_file() and kdk.is_dir()
    assert not output.exists() and not output.is_symlink(), 'output must be new'
    assert len({p.name for p in bundles}) == len(bundles), 'duplicate bundle names'
    inputs, identifiers, entries = {}, [], []
    for bundle in bundles:
        assert not bundle.is_symlink() and bundle.is_dir() and bundle.suffix == '.kext', bundle
        identifier = plistlib.loads((bundle / 'Contents/Info.plist').read_bytes())['CFBundleIdentifier']
        assert re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', identifier), identifier
        identifiers.append(identifier)
        for path in [bundle, *sorted(bundle.rglob('*'))]:
            assert not path.is_symlink() and (path.is_dir() or path.is_file()), path
            name = str(Path(bundle.name) / path.relative_to(bundle))
            assert '..' not in Path(name).parts and not Path(name).is_absolute()
            entries.append((path, name))
    assert len(set(identifiers)) == len(identifiers), 'duplicate bundle identifiers'
    output.parent.mkdir(parents=True, exist_ok=True)
    logs = output.with_name(output.name + '.build-logs')
    logs.mkdir(exist_ok=False)
    report = output.with_name(output.name + '.build.json')
    assert not report.exists()
    job = Path(tempfile.mkdtemp(prefix='snapintosh-auxkc-user-', dir='/private/var/tmp'))
    stage, archive = job / 'stage', job / 'inputs.tar'
    stage.mkdir()
    verifier = ROOT / 'tools/auxkc-bundles.py'
    record = dict(status='RUNNING', started=time.time(), caller_uid=os.getuid(),
        kmutil_uid=os.geteuid(), source_sha256=sha(__file__), output=str(output),
        boot=str(boot), boot_sha256=sha(boot), kdk=str(kdk),
        bundle_identifiers=identifiers, authorization='sudo GNU tar (prompts unless credentials are cached)',
        policy_changed=False, administrator_dialog=False, hardware_access=False,
        inputs_sha256={str(verifier): sha(verifier)}, commands=[], staging_directory=str(stage))
    error = None
    def run(name, command):
        record['commands'].append(command)
        with (logs / (name + '.log')).open('x') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
        assert result.returncode == 0, (name, result.returncode, str(logs / (name + '.log')))
    try:
        with tarfile.open(archive, 'w') as tar:
            for path, name in entries:
                info = tarfile.TarInfo(name)
                info.uid = info.gid = 0
                info.uname, info.gname = 'root', 'wheel'
                if path.is_dir():
                    info.type, info.mode = tarfile.DIRTYPE, 0o755
                    tar.addfile(info)
                else:
                    content = path.read_bytes()
                    inputs[str(path)] = hashlib.sha256(content).hexdigest()
                    info.size = len(content)
                    info.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
                    tar.addfile(info, io.BytesIO(content))
        record['inputs_sha256'].update(inputs)
        run('stage', ['/usr/bin/sudo', TAR, '--extract', '--file', str(archive),
            '--directory', str(stage), '--same-owner'])
        ownership = {}
        for path, name in entries:
            staged = stage / name
            stat = staged.stat()
            ownership[name] = [stat.st_uid, stat.st_gid]
            assert ownership[name] == [0, 0], name
            if path.is_file():
                assert sha(staged) == inputs[str(path)], name
        record['staged_ownership'] = ownership
        command = ['/usr/bin/kmutil', 'create', '-z', '-x', '-n', 'aux', '-a', 'arm64e',
            '-V', 'release', '-B', str(boot), '-A', str(output), '-r', str(stage)]
        for identifier in identifiers:
            command += ['-b', identifier]
        command += ['-M', '--kdk', str(kdk)]
        run('kmutil', command)
        run('bundles', [sys.executable, '-B', str(verifier), str(output), *map(str, bundles)])
        assert b'Validating extension failed' not in output.read_bytes()
        assert output.stat().st_uid == os.getuid()
        for path, digest in record['inputs_sha256'].items():
            assert sha(path) == digest, path
        assert sha(boot) == record['boot_sha256']
        record.update(status='PASSWORDLESS_AUXKC_BUILT', collection_sha256=sha(output),
                      collection_owner=output.stat().st_uid)
    except BaseException as failure:
        error = failure
        record.update(status='FAIL', error=repr(failure))
    finally:
        command = ['/usr/bin/sudo', TAR, '--create', '--file', '/dev/null',
            '--remove-files', '--directory', str(job), 'stage']
        record['commands'].append(command)
        cleaned = subprocess.run(command, capture_output=True, text=True)
        record['cleanup'] = dict(exit_code=cleaned.returncode,
            output=cleaned.stdout + cleaned.stderr, stage_removed=not stage.exists())
        if cleaned.returncode or stage.exists():
            record['status'] = 'FAIL'
            error = error or RuntimeError('root-owned staging cleanup failed; see build record')
        else:
            archive.unlink(missing_ok=True)
            job.rmdir()
        record['finished'] = time.time()
        record['artifacts_sha256'] = {str(p.relative_to(output.parent)): sha(p)
            for p in [output, *logs.iterdir()] if p.is_file()}
        report.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(dict(status=record['status'], record=str(report), sha256=sha(report))))
    if error:
        raise SystemExit(str(error))

if __name__ == '__main__':
    main()
