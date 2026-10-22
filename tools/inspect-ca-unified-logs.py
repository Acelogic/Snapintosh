#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Decode saved WindowServer log events from a bounded, local unified archive.

Failure inventory: wrong snapshot, writable mount, symlink traversal, unbounded
archive, missing decoder strings, incomplete decoding, and stale boot events
mistaken for the current guest. Preserve raw files and decoder status. No A16
access and no installed or snapshotted filesystem changes.
"""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / 'tools/inspect-ca-crash-logs.py'
assert hashlib.sha256(base.read_bytes()).hexdigest() == 'ff3b589fda810228210a3e699783f9728e9a058d9f74b4315385f574f4692375'
source = base.read_text()
assert source.count("OUT = BASE / 'crash-log-inspection-v1'") == 1
source = source.replace("OUT = BASE / 'crash-log-inspection-v1'", "OUT = BASE / 'unified-log-inspection-v1'")
anchor = "    record['status'] = 'READ_ONLY_CRASH_LOG_INSPECTION_COMPLETE'"
assert source.count(anchor) == 1
decoder = r'''
    import shutil
    archive = OUT / 'guest.logarchive'
    archive.mkdir()
    files = []
    total = 0
    for relative, destination in [('private/var/db/diagnostics', archive),
                                  ('private/var/db/uuidtext', archive/'uuidtext')]:
        origin = mount / relative
        if not origin.is_dir():
            record.setdefault('missing_archive_roots', []).append(relative)
            continue
        assert origin.resolve().is_relative_to(mount.resolve())
        for path in sorted(origin.rglob('*')):
            assert not path.is_symlink(), path
            if not path.is_file():
                continue
            size = path.stat().st_size
            total += size
            assert total <= 512 << 20 and len(files) < 20000, 'bounded archive limit'
            dest = destination / path.relative_to(origin)
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, dest)
            assert sha(path) == sha(dest)
            files.append(dict(path=str(dest.relative_to(archive)), bytes=size, sha256=sha(dest)))
    record['archive'] = dict(path=str(archive), bytes=total, files=files)
    command = ['/usr/bin/log', 'show', '--archive', str(archive), '--style', 'ndjson',
               '--info', '--debug', '--predicate',
               'process == "WindowServer" OR eventMessage CONTAINS[c] "WindowServer" OR eventMessage CONTAINS[c] "Adreno" OR eventMessage CONTAINS[c] "uncaught exception"']
    output, errors = OUT/'windowserver.ndjson', OUT/'decoder.log'
    with output.open('x') as stdout, errors.open('x') as stderr:
        result = subprocess.run(command, stdout=stdout, stderr=stderr, timeout=90)
    record['decoder'] = dict(command=command, exit_code=result.returncode,
        output_sha256=sha(output), output_bytes=output.stat().st_size,
        diagnostics_sha256=sha(errors), boundary='Saved datastore events; boot identity and time require attribution')
'''
source = source.replace(anchor, decoder + '\n' + anchor)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))
