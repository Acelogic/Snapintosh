#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Keep only the staged main APFS container; preserve every other seed byte."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import plistlib
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
START = 524308480
END = START + 62826479616
TOTAL = 64 << 30
CHUNK = 8 << 20
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def signature(path):
    s = path.stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--stage', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    stage_path, out = args.stage.resolve(), args.output.resolve()
    stage = json.loads(stage_path.read_text())
    assert stage['status'] == 'CLEAR_FILES_STAGED_LOCAL_ONLY' and not stage['ssd_writes']
    assert stage['source_sha256'] == sha(ROOT / 'tools/stage-adreno-clear-image.py')
    for name, digest in stage['inputs_sha256'].items(): assert sha(Path(name)) == digest
    before, staged = Path(stage['seed']), Path(stage['image'])
    assert signature(before) == stage['seed_stat'] == stage['seed_stat_after']
    assert signature(staged) == stage['image_stat']
    assert before.stat().st_size == staged.stat().st_size == TOTAL
    assert not out.exists() and stage['detach'] and not any(x['exit_code'] for x in stage['detach'])
    mounts = plistlib.loads(subprocess.check_output(['hdiutil', 'info', '-plist']))
    assert not any(Path(x.get('image-path', '/')).resolve() in (before, staged) for x in mounts.get('images', []))
    out.mkdir(parents=True)
    image = out / 'staged.img'
    subprocess.run(['cp', '-c', str(staged), str(image)], check=True)
    os.chmod(image, 0o644)
    restored = []
    record = dict(status='RUNNING', started=time.time(), source_sha256=sha(Path(__file__)),
        original_stage=str(stage_path), original_stage_sha256=sha(stage_path),
        image=str(image), seed=str(before), seed_stat=signature(before),
        original_image=str(staged), original_image_stat=signature(staged), ssd_writes=False)
    try:
        with before.open('rb') as seed, image.open('r+b') as normalized:
            for low, high in ((0, START), (END, TOTAL)):
                for offset in range(low, high, CHUNK):
                    count = min(CHUNK, high - offset)
                    seed.seek(offset)
                    normalized.seek(offset)
                    a, b = seed.read(count), normalized.read(count)
                    assert len(a) == len(b) == count
                    if a == b:
                        continue
                    for at in range(0, count, 4096):
                        if a[at:at + 4096] == b[at:at + 4096]:
                            continue
                        normalized.seek(offset + at)
                        data = a[at:at + 4096]
                        assert normalized.write(data) == len(data)
                        if restored and restored[-1][1] == offset + at:
                            restored[-1][1] += len(data)
                        else:
                            restored.append([offset + at, offset + at + len(data)])
            normalized.flush()
            os.fsync(normalized.fileno())
        main_hash, outside_hash = hashlib.sha256(), hashlib.sha256()
        with before.open('rb') as seed, staged.open('rb') as source, image.open('rb') as normalized:
            regions = [(0, START, seed, outside_hash), (START, END, source, main_hash),
                       (END, TOTAL, seed, outside_hash)]
            for low, high, expected, hasher in regions:
                expected.seek(low)
                normalized.seek(low)
                for offset in range(low, high, CHUNK):
                    count = min(CHUNK, high - offset)
                    a, b = expected.read(count), normalized.read(count)
                    assert len(a) == len(b) == count and a == b, offset
                    hasher.update(b)
        assert signature(before) == record['seed_stat'] and signature(staged) == record['original_image_stat']
        assert sha(stage_path) == record['original_stage_sha256']
        record.update(status='CLEAR_STAGE_NORMALIZED_LOCAL_ONLY', main_sha256=main_hash.hexdigest(),
            outside_sha256=outside_hash.hexdigest(), restored_ranges=restored,
            restored_bytes=sum(b - a for a, b in restored), verified_bytes=TOTAL)
    except BaseException as error:
        record.update(status='FAIL', exception=repr(error))
        raise
    finally:
        record.update(finished=time.time(), image_stat=signature(image))
        (out / 'normalization.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({k: record[k] for k in ('status', 'main_sha256', 'restored_bytes', 'verified_bytes')}))


if __name__ == '__main__':
    main()
