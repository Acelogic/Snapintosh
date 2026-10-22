#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Resumable IPSW downloader.

Apple's restore images are ~27GB and the CDN drops connections, so this resumes
with Range requests rather than restarting. Progress goes to stdout so it can be
followed with tail(1) when run in the background.

  python3 tools/fetch-ipsw.py <url> [destination]
"""
import os
import sys
import time
import urllib.request
from pathlib import Path

CHUNK = 1 << 20


def fetch(url, path):
    for attempt in range(1, 41):
        have = path.stat().st_size if path.exists() else 0
        request = urllib.request.Request(url)
        if have:
            request.add_header('Range', f'bytes={have}-')
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                if have and response.status != 206:
                    print(f'server ignored Range (status {response.status}); restarting')
                    path.unlink(missing_ok=True)
                    have = 0
                total = have + int(response.headers.get('Content-Length', 0))
                start, last = time.monotonic(), 0.0
                with path.open('ab' if have else 'wb') as out:
                    while True:
                        block = response.read(CHUNK)
                        if not block:
                            break
                        out.write(block)
                        have += len(block)
                        now = time.monotonic()
                        if now - last > 5:
                            rate = have / max(now - start, 1e-9) / 1e6
                            pct = 100.0 * have / total if total else 0.0
                            print(f'{have/1e9:6.2f} / {total/1e9:.2f} GB  '
                                  f'{pct:5.1f}%  {rate:5.1f} MB/s', flush=True)
                            last = now
            if total and have >= total:
                print(f'complete: {have/1e9:.2f} GB -> {path}', flush=True)
                return 0
        except Exception as error:                      # noqa: BLE001 - resume on anything
            print(f'attempt {attempt}: {type(error).__name__}: {error}; resuming', flush=True)
            time.sleep(min(5 * attempt, 60))
    print('gave up', flush=True)
    return 1


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    url = sys.argv[1]
    path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(os.path.basename(url))
    path.parent.mkdir(parents=True, exist_ok=True)
    return fetch(url, path)


if __name__ == '__main__':
    sys.exit(main())
