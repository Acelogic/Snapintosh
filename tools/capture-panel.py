#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read the live GOP framebuffer through q1n1 and save a PNG; never draw."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
from bootcontract import HostRuntime
from run import DEFAULT_DEVICE, connect, q1n1


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('output', type=Path)
    ap.add_argument('--device', default=DEFAULT_DEVICE)
    ap.add_argument('--block-bytes', type=int, choices=(1024, 4096, 65536), default=65536,
                    help='maximum read payload; smaller blocks can help CDC links')
    ap.add_argument('--reconnects', type=int, choices=range(4), default=0,
                    help='bounded total reconnects after failed read-only transfers')
    args = ap.parse_args()
    from PIL import Image
    proxy = connect(args.device, tries=2)
    try:
        info = proxy.bootinfo()
        fb = HostRuntime.from_q1n1(info, with_framebuffer=True).framebuffer
        # Bound each USB transaction; one full-panel read can exceed the
        # transport's request timeout before its checksum header arrives.
        size = fb.stride * fb.height
        block = args.block_bytes
        identity_keys = ('image_base', 'stage_generation', 'fb_base', 'fb_width',
                         'fb_height', 'fb_stride', 'fb_format')
        identity = tuple(info[key] for key in identity_keys)
        remaining = args.reconnects
        chunks = []
        for offset in range(0, size, block):
            count = min(block, size - offset)
            while True:
                try:
                    data = proxy.readmem(fb.base + offset, count)
                    if len(data) != count:
                        raise q1n1.ProxyError('short framebuffer read')
                    chunks.append(data)
                    break
                except q1n1.ProxyError as error:
                    if not remaining:
                        raise
                    remaining -= 1
                    print(f'read at {offset:#x} failed ({error}); reconnecting, '
                          f'{remaining} retries remain', flush=True)
                    proxy.link.close()
                    proxy = None
                    proxy = connect(args.device, tries=2)
                    retry_info = proxy.bootinfo()
                    if tuple(retry_info[key] for key in identity_keys) != identity:
                        raise RuntimeError('target or framebuffer changed during capture')
        pixels = b''.join(chunks)
        image = Image.frombytes('RGB', (fb.width, fb.height), pixels, 'raw',
                                'BGRX' if info['fb_format'] == 1 else 'RGBX', fb.stride)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        image.save(args.output)
        print(f'{args.output.resolve()}: {fb.width}x{fb.height}, '
              f'{len(pixels)} framebuffer bytes read; no pixels written')
    finally:
        if proxy is not None:
            proxy.link.close()


if __name__ == '__main__':
    main()
