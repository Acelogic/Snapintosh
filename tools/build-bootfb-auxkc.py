#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Serialize the experimental codeless collection; never installs or loads it."""
import argparse
import hashlib
from pathlib import Path
import plistlib
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import bootfb
import xnuboot as xb


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--dedicated-provider', action='store_true',
                        help='match the independent virtual framebuffer provider')
    args = parser.parse_args()
    xb.configure_guest('j700ap-26A428-bootfb-nub' if args.dedicated_provider else 'j700ap-26A428-bootfb')
    image = xb.kc_load.Image(xb.DEFAULT_KERNELCACHE.read_bytes())
    info = plistlib.loads((ROOT / 'drivers/boot-framebuffer/'
                          'SnapintoshBootFramebuffer.kext/Contents/Info.plist').read_bytes())
    payload = bootfb.build_auxkc(image, info, dedicated=args.dedicated_provider)
    args.output.write_bytes(payload)
    print(f'{args.output}: {len(payload)} bytes; SHA256 {hashlib.sha256(payload).hexdigest()}')


if __name__ == '__main__':
    main()
