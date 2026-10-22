#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Extract the profile's BaseSystem trust cache after checking its manifest."""
import argparse
import hashlib
from pathlib import Path
import plistlib
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
from guestprofile import get_profile


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('ipsw', type=Path)
    ap.add_argument('--guest-profile', default='j700ap-26A428-no-clpc')
    ap.add_argument('--output', type=Path)
    args = ap.parse_args()
    profile = get_profile(args.guest_profile)
    spec = profile.trust_cache
    if spec is None or profile.root_hash is None:
        raise ValueError('selected guest has no audited BaseSystem trust cache')
    with zipfile.ZipFile(args.ipsw) as archive:
        manifest = plistlib.loads(archive.read('BuildManifest.plist'))
        if manifest['ProductBuildVersion'] != profile.root_hash.build_id:
            raise ValueError('IPSW build does not match guest profile')
        identities = [i for i in manifest['BuildIdentities'] if
                      i['Info'].get('DeviceClass') == profile.root_hash.device_class]
        if not identities:
            raise ValueError('IPSW has no selected board identity')
        for identity in identities:
            component = identity['Manifest'][spec.component]
            if (component['Info']['Path'] != spec.member or
                    component['Digest'].hex() != spec.component_sha384):
                raise ValueError('manifest trust cache differs from pinned profile')
        payload = spec.extract(archive.read(spec.member))
    output = args.output or ROOT / 'downloads/extracted' / profile.firmware_subdir / spec.filename
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and output.read_bytes() != payload:
        raise ValueError(f'refusing to replace a different cache: {output}')
    output.write_bytes(payload)
    print(f'{output}: {spec.entries} entries, {len(payload)} bytes, '
          f'SHA-256 {hashlib.sha256(payload).hexdigest()}')


if __name__ == '__main__':
    main()
