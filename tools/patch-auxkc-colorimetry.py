#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The display8 AuxKC with an sRGB colour element (docs/ADRENO-WINDOWSERVER-TARGETS-20261017.md).

    python3 tools/patch-auxkc-colorimetry.py SOURCE.kc OUT-DIR

AdrenoDisplay::publishDisplayAttributes builds its single IOAVVideoColorElement with
withCapabilities(standard 2, depth 8, encoding 0, range 0, EOTF 0, colorimetry 16, false, ...).
Colorimetry 16 is IOAVVideoColorimetryString's "Default RGB", the panel's native gamut. QuartzCore
26A428's IOMFBDisplay::update_digital_modes gives an RGB "Default RGB" element on a display whose
hotplug state byte 3 is set its native colour code, and update_framebuffer_locked then sets
supportsExtendedColors; framebuffer_pixel_format answers 'b3a8' (Metal 550) instead of 'BGRA'. The
panel is sRGB (the element's own primaries are Rec.709, /product artwork-display-gamut is "sRGB"),
so the honest value is colorimetry 10, "sRGB".

The kext source says 10 now (gpu/adreno-kext/kext/src/AdrenoDisplay.cpp). The collection cannot be
relinked here (build/kmutil-auxkc.sh needs root to stage root:wheel kexts), so the retained, booted
collection is patched instead: exactly one instruction, the colorimetry argument, `mov w5, #0x10`
becomes `mov w5, #0xa`. The eight-instruction argument setup must occur exactly once, inside the
AdrenoX2 executable segment; every other byte must be unchanged. The manifest keeps the admission
summary (bundles, fixups, ranges, UUID are the source collection's) with the new sha256 and a patch
record.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
import auxkc  # noqa: E402


def mov_w(reg, imm):
    return 0x52800000 | (imm << 5) | reg


def mov_x(reg, imm):
    return 0xd2800000 | (imm << 5) | reg


SETUP = [mov_w(0, 2), mov_w(1, 8), mov_w(2, 0), mov_w(3, 0), mov_w(4, 0), mov_w(5, 16), mov_w(6, 0), mov_x(7, 0)]
OLD, NEW = mov_w(5, 16), mov_w(5, 10)
sha = lambda data: hashlib.sha256(data).hexdigest()


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 64
    source, out = Path(sys.argv[1]), Path(sys.argv[2])
    if out.exists():
        print(f'{out} exists')
        return 64
    data = source.read_bytes()
    manifest = json.loads(auxkc.manifest_path(source).read_text())
    if manifest.get('sha256') != sha(data):
        raise SystemExit('source collection does not match its manifest')
    pattern = struct.pack('<8I', *SETUP)
    hits = [i for i in range(0, len(data) - len(pattern) + 1, 4) if data[i:i + len(pattern)] == pattern]
    if len(hits) != 1:
        raise SystemExit(f'colour element argument setup found {len(hits)} times, expected once')
    at = hits[0] + 4 * SETUP.index(OLD)
    collection = auxkc.Collection(data)
    executable = [(name, va, off, filesize) for name, va, vmsize, off, filesize, _, initprot in collection.segments
                  if initprot & 4 and filesize and off <= at < off + filesize]
    if len(executable) != 1:
        raise SystemExit(f'patch site {at:#x} is not in exactly one executable segment: {executable}')
    name, va, off, _ = executable[0]
    patched = bytearray(data)
    struct.pack_into('<I', patched, at, NEW)
    changed = [i for i in range(len(data)) if data[i] != patched[i]]
    if not changed or changed[0] < at or changed[-1] >= at + 4:
        raise SystemExit(f'unexpected changed bytes {changed[:8]}')
    out.mkdir(parents=True)
    kc = out / source.name
    kc.write_bytes(patched)
    record = dict(manifest)
    record.update(sha256=sha(bytes(patched)), bytes=len(patched))
    record['patch'] = dict(source=str(source), source_sha256=sha(data), file_offset=hex(at), segment=name,
                           vmaddr=hex(va + at - off), old=f'{OLD:#010x} mov w5, #0x10 (colorimetry 16, Default RGB)',
                           new=f'{NEW:#010x} mov w5, #0xa (colorimetry 10, sRGB)', changed_bytes=len(changed),
                           tool='tools/patch-auxkc-colorimetry.py', tool_sha256=sha(Path(__file__).read_bytes()))
    auxkc.manifest_path(kc).write_text(json.dumps(record, indent=1, sort_keys=False) + '\n')
    # The loader's own admission must accept the patched bytes with this manifest.
    auxkc.load(kc, manifest['kernel_sha256'])
    print(json.dumps(dict(out=str(kc), sha256=record['sha256'], file_offset=hex(at), vmaddr=record['patch']['vmaddr'],
                          segment=name, changed_bytes=len(changed))))
    return 0


if __name__ == '__main__':
    sys.exit(main())
