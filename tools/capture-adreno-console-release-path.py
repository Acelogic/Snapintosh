#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Save selected-image evidence for replacing disable-screen with release-screen.

This is a read-only binary capture, not a runtime display qualification. Failure
inventory and manual path review are in docs/ADRENO-GUI-INTEGRATION-20260927.md.
"""
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL = ROOT.parent / 'Snapintosh'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    kernel = ORIGINAL / 'downloads/extracted/j700ap/kernelcache.release.mac17p'
    reader = ORIGINAL / 'tools/kc-xref.py'
    symbolicator = ORIGINAL / 'tools/kc-symbolicate.py'
    kc = runpy.run_path(str(reader))['Kernelcache'](kernel)
    dis = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    ranges = {
        'PE_initialize_console': (0xfffffe000c1eeb20, 0xfffffe000c1eecd0),
        'initialize_screen_entry': (0xfffffe000ba55740, 0xfffffe000ba55780),
        'initialize_screen_release': (0xfffffe000ba55c80, 0xfffffe000ba55d18),
        'initialize_screen_return': (0xfffffe000ba55fe8, 0xfffffe000ba56020),
        'gc_enable': (0xfffffe000ba56050, 0xfffffe000ba56500),
        'vc_progress_initialize': (0xfffffe000ba55130, 0xfffffe000ba55298),
        'vc_progress_set': (0xfffffe000ba53c78, 0xfffffe000ba53f80),
        'internal_enable_progressmeter': (0xfffffe000ba54b5c, 0xfffffe000ba55040),
    }
    instructions = {}
    for name, (start, end) in ranges.items():
        raw = kc.data[kc.va2off(start):kc.va2off(end)]
        (out / (name + '.bin')).write_bytes(raw)
        decoded = list(dis.disasm(raw, start))
        assert len(decoded) * 4 == len(raw), name
        instructions.update({i.address: (i.mnemonic, i.op_str) for i in decoded})
        (out / (name + '.txt')).write_text(''.join(
            f'{i.address:#018x} {bytes(i.bytes).hex()} {i.mnemonic} {i.op_str}\n' for i in decoded))
    # These anchors bind the manually reviewed nullptr/op5 route. They do not
    # claim an exhaustive control-flow proof or that a physical swap succeeded.
    anchors = {
        0xfffffe000c1eeb7c: ('str', 'wzr, [x9, #0x4f8]'),
        0xfffffe000c1eec7c: ('mov', 'w1, #5'),
        0xfffffe000c1eec80: ('bl', '#0xfffffe000ba55740'),
        0xfffffe000ba5577c: ('cbz', 'x0, #0xfffffe000ba55c80'),
        0xfffffe000ba55cac: ('cmp', 'w19, #5'),
        0xfffffe000ba55cb8: ('strb', 'wzr, [x8, #0x7c]'),
        0xfffffe000ba55cbc: ('strb', 'wzr, [x21, #0x94]'),
        0xfffffe000ba55cc4: ('bl', '#0xfffffe000ba56050'),
        0xfffffe000ba56088: ('ldr', 'w8, [x8, #0x4f8]'),
        0xfffffe000ba5601c: ('retab', ''),
        0xfffffe000ba55294: ('ret', ''),
    }
    for address, expected in anchors.items():
        assert instructions[address] == expected, (hex(address), instructions[address])
    addresses = [*anchors, 0xfffffe000c816078, 0xfffffe000c81607c,
                 0xfffffe000c816094, 0xfffffe000c815dd8,
                 0xfffffe000b911a0c, 0xfffffe000b911e04]
    symbols = subprocess.run(['python3', str(symbolicator), *map(hex, addresses)],
        check=True, text=True, capture_output=True).stdout
    (out / 'symbols.txt').write_text(symbols)
    sdk = Path(subprocess.check_output(['xcrun', '--show-sdk-path'], text=True).strip())
    header = sdk / 'System/Library/Frameworks/Kernel.framework/Headers/pexpert/pexpert.h'
    assert '#define kPEReleaseScreen        5' in header.read_text()
    record = dict(status='SELECTED_KERNEL_CONSOLE_RELEASE_PATH_CAPTURED_NOT_EXECUTED',
        inputs_sha256={str(p): sha(p) for p in [kernel, reader, symbolicator, header, Path(__file__)]},
        ranges={name: [hex(a), hex(b)] for name, (a, b) in ranges.items()},
        anchors={hex(a): list(v) for a, v in anchors.items()},
        artifacts_sha256={p.name: sha(p) for p in out.iterdir() if p.is_file()},
        boundary='Selected 26A428 code and SDK operation value. Manual review identifies '
                 'release-screen text/progress disabling and avoids op7 serial-selector store. '
                 'No hardware access, successful swap, screen image, or GUI is implied.')
    path = out / 'capture.json'
    path.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(dict(status=record['status'], path=str(path), sha256=sha(path))))

if __name__ == '__main__':
    main()
