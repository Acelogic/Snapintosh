#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify the SnapI2CHID test fixture against the retained A16 evidence, then
build and run tools/test-snap-i2c-hid.c under ASan/UBSan.

The fixture header carries the physically captured bytes; this refuses to run
the C test unless they equal the evidence artifacts named below (by SHA256).
"""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tools/test-snap-i2c-hid-fixture.h'
EVIDENCE = {
    'descriptor': ('build/a16-hid-descriptor-gen56-20260928-v1.json',
                   '3a8895c73445ad76141a9bf825a45a7b2e9f2220ab94f1c73711a7d92a811ff6'),
    'report': ('build/a16-hid-report-descriptor-gen57-20260928-v1.json',
               '7c55ad9ecc308853472f4f3c8e22461f93cb3b185217c5cb533be90193d7b8dc'),
    'state': ('build/a16-keyboard-state-gen59-20260928-v1.json',
              'ba7c0d49ebf7bf79c10e847983317200966ff0503d3b4b8601054f76bbe7889c'),
}
REPORT_SHA = '0887190d374bd8f4ff9e5278af8e7831fc149714b1f681860cc87a9c27cbaacb'
SOURCES = ['tools/test-snap-i2c-hid.c'] + [
    f'drivers/snap-i2c-hid/src/{name}.c' for name in ('geni-i2c', 'hid-rdesc', 'i2c-hid')]


def array(text, name):
    match = re.search(r'\b%s\[\d*\] = \{(.*?)\};' % re.escape(name), text, re.S)
    assert match, name
    return bytes(int(v, 16) for v in re.findall(r'0x([0-9a-f]{2})\b', match.group(1)))


def evidence(key):
    rel, digest = EVIDENCE[key]
    path = ROOT / rel
    blob = path.read_bytes()
    assert hashlib.sha256(blob).hexdigest() == digest, f'{rel} differs from the recorded evidence'
    return json.loads(blob)


def check_fixture():
    text = FIXTURE.read_text()
    descriptor = evidence('descriptor')['descriptor_transaction']
    report = evidence('report')
    state = evidence('state')['keyboard_state_transaction']
    assert descriptor['status'] == 'TWO_IDENTICAL_HID_DESCRIPTORS'
    assert report['report_descriptor_transaction']['status'] == 'TWO_IDENTICAL_HID_REPORT_DESCRIPTORS'
    assert state['command_packet'] == '05001f02360600'
    raw = {row['raw_hex'] for row in descriptor['attempts']}
    assert raw == {array(text, 'a16_eckb_hid_desc').hex()}
    rdesc = array(text, 'a16_eckb_report_desc')
    assert hashlib.sha256(rdesc).hexdigest() == REPORT_SHA
    assert {row['raw_hex'] for row in report['report_descriptor_transaction']['attempts']} == {rdesc.hex()}
    assert {row['raw_hex'] for row in state['attempts']} == {array(text, 'a16_eckb_get_report_54').hex()}
    fixture_regs = {int(o, 16): int(v, 16) for o, v in
                    re.findall(r'\{(0x[0-9a-f]+), (0x[0-9a-f]+)\}', text)}
    observed = {int(row['address'], 16) - 0x0088c000: row['value']
                for row in report['registers'].values()}
    assert fixture_regs == observed, 'register snapshot differs from generation57'
    return dict(hid_descriptor=len(raw.pop()) // 2, report_descriptor=len(rdesc),
                registers=len(observed))


def main():
    summary = check_fixture()
    out = ROOT / 'build/test-snap-i2c-hid'
    out.parent.mkdir(exist_ok=True)
    cmd = ['cc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined', '-Wall', '-Wextra',
           '-Werror', '-Idrivers/snap-i2c-hid/src', *SOURCES, '-o', str(out)]
    subprocess.run(cmd, cwd=ROOT, check=True)
    result = subprocess.run([str(out)], cwd=ROOT, capture_output=True, text=True)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode:
        raise SystemExit(result.returncode)
    print(json.dumps(dict(fixture='MATCHES_EVIDENCE', **summary)))


if __name__ == '__main__':
    main()
