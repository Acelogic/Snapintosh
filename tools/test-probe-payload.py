#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Reproduce single-source section extraction without touching physical hardware."""
from pathlib import Path
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import run


with tempfile.TemporaryDirectory() as directory:
    root=Path(directory)
    (root/'probes').mkdir()
    # This is the exact helper packaging error: assembly succeeds, .text is
    # empty, and objcopy --only-section=.text also succeeds with zero output.
    (root/'probes/empty-section.S').write_text('.section .text.entry,"ax"\nret\n')
    (root/'probes/normal-section.S').write_text('.text\nret\n')
    (root/'probes/oversized.S').write_text(f'.text\n.space {run.OUT_AT-run.CODE_AT+4}\n')
    old=run.ROOT
    try:
        run.ROOT=root
        for name in ('empty-section','oversized'):
            try:run.build(name,root/'build')
            except ValueError as error:
                assert 'outside reserved code size' in str(error)
            else:raise AssertionError(f'{name} admitted')
        assert run.build('normal-section',root/'build')==bytes.fromhex('c0035fd6')
    finally:run.ROOT=old
    actual=run.build('cache-geometry',root/'cache')
    assert len(actual)==100
    assert actual[:4]==bytes.fromhex('414238d5')  # MRS X1, CurrentEL at entry
    assert actual.count(bytes.fromhex('22740bd5'))==1  # One DC ZVA X2
print('PASS: 4 actual-toolchain payload checks; no hardware or xnuboot rebuild')
