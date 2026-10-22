#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import subprocess
import tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as directory:
    binary=str(Path(directory)/'cpu-release')
    subprocess.run(['clang','-std=gnu11','-O1','-g','-fsanitize=address,undefined',
        '-Icompat','tools/test-cpu-release.c','compat/cpu-release.c','-o',binary],
        cwd=ROOT,check=True,timeout=30)
    subprocess.run([binary],check=True,timeout=30)
