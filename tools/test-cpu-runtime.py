#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory() as directory:
    binary=str(Path(directory)/'cpu-runtime')
    subprocess.run(['clang','-std=gnu11','-O1','-g','-fsanitize=address,undefined',
        '-Icompat','tools/test-cpu-runtime.c','compat/cpu-runtime.c','-o',binary],
        cwd=ROOT,check=True,timeout=30)
    subprocess.run([binary],check=True,timeout=30)
