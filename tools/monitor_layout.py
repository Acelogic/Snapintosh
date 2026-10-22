# SPDX-License-Identifier: MIT
"""Read private monitor offsets from Clang's target layout, never host ctypes.

Consumers must separately bind resident bytes to the current built monitor
before interpreting target RAM. This parser supplies structure offsets, not
proof that an arbitrary older resident binary has the same layout.

defines: the -D flags the monitor was built with (a run's launch.json or
qualification.json 'flags'; other entries are ignored). Several structures
change size with them -- SNAP_UNNEST_4K_FAST grows struct sptm_root_memo by
0xf8000 bytes, which moves every context field after root_memo (console_log
among them) and the context's end, where the table arena starts -- so a
running or stopped monitor's context is read with its own build's defines.
No defines keeps the define-free layout (params' appended blocks start at its
size; offsets before root_memo are the same in every build).
"""
from pathlib import Path
import re
import subprocess

ROOT=Path(__file__).resolve().parents[1]

def build_defines(flags):
    """The -D entries of a build's flag list, in order."""
    return [f for f in (flags or ()) if isinstance(f,str) and f.startswith('-D')]

class MonitorLayout:
    def __init__(self,defines=()):
        self.defines=build_defines(defines)
        text=subprocess.run(['clang','--target=aarch64-unknown-none-elf',
            '-ffreestanding','-mgeneral-regs-only','-Ishadow','-Icompat',*self.defines,
            '-Xclang','-fdump-record-layouts','-fsyntax-only','probes/xnuboot.c'],
            cwd=ROOT,capture_output=True,text=True,check=True).stdout
        self.records={}
        for block in text.split('*** Dumping AST Record Layout'):
            match=re.search(r'^\s*0 \| struct (\w+)\n',block,re.M)
            if match:
                name=match[1]
                if name in self.records:raise ValueError(f'duplicate layout {name}')
                self.records[name]=block

    def offset(self,kind,field):
        found=re.findall(r'^\s*(\d+) \|   \S.* '+re.escape(field)+r'$',self.records[kind],re.M)
        if len(found)!=1:raise ValueError(f'ambiguous monitor field {kind}.{field}')
        return int(found[0])

    def length(self,kind,field):
        found=re.findall(r'^\s*\d+ \|   \S+\[(\d+)\] '+re.escape(field)+r'$',self.records[kind],re.M)
        if len(found)!=1:raise ValueError(f'ambiguous or non-array monitor field {kind}.{field}')
        return int(found[0])

    def size(self,kind):
        found=re.findall(r'\[sizeof=(\d+),',self.records[kind])
        if len(found)!=1:raise ValueError(f'ambiguous monitor size {kind}')
        return int(found[0])
