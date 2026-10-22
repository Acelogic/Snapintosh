#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture original J700 memory preparation and mapping synchronization."""
from pathlib import Path
import hashlib
import importlib.util
import json
import sys

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('wiring_trace',ROOT/'tools/trace-adreno-memory-map.py')
trace=importlib.util.module_from_spec(spec);spec.loader.exec_module(trace)
trace.TARGETS={'IOGPUFamily':('com.apple.iokit.IOGPUFamily',(
    '__ZN11IOGPUMemory13prepareMemoryEv',
    '__ZN11IOGPUMemory19prepare_memory_slowEjby',
    '__ZN11IOGPUMemory13prepareMemoryEjby',
    '__ZN11IOGPUMemory13prepareMemoryEjb',
    '__ZN11IOGPUMemory13prepareMemoryEy',
    '__ZN11IOGPUMemory18prepareMemoryQuickEv',
    '__ZN11IOGPUMemory14completeMemoryEv',
    '__ZNK11IOGPUMemory15getPrepareCountEv',
    '__ZNK11IOGPUMemory4lockEv',
    '__ZNK11IOGPUMemory6unlockEv',
    '__ZN11IOGPUMemory4wireEy',
    '__ZN11IOGPUMemory15commit_mappingsEy',
    '__ZN11IOGPUMemory16release_mappingsEy',
    '__ZN14IOGPUMemoryMap10commit_pteEy',
    '__ZN14IOGPUMemoryMap11release_pteEy',
    '__ZN13IOGPUResource5unmapEv',
    '__ZN13IOGPUResource4freeEv',
    '__ZN13IOGPUResource13sharedReleaseEP11IOGPUDevice',
    '__ZN17IOGPUCommandQueue20processCommandBufferEPK34IOGPUCommandQueueCommandBufferArgs',
    '__ZN14IOGPUScheduler18collectGartWiringsEv',
    '__ZN14IOGPUScheduler16freeToWireMemoryEP11IOGPUMemory',
    '__ZN14IOGPUSysMemory4wireEv',
    '__ZN14IOGPUSysMemory6unwireEv'))}
trace.FIXED_PATH_WITNESSES={}
trace.main()
output=Path(sys.argv[sys.argv.index('--output')+1]);record=json.loads(output.read_text())
record['wiring_tracer_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
record['wiring_boundary']=__doc__+' Static trace only; no preparation or GPU execution.'
output.write_text(json.dumps(record,indent=2)+'\n')
