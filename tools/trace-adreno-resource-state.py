#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind native resource ownership and map fields to the original J700 IOGPU image."""
from pathlib import Path
import hashlib
import importlib.util
import json
import sys

ROOT=Path(__file__).resolve().parents[1]
base=ROOT/'tools/trace-adreno-memory-map.py'
spec=importlib.util.spec_from_file_location('resource_state_trace',base)
trace=importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)
trace.TARGETS={'IOGPUFamily':('com.apple.iokit.IOGPUFamily',(
    '__ZN21IOGPUDeviceUserClient14s_new_resourceEPS_PvP25IOExternalMethodArguments',
    '__ZN21IOGPUDeviceUserClient12new_resourceEP20IOGPUNewResourceArgsP26IOGPUNewResourceReturnDatayPj',
    '__ZN11IOGPUDevice14retainResourceEj',
    '__ZNK14IOGPUNamespace18retainObjectLockedEj',
    '__ZN13IOGPUResource3mapEyj',
    '__ZN13IOGPUResource5unmapEv',
    '__ZN13IOGPUResource23getMemoryAllocParameterEv',
    '__ZNK13IOGPUResource34getGPUVirtualAddressForUserProcessEv',
    '__ZNK13IOGPUResource17getMappingOptionsEP20IOGPUNewResourceArgsy',
))}
trace.FIXED_PATH_WITNESSES={}
trace.main()
output=Path(sys.argv[sys.argv.index('--output')+1])
record=json.loads(output.read_text())
record['resource_state_tracer_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
record['resource_state_boundary']=__doc__+' Static code; no guest access or calls.'
output.write_text(json.dumps(record,indent=2)+'\n')
