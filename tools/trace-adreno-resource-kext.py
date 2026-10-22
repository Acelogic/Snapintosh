#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture native IOGPU allocation, descriptor replacement and free ordering."""
from pathlib import Path
import hashlib
import importlib.util
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
base = ROOT/'tools/trace-adreno-memory-map.py'
spec = importlib.util.spec_from_file_location('adreno_mapping_trace', base)
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)
extra = (
    '__ZN14IOGPUMemoryMap10update_pteEjP18IOMemoryDescriptorS1_',
    '__ZN11IOGPUMemory15update_mappingsEjP18IOMemoryDescriptorS1_',
    '__ZN14IOGPUSysMemory28replace_backing_bytes_lockedEP4taskyy',
    '__ZN14IOGPUSysMemory29replace_backing_ranges_lockedEP4taskP14IOVirtualRangejb',
    '__ZN11IOGPUMemory46createGPUMappingInTaskAtAddressLengthAlignmentEP9IOGPUTaskyyyj',
    '__ZN14IOGPUMemoryMap34getGPUVirtualAddressForUserProcessEv',
    '__ZN9IOGPUTask8allocateEP14IOGPUMemoryMap',
    '__ZN9IOGPUTask10deallocateEP14IOGPUMemoryMapy',
)
scope, wanted = trace.TARGETS['IOGPUFamily']
trace.TARGETS['IOGPUFamily'] = (scope, wanted + extra)
scope, wanted = trace.TARGETS['AppleT8110DART']
trace.TARGETS['AppleT8110DART'] = (scope, wanted + (
    '__ZN14AppleT8110DART14setTranslationEP13IODARTVMSpacejPvjjjj',))
scope, wanted = trace.TARGETS['kernel']
trace.TARGETS['kernel'] = (scope, wanted + ('_pmap_iommu_map', '_t8110dart_get_desc'))
trace.main()
output = Path(sys.argv[sys.argv.index('--output')+1])
record = json.loads(output.read_text())
record['resource_kext_tracer_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
record['resource_kext_boundary'] = __doc__
output.write_text(json.dumps(record, indent=2)+'\n')
