#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture original J700 segment resource parsing and lifetime contracts."""
from pathlib import Path
import hashlib
import importlib.util
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
base = ROOT/'tools/trace-adreno-memory-map.py'
spec = importlib.util.spec_from_file_location('adreno_resource_list_trace', base)
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)
trace.TARGETS = {
    'IOGPUFamily': ('com.apple.iokit.IOGPUFamily', (
        '__ZN17IOGPUCommandQueue20processCommandBufferEPK34IOGPUCommandQueueCommandBufferArgs',
        '__ZN17IOGPUCommandQueue18reclaimSegmentListEP24IOGPUSegmentResourceList',
        '__ZN11IOGPUDevice14retainResourceEj',
        '__ZNK14IOGPUNamespace12retainObjectEj',
        '__ZNK14IOGPUNamespace18retainObjectLockedEj',
        '__ZNK11IOGPUObject6retainEv',
        '__ZNK11IOGPUObject7releaseEv',
        '__ZN23IOGPUKernelMappedMemory13getKernelDataEv',
        '__ZN16IOGPUDeviceShmem13getKernelDataEv',
        '__ZNK16IOGPUDeviceShmem9getLengthEv',
        '__ZN23IOGPUKernelMappedMemory17releaseKernelDataEv',
        '__ZN13IOGPUResource3mapEyj',
        '__ZN13IOGPUResource5unmapEv',
        '__ZN14IOGPUSysMemory4wireEv',
        '__ZN14IOGPUSysMemory6unwireEv')),
    'AGXG17P': ('com.apple.AGXG17P', (
        '__ZN22AGXSegmentResourceList16parseAndValidateER21AGXSharedStreamParser',
        '__ZN27AGXSegmentResourceDescGroup16parseAndValidateER21AGXSharedStreamParser',
        '__ZN18AGXAllocationList226initWithSharedResourceListEP11IOGPUDeviceR21AGXSharedStreamParser',
        '__ZN18AGXAllocationList226initWithSharedResourceListEP11IOGPUDevicePK30IOGPUSegmentResourceListHeaderP16IOGPUDeviceShmem',
        '__ZN18AGXAllocationList24freeEv',
        '__ZN15AGXCommandQueue16parseSegmentListEP11IOGPUDevicePK30IOGPUSegmentResourceListHeaderP16IOGPUDeviceShmem')),
}
trace.EXPECTED_UUIDS['AGXG17P'] = '80c847da-77c1-32e5-bc68-9dfc853fb71f'
trace.FIXED_PATH_WITNESSES = {}
trace.main()
output = Path(sys.argv[sys.argv.index('--output')+1])
record = json.loads(output.read_text())
record['resource_list_tracer_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
record['resource_list_boundary'] = __doc__ + ' Static trace only; no native execution.'
output.write_text(json.dumps(record, indent=2)+'\n')
