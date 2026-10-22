#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture original J700 queue, submission error and resource-list contracts."""
from pathlib import Path
import hashlib
import importlib.util
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
base = ROOT/'tools/trace-adreno-memory-map.py'
spec = importlib.util.spec_from_file_location('adreno_submit_trace', base)
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)
trace.TARGETS = {
    'IOGPUFamily': ('com.apple.iokit.IOGPUFamily', (
        '__ZN17IOGPUCommandQueue27processSegmentKernelCommandEP24IOGPUSegmentResourceListPK18IOGPUKernelCommandS4_PKhS6_PK34IOGPUCommandQueueCommandBufferArgs',
        '__ZN17IOGPUCommandQueue28processSegmentKernelCommandsEP24IOGPUSegmentResourceListPK18IOGPUKernelCommandS4_PKhS6_PK34IOGPUCommandQueueCommandBufferArgs',
        '__ZN17IOGPUCommandQueue20processCommandBufferEPK34IOGPUCommandQueueCommandBufferArgs',
        '__ZN17IOGPUCommandQueue18setSubmissionErrorEj',
        '__ZN17IOGPUCommandQueue18reclaimSegmentListEP24IOGPUSegmentResourceList',
        '__ZN11IOGPUDevice14retainResourceEj',
        '__ZN11IOGPUDevice11getResourceEj',
        '__ZN11IOGPUDevice21lockResourceNamespaceEv',
        '__ZN11IOGPUDevice23unlockResourceNamespaceEv',
        '__ZNK14IOGPUNamespace12retainObjectEj',
        '__ZN13IOGPUResource3mapEyj',
        '__ZN13IOGPUResource5unmapEv',
        '__ZN13IOGPUResource4freeEv',
        '__ZN13IOGPUResource22deviceCacheSynchronizeEv',
        '__ZN13IOGPUResource21deviceCacheInvalidateEv',
        '__ZN14IOGPUSysMemory4wireEv',
        '__ZN14IOGPUSysMemory6unwireEv',
        '__ZN17IOGPUCommandQueue4initEP5IOGPUP11IOGPUDeviceP30IOGPUDeviceNewCommandQueueArgs')),
    'AGXG17P': ('com.apple.AGXG17P', (
        '__ZN18AGXAllocationList226initWithSharedResourceListEP11IOGPUDeviceR21AGXSharedStreamParser',
        '__ZN18AGXAllocationList226initWithSharedResourceListEbP11IOGPUDevicePK30IOGPUSegmentResourceListHeaderP16IOGPUDeviceShmem',
        '__ZN18AGXAllocationList226initWithSharedResourceListEP11IOGPUDevicePK30IOGPUSegmentResourceListHeaderP16IOGPUDeviceShmem',
        '__ZN15AGXCommandQueue16parseSegmentListEP11IOGPUDevicePK30IOGPUSegmentResourceListHeaderP16IOGPUDeviceShmem')),
}
trace.EXPECTED_UUIDS['AGXG17P'] = '80c847da-77c1-32e5-bc68-9dfc853fb71f'
trace.FIXED_PATH_WITNESSES = {}
trace.main()
output = Path(sys.argv[sys.argv.index('--output')+1])
record = json.loads(output.read_text())
record['submit_tracer_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
record['submit_boundary'] = __doc__ + ' Static trace only; no native execution.'
output.write_text(json.dumps(record, indent=2)+'\n')
