#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Pin original native resource creation and mapping lifecycle without guest calls."""
from pathlib import Path
import hashlib
import importlib.util
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / 'tools/trace-adreno-memory-map.py'
spec = importlib.util.spec_from_file_location('resource_lifecycle_trace', base)
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)
trace.TARGETS = {'IOGPUFamily': ('com.apple.iokit.IOGPUFamily', (
    '__ZN11IOGPUDevice12new_resourceEP20IOGPUNewResourceArgsP26IOGPUNewResourceReturnDatayPj',
    '__ZN13IOGPUResource4initEP5IOGPUP11IOGPUDevicej',
    '__ZN13IOGPUResource10initializeEP11IOGPUDeviceP20IOGPUNewResourceArgsy',
    '__ZN13IOGPUResource3mapEy',
    '__ZN13IOGPUResource3mapEyj',
    '__ZNK13IOGPUResource17getMappingOptionsEP20IOGPUNewResourceArgsy',
    '__ZN5IOGPU14createResourceEP11IOGPUDevicej',
    '__ZN11IOGPUDevice25create_resource_iosurfaceEjyyPj',
))}
trace.FIXED_PATH_WITNESSES = {}
trace.main()
output = Path(sys.argv[sys.argv.index('--output') + 1])
record = json.loads(output.read_text())
record['resource_lifecycle_tracer_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
record['resource_lifecycle_boundary'] = __doc__
output.write_text(json.dumps(record, indent=2) + '\n')
