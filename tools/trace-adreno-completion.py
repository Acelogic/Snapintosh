#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture original J700 synchronous segment, error and retirement ordering."""
from pathlib import Path
import hashlib
import importlib.util
import json
import sys

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('completion_trace',ROOT/'tools/trace-adreno-memory-map.py')
trace=importlib.util.module_from_spec(spec);spec.loader.exec_module(trace)
trace.TARGETS={'IOGPUFamily':('com.apple.iokit.IOGPUFamily',(
    '__ZN17IOGPUCommandQueue27processSegmentKernelCommandEP24IOGPUSegmentResourceListPK18IOGPUKernelCommandS4_PKhS6_PK34IOGPUCommandQueueCommandBufferArgs',
    '__ZN17IOGPUCommandQueue28processSegmentKernelCommandsEP24IOGPUSegmentResourceListPK18IOGPUKernelCommandS4_PKhS6_PK34IOGPUCommandQueueCommandBufferArgs',
    '__ZN17IOGPUCommandQueue14processSegmentEP24IOGPUSegmentResourceListPK18IOGPUKernelCommandS4_PKhS6_PK34IOGPUCommandQueueCommandBufferArgs',
    '__ZN17IOGPUCommandQueue20processCommandBufferEPK34IOGPUCommandQueueCommandBufferArgs',
    '__ZN17IOGPUCommandQueue18setSubmissionErrorEj',
    '__ZN17IOGPUCommandQueue18reclaimSegmentListEP24IOGPUSegmentResourceList',
    '__ZN17IOGPUCommandQueue19submitCommandBufferEPK34IOGPUCommandQueueCommandBufferArgs',
    '__ZN17IOGPUCommandQueue19retireCommandBufferEP15IOGPUEventFence',
    '__ZN17IOGPUCommandQueue21submit_command_bufferEPK34IOGPUCommandQueueCommandBufferArgs',
    '__ZN17IOGPUCommandQueue22submit_command_buffersEPK34IOGPUCommandQueueCommandBufferArgsyyPj',
    '__ZNK17IOGPUCommandQueue14work_submittedEy',
    '__ZNK17IOGPUCommandQueue14work_completedEy',
    '__ZNK17IOGPUEventMachine11finishEventEPK10IOGPUEvent',
    '__ZNK17IOGPUEventMachine11finishEventEP10IOGPUEvent',
    '__ZN17IOGPUEventMachine18forceCompleteEventEPK10IOGPUEvent',
    '__ZN17IOGPUFenceMachine19process_eventfencesEP19EventFencesListHeadb',
    '__ZN17IOGPUFenceMachine18check_event_fencesEP19EventFencesListHeadyy',
    '__ZN17IOGPUFenceMachine13notify_fencesEv',
    '__ZN17IOGPUFenceMachine26sendCompletionNotificationEP22IOGPUNotificationQueueyyyjy',
    '__ZN15IOGPUBlockFence12notifyClientEv'))}
trace.FIXED_PATH_WITNESSES={}
trace.main()
output=Path(sys.argv[sys.argv.index('--output')+1]);record=json.loads(output.read_text())
record['completion_tracer_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
record['completion_boundary']=__doc__+' Static trace only; no native execution.'
output.write_text(json.dumps(record,indent=2)+'\n')
