#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The plug-in's submission waits, end to end on this Mac (agents/present-sync FAILURE-MODES.md S1-S7; no GPU, no A16).

Core Animation (26A428 MetalContext::flush(true)) ends a frame with commitAndWaitUntilSubmitted and swaps once it
returns; WindowServer's queue has a submission queue, so -commit alone only enqueues. The Adreno kext runs a command
buffer to completion inside the kernel submission, so "submitted" means "drawn". The harness
(gpu/adreno-kext/plugin/harness/present-sync.m) replaces -[IOGPUMetalCommandQueue submitCommandBuffers:count:] with a
stand-in for that synchronous kernel path and checks:
  ws-queue / ws-deadline  each commitAndWaitUntilSubmitted (and the deadline form) returns only after the stand-in
                          finished that command buffer; the kernel commands hold encoded work and one FENCE, last
  async-commit            plain -commit still returns at once while the submission queue is blocked
  blocked-queue           with the submission queue blocked 600 ms the wait returns at its 250 ms bound, YES
  self-queue              called on the submission queue itself: returns at the bound (no deadlock)
  refused                 an encoding refusal still raises at once
  ca-renderer             Core Animation's own frames (CARenderer on the plug-in device): the commit variants it sends
                          (CARenderer's context commits plainly; WindowServer's IOMFBDisplay context, created with flags
                          0, flushes with commitAndWaitUntilSubmitted), and every command buffer it waited for was finished
                          by the frame's end
--expect-before: the unchanged plug-in must fail (its wait returns before the submission).
--pipeline (agents/gpu-pipeline FAILURE-MODES.md U1-U3, C1): the cases above, then the same bundle against the pipelined
kext's stand-in (one IB on the GPU at a time; the submission returns once its IB started; IOGPU's completion follows at
the GPU end):
  ws-queue-pipe           commitAndWaitUntilSubmitted returns once queued, before the GPU end; all complete in order
  complete-pipe           completed handlers, waitUntilCompleted and the staging arenas' recycling after the GPU end
  overlap-fps             5 ms CPU + 13.4 ms GPU frames: pipelined approaches 1000 / 13.4, synchronous stays at 1000 / 18.4
  shadow-pipe             an unaligned IOSurface's shadow is refilled only after the command buffer using it finished
With --pipeline --expect-before the plug-in built without -DADRENO_PIPELINE must pass every case but shadow-pipe and fail
that one (its refill does not wait).

    python3 tools/test-adreno-present-sync.py --bundle BUNDLE --output NEW-DIR [--expect-before] [--pipeline]
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / 'gpu/adreno-kext/plugin/harness'
CASES = ['ws-queue', 'ws-deadline', 'async-commit', 'blocked-queue', 'self-queue', 'refused', 'ca-renderer']
PIPE_CASES = ['ws-queue-pipe', 'complete-pipe', 'overlap-fps', 'shadow-pipe']


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--bundle', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--expect-before', action='store_true')
    ap.add_argument('--pipeline', action='store_true')
    args = ap.parse_args()
    cases = CASES + (PIPE_CASES if args.pipeline else [])
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    lib, exe = out / 'default-device-interpose.dylib', out / 'present-sync'
    subprocess.run(['xcrun', 'clang', '-dynamiclib', '-arch', 'arm64e', str(HARNESS / 'default-device-interpose.m'), '-o',
                    str(lib), '-framework', 'Foundation', '-framework', 'Metal'], check=True)
    subprocess.run(['xcrun', 'clang', '-arch', 'arm64e', '-fobjc-arc', '-O1', str(HARNESS / 'present-sync.m'), '-o', str(exe),
                    '-framework', 'Foundation', '-framework', 'Metal', '-framework', 'QuartzCore', '-framework', 'IOSurface',
                    '-framework', 'IOKit', '-framework', 'CoreGraphics'], check=True)
    for f in (lib, exe):
        subprocess.run(['codesign', '-f', '-s', '-', str(f)], check=True, capture_output=True)
    env = {'DYLD_INSERT_LIBRARIES': str(lib), 'PATH': '/usr/bin:/bin'}
    if args.pipeline:
        env['PS_PIPELINE'] = '1'
    run = subprocess.run([str(exe), str(args.bundle.resolve()), str(out / 'capture')], capture_output=True, text=True,
                         timeout=900, env=env)
    (out / 'harness.log').write_text(run.stdout + run.stderr)
    failures = []
    try:
        report = json.loads((out / 'capture' / 'report.json').read_text())
    except (OSError, ValueError) as e:
        report = {}
        failures.append(f'no report ({e}); harness exit {run.returncode}')
    for name in cases:
        case = report.get(name)
        if case is None:
            failures.append(f'{name}: did not run')
            continue
        failures += [f'{name}: {f}' for f in case.get('failed', [])]
    if report.get('bad_kernel_commands'):
        failures.append(f'{report["bad_kernel_commands"]} command buffers with malformed kernel commands')
    summary = {k: report.get(k) for k in cases}
    (out / 'result.json').write_text(json.dumps({'failures': failures, 'cases': summary, 'pipeline': args.pipeline,
                                                 'expect_before': args.expect_before}, indent=1, sort_keys=True) + '\n')
    ws = report.get('ws-queue') or {}
    ca = report.get('ca-renderer') or {}
    line = (f'ws-queue {ws.get("kernel_done_at_return")}/{ws.get("command_buffers")} finished at return '
            f'(mean wait {ws.get("mean_wait_ms", 0):.2f} ms); Core Animation: {ca.get("ca_commit_and_wait")} '
            f'commitAndWaitUntilSubmitted in {ca.get("frames")} frames, '
            f'{ca.get("waited_commits_finished_at_frame_end")}/{ca.get("waited_commits")} finished at the frame end')
    if args.pipeline:
        fps = report.get('overlap-fps') or {}
        line += (f'; pipelined stand-in: {fps.get("pipelined_fps", 0):.1f} fps against {fps.get("sync_fps", 0):.1f} '
                 f'synchronous (13.4 ms GPU + 5 ms CPU)')
    if args.expect_before and args.pipeline:
        # The plug-in without -DADRENO_PIPELINE: the commit semantics are the kext's (it passes those), the shadow
        # refill does not wait (it must fail shadow-pipe, and only that).
        shadow = [f for f in failures if f.startswith('shadow-pipe:')]
        other = [f for f in failures if not f.startswith('shadow-pipe:')]
        if shadow and not other:
            print(f'PASS (expect-before, pipeline): the plug-in without the define fails only shadow-pipe ({len(shadow)}); {line}')
            for f in shadow:
                print(f'  {f}')
            return 0
        print(f'FAIL (expect-before, pipeline): shadow-pipe failures {len(shadow)}, other failures {len(other)}; {line}')
        for f in failures:
            print(f'  {f}')
        return 1
    if args.expect_before:
        if failures:
            print(f'PASS (expect-before): the unchanged plug-in fails {len(failures)} checks; {line}')
            for f in failures[:12]:
                print(f'  {f}')
            return 0
        print(f'FAIL (expect-before): the unchanged plug-in passed every check; {line}')
        return 1
    if failures:
        print(f'FAIL: {len(failures)} checks; {line}')
        for f in failures:
            print(f'  {f}')
        return 1
    print(f'PASS: {report.get("checks")} checks; {line}; {out / "result.json"}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
