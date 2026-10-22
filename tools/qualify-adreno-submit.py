#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind the guest fence transport to native ABI and repeatable host artifacts.

This verifies compiled artifacts and integration replays. It does not establish
native IOGPU execution, guest framework identity, hardware fences or rendering.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--artifacts', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    out = args.artifacts.resolve()
    assert not args.output.exists()
    read = lambda name: json.loads((out/name).read_text())
    monitor = read('current/monitor/build.json')
    profile = read('current/profile/qualification-v1.json')
    resource = read('resource-abi-v1.json')
    native = read('native-v2.json')
    user = read('user-abi-v3.json')
    sources = {}
    for record in (monitor, profile, resource):
        for name, digest in record.get('source_sha256', record.get('sources_sha256', {})).items():
            assert sha(ROOT/name) == digest, name
            sources[name] = digest
    assert native['tracer_sha256'] == sha(ROOT/'tools/trace-adreno-memory-map.py')
    assert native['submit_tracer_sha256'] == sha(ROOT/'tools/trace-adreno-submit.py')
    image = next(i for i in native['images'] if i['image'] == 'IOGPUFamily')
    assert image['uuid'] == '6172533f-b127-35e2-90b8-f7b3b1f2c5b7'
    spec = importlib.util.spec_from_file_location('resource_abi', ROOT/'tools/qualify-adreno-resource-kext.py')
    abi = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(abi)
    raw, syms, segments, word_at = abi.macho(abi.KDK/'Extensions/IOGPUFamily.kext/Contents/MacOS/IOGPUFamily')
    assert hashlib.sha256(raw).hexdigest() == image['kdk_sha256']
    base = next(s[0] for s in segments if s[3] == b'__TEXT')
    kext = out/'kext-v1/AdrenoX2.kext'
    binary = kext/'Contents/MacOS/AdrenoX2'
    plugin = out/'plugin-v2/AdrenoMetal.bundle'
    for bundle in (kext, plugin):
        subprocess.run(['codesign', '--verify', '--strict', str(bundle)], check=True, capture_output=True)
    assert sha(binary) == resource['kext_sha256']
    disassembly = out/'kext-v1-disassembly.txt'
    assert sha(disassembly) == resource['disassembly_sha256']
    text = disassembly.read_text()
    prefix = '__ZN18AdrenoCommandQueue27processSegmentKernelCommand'
    code = text[text.index(prefix):].split('\n__')[0]
    contracts = []
    for slot, disc, method, compiled_slot in [(0x160, 0x967b, 'processSegmentKernelCommand', 0x170),
                                             (0x1b0, 0xe135, 'setSubmissionError', 0x1b0)]:
        word = word_at(syms['__ZTV17IOGPUCommandQueue']+16+slot)
        target = base+(word & 0xffffffff)
        names = [n for n, va in syms.items() if va == target]
        assert any(method in n for n in names), names
        assert (word >> 32)&0xffff == disc
        assert re.search(r'movk\s+x(?:16|17), #'+hex(disc)+r', lsl #48', code)
        assert re.search(r'#'+hex(compiled_slot)+r'(?:\]|$)', code, re.M)
        contracts.append(dict(slot=hex(slot), discriminator=hex(disc), method=method, target=hex(target)))
    assert re.search(r'mov\s+w1, #0xa\b', code)
    assert 'bl\t_adreno_submit_command' in code
    _, ksyms, _, kword = abi.macho(binary)
    callback = kword(ksyms['__ZTV18AdrenoCommandQueue']+16+0x160)
    assert (callback >> 32)&0xffff == 0x967b
    assert callback & 0xffffffff == next(va for n, va in ksyms.items() if n.startswith(prefix))
    error = next(f for f in image['functions'] if '18setSubmissionErrorEj' in f['symbol'])
    ops = [(i['mnemonic'], i['operands']) for i in error['instructions']]
    assert ('ldr', 'x8, [x0, #0x518]') in ops and ('str', 'w1, [x8, #0xc8]') in ops
    assert user['host_build'] == '26A428'
    cls = next(c for c in user['classes'] if c['class'] == 'IOGPUMetalCommandBuffer')
    assert cls['image']['uuid'] == '3959324F-D63D-3387-8E97-238F27A76B74'
    methods = {m['selector']:m for m in cls['methods']}
    assert methods['_reserveKernelCommandBufferSpace:']['encoding'] == '^v24@0:8Q16'
    assert methods['beginSegment:']['encoding'] == 'v24@0:8^v16'
    # Record the original executable helpers that exposed the invalid initial
    # end. Their identity is fixed to this captured host image, not the guest.
    helpers = {}
    for name in ('beginSegment:', 'endCurrentSegment'):
        targets = methods[name]['direct_targets']
        assert len(targets) == 1 and len(bytes.fromhex(targets[0]['code_hex'])) == 512
        helpers[name] = dict(offset=targets[0]['offset'],
            sha256=hashlib.sha256(bytes.fromhex(targets[0]['code_hex'])).hexdigest())
    for name, marker in [('replay-v1.log', 'PASS: 1969 '),
                         ('replay-metal-v2.log', 'PASS: 33 '),
                         ('replay-metal-before.log', 'FAILED:'),
                         ('replay-metal-native-contract-before.log', 'FAIL 20: phase == 3')]:
        assert marker in (out/name).read_text(), name
    for name in ('kext-v1-build.log', 'plugin-v2-build.log'):
        assert 'warning:' not in (out/name).read_text()
    layout = (out/'kext-layout.log').read_text()
    for clsname, fields, size in [('AdrenoAcceleratorX2', [(816,'fStamps'),(840,'fStampDMA'),
        (848,'fStampGPUAddress'),(866,'fStampCleanupFailed'),(872,'fSubmitLock'),(880,'fSubmittedFences')],888),
        ('AdrenoCommandQueue', [(1488,'fAccelerator')],1496)]:
        section = layout.split('0 | class '+clsname+'\n')[1].split('*** Dumping')[0]
        for offset, field in fields:
            assert re.search(r'\n\s*'+str(offset)+r' \|.*\b'+field+r'\b', section)
        assert '[sizeof='+str(size)+',' in section
    assert len(resource['virtual_calls']) == 22 and len(resource['callbacks']) == 7
    assert profile['preserved_model_count'] == 122
    assert profile['images']['combined']['gpu_params'][0] == 0x17
    assert '-DSNAP_CLASS_LEAF_MEMO=0' in monitor['build_defines']
    assert sha(out/'current/monitor/xnuboot.bin') == monitor['monitor_sha256']
    for path in (ROOT/'gpu/adreno-kext').rglob('*'):
        if path.is_file() and not any(p in ('out','scratch') for p in path.parts) and path.suffix in ('.c','.cpp','.h','.m','.sh','.plist'):
            sources[str(path.relative_to(ROOT))] = sha(path)
    for name in ('tools/test-adreno.c','tools/replay-adreno-metal-submit.m','tools/capture-iogpu-submit-abi.m',
                 'tools/trace-adreno-submit.py','tools/qualify-adreno-submit.py',
                 'build/build-adreno-kext-resource-20260926.py'):
        sources[name] = sha(ROOT/name)
    result = dict(status='HOST_SUBMISSION_TRANSPORT_QUALIFIED_NATIVE_EXECUTION_PENDING', boundary=__doc__,
        replay_checks=1969, plugin_replay_checks=33, resource_native_calls=22, resource_callbacks=7,
        queue_contracts=contracts, queue_callback_slot=44, host_segment_helpers=helpers,
        kext_sha256=sha(binary), plugin_sha256=sha(plugin/'Contents/MacOS/AdrenoMetal'),
        monitor_sha256=monitor['monitor_sha256'], sources_sha256=sources,
        artifacts_sha256={str(p.relative_to(out)):sha(p) for p in sorted(out.rglob('*'))
            if p.is_file() and p != args.output.resolve() and p.suffix != '.log'})
    # Bind completed evidence logs explicitly; the pending privileged AuxKC
    # log and the log receiving this qualifier's own output can still change.
    for name in ('replay-v1.log','replay-metal-v2.log','replay-metal-before.log',
                 'replay-metal-native-contract-before.log','kext-layout.log',
                 'kext-v1-build.log','plugin-v2-build.log','current-build.log'):
        result['artifacts_sha256'][name] = sha(out/name)
    args.output.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in
        ('sources_sha256','artifacts_sha256','boundary','host_segment_helpers','queue_contracts')}))


if __name__ == '__main__': main()
