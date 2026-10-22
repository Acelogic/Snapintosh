#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay the pinned TXM12 wrapper and native Image4 path before implementation.

The wrapper stops at the core loader; it never substitutes authentication.
Image4 runs include parser negatives, exact captured-tree initialization, and
optional identity/tamper controls. Only PAC mechanics, diagnostic output and
workspace provisioning are modeled. See docs/TXM-TRUST-LOAD-20260925.md.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build/test-python-deps'))
from unicorn import Uc, UcError, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
import unicorn.arm64_const as reg

TXM_SHA = 'b746aaba8d3c0874911a53bf51f9591854783aa6e7b02f25494c2d782eecd246'
MONITOR_SHA = 'b99546195df08b63d421faa15215f4dea68128f39ecfe82a79c31f70d88f934c'
CAPTURE_PINS = {
    13: (MONITOR_SHA, 'da62f681a539e4384dd815f84dec898c3e570cbccd00318d6d9e5e0a03bdb111'),
    14: ('b9f4024c191dfcee3a3d72c4ddc98227799cc17042a7704c8ae57aac18286d43',
         '3713854a229f36e7d79640c0c5c0c3f9158fdc2d6189c33904b9e754756f0f7d'),
    27: ('7654fd2a92aa5e10a2070c55392c3938777208621d5eaf357c4ed5df23b6f1ba',
         '8613fd4e512d91c94ef09283c6891b84f6b2df3ffb13a6db74628ad41901fac7'),
}
BASE = 0xfffffff017000000
LINK_BASE = BASE
WRAPPER, CORE, IMAGE4 = BASE + 0x3f8b4, BASE + 0x3a37c, BASE + 0x45754
RUNTIME, RESULT = BASE + 0x20400, 0x1010000
PAYLOAD, MANIFEST, STACK, STOP = 0x1040000, 0x1050000, 0x11dfc00, 0x11f0000
MODULE, DYNAMIC, CONFIG, QUERY = 0x1080000, 0x1090000, 0x10a0000, 0x10e0000
PRIOR_PAYLOAD, PRIOR_MODULE = 0x1060000, MODULE + 0x200
APP_PAYLOAD, APP_MODULE = 0x1070000, MODULE + 0x300
LIBRARY = BASE + 0x46ac8
REGS = [getattr(reg, 'UC_ARM64_REG_X' + str(n)) for n in range(31)]


def main():
    global BASE, WRAPPER, CORE, IMAGE4, RUNTIME, LIBRARY
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    ap.add_argument('--image4', action='store_true', help='also explore the native Image4 path')
    ap.add_argument('--device-tree', type=Path,
                    help='add native Image4 initialization using the exact audited guest tree')
    ap.add_argument('--instruction-limit', type=int, default=20000000)
    ap.add_argument('--cpro-control', action='store_true',
                    help='diagnose CPRO with one changed byte in a private tree copy; never updates the guest')
    ap.add_argument('--sdom-control', action='store_true',
                    help='after the CPRO control, diagnose adding the signed ticket SDOM1 to that private copy')
    ap.add_argument('--tamper-controls', action='store_true',
                    help='replay payload, manifest-signature and certificate-signature corruption with the identity control')
    ap.add_argument('--profile-publication', action='store_true',
                    help='qualify the installed profile identity publisher against the entire captured tree')
    ap.add_argument('--capture', type=Path,
                    default=ROOT / 'build/installed-txm-donation-300s-20260925-txm12-input.json')
    ap.add_argument('--expect-native-auth', action='store_true',
                    help='require the captured on-device tree to pass without identity overrides')
    ap.add_argument('--registration', action='store_true',
                    help='run native authentication, cache registration and UUID queries in one runtime')
    ap.add_argument('--coexist-capture', type=Path,
                    help='authenticate a pinned type13 capture before type14, then query both caches')
    ap.add_argument('--coexist-app-capture', type=Path,
                    help='also authenticate type14 after type13 before the captured type27 load')
    ap.add_argument('--portable-base', type=lambda s: int(s, 0),
                    help='relocate TXM and replace only PAC ABI instructions and diagnostic transport')
    ap.add_argument('--portable-output', type=Path,
                    help='save the replayed flat relocated image for bridge development')
    ap.add_argument('--bridge', type=Path,
                    help='run relocated routines through the compiled EL2 call/panic bridge')
    args = ap.parse_args()
    replay_source = Path(__file__).read_bytes()
    assert 10000 <= args.instruction_limit <= 200000000
    assert not args.cpro_control or (args.image4 and args.device_tree)
    assert not args.sdom_control or args.cpro_control
    assert not args.tamper_controls or args.sdom_control
    assert not args.profile_publication or (args.image4 and args.device_tree)
    assert not args.registration or args.device_tree
    assert not args.coexist_capture or (args.registration and args.device_tree)
    assert not args.coexist_app_capture or args.coexist_capture
    assert not args.expect_native_auth or (args.image4 and args.device_tree
                                          and not args.cpro_control and not args.profile_publication)
    assert not args.output.exists(), 'preserve previous evidence'
    assert not args.portable_output or (args.portable_base and not args.portable_output.exists())
    assert not args.bridge or args.portable_base
    if args.portable_base is not None:
        assert 0x20000000 <= args.portable_base <= 0xf0000000 and args.portable_base % 0x4000 == 0
        BASE = args.portable_base
        WRAPPER, CORE, IMAGE4 = BASE + 0x3f8b4, BASE + 0x3a37c, BASE + 0x45754
        RUNTIME, LIBRARY = BASE + 0x20400, BASE + 0x46ac8
    sha = lambda b: hashlib.sha256(b).hexdigest()
    sys.path.insert(0, str(ROOT / 'probes'))
    from txmnative import relocate
    relocator_sha = sha((ROOT / 'probes/txmnative.py').read_bytes())
    raw = (ROOT / 'downloads/extracted/j700ap/txm.macosx.release').read_bytes()
    bridge = args.bridge.read_bytes() if args.bridge else None
    flat, fixes, patches = relocate(raw, BASE, bridge)
    capture_path = args.capture
    capture_raw = capture_path.read_bytes()
    capture = json.loads(capture_raw)
    assert capture['source_bound'] and capture['selector'] == 12
    cache_type = capture['cache_type']
    assert cache_type in CAPTURE_PINS
    assert capture['monitor_sha256'] == CAPTURE_PINS[cache_type][0]
    tree = args.device_tree.read_bytes() if args.device_tree else None
    if tree is not None:
        assert sha(tree) == capture['tree_sha256']
    inputs = {}
    for name in ('payload', 'manifest'):
        part = capture[name]
        data = bytes.fromhex(part['hex'])
        assert len(data) == part['bytes'] and sha(data) == part['sha256']
        assert part['sha256'] == {
            'payload': CAPTURE_PINS[cache_type][1],
            'manifest': '76c9cfcb1c91b9d2e3a33cec7f0333ff1eb71a5e15cb51b8118877d920b15527'}[name]
        assert part['frame_metadata'] == '00002a00000000000100000000000000'
        inputs[name] = data
    prior = prior_raw = prior_inputs = None
    if args.coexist_capture:
        assert cache_type == (27 if args.coexist_app_capture else 14)
        prior_raw = args.coexist_capture.read_bytes()
        prior = json.loads(prior_raw)
        assert prior['source_bound'] and prior['selector'] == 12 and prior['cache_type'] == 13
        assert prior['monitor_sha256'] == CAPTURE_PINS[13][0]
        assert prior['tree_sha256'] == capture['tree_sha256']
        prior_inputs = {n: bytes.fromhex(prior[n]['hex']) for n in ('payload', 'manifest')}
        for n, data in prior_inputs.items():
            assert len(data) == prior[n]['bytes'] and sha(data) == prior[n]['sha256']
        assert sha(prior_inputs['payload']) == CAPTURE_PINS[13][1]
        assert prior_inputs['manifest'] == inputs['manifest']
    app_raw = app_inputs = None
    if args.coexist_app_capture:
        app_raw=args.coexist_app_capture.read_bytes(); app_capture=json.loads(app_raw)
        assert app_capture['source_bound'] and app_capture['selector']==12 and app_capture['cache_type']==14
        assert app_capture['monitor_sha256']==CAPTURE_PINS[14][0] and app_capture['tree_sha256']==capture['tree_sha256']
        app_inputs={n:bytes.fromhex(app_capture[n]['hex']) for n in ('payload','manifest')}
        for n,data in app_inputs.items():
            assert len(data)==app_capture[n]['bytes'] and sha(data)==app_capture[n]['sha256']
        assert sha(app_inputs['payload'])==CAPTURE_PINS[14][1] and app_inputs['manifest']==inputs['manifest']

    def native(words, start, mode, payload=None, manifest=None, initialize=False, tree_override=None):
        u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        u.ctl_set_cpu_model(reg.UC_CPU_ARM64_MAX)
        u.mem_map(BASE, 0x200000)
        u.mem_write(BASE, bytes(flat))
        u.mem_map(0x1000000, 0x200000)
        use_bridge = bool(bridge) and mode != 'wrapper'
        if use_bridge:
            u.reg_write(reg.UC_ARM64_REG_PSTATE, 0x3c9)  # EL2h, masked exceptions.
        if initialize:
            active_tree = tree if tree_override is None else tree_override
            assert active_tree is not None and len(active_tree) < 0x100000
            u.mem_map(0x1200000, 0x100000)
            u.mem_write(0x1200000, active_tree)
            # Native secure-DT context is {base, length}; 3db6c returns it only
            # when the boot initialization bit is set. No chosen fields change.
            u.mem_write(BASE + 0x203e0, struct.pack('<QQ', 0x1200000, len(active_tree)))
            u.mem_write(BASE + 0x203f0, b'\1')
            # The native stack ABI reserves its last 0x400 bytes for thread
            # state. Supply workspace; acquisition/release executes natively.
            u.mem_map(0x1300000, 0x100000)
            u.mem_write(STACK, b'\1')
            u.mem_write(STACK + 0x60, struct.pack('<QQQ', 0x1300000, 0x100000, 0x100000))
        u.mem_write(PAYLOAD, inputs['payload'] if payload is None else payload)
        u.mem_write(MANIFEST, inputs['manifest'] if manifest is None else manifest)
        if prior_inputs and mode == 'registration':
            u.mem_write(PRIOR_PAYLOAD, prior_inputs['payload'])
            if app_inputs:u.mem_write(APP_PAYLOAD, app_inputs['payload'])
        if mode == 'registration':
            # Empty native runtime/list storage. The library requires its
            # configuration pointer to be present; no callback result is
            # replaced, and all Image4 policy/crypto runs natively.
            u.mem_write(RUNTIME, bytes(0x30))
            u.mem_write(RUNTIME, struct.pack('<Q', CONFIG))
            u.mem_write(RUNTIME + 0x20, struct.pack('<Q', DYNAMIC))
            u.mem_write(QUERY, inputs['payload'][23 + 4:23 + 20])
        u.reg_write(reg.UC_ARM64_REG_CPACR_EL1, 3 << 20)
        u.reg_write(reg.UC_ARM64_REG_SP, STACK)
        u.reg_write(reg.UC_ARM64_REG_X30, STOP)
        for n, value in enumerate(words):
            u.reg_write(REGS[n], value)
        event = {'pac_modeled': 0, 'instructions': 0, 'calls': [], 'stages': {}}
        el2_control = dict(cptr=0x400, reads=0, writes=0)
        def q(at):
            return struct.unpack('<Q', u.mem_read(at, 8))[0]
        def hook(uc, at, size, context):
            event['instructions'] += 1
            word, = struct.unpack('<I', uc.mem_read(at, 4))
            if use_bridge and word & ~31 in (0xd53c1140, 0xd51c1140):
                # Unicorn raises on CPTR_EL2 even with the EL2h PSTATE fixture.
                # Model only this control register; the bridge's save, mask,
                # restore and all native Image4 instructions still execute.
                index = word & 31
                assert index < 31
                if word & ~31 == 0xd53c1140:
                    uc.reg_write(REGS[index], el2_control['cptr'])
                    el2_control['reads'] += 1
                else:
                    el2_control['cptr'] = uc.reg_read(REGS[index])
                    el2_control['writes'] += 1
                uc.reg_write(reg.UC_ARM64_REG_PC, at + 4)
                return
            if initialize and at == BASE + 0x68bcc:
                name = bytes(uc.mem_read(uc.reg_read(REGS[2]), 128)).split(b'\0', 1)[0]
                event.setdefault('dt_queries', []).append(name.decode('utf8', 'replace'))
            if initialize and at == BASE + 0x39cc4 and args.portable_base is None:
                # TXM's diagnostic ring is a transport dependency, not an
                # authentication result. Retain the format and argument bytes
                # instead of requiring a native ring/atomic counter here.
                address = uc.reg_read(REGS[0])
                fmt = bytes(uc.mem_read(address, 384)).split(b'\0', 1)[0]
                values = bytes(uc.mem_read(uc.reg_read(REGS[1]), 48))
                event.setdefault('modeled_diagnostic_log', []).append(
                    dict(format=fmt.decode('utf8', 'replace'), arguments_hex=values.hex()))
                uc.reg_write(REGS[0], 0)
                uc.reg_write(reg.UC_ARM64_REG_PC, uc.reg_read(REGS[30]))
                return
            for pc, stage in ((BASE + 0x45880, 'manifest_init'),
                              (BASE + 0x458a4, 'payload_init'),
                              (BASE + 0x458c4, 'environment_init'),
                              (BASE + 0x4596c, 'manifest_evaluate'),
                              (BASE + 0x45988, 'payload_evaluate')):
                if at == pc:
                    event['stages'][stage] = hex(uc.reg_read(REGS[0]))
            if mode == 'wrapper' and at == BASE + 0x41aa8:
                uc.reg_write(REGS[0], RESULT)
                uc.reg_write(reg.UC_ARM64_REG_PC, uc.reg_read(REGS[30]))
                return
            if mode == 'wrapper' and at == CORE:
                event['core'] = dict(cache_type=uc.reg_read(REGS[0]),
                    regions=[[hex(q(uc.reg_read(REGS[n]) + i * 8)) for i in range(3)]
                             for n in (1, 2)])
                uc.emu_stop()
                return
            if at == BASE + 0x3d818 and not use_bridge:
                event['panic'] = [hex(uc.reg_read(REGS[n])) for n in (0, 1)]
                event['panic_lr'] = hex(uc.reg_read(REGS[30]))
                uc.emu_stop()
                return
            if at == BASE + 0x3d60c and not use_bridge:
                event['platform_panic'] = hex(uc.reg_read(REGS[0]))
                uc.emu_stop()
                return
            if word in (0xd503237f, 0xd50323ff, 0xd503233f, 0xd50323bf):
                event['pac_modeled'] += 1
                uc.reg_write(reg.UC_ARM64_REG_PC, at + 4)
            elif word == 0xd65f0fff:
                event['pac_modeled'] += 1
                uc.reg_write(reg.UC_ARM64_REG_PC, uc.reg_read(REGS[30]))
            elif word & 0xfffffc00 in (0xdac10000, 0xdac10400, 0xdac10800, 0xdac10c00,
                                      0xdac11000, 0xdac11400, 0xdac11800, 0xdac11c00):
                # Register PAC/AUT operate on unsigned rebased addresses here.
                event['pac_modeled'] += 1
                uc.reg_write(reg.UC_ARM64_REG_PC, at + 4)
            elif word & 0xfffffc00 in (0xd73f0800, 0xd73f0c00, 0xd71f0800, 0xd71f0c00):
                target = uc.reg_read(REGS[(word >> 5) & 31])
                event['pac_modeled'] += 1
                if (word & 0xfffffc00) in (0xd73f0800, 0xd73f0c00):
                    uc.reg_write(REGS[30], at + 4)
                uc.reg_write(reg.UC_ARM64_REG_PC, target)
            elif word & 0xfc000000 == 0x94000000:
                imm = word & 0x3ffffff
                if imm & 0x2000000:
                    imm -= 0x4000000
                target = at + imm * 4
                event['calls'].append(hex(target))
                if len(event['calls']) > 60:
                    event['calls'].pop(0)
        u.hook_add(UC_HOOK_CODE, hook)
        def invoke(entry, limit):
            if not use_bridge:
                u.emu_start(entry, STOP, count=limit)
                return
            native_sp = u.reg_read(reg.UC_ARM64_REG_SP)
            arguments = [u.reg_read(REGS[n]) for n in range(8)]
            saved_regs = [u.reg_read(REGS[n]) for n in range(19, 30)]
            # A guest trap is not a C caller: every full SIMD register is live.
            # Distinct high/low halves expose the old d8..d15-only bridge.
            simd = [getattr(reg, 'UC_ARM64_REG_Q' + str(n)) for n in range(32)]
            saved_fp = [(0xfedcba9876540000 + n) << 64 | (0x123456789abc0000 + n)
                        for n in range(32)]
            for register, value in zip(simd, saved_fp):
                u.reg_write(register, value)
            saved_control = [u.reg_read(reg.UC_ARM64_REG_FPCR), u.reg_read(reg.UC_ARM64_REG_FPSR)]
            parameters = 0x1020000
            u.mem_write(parameters, struct.pack('<16Q', BASE, native_sp, entry, *arguments, *([0] * 5)))
            u.reg_write(REGS[0], parameters)
            u.reg_write(REGS[30], STOP)
            host_sp = 0x11bf000
            u.reg_write(reg.UC_ARM64_REG_SP, host_sp)
            u.emu_start(BASE + 0x100000, STOP, count=limit)
            result = struct.unpack('<16Q', u.mem_read(parameters, 128))
            returned = u.reg_read(reg.UC_ARM64_REG_PC) == STOP
            preserved = (saved_regs == [u.reg_read(REGS[n]) for n in range(19, 30)]
                         and saved_fp == [u.reg_read(register) for register in simd]
                         and saved_control == [u.reg_read(reg.UC_ARM64_REG_FPCR), u.reg_read(reg.UC_ARM64_REG_FPSR)]
                         and el2_control['cptr'] == 0x400
                         and u.reg_read(reg.UC_ARM64_REG_SP) == host_sp)
            event.setdefault('bridge_calls', []).append(dict(entry=hex(entry), returned=returned,
                normal=result[15], panic=[hex(result[12]), hex(result[13])],
                status=hex(result[14]), callee_state_preserved=preserved,
                guest_simd_preserved=saved_fp == [u.reg_read(register) for register in simd]))
            if returned:
                assert preserved and u.reg_read(REGS[0]) == result[14], event['bridge_calls'][-1]
                if not result[15]:
                    event['bridge_panic'] = [hex(result[12]), hex(result[13])]
                u.reg_write(reg.UC_ARM64_REG_SP, native_sp)
        try:
            ready = True
            if initialize:
                invoke(BASE + 0x791a0, 2000000)
                ready = u.reg_read(reg.UC_ARM64_REG_PC) == STOP
                event['platform_init'] = dict(returned=ready,
                    pc=hex(u.reg_read(reg.UC_ARM64_REG_PC)), instructions=event['instructions'])
                event['calls'] = []
                u.reg_write(reg.UC_ARM64_REG_SP, STACK)
                u.reg_write(REGS[30], STOP)
                for n, value in enumerate(words):
                    u.reg_write(REGS[n], value)
            if ready:
                if prior_inputs and mode == 'registration':
                    # Authenticate the original OS payload first in this same
                    # runtime, including when the following App input is corrupt.
                    active_manifest = bytes(u.mem_read(MANIFEST, len(inputs['manifest'])))
                    u.mem_write(MANIFEST, prior_inputs['manifest'])
                    for n, value in enumerate([RUNTIME, 13, PRIOR_MODULE, PRIOR_PAYLOAD,
                            len(prior_inputs['payload']), MANIFEST, len(prior_inputs['manifest'])]):
                        u.reg_write(REGS[n], value)
                    invoke(LIBRARY, args.instruction_limit)
                    assert u.reg_read(reg.UC_ARM64_REG_PC) == STOP and u.reg_read(REGS[0]) == 1
                    event['prior_load'] = dict(status='0x1',
                        module_hex=bytes(u.mem_read(PRIOR_MODULE, 32)).hex(),
                        lists=[hex(q(x)) for x in (RUNTIME + 0x10, RUNTIME + 0x18, DYNAMIC, DYNAMIC + 8)])
                    if app_inputs:
                        u.reg_write(reg.UC_ARM64_REG_SP,STACK);u.reg_write(REGS[30],STOP)
                        for n,value in enumerate([RUNTIME,14,APP_MODULE,APP_PAYLOAD,
                                len(app_inputs['payload']),MANIFEST,len(app_inputs['manifest'])]):
                            u.reg_write(REGS[n],value)
                        invoke(LIBRARY,args.instruction_limit)
                        assert u.reg_read(reg.UC_ARM64_REG_PC)==STOP and u.reg_read(REGS[0])==1
                        event['app_load']=dict(status='0x1',module_hex=bytes(u.mem_read(APP_MODULE,32)).hex())
                        assert q(DYNAMIC)==APP_MODULE and q(APP_MODULE)==PRIOR_MODULE
                    u.mem_write(MANIFEST, active_manifest)
                    u.reg_write(reg.UC_ARM64_REG_SP, STACK)
                    u.reg_write(REGS[30], STOP)
                    for n, value in enumerate(words):
                        u.reg_write(REGS[n], value)
                invoke(start, args.instruction_limit)
            if mode == 'registration' and u.reg_read(reg.UC_ARM64_REG_PC) == STOP:
                def snapshot():
                    return dict(returned=u.reg_read(reg.UC_ARM64_REG_PC) == STOP,
                        status=hex(u.reg_read(REGS[0])),
                        lists=[hex(q(x)) for x in (RUNTIME + 0x10, RUNTIME + 0x18,
                                                   DYNAMIC, DYNAMIC + 8)],
                        module_hex=bytes(u.mem_read(MODULE, 32)).hex(),
                        prior_module_hex=bytes(u.mem_read(PRIOR_MODULE, 32)).hex(),
                        app_module_hex=bytes(u.mem_read(APP_MODULE, 32)).hex(),
                        spare_module_hex=bytes(u.mem_read(MODULE + 0x100, 32)).hex())
                event['registration'] = [dict(name='first-load', **snapshot())]
                followups = [
                        ('uuid-hit', BASE + 0x463dc, [RUNTIME, QUERY, RESULT]),
                        ('duplicate-load', LIBRARY, [RUNTIME, cache_type, MODULE + 0x100,
                         PAYLOAD, len(inputs['payload']), MANIFEST, len(inputs['manifest'])]),
                        ('uuid-miss', BASE + 0x463dc, [RUNTIME, QUERY + 0x40, RESULT + 8])]
                if prior_inputs:
                    followups.append(('prior-uuid-hit', BASE + 0x463dc,
                                      [RUNTIME, PRIOR_PAYLOAD + 27, RESULT + 16]))
                    followups.append(('prior-duplicate-load', LIBRARY,
                        [RUNTIME, 13, MODULE + 0x100, PRIOR_PAYLOAD,
                         len(prior_inputs['payload']), MANIFEST, len(prior_inputs['manifest'])]))
                if app_inputs:
                    followups.extend([
                        ('app-uuid-hit',BASE+0x463dc,[RUNTIME,APP_PAYLOAD+27,RESULT+24]),
                        ('app-duplicate-load',LIBRARY,[RUNTIME,14,MODULE+0x100,APP_PAYLOAD,
                            len(app_inputs['payload']),MANIFEST,len(app_inputs['manifest'])])])
                if u.reg_read(REGS[0]) != 1:
                    followups = []
                for name, entry, params in followups:
                    u.reg_write(reg.UC_ARM64_REG_SP, STACK)
                    u.reg_write(REGS[30], STOP)
                    for n, value in enumerate(params):
                        u.reg_write(REGS[n], value)
                    invoke(entry, args.instruction_limit)
                    event['registration'].append(dict(name=name, **snapshot()))
                    if u.reg_read(reg.UC_ARM64_REG_PC) != STOP:
                        break
                if followups and u.reg_read(reg.UC_ARM64_REG_PC) == STOP:
                    hashes = []
                    caches = [(cache_type, PAYLOAD, inputs['payload'])]
                    if prior_inputs:
                        caches.append((13, PRIOR_PAYLOAD, prior_inputs['payload']))
                    if app_inputs:
                        caches.append((14, APP_PAYLOAD, app_inputs['payload']))
                    for typ, location, data in caches:
                        count, = struct.unpack_from('<I', data, 43)
                        for kind in (range(4) if prior_inputs else (2,)):
                            for index in range(count):
                                address = location + 23 + 24 + index * 24
                                u.mem_write(RESULT + 0x20, bytes(16))
                                u.reg_write(reg.UC_ARM64_REG_SP, STACK)
                                u.reg_write(REGS[30], STOP)
                                for n, value in enumerate([RUNTIME, kind, address, 20, RESULT + 0x20]):
                                    u.reg_write(REGS[n], value)
                                invoke(BASE + 0x46668, args.instruction_limit)
                                hashes.append(dict(index=index, cache_type=typ, kind=kind,
                                    returned=u.reg_read(reg.UC_ARM64_REG_PC) == STOP,
                                    status=hex(u.reg_read(REGS[0])),
                                    module=hex(q(RESULT + 0x20)), entry=hex(q(RESULT + 0x28))))
                    event['cdhash_queries'] = hashes
        except UcError as error:
            event['emulation_error'] = str(error)
        event['pc'] = hex(u.reg_read(reg.UC_ARM64_REG_PC))
        event['x0'] = hex(u.reg_read(REGS[0]))
        event['returned'] = u.reg_read(reg.UC_ARM64_REG_PC) == STOP
        event['instruction_limit'] = args.instruction_limit
        event['budget_exhausted'] = not event['returned'] and not any(
            k in event for k in ('panic', 'platform_panic', 'core', 'emulation_error'))
        event['output'] = [hex(q(RESULT + i * 8)) for i in range(10)]
        event['input_unchanged'] = (
            bytes(u.mem_read(PAYLOAD, len(inputs['payload']))) ==
            (inputs['payload'] if payload is None else payload) and
            bytes(u.mem_read(MANIFEST, len(inputs['manifest']))) ==
            (inputs['manifest'] if manifest is None else manifest))
        if mode == 'cache-parse':
            event['module_hex'] = bytes(u.mem_read(MODULE, 32)).hex()
        if prior_inputs and mode == 'registration':
            event['prior_input_unchanged'] = bytes(u.mem_read(PRIOR_PAYLOAD,
                len(prior_inputs['payload']))) == prior_inputs['payload']
            event['prior_module_unchanged'] = bytes(u.mem_read(PRIOR_MODULE, 32)).hex() == event['prior_load']['module_hex']
            if app_inputs:
                event['app_input_unchanged']=bytes(u.mem_read(APP_PAYLOAD,len(app_inputs['payload'])))==app_inputs['payload']
                event['app_module_unchanged']=bytes(u.mem_read(APP_MODULE,32)).hex()==event['app_load']['module_hex']
        if use_bridge:
            event['modeled_el2_control'] = el2_control
        if initialize:
            event['device_tree_sha256'] = sha(active_tree)
            event['scratch'] = dict(pa='0x1300000', bytes=0x100000,
                acquired=bytes(u.mem_read(STACK + 0x78, 1)).hex(),
                boundary='Replay workspace only; native allocator acquisition/release executes unchanged.')
        return event

    words = [cache_type, PAYLOAD, len(inputs['payload']), MANIFEST, len(inputs['manifest'])]
    cases = [('captured', words, None)]
    for name, n in [('payload', 1), ('manifest', 3)]:
        for label, index, value, code in [
                ('null', n, 0, 0x40), ('empty', n + 1, 0, 0x41),
                ('unaligned', n, words[n] + 1, 0xc0),
                ('round-overflow', n + 1, (1 << 64) - 1, 0x43),
                ('range-overflow', n, (1 << 64) - 0x4000, 0x42)]:
            changed = list(words)
            changed[index] = value
            cases.append((name + '-' + label, changed, code))
    rows = []
    for name, params, code in cases:
        result = native(params, WRAPPER, 'wrapper')
        if code is None:
            assert result.get('core') == dict(cache_type=cache_type, regions=[
                [hex(PAYLOAD), '0x4000', hex(len(inputs['payload']))],
                [hex(MANIFEST), '0x4000', hex(len(inputs['manifest']))]]), result
        else:
            assert result.get('panic') == [hex(code), '0x0'] and 'core' not in result, result
        assert result['input_unchanged'] and all(v == '0x0' for v in result['output'])
        rows.append(dict(name=name, result=result))
    exploration = []
    if args.image4:
        params = [RUNTIME, cache_type, PAYLOAD, len(inputs['payload']),
                  MANIFEST, len(inputs['manifest']), RESULT, RESULT + 8]
        variations = [('captured-zero-runtime', params, None, None, 0x8a002)]
        for part, status in [('payload', 0x7a402), ('manifest', 0x6a102)]:
            for label, offset in [('bad-sequence', 0), ('bad-magic', 6)]:
                changed = bytearray(inputs[part])
                changed[offset] ^= 1
                variations.append((part + '-' + label, params,
                                   bytes(changed) if part == 'payload' else None,
                                   bytes(changed) if part == 'manifest' else None, status))
            short = list(params)
            short[3 if part == 'payload' else 5] -= 1
            variations.append((part + '-truncated', short, None, None, status))
        wrong_tag = bytearray(inputs['payload'])
        wrong_tag[15] ^= 1
        variations.append(('payload-wrong-tag', params, bytes(wrong_tag), None, 0x7a402))
        for invalid_type, status in [(0, 0x12102), (1, 0x22102), (2, 0x32102), (28, 0x42102)]:
            changed = list(params)
            changed[1] = invalid_type
            variations.append((f'cache-type-{invalid_type}', changed, None, None, status))
        for name, params, payload, manifest, expected in variations:
            result = native(params, IMAGE4, 'image4', payload, manifest)
            assert result['returned'] and result['x0'] == hex(expected), (name, result)
            assert result['input_unchanged'] and all(v == '0x0' for v in result['output'])
            assert 'manifest_evaluate' not in result['stages']
            assert 'payload_evaluate' not in result['stages']
            exploration.append(dict(name=name, result=result))
        if tree is not None:
            params = [RUNTIME, cache_type, PAYLOAD, len(inputs['payload']),
                      MANIFEST, len(inputs['manifest']), RESULT, RESULT + 8]
            baseline = native(params, IMAGE4, 'image4', initialize=True)
            assert baseline['returned']
            if args.expect_native_auth:
                assert baseline['x0'] == '0x2'
                assert baseline['stages']['manifest_evaluate'] == '0x0'
                assert baseline['stages']['payload_evaluate'] == '0x0'
                assert baseline['output'] == [hex(PAYLOAD + 23), hex(len(inputs['payload']) - 23)] + ['0x0'] * 8
            else:
                assert baseline['x0'] == '0xca302'
                assert baseline['stages']['manifest_evaluate'] == '0x138a'
            assert baseline['scratch']['acquired'] == '00' and baseline['input_unchanged']
            exploration.append(dict(name='captured-native-device-tree-init', result=baseline))
            if args.cpro_control:
                sys.path.insert(0, str(ROOT / 'probes'))
                from appledt import DeviceTree
                control = DeviceTree(tree)
                assert control.get('/device-tree/chosen', 'certificate-production-status') == bytes(4)
                control.set_u32('/device-tree/chosen', 'certificate-production-status', 1)
                altered = control.serialize()
                assert len(altered) == len(tree)
                changes = [dict(offset=i, before=a, after=b) for i, (a, b)
                           in enumerate(zip(tree, altered)) if a != b]
                assert len(changes) == 1 and changes[0]['before'] == 0 and changes[0]['after'] == 1
                one_field = native(params, IMAGE4, 'image4', initialize=True, tree_override=altered)
                assert one_field['returned'] and one_field['x0'] == '0xca302'
                assert one_field['stages']['manifest_evaluate'] == '0x1389'
                assert one_field['scratch']['acquired'] == '00' and one_field['input_unchanged']
                exploration.append(dict(name='diagnostic-cpro-only-one-byte', changes=changes,
                    result=one_field,
                    boundary='One-field diagnostic only; guest tree, SSD and signing policy are unchanged.'))
                if args.sdom_control:
                    original = DeviceTree(tree)
                    assert 'security-domain' not in original.nodes['/device-tree/chosen']
                    control.put('/device-tree/chosen', 'security-domain', struct.pack('<I', 1))
                    altered = control.serialize()
                    check = DeviceTree(altered)
                    assert set(check.nodes) == set(original.nodes)
                    fields = []
                    for path, props in check.nodes.items():
                        assert set(original.nodes[path]) <= set(props)
                        for key, prop in props.items():
                            old = original.nodes[path].get(key)
                            if old is None or (old.value, old.placeholder) != (prop.value, prop.placeholder):
                                fields.append((path, key, old.value.hex() if old else None, prop.value.hex()))
                    assert sorted(fields) == sorted([
                        ('/device-tree/chosen', 'certificate-production-status', '00000000', '01000000'),
                        ('/device-tree/chosen', 'security-domain', None, '01000000')])
                    positive = native(params, IMAGE4, 'image4', initialize=True, tree_override=altered)
                    assert positive['returned'] and positive['x0'] == '0x2'
                    assert positive['stages']['manifest_evaluate'] == '0x0'
                    assert positive['stages']['payload_evaluate'] == '0x0'
                    assert positive['output'] == [hex(PAYLOAD + 23), hex(len(inputs['payload']) - 23)] + ['0x0'] * 8
                    assert positive['scratch']['acquired'] == '00' and positive['input_unchanged']
                    exploration.append(dict(name='diagnostic-cpro-and-sdom', changed_properties=fields,
                        result=positive,
                        boundary='Two-field diagnostic only; neither guest identity nor signing policy is changed.'))
                    if args.tamper_controls:
                        # Offsets are bound to this exact captured IM4M: outer
                        # signature is OCTET STRING [1246,1758); the sole signer
                        # certificate BIT STRING [3064,3577) has one unused-bit byte.
                        assert inputs['manifest'][1242:1246] == bytes.fromhex('04820200')
                        assert inputs['manifest'][3060:3065] == bytes.fromhex('0382020100')
                        for name, part, offset in [('payload-entry', 'payload', len(inputs['payload']) - 1),
                                                   ('manifest-signature', 'manifest', 1246),
                                                   ('certificate-signature', 'manifest', 3065)]:
                            changed = bytearray(inputs[part])
                            changed[offset] ^= 1
                            result = native(params, IMAGE4, 'image4',
                                payload=bytes(changed) if part == 'payload' else None,
                                manifest=bytes(changed) if part == 'manifest' else None,
                                initialize=True, tree_override=altered)
                            assert result['returned'] and int(result['x0'], 16) & 0xff00, (name, result)
                            assert result['output'] == ['0x0'] * 10 and result['input_unchanged']
                            assert result['scratch']['acquired'] == '00'
                            exploration.append(dict(name='tamper-' + name, part=part, offset=offset,
                                sha256=sha(changed), result=result,
                                boundary='Native authentication failure with DER structure and identity control retained.'))
    publication = None
    if args.profile_publication:
        sys.path.insert(0, str(ROOT / 'probes'))
        from appledt import DeviceTree
        from guestprofile import get_profile
        from chipid import populate_image4_identity
        from dataclasses import replace
        profile = get_profile('j700ap-26A428-xars-uniform-auxkc-installed')
        candidate = DeviceTree(tree)
        populate_image4_identity(candidate, profile.chip_id_boot)
        published = candidate.serialize()
        assert sha(published) == '4ecd09995644831be124a7039efef3bbd1efc8a49e427757e3a11f05bab4e5f6'
        populate_image4_identity(candidate, profile.chip_id_boot)
        assert candidate.serialize() == published, 'publisher is not idempotent'
        unchanged = DeviceTree(tree)
        populate_image4_identity(unchanged, get_profile('j700ap-26A428-xars-uniform-auxkc').chip_id_boot)
        assert unchanged.serialize() == tree, 'BaseSystem identity must remain unchanged'
        refused = []
        for case in ('domain-conflict', 'malformed-cpro', 'wrong-chip', 'wrong-board'):
            candidate = DeviceTree(tree)
            spec = profile.chip_id_boot
            if case == 'domain-conflict':
                candidate.put('/device-tree/chosen', 'security-domain', struct.pack('<I', 2))
            elif case == 'malformed-cpro':
                candidate.put('/device-tree/chosen', 'certificate-production-status', b'\0')
            elif case == 'wrong-chip':
                spec = replace(spec, chip_id=0x8150)
            else:
                spec = replace(spec, board_id=0x65)
            before = candidate.serialize()
            try:
                populate_image4_identity(candidate, spec)
            except ValueError:
                assert candidate.serialize() == before, 'refusal changed tree'
                refused.append(case)
            else:
                raise AssertionError('publisher accepted ' + case)
        params = [RUNTIME, cache_type, PAYLOAD, len(inputs['payload']),
                  MANIFEST, len(inputs['manifest']), RESULT, RESULT + 8]
        verified = native(params, IMAGE4, 'image4', initialize=True, tree_override=published)
        assert verified['returned'] and verified['x0'] == '0x2'
        assert verified['stages']['manifest_evaluate'] == '0x0'
        assert verified['stages']['payload_evaluate'] == '0x0'
        assert verified['input_unchanged'] and verified['scratch']['acquired'] == '00'
        publication = dict(profile=profile.name, tree_sha256=sha(published),
            refused=refused, base_system_unchanged=True, idempotent=True,
            source_sha256={f: sha((ROOT / f).read_bytes()) for f in
                           ('probes/chipid.py', 'probes/guestprofile.py', 'probes/xnuboot.py')},
            result=verified, boundary='Actual profile publisher plus native authentication; hardware publication still requires a fresh boot.')
    registration = None
    cache_parser = []
    copy_policy = []
    if args.registration:
        params = [RUNTIME, cache_type, MODULE, PAYLOAD, len(inputs['payload']),
                  MANIFEST, len(inputs['manifest'])]
        good = native(params, LIBRARY, 'registration', initialize=True)
        sequence = good.get('registration', [])
        expected_status = ['0x1', '0x5', '0x82301', '0x32405'] + (['0x5', '0x82301'] if prior_inputs else [])
        if app_inputs:expected_status+=['0x5','0x82301']
        assert [s['status'] for s in sequence] == expected_status, good
        module = struct.pack('<QQQQ', APP_MODULE if app_inputs else (PRIOR_MODULE if prior_inputs else 0),
                             cache_type, len(inputs['payload']) - 23, PAYLOAD + 23).hex()
        for step in sequence:
            assert step['returned'] and step['module_hex'] == module
            assert step['spare_module_hex'] == bytes(32).hex()
            assert step['lists'] == ['0x0', '0x0', hex(MODULE), '0x0']
        assert good['input_unchanged'] and good['scratch']['acquired'] == '00'
        count = struct.unpack_from('<I', inputs['payload'], 43)[0]
        if prior_inputs:
            count = 4 * (count + struct.unpack_from('<I', prior_inputs['payload'], 43)[0] +
                         (struct.unpack_from('<I',app_inputs['payload'],43)[0] if app_inputs else 0))
            assert good['prior_input_unchanged'] and good['prior_module_unchanged']
        if app_inputs:assert good['app_input_unchanged'] and good['app_module_unchanged']
        assert len(good['cdhash_queries']) == count
        for query in good['cdhash_queries']:
            assert query['returned']
            if query['kind'] in (0, 2):
                location, expected_module = (PAYLOAD, MODULE) if query['cache_type'] == cache_type else (PRIOR_PAYLOAD, PRIOR_MODULE)
                if app_inputs and query['cache_type']==14:location,expected_module=APP_PAYLOAD,APP_MODULE
                assert query['status'] == '0x10' and query['module'] == hex(expected_module), query
                assert query['entry'] == hex(location + 23 + 24 + query['index'] * 24), query
            else:
                assert query['status'] == '0x12411' and query['module'] == query['entry'] == '0x0', query
        registration = [dict(name='authenticated-registration', result=good)]
        for label, which, offset in [('payload-corrupt', 'payload', -1),
                                      ('manifest-signature-corrupt', 'manifest', 1246),
                                      ('certificate-signature-corrupt', 'manifest', 3065)]:
            changed = bytearray(inputs[which]); changed[offset] ^= 1
            result = native(params, LIBRARY, 'registration', initialize=True, **{which: bytes(changed)})
            assert result['returned'] and int(result['x0'], 16) & 0xff00
            step, = result['registration']
            assert step['lists'] == ['0x0', '0x0', hex(APP_MODULE) if app_inputs else (hex(PRIOR_MODULE) if prior_inputs else '0x0'), '0x0']
            assert step['module_hex'] == bytes(32).hex()
            assert result['input_unchanged'] and result['scratch']['acquired'] == '00'
            if prior_inputs:
                assert result['prior_input_unchanged'] and result['prior_module_unchanged']
            if app_inputs:assert result['app_input_unchanged'] and result['app_module_unchanged']
            registration.append(dict(name=label, result=result))
        inner_length = len(inputs['payload']) - 23
        for label, length, edit in [('captured', inner_length, None),
                ('short-header', 23, None), ('truncated-entry', inner_length - 1, None),
                ('trailing-byte', inner_length + 1, None),
                ('unknown-version', inner_length, (0, 3)),
                ('count-overflow', inner_length, (20, 0xffffffff))]:
            changed = bytearray(inputs['payload'])
            if edit:
                struct.pack_into('<I', changed, 23 + edit[0], edit[1])
            result = native([MODULE, PAYLOAD + 23, length], BASE + 0x468e0,
                            'cache-parse', payload=bytes(changed))
            expected = {'captured': 4, 'short-header': 0x12647,
                        'truncated-entry': 0x52647, 'trailing-byte': 4,
                        'unknown-version': 0x32149, 'count-overflow': 0x52647}[label]
            assert result['returned'] and int(result['x0'], 16) == expected
            assert result['input_unchanged']
            expected_module = (struct.pack('<QQQQ', 0, 0xff, length, PAYLOAD + 23)
                               if expected == 4 else bytes(32))
            assert result['module_hex'] == expected_module.hex()
            cache_parser.append(dict(name=label, result=result))
        for length in (0, 1, 3599, 8192, 8193, 16384):
            result = native([length], BASE + 0x3c494, 'copy-policy')
            assert result['returned'] and result['x0'] == hex(int(1 <= length <= 8192))
            copy_policy.append(dict(length=length, copied=int(result['x0'], 16)))
    assert Path(__file__).read_bytes() == replay_source, 'replay source changed while running'
    assert sha((ROOT / 'probes/txmnative.py').read_bytes()) == relocator_sha
    bridge_panics = []
    if bridge:
        for offset in (0x3d818, 0x3d60c, 0x3d99c):
            result = native([0x123, 0x456], BASE + offset, 'bridge-panic')
            assert result['returned'] and result['bridge_panic'] == ['0x123', '0x456']
            assert result['x0'] == '0xffffffffffffffff'
            bridge_panics.append(result)
    if args.portable_base is not None:
        results = [x['result'] for x in rows + exploration + (registration or []) + cache_parser]
        assert results and all(r['pac_modeled'] == 0 for r in results)
        if args.portable_output:
            with args.portable_output.open('xb') as f:
                f.write(flat)
    record = dict(replay_sha256=sha(replay_source), relocator_sha256=relocator_sha,
                  txm_sha256=TXM_SHA, capture_sha256=sha(capture_raw), cache_type=cache_type,
                  capture_path=str(capture_path), expected_native_auth=args.expect_native_auth,
                  coexist_capture_path=str(args.coexist_capture) if prior_raw else None,
                  coexist_capture_sha256=sha(prior_raw) if prior_raw else None,
                  coexist_app_capture_path=str(args.coexist_app_capture) if app_raw else None,
                  coexist_app_capture_sha256=sha(app_raw) if app_raw else None,
                  fixups=len(fixes), tree_sha256=sha(tree) if tree is not None else None,
                  wrapper_cases=rows, image4_exploration=exploration,
                  profile_publication=publication,
                  registration=registration,
                  cache_parser=cache_parser, copy_policy=copy_policy,
                  portable=dict(base=hex(BASE), image_sha256=sha(flat), patches=patches,
                                bridge_sha256=sha(bridge) if bridge else None,
                                bridge_panic_cases=bridge_panics,
                                image_path=str(args.portable_output) if args.portable_output else None)
                           if args.portable_base is not None else None,
                  boundary='Wrapper region validation only; core loader is a stop, not a success stub. '
                           'Image4 negative controls use uninitialized platform state; the optional exact-tree '
                           'initialization is recorded separately. Optional registration executes native '
                           'authentication, list insertion, UUID and CDHash lookups with an empty runtime fixture; '
                           'it does not execute core ownership transfer or qualify on-device cache registration.')
    with args.output.open('x') as f:
        json.dump(record, f, indent=2)
        f.write('\n')
    print(json.dumps(dict(output=str(args.output), wrapper_cases=len(rows),
        image4=[dict(name=x['name'], returned=x['result']['returned'], status=x['result']['x0'],
                     stages=x['result']['stages']) for x in exploration],
        profile_publication=bool(publication), registration_cases=len(registration or []),
        cache_parser_cases=len(cache_parser), copy_policy=copy_policy,
        boundary=record['boundary']), indent=2))


if __name__ == '__main__':
    main()
