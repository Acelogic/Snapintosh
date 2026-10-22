#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Replay 26A428 SkyLight's Metal-device gate: why WindowServer aborts.

WindowServer's WSInitialize calls WSCompositorActivateDefault, whose
activate_compositor_default once-block runs WSSystemCanCompositeWithMetal's
once-block. That block asks Metal for every device (with an add-observer),
waits a fixed interval for one, and otherwise formats
"No suitable Metal devices present after %llu seconds.", stores it as the
crash-reporter message and calls abort(). abort() sends SIGABRT to its own
thread through __pthread_kill (SVC 328), so the kernel creates a corpse,
AMFI refuses the core dump, launchd respawns WindowServer and ReportCrash
starts: the loop seen in every long run.

This runs the original instructions from the mounted BaseSystem dyld cache
under unicorn. libdispatch, Metal, os_log, libc and objc calls are explicit
fixtures chosen per scenario; PAC instructions are stepped over. It also
proves statically that no returning path of WSInitialize skips the call.
Offline evidence from Apple's code, not a physical run.
"""
from pathlib import Path
import argparse
import hashlib
import runpy
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'build/test-python-deps'))
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED  # noqa: E402
import unicorn.arm64_const as reg  # noqa: E402
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM  # noqa: E402

Cache = runpy.run_path(str(ROOT / 'tools/dyld-cache.py'))['Cache']
DEFAULT_CACHE = Path('/Volumes/macOS Base System/System/Library/dyld')
SKYLIGHT = '/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/SkyLight'

# Unslid 26A428 BaseSystem addresses. Each is re-derived from the cache's own
# symbol table (or instruction bytes) at startup; a different cache fails.
FUNCTIONS = {
    'metal_block': ('___WSSystemCanCompositeWithMetal_block_invoke', 0x18708b508, 0x18708b6e8),
    'default_block': ('____ZL27activate_compositor_defaultv_block_invoke', 0x186fe4e08, 0x186fe4e60),
    'activate_default': ('_WSCompositorActivateDefault', 0x186fe3bc8, 0x186fe3c68),
    'ws_initialize': ('_WSInitialize', 0x187232c10, 0x187235ba8),
}
# SHA-256 of each function's original instruction bytes in the 26A428 cache.
CODE_SHA256 = {
    'metal_block': 'dfb6c49d4b433c6c255c9dc4fb483247165d6b4d22f7a6b30341a0e62e9b5b04',
    'default_block': '445f003c88f33e119423ee012a718c464be7011dd31c93812851ecd59936990c',
    'activate_default': '8fcfff438082c4c89dc5b4b29d0683b4959558170e3c87703a1e2f9fe9e76d20',
    'ws_initialize': 'b061364d2db16d9b0d386f6955c140e5926c507199d5a624ed6d5e467ddee1c9',
}
METAL_ACTIVATE = ('__ZL25activate_compositor_metalb', 0x186fe36a0)
SW_ACTIVATE = ('__ZL22activate_compositor_swb', 0x186fe3730)
SLS_LOG_BREAK = ('_SLSLogBreak', 0x1870fbcf0)
CALL_SITE = 0x187235770            # WSInitialize: bl _WSCompositorActivateDefault
METAL_LOVIN = 0x1c39d44a8          # WSSystemCanCompositeWithMetal()::metal_lovin
METAL_ONCE = 0x1c39d44b0
USE_SOFTWARE = 0x1c39d3e40         # read by WSCompositorActivateDefault
INIT_ONCE = 0x1c39d3e28            # initialize_compositors
DEFAULT_ONCE = 0x1c39d3e38         # activate_compositor_default
CR_MESSAGE = 0x1c39cea28           # _gCRAnnotations + 8 (crash-log message)
METAL_LITERAL = 0x1c560c518        # block literal passed to dispatch_once(METAL_ONCE)
DEFAULT_LITERAL = 0x1c560b018
GUARD_SLOT = 0x1c003a970           # -> ___stack_chk_guard
ABORT_TEXT = 'No suitable Metal devices present after %llu seconds.'
ABSENT_TEXT = 'Metal device initially absent.'
TIMEOUT_NS = 30_000_000_000

LIBS = ['/usr/lib/system/libdispatch.dylib', '/usr/lib/system/libsystem_c.dylib',
        '/usr/lib/system/libsystem_trace.dylib', '/usr/lib/libobjc.A.dylib',
        '/System/Library/Frameworks/Metal.framework/Versions/A/Metal']
NORETURN = {'_abort', '_abort_report_np', '___stack_chk_fail'}

STACK = 0x10000000
HEAP = 0x10100000
RETURN = 0x10200000
GUARD = 0x10300000
GUARD_VALUE = 0x5a17c0de5a17c0de
SEM, ARRAY, OBSERVER, TOKEN = 0xa000, 0xb000, 0xc000, 0xd000


class Replay:
    def __init__(self, cache_dir):
        self.cache = Cache(cache_dir)
        self.md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.symbols = {}
        for path in [SKYLIGHT, *LIBS]:
            for address, name, kind, _ in self.cache.symbols(path):
                if address and (kind & 0x0e) == 0x0e:
                    self.symbols.setdefault(address, name)
        self.by_name = {}
        for address, name in self.symbols.items():
            self.by_name.setdefault(name, set()).add(address)
        for key, (name, start, end) in FUNCTIONS.items():
            assert start in self.by_name.get(name, ()), f'{name} is not at {start:#x}'
        for name, address in (METAL_ACTIVATE, SW_ACTIVATE, SLS_LOG_BREAK):
            assert address in self.by_name.get(name, ()), f'{name} is not at {address:#x}'
        self.code = {}
        for key, (_, start, end) in FUNCTIONS.items():
            raw = self.cache.read(start, end - start)
            self.code[key] = hashlib.sha256(raw).hexdigest()
            for ins in self.md.disasm(raw, start):
                self.code.setdefault('insn', {})[ins.address] = ins
        self.insn = self.code.pop('insn')
        self.stubs = {}

    # ------------------------------------------------------------ resolution
    def stub(self, address):
        """Name a call target: an auth stub, an objc selector stub or code."""
        if address in self.stubs:
            return self.stubs[address]
        name = self.symbols.get(address)
        if name is None:
            ins = list(self.md.disasm(self.cache.read(address, 16), address))
            ops = [i.mnemonic for i in ins]
            if ops[:4] == ['adrp', 'add', 'ldr', 'braa']:
                slot = int(ins[0].op_str.split('#')[1], 16) + int(ins[1].op_str.split('#')[1], 16)
                try:
                    target = self.cache.pointer_target(slot) & ((1 << 48) - 1)
                    name = self.symbols.get(target, f'?{target:#x}')
                except ValueError:
                    # Not a chained pointer: an unresolved stub. The path
                    # proof treats it as returning, which can only add paths.
                    name = f'?stub:{address:#x}'
            elif ops[:3] == ['adrp', 'add', 'b'] and ins[0].op_str.startswith('x1,'):
                selector = int(ins[0].op_str.split('#')[1], 16) + int(ins[1].op_str.split('#')[1], 16)
                name = 'objc:' + self.cache.string(selector)
            else:
                name = f'?{address:#x}'
        self.stubs[address] = name
        return name

    # ------------------------------------------------------------ emulation
    def machine(self, seeds):
        u = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        mapped = set()

        def page(address):
            base = address & ~0xfff
            if base not in mapped:
                u.mem_map(base, 0x1000)
                mapped.add(base)
                return True
            return False

        for key, (_, start, end) in FUNCTIONS.items():
            for base in range(start & ~0xfff, (end + 0xfff) & ~0xfff, 0x1000):
                if page(base):
                    u.mem_write(base, self.cache.read(base, 0x1000))
        for base in (STACK, HEAP, RETURN, GUARD):
            for n in range(0, 0x10000 if base in (STACK, HEAP) else 0x1000, 0x1000):
                page(base + n)
        for address, value in seeds.items():
            page(address)
            u.mem_write(address, struct.pack('<Q', value))
        u.mem_write(GUARD, struct.pack('<Q', GUARD_VALUE))

        def unmapped(uc, access, address, size, value, _):
            # Read-only cache data (strings, constants) is real; writable data
            # the block touches is either seeded above or starts as zero.
            if not 0x180000000 <= address < 0x200000000:
                return False
            base = address & ~0xfff
            page(base)
            try:
                lo, hi, off, path, view, prot = self.cache.locate(base)
                if not prot & 2:
                    uc.mem_write(base, self.cache.read(base, 0x1000))
            except ValueError:
                pass
            return True

        u.hook_add(UC_HOOK_MEM_UNMAPPED, unmapped)
        u.reg_write(reg.UC_ARM64_REG_CPACR_EL1, 3 << 20)
        u.reg_write(reg.UC_ARM64_REG_SP, STACK + 0xf000)
        u.reg_write(reg.UC_ARM64_REG_X30, RETURN)
        return u

    def run(self, entry, seeds, fixtures, stop=()):
        u = self.machine(seeds)
        events = []
        state = dict(stopped=None, heap=HEAP)

        def x(n):
            return u.reg_read(getattr(reg, f'UC_ARM64_REG_X{n}'))

        def ret(pc, value=None):
            if value is not None:
                u.reg_write(reg.UC_ARM64_REG_X0, value)
            u.reg_write(reg.UC_ARM64_REG_PC, pc + 4)

        def string(address):
            if 0x180000000 <= address < 0x200000000:
                return self.cache.string(address)     # constant cache strings
            data = bytes(u.mem_read(address, 256))
            return data.split(b'\0', 1)[0].decode()

        def hook(uc, pc, size, _):
            if pc in stop:
                state['stopped'] = pc
                uc.emu_stop()
                return
            ins = self.insn.get(pc)
            assert ins is not None, f'execution left the replayed functions at {pc:#x}'
            m = ins.mnemonic
            if m in ('pacibsp', 'autibsp', 'pacda', 'pacia', 'autda', 'xpacd', 'paciza'):
                uc.reg_write(reg.UC_ARM64_REG_PC, pc + 4)
                return
            if m == 'retab':
                uc.reg_write(reg.UC_ARM64_REG_PC, x(30))
                return
            if m == 'brk':
                raise AssertionError(f'trap at {pc:#x}')
            if m in ('bl', 'b') and ins.op_str.startswith('#'):
                target = int(ins.op_str[1:], 16)
                if target in self.insn and target not in stop:
                    return
                if m == 'b' and target in stop:
                    state['stopped'] = target
                    uc.emu_stop()
                    return
                name = SLS_LOG_BREAK[0] if target == SLS_LOG_BREAK[1] else self.stub(target)
                args = [x(n) for n in range(6)]
                sp = u.reg_read(reg.UC_ARM64_REG_SP)
                handler = fixtures.get(name)
                assert handler is not None, f'unmodelled call {name} at {pc:#x}'
                result = handler(dict(args=args, sp=sp, mem=u, string=string, state=state))
                events.append((name, args, result))
                if name in NORETURN:
                    state['stopped'] = name
                    uc.emu_stop()
                    return
                if m == 'b':        # tail call: return to our caller
                    if result is not None:
                        u.reg_write(reg.UC_ARM64_REG_X0, result)
                    uc.reg_write(reg.UC_ARM64_REG_PC, x(30))
                    return
                ret(pc, result)
                return

        u.hook_add(UC_HOOK_CODE, hook)
        u.emu_start(entry, RETURN, count=5000)
        if state['stopped'] is None:
            assert u.reg_read(reg.UC_ARM64_REG_PC) == RETURN, 'did not return'
            state['stopped'] = 'return'
        read = lambda address: struct.unpack('<Q', bytes(u.mem_read(address, 8)))[0]
        return events, state, read

    # ------------------------------------------------------------ scenarios
    def metal_block(self, initial_devices, device_arrives):
        seeds = {GUARD_SLOT: GUARD, METAL_LOVIN: 0, CR_MESSAGE: 0}
        seen = dict(signaled=0, observer=None)

        def asprintf(call):
            u, sp = call['mem'], call['sp']
            fmt = call['string'](call['args'][1])
            value = struct.unpack('<Q', bytes(u.mem_read(sp, 8)))[0]  # Darwin varargs
            text = fmt.replace('%llu', str(value)).encode() + b'\0'
            where = call['state']['heap']
            call['state']['heap'] += 0x100
            u.mem_write(where, text)
            u.mem_write(call['args'][0], struct.pack('<Q', where))
            call['state']['asprintf'] = (fmt, value, text[:-1].decode(), where)
            return len(text) - 1

        def observer_copy(call):
            u = call['mem']
            u.mem_write(call['args'][0], struct.pack('<Q', OBSERVER))
            seen['observer'] = call['args'][1]
            return ARRAY

        def signal(call):
            assert call['args'][0] == SEM
            seen['signaled'] += 1
            return 0

        def wait(call):
            assert call['args'][0] == SEM and call['args'][1] == TOKEN
            return 0 if seen['signaled'] or device_arrives else 1

        def log(call):
            call['state'].setdefault('logs', []).append(call['string'](call['args'][3]))

        fixtures = {
            '_dispatch_semaphore_create': lambda call: SEM,
            '_MTLCopyAllDevicesWithObserver': observer_copy,
            'objc:count': lambda call: initial_devices,
            '_dispatch_semaphore_signal': signal,
            '_os_log_type_enabled': lambda call: 1,
            '__os_log_impl': log,
            '__os_log_error_impl': log,
            '_dispatch_time': lambda call: TOKEN,
            '_dispatch_semaphore_wait': wait,
            '_dispatch_release': lambda call: None,
            '_MTLRemoveDeviceObserver': lambda call: None,
            '_objc_release': lambda call: None,        # objc_release_x0 alias
            '_asprintf': asprintf,
            '_SLSLogBreak': lambda call: None,
            '_abort': lambda call: None,
            '___stack_chk_fail': lambda call: None,
        }
        events, state, read = self.run(FUNCTIONS['metal_block'][1], seeds, fixtures)
        return events, state, read, seen

    def default_block(self, metal_lovin, once_done):
        seeds = {METAL_LOVIN: metal_lovin, METAL_ONCE: (1 << 64) - 1 if once_done else 0,
                 USE_SOFTWARE: 0}
        calls = []
        fixtures = {'_dispatch_once': lambda call: calls.append(call['args'][:2])}
        events, state, read = self.run(FUNCTIONS['default_block'][1], seeds, fixtures)
        return calls, read(USE_SOFTWARE) & 0xff, state

    def activate(self, use_software, once_done):
        done = (1 << 64) - 1 if once_done else 0
        seeds = {INIT_ONCE: done, DEFAULT_ONCE: done, USE_SOFTWARE: use_software}
        calls = []
        fixtures = {'_dispatch_once': lambda call: calls.append(call['args'][:2])}
        events, state, read = self.run(FUNCTIONS['activate_default'][1], seeds, fixtures,
                                       stop={METAL_ACTIVATE[1], SW_ACTIVATE[1]})
        return calls, state['stopped']

    # ------------------------------------------------------------ static proof
    def initialize_paths(self):
        """Every returning path of WSInitialize passes CALL_SITE.

        Explore WSInitialize from its entry without executing CALL_SITE. Calls
        fall through except the named noreturn functions; conditional branches
        take both edges. Any ret reached means a path skips the call."""
        name, start, end = FUNCTIONS['ws_initialize']
        call = self.insn[CALL_SITE]
        assert call.mnemonic == 'bl' and int(call.op_str[1:], 16) == FUNCTIONS['activate_default'][1]
        seen, work, rets, indirect, noreturn = set(), [start], [], [], 0
        while work:
            pc = work.pop()
            while start <= pc < end and pc not in seen:
                seen.add(pc)
                if pc == CALL_SITE:
                    break
                ins = self.insn[pc]
                m, op = ins.mnemonic, ins.op_str
                if m in ('ret', 'retab'):
                    rets.append(pc)
                    break
                if m in ('br', 'braa', 'braaz'):
                    indirect.append(pc)
                    break
                if m == 'brk':
                    break
                if m == 'bl' and op.startswith('#'):
                    target = int(op[1:], 16)
                    if self.stub(target) in NORETURN:
                        noreturn += 1
                        break
                if m == 'b' and op.startswith('#'):
                    target = int(op[1:], 16)
                    if not start <= target < end:
                        indirect.append(pc)   # tail call out of the function
                        break
                    pc = target
                    continue
                if m.startswith('b.') or m in ('cbz', 'cbnz', 'tbz', 'tbnz'):
                    work.append(int(op.rsplit('#', 1)[1], 16))
                pc += 4
        return dict(explored=len(seen), rets_without_call=rets, indirect_exits=indirect,
                    noreturn_calls=noreturn)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--cache', type=Path, default=DEFAULT_CACHE)
    args = parser.parse_args()
    if not (args.cache / 'dyld_shared_cache_arm64e.map').is_file():
        raise SystemExit(f'{args.cache}: 26A428 BaseSystem dyld cache not mounted')
    r = Replay(args.cache)
    checks = 0

    def check(condition, message):
        nonlocal checks
        assert condition, message
        checks += 1

    for key, digest in r.code.items():
        check(digest == CODE_SHA256[key], f'{key} bytes differ from 26A428: {digest}')
        print(f'{key}: sha256 {digest}')
    # Scenario 1: no Metal device, none arrives -> abort with the message.
    events, state, read, seen = r.metal_block(0, False)
    names = [e[0] for e in events]
    check(state['stopped'] == '_abort', f'no-device block ended at {state["stopped"]}')
    check(names[:3] == ['_dispatch_semaphore_create', '_MTLCopyAllDevicesWithObserver', 'objc:count'],
          f'order {names[:3]}')
    check('_dispatch_semaphore_signal' not in names, 'no device must not signal')
    time_call = [e for e in events if e[0] == '_dispatch_time'][0]
    check(time_call[1][0] == 0 and time_call[1][1] == TIMEOUT_NS,
          f'dispatch_time({time_call[1][0]:#x}, {time_call[1][1]}) is not NOW + 30 s')
    fmt, value, text, where = state['asprintf']
    check(fmt == ABORT_TEXT and value == 30, f'asprintf {fmt!r} {value}')
    check(text == 'No suitable Metal devices present after 30 seconds.', text)
    check(read(CR_MESSAGE) == where, 'message is not the crash-reporter annotation')
    check(ABSENT_TEXT in state['logs'] and '%{public}s' in state['logs'], state['logs'])
    check(read(METAL_LOVIN) & 0xff == 0, 'metal_lovin set on the abort path')
    check(names[-3:] == ['_SLSLogBreak', '_os_log_type_enabled', '__os_log_error_impl'] or
          names[-4:-1] == ['_SLSLogBreak', '_os_log_type_enabled', '__os_log_error_impl'], names)
    check('_MTLRemoveDeviceObserver' not in names, 'abort path removed the observer')
    print('no device: waits NOW+30 s, then abort() with', repr(text))
    # Scenario 2: a device is present at once -> signal, metal_lovin=1, return.
    events, state, read, seen = r.metal_block(1, False)
    names = [e[0] for e in events]
    check(state['stopped'] == 'return', f'device-present block ended at {state["stopped"]}')
    check(names.index('_dispatch_semaphore_signal') < names.index('_dispatch_semaphore_wait'), names)
    check(read(METAL_LOVIN) & 0xff == 1 and '_abort' not in names, 'device present')
    check('_MTLRemoveDeviceObserver' in names and read(CR_MESSAGE) == 0, 'observer/annotation')
    print('device present: metal_lovin=1, no abort')
    # Scenario 3: no device initially, the observer fires before the deadline.
    events, state, read, seen = r.metal_block(0, True)
    names = [e[0] for e in events]
    check(state['stopped'] == 'return' and read(METAL_LOVIN) & 0xff == 1, 'late device')
    check('_asprintf' not in names and seen['observer'] is not None, 'late device')
    print('device arrives within 30 s: metal_lovin=1, no abort')
    # activate_compositor_default: software only when metal_lovin==0.
    for lovin, software in ((1, 0), (0, 1)):
        calls, flag, state = r.default_block(lovin, True)
        check(not calls and flag == software, f'metal_lovin={lovin} -> software flag {flag}')
    calls, flag, state = r.default_block(1, False)
    check(len(calls) == 1 and calls[0] == [METAL_ONCE, METAL_LITERAL], f'once call {calls}')
    check(r.cache.pointer_target(METAL_LITERAL + 0x10) & ((1 << 48) - 1) == FUNCTIONS['metal_block'][1],
          'metal once literal invokes the Metal block')
    print('activate_compositor_default: software compositor only if metal_lovin==0')
    # WSCompositorActivateDefault: tail-branches on the software flag.
    for software, target in ((0, METAL_ACTIVATE[1]), (1, SW_ACTIVATE[1])):
        calls, stopped = r.activate(software, True)
        check(not calls and stopped == target, f'software={software} -> {stopped}')
    calls, stopped = r.activate(0, False)
    check([c[0] for c in calls] == [INIT_ONCE, DEFAULT_ONCE] and calls[1][1] == DEFAULT_LITERAL, calls)
    check(r.cache.pointer_target(DEFAULT_LITERAL + 0x10) & ((1 << 48) - 1) == FUNCTIONS['default_block'][1],
          'default once literal invokes activate_compositor_default')
    print('WSCompositorActivateDefault: Metal compositor unless the software flag is set')
    # WSInitialize always makes the call before it can return.
    proof = r.initialize_paths()
    check(not proof['rets_without_call'] and not proof['indirect_exits'], proof)
    check(proof['noreturn_calls'] >= 1 and proof['explored'] > 1000, proof)
    print(f'WSInitialize: {proof["explored"]} instructions explored, no return path skips '
          f'the call at {CALL_SITE:#x} ({proof["noreturn_calls"]} noreturn exits)')
    print(f'{checks} checks passed')


if __name__ == '__main__':
    main()
