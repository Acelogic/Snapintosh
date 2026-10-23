#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""How a run ended decides the exit code, so the mapping needs its own test.

No hardware and no proxy: classify() takes the four things a finished run
leaves behind -- whether the guest entered, the recorded fault word, the
console text and the event log -- and every case below is one shape those can
arrive in. The point of the suite is the ordering. A run that panics has also
usually taken an exception, and a run stopped by an unimplemented endpoint has
a monitor call as its last event either way, so the branches overlap by nature
and the tests pin down which one wins.

    python3 tools/test-classify.py
"""
import importlib.util
import pathlib
import re
import struct
import sys
from source_text import read_source

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('run', ROOT / 'probes' / 'run.py')
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

MONITOR, S2_FAULT, GUEST_EXC, SYSREG, WATCHDOG = 1, 2, 3, 4, 6
DISPATCH_CMD = 8
SERROR, ASYNC = 12, 13
MMIO_STOP = 16


def event(kind, a=0):
    """One log entry: (kind, pc, a, b, c, repeats), as xnuboot_report packs it."""
    return (kind, 0xfffffe0000000000, a, 0, 0, 0)


def call(table, endpoint, cmd=0, domain=0):
    """A monitor call, as x16 packs it: cmd[63:56] domain[55:48] table[39:32]."""
    return event(MONITOR, (cmd << 56) | (domain << 48) | (table << 32) | endpoint)


def dispatch(cmd, domain=0):
    """The guest's refusal record for a call that is not an endpoint call."""
    x16 = cmd << 56 | domain << 48
    return (DISPATCH_CMD, 0xfffffe0000000000, cmd, domain, x16, 0)


checks = 0


def expect(name, got_code, want_code, reason=''):
    global checks
    checks += 1
    if got_code != want_code:
        print(f'FAIL: {name}\n  wanted {run.EXIT_NAMES[want_code]} ({want_code}), '
              f'got {run.EXIT_NAMES.get(got_code, got_code)} ({got_code}): {reason}')
        sys.exit(1)


def case(name, want, entered=1, fault=0, console='', log=(), **kwargs):
    code, reason = run.classify(entered, fault, console, list(log), **kwargs)
    expect(name, code, want, reason)


# The guest never ran. Nothing else in the log can matter, so this outranks
# every other signal -- including a stale fault word from a previous run.
case('never entered', run.EXIT_NO_ENTRY, entered=0)
case('never entered, stale fault', run.EXIT_NO_ENTRY, entered=0, fault=0x96000004)
case('never entered, events present', run.EXIT_NO_ENTRY, entered=0,
     log=[call(0, 1), event(GUEST_EXC)])

# The watchdog outranks recovered exceptions and monitor activity. An observed
# panic still identifies why the guest stopped making progress.
case('watchdog', run.EXIT_WATCHDOG, log=[call(0, 1), event(WATCHDOG)])
case('watchdog beats a trailing monitor call', run.EXIT_WATCHDOG,
     log=[event(WATCHDOG), call(0, 1)])
case('watchdog beats an exception', run.EXIT_WATCHDOG,
     log=[event(GUEST_EXC), event(WATCHDOG)])
for panic in ('panic(cpu 0): failed', 'Nested panic detected - entry count: 2'):
    case('watchdog recovery must preserve an observed panic', run.EXIT_PANIC,
         console=panic, log=[event(WATCHDOG)])
code, why = run.classify(1, 0, '', [event(GUEST_EXC),
    (26, 0xfffffe000c22b4f4, 4, 0xe57b8000, 0x10a, 0)])
expect('update refusal after a recovered exception', code, run.EXIT_UNSUPPORTED, why)
assert 'UPDATE_DISJOINT rejected' in why and '0x10a' in why
code, why = run.classify(1, 0, '', [event(GUEST_EXC),
    (42, 0x1026f8bf4, 0x1026f8bf0, 0, 4, 0)])
expect('failed EL0 witness is not successful userspace', code, run.EXIT_UNSUPPORTED, why)
assert 'EL0 execution witness rejected' in why and 'physical SPSR 0x4' in why
code, why = run.classify(1, 0, '', [event(GUEST_EXC),
    (43, 0xfffffe000c22b3c8, 1, 3, 0, 0)])
expect('panic-mode refusal survives recovered faults', code, run.EXIT_UNSUPPORTED, why)
assert 'panic-state contract stopped' in why and 'owner 0x3' in why
for kind, label in ((27, 'UPDATE_REGION'), (28, 'mapping references'), (29, 'SLIDE_REGION')):
    code, why = run.classify(1, 0, '', [event(GUEST_EXC),
        (kind, 0xfffffe000c22b4b8, 12, 0xfffffecd37fd8000, 2, 0)])
    expect(f'{label} counter failure remains a strict stop', code, run.EXIT_UNSUPPORTED, why)
    assert label in why and 'underflow' in why
# Generation78: SWITCH_ROOT needed a shared-region group with every record in
# use. The stop names that, not a generic "memory unavailable".
code, why = run.classify(1, 0, '', [event(GUEST_EXC)],
    last_event=(54, 0xfffffe000c22b6d4, 1, 0x8d4ed8000, 4096, 0))
expect('shared-group exhaustion is its own strict stop', code, run.EXIT_UNSUPPORTED, why)
assert 'group records exhausted' in why and '0x8d4ed8000' in why and '4096' in why
code, why = run.classify(1, 0, '', [event(GUEST_EXC)],
    last_event=(30, 0xfffffe000c22a96c, 8, 0xfffffe010a628000, 36, 0))
expect('TXM refusal survives saturated log', code, run.EXIT_UNSUPPORTED, why)
assert 'TXM request rejected' in why and '0x24' in why and 'not implemented' not in why

# Completed slides cannot share the TXM refusal event ID. Clock failures must
# remain visible after the bounded event log fills.
c_events = re.findall(r'^#define (EV_\w+)\s+(\d+)\b',
                     read_source(ROOT / 'probes/xnuboot.c'), re.M)
assert len({int(n) for _, n in c_events}) == len(c_events), 'duplicate event IDs'
assert run.EVENTS[31] == 'SLIDE_REGION completed'
code, why = run.classify(1, 0, '', [event(GUEST_EXC)],
    last_event=(36, 0xfffffe0008ba63ec, 1 << 9, 0, 0, 0))
expect('guest reset survives saturated log', code, run.EXIT_GUEST_RESET, why)
assert '0x200' in why and 'host reset was not issued' in why
code, why = run.classify(1, 0, '', [event(GUEST_EXC)],
    last_event=(36, 0xfffffe0008ba63ec, 1 << 63, (1 << 31) | 1, 0, 0))
expect('expanded reset bitmap survives saturated log', code, run.EXIT_GUEST_RESET, why)
assert hex((1<<95)|(1<<64)|(1<<63)) in why
assert run.EXIT_GUEST_RESET not in (run.EXIT_WATCHDOG, run.EXIT_PANIC, run.EXIT_SERROR)
code, why = run.classify(1, 0, '', [event(GUEST_EXC)],
    last_event=(34, 0xfffffe0009bc4514, (1 << 32) | 3, 0x220000030, 0x93950005, 0))
expect('virtual device refusal survives saturated log', code, run.EXIT_UNSUPPORTED, why)
assert 'model 1' in why and '0x220000030' in why and 'unknown register' in why
code, why = run.classify(1, 0, '', [event(GUEST_EXC)],
    last_event=(34, 0xfffffe0009bc474c, (1 << 32) | 6, 0x220068000, 0x93d58045, 0))
expect('virtual counter invalid value is explicit', code, run.EXIT_UNSUPPORTED, why)
assert 'unsupported register value or event index' in why
# With the registry, a refusal names its node, window offset and access.
from collections import namedtuple
Model = namedtuple('Model', 'node kind base span config')
registry = (Model('/device-tree/arm-io/mcc', 1, 0x220000000, 0x140000, (4, 0, 0, 0, 0)),
            Model('/device-tree/arm-io/sep', 45, 0x282600000, 0x9000, (8, 1, 346, 343, 15)),
            Model('/device-tree/arm-io/gpio0', 40, 0x31a000000, 0x100000, (216, 7, 0x7f, 0, 0)))
code, why = run.classify(1, 0, '', [event(GUEST_EXC)], models=registry,
    last_event=(34, 0xfffffe0009bc4514, (1 << 32) | 3, 0x220000030, 0x93950005, 0))
expect('located device refusal', code, run.EXIT_UNSUPPORTED, why)
assert '(/device-tree/arm-io/mcc +0x30, read of 4 bytes into x21)' in why, why
assert 'unknown register' in why and 'SEP' not in why
code, why = run.classify(1, 0, '', [event(GUEST_EXC)], models=registry,
    last_event=(34, 0xfffffe0009160000, (40 << 32) | 6, 0x31a0001a0, 0x938b0045, 0))
assert '(/device-tree/arm-io/gpio0 +0x1a0, write of 4 bytes from x11)' in why, why
# The SEP service refusal behind a transport-accepted STP is named as such.
code, why = run.classify(1, 0, '', [event(GUEST_EXC)], models=registry,
    last_event=(34, 0xfffffe0008b08a78, (45 << 32) | 3, 0x282608800, 0x92000045, 0))
expect('SEP service refusal', code, run.EXIT_UNSUPPORTED, why)
assert '/device-tree/arm-io/sep +0x8800, write with no syndrome' in why, why
assert 'did not recognise the submitted message' in why, why
# A kind that disagrees with the registry, or no registry, keeps the old text.
code, why = run.classify(1, 0, '', [event(GUEST_EXC)], models=registry,
    last_event=(34, 0xfffffe0009bc4514, (7 << 32) | 3, 0x220000030, 0x93950005, 0))
assert '/device-tree' not in why and '(read of 4 bytes into x21)' in why, why
code, why = run.classify(1, 0, '', [event(GUEST_EXC)],
    last_event=(34, 0xfffffe0008b08a78, (45 << 32) | 3, 0x282608800, 0x92000045, 0))
assert 'did not recognise' not in why and 'unknown register' in why, why
for reason, message in run.CLOCK_FAILURES.items():
    code, why = run.classify(1, 0, '', [event(GUEST_EXC)],
        last_event=(32, 0xfffffe000c2448fc, reason, 0x3d3c12, 0x40f, 0))
    expect('strict clock refusal survives saturated log', code, run.EXIT_UNSUPPORTED, why)
    assert message in why and '0x40f' in why
for reason,message in run.IPI_FAILURES.items():
    code,why=run.classify(1,0,'',[event(GUEST_EXC)],
        last_event=(37,0xfffffe000c1ebfe0,reason,0x317c00,0x101,0))
    expect('IPI refusal survives saturated log',code,run.EXIT_UNSUPPORTED,why)
    assert message in why and '0x101' in why

for reason,message in run.SPRR_FAILURES.items():
    code,why=run.classify(1,0,'',[event(GUEST_EXC)],
        last_event=(39,0xfffffe000ba693c4,reason,0x3bbc02,0x2010003030100000,0))
    expect('SPRR refusal survives saturated log',code,run.EXIT_UNSUPPORTED,why)
    assert message in why and '0x2010003030100000' in why

# An SError is not the watchdog.
#
# IRQ, FIQ and SError shared one vector and one event, so a bus error -- the
# guest touching a Qualcomm peripheral that does not answer -- was reported as
# "the guest was still running when its time ran out". Those are opposite
# findings and they now have opposite exit codes. The rule the transcript must
# obey: the word "watchdog" appears only when CNTHP_CTL_EL2.ISTATUS said the
# comparator fired.
def serror(esr=0x2f000000, pc=0xfffffe000b9193d0):
    '''ESR_EL2 with EC 0x2f, as the SError vector leaves it.'''
    return (SERROR, pc, esr, 0, 0, 0)


def async_other(which, pc=0xfffffe000b9193d0):
    '''An IRQ or FIQ taken to EL2 with the comparator not fired.'''
    return (ASYNC, pc, which, 0, 0, 0)


code, why = run.classify(1, 0, '', [call(0, 1), serror()])
expect('an SError is its own exit code', code, run.EXIT_SERROR, why)
assert 'watchdog' not in why.lower(), (
    'an SError must never be described as the watchdog: ' + why)
assert '0x2f000000' in why and 'fffffe000b9193d0' in why, (
    'the syndrome and the guest pc are the whole finding: ' + why)
checks += 3

# The exit code is a code of its own, not a re-use of the watchdog's.
assert run.EXIT_SERROR != run.EXIT_WATCHDOG
assert run.EXIT_SERROR in run.EXIT_NAMES
assert 'watchdog' not in run.EXIT_NAMES[run.EXIT_SERROR].lower()
checks += 3

# An SError outranks the watchdog rather than being confused with it: both are
# terminal and asynchronous, and only one of them means the timer fired.
code, why = run.classify(1, 0, '', [serror(), event(WATCHDOG)])
expect('an SError outranks a watchdog record', code, run.EXIT_SERROR, why)
checks += 1

# An IRQ or FIQ that is neither is recorded as what it is. The timer is the only
# interrupt routed to EL2, so this is an unknown, and an unknown must not be
# dressed up as either of the two things we do understand.
for which, name in ((0, 'IRQ'), (1, 'FIQ')):
    code, why = run.classify(1, 0, '', [call(0, 1), async_other(which)])
    assert code not in (run.EXIT_WATCHDOG, run.EXIT_SERROR), (
        f'a stray {name} was classified as the watchdog or an SError')
    expect(f'a stray {name} is unclassified, not the watchdog', code,
           run.EXIT_UNCLASSIFIED, why)
    assert 'watchdog' not in why.lower(), (
        f'a stray {name} must not print the word watchdog: ' + why)
    assert name in why, f'the vector it arrived at is the fact: {why}'
    checks += 4

# And a real watchdog is still a watchdog: the new branches must not swallow
# the verdict they were carved out of.
code, why = run.classify(1, 0, '', [call(0, 1), event(WATCHDOG)])
expect('the timer firing is still the watchdog', code, run.EXIT_WATCHDOG, why)
checks += 1

# A virtual ANS2 refusal (EV_ANS, compat/ans.h) names its reason and site.
code, why = run.classify(1, 0, '', [call(6, 1), (50, 0x1000, 11 << 32 | 6 << 8 | 1, 0x80, 2, 0)])
expect('virtual ANS2 SPTM refusal', code, run.EXIT_UNSUPPORTED, why)
assert 'frame' in why and 'table 6 endpoint 1' in why, why
code, why = run.classify(1, 0, '', [(50, 0x1000, 3 << 32 | 50, 0x38dcc1234, 0x93c08006, 0)])
expect('virtual ANS2 MMIO refusal', code, run.EXIT_UNSUPPORTED, why)
assert 'register' in why and '0x38dcc1234' in why, why
assert 50 in run.EVENTS
checks += 3

# Both new kinds must have a transcript label, or the log prints a bare number
# where the finding should be.
for kind in (run.EV_SERROR, run.EV_ASYNC):
    assert kind in run.EVENTS, f'event kind {kind} has no label'
    checks += 1
assert set(run.ASYNC_VECTORS) == {0, 1, 2}, 'xnuboot.S has three async vectors'
checks += 1


# Words beat syndromes. A kernel that said what it thought went wrong has told
# us more than the exception that got it there.
case('panic', run.EXIT_PANIC, console='panic(cpu 0 caller 0x0): something\n',
     log=[event(GUEST_EXC)])
case('panic, mixed case', run.EXIT_PANIC, console='PANIC: bad news\n')
case('panic outranks an unimplemented endpoint', run.EXIT_PANIC,
     console='panic(cpu 0): no\n', log=[call(7, 0x32)])
# A watchdog can recover a spinning panic handler; keep that concrete cause.
case('panic remains visible after watchdog recovery', run.EXIT_PANIC,
     console='panic(cpu 0): no\n', log=[event(WATCHDOG)])

# Exceptions the guest took, and memory it could not reach.
case('guest exception', run.EXIT_GUEST_EXC, log=[call(0, 1), event(GUEST_EXC)])
case('stage-2 fault', run.EXIT_GUEST_EXC, log=[call(0, 1), event(S2_FAULT)])
# An absent IPA inside a window the guest tree names says which node it was;
# nested windows resolve to the tightest, as xnuboot.owner_of does.
inventory = [(0x385010000, 0x4000, 'i2c0'), (0x308100000, 0xa8000, 'pmgr'),
             (0x308128000, 0x10000, 'dockchannel-uart')]
def s2(ipa):
    return run.classify(1, 0, '', [call(0, 1), (S2_FAULT, 0xfffffe000992ed20, ipa,
                                                0x93800045, 0xfffffe5000000014, 0)],
                        inventory=inventory)
code, why = s2(0x385010014)
expect('named absent window', code, run.EXIT_GUEST_EXC, why)
assert "inside the guest tree's i2c0 window +0x14 of 0x4000" in why, why
code, why = s2(0x308128004)
assert "dockchannel-uart window +0x4 of 0x10000" in why and 'pmgr' not in why, why
code, why = s2(0x308100010)
assert "pmgr window +0x10 of 0xa8000" in why, why
for ipa in (0x500000000, 0):
    code, why = s2(ipa)
    expect('unnamed stage-2 fault keeps its verdict', code, run.EXIT_GUEST_EXC, why)
    assert 'inside the guest tree' not in why, why
code, why = run.classify(1, 0, '', [call(0, 1), (S2_FAULT, 0, 0x385010014, 0x93800045, 0, 0)])
assert 'inside the guest tree' not in why, why
case('fault word with no event', run.EXIT_GUEST_EXC, fault=0x96000004,
     log=[event(SYSREG)])

# The case that needs the ordering argument: xnuboot.c logs a call before
# dispatching it, and logs it again and stops when the endpoint is not
# implemented. So a run whose LAST event is a monitor call stopped on it.
case('unimplemented endpoint', run.EXIT_UNSUPPORTED, log=[call(0, 1), call(7, 0x32)])
case('unimplemented endpoint after traffic', run.EXIT_UNSUPPORTED,
     log=[call(0, 1), event(SYSREG), call(7, 0x32)])
case('resumed exception does not hide a later refused endpoint', run.EXIT_UNSUPPORTED,
     log=[event(GUEST_EXC), call(7, 0x32)])
case('resumed exception does not hide the terminal call after overflow', run.EXIT_UNSUPPORTED,
     log=[event(GUEST_EXC)], dropped=100, last_event=call(7, 0x32))
case('resumed exception alone does not prove a fatal fault', run.EXIT_UNCLASSIFIED,
     log=[event(GUEST_EXC), event(SYSREG)])
case('unsupported return is named after a resumed fault', run.EXIT_UNSUPPORTED,
     log=[event(GUEST_EXC), event(25)])
# A monitor call that is not last is just traffic, not the reason for stopping.
case('monitor call not last is not the stop', run.EXIT_GUEST_EXC,
     log=[call(7, 0x32), event(GUEST_EXC)])

# The fault word means one thing.
#
# xnuboot_report used to write the fault syndrome into report word 6 and then
# overwrite it with the exception-return trampoline XNU registers, which it
# does early in every boot. From that call on, word 6 held a kernel code
# address; classify() tested it for non-zero and answered "a fault was
# recorded", printing a return address under the label ESR -- and
# EXIT_UNCLASSIFIED, the honest "we do not model this stop", became unreachable
# on hardware for the rest of the run.
#
# The trampoline now has a word of its own. This is the case that has to reach
# the unclassified verdict, because everything about the run says "nothing
# recognised" and only the polluted slot said otherwise.
EXC_RETURN = 0xfffffe000b86fa90     # an exception-return trampoline, shaped
                                    # like every kernel text address here

code, why = run.classify(1, EXC_RETURN, '', [event(SYSREG)])
expect('a trampoline in the fault slot is not a fault', code,
       run.EXIT_UNCLASSIFIED, why)
assert 'not a syndrome' in why, why
assert 'ESR' not in why, 'a code address must never be printed as an ESR: ' + why
checks += 3

# ...and with an entirely empty log, which is the same stop with even less to
# go on. This is the shape a truncated run arrives in.
code, why = run.classify(1, EXC_RETURN, '', [])
expect('a trampoline with no events is still unclassified', code,
       run.EXIT_UNCLASSIFIED, why)
checks += 1

# A real syndrome in that slot still means what it says, so the check is about
# the shape of the value and not about suppressing the branch.
for esr in (0x96000004,        # data abort, lower EL
            0x8600000f,        # instruction abort
            0xf2000000):       # BRK
    code, why = run.classify(1, esr, '', [event(SYSREG)])
    expect(f'a real syndrome {esr:#x} is still a fault', code,
           run.EXIT_GUEST_EXC, why)
    assert f'{esr:#x}' in why and 'ESR' in why, why
    checks += 2

# The test that decides the two apart, on its own. Every syndrome has a
# non-zero EC in bits 31:26 and nothing above bit 36; every kernel address on
# this machine has the top sixteen bits set.
assert run.is_syndrome(0x96000004)
assert run.is_syndrome(0x2f000000)
assert not run.is_syndrome(EXC_RETURN)
assert not run.is_syndrome(0xfffffe000b9193d0)
assert not run.is_syndrome(0)
assert not run.is_syndrome(0x00000004), 'EC 0 is "unknown reason", not recorded'
checks += 6

# The two live in different words, which is the whole fix: a layout where they
# share one is the bug, whatever the classifier then does about it.
FAULT_WORD_OFFSET = 16 + 6 * 8
assert run.EXC_RETURN_OFFSET != FAULT_WORD_OFFSET, (
    'the trampoline is back in the fault slot')
assert run.EXC_RETURN_OFFSET > run.COUNTERS_OFFSET, (
    'the trampoline word sits after the counters')
checks += 2


# Nothing recognised. This must not be success: it is the branch that catches
# a stop nobody has modelled yet, and calling it zero is the bug this file
# exists to prevent.
case('unrecognised stop', run.EXIT_UNCLASSIFIED, log=[event(SYSREG)])
case('no events at all', run.EXIT_UNCLASSIFIED)

# The reason strings are what a person reads first, so they must name the
# endpoint rather than leaving it to be looked up.
code, reason = run.classify(1, 0, '', [call(7, 0x32)])
assert 'UAT' in reason and '0x32' in reason, reason
checks += 1

# x16's top byte is a field of its own, and the four calls that carry it must
# never again be reported as the endpoint-0 call they used to decode as.
#
# This is the regression that motivated the whole check: commands 2, 4, 5 and 6
# all have domain, table and endpoint zero, so a classifier that reads only the
# low 48 bits calls every one of them "XNU_BOOTSTRAP endpoint 0x0" -- which is
# LOCKDOWN, which we implement, which makes an unimplemented call look handled.
for cmd in (2, 4, 5, 6):
    code, reason = run.classify(1, 0, '', [dispatch(cmd)])
    expect(f'dispatch command {cmd:#x} is unsupported', code, run.EXIT_UNSUPPORTED)
    assert f'{cmd:#x}' in reason, reason
    assert 'endpoint' not in reason or 'not an endpoint call' in reason, reason
    checks += 1

    # And the same again if only the monitor-call record survives, because the
    # guest writes that one first and the log can be truncated between them.
    code, reason = run.classify(1, 0, '', [call(0, 0, cmd=cmd)])
    expect(f'command {cmd:#x} seen as a bare monitor call', code, run.EXIT_UNSUPPORTED)
    assert 'not an endpoint call' in reason, reason
    assert 'LOCKDOWN' not in reason and 'endpoint 0x0,' not in reason, reason
    checks += 1

# Command 0 with everything else zero is the genuine LOCKDOWN call -- the stub
# at 0xfffffe000c22b37c builds x16 = 0 outright -- and it must still read as an
# endpoint call rather than being swept up with the four above.
code, reason = run.classify(1, 0, '', [call(0, 0)])
expect('a real endpoint 0 call is still an endpoint call', code, run.EXIT_UNSUPPORTED)
assert 'XNU_BOOTSTRAP endpoint 0x0' in reason, reason
checks += 1

# Domain is part of the route, not decoration: domain 2 table 0 is TXM and
# domain 3 table 0 is the cL4 ringgate, and a table-only lookup called both of
# them XNU_BOOTSTRAP.
for domain, want in ((2, 'TXM_XNU'), (3, 'cL4')):
    code, reason = run.classify(1, 0, '', [call(0, 0, domain=domain)])
    assert want in reason, reason
    assert 'XNU_BOOTSTRAP' not in reason, reason
    checks += 1

# A dispatch-command refusal wins over the monitor-call record that precedes
# it, since the guest writes both for one call and the second is the specific
# one.
code, reason = run.classify(1, 0, '', [call(0, 0, cmd=5), dispatch(5)])
expect('the refusal record wins over the call record', code, run.EXIT_UNSUPPORTED)
assert 'not an endpoint call' in reason, reason
checks += 1

# EXIT_OK is unreachable from classify() by construction: there is no
# checkpoint yet, so nothing here may return it.
for name, want, kwargs in [
        ('entered only', run.EXIT_UNCLASSIFIED, {}),
        ('calls answered', run.EXIT_UNCLASSIFIED, {'log': [event(SYSREG)]}),
]:
    code, _ = run.classify(1, 0, '', list(kwargs.get('log', [])))
    assert code != run.EXIT_OK, f'{name} classified as success'
    checks += 1


# The guest register area, round-tripped.
#
# probes/xnuboot.c writes it and probes/run.py reads it, and the only thing
# holding the two together is a pair of constants computed the same way in two
# languages. This builds the buffer the way the C side lays it out and reads it
# back with the host's own reader, so a layout change on either side fails here
# rather than printing plausible nonsense off the machine.

# XNU's own declaration that it is taking a fatal exception, dispatch command
# 0x2. It fires on the way out of the exception vector, BEFORE panic() has run,
# so it is often the only thing that ever says the run is over -- there may be
# no panic string at all. It has to beat the generic "took an exception".
WEDGE = run.WEDGE_CALLER
VECTOR = 0xfffffe000b86faa4


def panic_entry(caller, elr=0xfffffe000b8c22a0, esr=0x2000000):
    return (run.EV_PANIC_ENTRY, 0xfffffe0000000000, caller, elr, esr, 0)


code, reason = run.classify(1, 0, '', [panic_entry(VECTOR)])
expect('a fatal-exception announcement is a panic', code, run.EXIT_PANIC)
assert 'fatal exception' in reason and f'{VECTOR:#x}' in reason, reason
checks += 2

# The wedge has to say that nothing afterwards runs, because a transcript that
# does not say so looks like a run that merely stopped early.
code, reason = run.classify(1, 0, '', [panic_entry(WEDGE)])
expect('the wedge is a panic', code, run.EXIT_PANIC)
assert 'wedge' in reason and 'wfe' in reason, reason
checks += 2

# It beats the generic guest-exception branch: XNU saying so outranks us
# inferring it from a syndrome.
code, _ = run.classify(1, 0, '', [event(GUEST_EXC), panic_entry(VECTOR)])
expect('the announcement outranks a recorded exception', code, run.EXIT_PANIC)
checks += 1

# But a real panic string still wins, because words beat everything.
code, reason = run.classify(1, 0, 'panic: something specific\n',
                            [panic_entry(VECTOR)])
expect('a panic string still wins', code, run.EXIT_PANIC)
assert 'something specific' in reason, reason
checks += 2

# Every caller this project has named must decode to something, and the latch
# set must be a subset of them -- a caller in one table and not the other is
# how a wrong register label gets printed.
assert set(run.PANIC_LATCH_CALLERS) <= set(run.PANIC_CALLERS), (
    'a latching caller is missing from PANIC_CALLERS')
assert WEDGE in run.PANIC_CALLERS, 'the wedge caller is not named'
assert WEDGE not in run.PANIC_LATCH_CALLERS, (
    'the wedge does not latch ELR/ESR/FAR; decoding them there would be wrong')
checks += 3

# Every latching caller must name all four registers, and the roles are not the
# same at every site: x25 and x26 swap between the EL1h vectors and the
# kernel-mode continuation. A site that copied the wrong shape would print one
# register's value under another's meaning.
for site, roles in run.PANIC_LATCH_CALLERS.items():
    assert set(roles) == {25, 26, 27, 28}, f'{site:#x} does not name x25..x28'
    assert roles[27] == 'ESR' and roles[28] == 'FAR', (
        f'{site:#x}: x27 is ESR and x28 is FAR on every path')
    assert set(roles.values()) == {'saved_state', 'ELR', 'ESR', 'FAR'}, (
        f'{site:#x} assigns a role twice or omits one')
    checks += 1
assert run.PANIC_LATCH_CALLERS[0xfffffe000b86f6a8][25] == 'ELR', (
    'the kernel-mode continuation has x25 = ELR and x26 = saved_state, '
    'the opposite way round from the EL1h vectors')
assert run.PANIC_LATCH_CALLERS[0xfffffe000b86faa4][25] == 'saved_state'
checks += 2


# A MAP_PAGE we refused. The whole point is that the six branches are
# distinguishable, so each one must reach the transcript by name, and the
# failure must outrank the kernel's downstream panic -- "pmap_enter failed" is
# the symptom of our error, not an independent finding.
def map_failed(reason, va=0xfffffe0012340000, detail=0, level=0):
    return (run.EV_MAP_FAILED, 0xfffffe0000000000,
            reason | (level << 8), va, detail, 0)


for reason in sorted(run.MAP_FAILURES):
    code, why = run.classify(1, 0, '', [map_failed(reason)])
    expect(f'MAP_PAGE reason {reason} is unsupported', code, run.EXIT_UNSUPPORTED)
    assert run.MAP_FAILURES[reason] in why, why
    assert '0xfffffe0012340000' in why, 'the failing VA is missing'
    checks += 2

# Six distinct reasons must produce six distinct sentences: if two collapse, a
# reader cannot tell which branch failed, which is the bug this replaced.
sentences = {run.classify(1, 0, '', [map_failed(r)])[1]
             for r in run.MAP_FAILURES}
assert len(sentences) == len(run.MAP_FAILURES), (
    'two MAP_PAGE reasons produce the same reason string')
checks += 1

# And it beats the panic text, while still quoting it.
code, why = run.classify(1, 0, 'panic: pmap_steal_memory() pmap_enter failed\n',
                         [map_failed(2)])
expect('our map failure outranks the panic it caused', code, run.EXIT_UNSUPPORTED)
assert 'MAP_TABLE' in why, 'reason 2 should name the call that would fix it'
assert 'pmap_enter failed' in why, 'the panic text should still be quoted'
checks += 3

# The count is the first failure, not the last, since the first is the one that
# started it.
code, why = run.classify(1, 0, '', [map_failed(2, va=0x1000), map_failed(6, va=0x2000)])
assert '0x1000' in why and '2 times' in why, why
checks += 1


# Cheap hygiene, four items that each close a hole where the transcript said
# less than the run knew.

# A root MAP_PAGE cannot read. mem_read/mem_write at EL2 are a raw dereference
# and a `return 0`: they cannot fail, so a bad root was not a failure reason but
# an unlabelled EL2 fault, arriving at the host as "the monitor faulted, ESR
# ..." with no call, no VA and no root in it. The bounds check is what makes a
# bad address reportable at all, and reason 11 is where it lands.
code, why = run.classify(1, 0, '', [map_failed(11, va=0xfffffe0012340000,
                                               detail=0x1234000)])
expect('a root outside our memory is a named MAP_PAGE failure', code,
       run.EXIT_UNSUPPORTED, why)
assert run.MAP_FAILURES[11] in why, why
assert '0xfffffe0012340000' in why, 'the VA of the failing call is missing'
checks += 3

# Every prepare code the probe can return has a name. Three of them were added
# to xnuboot.c and never named here, so a prepare that failed on the TTBR0
# shadow printed "-8" -- on the one path where nothing else is produced to read.
for code_ in range(-15, 0):
    assert code_ in run.PREPARE_FAILURES, (
        f'xnuboot_prepare() can return {code_} and run.py has no name for it')
    assert len(run.PREPARE_FAILURES[code_]) > 10, (
        f'{code_} needs a sentence, not a label')
    checks += 1
assert len(set(run.PREPARE_FAILURES.values())) == len(run.PREPARE_FAILURES), (
    'two prepare codes share a sentence, so the transcript cannot tell them '
    'apart')
checks += 1

# -8 and -9 are the low regime, and must not read as the upper-half shadow that
# -1 and -2 already cover. Four codes, two regimes, four distinct sentences.
assert 'TTBR0' in run.PREPARE_FAILURES[-8] and 'TTBR0' in run.PREPARE_FAILURES[-9]
assert 'TTBR0' not in run.PREPARE_FAILURES[-1]
assert 'TTBR0' not in run.PREPARE_FAILURES[-2]
checks += 4


# Substituting a panic's arguments into its format string.
#
# The record gives the format string; without the arguments it says the shape
# of the complaint and not the complaint. Both real panics this project has hit
# are here, with the argument words the call sites push.
STRINGS = {0xfffffe0007066f1a: 'pmap.c', 0xfffffe000706c0b4: 'prng_random.c'}


def fake_peekstr(va, limit=256):
    return STRINGS.get(va)


# pmap_steal_memory: `stp x20, x8, [sp]` pushes map_addr and phys_page, then
# the trailing @%s:%d pair.
said = run.format_panic(
    'pmap_steal_memory() pmap_enter failed, map_addr=%#lx, phys_page=%u @%s:%d',
    [0xfffffe0012340000, 0x4321, 0xfffffe0007066f1a, 2512, 0, 0, 0, 0],
    fake_peekstr)
assert 'map_addr=fffffe0012340000' in said, said
assert 'phys_page=17185' in said, said
assert '"pmap.c":2512' in said, said
checks += 3

# The seed panic, whose two %u are expected and got.
said = run.format_panic(
    'Expected %u seed bytes from bootloader, but got %u.\n @%s:%d',
    [256, 64, 0xfffffe000706c0b4, 75, 0, 0, 0, 0], fake_peekstr)
assert 'Expected 256 seed bytes' in said and 'got 64' in said, said
assert '"prng_random.c":75' in said, said
checks += 2

# %% consumes no argument -- getting this wrong shifts every later value.
said = run.format_panic('100%% done, x=%u', [7, 0], fake_peekstr)
assert said == '100% done, x=7', said
checks += 1

# Degrading rather than lying: too few words returns nothing at all, and an
# unknown conversion stops instead of guessing how many words it consumed.
assert run.format_panic('%u %u %u', [1], fake_peekstr) is None
assert '<unformatted>' in run.format_panic('%w', [1], fake_peekstr)
assert run.format_panic('', [], fake_peekstr) is None
assert run.format_panic(None, [], fake_peekstr) is None
checks += 4

# A string argument that cannot be read prints its pointer rather than a lie.
said = run.format_panic('%s', [0xdeadbeef], fake_peekstr)
assert '0xdeadbeef' in said, said
checks += 1

# A PTE pointing outside the memory we declared. Completed, not refused, so it
# must NOT be classified as a failure -- it is a different thing and conflating
# them would hide whichever is rarer.
outside = (run.EV_MAP_OUTSIDE, 0xfffffe0000000000,
           0x308128000, 0xf2000000, 0x006000030812840f, 0)
code, why = run.classify(1, 0, '', [outside])
assert code != run.EXIT_UNSUPPORTED or 'MAP_PAGE returned an error' not in why, (
    'an out-of-window PTE was reported as a MAP_PAGE failure')
checks += 1

# And it must not suppress a real failure recorded alongside it.
code, why = run.classify(1, 0, '', [outside, map_failed(2)])
expect('a real failure still wins over an out-of-window note', code,
       run.EXIT_UNSUPPORTED)
assert 'MAP_TABLE' in why, why
checks += 2

# The regression a7a9592 introduced, and the three things that now prevent it.
#
# Every MAP_PAGE produced two events, the 64-entry log overflowed, and the
# classifier named a cause from a truncated tail: "endpoint 0x2 is not
# implemented", for a run that completed 379 of them.

# 1. A verdict may never contradict the run's own arithmetic.
tail = [call(0, run.SPTM_FN_MAP_PAGE)]
code, why = run.classify(1, 0, '', tail, {'map_pages': 379})
expect('endpoint 0x2 is not called unimplemented after 379 completions',
       code, run.EXIT_UNCLASSIFIED)
assert 'not implemented' not in why, why
assert '379' in why and 'does not reach the real ending' in why, why
checks += 3

# ...but with no completions it is still the right answer, so the check must not
# blanket-suppress the verdict.
code, why = run.classify(1, 0, '', tail, {'map_pages': 0})
expect('and is still unimplemented when nothing completed it', code,
       run.EXIT_UNSUPPORTED)
assert 'not implemented' in why, why
checks += 2

# 2. It must work with no counters at all, since classify is called that way
# from the offline tests.
code, _ = run.classify(1, 0, '', tail)
expect('no counters means the old behaviour', code, run.EXIT_UNSUPPORTED)
checks += 1

# 3. A different endpoint is unaffected -- the check is about this specific
# false claim, not about suppressing unsupported verdicts generally.
code, why = run.classify(1, 0, '', [call(7, 0x32)], {'map_pages': 379})
expect('an unrelated endpoint still classifies', code, run.EXIT_UNSUPPORTED)
assert 'UAT' in why, why
checks += 2


# A truncated log must not veto the kernel's own words.
#
# The log is the only thing truncation damages -- the panic record is read out
# of memory after the run and cannot overflow. Refusing to name a cause when
# XNU wrote one down is honest but needlessly uninformative.
SAID = ('pmap_steal_memory() pmap_enter failed, map_addr=f25ec000, '
        'phys_page=233614 @"vm_resident.c":2512')

code, why = run.truncated(321, 64, SAID)
expect('a populated panic record beats a truncated log', code, run.EXIT_PANIC)
assert 'pmap_enter failed' in why, why
assert '321 events did not fit' in why, 'the loss must still be disclosed'
checks += 3

code, why = run.truncated(321, 64, None)
expect('an empty record with a truncated log stays unclassified', code,
       run.EXIT_UNCLASSIFIED)
assert 'panic record is empty' in why, why
checks += 2

# The disclosure is not optional: a reader must never take the panic as a
# complete account of the run when events were lost.
for said in (SAID, None):
    _, why = run.truncated(7, 64, said)
    assert 'did not fit' in why, 'truncation must be disclosed either way'
    checks += 1

# A truncated log does not hide a MAP failure.
#
# When the 64-entry log overflowed, the runner returned truncated() and never
# called classify() at all. The log fills from the FRONT, so what survives an
# overflow is the start of the run -- and a MAP_PAGE we refused, a panic
# announcement or a stage-2 fault sitting in that head never reached the
# verdict. Reason 10, which the two commits before this one exist to surface,
# is exactly such an event. As the boot gets longer, overflow stops being the
# edge case and becomes the normal one, so this was on its way to being every
# run.
#
# conclude() is the composition: classify from what survived, suppress only the
# inference that reads the tail, and fall back to the loss report when what
# survived names nothing.

# 1. The facts in the head still reach the verdict.
code, why = run.conclude(1, 0, '', [map_failed(10)], {'map_failures': 1},
                         dropped=257, panic_said=None)
expect('a MAP failure in the head survives truncation', code,
       run.EXIT_UNSUPPORTED, why)
assert run.MAP_FAILURES[10] in why, why
assert 'did not fit' in why, 'the loss must still be disclosed'
checks += 3

for name, entry, want in (
        ('a panic announcement', panic_entry(VECTOR), run.EXIT_PANIC),
        ('a stage-2 fault', event(S2_FAULT), run.EXIT_GUEST_EXC),
        ('an exception with no known terminal event', event(GUEST_EXC), run.EXIT_UNCLASSIFIED),
        ('an SError', serror(), run.EXIT_SERROR)):
    code, why = run.conclude(1, 0, '', [entry], {}, dropped=257)
    expect(f'{name} in the head survives truncation', code, want, why)
    assert 'did not fit' in why, f'{name}: the loss must still be disclosed'
    checks += 2

# The kernel's own words too, which never depended on the log at all.
code, why = run.conclude(1, 0, 'panic(cpu 0): something\n', [], {}, dropped=257)
expect('a panic string survives truncation', code, run.EXIT_PANIC, why)
checks += 1

# 2. ...and ONLY the tail inference is suppressed. "The last event was a monitor
# call, so that is where it stopped" is the one thing a missing tail invalidates.
tail_only = [call(0, 1), call(7, 0x32)]
code, why = run.conclude(1, 0, '', tail_only, {}, dropped=0)
expect('with nothing dropped the last call is still the stop', code,
       run.EXIT_UNSUPPORTED, why)
checks += 1

code, why = run.conclude(1, 0, '', tail_only, {}, dropped=257)
assert code != run.EXIT_UNSUPPORTED, (
    'a truncated log must not name the last surviving call as the stop')
expect('a truncated log names no monitor-call cause', code,
       run.EXIT_UNCLASSIFIED, why)
assert 'not implemented' not in why, why
assert 'did not fit' in why, why
checks += 3

# The same for a dispatch-command refusal, the other tail reader.
code, why = run.conclude(1, 0, '', [dispatch(5)], {}, dropped=257)
assert code != run.EXIT_UNSUPPORTED, (
    'a truncated log must not name the last surviving dispatch command')
checks += 1

# 3. A fact that is not in the log at all is not a log inference either: the
# fault word comes from the report, which truncation cannot reach.
code, why = run.conclude(1, EXC_RETURN, '', [], {}, dropped=257)
assert 'not a syndrome' in why, (
    'the fault word survives truncation -- it was never in the log: ' + why)
checks += 1

code, why = run.conclude(1, 0, '', [async_other(0)], {}, dropped=257)
assert 'IRQ' in why, 'a stray IRQ in the head survives truncation: ' + why
checks += 1

# 4. Nothing in the head: the loss IS the finding, and the panic record beats
# it, exactly as before. This is truncated()'s own behaviour, reached through
# conclude().
code, why = run.conclude(1, 0, '', [event(SYSREG)], {}, dropped=257,
                         panic_said=SAID)
expect('an empty head defers to the panic record', code, run.EXIT_PANIC, why)
assert 'pmap_enter failed' in why and '257 events did not fit' in why, why
checks += 3

code, why = run.conclude(1, 0, '', [event(SYSREG)], {}, dropped=257)
expect('an empty head and no record stays unclassified', code,
       run.EXIT_UNCLASSIFIED, why)
assert 'panic record is empty' in why, why
checks += 2

# 5. Counters, not log lines. record() collapses repeats by (kind, pc, a), so
# seventeen failures at seventeen addresses can arrive as one entry -- and an
# overflowed log drops the rest outright. Counting entries under-reports both
# ways, and the number is the first thing a reader uses to judge severity.
code, why = run.conclude(1, 0, '', [map_failed(10)], {'map_failures': 17},
                         dropped=257)
assert '17 times' in why, f'the count must come from the probe counter: {why}'
assert '1 time,' not in why, why
checks += 2

# Two log entries, one truth: the counter wins over both of them.
code, why = run.classify(1, 0, '', [map_failed(2, va=0x1000),
                                    map_failed(6, va=0x2000)],
                         {'map_failures': 41})
assert '41 times' in why and '0x1000' in why, why
checks += 2

# With no tally at all -- how the offline cases above call it -- the log count
# is the fallback rather than a crash or a zero.
code, why = run.classify(1, 0, '', [map_failed(2), map_failed(6)])
assert '2 times' in why, why
checks += 1

# 6. Without truncation, conclude() is classify() unchanged: no disclosure is
# bolted onto a verdict that has nothing to disclose.
for log_ in ([call(0, 1), call(7, 0x32)], [event(GUEST_EXC)], [map_failed(10)],
             []):
    assert run.conclude(1, 0, '', log_, {}) == run.classify(1, 0, '', log_, {}), (
        'conclude() changed a verdict for a run that lost nothing')
    checks += 1


# The terminal word: a run can always name its own stop.
#
# Everything above this point is what a run could say with only the log. The
# probe now records its last event in a slot outside the ring, so the tail is a
# fact rather than an inference, and truncation stops reaching the branches
# that read it. These cases are the ones that were unanswerable before.

# 1. The case from the last run, exactly: 116 events dropped, the head holding
# nothing but sysreg traps, and an empty panic record. Without the terminal word
# this is "the run stopped for a reason nothing recorded". With it the stop is
# named, because the probe knew it all along and had nowhere to put it.
code, why = run.conclude(1, 0, '', [event(SYSREG)], {}, dropped=116,
                         last_event=call(0, 0x33))
expect('a dropped log still names the endpoint that stopped it', code,
       run.EXIT_UNSUPPORTED, why)
assert 'endpoint 0x33' in why, why
assert 'nothing recorded' not in why, (
    'the terminal word exists so this sentence can never be printed again: '
    + why)
assert 'how it ended is known' in why, 'the loss is still disclosed: ' + why
checks += 4

# The same log WITHOUT the terminal word is the old answer, unchanged. The two
# lines below are the before and after of this change, side by side.
code_no, why_no = run.conclude(1, 0, '', [event(SYSREG)], {}, dropped=116)
expect('...and without it, the old unclassified verdict stands', code_no,
       run.EXIT_UNCLASSIFIED, why_no)
assert code_no != code, 'the terminal word must change this verdict'
checks += 2

# 2. A dispatch-command refusal, the other tail reader, through the same route.
code, why = run.conclude(1, 0, '', [event(SYSREG)], {}, dropped=116,
                         last_event=dispatch(5))
expect('a dropped log still names the dispatch command', code,
       run.EXIT_UNSUPPORTED, why)
assert 'dispatch command 0x5' in why, why
checks += 2

# 3. A terminal event no branch models still gets named. The exit code stays
# unclassified -- knowing WHAT the run last did is not knowing WHY it stopped --
# but the sentence now carries a fact instead of an apology.
code, why = run.classify(1, 0, '', [], {}, dropped=116,
                         last_event=event(SYSREG))
expect('an unmodelled terminal event is named, not shrugged at', code,
       run.EXIT_UNCLASSIFIED, why)
assert 'sysreg' in why and 'terminal word' in why, why
assert why != run.NOTHING_RECOGNISED, why
checks += 3

# 4. The head still wins over the tail. A MAP_PAGE failure at the front of the
# log is the cause; the terminal word is where the run happened to be when it
# gave up, and ordering the other way would report the symptom as the disease.
code, why = run.conclude(1, 0, '', [map_failed(10)], {'map_failures': 3},
                         dropped=116, last_event=call(0, 0x33))
expect('a MAP failure in the head still outranks the terminal word', code,
       run.EXIT_UNSUPPORTED, why)
assert run.MAP_FAILURES[10] in why, why
assert 'endpoint 0x33' not in why, why
checks += 3

# 5. A terminal word that IS the last log entry changes nothing on a run that
# fitted. The two agree by construction there, and a verdict that moved would
# mean the slot and the ring disagree about what happened.
for log_ in ([call(0, 1), call(7, 0x32)], [event(GUEST_EXC)], [map_failed(10)]):
    with_word = run.conclude(1, 0, '', log_, {}, last_event=log_[-1])
    without = run.conclude(1, 0, '', log_, {})
    assert with_word == without, (
        f'the terminal word changed a verdict on a run that lost nothing: '
        f'{with_word} != {without}')
    checks += 1


# The probe's source, read once: several checks below are about WHERE a
# statement sits or WHAT a constant is, and those are properties of the
# source rather than of anything importable.
_record = read_source(ROOT / 'probes' / 'xnuboot.c')

# The report's geometry, rebuilt here from the C side's own constants rather
# than imported from run.py, so the two arithmetics are independent and a
# mismatch is a failure instead of a shared mistake. EVENT_MAX is read out of
# xnuboot.c: a literal here would agree with run.py and with nothing else,
# which is exactly how a layout change goes unnoticed.
EVENT_MAX = int(re.search(r'#define EVENT_MAX (\d+)', _record).group(1))
CONSOLE_MAX = int(re.search(r'#define CONSOLE_MAX\s+(\d+)', _record).group(1))
REG_WORDS = 36
assert run.EVENT_MAX == EVENT_MAX, (
    f'run.py reads {run.EVENT_MAX} events, xnuboot.c writes {EVENT_MAX}')
assert run.CONSOLE_MAX == CONSOLE_MAX, (
    f'run.py reads {run.CONSOLE_MAX} console bytes, xnuboot.c writes '
    f'{CONSOLE_MAX}')
assert run.LOG_OFFSET == 16 + 8 * 8, run.LOG_OFFSET
assert run.LOG_BYTES == EVENT_MAX * 6 * 8, run.LOG_BYTES
assert run.CONSOLE_OFFSET == 16 + (8 + 6 * EVENT_MAX) * 8, run.CONSOLE_OFFSET
checks += 5
OUT_GUEST_REGS = 8 + 6 * EVENT_MAX + CONSOLE_MAX // 8      # C-side word index

OUT_PANIC_REGS = OUT_GUEST_REGS + 1 + 2 * REG_WORDS

assert run.GUEST_REGS_OFFSET == 16 + OUT_GUEST_REGS * 8, (
    f'run.py reads the registers at {run.GUEST_REGS_OFFSET}, xnuboot.c writes '
    f'them at {16 + OUT_GUEST_REGS * 8}')
assert run.GUEST_REGS_WORDS == REG_WORDS
OUT_COUNTERS = OUT_PANIC_REGS + 1 + REG_WORDS

assert run.PANIC_REGS_OFFSET == 16 + OUT_PANIC_REGS * 8, (
    f'run.py reads the panic frame at {run.PANIC_REGS_OFFSET}, xnuboot.c '
    f'writes it at {16 + OUT_PANIC_REGS * 8}')
assert run.COUNTERS_OFFSET == 16 + OUT_COUNTERS * 8, (
    f'run.py reads the counters at {run.COUNTERS_OFFSET}, xnuboot.c writes '
    f'them at {16 + OUT_COUNTERS * 8}')
assert len(run.COUNTER_NAMES) == 13, 'xnuboot.c writes thirteen counters'
# ...and each slot holds the field run.py's key says it does.
#
# The two sides agreed on the COUNT and on nothing else: a C side that wrote
# `counters[8] = 0` while run.py called slot 8 "ranges_dropped" passed every
# check here, and the transcript would have reported an overflow of zero for a
# table that overflowed. Reading the assignments out of the source and matching
# them against the key list is what makes the correspondence checkable rather
# than conventional.
_slots = dict((int(_i), _f) for _i, _f in
              re.findall(r'counters\[(\d+)\] = (?:c|vcpu_of\(c\))->(\w+);', _record))
assert len(_slots) == len(run.COUNTER_KEYS), (
    f'xnuboot.c assigns {len(_slots)} counter slots and run.py names '
    f'{len(run.COUNTER_KEYS)}')
for _i, _key in enumerate(run.COUNTER_KEYS):
    assert _slots.get(_i) == _key, (
        f'counter slot {_i} is run.py\'s "{_key}" and xnuboot.c writes '
        f'"{_slots.get(_i)}" there')
    checks += 1
assert len(run.COUNTER_KEYS) == len(run.COUNTER_NAMES), (
    'every counter needs both a key the classifier reads and a name the '
    'transcript prints; a mismatch silently shifts every later counter')
# Derived from the key list rather than repeated: the two sides of this merge
# each added an eighth counter, and a hard-coded 8 here would have put the
# trampoline back on top of one of them.
OUT_EXC_RETURN = OUT_COUNTERS + len(run.COUNTER_KEYS)
assert run.EXC_RETURN_OFFSET == 16 + OUT_EXC_RETURN * 8, (
    f'run.py reads the exception-return trampoline at '
    f'{run.EXC_RETURN_OFFSET}, xnuboot.c writes it at '
    f'{16 + OUT_EXC_RETURN * 8}')
OUT_BAD_REGS = OUT_EXC_RETURN + 1
assert run.BAD_REGS_OFFSET == 16 + OUT_BAD_REGS * 8, (
    f'run.py reads ELR_EL2/FAR_EL2 at {run.BAD_REGS_OFFSET}, xnuboot.c writes '
    f'them at {16 + OUT_BAD_REGS * 8}')
# The terminal word: six words in the shape of a log entry, past the two the
# `bad` vector leaves. A run whose log overflowed reads its ending from here.
OUT_LAST_EVENT = OUT_BAD_REGS + 2
assert run.LAST_EVENT_OFFSET == 16 + OUT_LAST_EVENT * 8, (
    f'run.py reads the terminal word at {run.LAST_EVENT_OFFSET}, xnuboot.c '
    f'writes it at {16 + OUT_LAST_EVENT * 8}')
checks += 1

# ...and that the probe writes it where it claims to.
#
# The offset check above proves the two sides agree about WHERE the word is. It
# says nothing about WHEN it is written, and the whole value of the slot is that
# no early return can skip it: record() returns early both for a repeat and for
# a full log, and a write placed after either one would leave the terminal word
# stale exactly on the runs that need it -- a long boot whose log overflowed, or
# a guest spinning on one register. Read out of the source, because the property
# is positional and there is nothing else offline that can see it.
_body = _record[_record.index('static void record(struct context *c'):]
_body = _body[:_body.index('\n}\n')]
_write = _body.index('c->last.kind = kind;')
assert _write < _body.index('if (c->events)'), (
    'the terminal word is written after the repeat check, so a run whose last '
    'events were repeats would report a stale one')
assert _write < _body.index('c->events >= EVENT_MAX'), (
    'the terminal word is written after the capacity check, which is the one '
    'case it exists for: a log that overflowed would carry no ending at all')
for _field in ('kind', 'pc', 'a', 'b', 'c'):
    assert f'c->last.{_field} =' in _body, (
        f'record() does not set c->last.{_field}, so the terminal word carries '
        f'a stale value in that slot')
    checks += 1
checks += 2

# The per-endpoint counters: 64 buckets and one for everything else.
OUT_ENDPOINTS = OUT_LAST_EVENT + 6
assert run.ENDPOINTS_OFFSET == 16 + OUT_ENDPOINTS * 8, (
    f'run.py reads the endpoint counters at {run.ENDPOINTS_OFFSET}, xnuboot.c '
    f'writes them at {16 + OUT_ENDPOINTS * 8}')
assert run.ENDPOINT_BUCKETS == 64, (
    'xnuboot.c declares ENDPOINT_BUCKETS 64; a different number here reads the '
    '"everything else" bucket as an endpoint, or an endpoint as it')
checks += 2

# SPTM's table has 51 entries and its highest endpoint is 0x32, so 64 buckets
# hold every one of them without two sharing a column. This is the check that
# the bucket count is not merely large but large ENOUGH -- the failure it
# guards against is an endpoint's calls being silently added to another's.
assert max(run.SPTM_ENDPOINTS) < run.ENDPOINT_BUCKETS, (
    f'endpoint {max(run.SPTM_ENDPOINTS):#x} does not fit in '
    f'{run.ENDPOINT_BUCKETS} buckets, so it would alias onto '
    f'{max(run.SPTM_ENDPOINTS) % run.ENDPOINT_BUCKETS:#x}')
# ...and every endpoint this file already acts on by number has a name, so a
# transcript never prints a bare number for a call we implement.
for _fn in (run.SPTM_FN_MAP_PAGE, 0x32, 0x2d, 0x2e, 0x0e, 0x12, 0x0f, 0x13):
    assert _fn in run.SPTM_ENDPOINTS, f'endpoint {_fn:#x} has no name'
    checks += 1
checks += 1

# The probe counts every call that reaches the dispatcher, not every call it
# answers, and the two differ by exactly the refusals. Read out of the source,
# because the property is where the increment sits: after the dispatch it would
# miss the refusals, and the refusals are the ones worth counting.
_mc = _record[_record.index('static int monitor_call_impl(struct context *c'):]
_mc = _mc[:_mc.index('\n}\n')]
assert _mc.index('c->endpoint_calls[') < _mc.index('if (cmd == SPTM_CMD_PANIC_ENTRY)'), (
    'the endpoint counter is incremented after the dispatch begins, so calls '
    'that are refused rather than answered go uncounted -- which is the gap it '
    'exists to close')
assert 'c->endpoint_other++' in _mc, (
    'nothing counts calls to another domain, table or dispatch command, so the '
    'columns cannot be made to add up')
checks += 2

# The out-of-memory span table: a count, an overflow count, then the slots.
OUT_RANGES = OUT_ENDPOINTS + run.ENDPOINT_BUCKETS + 1
assert run.RANGES_OFFSET == 16 + OUT_RANGES * 8, (
    f'run.py reads the span table at {run.RANGES_OFFSET}, xnuboot.c writes it '
    f'at {16 + OUT_RANGES * 8}')
assert (run.MAP_RANGES, run.MAP_RANGE_WORDS) == (128, 4), (
    'the span table is 128 slots of {va, pa, pages, attrs}; a mismatch here '
    'reads one slot\'s fields as another\'s')
checks += 2

# The guest's translation registers, after the span table.
OUT_GUEST_SYSREGS = OUT_RANGES + 2 + run.MAP_RANGES * run.MAP_RANGE_WORDS
assert run.GUEST_SYSREGS_OFFSET == 16 + OUT_GUEST_SYSREGS * 8, (
    f'run.py reads the guest sysregs at {run.GUEST_SYSREGS_OFFSET}, xnuboot.c '
    f'writes them at {16 + OUT_GUEST_SYSREGS * 8}')
# Order matters here more than usual: these are five bare words with no tags,
# so a name out of step with the C's assignments labels TTBR1 as TCR and
# nothing about the value looks wrong.
_sr = dict((int(_i), _f) for _i, _f in
           re.findall(r'out\[OUT_GUEST_SYSREGS \+ (\d+)\] = vcpu_of\(c\)->guest_(\w+);',
                      _record))
assert len(_sr) == len(run.GUEST_SYSREG_NAMES), (
    f'xnuboot.c writes {len(_sr)} guest sysregs and run.py names '
    f'{len(run.GUEST_SYSREG_NAMES)}')
for _i, _name in enumerate(run.GUEST_SYSREG_NAMES):
    assert _sr.get(_i) == _name.split('_')[0].lower(), (
        f'guest sysreg slot {_i} is run.py\'s {_name} and xnuboot.c writes '
        f'guest_{_sr.get(_i)} there')
    checks += 1
assert 'MAIR_EL1' in run.GUEST_SYSREG_NAMES, (
    'MAIR is the one with a question attached -- whether XNU ever writes it -- '
    'and reading it back is how that question gets an answer from hardware')
checks += 2

# The whole report has to fit between `out` and the work area.
assert run.EXCEPTION_FLOW_OFFSET == run.ASYNC_REGS_OFFSET + 37 * 8
assert '#define OUT_EXCEPTION_FLOW (OUT_ASYNC_REGS + 1 + GUEST_REGS_WORDS)' in _record
assert run.EXCEPTION_FLOW_OFFSET + 24 < 0x10000
checks += 3
#
# The log just grew from 64 entries to 512 and three tables were appended after
# it, so "obviously there is room" stopped being obvious. The probe writes this
# buffer at EL2 with the MMU configured its own way: running past the end would
# not fault, it would write into the shadow tables the hardware is walking, and
# the damage would surface as a page-table bug somewhere else entirely.
assert run.AIC_FLOW_OFFSET == run.CLOCK_ADAPTER_OFFSET + 12 * 8
assert '#define OUT_AIC_FLOW (OUT_CLOCK_ADAPTER + 12)' in _record
assert run.WATCHDOG_FLOW_OFFSET == run.AIC_FLOW_OFFSET + 5 * 8
assert '#define OUT_WATCHDOG_FLOW (OUT_AIC_FLOW + 5)' in _record
assert run.MODEL_MAX==128 and run.RESET_WORDS==2
assert run.OPTIONAL_FLOW_OFFSET == run.WATCHDOG_FLOW_OFFSET + (2 + 3*128) * 8
assert '#define OUT_OPTIONAL_FLOW (OUT_WATCHDOG_FLOW + DEVICE_RESET_WORDS + 3*DEVICE_MODEL_MAX)' in _record
assert run.IPI_FLOW_OFFSET == run.OPTIONAL_FLOW_OFFSET + 2 * 8
assert run.CPU_FLOW_OFFSET == run.IPI_FLOW_OFFSET + 8 * 8
assert run.VCPU_FLOW_OFFSET == run.CPU_FLOW_OFFSET + 8 * 8
assert run.SHARED_FLOW_OFFSET == run.VCPU_FLOW_OFFSET + 6 * 12 * 8
assert run.SERVICE_FLOW_OFFSET == run.SHARED_FLOW_OFFSET + 3 * 8
REPORT_END = run.SERVICE_FLOW_OFFSET + 14 * 8
assert run.REPORT_RESERVE == 0x10000
assert 'OUT_RUNTIME_STORAGE + GUEST_CPU_COUNT*5 + 1 <= 0x10000/8' in _record
assert REPORT_END <= run.REPORT_RESERVE, 'probe report exceeds its 64 KiB reservation'
checks += 3
assert REPORT_END <= run.OUT_HEADROOM, (
    f'the report is {REPORT_END} bytes and only {run.OUT_HEADROOM} are free '
    f'before the work area; the next thing it would overwrite is the shadow '
    f'page tables')
# ...with room to spare, so the next field added is not a silent cliff edge.
assert REPORT_END < run.OUT_HEADROOM // 2, (
    f'the report fills more than half its headroom ({REPORT_END} of '
    f'{run.OUT_HEADROOM}); move the work area before adding to it')
checks += 2

# Sysreg traps collapse by which REGISTER was touched, not by (pc, ISS).
#
# 36 of the last run's 64 log entries were sysreg traps -- three quarters of
# the log before the boot had finished starting. The ISS carries the register's
# encoding AND the general-purpose register the value moved through AND the
# direction, so collapsing on the whole word makes "read CNTFRQ into x0" and
# "read CNTFRQ into x1" two facts, and comparing pc splits them again per call
# site. SYSREG_ID is the mask that keeps the first and drops the rest.
_mask = int(re.search(r'#define SYSREG_ID\s+(0x[0-9A-Fa-f]+)', _record)
            .group(1), 16)
# Rebuilt from the field positions rather than copied: ESR_EL2 EC 0x18 lays the
# ISS out as Op0 [21:20], Op2 [19:17], Op1 [16:14], CRn [13:10], Rt [9:5],
# CRm [4:1], Direction [0].
_want = 0
for _lo, _bits in ((20, 2), (17, 3), (14, 3), (10, 4), (1, 4)):   # op0 op2 op1 crn crm
    _want |= ((1 << _bits) - 1) << _lo
assert _mask == _want, (
    f'SYSREG_ID is {_mask:#x}; the register-naming fields of an MSR/MRS ISS '
    f'are {_want:#x}')
assert not _mask & (0x1f << 5), 'SYSREG_ID must drop Rt, or two reads of one '\
    'register into different registers stay two entries'
assert not _mask & 1, 'SYSREG_ID must drop the direction bit'
checks += 3

# ...and that record() actually uses it, on a path that does not compare pc.
_collapse = _body[:_body.index('if (c->events >= EVENT_MAX)')]
assert 'kind == EV_SYSREG' in _collapse and 'SYSREG_ID' in _collapse, (
    'record() does not special-case sysreg traps, so they still collapse by '
    '(kind, pc, a) and fill the log')
_arm = _collapse[_collapse.index('kind == EV_SYSREG'):]
_arm = _arm[:_arm.index('} else {')]
assert 'last->pc == pc' not in _arm, (
    'the sysreg arm still compares pc, so the same register read from two '
    'call sites stays two entries -- which is most of what filled the log')
checks += 2

# Every register the probe traps by name has a name in the transcript, or the
# log prints a bare S3_0_C2_C0_2 where the finding should be.
for _m in re.finditer(r'#define SR_(\w+)\s+SYSREG\((\d+), (\d+), (\d+), (\d+), (\d+)\)',
                      _record):
    _enc = tuple(int(g) for g in _m.groups()[1:])
    assert _enc in run.SYSREGS, (
        f'xnuboot.c traps SR_{_m.group(1)} at {_enc} and run.py has no name '
        f'for it')
    assert run.SYSREGS[_enc] == _m.group(1), (
        f'{_enc} is SR_{_m.group(1)} in xnuboot.c and '
        f'{run.SYSREGS[_enc]} in run.py')
    checks += 2

# The two ID-register dumps are named, not printed as "other pc 0x0".
#
# xnuboot.c records them with pc 0 and pc 1 as a place to put three system
# registers each; the transcript printed them through the fallback branch as a
# label and three bare hex words, which is a line nobody can read and nobody
# did. They say whether this silicon has SME (which XNU configures
# unconditionally) and whether it has FEAT_NV2 (without which XNU cannot be run
# at EL1 at all), so they are two of the more consequential lines in the report.
_runsrc = (ROOT / 'probes' / 'run.py').read_text()
for _pc, _needles in ((0, ('MIDR_EL1', 'ID_AA64PFR0_EL1', 'ID_AA64PFR1_EL1')),
                      (1, ('ID_AA64MMFR2_EL1', 'ID_AA64MMFR4_EL1',
                           'ID_AA64MMFR0_EL1'))):
    assert f'kind == 5 and pc == {_pc}' in _runsrc, (
        f'the EV_OTHER record with pc {_pc} has no branch of its own, so it '
        f'prints as "other pc {_pc:#x}" and three bare words')
    for _needle in _needles:
        assert _needle in _runsrc, (
            f'the pc {_pc} line does not name {_needle}')
        checks += 1
    checks += 1
# ...and the registers they carry are the ones xnuboot.c actually reads there,
# by (CRm, op2) into id_register(). A name attached to the wrong column is
# worse than a bare number.
for _pc, _args in ((0, '4, 0), id_register(4, 1), id_register(0, 0)'),
                   (1, '7, 2), id_register(7, 4), id_register(7, 0)')):
    assert _args in _record, (
        f'the pc {_pc} record no longer reads the registers run.py names for '
        f'it; the transcript would label the wrong values')
    checks += 1

# A span is extended only when the next page continues it in BOTH address
# spaces AND carries the same attributes. Read out of the source because all
# three conditions are the property: dropping the VA test merges two different
# mappings of one device, dropping the PA test merges two devices mapped back
# to back, and dropping the attribute test leaves a single `attrs` field
# describing only the span's first page while appearing to describe all of it.
_note = _record[_record.index('static void map_range_note('):]
_note = _note[:_note.index('\n}\n')]
for _cond, _why in (
        ('r->va + r->pages * page == va', 'two mappings of one device merge'),
        ('r->pa + r->pages * page == pa', 'two adjacent devices merge'),
        ('r->attrs == attrs',
         'the attrs field would describe only the first page')):
    assert _cond in _note, (
        f'map_range_note() does not test {_cond}, so {_why}')
    checks += 1
assert 'c->ranges_dropped++' in _note, (
    'a full span table must count what it could not hold; silently stopping '
    'would report a device surface smaller than the one the kernel asked for')
assert _note.index('c->ranges_dropped++') < _note.index('c->range_count++'), (
    'the overflow check must come before the slot is taken')
checks += 2

# The table is filled at the same place the counter is bumped, so "the spans
# add up to map_outside" is true by construction rather than by coincidence --
# which is what lets the transcript check it.
_mp = _record[_record.index('uint64_t pte_pa = new_pte & PT_OA_MASK;'):]
_mp = _mp[:_mp.index('uint64_t slot = table')]
assert 'c->map_outside++' in _mp and 'map_range_note(' in _mp, (
    'the span table and the out-of-memory counter must be written at the same '
    'place, or they describe different sets of pages')
checks += 1
assert 'console_dropped' in run.COUNTER_KEYS, (
    'the console counts the bytes it drops past CONSOLE_MAX')
assert 'ranges_dropped' in run.COUNTER_KEYS, (
    'the span table counts what it had no room for, in the counter slot the '
    'retired map_withheld used to hold')
assert 'map_device' in run.COUNTER_KEYS, (
    'and MAP_PAGE counts the mappings onto windows the guest device tree names')

# Nothing withholds a mapping any more.
#
# Withholding wrote a PTE into the guest's own table and kept it out of the
# shadow, so XNU faulted at stage 1 inside its own handler and the transcript
# read "XNU faulted" where it could have read "the AIC at 0x301000000 was
# read". Under the narrowed stage-2 map (T4) those addresses are absent rather
# than identity-mapped, so an installed PTE traps to EL2 with the IPA, the
# register, the size and the direction -- installing is the loud option and
# withholding was the quiet one, which is the reverse of how they arrived.
#
# Checked in the source because the property is an ABSENCE, and an absence has
# no runtime to observe it in. The counter is gone too: a counter that cannot
# be non-zero is the same dead guard this project has twice found and removed.
assert 'map_withheld' not in run.COUNTER_KEYS, (
    'map_withheld can no longer be non-zero, so it is a counter that never '
    'fires -- exactly the guard this project keeps finding')
assert 'EV_MAP_WITHHELD' not in _record.split('/* 14 was EV_MAP_WITHHELD')[-1], (
    'EV_MAP_WITHHELD is still recorded somewhere')
assert 'c->map_withheld' not in _record, (
    'something still counts a withheld mapping')
assert 'points_outside && !is_device' not in _record, (
    'the withholding branch is back: a PTE outside our memory that is not a '
    'named device is being kept out of the hardware tables again')
# ...and the reason it is safe: the shadow insert is now reached for every
# valid leaf, not for every valid leaf that is not one of these.
_shadow = _record[_record.index('int is_device = 0;'):]
_shadow = _shadow[:_shadow.index('int put_leaf = shadow_insert')]
assert 'if (leaf.valid) {' in _shadow, (
    'the shadow insert is no longer guarded by leaf.valid alone, so some '
    'valid mapping is still being skipped')
checks += 5
# The UART model's three. A modelled device access records no event -- there is
# one per character of the kernel's output and the log holds 64 entries -- so
# these counters are the only evidence the console channel worked at all.
assert 'uart_tx' in run.COUNTER_KEYS, (
    'the UART model counts the bytes XNU put on its own serial line; without '
    'it a run where the console never engaged and a run where it engaged and '
    'said nothing look identical')
assert 'mmio_reads' in run.COUNTER_KEYS and 'mmio_writes' in run.COUNTER_KEYS, (
    'the dispatcher counts the device registers it answered in each direction')
checks += 11

buf = bytearray(16 + (OUT_PANIC_REGS + 1 + REG_WORDS) * 8)


def c_word(index, value):
    """out[index] as the C side numbers it: 16 bytes above the host's `out`."""
    struct.pack_into('<Q', buf, 16 + index * 8, value)


class FakeProxy:
    def readmem(self, addr, n):
        return bytes(buf[addr:addr + n])


captured = []
_print = print
try:
    import builtins
    builtins.print = lambda *a, **k: captured.append(' '.join(str(x) for x in a))

    # Nothing captured: the reader must stay silent rather than print zeros.
    run.guest_registers(FakeProxy(), 0)
    silent = not captured

    # Two snapshots, with values that cannot be confused for each other.
    first = list(range(0xA000, 0xA000 + 31)) + [0xF1F1, 0x3c5, 0xB8C22A0, 0x2000000]
    last = list(range(0xB000, 0xB000 + 31)) + [0xF2F2, 0x3c4, 0xC234ADC, 0x96000004]
    c_word(OUT_GUEST_REGS, 2)
    for i, v in enumerate(first):
        c_word(OUT_GUEST_REGS + 1 + i, v)
    for i, v in enumerate(last):
        c_word(OUT_GUEST_REGS + 1 + REG_WORDS + i, v)
    captured.clear()
    run.guest_registers(FakeProxy(), 0)
    text = '\n'.join(captured)
finally:
    import builtins
    builtins.print = _print

assert silent, 'the reader printed something with no exceptions captured'
checks += 1
for name, value in (('x0 of the first', 0xa000), ('x30 of the first', 0xa01e),
                    ('x0 of the last', 0xb000), ('x30 of the last', 0xb01e),
                    ('the first PC', 0xb8c22a0), ('the last PC', 0xc234adc)):
    assert f'{value:#018x}' in text or f'{value:#x}' in text, f'{name} is missing'
    checks += 1
assert 'SP ' in text and 'SPSR_EL1' in text and 'ESR_EL1' in text, text
checks += 1


# The panic frame, and the part that must not be got wrong: x26/x27/x28 are the
# fault only at the three callers that latch them. Decoding them anywhere else
# would print a per-CPU pointer as a faulting address, with a label.
def panic_buffer(caller):
    b = bytearray(16 + (OUT_PANIC_REGS + 1 + REG_WORDS) * 8)
    frame = [0x1111 * (n + 1) for n in range(31)]
    frame[25], frame[26], frame[27], frame[28] = 0x2525, 0x2626, 0x2727, 0x2828
    frame[30] = caller
    words = frame + [0xF00D, 0x3c5, 0xfffffe000b8c22a0, 0x2000000, 0xdeadbeef]
    struct.pack_into('<Q', b, 16 + OUT_PANIC_REGS * 8, 1)
    for i, v in enumerate(words):
        struct.pack_into('<Q', b, 16 + (OUT_PANIC_REGS + 1 + i) * 8, v)
    return b


def capture_panic(caller):
    global buf
    buf = panic_buffer(caller)
    got = []
    import builtins
    saved = builtins.print
    builtins.print = lambda *a, **k: got.append(' '.join(str(x) for x in a))
    try:
        run.panic_entry(FakeProxy(), 0)
    finally:
        builtins.print = saved
    return '\n'.join(got)


text = capture_panic(VECTOR)
assert 'ELR_EL1 0xfffffe000b8c22a0' in text, text
assert f'{0xdeadbeef:#018x}' in text, 'FAR_EL1 is missing'
assert 'saved_state' in text and f'{0x2626:#018x} (ELR)' in text, (
    'a latching caller must have x25..x28 decoded')
assert 'synchronous exception vector' in text, text
checks += 4

text = capture_panic(WEDGE)
assert 'NOT the fault here' in text, (
    'a non-latching caller must say its x26/x27/x28 are not the fault')
assert 'saved_state' not in text, 'x25..x28 were decoded at a caller that does '\
                                  'not latch them'
assert 'wfe' in text and 'NOTHING' in text, 'the wedge must say nothing runs after'
checks += 3

text = capture_panic(0xfffffe0000badbad)
assert 'has not seen before' in text, 'an unknown caller must say so'
assert 'NOT the fault here' in text, 'an unknown caller must not be assumed to latch'
checks += 2

# --------------------------------------------------------------------------
# A stage-2 fault, in words -- docs/PLAN-HISTORY-20260922.md Section 0, T4
#
# Under the narrowed map every device touch stops the run as a stage-2 fault,
# and the next step is priced by what the report says about it: the IPA, and
# from the syndrome the access size, the register and the direction (when
# ISS.ISV is set), whether the stage-1 walk itself faulted, and the fault kind.
# The bit positions are the architecture's -- ESR_EL2 ISS for a data abort:
# ISV[24] SAS[23:22] SSE[21] SRT[20:16] SF[15] S1PTW[7] WnR[6] DFSC[5:0] -- and
# a wrong one here would name the wrong register with full confidence.


def dabt(isv=1, sas=2, sse=0, srt=0, sf=0, s1ptw=0, wnr=0, fsc=0x07):
    iss = ((isv << 24) | (sas << 22) | (sse << 21) | (srt << 16) | (sf << 15)
           | (s1ptw << 7) | (wnr << 6) | fsc)
    return (0x24 << 26) | iss


text = run.s2_fault_words(0x2a9c0000, dabt(sas=2, srt=5, wnr=1, fsc=0x07))
assert 'translation fault at level 3' in text and 'write of 4 bytes, w5' in text, text
text = run.s2_fault_words(0x2a9c0000, dabt(sas=3, srt=3, sf=1, fsc=0x05))
assert 'translation fault at level 1' in text and 'read of 8 bytes, x3' in text, text
text = run.s2_fault_words(0x2a9c0000, dabt(sas=0, srt=17, sse=1, fsc=0x06))
assert 'read of 1 byte, w17, sign-extended' in text, text
text = run.s2_fault_words(0x82500000, dabt(sas=2, srt=8, wnr=1, fsc=0x0f))
assert 'permission fault at level 3' in text and 'write of 4 bytes, w8' in text, text
text = run.s2_fault_words(0x2a9c0000, dabt(isv=0, wnr=1))
assert 'write, ISV clear' in text, text
text = run.s2_fault_words(0x82501000, dabt(s1ptw=1))
assert 'S1PTW' in text and 'table page' in text, text
text = run.s2_fault_words(0x2a9c0000, (0x20 << 26) | 0x07)
assert 'instruction fetch' in text and 'translation fault at level 3' in text, text
text = run.s2_fault_words(0, dabt())
assert 'IPA unknown' in text and 'HPFAR read zero' in text, text
checks += 8

# And the verdict carries it: the reason names the IPA, the access and the PC,
# so the transcript's last line is the answer without reading the log.
code, reason = run.classify(1, 0, '', [
    call(0, 1),
    (S2_FAULT, 0xfffffe000b9193d0, 0x2a9c0000,
     dabt(sas=2, srt=5, wnr=1, fsc=0x07), 0xfffffe0010000000, 0)])
assert code == run.EXIT_GUEST_EXC, reason
assert ('0x2a9c0000' in reason and 'write of 4 bytes, w5' in reason
        and '0xfffffe000b9193d0' in reason), reason
checks += 1

# Where the IPA falls, against the loader's own list: inside a range it is
# that range's permission; in none, the address does not exist for the guest.
ranges = [(0xda000000, 0xf5000000, 'rw', 'DRAM + reserve'),
          (0x82500000, 0x84500000, 'ro', 'work area (shadow tables)')]
assert 'in no range' in run.s2_where_words(0x2a9c0000, ranges)
where = run.s2_where_words(0x82501000, ranges)
assert 'inside the work area' in where and '(ro)' in where, where
assert 'nowhere' in run.s2_where_words(0, ranges)
checks += 3

# --------------------------------------------------------------------------
# The UART, and the registers it does not model.
#
# This is the stop that step B is designed to produce whenever it meets a
# register it has no answer for, so the words have to carry the whole next
# iteration: which window, which offset, how wide and which way. A stop that
# said only "a device faulted" would cost a hardware run to learn what this
# already knows.


def mmio(reason, window, offset, esr, ipa=0x308128000, pc=0xfffffe000c2533f0):
    """One EV_MMIO_STOP, as xnuboot.c's mmio_stop() packs it."""
    return (MMIO_STOP, pc, (reason << 48) | (window << 32) | offset, esr, ipa, 0)


text = run.mmio_stop_words((1 << 48) | (0 << 32) | 0x4028, dabt(sas=2, srt=9))
assert 'window 0' in text and '+0x4028' in text, text
assert 'read of 4 bytes' in text, text
assert 'this offset is not' in text, text
checks += 1

text = run.mmio_stop_words((1 << 48) | (1 << 32) | 0x10, dabt(sas=2, srt=9, wnr=1))
assert 'window 1' in text and 'irq' in text and '+0x10' in text, text
assert 'write of 4 bytes' in text, text
checks += 1

# ISV clear is the one the brief singles out: the syndrome does not say which
# registers moved, so the model must stop and the words must say why.
text = run.mmio_stop_words((2 << 48) | (0 << 32) | 0x4004, dabt(isv=0, wnr=1))
assert 'ISV clear' in text and 'guess' in text, text
checks += 1

text = run.mmio_stop_words((4 << 48) | (0 << 32) | 0x8, dabt(s1ptw=1))
assert 'stage-1 table walk' in text, text
checks += 1

text = run.mmio_stop_words((5 << 48) | (0 << 32) | 0, dabt())
assert 'not the shape' in text, text
checks += 1

# ...and the verdict it produces. Named as unsupported rather than as a guest
# exception: the kernel did nothing wrong, we are simply missing a register.
code, reason = run.classify(True, 0, '', [
    call(0, 0x2d),
    mmio(1, 0, 0x4028, dabt(sas=2, srt=9))])
assert code == run.EXIT_UNSUPPORTED, (code, reason)
assert 'device register we do not model' in reason, reason
assert '+0x4028' in reason and 'window 0' in reason, reason
assert '0xfffffe000c2533f0' in reason, reason
checks += 1

# It is more specific than the plain stage-2 fault, and must win over one --
# the address is already known to be a device the kernel's own tree names, and
# only this event carries the offset.
code, reason = run.classify(True, 0, '', [
    mmio(1, 0, 0x4028, dabt(sas=2, srt=9)),
    (S2_FAULT, 0xfffffe000b9193d0, 0x2a9c0000, dabt(sas=2, srt=5), 0, 0)])
assert code == run.EXIT_UNSUPPORTED, (code, reason)
assert '+0x4028' in reason, reason
checks += 1

# Every stop reason the probe can emit has words. A reason added on one side
# and not the other prints as a bare number, which is exactly the transcript
# that costs a run to interpret.
for reason_ in range(1, 6):
    assert f'reason {reason_}' not in run.mmio_stop_words(
        (reason_ << 48), dabt()), f'MMIO stop reason {reason_} has no words'
checks += 1

# And every window the loader can pass is named rather than numbered.
assert len(run.MMIO_WINDOWS) == 2, (
    'the dockchannel-uart node declares two reg windows; a third would need a '
    'name here before it could be reported')
checks += 1

for error, description in run.RETYPE_FAILURES.items():
    terminal = (18, 0xfffffe000c22b3c8, error, 0xe4638000, 20, 0)
    code, reason = run.classify(1, 0, '', [call(0, 1)], last_event=terminal)
    expect(f'RETYPE failure {error}', code, run.EXIT_UNSUPPORTED, reason)
    assert description in reason and '0xe4638000' in reason
    code, reason = run.classify(1, 0, '', [terminal])
    expect(f'RETYPE failure {error} from intact log', code, run.EXIT_UNSUPPORTED, reason)
    code, reason = run.classify(1, 0, '', [call(0, 1)], dropped=100,
                                last_event=terminal)
    expect(f'RETYPE failure {error} survives log overflow', code, run.EXIT_UNSUPPORTED, reason)

for terminal, expected in [
    ((3, 0xfffffe000ba63cd0, 0x96000005, 0x90, 0xfffffe000b871e28, 0),
     run.EXIT_GUEST_EXC),
    ((6, 0xfffffe000c268520, 0, 0, 0, 0), run.EXIT_WATCHDOG),
]:
    code, reason = run.classify(True, 0, '', [call(0, 2)], dropped=100,
                                last_event=terminal)
    expect('terminal fault remains classifiable after log overflow', code, expected, reason)

warning = 'debug_log_init: Error!! gPanicBase is still not initialized\n'
code, reason = run.conclude(1, 0, '', [], dropped=20,
    panic_said='kvtophys_nofail: VA->PA translation failed',
    last_event=(3, 0, 0x2000000, 0, 0xfffffe000b8c22a0, 0))
expect('captured panic format survives a terminal debugger exception', code, run.EXIT_PANIC)
assert 'kvtophys_nofail' in reason, reason
for domain, table in ((2, 0), (0, 1)):
    other = (1, 0xfffffe000c22a96c, (domain << 48) | (table << 32) | 2, 0, 0, 0)
    code, reason = run.classify(1, 0, '', [], {'map_pages': 2078},
                                dropped=1131, last_event=other)
    expect('SPTM map completions do not count another domain/table endpoint 2',
           code, run.EXIT_UNSUPPORTED, reason)
terminal = (1, 0xfffffe000c22a96c, 0x0002000000000001, 0xe4518000, 0, 0)
code, reason = run.classify(1, 0, warning, [], dropped=1667, last_event=terminal)
expect('panic-buffer warning does not hide an unsupported TXM call',
       code, run.EXIT_UNSUPPORTED, reason)
assert 'TXM_XNU endpoint 0x1' in reason and 'gPanicBase' not in reason, reason
code, reason = run.classify(1, 0, warning + 'panic(cpu 0): real fault\n', [])
expect('real panic after a panic-buffer warning is selected', code, run.EXIT_PANIC)
assert 'real fault' in reason and 'gPanicBase' not in reason, reason
checks += 2

print(f'PASS: {checks} run-classification checks '
      '(no hardware, no proxy, no kernelcache)')
