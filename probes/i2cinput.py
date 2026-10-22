# SPDX-License-Identifier: MIT
"""Opt-in A16 built-in keyboard for the SnapI2CHID kext: tree node, stage 2, params.

docs/A16-INPUT-INSTALLED-20261017.md (design: docs/A16-INPUT-DRIVER-20260928.md
section 3, Phase 1). The monitor side is compat/i2c-input.h, compiled only with
-DSNAP_I2C_INPUT=1; a profile without i2c_input changes nothing here or there.

For each enabled device the tree gains, under /arm-io:
  * one `ranges` triple, child 0x7_xxxx_xxxx -> the GENI serial engine's 16 KiB
    QUP window (appended: XNU reads the first triple as the SoC base);
  * a node the kext matches (IONameMatch snapintosh,geni-i2c-hid) whose reg is
    the first 4 KiB of that window only, with the HID-over-I2C address,
    descriptor register and identity from the A16 evidence, a poll period and
    irq-policy 1 (M_IRQ_EN = 0). No `interrupts` property: Phase 1 polls.
The monitor maps exactly that page (Device-nGnRE, RW, XN) after checking the
appended words against its own allow-list; any other address stays absent.

The touchpad (TCPD/ASUF1209 on I2C1, 0x00B80000) is described but refused until
its controller has had the read-only register survey and descriptor reads the
keyboard had (generations 54-57): an unclocked QUP can fault or stall the bus
on the first read, and the kext's start reads it before any check can run.
"""
from dataclasses import dataclass
import struct

PARAMS_WORDS = 6                         # compat/i2c-input.h I2C_INPUT_PARAMS_WORDS
MAGIC = int.from_bytes(b'SNAPI2C1', 'little')
F_KEYBOARD, F_TOUCHPAD = 1, 2
PAGE = 0x1000                            # the one page stage 2 maps per device
QUP_SPAN = 0x4000                        # each serial engine's window (A16 DSDT _CRS)
CHILD_OFFSET = 0x7_0000_0000             # arm-io child space, as the Adreno's 0x7_03D0_0000
DEFINE = '-DSNAP_I2C_INPUT=1'
MATCH = 'snapintosh,geni-i2c-hid'
BUNDLE = 'org.snapintosh.driver.SnapI2CHID'
IRQ_POLICY_MASKED = 1                    # geni-i2c.h GENI_I2C_IRQ_MASKED
# shadow/stage2.h: S2_AP_RW | S2_ATTRS_DEVICE, and S2_XN (as probes/adreno.py).
S2_DEVICE_RW, S2_XN = 0x7C4, 1 << 54
# Flip only after i2c0's read-only survey and two identical descriptor reads pass on hardware:
# tools/qualify-a16-touchpad.py survey, then descriptors, both on a stopped quiesced run.
# Qualified on hardware 2026-10-18 after v47 (stopped, preserved, quiesced; generation 33):
# build/a16-touchpad-survey-installed-fresh-20261017-v47.json (CONTROLLER_QUALIFIED) and
# build/a16-touchpad-descriptors-installed-fresh-20261017-v47.json (DESCRIPTORS_VERIFIED, 2808:0219, 764-byte rdesc).
TOUCHPAD_QUALIFIED = True


@dataclass(frozen=True)
class Device:
    flag: int
    node: str
    pa: int                   # the GENI serial engine (QUP window base)
    address: int              # 7-bit HID-over-I2C address
    descriptor_register: int  # ACPI _DSM / DT hid-descr-addr
    vendor: int
    product: int
    product_name: str
    evidence: str


KEYBOARD = Device(F_KEYBOARD, '/device-tree/arm-io/i2c-hid-kbd', 0x0088C000, 0x15, 1, 0x0B05, 0x4B42,
                  'ASUS Zenbook A16 Keyboard',
                  'ECKB/QTEC0001 on IC20; HID descriptor gen56, report descriptor gen57 (0887190d)')
TOUCHPAD = Device(F_TOUCHPAD, '/device-tree/arm-io/i2c-hid-tpd', 0x00B80000, 0x15, 1, 0x2808, 0x0219,
                  'ASUS Zenbook A16 Touchpad',
                  'TCPD/ASUF1209 on I2C1 (firmware selection gen57); controller and descriptors unread')
DEVICES = (KEYBOARD, TOUCHPAD)


@dataclass(frozen=True)
class I2CInputSpec:
    keyboard: bool = True
    touchpad: bool = False
    poll_us: int = 8000
    irq_policy: int = IRQ_POLICY_MASKED

    def __post_init__(self):
        if not (self.keyboard or self.touchpad):
            raise ValueError('i2c_input enables no device')
        if not 1000 <= self.poll_us <= 100000:
            raise ValueError('poll period outside the kext\'s 1..100 ms')
        if self.irq_policy != IRQ_POLICY_MASKED:
            raise ValueError('Phase 1 routes no interrupt: irq-policy must be 1 (M_IRQ_EN = 0)')

    def require_qualified(self):
        """The touchpad is described (and its profile exists) but refused at use until qualified."""
        if self.touchpad and not TOUCHPAD_QUALIFIED:
            raise ValueError('the touchpad controller is unqualified: run tools/qualify-a16-touchpad.py '
                             'survey and descriptors on a stopped run, then set TOUCHPAD_QUALIFIED')

    def devices(self):
        return tuple(d for d in DEVICES if (d is KEYBOARD and self.keyboard) or
                     (d is TOUCHPAD and self.touchpad))

    def flags(self):
        return sum(d.flag for d in self.devices())


def stage2_ranges(spec):
    """The monitor's passthrough, as probes/xnuboot.stage2_ranges lists ranges."""
    spec.require_qualified()
    return [(d.pa, d.pa + PAGE, 'rw', f'{d.node.rsplit("/", 1)[1]} GENI I2C page (Device-nGnRE)')
            for d in spec.devices()]


def params_words(spec):
    """struct i2c_input_params, in field order."""
    spec.require_qualified()
    words = [MAGIC, spec.flags()]
    for d in DEVICES:
        words += [d.pa, d.pa + PAGE] if d in spec.devices() else [0, 0]
    assert len(words) == PARAMS_WORDS
    return words


def rows(words):
    """compat/i2c-input.h i2c_input_rows: [(lo, hi)] of a valid block, or None."""
    if len(words) != PARAMS_WORDS:
        return None
    magic, flags, *pairs = words
    if magic != MAGIC or not flags or flags & ~(F_KEYBOARD | F_TOUCHPAD):
        return None
    out = []
    for d, (lo, hi) in zip(DEVICES, zip(pairs[0::2], pairs[1::2])):
        if flags & d.flag:
            if (lo, hi) != (d.pa, d.pa + PAGE):
                return None
            out.append((lo, hi))
        elif lo or hi:
            return None
    return out


def stage2_audit_ranges(words):
    """The passthrough as tools/stage2audit audits a stopped monitor's stage 2:
    [(lo, hi, low attributes, upper attributes)] of the appended words (none if invalid)."""
    return [(lo, hi, S2_DEVICE_RW, S2_XN) for lo, hi in rows(words) or ()]


def prepare_tree(dt, spec, owned=()):
    """Add the ranges and nodes, all or nothing. `owned` is [(base, size)] the
    guest's memory and the monitor's: no window may touch it."""
    from appledt import Property
    spec.require_qualified()
    bus = '/device-tree/arm-io'
    raw = dt.nodes[bus]['ranges']
    if raw.placeholder or len(raw.value) % 24:
        raise ValueError('arm-io ranges are not resolved (child, parent, span) triples')
    ranges = list(struct.iter_unpack('<3Q', raw.value))
    add = [(CHILD_OFFSET + d.pa, d.pa, QUP_SPAN) for d in spec.devices()]
    for child, parent, span in add:
        for c, p, s in ranges:
            if child < c + s and c < child + span:
                raise ValueError(f'arm-io child range {child:#x} overlaps {c:#x}')
            if parent < p + s and p < parent + span:
                raise ValueError(f'arm-io parent range {parent:#x} overlaps {p:#x}')
        for base, size in owned:
            if parent < base + size and base < parent + span:
                raise ValueError('an input window overlaps guest or monitor memory')
    for d in spec.devices():
        if d.node in dt.nodes:
            raise ValueError(f'{d.node} already exists')
    for path, props in dt.nodes.items():
        compatible = props.get('compatible')
        if compatible is not None and MATCH.encode() in bytes(compatible.value).split(b'\0'):
            raise ValueError(f'{path} already claims {MATCH}')
    u32 = lambda *v: struct.pack(f'<{len(v)}I', *v)
    dt.put(bus, 'ranges', raw.value + b''.join(struct.pack('<3Q', *r) for r in add))
    made = []
    for d in spec.devices():
        props = {
            'name': d.node.rsplit('/', 1)[1].encode() + b'\0',
            'compatible': MATCH.encode() + b'\0',
            'device_type': b'i2c-hid\0',
            'reg': struct.pack('<QQ', CHILD_OFFSET + d.pa, PAGE),
            'snapintosh,hid-address': u32(d.address),
            'snapintosh,hid-descriptor-reg': u32(d.descriptor_register),
            'snapintosh,hid-vendor-product': u32(d.vendor, d.product),
            'snapintosh,poll-us': u32(spec.poll_us),
            'snapintosh,irq-policy': u32(spec.irq_policy),
            'snapintosh,hid-product': d.product_name.encode() + b'\0',
        }
        dt.nodes[d.node] = {k: Property(k, v) for k, v in props.items()}
        dt.children[d.node] = []
        dt.children[bus].append(d.node)
        made.append(d.node)
    return dict(nodes=made, ranges=add)
