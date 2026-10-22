# SPDX-License-Identifier: MIT
"""Opt-in read-only DPU INTF_5 page for the AdrenoDisplay kext's beam (--present-beam): stage 2, params, GPU node.

agents/tear-free FAILURE-MODES.md (A1-A5, D3, E3). The monitor side is compat/display-timing.h, compiled only with
-DSNAP_DISPLAY_TIMING=1; the kext side is AdrenoDisplayBeam.h (-DADRENO_BEAM=1). With xnuboot.DISPLAY_TIMING None (the
default) nothing here runs and the loader output is unchanged.

The page: the eDP interface's timing engine, glymur.dtsi mdss_mdp "mdp" 0x0ae01000 + dpu_12_2_glymur.h intf_5 0x39000
= 0x0ae3a000 (compat/dpu-intf.h). The monitor maps exactly that page, Device-nGnRE, READ-ONLY, execute-never, after
checking the appended words against its own constants; the loader adds:
  * struct display_timing_params after struct params (after the QCC2072 block when that is appended too);
  * two properties on the GPU node, which the kext reads: snapintosh,dpu-intf-abi (u32 1) and snapintosh,dpu-intf-pa
    (u64). No node, no arm-io ranges: the kext maps the page by its physical address.
Nothing writes the DPU.
"""
from dataclasses import dataclass
from pathlib import Path
import re
import struct

MAGIC = int.from_bytes(b'SNAPDPU1', 'little')
F_INTF = 1
PARAMS_WORDS = 4                         # compat/display-timing.h DISPLAY_TIMING_PARAMS_WORDS
MDP_PA = 0x0AE01000                      # glymur.dtsi mdss_mdp reg "mdp"
INTF_INDEX = 5                           # eDP: mdss_dp3 (port@5)
INTF_PA = MDP_PA + 0x34000 + 0x1000 * INTF_INDEX
PAGE = 0x1000
DEFINE = '-DSNAP_DISPLAY_TIMING=1'
ENV = 'SNAP_DISPLAY_TIMING'
ABI = 1
ABI_PROPERTY = 'snapintosh,dpu-intf-abi'  # compat/dpu-intf.h DPU_INTF_ABI_PROPERTY
PA_PROPERTY = 'snapintosh,dpu-intf-pa'    # compat/dpu-intf.h DPU_INTF_PA_PROPERTY
# shadow/stage2.h: S2_AP_RO | S2_ATTRS_DEVICE, and S2_XN.
S2_DEVICE_RO, S2_XN = 0x744, 1 << 54
assert INTF_PA == 0x0AE3A000


@dataclass(frozen=True)
class DisplayTimingSpec:
    intf: bool = True


SPEC = DisplayTimingSpec()


def header_constants(root):
    """compat/dpu-intf.h's address and property names, for the cross-check the tests run."""
    text = (Path(root) / 'compat/dpu-intf.h').read_text()
    get = lambda name: re.search(rf'#define {name}\s+(\S+)', text).group(1)
    return dict(mdp=int(get('DPU_MDP_PA').rstrip('ULL'), 16), first=int(get('DPU_INTF_FIRST').rstrip('ULL'), 16),
                stride=int(get('DPU_INTF_STRIDE').rstrip('ULL'), 16), index=int(get('DPU_INTF_INDEX').rstrip('u')),
                abi_property=get('DPU_INTF_ABI_PROPERTY').strip('"'), pa_property=get('DPU_INTF_PA_PROPERTY').strip('"'))


def stage2_ranges(spec):
    """The monitor's passthrough, as probes/xnuboot.stage2_ranges lists ranges."""
    if spec is None:
        return []
    return [(INTF_PA, INTF_PA + PAGE, 'ro', 'DPU INTF_5 timing page (Device-nGnRE, read-only)')]


def params_words(spec):
    """struct display_timing_params, in field order."""
    if spec is None:
        raise ValueError('no display timing spec')
    words = [MAGIC, F_INTF, INTF_PA, INTF_PA + PAGE]
    assert len(words) == PARAMS_WORDS
    return words


def rows(words):
    """compat/display-timing.h display_timing_rows: [(lo, hi)] of a valid block, or None."""
    if len(words) != PARAMS_WORDS or list(words) != [MAGIC, F_INTF, INTF_PA, INTF_PA + PAGE]:
        return None
    return [(INTF_PA, INTF_PA + PAGE)]


def stage2_audit_ranges(words):
    """The passthrough as tools/stage2audit audits a stopped monitor's stage 2:
    [(lo, hi, low attributes, upper attributes)] of the appended words (none if invalid)."""
    return [(lo, hi, S2_DEVICE_RO, S2_XN) for lo, hi in rows(words) or ()]


def advertise(dt, spec, owned=()):
    """The two GPU-node properties the kext reads. The GPU node must exist (an Adreno profile); the page must stay clear
    of `owned` [(base, size)] (guest and monitor memory)."""
    import adreno
    if spec is None:
        return None
    if adreno.GPU_NODE not in dt.nodes:
        raise ValueError('--present-beam needs the Adreno GPU node (an Adreno profile)')
    for base, size in owned:
        if INTF_PA < base + size and base < INTF_PA + PAGE:
            raise ValueError('the DPU INTF page overlaps guest or monitor memory')
    for name in (ABI_PROPERTY, PA_PROPERTY):
        if name in dt.nodes[adreno.GPU_NODE]:
            raise ValueError(f'the GPU node already has {name}')
    dt.add(adreno.GPU_NODE, ABI_PROPERTY, struct.pack('<I', ABI))
    dt.add(adreno.GPU_NODE, PA_PROPERTY, struct.pack('<Q', INTF_PA))
    return dict(node=adreno.GPU_NODE, properties=[ABI_PROPERTY, PA_PROPERTY], pa=INTF_PA)
