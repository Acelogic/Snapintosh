# SPDX-License-Identifier: MIT
"""Explicit SOC tuner policy for a virtual memory controller."""
from dataclasses import dataclass
import hashlib


@dataclass(frozen=True)
class SOCTunerBootSpec:
    node: str
    compatible: bytes
    mcc_power_gating_sha256: str


def populate_soctuner_boot(dt, spec):
    """Disable optional physical MCC gating, retaining the SOC tuner provider.

    Stock 26A428 start converts mcc-power-gating to boolean +0x9b. The
    enableMCCPowerGating method returns before any MCC function call when
    this flag is false. Zero is a policy selection here, not a completed
    hardware-disable request. Firmware identity is bound by GuestProfile.
    """
    props=dt.nodes.get(spec.node,{})
    def required(name):
        prop=props.get(name)
        if prop is None or prop.placeholder:
            raise ValueError(f'{spec.node}: unresolved {name}')
        return bytes(prop.value)
    if spec.compatible not in required('compatible').split(b'\0'):
        raise ValueError('unsupported SOC tuner provider')
    digest=spec.mcc_power_gating_sha256
    if (not isinstance(digest,str) or len(digest)!=64 or
            any(c not in '0123456789abcdef' for c in digest)):
        raise ValueError('invalid MCC power-gating source binding')
    raw=required('mcc-power-gating')
    disabled=bytes(4)
    if len(raw)!=4 or (raw!=disabled and hashlib.sha256(raw).hexdigest()!=digest):
        raise ValueError('SOC tuner MCC power-gating policy changed')
    # Accept the already-published zero for idempotence. All checks precede
    # the only mutation; other policies, providers and memory maps survive.
    dt.put(spec.node,'mcc-power-gating',disabled)
