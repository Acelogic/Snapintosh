# SPDX-License-Identifier: MIT
"""PMGR performance metadata for a fixed-state virtual platform."""
from dataclasses import dataclass
import hashlib
import struct

# Nominal virtual ANE frequency/voltage records. The nonzero voltage word
# selects PMGR's frequency-table format: Hz -> MHz, count = record count.
# With voltage zero, the first word is instead a logical state index, and
# PMGR derives count = last index + 1 (1000,0 therefore creates 1001 states).
# Neither word is host telemetry or authorization for a voltage transition.
# CLPC drops fANE index zero, so reserve it for an inactive clock and back
# selector one with the active frequency. These are not electrical controls.
VIRTUAL_ANE_STATES = ((0, 1000), (1_000_000_000, 1000))
VIRTUAL_ANE_ACTIVE_INDEX = 1

# Only features whose absent-property path has been audited in the bound
# kernel. Required platform providers and power-domain topology are not here.
OPTIONAL_FEATURES = frozenset(('cpu-apsc', 'soc-tvm', 'disp-tvm', 'ave-tvm',
                               'gfx-tvm', 'dcs-tvm', 'ppt-thrtl', 'llc-thrtl',
                               'amx-thrtl', 'cpu-fixed-freq-pll-relock'))


@dataclass(frozen=True)
class PMGRBootSpec:
    node: str
    compatible: bytes
    domains_sha256: str
    tables: tuple[tuple[int, tuple[tuple[int, int], ...]], ...]
    omit_hw_dpe_sha256: str | None = None
    omit_features: tuple[tuple[str, str], ...] = ()


def populate_pmgr_boot(dt, spec):
    """Publish only the audited logical states; no PMGR MMIO is completed.

    26A428 initDriver divides each OSData length by eight. CPU domains use
    nonzero Q16-nanosecond periods; ...978a0f8 converts them to MHz with
    65536000 / period. A single period 65536 advertises a nominal 1 GHz
    virtual CPU, not Qualcomm clock telemetry or a host frequency change.
    ANE uses inactive/active frequency records with nonzero nominal voltage words;
    this is fixed virtual metadata, with no physical electrical backend.
    Other indexed domains use consecutive logical levels and voltage zero.
    All transition/control accesses still require a separate model.
    """
    props=dt.nodes.get(spec.node,{})
    def required(name):
        prop=props.get(name)
        if prop is None or prop.placeholder:
            raise ValueError(f'{spec.node}: unresolved {name}')
        return bytes(prop.value)
    if spec.compatible not in required('compatible').split(b'\0'):
        raise ValueError('unsupported PMGR provider')
    # Stock 26A428 initDriver ...978e870 skips local hardware DPE node
    # construction when this optional property is absent. We have no energy
    # sampling backend, so do not advertise one. Bind the omission to the
    # audited source payload; CPU energy metadata and PMP remain unchanged.
    # An already absent property is allowed for idempotent publication.
    # The profile may omit audited APSC/TVM/throttler/PLL features: the table starts
    # invalid, and start() ...977f584 only marks it valid after a successful
    # feature property lookup. restoreHW consults validFeature before issuing
    # its control. A value of zero would still advertise the feature and
    # request a hardware disable sequence, so absence is deliberate.
    features=spec.omit_features
    if (type(features) is not tuple or
            any(type(entry) is not tuple or len(entry)!=2 or
                type(entry[0]) is not str or entry[0] not in OPTIONAL_FEATURES
                for entry in features) or
            len({name for name,_ in features})!=len(features)):
        raise ValueError('unsupported or duplicate optional PMGR feature')
    if any(digest is None for _,digest in features):
        raise ValueError('optional PMGR feature requires a source binding')
    omissions = (('hw-dpe-reg', spec.omit_hw_dpe_sha256),) + features
    for name, digest in omissions:
        if digest is None:
            continue
        if (not isinstance(digest, str) or len(digest) != 64 or
                any(c not in '0123456789abcdef' for c in digest)):
            raise ValueError(f'invalid {name} source binding')
        if name in props and hashlib.sha256(required(name)).hexdigest() != digest:
            raise ValueError(f'PMGR {name} capability changed')
    raw=required('perf-domains')
    if not raw or len(raw)%28 or hashlib.sha256(raw).hexdigest()!=spec.domains_sha256:
        raise ValueError('PMGR performance-domain topology changed')
    kinds={}
    for off in range(0,len(raw),28):
        domain,kind=raw[off],raw[off+2]
        if domain in kinds or kind not in (0,1):
            raise ValueError('unsupported PMGR domain kind or duplicate ID')
        kinds[domain]=kind
    staged={}
    for domain,entries in spec.tables:
        if type(domain) is not int or domain not in kinds or domain in staged:
            raise ValueError('invalid or duplicate virtual performance domain')
        if not 1<=len(entries)<32:
            raise ValueError('virtual performance table must be nonempty and bounded')
        for entry in entries:
            if len(entry)!=2 or any(type(v) is not int or not 0<=v<=0xffffffff for v in entry):
                raise ValueError('performance entries must contain two u32 words')
        if kinds[domain]==1:
            if entries!=((65536,0),):
                raise ValueError('virtual CPU supports only its fixed nominal state')
        elif domain==8:
            if entries!=VIRTUAL_ANE_STATES:
                raise ValueError('virtual ANE requires its inactive and active frequency-format states')
        elif entries!=tuple((i,0) for i in range(len(entries))):
            raise ValueError('virtual indexed domains require consecutive unpowered levels')
        encoded=b''.join(struct.pack('<II',*entry) for entry in entries)
        previous=props.get(f'voltage-states{domain}')
        if previous is not None and (previous.placeholder or bytes(previous.value)!=encoded):
            raise ValueError(f'conflicting voltage-states{domain}')
        # Firmware may already select an initial/nominal/boost index. Never
        # silently publish a smaller table that makes such indices invalid.
        for prefix in ('initial-performance','nominal-performance','boost-performance'):
            name=f'{prefix}{domain}'
            if name in props:
                value=required(name)
                if len(value)!=4 or struct.unpack('<I',value)[0]>=len(entries):
                    raise ValueError(f'{name} is outside the virtual state table')
        staged[domain]=encoded
    if set(staged)!=set(kinds):
        raise ValueError('virtual tables must cover every declared performance domain')
    # Validate the complete graph before publishing any property.
    for domain,encoded in staged.items():
        dt.put(spec.node,f'voltage-states{domain}',encoded)
    for name, digest in omissions:
        if digest is not None:
            props.pop(name, None)
    return tuple((domain,len(encoded)//8) for domain,encoded in staged.items())
