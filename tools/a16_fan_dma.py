# SPDX-License-Identifier: MIT
"""Read-only plans for IC10 firmware GPI9 and the apps MMU-500 mapping."""
from a16_fan_gpi import Refused, require

SMMU = 0x15000000
SID = 0xCB6
# Qualcomm IDR0 can report more groups, but firmware may mishandle the
# nonarchitected suffix. The upstream detection writes S2CR, so it is excluded.
READABLE_GROUP_LIMIT = 128
CONTEXT_FAULT_MASK = 0xc00001fe  # FSR.Format[10:9] is read-only format, not a fault.
HEADER = {'scr0': 0, 'sacr': 0x10, 'idr0': 0x20, 'idr1': 0x24,
          'idr2': 0x28, 'idr7': 0x3c, 'gfsr': 0x48, 'gfsynr0': 0x50,
          'gfsynr1': 0x54, 'gfsynr2': 0x58, 'tlb_status': 0x74}


def identity_plan():
    result = [(f'smmu.{name}', SMMU + offset) for name, offset in HEADER.items()]
    # BIOS312 ac_fw_config_9 explicitly names this 16 KiB region for IC10.
    for tag, base in [('ch0', 0xA34000), ('ch1', 0xA34080), ('event', 0xA35000)]:
        for name, offset in {'config': 0, 'length': 4, 'base_low': 8, 'base_high': 12,
                             'rp_low': 16, 'rp_high': 20, 'wp_low': 24, 'wp_high': 28}.items():
            result.append((f'firmware_gpi9.{tag}.{name}', base + offset))
        if tag != 'event':
            for index in range(4):
                result.append((f'firmware_gpi9.{tag}.scratch{index}', base + 0x60 + index * 4))
    for name, offset in {'irq_type': 0x3080, 'irq_mask': 0x3088, 'ch_irq': 0x3090,
                         'event_irq': 0x3094, 'global_irq': 0x3100,
                         'general_irq': 0x3118, 'error_log': 0x3200}.items():
        result.append((f'firmware_gpi9.{name}', 0xA34000 + offset))
    return result


def values_for(reads, plan):
    expected = dict(plan)
    values = {}
    for row in reads:
        name = row['name']
        require(name in expected and int(row['address'], 0) == expected[name], 'unplanned register')
        require(name not in values, 'duplicate register')
        require(type(row['value']) is int and 0 <= row['value'] <= 0xffffffff, 'bad register value')
        values[name] = row['value']
    require(values.keys() == expected.keys(), 'incomplete capture')
    return values


def geometry(values):
    id0, id1 = values['smmu.idr0'], values['smmu.idr1']
    require(id0 not in (0, 0xffffffff) and id1 not in (0, 0xffffffff), 'unrecognized/zero MMU identity')
    require(id0 & (1 << 27), 'stream-indexed SMMU is outside this survey contract')
    groups = id0 & 255
    require(groups > 0, 'stream-matching SMMU reports no mapping groups')
    banks, s2banks = id1 & 255, (id1 >> 16) & 255
    stride = 1 << (16 if id1 >> 31 else 12)
    page_count = 1 << (((id1 >> 28) & 7) + 1)
    cb_base = SMMU + page_count * stride
    require(0 < banks <= 112 and s2banks <= banks, 'context geometry differs from A16 IORT bound')
    require(cb_base + banks * stride <= SMMU + 0x100000, 'context geometry exceeds IORT resource')
    extended = bool(values['smmu.scr0'] & 8)
    require(not extended or id0 & (1 << 8), 'EXIDENABLE without advertised extended IDs')
    sid_bits = 16 if extended else min((id0 >> 9) & 15, 15)
    require(0 < sid_bits <= 16 and SID < 1 << sid_bits, 'stream 0xcb6 exceeds SID width')
    readable_groups = min(groups, READABLE_GROUP_LIMIT)
    return dict(groups=groups, surveyed_groups=readable_groups,
                mapping_coverage_complete=groups == readable_groups,
                unsurveyed_groups=list(range(readable_groups, groups)),
                banks=banks, stage2_banks=s2banks, stride=stride,
                cb_base=cb_base, gr1=SMMU + stride, extended_ids=extended, sid_bits=sid_bits)


def identity_decode(reads):
    values = values_for(reads, identity_plan())
    result = dict(hardware_lease_admitted=False,
                  firmware_gpi9_states=[(values[f'firmware_gpi9.{tag}.config'] >> 20) & 15
                                        for tag in ('ch0', 'ch1', 'event')])
    try:
        result['geometry'] = geometry(values)
        result['next_phase'] = 'streams'
    except Refused as exc:
        result.update(next_phase=None, refusal=str(exc))
    return result


def streams_plan(identity):
    require(identity.get('status') == 'READ_COMPLETE' and identity.get('phase') == 'identity',
            'stream phase requires a completed identity capture')
    values = values_for(identity['reads'], identity_plan())
    shape = geometry(values)
    result = [(f'smmu.{name}', SMMU + offset) for name, offset in HEADER.items()]
    for index in range(shape['surveyed_groups']):
        result.extend([(f'smr{index}', SMMU + 0x800 + index * 4),
                       (f's2cr{index}', SMMU + 0xc00 + index * 4)])
    return result


def streams_decode(reads, identity):
    values = values_for(reads, streams_plan(identity))
    previous = values_for(identity['reads'], identity_plan())
    for name in HEADER:
        require(values[f'smmu.{name}'] == previous[f'smmu.{name}'], 'SMMU header changed between phases')
    shape = geometry(values)
    mask_limit = (1 << shape['sid_bits']) - 1
    routes, all_valid = [], []
    for index in range(shape['surveyed_groups']):
        smr, s2cr = values[f'smr{index}'], values[f's2cr{index}']
        valid = bool(s2cr & 1024) if shape['extended_ids'] else bool(smr & 0x80000000)
        if not valid:
            continue
        mask = (smr >> 16) & mask_limit
        stream = smr & mask_limit
        row = dict(index=index, sid=stream, mask=mask, type=(s2cr >> 16) & 3,
                   bank=s2cr & 255, matches_cb6=((SID ^ stream) & ~mask & mask_limit) == 0)
        all_valid.append(row)
        if row['matches_cb6']:
            routes.append(row)
    bank = (routes[0]['bank'] if shape['mapping_coverage_complete'] and
            len(routes) == 1 and routes[0]['type'] == 0 else None)
    context_reads = []
    if bank is not None:
        context_reads = context_registers(shape, bank)
    return dict(hardware_lease_admitted=False, target_sid=SID, matching_routes=routes,
                implemented_groups=shape['groups'], surveyed_groups=shape['surveyed_groups'],
                mapping_coverage_complete=shape['mapping_coverage_complete'],
                unsurveyed_groups=shape['unsurveyed_groups'],
                context_plan_refusal=(None if shape['mapping_coverage_complete'] else
                    'unobserved Qualcomm groups prevent global matching/ownership conclusions'),
                live_match_groups=all_valid, unique_translation_bank=bank,
                shared_bank_matches=[r['index'] for r in all_valid
                                     if bank is not None and r['type'] == 0 and r['bank'] == bank],
                next_context_read_plan=[dict(name=n, address=hex(a)) for n, a in context_reads],
                unmatched_is_not_mapping_proof=True)


def context_registers(shape, bank):
    require(0 <= bank < shape['banks'], 'observed translation names nonexistent bank')
    result = [(f'bank{bank}.cbar', shape['gr1'] + 4 * bank),
              (f'bank{bank}.cba2r', shape['gr1'] + 0x800 + 4 * bank)]
    base = shape['cb_base'] + shape['stride'] * bank
    for name, offset in {'sctlr': 0, 'actlr': 4, 'tcr2': 0x10,
                         'ttbr0_low': 0x20, 'ttbr0_high': 0x24,
                         'ttbr1_low': 0x28, 'ttbr1_high': 0x2c,
                         'tcr': 0x30, 'mair0': 0x38, 'mair1': 0x3c,
                         'fsr': 0x58, 'far_low': 0x60, 'far_high': 0x64,
                         'fsynr0': 0x68, 'fsynr1': 0x6c, 'tlb_status': 0x7f4}.items():
        result.append((f'bank{bank}.{name}', base + offset))
    return result


def context_subject(identity, streams):
    require(streams.get('status') == 'READ_COMPLETE' and streams.get('phase') == 'streams',
            'context observation requires a completed stream capture')
    decoded = streams_decode(streams['reads'], identity)
    routes = decoded['matching_routes']
    require(len(routes) == 1 and routes[0]['type'] == 0,
            'context observation requires one observed translating route')
    shape = geometry(values_for(identity['reads'], identity_plan()))
    context_registers(shape, routes[0]['bank'])
    return shape, routes[0], decoded


def context_plan(identity, streams):
    shape, route, _ = context_subject(identity, streams)
    index, bank = route['index'], route['bank']
    route_reads = [(f'smr{index}', SMMU + 0x800 + 4 * index),
                   (f's2cr{index}', SMMU + 0xc00 + 4 * index)]
    bank_reads = context_registers(shape, bank)
    # The first twelve bank words are translation controls; status follows.
    return ([(f'smmu.{name}', SMMU + offset) for name, offset in HEADER.items()] +
            route_reads + bank_reads +
            [('verify.' + name, address) for name, address in route_reads + bank_reads[:12]])


def context_decode(reads, identity, streams):
    values = values_for(reads, context_plan(identity, streams))
    shape, route, prior = context_subject(identity, streams)
    previous = values_for(streams['reads'], streams_plan(identity))
    for name in previous.keys() & values.keys():
        require(values[name] == previous[name], 'SMMU header/observed route changed')
    for name, value in values.items():
        if name.startswith('verify.'):
            require(value == values[name[7:]], 'translation controls changed during observation')
    bank = route['bank']
    word = lambda name: values[f'bank{bank}.{name}']
    return dict(hardware_lease_admitted=False, mapping_admitted=False,
                observation_only=True, observed_route=route, observed_bank=bank,
                mapping_coverage_complete=shape['mapping_coverage_complete'],
                unsurveyed_groups=shape['unsurveyed_groups'],
                observed_shared_bank_groups=[r['index'] for r in prior['live_match_groups']
                                             if r['type'] == 0 and r['bank'] == bank],
                controls_stable_between_reads=True, cbar_type=(word('cbar') >> 16) & 3,
                linked_stage2_bank=((word('cbar') >> 8) & 255
                                    if (word('cbar') >> 16) & 3 == 3 else None),
                va64=bool(word('cba2r') & 1), translation_enabled=bool(word('sctlr') & 1),
                ttbr0=word('ttbr0_low') | word('ttbr0_high') << 32,
                ttbr1=word('ttbr1_low') | word('ttbr1_high') << 32,
                tcr=word('tcr'), tcr2=word('tcr2'), fault_status=word('fsr'),
                fault_bits=word('fsr') & CONTEXT_FAULT_MASK,
                fault_format=(word('fsr') >> 9) & 3,
                tlb_status=word('tlb_status'), table_walk_admitted=False)


def linked_subject(identity, streams, context_capture):
    require(context_capture.get('status') == 'READ_COMPLETE' and
            context_capture.get('phase') == 'context', 'linked phase requires completed context capture')
    decoded = context_decode(context_capture['reads'], identity, streams)
    shape, route, _ = context_subject(identity, streams)
    require(decoded['cbar_type'] == 3, 'observed bank does not link a stage2 bank')
    values = values_for(identity['reads'], identity_plan())
    require(values['smmu.idr0'] & (1 << 29), 'SMMU does not advertise stage2 translation')
    bank = decoded['linked_stage2_bank']
    require(bank != route['bank'] and 0 <= bank < shape['banks'], 'invalid/self-referential linked bank')
    return shape, route, bank


def stage2_registers(shape, bank):
    base = shape['cb_base'] + shape['stride'] * bank
    result = [(f'bank{bank}.cbar', shape['gr1'] + 4 * bank),
              (f'bank{bank}.cba2r', shape['gr1'] + 0x800 + 4 * bank)]
    for name, offset in {'sctlr': 0, 'actlr': 4, 'ttbr0_low': 0x20, 'ttbr0_high': 0x24,
                         'tcr': 0x30, 'fsr': 0x58, 'far_low': 0x60, 'far_high': 0x64,
                         'fsynr0': 0x68, 'fsynr1': 0x6c, 'tlb_status': 0x7f4}.items():
        result.append((f'bank{bank}.{name}', base + offset))
    return result


def linked_plan(identity, streams, context_capture):
    shape, route, bank = linked_subject(identity, streams, context_capture)
    index = route['index']
    route_reads = [(f'smr{index}', SMMU + 0x800 + 4 * index),
                   (f's2cr{index}', SMMU + 0xc00 + 4 * index)]
    parent_reads = context_registers(shape, route['bank'])[:12]
    bank_reads = stage2_registers(shape, bank)
    return ([(f'smmu.{name}', SMMU + offset) for name, offset in HEADER.items()] +
            route_reads + parent_reads + bank_reads +
            [('verify.' + name, address) for name, address in
             route_reads + parent_reads + bank_reads[:7]])


def linked_decode(reads, identity, streams, context_capture):
    values = values_for(reads, linked_plan(identity, streams, context_capture))
    shape, route, bank = linked_subject(identity, streams, context_capture)
    previous = values_for(context_capture['reads'], context_plan(identity, streams))
    for name in previous.keys() & values.keys():
        require(values[name] == previous[name], 'parent translation controls changed')
    for name, value in values.items():
        if name.startswith('verify.'):
            require(value == values[name[7:]], 'linked translation controls changed during observation')
    word = lambda name: values[f'bank{bank}.{name}']
    require((word('cbar') >> 16) & 3 == 0, 'linked bank is not a stage2 context')
    return dict(hardware_lease_admitted=False, mapping_admitted=False, table_walk_admitted=False,
                observation_only=True, parent_bank=route['bank'], observed_stage2_bank=bank,
                mapping_coverage_complete=shape['mapping_coverage_complete'],
                unsurveyed_groups=shape['unsurveyed_groups'], controls_stable_between_reads=True,
                va64=bool(word('cba2r') & 1), translation_enabled=bool(word('sctlr') & 1),
                ttbr0=word('ttbr0_low') | word('ttbr0_high') << 32, tcr=word('tcr'),
                fault_status=word('fsr'), fault_bits=word('fsr') & CONTEXT_FAULT_MASK,
                fault_format=(word('fsr') >> 9) & 3, tlb_status=word('tlb_status'))
