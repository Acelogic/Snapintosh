# SPDX-License-Identifier: MIT
"""Read native processor states and requested/effective recommendation masks.

Caller supplies the audited stopped topology and bounded kernel reader. No
guest calls or writes. Layout comes from this kernel's cpu_to_processor,
processor_info and core-recommendation update instructions.
"""
import struct

REQUESTED = 0xfffffe000c6bc7a8
EFFECTIVE = 0xfffffe000c6bc7c8
PROCESSOR_DELTA = -0x708
STATES = {0:'offline',2:'starting',3:'pending_offline',4:'idle',5:'dispatching',6:'running'}
WITNESSES = (
    (0xfffffe000ba7ecd8, 0x900063e8),
    (0xfffffe000ba7ecdc, 0x911cc108),
    (0xfffffe000ba7ece0, 0x900063e9),
    (0xfffffe000ba7ece4, 0x9100a129),
    (0xfffffe000ba7ece8, 0xf940014a),
    (0xfffffe000ba7ecec, 0xcb080128),
    (0xfffffe000ba7ecf0, 0x8b080148),
    (0xfffffe000b91ebac, 0xb9406401),
    (0xfffffe000b91ec04, 0xb9400008),
    (0xfffffe000b932e08, 0x39001356),
    (0xfffffe000b932e0c, 0xb9406748),
    (0xfffffe000b932e14, 0xd0006c4a),
    (0xfffffe000b932e18, 0xf943e549),
    (0xfffffe000b932e1c, 0xaa090108),
    (0xfffffe000b932e20, 0xf903e548),
    (0xfffffe000b933094, 0x390012ff),
    (0xfffffe000b933098, 0xb94066e8),
    (0xfffffe000b938e38, 0x90006c28),
    (0xfffffe000b938e3c, 0x911ec108),
    (0xfffffe000b938e48, 0xf9000115),
    (0xfffffe000b938e4c, 0xf9400508),
    (0xfffffe000b938e50, 0x8a150108),
    (0xfffffe000b938e58, 0xf9000515),
    (0xfffffe000b938e5c, 0xf9400108),
    (0xfffffe000b938e60, 0x8a0802a8),
    (0xfffffe000b938e64, 0x90006c29),
    (0xfffffe000b938e68, 0xf903d528),
)

def collect(topology, read, instruction):
    for address,word in WITNESSES:
        if instruction(address)!=word:
            raise ValueError(f'native processor witness differs at {address:#x}')
    cpus=topology['cpu_data_entries'];count=topology['num_cpus']
    if not 1<=count<=64 or len(cpus)!=count or {c['index'] for c in cpus}!=set(range(count)):
        raise ValueError('invalid processor topology coverage')
    addresses=[int(c['data_va'],16)+PROCESSOR_DELTA for c in cpus]
    if len(set(addresses))!=count or any(a&7 or not 0xfffffe0000000000<=a<0xffffffffffffe000 for a in addresses):
        raise ValueError('invalid processor address geometry')
    def exact(address,size):
        raw=read(address,size)
        if len(raw)!=size:raise ValueError('short native processor read')
        return raw
    mask_raw=exact(REQUESTED,24);requested,system,user=struct.unpack('<3Q',mask_raw)
    effective_raw=exact(EFFECTIVE,8);effective,=struct.unpack('<Q',effective_raw)
    if requested!=system&user or effective&~((1<<count)-1):
        raise ValueError('native core mask relationship differs')
    rows=[]
    for cpu,address in zip(cpus,addresses):
        raw=exact(address,0x68);state,=struct.unpack_from('<I',raw)
        cpuid,=struct.unpack_from('<I',raw,0x64);recommended=raw[4]
        if cpuid!=cpu['index'] or state not in STATES or recommended not in (0,1):
            raise ValueError('native processor identity or state differs')
        if recommended!=bool(effective&(1<<cpuid)):
            raise ValueError('processor recommendation differs from effective mask')
        rows.append(dict(cpu=cpuid,processor=hex(address),state=state,state_name=STATES[state],
                         recommended=bool(recommended),raw_hex=raw.hex()))
    return dict(complete=True,requested=hex(requested),requested_system=hex(system),
                requested_user=hex(user),effective=hex(effective),
                requested_raw_hex=mask_raw.hex(),effective_raw_hex=effective_raw.hex(),
                processors=rows,witnesses=[dict(address=hex(a),word=hex(w)) for a,w in WITNESSES],
                boundary='Native processor IDs agree with audited CPU topology; per-processor recommendations agree with the effective mask. Request masks can differ from effective policy. Idle does not prove an unavailable core or scheduler failure.')
