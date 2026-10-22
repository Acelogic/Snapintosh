# SPDX-License-Identifier: MIT
"""Bind only the six selected CPU external-debug software locks."""
from dataclasses import dataclass
import struct
from devicemodel import CORESIGHT_LOCK_V1,DeviceModel,device_model_words

@dataclass(frozen=True)
class CoreSightBootSpec:
    node: str
    compatible: bytes
    base: int
    span: int

def coresight_models(dt,specs):
    models=[]
    if len(specs)!=6 or len({s.node for s in specs})!=6:
        raise ValueError('CoreSight needs the six bound CPU declarations')
    for index,spec in enumerate(specs):
        if spec.node!=f'/device-tree/cpus/cpu{index}' or spec.span!=0x300c8:
            raise ValueError('CoreSight CPU binding changed')
        props=dt.nodes.get(spec.node,{})
        def required(name):
            prop=props.get(name)
            if prop is None or prop.placeholder:
                raise ValueError(f'{spec.node}: unresolved {name}')
            return bytes(prop.value)
        if spec.compatible not in required('compatible').split(b'\0'):
            raise ValueError('CoreSight CPU identity changed')
        if (required('coresight-reg')!=struct.pack('<QQ',spec.base,spec.span) or
                required('reg-private')!=struct.pack('<Q',spec.base)):
            raise ValueError('CoreSight address declaration changed')
        models.append(DeviceModel(spec.node,CORESIGHT_LOCK_V1,spec.base,0x1000,
                                  (index,0,0,0,0)))
    device_model_words(models)
    return tuple(models)
