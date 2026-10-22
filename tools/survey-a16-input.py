#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Observe the ACPI-identified keyboard controller only after XNU has stopped."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import struct
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT/'build/a16-input-resources-20260927-v1.json'
INVENTORY_SHA = '7da1fb40b58e4dbc600ec5c3c68f74fb0125df6fad12b50e423e3c8798ff7b6b'
BASE, EXTENT = 0x0088c000, 0x4000
# Status/configuration only: no RX FIFO, IRQ-clear, command or DMA pointer access.
REGISTERS = [('firmware_revision',0x68),('fifo_disabled',0x64),('engine_status',0x40),
    ('master_clock',0x48),('clock_control',0x60),('clock_select',0x7c),('dma_mode',0x258),
    ('master_irq_status',0x610),('slave_irq_status',0x640),('tx_fifo_status',0x800),
    ('rx_fifo_status',0x804),('io_status',0x908),('dma_interface',0xe20),
    ('hardware_parameter0',0xe24),('hardware_parameter1',0xe28),('hardware_parameter2',0xe2c)]
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()


def inventory():
    assert sha(INVENTORY) == INVENTORY_SHA
    result = json.loads(INVENTORY.read_text())
    assert result['status'] == 'CAPTURED_ACPI_INPUT_DECLARATIONS_VERIFIED'
    for name, digest in result['inputs_sha256'].items():
        assert sha(name) == digest, name
    controller = result['devices']['IC20']
    memory = [r for r in controller['resources']['RBUF']['decoded'] if r['type']=='fixed_memory32']
    assert len(memory)==1 and memory[0]['address']==BASE and memory[0]['bytes']==EXTENT
    keyboard = result['devices']['ECKB']
    assert keyboard['hardware_ids']==['QTEC0001'] and 'PNP0C50' in keyboard['compatible_ids']
    serial = [r for r in keyboard['resources']['RBUF']['decoded'] if r['type']=='i2c']
    assert len(serial)==1 and serial[0]['controller']=='\\_SB.IC20'
    assert serial[0]['address']==0x15 and serial[0]['speed_hz']==400000
    assert all(offset%4==0 and 0<=offset<=EXTENT-4 for _,offset in REGISTERS)
    return dict(controller='IC20',keyboard='ECKB',base=hex(BASE),extent=EXTENT,
        peripheral_address=0x15,speed_hz=400000,inventory_sha256=INVENTORY_SHA,
        registers=[dict(name=name,offset=hex(offset),address=hex(BASE+offset)) for name,offset in REGISTERS])


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--after-prefix', required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--check-inputs', action='store_true')
    args = ap.parse_args()
    assert re.fullmatch('[a-z0-9-]+',args.after_prefix)
    assert not args.output.exists()
    plan = inventory()
    record = dict(status='PLAN_VERIFIED',hardware_access=False,plan=plan,
        source_sha256=sha(Path(__file__)),started=time.time(),registers={},mmio_writes=False,
        fifo_data_reads=False,guest_resumed=False,
        boundary='Controller register observation only; no I2C transaction, input report or guest HID qualification.')
    if args.check_inputs:
        with args.output.open('x') as f:
            f.write(json.dumps(record,indent=2)+'\n')
        print(json.dumps(dict(status=record['status'],output=str(args.output))))
        return
    path = lambda suffix: ROOT/'build'/(args.after_prefix+suffix)
    launch, audit = [json.loads(path(s).read_text()) for s in ['-launch.json','-audit.json']]
    assert launch.get('finished') and isinstance(launch.get('exit_code'),int)
    assert audit['runtime_stop_qualified'] and audit['user_mapping_qualified']
    assert audit['monitor_sha256']==launch['monitor_sha256']
    try:
        os.kill(launch['pid'],0)
    except ProcessLookupError:
        pass
    else:
        raise RuntimeError('XNU launcher remains live')
    for name,digest in launch['source_sha256'].items():
        assert sha(name)==digest,name
    runtime = Path(launch['runtime_root'])
    assert runtime == Path(launch['observer_root'])
    sys.path[:0] = [str(runtime/'probes'),str(runtime/'tools')]
    import run
    from monitor_layout import MonitorLayout
    layout = MonitorLayout()
    assert layout.size('context')==launch['context_bytes']
    blob = Path(launch['monitor_path']).read_bytes()
    assert hashlib.sha256(blob).hexdigest()==launch['monitor_sha256']
    generation = launch['adreno_record']['stage_generation']
    record.update(status='RUNNING',hardware_access=True,generation=generation,
        launch_sha256=sha(path('-launch.json')),audit_sha256=sha(path('-audit.json')),
        monitor_sha256=launch['monitor_sha256'])
    # Reserve the evidence path before touching the target; rewrite it only here.
    with args.output.open('x') as f:
        f.write(json.dumps(record,indent=2)+'\n')
    proxy = None
    previous = None
    try:
        proxy = run.connect('udp://en5',tries=1)
        info = proxy.bootinfo()
        assert info['current_el']==2 and info['stage_generation']==generation
        work,size = run.resident_work(proxy,info)
        def read(pa,count):
            return b''.join(proxy.readmem(pa+i,min(65536,count-i),live=True)
                for i in range(0,count,65536))
        assert read(info['heap_base']+run.CODE_AT,len(blob))==blob
        stop_pa = work+layout.offset('context','services')
        stop = struct.pack('<8Q',*audit['service'])
        assert read(stop_pa,64)==stop
        previous = proxy.serror_state()
        record['guard_before']=previous
        assert previous['mechanism'] and not any(previous[k] for k in ['before','during','unconsumed'])
        proxy.serror_reset()
        proxy.serror_strict(True)
        for name,offset in REGISTERS:
            record['reading']=dict(name=name,address=hex(BASE+offset))
            value = proxy.read32(BASE+offset)
            record['registers'][name]=dict(address=hex(BASE+offset),value=value,hex=hex(value))
        proxy.read64(previous['address'])  # Poll a late SError after successful reads.
        record['guard_after']=proxy.serror_state()
        assert not any(record['guard_after'][k] for k in ['before','during','unconsumed'])
        assert read(stop_pa,64)==stop
        values = {name:row['value'] for name,row in record['registers'].items()}
        record['interpretation']=dict(protocol=(values['firmware_revision']>>8)&255,
            expected_i2c_protocol=3,fifo_disabled=bool(values['fifo_disabled']&1),
            master_active=bool(values['engine_status']&1),
            slave_active=bool(values['engine_status']&(1<<12)),
            master_clock_enabled=bool(values['master_clock']&1),
            master_clock_divider=(values['master_clock']>>4)&0xfff,
            dma_mode_enabled=bool(values['dma_mode']&1))
        record['status']='STOPPED_IC20_REGISTERS_CAPTURED'
    except BaseException as error:
        record.update(status='FAILED',error=repr(error))
        raise
    finally:
        if proxy is not None:
            if previous is not None:
                try:
                    if 'guard_after' not in record:
                        record['guard_after']=proxy.serror_state()
                    proxy.serror_strict(bool(previous['flags']&run.q1n1.SERROR_STRICT))
                except BaseException as error:
                    record['guard_restore_error']=repr(error)
                    record['status']='FAILED'
            proxy.link.close()
        record['finished']=time.time()
        args.output.write_text(json.dumps(record,indent=2)+'\n')
    assert record['status']=='STOPPED_IC20_REGISTERS_CAPTURED'
    print(json.dumps(dict(status=record['status'],output=str(args.output),interpretation=record['interpretation'])))


if __name__=='__main__':
    main()
