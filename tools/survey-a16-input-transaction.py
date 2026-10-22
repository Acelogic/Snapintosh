#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read IC20 packing/timing prerequisites after the stopped captures finish.

Failure inventory: all guards in survey-a16-input.py plus wrong configuration
offsets, stale firmware packing/timing assumptions, FIFO capacity mismatch and
confusing a register survey with a completed HID descriptor transaction.
This adapter only reads configuration/status; no FIFO pops or MMIO writes.
"""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
base = ROOT / 'tools/survey-a16-input.py'
base_sha = '3806a6af287ee293e08b862aa091e30219d320ef69fd9119b0b567800d1274d0'
assert hashlib.sha256(base.read_bytes()).hexdigest() == base_sha
source = base.read_text()
extra = [('byte_granularity', 0x254), ('tx_packing0', 0x260), ('tx_packing1', 0x264),
         ('tx_transfer_length', 0x26c), ('rx_transfer_length', 0x270), ('scl_counters', 0x278),
         ('rx_packing0', 0x284), ('rx_packing1', 0x288), ('master_irq_enable', 0x614),
         ('slave_irq_enable', 0x644), ('tx_watermark', 0x80c), ('rx_watermark', 0x810),
         ('rx_rfr_watermark', 0x814)]
anchor = 'sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()'
assert source.count(anchor) == 1
source = source.replace(anchor, 'REGISTERS += ' + repr(extra) + '\n' + anchor)
anchor = '    if args.check_inputs:'
assert source.count(anchor) == 1
source = source.replace(anchor, "    record['adapter_input_sha256'] = " + repr({str(base): base_sha}) + '\n' + anchor)
old_pid = "    try:\n        os.kill(launch['pid'],0)\n    except ProcessLookupError:\n        pass\n    else:\n        raise RuntimeError('XNU launcher remains live')"
new_pid = """    from datetime import datetime, timezone
    import subprocess
    observed = subprocess.run(['ps', '-p', str(launch['pid']), '-o', 'lstart='],
        env=dict(os.environ, TZ='UTC', LC_ALL='C'), capture_output=True, text=True)
    if observed.stdout.strip():
        started = datetime.strptime(observed.stdout.strip(), '%a %b %d %H:%M:%S %Y').replace(tzinfo=timezone.utc).timestamp()
        assert started > launch['finished'], 'original launcher may still be present'
    else:
        assert observed.returncode == 1 and not observed.stderr.strip(), observed.stderr"""
assert source.count(old_pid) == 1
source = source.replace(old_pid, new_pid)
anchor = "        record['status']='STOPPED_IC20_REGISTERS_CAPTURED'"
assert source.count(anchor) == 1
source = source.replace(anchor, """        record['transaction_prerequisites'] = dict(
            tx_fifo_width=(values['hardware_parameter0'] >> 24) & 63,
            tx_fifo_depth=(values['hardware_parameter0'] >> 16) & 63,
            rx_fifo_width=(values['hardware_parameter1'] >> 24) & 63,
            rx_fifo_depth=(values['hardware_parameter1'] >> 16) & 63,
            packing_8bit_4bytes_msb_first=dict(cfg0='0x7f8fe', cfg1='0xffefe'),
            tx_packing_matches=values['tx_packing0']==0x7f8fe and values['tx_packing1']==0xffefe,
            rx_packing_matches=values['rx_packing0']==0x7f8fe and values['rx_packing1']==0xffefe,
            scl_high_count=(values['scl_counters'] >> 20) & 1023,
            scl_low_count=(values['scl_counters'] >> 10) & 1023,
            scl_cycle_count=values['scl_counters'] & 1023,
            boundary='Observed configuration only; no bus transaction or HID descriptor proof')
""" + anchor)
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))
