#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read and verify the physical ECKB HID descriptor after a qualified XNU stop.

Failure inventory: docs/A16-HID-DESCRIPTOR-TRANSACTION-20260928.md.
--check-inputs is offline. This is a controller-local transaction, not a guest
HID driver or keyboard-input qualification. Never run beside another A16 client.
"""
from pathlib import Path
import hashlib
import json
import struct
import time

ROOT = Path(__file__).resolve().parents[1]
BASE = 0x0088c000
DONE, CANCEL, ABORT = 1, 1 << 4, 1 << 5
RX_WM, RX_LAST, TX_WM = 1 << 26, 1 << 27, 1 << 30
ERRORS = (1 << 1) | (1 << 2) | (1 << 3) | (1 << 10) | (1 << 12) | (1 << 13) | (1 << 24) | (1 << 29)
EVENTS = DONE | CANCEL | ABORT | RX_WM | RX_LAST | TX_WM | ERRORS
ACTIVE = 1 | (1 << 12)
TX_WORDS, RX_WORDS = (1 << 28) - 1, (1 << 25) - 1


def perform_descriptor(proxy, values, record, output):
    required = {
        'fifo_disabled': 0, 'engine_status': 0, 'master_clock': 0x21,
        'clock_select': 0, 'dma_mode': 0, 'tx_fifo_status': 0, 'rx_fifo_status': 0,
        'byte_granularity': 0, 'tx_packing0': 0x7f8fe, 'tx_packing1': 0xffefe,
        'rx_packing0': 0x7f8fe, 'rx_packing1': 0xffefe, 'scl_counters': 0x503018,
    }
    assert (values['firmware_revision'] >> 8) & 255 == 3, 'not I2C firmware'
    for name, expected in required.items():
        assert values[name] == expected, (name, hex(values[name]), hex(expected))
    for name in ['hardware_parameter0', 'hardware_parameter1']:
        assert (values[name] >> 24) & 63 == 32 and (values[name] >> 16) & 63 == 32
    assert not values['master_irq_status'] & EVENTS, 'preexisting transaction/error events'
    transfer = record['descriptor_transaction'] = dict(
        controller_base=hex(BASE), peripheral_address=0x15, descriptor_register=1,
        method='WRITE with STOP_STRETCH, then repeated-START READ',
        command_timeout_seconds=1.0, cleanup_timeout_seconds=0.5,
        journal=[], attempts=[], status='STARTING')
    sound, changed = True, False

    def save():
        output.write_text(json.dumps(record, indent=2) + '\n')

    def read(offset):
        nonlocal sound
        try:
            return proxy.read32(BASE + offset)
        except BaseException:
            sound = False
            raise

    def write(offset, value, purpose):
        nonlocal sound, changed
        row = dict(offset=hex(offset), value=hex(value), purpose=purpose,
                   intent_time=time.time(), confirmed=False)
        transfer['journal'].append(row)
        record['mmio_writes'] = changed = True
        save()
        try:
            proxy.write32(BASE + offset, value)
        except BaseException:
            sound = False
            row['transport_uncertain'] = True
            save()
            raise
        row.update(confirmed=True, confirmed_time=time.time())
        save()

    def guard():
        nonlocal sound
        try:
            state = proxy.serror_state()
            assert state['mechanism'] and not any(state[k] for k in ['before', 'during', 'unconsumed']), state
            return state
        except BaseException:
            sound = False
            raise

    def wait_for(bits, label, timeout=1.0, allow_errors=False):
        deadline, previous, polls = time.monotonic() + timeout, None, 0
        states = []
        transfer.setdefault('polls', []).append(dict(label=label, states=states))
        while time.monotonic() < deadline and polls < 1024:
            status = read(0x610)
            polls += 1
            if status != previous:
                states.append(dict(status=hex(status), time=time.time(), poll=polls))
                previous = status
            if status & ERRORS and not allow_errors:
                raise RuntimeError(f'{label}: controller error {status:#x}')
            if status & bits:
                return status
            time.sleep(0.001)
        raise TimeoutError(label)

    def acknowledge(status, purpose):
        if status & EVENTS:
            write(0x618, status & EVENTS, purpose)

    def idle():
        return not read(0x40) & ACTIVE

    saved = {0x26c: values['tx_transfer_length'], 0x270: values['rx_transfer_length'],
             0x614: values['master_irq_enable']}
    try:
        transfer['guard_before_commands'] = guard()
        write(0x614, saved[0x614] | EVENTS, 'enable polled master completion/error events')
        for attempt in range(2):
            assert idle() and not read(0x800) & TX_WORDS and not read(0x804) & RX_WORDS, 'transaction did not begin with idle empty FIFOs'
            prior_status = read(0x610)
            assert not prior_status & ERRORS, f'late controller error before transaction: {prior_status:#x}'
            acknowledge(prior_status, 'clear observed prior completion events')
            write(0x26c, 2, 'two-byte HID descriptor register selector')
            write(0x600, (1 << 27) | (0x15 << 9) | 4, 'WRITE to ECKB with STOP_STRETCH')
            write(0x700, 1, 'TX bytes 01 00; unused packed bytes ignored by explicit length')
            acknowledge(wait_for(DONE, f'write-{attempt}'), 'acknowledge selector WRITE completion')
            write(0x270, 30, 'exact HID descriptor read length')
            write(0x600, (2 << 27) | (0x15 << 9), 'READ from ECKB with final STOP')
            status = wait_for(DONE, f'read-{attempt}')
            assert idle(), 'READ completed but engine remains active'
            fifo_status = read(0x804)
            words = fifo_status & RX_WORDS
            assert words == 8, f'unexpected descriptor FIFO word count: {words}'
            record['fifo_data_reads'] = True
            row = dict(attempt=attempt + 1, irq_status=hex(status), fifo_status=hex(fifo_status),
                       receive_words=[], fifo_pop_journal=[], raw_hex=None)
            transfer['attempts'].append(row)
            save()
            for _ in range(words):
                pop = dict(word_index=len(row['receive_words']), intent_time=time.time(), confirmed=False)
                row['fifo_pop_journal'].append(pop)
                save()
                value = read(0x780)
                row['receive_words'].append(value)
                pop.update(confirmed=True, value=hex(value), confirmed_time=time.time())
                save()
            assert not read(0x804) & RX_WORDS, 'receive FIFO did not drain'
            raw = struct.pack('<8I', *row['receive_words'])[:30]
            row['raw_hex'] = raw.hex()
            names = ['descriptor_length', 'version', 'report_descriptor_length', 'report_descriptor_register',
                     'input_register', 'maximum_input_length', 'output_register', 'maximum_output_length',
                     'command_register', 'data_register', 'vendor_id', 'product_id', 'device_version', 'reserved']
            row['descriptor'] = dict(zip(names, struct.unpack('<13HI', raw)))
            descriptor = row['descriptor']
            assert descriptor['descriptor_length'] == 30 and descriptor['version'] == 0x100, descriptor
            assert 0 < descriptor['report_descriptor_length'] <= 16384, descriptor
            assert 2 <= descriptor['maximum_input_length'] <= 4096, descriptor
            assert descriptor['maximum_output_length'] <= 4096 and descriptor['reserved'] == 0, descriptor
            final_status = read(0x610)
            row['final_irq_status'] = hex(final_status)
            assert not final_status & ERRORS, f'late controller error after descriptor: {final_status:#x}'
            acknowledge(status | final_status, 'acknowledge descriptor READ completion')
            row['guard_after'] = guard()
            save()
        assert transfer['attempts'][0]['raw_hex'] == transfer['attempts'][1]['raw_hex'], 'descriptor changed between transactions'
        transfer['status'] = 'TWO_IDENTICAL_HID_DESCRIPTORS'
    except BaseException as error:
        transfer.update(status='FAILED', error=repr(error))
        raise
    finally:
        cleanup = transfer['cleanup'] = dict(transport_sound=sound, restored=False)
        try:
            if changed and sound:
                cleanup['guard_before'] = guard()
                if not idle():
                    for control, completed, label in [(4, CANCEL, 'cancel'), (2, ABORT, 'abort')]:
                        write(0x604, control, 'bounded cleanup ' + label)
                        try:
                            acknowledge(wait_for(completed, label, 0.5, allow_errors=True), 'acknowledge cleanup ' + label)
                        except TimeoutError:
                            cleanup[label + '_timeout'] = True
                        if idle():
                            break
                assert idle(), 'cleanup failed to idle the controller'
                acknowledge(read(0x610), 'acknowledge observed final events')
                for offset, value in saved.items():
                    write(offset, value, 'restore saved controller configuration')
                    assert read(offset) == value, 'controller configuration restoration failed'
                cleanup.update(restored=True, engine_status=hex(read(0x40)),
                    tx_fifo_status=hex(read(0x800)), rx_fifo_status=hex(read(0x804)), io_status=hex(read(0x908)),
                    guard_after=guard())
                cleanup['fifos_empty'] = not (int(cleanup['tx_fifo_status'], 16) & TX_WORDS or int(cleanup['rx_fifo_status'], 16) & RX_WORDS)
                cleanup['io_inputs_match'] = int(cleanup['io_status'], 16) & 3 == values['io_status'] & 3
                if transfer['status'] == 'TWO_IDENTICAL_HID_DESCRIPTORS':
                    assert cleanup['fifos_empty'] and cleanup['io_inputs_match'], 'successful descriptor read did not leave empty FIFOs and original line inputs'
            elif changed:
                cleanup['reason'] = 'uncertain transport or SError; no further MMIO cleanup attempted'
        except BaseException as error:
            cleanup['error'] = repr(error)
            transfer['status'] = 'FAILED'
            raise
        finally:
            save()
    assert transfer['status'] == 'TWO_IDENTICAL_HID_DESCRIPTORS' and transfer['cleanup']['restored']


template = ROOT / 'tools/survey-a16-input-transaction.py'
assert hashlib.sha256(template.read_bytes()).hexdigest() == '6b7532d982bd097c64794732421867aa75915f9e83330fedae3041bf595bde8f'
source = template.read_text()
dispatch = "exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))"
assert source.count(dispatch) == 1
namespace = dict(__file__=str(template), __name__='prepared_survey')
exec(compile(source.replace(dispatch, 'GENERATED_SOURCE = source'), str(template), 'exec'), namespace)
source = namespace['GENERATED_SOURCE']
anchor = '    if args.check_inputs:'
assert source.count(anchor) == 1
source = source.replace(anchor, "    record['operation'] = 'BOUNDED_ECKB_HID_DESCRIPTOR_READ'\n"
    "    record['boundary'] = 'Physical descriptor response only; no keyboard reports, guest HID driver or visible input qualification'\n"
    "    record['transaction_plan'] = dict(peripheral_address=21, descriptor_register=1, read_bytes=30, repetitions=2, "
    "command_timeout_seconds=1, writable_offsets=['0x26c','0x270','0x600','0x604','0x614','0x618','0x700'], fifo_pop_offset='0x780')\n"
    "    record['transaction_adapter_sha256'] = " + repr(hashlib.sha256(template.read_bytes()).hexdigest()) + "\n" + anchor)
anchor = "        proxy.read64(previous['address'])  # Poll a late SError after successful reads."
assert source.count(anchor) == 1
source = source.replace(anchor, "        perform_descriptor(proxy, {name: row['value'] for name,row in record['registers'].items()}, record, args.output)\n" + anchor)
source = source.replace('STOPPED_IC20_REGISTERS_CAPTURED', 'STOPPED_A16_HID_DESCRIPTOR_VERIFIED')
exec(compile(source, str(template), 'exec'), dict(__file__=__file__, __name__='__main__', perform_descriptor=perform_descriptor))
