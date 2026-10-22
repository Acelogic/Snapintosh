#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read the physical A16 HID report descriptor after a qualified guest stop.

Failure inventory: docs/A16-HID-REPORT-DESCRIPTOR-20260928.md.
--check-inputs is offline. This does not initialize the device or deliver input.
"""
from pathlib import Path
import hashlib
import json
import struct
import time

ROOT = Path(__file__).resolve().parents[1]
DESCRIPTOR_READER = ROOT / 'tools/read-a16-hid-descriptor.py'
DESCRIPTOR_READER_SHA = '1dbc171f55cfa135ea99f848caff29483408e964199a67b5bd261cbd75dddc61'
DESCRIPTOR_EVIDENCE = ROOT / 'build/a16-hid-descriptor-gen56-20260928-v1.json'
DESCRIPTOR_EVIDENCE_SHA = '3a8895c73445ad76141a9bf825a45a7b2e9f2220ab94f1c73711a7d92a811ff6'
BASE = 0x0088c000
DONE, CANCEL, ABORT = 1, 1 << 4, 1 << 5
RX_WM, RX_LAST, TX_WM = 1 << 26, 1 << 27, 1 << 30
ERRORS = sum(1 << bit for bit in (1, 2, 3, 9, 10, 12, 13, 24, 25, 28, 29))
EVENTS = DONE | CANCEL | ABORT | RX_WM | RX_LAST | TX_WM | ERRORS
ACTIVE, TX_WORDS, RX_WORDS = 1 | (1 << 12), (1 << 28) - 1, (1 << 25) - 1


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def descriptor_inputs():
    assert sha(DESCRIPTOR_READER) == DESCRIPTOR_READER_SHA
    assert sha(DESCRIPTOR_EVIDENCE) == DESCRIPTOR_EVIDENCE_SHA
    evidence = json.loads(DESCRIPTOR_EVIDENCE.read_text())
    assert evidence['status'] == 'STOPPED_A16_HID_DESCRIPTOR_VERIFIED'
    transaction = evidence['descriptor_transaction']
    assert transaction['status'] == 'TWO_IDENTICAL_HID_DESCRIPTORS'
    assert transaction['cleanup']['restored'] and transaction['cleanup']['fifos_empty']
    attempts = transaction['attempts']
    assert len(attempts) == 2 and attempts[0]['raw_hex'] == attempts[1]['raw_hex']
    descriptor = attempts[0]['descriptor']
    assert (descriptor['vendor_id'], descriptor['product_id']) == (0x0b05, 0x4b42)
    assert (descriptor['report_descriptor_register'], descriptor['report_descriptor_length']) == (2, 144)
    return attempts[0]


def describe_items(raw, descriptor):
    """Retain item bytes and derive bounded report sizes; do not infer events."""
    items, reports, stack, collections, globals_ = [], {}, [], [], {}
    pos = 0
    while pos < len(raw):
        start, prefix = pos, raw[pos]
        pos += 1
        if prefix == 0xfe:
            assert pos + 2 <= len(raw), 'truncated long item header'
            size, tag = raw[pos:pos + 2]
            pos += 2
            assert pos + size <= len(raw), 'truncated long item payload'
            items.append(dict(offset=start, type='long', tag=tag, data=raw[pos:pos + size].hex()))
            pos += size
            continue
        size = (0, 1, 2, 4)[prefix & 3]
        kind, tag = (prefix >> 2) & 3, prefix >> 4
        assert pos + size <= len(raw), 'truncated short item'
        payload = raw[pos:pos + size]
        value = int.from_bytes(payload, 'little')
        pos += size
        item = dict(offset=start, type=kind, tag=tag, data=payload.hex(), value=value)
        items.append(item)
        if kind == 1:
            if tag == 10:
                assert size == 0 and len(stack) < 16, 'invalid global push'
                stack.append(globals_.copy())
            elif tag == 11:
                assert size == 0 and stack, 'invalid global pop'
                globals_ = stack.pop()
            else:
                if tag == 8:
                    assert size == 1 and 1 <= value <= 255, 'invalid report ID'
                globals_[tag] = value
        elif kind == 0:
            if tag == 10:
                assert size == 1 and len(collections) < 32, 'invalid collection'
                collections.append(start)
            elif tag == 12:
                assert size == 0 and collections, 'unbalanced end collection'
                collections.pop()
            elif tag in (8, 9, 11):
                assert collections, 'report field outside a collection'
                assert size and 7 in globals_ and 9 in globals_, 'missing report field size/count'
                bits = globals_[7] * globals_[9]
                assert 0 < bits <= 65533 * 8, 'unbounded report field'
                report_id = globals_.get(8, 0)
                key = ({8: 'input', 9: 'output', 11: 'feature'}[tag], report_id)
                reports[key] = reports.get(key, 0) + bits
                item.update(report_type=key[0], report_id=report_id, bits=bits)
    assert not collections and not stack, 'unbalanced HID collection/global stack'
    assert reports, 'no report fields'
    ids = {key[1] for key in reports}
    assert not (0 in ids and len(ids) > 1), 'mixed numbered and unnumbered reports'
    shapes = []
    for (kind, report_id), bits in sorted(reports.items()):
        payload_bytes = (bits + 7) // 8 + bool(report_id)
        wire_bytes = payload_bytes + 2
        limit = {'input': descriptor['maximum_input_length'],
                 'output': descriptor['maximum_output_length'], 'feature': 65535}[kind]
        assert wire_bytes <= limit, (kind, report_id, wire_bytes, limit)
        shapes.append(dict(type=kind, report_id=report_id, bits=bits,
                           payload_bytes=payload_bytes, length_prefixed_bytes=wire_bytes))
    return dict(items=items, reports=shapes,
                boundary='Structural items and sizes only; usages retained as raw items, no input-event proof')


def perform_report_descriptor(proxy, values, record, output):
    expected = descriptor_inputs()
    # Retain the qualified short-read implementation and its cleanup, while
    # also checking all FIFO access error flags in this new transaction path.
    old_source = DESCRIPTOR_READER.read_text().split("\ntemplate = ROOT / ", 1)[0]
    namespace = dict(__file__=str(DESCRIPTOR_READER))
    exec(compile(old_source, str(DESCRIPTOR_READER), 'exec'), namespace)
    namespace.update(ERRORS=ERRORS | CANCEL | ABORT, EVENTS=EVENTS)
    namespace['perform_descriptor'](proxy, values, record, output)
    observed = record['descriptor_transaction']['attempts'][0]
    assert observed['raw_hex'] == expected['raw_hex'], 'physical HID descriptor identity changed'
    descriptor = observed['descriptor']
    register, length = descriptor['report_descriptor_register'], descriptor['report_descriptor_length']
    transfer = record['report_descriptor_transaction'] = dict(
        controller_base=hex(BASE), peripheral_address=0x15, register=register,
        read_bytes=length, fifo_capacity_words=32, command_timeout_seconds=5,
        cleanup_timeout_seconds=0.5, journal=[], attempts=[], status='STARTING')
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
            assert state['mechanism'] and not any(state[k] for k in ('before', 'during', 'unconsumed')), state
            return state
        except BaseException:
            sound = False
            raise

    def idle():
        return not read(0x40) & ACTIVE

    def acknowledge(status, purpose):
        if status & EVENTS:
            write(0x618, status & EVENTS, purpose)

    def wait_for(bits, label, timeout, cleanup=False):
        deadline = time.monotonic() + timeout
        for _ in range(1024):
            status = read(0x610)
            if not cleanup and status & (ERRORS | CANCEL | ABORT):
                raise RuntimeError(f'{label}: controller error {status:#x}')
            if status & bits:
                return status
            if time.monotonic() >= deadline:
                break
            time.sleep(0.001)
        raise TimeoutError(label)

    def receive(row):
        deadline = time.monotonic() + 5
        wanted_words = (length + 3) // 4
        for poll in range(1024):
            status = read(0x610)
            if status & (ERRORS | CANCEL | ABORT):
                raise RuntimeError(f'READ controller error {status:#x}')
            fifo = read(0x804)
            count = fifo & RX_WORDS
            assert count <= 32, f'impossible FIFO occupancy: {count}'
            assert len(row['receive_words']) + count <= wanted_words, 'extra report words'
            batch = dict(poll=poll, irq_status=hex(status), fifo_status=hex(fifo), words=count)
            row['polls'].append(batch)
            if count and fifo & (1 << 31):
                last_bytes = (fifo >> 28) & 7
                assert last_bytes in (0, 4), f'partial final word in aligned report: {last_bytes}'
                assert len(row['receive_words']) + count == wanted_words, 'early RX_LAST'
            for _ in range(count):
                assert time.monotonic() < deadline, 'READ exceeded service deadline'
                pop = dict(word_index=len(row['receive_words']), intent_time=time.time(), confirmed=False)
                row['fifo_pop_journal'].append(pop)
                record['fifo_data_reads'] = True
                save()
                try:
                    value = read(0x780)
                except BaseException:
                    pop['transport_uncertain'] = True
                    save()
                    raise
                row['receive_words'].append(value)
                pop.update(confirmed=True, value=hex(value), confirmed_time=time.time())
                save()
            # Only acknowledge events observed before draining. A newly arriving
            # LAST/DONE remains pending for the next poll.
            if status & DONE:
                assert len(row['receive_words']) == wanted_words, 'short report at DONE'
                assert idle(), 'DONE while controller remains active'
                assert not read(0x804) & RX_WORDS, 'unread words after DONE'
                final_status = read(0x610)
                assert not final_status & (ERRORS | CANCEL | ABORT), f'late READ error {final_status:#x}'
                row['final_irq_status'] = hex(final_status)
                acknowledge(status | final_status, 'acknowledge report READ completion')
                return struct.pack('<' + 'I' * wanted_words, *row['receive_words'])[:length]
            acknowledge(status & (RX_WM | RX_LAST), 'acknowledge observed receive service events')
            guard()
            if time.monotonic() >= deadline:
                break
            if not count:
                time.sleep(0.001)
        raise TimeoutError('report READ did not complete')

    saved = {0x26c: values['tx_transfer_length'], 0x270: values['rx_transfer_length'],
             0x614: values['master_irq_enable']}
    try:
        transfer['guard_before_commands'] = guard()
        write(0x614, saved[0x614] | EVENTS, 'enable polled report transaction events')
        for attempt in range(2):
            assert idle() and not read(0x800) & TX_WORDS and not read(0x804) & RX_WORDS, 'nonempty/busy controller'
            status = read(0x610)
            assert not status & (ERRORS | CANCEL | ABORT), f'preexisting controller error {status:#x}'
            acknowledge(status, 'acknowledge prior completion')
            write(0x26c, 2, 'two-byte report descriptor register selector')
            write(0x600, (1 << 27) | (0x15 << 9) | 4, 'WRITE selector with STOP_STRETCH')
            write(0x700, register, 'little-endian report descriptor register')
            acknowledge(wait_for(DONE, 'selector WRITE', 1), 'acknowledge selector WRITE')
            write(0x270, length, 'exact report descriptor byte length')
            row = dict(attempt=attempt + 1, receive_words=[], fifo_pop_journal=[], polls=[])
            transfer['attempts'].append(row)
            write(0x600, (2 << 27) | (0x15 << 9), 'READ report descriptor with final STOP')
            raw = receive(row)
            row.update(raw_hex=raw.hex(), sha256=hashlib.sha256(raw).hexdigest(), guard_after=guard())
            save()
        first, second = transfer['attempts']
        assert first['raw_hex'] == second['raw_hex'], 'report descriptor changed between reads'
        transfer['decoded'] = describe_items(bytes.fromhex(first['raw_hex']), descriptor)
        transfer['status'] = 'TWO_IDENTICAL_HID_REPORT_DESCRIPTORS'
    except BaseException as error:
        transfer.update(status='FAILED', error=repr(error))
        raise
    finally:
        cleanup = transfer['cleanup'] = dict(transport_sound=sound, restored=False)
        try:
            if changed and sound:
                cleanup['guard_before'] = guard()
                if not idle():
                    for control, completed, label in ((4, CANCEL, 'cancel'), (2, ABORT, 'abort')):
                        write(0x604, control, 'bounded cleanup ' + label)
                        try:
                            acknowledge(wait_for(completed, label, 0.5, cleanup=True), 'acknowledge cleanup ' + label)
                        except TimeoutError:
                            cleanup[label + '_timeout'] = True
                        if idle():
                            break
                assert idle(), 'cleanup could not idle controller'
                acknowledge(read(0x610), 'acknowledge observed final events')
                for offset, value in saved.items():
                    write(offset, value, 'restore saved controller setting')
                    assert read(offset) == value, 'controller setting did not restore'
                cleanup.update(restored=True, engine_status=hex(read(0x40)),
                    tx_fifo_status=hex(read(0x800)), rx_fifo_status=hex(read(0x804)),
                    io_status=hex(read(0x908)), guard_after=guard())
                cleanup['fifos_empty'] = not (int(cleanup['tx_fifo_status'], 16) & TX_WORDS or int(cleanup['rx_fifo_status'], 16) & RX_WORDS)
                cleanup['io_inputs_match'] = int(cleanup['io_status'], 16) & 3 == values['io_status'] & 3
                assert cleanup['fifos_empty'] and cleanup['io_inputs_match'], 'cleanup left data or changed IO inputs'
            elif changed:
                cleanup['reason'] = 'uncertain transport or SError; no further MMIO attempted'
        except BaseException as error:
            cleanup['error'] = repr(error)
            transfer['status'] = 'FAILED'
            raise
        finally:
            save()
    assert transfer['status'] == 'TWO_IDENTICAL_HID_REPORT_DESCRIPTORS' and cleanup['restored']


def main():
    expected = descriptor_inputs()
    template = ROOT / 'tools/survey-a16-input-transaction.py'
    assert sha(template) == '6b7532d982bd097c64794732421867aa75915f9e83330fedae3041bf595bde8f'
    source = template.read_text()
    dispatch = "exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))"
    assert source.count(dispatch) == 1
    namespace = dict(__file__=str(template), __name__='prepared_survey')
    exec(compile(source.replace(dispatch, 'GENERATED_SOURCE = source'), str(template), 'exec'), namespace)
    source = namespace['GENERATED_SOURCE']
    anchor = '    if args.check_inputs:'
    assert source.count(anchor) == 1
    plan = dict(peripheral_address=21, register=2, read_bytes=144, repetitions=2,
                fifo_capacity_words=32, max_poll_iterations=1024, read_deadline_seconds=5,
                descriptor_evidence_sha256=DESCRIPTOR_EVIDENCE_SHA,
                descriptor_reader_sha256=DESCRIPTOR_READER_SHA,
                expected_hid_descriptor=expected['raw_hex'],
                writable_offsets=['0x26c', '0x270', '0x600', '0x604', '0x614', '0x618', '0x700'],
                fifo_pop_offset='0x780')
    source = source.replace(anchor,
        "    record['operation'] = 'BOUNDED_STREAMING_ECKB_HID_REPORT_DESCRIPTOR_READ'\n"
        "    record['boundary'] = 'Physical report descriptor only; no keyboard/touchpad events or guest input proof'\n"
        "    record['transaction_plan'] = " + repr(plan) + '\n' + anchor)
    anchor = "        proxy.read64(previous['address'])  # Poll a late SError after successful reads."
    assert source.count(anchor) == 1
    source = source.replace(anchor,
        "        perform_report_descriptor(proxy, {name: row['value'] for name,row in record['registers'].items()}, record, args.output)\n" + anchor)
    source = source.replace('STOPPED_IC20_REGISTERS_CAPTURED', 'STOPPED_A16_HID_REPORT_DESCRIPTOR_VERIFIED')
    exec(compile(source, str(template), 'exec'), dict(__file__=__file__, __name__='__main__',
                                                   perform_report_descriptor=perform_report_descriptor))


if __name__ == '__main__':
    main()
