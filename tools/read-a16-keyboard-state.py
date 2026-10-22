#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Read report54 through the verified A16 I2C-HID command transport.

Failure inventory: docs/A16-KEYBOARD-STATE-20260928.md.
--check-inputs is offline. Actual execution requires a qualified stopped guest.
No reset/power/vendor command, guest resume, or guest HID event is performed.
"""
from pathlib import Path
import hashlib
import json
import struct

ROOT = Path(__file__).resolve().parents[1]
READER = ROOT / 'tools/read-a16-hid-report-descriptor.py'
READER_SHA = '099ea426c527c766ebbd861a4b5f36ee68a21c0a114b01b8d26d61c0e69c2dbf'
EVIDENCE = ROOT / 'build/a16-hid-report-descriptor-gen57-20260928-v1.json'
EVIDENCE_SHA = '7c55ad9ecc308853472f4f3c8e22461f93cb3b185217c5cb533be90193d7b8dc'
REPORT_SHA = '0887190d374bd8f4ff9e5278af8e7831fc149714b1f681860cc87a9c27cbaacb'
REPORT_ID, WIRE_BYTES = 54, 11
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()


def keyboard_inputs():
    assert sha(READER) == READER_SHA
    assert sha(EVIDENCE) == EVIDENCE_SHA
    evidence = json.loads(EVIDENCE.read_text())
    assert evidence['status'] == 'STOPPED_A16_HID_REPORT_DESCRIPTOR_VERIFIED'
    transfer = evidence['report_descriptor_transaction']
    assert transfer['status'] == 'TWO_IDENTICAL_HID_REPORT_DESCRIPTORS'
    assert transfer['cleanup']['restored'] and transfer['cleanup']['fifos_empty']
    attempts = transfer['attempts']
    assert len(attempts) == 2
    for attempt in attempts:
        assert hashlib.sha256(bytes.fromhex(attempt['raw_hex'])).hexdigest() == REPORT_SHA
    shape = [row for row in transfer['decoded']['reports']
             if row['type'] == 'input' and row['report_id'] == REPORT_ID]
    assert shape == [dict(type='input', report_id=54, bits=64,
                          payload_bytes=9, length_prefixed_bytes=11)]
    descriptor = evidence['descriptor_transaction']['attempts'][0]['descriptor']
    assert (descriptor['vendor_id'], descriptor['product_id']) == (0x0b05, 0x4b42)
    assert (descriptor['command_register'], descriptor['data_register']) == (5, 6)
    packet = struct.pack('<HBBB H', descriptor['command_register'],
                         0x1f, 2, REPORT_ID, descriptor['data_register'])
    assert packet.hex() == '05001f02360600'
    return packet


def decode_keyboard(raw):
    assert len(raw) == WIRE_BYTES, 'wrong physical receive length'
    assert int.from_bytes(raw[:2], 'little') == WIRE_BYTES, 'wrong HID length prefix'
    assert raw[2] == REPORT_ID, 'wrong HID report ID'
    keys = list(raw[5:11])
    return dict(report_id=raw[2], modifier_mask=raw[3], reserved_byte=raw[4],
        modifier_usages=[0xe0 + bit for bit in range(8) if raw[3] & (1 << bit)],
        key_array=keys, key_usages=[key for key in keys if key > 3],
        error_usages=[key for key in keys if 1 <= key <= 3],
        outside_logical_range=[key for key in keys if key > 0x65],
        boundary='Physical state only; no inferred press/release or guest IOHID delivery')


def prepare_reader():
    packet = keyboard_inputs()
    # Retain the physically exercised FIFO service, journaling and cleanup.
    # Exact single-match substitutions fail if that implementation changes.
    source = READER.read_text().split('\ndef main():', 1)[0]
    changes = {
        "register, length = descriptor['report_descriptor_register'], descriptor['report_descriptor_length']":
            "register, length = descriptor['command_register'], 11",
        "record['report_descriptor_transaction']": "record['keyboard_state_transaction']",
        "read_bytes=length, fifo_capacity_words=32, command_timeout_seconds=5,":
            "read_bytes=length, command_packet=PACKET.hex(), report_id=54, fifo_capacity_words=32, command_timeout_seconds=5,",
        "assert last_bytes in (0, 4), f'partial final word in aligned report: {last_bytes}'":
            "assert last_bytes == 3, f'wrong final byte count for 11-byte input: {last_bytes}'",
        "            write(0x26c, 2, 'two-byte report descriptor register selector')\n"
        "            write(0x600, (1 << 27) | (0x15 << 9) | 4, 'WRITE selector with STOP_STRETCH')\n"
        "            write(0x700, register, 'little-endian report descriptor register')\n"
        "            acknowledge(wait_for(DONE, 'selector WRITE', 1), 'acknowledge selector WRITE')":
            "            write(0x26c, len(PACKET), 'seven-byte extended-ID GET_REPORT command')\n"
            "            write(0x600, (1 << 27) | (0x15 << 9) | 4, 'WRITE command with STOP_STRETCH')\n"
            "            for offset in range(0, len(PACKET), 4):\n"
            "                word = int.from_bytes(PACKET[offset:offset + 4].ljust(4, b'\\0'), 'little')\n"
            "                write(0x700, word, 'GET_REPORT packet FIFO word')\n"
            "            acknowledge(wait_for(DONE, 'command WRITE', 1), 'acknowledge command WRITE')\n"
            "            assert not read(0x800) & TX_WORDS, 'command bytes remain in TX FIFO'",
        "        first, second = transfer['attempts']\n"
        "        assert first['raw_hex'] == second['raw_hex'], 'report descriptor changed between reads'\n"
        "        transfer['decoded'] = describe_items(bytes.fromhex(first['raw_hex']), descriptor)":
            "        assert len(transfer['attempts']) == 2\n"
            "        transfer['decoded'] = [decode_keyboard(bytes.fromhex(row['raw_hex']))\n"
            "                               for row in transfer['attempts']]",
    }
    for old, new in changes.items():
        assert source.count(old) == 1, old
        source = source.replace(old, new)
    assert source.count('TWO_IDENTICAL_HID_REPORT_DESCRIPTORS') == 2
    source = source.replace('TWO_IDENTICAL_HID_REPORT_DESCRIPTORS', 'TWO_KEYBOARD_STATE_RESPONSES')
    source = source.replace('report descriptor byte length', 'keyboard state byte length')
    source = source.replace('READ report descriptor with final STOP', 'READ keyboard state with final STOP')
    namespace = dict(__file__=str(READER), PACKET=packet, decode_keyboard=decode_keyboard)
    exec(compile(source, str(READER), 'exec'), namespace)
    namespace['descriptor_inputs']()
    return namespace['perform_report_descriptor'], packet


def main():
    perform, packet = prepare_reader()
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
    plan = dict(report_id=REPORT_ID, receive_bytes=WIRE_BYTES, command_packet=packet.hex(),
        repetitions=2, command_register=5, data_register=6, extended_report_id=True,
        report_reader_sha256=READER_SHA, report_evidence_sha256=EVIDENCE_SHA,
        report_descriptor_sha256=REPORT_SHA, guest_input_verified=False,
        writable_offsets=['0x26c', '0x270', '0x600', '0x604', '0x614', '0x618', '0x700'])
    source = source.replace(anchor,
        "    record['operation'] = 'BOUNDED_ECKB_GET_REPORT_INPUT54'\n"
        "    record['boundary'] = 'Keyboard state response only; no interrupt input or guest HID proof'\n"
        "    record['keyboard_state_plan'] = " + repr(plan) + '\n' + anchor)
    anchor = "        proxy.read64(previous['address'])  # Poll a late SError after successful reads."
    assert source.count(anchor) == 1
    source = source.replace(anchor,
        "        perform_keyboard_state(proxy, {name: row['value'] for name,row in record['registers'].items()}, record, args.output)\n" + anchor)
    source = source.replace('STOPPED_IC20_REGISTERS_CAPTURED', 'STOPPED_A16_KEYBOARD_STATE_VERIFIED')
    exec(compile(source, str(template), 'exec'), dict(__file__=__file__, __name__='__main__',
                                                   perform_keyboard_state=perform))


if __name__ == '__main__':
    main()
