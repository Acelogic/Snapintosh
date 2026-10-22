#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Verify official ASUS BSP bytes and extract the exact e14f QCC2072 board offline.

No installers/scripts execute. No device access, generated aliases or board patching.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import zlib

PACKAGE_SHA256 = 'e8f2389ac5d4dfd30a1a8481ec3c1e282f24baea2898414351d0b6eb1fa8a0b3'
DIRECTORY = 'QualcommBSP/WIFI_BT/qcwlancol8480/'
BOARD = 'bdwlan_qcc2072_1p0_ncm820A.elf'
MEMBERS = [BOARD, 'qcwlancol8480.inf', 'qcwlancol8480.cat', 'regdb.bin']
HARDWARE_ID = r'PCI\VEN_17CB&DEV_1112&SUBSYS_E14F105B'
LINUX_REVISION = 'c03c1a14507dfaf8b856c2608f9ac216021fc222'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def entries(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from entries(child)
    elif isinstance(value, list):
        for child in value:
            yield from entries(child)


def elf_info(data):
    require(52 <= len(data) <= 256 * 1024, 'board outside expected ELF size bound')
    h = struct.unpack_from('<16sHHIIIIIHHHHHH', data)
    ident, kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = h
    require(ident[:7] == b'\x7fELF\x01\x01\x01', 'expected ELF32 little endian version 1')
    require(kind == 2 and machine == 40 and version == 1 and ehsize == 52,
            'unexpected ELF header identity')
    require(phsize == 32 and 0 < phnum <= 128 and phoff >= ehsize and
            phoff + phnum * phsize <= len(data), 'bad program table bounds')
    require(shsize == 40 and 0 < shnum <= 128 and shoff >= ehsize and
            shoff + shnum * shsize <= len(data) and shstr < shnum, 'bad section table bounds')
    programs, sections = [], []
    for i in range(phnum):
        typ, offset, va, pa, size, memory, permissions, alignment = struct.unpack_from('<IIIIIIII', data, phoff + i * phsize)
        require(offset + size <= len(data) and size <= memory, 'program payload exceeds file/memory')
        programs.append({'type': typ, 'offset': offset, 'virtual_address': va,
                         'physical_address': pa, 'file_bytes': size, 'memory_bytes': memory,
                         'flags': permissions, 'alignment': alignment})
    for i in range(shnum):
        name, typ, permissions, addr, offset, size, link, info, alignment, entsize = struct.unpack_from('<IIIIIIIIII', data, shoff + i * shsize)
        require(typ == 8 or offset + size <= len(data), 'section payload exceeds file')
        sections.append({'index': i, 'type': typ, 'offset': offset, 'bytes': size})
    return {'class': 32, 'endianness': 'little', 'machine': machine, 'type': kind,
            'entry': entry, 'programs': programs, 'sections': sections,
            'all_tables_and_payloads_in_bounds': True, 'complete_file_bytes': len(data),
            'ath12k_qcc2072_board_size_limit': 256 * 1024, 'within_board_size_limit': True}


def inf_mapping(data):
    text = data.decode('utf-16')
    lines = text.splitlines()
    matches = [(i + 1, line) for i, line in enumerate(lines)
               if HARDWARE_ID.lower() in line.lower()]
    require(len(matches) == 1, 'hardware ID must have exactly one INF install mapping')
    line_number, hardware_line = matches[0]
    install = hardware_line.split('=', 1)[1].split(',', 1)[0].strip()
    sections = {}
    section = None
    for i, line in enumerate(lines):
        match = re.match(r'^\[([^\]]+)\]', line.strip())
        if match:
            section = match[1].lower()
            require(section not in sections, 'duplicate INF section')
            sections[section] = []
        elif section and line.strip() and not line.lstrip().startswith(';'):
            sections[section].append((i + 1, line))
    target = sections[(install + '.NTARM64').lower()]
    addreg = next((item for item in target if item[1].lstrip().lower().startswith('addreg')), None)
    copyfiles = next((item for item in target if item[1].lstrip().lower().startswith('copyfiles')), None)
    require(addreg and 'bd_ncm820a.reg' in addreg[1].lower(), 'wrong board registry selection')
    require(copyfiles and 'qcwlan_bd_ncm820a.copyfiles' in copyfiles[1].lower(), 'missing board copy selection')
    reg = sections['bd_ncm820a.reg']
    copies = sections['qcwlan_bd_ncm820a.copyfiles']
    require(len(reg) == 1 and 'BDFileName' in reg[0][1] and '"' + BOARD + '"' in reg[0][1], 'wrong board registry filename')
    require(len(copies) == 1 and copies[0][1].split(',', 1)[0].strip() == BOARD, 'wrong board copy filename')
    evidence = [matches[0], addreg, copyfiles, reg[0], copies[0]]
    return {'hardware_id': HARDWARE_ID, 'install_section': install + '.NTARM64',
            'board_file': BOARD, 'evidence': [{'line': n, 'text': line} for n, line in evidence],
            'copyright_lines': [line for line in lines[:15] if 'Copyright' in line or 'rights' in line]}, text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, required=True)
    parser.add_argument('--support-api', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    package = args.package.resolve()
    data = package.read_bytes()
    require(sha(data) == PACKAGE_SHA256, 'package hash differs from pinned official ASUS hash')
    api = args.support_api.read_bytes()
    found = [e for e in entries(json.loads(api)) if e.get('Version') == 'V1.312.4500.0'
             and e.get('Title') == 'Qualcomm Board Support Package']
    require(len(found) == 1 and found[0].get('sha256', '').lower() == PACKAGE_SHA256,
            'saved ASUS API entry does not match package')
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    offset = data.find(b'7z\xbc\xaf\x27\x1c')
    require(offset >= 0 and offset + 32 <= len(data), 'embedded archive signature absent')
    header = data[offset:offset + 32]
    require(zlib.crc32(header[12:32]) == struct.unpack_from('<I', header, 8)[0], 'bad 7z start header CRC')
    next_offset, next_size, next_crc = struct.unpack_from('<QQI', header, 12)
    archive_size = 32 + next_offset + next_size
    require(archive_size > 32 and offset + archive_size <= len(data), 'bad archive bounds')
    require(zlib.crc32(data[offset + 32 + next_offset:offset + archive_size]) == next_crc,
            'bad 7z next header CRC')
    archive = out / 'package.7z'
    archive.write_bytes(data[offset:offset + archive_size])
    listing = subprocess.run(['7z', 'l', '-slt', str(archive)], capture_output=True, text=True)
    (out / 'archive-list.txt').write_text(listing.stdout + listing.stderr)
    require(listing.returncode == 0, 'archive listing failed')
    records = []
    for block in listing.stdout.split('\n\n'):
        fields = dict(line.split(' = ', 1) for line in block.splitlines() if ' = ' in line)
        if 'Path' in fields:
            records.append(fields)
    extract = out / 'files'
    extract.mkdir()
    command = ['bsdtar', '--fast-read', '-xf', str(archive), '-C', str(extract)] + [DIRECTORY + n for n in MEMBERS]
    run = subprocess.run(command, capture_output=True, text=True)
    (out / 'extraction.log').write_text(run.stdout + run.stderr)
    require(run.returncode == 0, 'selective extraction failed; see extraction.log')
    members = {}
    for name in MEMBERS:
        path = extract / DIRECTORY / name
        raw = path.read_bytes()
        item = [item for item in records if item['Path'] == DIRECTORY + name]
        require(len(item) == 1, 'ambiguous archive member')
        crc = f'{zlib.crc32(raw):08X}'
        require(len(raw) == int(item[0]['Size']) and crc == item[0]['CRC'], 'member size/CRC mismatch')
        members[name] = {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw),
                         'archive_crc32': crc, 'archive_size_crc_match': True}
    board = Path(members[BOARD]['path']).read_bytes()
    mapping, inf = inf_mapping(Path(members['qcwlancol8480.inf']['path']).read_bytes())
    (out / 'qcwlancol8480.inf.utf8.txt').write_text(inf)
    license_paths = [item['Path'] for item in records if any(word in item['Path'].lower()
                     for word in ['license', 'notice', 'eula', 'copyright', 'agreement'])]
    result = {'status': 'EXACT_MODULE_PACKAGE_PROVENANCE_VERIFIED',
              'hardware_access': False, 'installer_executed': False, 'external_script_executed': False,
              'package': {'path': str(package), 'bytes': len(data), 'sha256': PACKAGE_SHA256,
                          'matches_asus_published_sha256': True,
                          'official_download_url': found[0]['DownloadUrl']['Global'],
                          'release_date': found[0]['ReleaseDate'], 'version': found[0]['Version']},
              'support_api': {'path': str(args.support_api.resolve()), 'sha256': sha(api)},
              'archive': {'path': str(archive), 'offset': offset, 'bytes': archive_size,
                          'sha256': sha(archive.read_bytes()), 'start_and_next_header_crc_valid': True},
              'members': members, 'inf_mapping': mapping, 'elf': elf_info(board),
              'extraction': {'command': command, 'exit': run.returncode},
              'license': {'standalone_license_notice_members': license_paths,
                          'wlan_standalone_license_found': any('WIFI_BT/' in p for p in license_paths),
                          'original_package_and_inf_preserved': True,
                          'redistribution_terms_for_extracted_board_reviewed': False},
              'payload': {'format': 'complete original ELF file', 'offset': 0, 'bytes': len(board),
                          'transformed': False, 'strip_elf_or_signature': False,
                          'rationale': 'Pinned ath12k core.c:373-374 stores the entire board IE; qmi.c:3163-3165 caps at board_size and qmi.c:2994,3027,3062-3063 copies every byte. QCC2072 board_size is 256 KiB at wifi7/hw.c:722.',
                          'linux_revision': LINUX_REVISION},
              'qualification': {'exact_subsystem_package_mapping': True,
                                'live_qmi_chip_id': None, 'live_qmi_board_id': None,
                                'generated_board_aliases': False,
                                'firmware_acceptance_verified': False,
                                'regulatory_compatibility_verified': False,
                                'native_wifi_runtime_verified': False},
              'tool_sha256': sha(Path(__file__).read_bytes())}
    path = out / 'receipt.json'
    path.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'receipt': str(path), 'sha256': sha(path.read_bytes()),
                      'status': result['status'], 'board': members[BOARD]}))


if __name__ == '__main__':
    main()
