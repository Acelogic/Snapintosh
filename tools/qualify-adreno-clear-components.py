#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Bind clear, raw-sign monitor and existing linked driver; no hardware access."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
from source_text import read_source, source_files

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()


def verify(path, root):
    record = json.loads(path.read_text())
    for key in ('sources_sha256', 'source_sha256'):
        for name, digest in record.get(key, {}).items():
            assert sha(root / name) == digest, (path, name)
    for name, digest in record.get('artifacts_sha256', {}).items():
        assert sha(path.parent / name) == digest, (path, name)
    return record


def macho(path):
    data = path.read_bytes()
    assert struct.unpack_from('<I', data)[0] == 0xfeedfacf
    position = 32
    sections, commands, tables = {}, [], {}
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        cmd, size = struct.unpack_from('<II', data, position)
        assert size >= 8 and position + size <= len(data)
        raw = data[position:position + size]
        commands.append((cmd, raw))
        if cmd == 0x19:
            segment = struct.unpack_from('<II16sQQQQiiII', raw)
            for i in range(segment[-2]):
                s = struct.unpack_from('<16s16sQQIIIIIIII', raw, 72 + i * 80)
                name = (s[1].rstrip(b'\0').decode(), s[0].rstrip(b'\0').decode())
                zero = (s[8] & 255) in (1, 12, 18)
                contents = b'' if zero else data[s[4]:s[4] + s[3]]
                assert zero or len(contents) == s[3]
                relocations = data[s[6]:s[6] + s[7] * 8]
                assert len(relocations) == s[7] * 8
                sections[name] = (s[2:4], s[5:], contents, relocations)
        elif cmd == 2:
            tables['symbols'] = struct.unpack('<6I', raw)[2:]
        elif cmd == 0xb:
            tables['dynamic'] = struct.unpack('<20I', raw)
        position += size
    symoff, count, stroff, strlen = tables['symbols']
    strings = data[stroff:stroff + strlen]
    symbols = []
    for i in range(count):
        string, typ, section, desc, value = struct.unpack_from('<IBBHQ', data, symoff + i * 16)
        assert string < len(strings)
        end = strings.index(0, string)
        if not typ & 0xe0:  # N_STAB debug records carry checkout/object paths.
            symbols.append((i, strings[string:end], typ, section, desc, value))
    dy = tables['dynamic']
    dynamic = tuple(data[dy[i]:dy[i] + dy[i + 1] * width]
                    for i, width in ((14, 4), (16, 8), (18, 8)))
    return sections, symbols, dynamic, commands


def compare_kext(old, new):
    a, b = macho(old), macho(new)
    assert a[:3] == b[:3], 'loaded sections, symbols or relocations changed'
    assert len(a[3]) == len(b[3])
    differences = []
    for (cmd, x), (cmd2, y) in zip(a[3], b[3]):
        assert cmd == cmd2
        if x == y:
            continue
        if cmd == 0x19:
            sx = struct.unpack_from('<II16sQQQQiiII', x)
            sy = struct.unpack_from('<II16sQQQQiiII', y)
            assert sx[2].rstrip(b'\0') == b'__LINKEDIT'
            assert sx[:4] == sy[:4] and sx[5] == sy[5] and sx[7:] == sy[7:]
        else:
            assert cmd in (2, 0x1b, 0x1d), hex(cmd)
        differences.append(hex(cmd))
    return dict(deployed_sha256=sha(old), rebuilt_sha256=sha(new),
        identical_sections=len(a[0]), identical_non_debug_symbols=len(a[1]),
        identical_indirect_symbols_and_relocations=True,
        differing_load_commands=differences,
        sections={'/'.join(k): hashlib.sha256(v[2]).hexdigest() for k, v in a[0].items()})


def layout(source, root):
    cmd = ['clang', '--target=aarch64-unknown-none-elf', '-ffreestanding',
        '-mgeneral-regs-only', '-I../shadow', '-I../compat', '-Xclang',
        '-fdump-record-layouts', '-fsyntax-only', '-x', 'c', '-']
    proc = subprocess.run(cmd, cwd=root / 'probes', input=source, text=True,
                          capture_output=True, check=True)
    block = next(b for b in proc.stdout.split('*** Dumping AST Record Layout')
                 if re.search(r'^\s*0 \| struct context\n', b, re.M))
    fields = {name: int(offset) for offset, name in
              re.findall(r'^\s*(\d+) \|   \S.* (\w+)$', block, re.M)}
    return dict(fields=fields, context_bytes=int(re.search(r'\[sizeof=(\d+),', block)[1]))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--clear', type=Path, required=True)
    ap.add_argument('--monitor', type=Path, required=True)
    ap.add_argument('--probe', type=Path, required=True)
    ap.add_argument('--link', type=Path, required=True)
    ap.add_argument('--mixed', type=Path, help='Captured mixed UPDATE_DISJOINT replay for the candidate sources')
    ap.add_argument('--original-root', type=Path, required=True)
    ap.add_argument('--fill-root', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    original, fill = args.original_root.resolve(), args.fill_root.resolve()
    paths = {k: getattr(args, k).resolve() for k in ('clear', 'monitor', 'probe', 'link')}
    roots = dict(clear=ROOT, monitor=ROOT, probe=ROOT, link=fill)
    if args.mixed:
        paths['mixed'] = args.mixed.resolve()
        roots['mixed'] = ROOT
    records = {k: verify(p, roots[k]) for k, p in paths.items()}
    clear, monitor, probe, link = (records[k] for k in ('clear', 'monitor', 'probe', 'link'))
    assert clear['status'] == 'METAL_TEXTURE_CLEAR_NATIVE_PACKING_GPU_MODEL_MATCHES_APPLE_REFERENCE'
    assert monitor['status'] == 'FILL_COMMAND_MONITOR_KEXT_HOST_QUALIFIED_NOT_INSTALLED'
    assert probe['status'] == 'GUEST_METAL_TEXTURE_CLEAR_PROBE_BUILT_NOT_EXECUTED'
    assert link['status'] == 'FILL_AUXKC_LINKED_PINNED_NOT_INSTALLED'
    assert probe['qualification_sha256'] == sha(paths['clear'])
    assert probe['plugin_sha256'] == clear['plugin_sha256']
    fill_path = Path(link['plan']['qualification'])
    assert sha(fill_path) == link['plan']['qualification_sha256']
    fill_record = verify(fill_path, fill)
    if fill_record['status'] == 'FILL_COMMAND_MONITOR_KEXT_HOST_QUALIFIED_NOT_INSTALLED':
        assert fill_path == paths['monitor'], 'linked driver must be this qualified monitor/kext pair'
        old = fill_path.parent / 'kext/AdrenoX2.kext/Contents/MacOS/AdrenoX2'
    else:
        assert fill_record['status'] == 'METAL_FILL_NATIVE_PRODUCER_DRIVER_MODEL_QUALIFIED_NOT_INSTALLED'
        old = fill_path.parent / 'integration/kext/AdrenoX2.kext/Contents/MacOS/AdrenoX2'
    new = paths['monitor'].parent / 'kext/AdrenoX2.kext/Contents/MacOS/AdrenoX2'
    assert sha(old) == link['plan']['kext_sha256'] == fill_record['kext_sha256']
    assert sha(new) == monitor['kext_sha256']
    comparison = compare_kext(old, new)
    matched = {}
    for directory in ('gpu/adreno-kext/kext', 'gpu/adreno-kext/include', 'compat'):
        for file in (ROOT / directory).rglob('*'):
            if file.is_file() and file.suffix in ('.c', '.h', '.cpp', '.S', '.sh', '.plist'):
                if directory == 'compat' and file.name.startswith('pauth-'):
                    continue
                name = str(file.relative_to(ROOT))
                assert sha(file) == sha(fill / name), name
                matched[name] = sha(file)
    physical_path = original / 'build/pauth-native-sign-20260927/physical-v1/physical.json'
    assert sha(physical_path) == '60adf8f269f935e32d7a27b7c9e64096da802145efff69e0156bdfe95eadd9b1'
    physical = json.loads(physical_path.read_text())
    assert physical['result'] == 'PASS' and len(physical['rows']) == 576
    assert physical['canonical_comparisons'] == 192 and physical['workspace_restored']
    assert physical['workspace_before_sha256'] == physical['workspace_after_sha256']
    assert not physical['exceptions'] and not any(physical['serror'].values())
    for n, h in physical['source_sha256'].items():
        assert sha(original / n) == h
        if n not in ('probes/run.py', 'tools/qualify-pauth-raw-native.py'):
            assert sha(ROOT / n) == h, n
    raw_build_path = original / 'build/pauth-native-sign-20260927/monitor-v1/build.json'
    raw_build = json.loads(raw_build_path.read_text())
    assert sha(raw_build_path) == '789ef818f2ea31d17094c4a767df55007c9c4494723702f275b2052e75f53f2a'
    assert monitor['build_defines'] == raw_build['build_defines']
    if args.mixed:
        mixed = records['mixed']
        assert mixed['status'] == 'PASS' and mixed['build_exit'] == mixed['replay_exit'] == 0
        assert mixed['regressions'] == {'test-sptm-update': 0, 'test-user-update': 0}
        for part in source_files(ROOT / 'probes/xnuboot.c'):
            assert mixed['source_sha256'][str(part.relative_to(ROOT))] == sha(part)
        assert sha(Path(mixed['capture'])) == mixed['capture_sha256']
        assert mixed['request']['count'] == 2 and int(mixed['request']['options'], 0) == 0x10a
    else:
        for part in source_files(original / 'probes/xnuboot.c'):
            assert sha(part) == raw_build['source_sha256'][str(part.relative_to(original))]
    context = layout(read_source(ROOT / 'probes/xnuboot.c'), ROOT)
    assert context == layout(read_source(original / 'probes/xnuboot.c'), original)
    assert len(context['fields']) == 215 and context['context_bytes'] == 5094208
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    commands = []
    environment = dict(os.environ, PYTHONPATH=str(original / 'build/test-python-deps'))
    def run(name, argv):
        commands.append(argv)
        proc = subprocess.run(argv, cwd=ROOT, env=environment, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT)
        (output / (name + '.log')).write_text(proc.stdout)
        assert proc.returncode == 0, (name, proc.returncode)
        return proc.stdout
    binary = output / 'pauth-pointer'
    run('pointer-build', ['clang', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
        '-Wall', '-Wextra', '-Werror', 'tools/test-pauth-pointer.c', 'compat/pauth-pointer.c',
        '-o', str(binary)])
    pointer = run('pointer', [str(binary)])
    assert pointer.strip() == 'pauth pointer: 12951 sanitizer checks passed'
    # Existing regression logic is unchanged; only fresh evidence/input paths differ.
    substitutions = [
        ('canonical', 'tools/test-pauth-native.py', "ROOT / 'build/pauth-address-probe'",
         repr(str(output / 'canonical'))),
        ('original', 'tools/replay-pauth-pointer.py', "ROOT / 'build/test-pauth-pointer'",
         repr(str(binary)))]
    for name, relative, before, after in substitutions:
        script = ROOT / relative
        source = script.read_text()
        assert source.count(before) == 1
        program = ('from pathlib import Path\nimport sys\n'
            f'sys.path.insert(0,{str(original / "build/test-python-deps")!r})\n'
            f'p=Path({str(script)!r})\ns=p.read_text()\n'
            f'assert s.count({before!r})==1\n'
            f's=s.replace({before!r},"Path("+{after!r}+")")\n')
        if name == 'original':
            old_firmware = "ROOT / 'downloads/extracted/j700ap/sptm.t8140.release'"
            assert source.count(old_firmware) == 1
            replacement = f'Path({str(original / "downloads/extracted/j700ap/sptm.t8140.release")!r})'
            program += f's=s.replace({old_firmware!r},{replacement!r})\n'
        program += "exec(compile(s,str(p),'exec'),dict(__file__=str(p),__name__='__main__'))\n"
        text = run(name, [sys.executable, '-c', program])
        replay = json.loads(text)
        assert replay['cases'] == (212 if name == 'canonical' else 6447)
    run('raw-sign', [sys.executable, 'tools/test-pauth-native-sign.py', '--output', str(output / 'raw')])
    raw = json.loads((output / 'raw/replay.json').read_text())
    assert raw['cases'] == 462 and raw['probe_sha256'] == physical['raw_probe_sha256']
    canonical = output / 'canonical/pauth-address.bin'
    assert sha(canonical) == physical['canonical_probe_sha256']
    (output / 'context-layout.json').write_text(json.dumps(context, indent=2) + '\n')
    sources = {str(p.relative_to(ROOT)): sha(p) for p in [Path(__file__),
        ROOT / 'tools/test-pauth-pointer.c', ROOT / 'tools/replay-pauth-pointer.py',
        ROOT / 'tools/test-pauth-native.py', ROOT / 'tools/test-pauth-native-sign.py']}
    for k, p in paths.items(): verify(p, roots[k])
    verify(fill_path, fill)
    result = dict(status='CLEAR_COMPONENTS_BOUND_NOT_INSTALLED',
        components={k: dict(path=str(p), sha256=sha(p)) for k, p in paths.items()},
        sources_sha256=sources, unchanged_kext_inputs_sha256=matched,
        kext_comparison=comparison, context_bytes=context['context_bytes'],
        context_fields=len(context['fields']), physical_record=str(physical_path),
        physical_record_sha256=sha(physical_path), raw_build_sha256=sha(raw_build_path),
        deployed_kext=str(old), deployed_kext_sha256=sha(old),
        deployed_collection=str(paths['link'].parent / 'AdrenoX2.kc'),
        deployed_collection_sha256=link['collection_sha256'],
        monitor=str(paths['monitor'].parent / 'monitor/xnuboot.bin'),
        monitor_sha256=monitor['monitor_sha256'], plugin_sha256=clear['plugin_sha256'],
        guest_probe_sha256=probe['binary_sha256'], commands=commands,
        python_dependency_path=environment['PYTHONPATH'],
        artifacts_sha256={str(p.relative_to(output)): sha(p) for p in sorted(output.rglob('*')) if p.is_file()},
        boundary='Source/build/model binding plus reuse of separately recorded PA hardware proof. Clear image and display presentation have not run on A16; no SSD update or guest image is qualified here.')
    (output / 'components.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({k: result[k] for k in ('status', 'context_fields', 'context_bytes', 'monitor_sha256', 'deployed_collection_sha256')}))


if __name__ == '__main__':
    main()
