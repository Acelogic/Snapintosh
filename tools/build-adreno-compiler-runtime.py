#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Package the real compiler dependency closure and exercise its C API from arm64e."""
from pathlib import Path
import argparse
import hashlib
import json
import importlib.util
import re
import shlex
import shutil
import struct
import subprocess
import time

from source_text import source_files

ROOT = Path(__file__).resolve().parents[1]


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def dependencies(p):
    lines = subprocess.check_output(['otool', '-L', str(p)], text=True).splitlines()[1:]
    return [line.strip().split(' (compatibility version', 1)[0] for line in lines]


def system_path(p):
    return p.startswith(('/usr/lib/', '/System/Library/'))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--compiler-root', type=Path, required=True)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument('--translation', type=Path, help='Existing exact translation baseline')
    mode.add_argument('--source-build', action='store_true', help='Package current sources; qualify actual callbacks separately')
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--llvm-build', type=Path, help='Verified arm64e LLVM build.json')
    ap.add_argument('--mesa-build', type=Path, help='Verified arm64e Mesa build.json')
    ap.add_argument('--baseline-source-ref', help='Git commit holding unchanged translation-baseline source bytes when rebuilding an edited compiler')
    args = ap.parse_args()
    compiler, out = args.compiler_root.resolve(), args.output.resolve()
    translation = args.translation.resolve() if args.translation else None
    assert not out.exists(), 'preserve previous attempts'
    assert bool(args.llvm_build) == bool(args.mesa_build)
    assert not args.source_build or args.llvm_build, 'source builds require both verified arm64e dependency records'
    assert not args.source_build or not args.baseline_source_ref, 'source builds have no historical baseline'
    translated = json.loads(translation.read_text()) if translation else {}
    if translation: assert translated['status'] == 'NATIVE_CALLBACKS_TRANSLATED_TO_IR3'
    baseline_sources = {}
    baseline_ref = None
    if args.baseline_source_ref:
        baseline_ref = subprocess.check_output(['git', '-C', str(compiler), 'rev-parse',
            '--verify', args.baseline_source_ref + '^{commit}'], text=True).strip()
        repository = Path(subprocess.check_output(['git', '-C', str(compiler), 'rev-parse',
            '--show-toplevel'], text=True).strip())
    for group in ['compiler_sources_sha256', 'compiler_binaries_sha256']:
        for name, digest in (translated[group] if translation else {}).items():
            current = sha(Path(name))
            if current == digest:
                continue
            assert group == 'compiler_sources_sha256' and baseline_ref, name
            # The translation may name a sibling worktree of the same repository (its git objects hold the
            # baseline commit): resolve each source against its own worktree.
            owner = Path(subprocess.check_output(['git', '-C', str(Path(name).parent), 'rev-parse',
                '--show-toplevel'], text=True).strip())
            common = lambda root: subprocess.check_output(['git', '-C', str(root), 'rev-parse', '--path-format=absolute',
                '--git-common-dir'], text=True)
            assert common(owner) == common(repository), name
            relative = Path(name).resolve().relative_to(owner)
            historical = subprocess.check_output(['git', '-C', str(owner), 'show',
                baseline_ref + ':' + str(relative)])
            assert hashlib.sha256(historical).hexdigest() == digest, name
            baseline_sources[name] = dict(commit=baseline_ref, path=str(relative),
                baseline_sha256=digest, current_sha256=current)
    for name, digest in (translated['artifacts_sha256'] if translation else {}).items():
        assert sha(translation.parent / name) == digest, name
    out.mkdir(parents=True)
    shutil.copy2(Path(__file__), out / 'build-source.py')
    runtime = out / 'runtime'
    runtime.mkdir()
    (out / 'api').mkdir()
    commands, inputs, closure = [], {}, {}
    record = dict(status='RUNNING', started=time.time(), translation=str(translation) if translation else None,
        translation_sha256=sha(translation) if translation else None, commands=commands, inputs_sha256=inputs,
        dependencies=closure, source_sha256=sha(Path(__file__)),
        boundary=('Current source arm64e compiler package; callback execution requires separate qualification.' if args.source_build else
            'Host arm64e C API caller and relocatable signed compiler closure; no guest load or Metal pipeline integration.'))
    record['historical_baseline_sources'] = baseline_sources

    def run(command, label):
        row = dict(command=[str(x) for x in command], log=label + '.log')
        commands.append(row)
        with (out / row['log']).open('x') as log:
            result = subprocess.run(row['command'], stdout=log, stderr=subprocess.STDOUT, timeout=180)
        row['exit_code'] = result.returncode
        assert result.returncode == 0, row

    try:
        mesa = compiler / 'build/mesa'
        llvm_config = Path('/opt/homebrew/opt/llvm/bin/llvm-config')
        compiler_inputs = ['-Wl,-force_load,' + str(compiler / 'build/libair2ir3.a')]
        compiler_arch = 'arm64'
        library_search = []
        extra_libs = ['-L/opt/homebrew/opt/zstd/lib', '-lzstd', '-lz']
        if args.llvm_build:
            llvm_record, mesa_record = args.llvm_build.resolve(), args.mesa_build.resolve()
            lj, mj = [json.loads(p.read_text()) for p in [llvm_record, mesa_record]]
            assert lj['status'] == 'ARM64E_LLVM_BUILT' and mj['status'] == 'ARM64E_MESA_BUILT'
            for p in [llvm_record, mesa_record]: inputs[str(p)] = sha(p)
            for row in lj['libraries'] + mj['libraries']:
                path = Path(row['path']); assert sha(path) == row['sha256'], path
                inputs[str(path)] = row['sha256']
            mesa = mesa_record.parent / 'build'
            mesa_source = Path(mj['source'])
            for name, digest in mj['source_sha256'].items():
                if Path(name).name == '.DS_Store' or Path(name).name.startswith('._'):
                    continue                # Finder metadata the Mesa build recorded but never compiles
                assert sha(mesa_source / name) == digest, name
            llvm_root = llvm_record.parent / 'build'
            llvm_config = llvm_root / 'bin/llvm-config'
            library_search.append(llvm_root / 'lib')
            compiler_arch = 'arm64e'
            extra_libs = ['-lz']
            build_source = compiler / 'src/build.sh'
            inputs[str(build_source)] = sha(build_source)
            text = build_source.read_text()
            def array(name):
                found = re.search(r'^' + name + r'=\((.*?)\)', text, re.M | re.S)
                assert found, name
                replacements = {'$HERE': str(compiler / 'src'), '$M': str(mesa_source), '$B': str(mesa)}
                result = []
                for item in shlex.split(found.group(1)):
                    for key, value in replacements.items(): item = item.replace(key, value)
                    assert '$' not in item, item
                    result.append(item)
                return result
            include, defines, cxx = array('INC'), array('DEFS'), array('CXXF')
            flags = shlex.split(subprocess.check_output([llvm_config, '--cxxflags'], text=True))
            flags = [x for x in flags if not x.startswith('-std=') and x != '-fno-exceptions']
            cid_source = compiler / 'tools/compiler_id.py'
            inputs[str(cid_source)] = sha(cid_source)
            spec = importlib.util.spec_from_file_location('runtime_compiler_id', cid_source)
            cid = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(cid)
            base_id = cid.compiler_id(str(mesa), str(llvm_config))
            mesa_options = hashlib.sha256('\n'.join(cid.mesa_options(str(mesa))).encode()).hexdigest()[:8]
            llvm_options = sorted(x for r in lj['commands'] if r['log'] == 'configure.log'
                for x in r['command'] if x.startswith('-D'))
            llvm_options_hash = hashlib.sha256(json.dumps(llvm_options).encode()).hexdigest()[:8]
            identity = re.sub(r'-o[0-9a-f]{8}\+llvm-', '-o' + mesa_options + '+llvm-', base_id)
            identity += '+arm64e-' + llvm_options_hash
            record['compiler_id'] = identity
            record['llvm_options'] = llvm_options
            for name in cid.SRC:
                for path in source_files(compiler / name): inputs[str(path)] = sha(path)
            cpp_object, sampler_object = out / 'air2ir3.o', out / 'a8xx_sampler.o'
            run(['xcrun', 'clang++', '-arch', compiler_arch, '-mmacosx-version-min=27.0',
                *cxx, *flags, *include, *defines, '-DAIR2IR3_COMPILER_ID="' + identity + '"',
                '-DAIR2IR3_NO_MAIN', '-c', compiler / 'src/air2ir3.cpp', '-o', cpp_object], 'compile-compiler')
            run(['xcrun', 'clang', '-arch', compiler_arch, '-mmacosx-version-min=27.0',
                '-std=c11', '-O1', '-g', *include, *defines, '-c', compiler / 'src/a8xx_sampler.c',
                '-o', sampler_object], 'compile-sampler')
            compiler_inputs = [cpp_object, sampler_object]
        else:
            inputs[str(compiler / 'build/libair2ir3.a')] = sha(compiler / 'build/libair2ir3.a')
        archives = [mesa / name for name in [
            'src/freedreno/ir3/libfreedreno_ir3.a', 'src/freedreno/isa/libir3encode.a',
            'src/freedreno/isa/libir3decode.a', 'src/compiler/isaspec/libisaspec.a',
            'src/freedreno/common/libfreedreno_common.a', 'src/compiler/nir/libnir.a',
            'src/compiler/libcompiler.a', 'src/util/libmesa_util.a',
            'src/util/libmesa_util_simd.a', 'src/c11/impl/libmesa_util_c11.a',
            'src/util/blake3/libblake3.a']]
        for p in archives + [compiler / 'tests/api_test.c', compiler / 'src/air2ir3_api.h']:
            inputs[str(p)] = sha(p)
        llvm_flags = shlex.split(subprocess.check_output([llvm_config,
            '--ldflags', '--libs', 'core', 'bitreader', 'bitwriter', 'passes', 'irreader',
            'analysis', 'transformutils', 'ipo', 'scalaropts', 'instcombine', '--system-libs'], text=True))
        inputs[str(llvm_config)] = sha(llvm_config)
        if args.llvm_build:
            record['llvm_link_archives'] = []
            for flag in llvm_flags:
                if not flag.startswith('-lLLVM'): continue
                archive = llvm_root / 'lib' / ('lib' + flag[2:] + '.a')
                assert archive.is_file(), archive
                inputs[str(archive)] = sha(archive)
                arch = subprocess.check_output(['lipo', '-archs', archive], text=True).strip()
                assert arch == 'arm64e', (archive, arch)
                record['llvm_link_archives'].append(dict(path=str(archive), architecture=arch))
        library = runtime / 'libAdrenoCompiler.dylib'
        run(['xcrun', 'clang++', '-arch', compiler_arch, '-mmacosx-version-min=27.0', '-dynamiclib',
            '-Wl,-headerpad_max_install_names', '-Wl,-dead_strip',
            '-Wl,-exported_symbol,_air2ir3_*', '-Wl,-install_name,@rpath/libAdrenoCompiler.dylib',
            '-o', library, *compiler_inputs, *archives, *llvm_flags, *extra_libs], 'link-library')
        queue = [(library, library)]
        copies = {}
        while queue:
            source, target = queue.pop(0)
            deps = dependencies(source)
            own = deps[0]
            closure[target.name] = dict(original=str(source), original_dependencies=deps)
            if source != library:
                inputs[str(source)] = sha(source)
                shutil.copy2(source, target)
            run(['install_name_tool', '-id', '@loader_path/' + target.name, target], 'id-' + target.name)
            for dep in deps[1:]:
                if system_path(dep): continue
                original = Path(dep)
                if dep.startswith('@rpath/'):
                    matches = [p / dep[len('@rpath/'):] for p in library_search if (p / dep[len('@rpath/'):]).is_file()]
                    assert len(matches) == 1, (dep, matches)
                    original = matches[0]
                assert original.is_absolute() and original.is_file(), dep
                destination = runtime / original.name
                if destination.name in copies:
                    assert copies[destination.name].resolve() == original.resolve(), 'dependency basename collision'
                else:
                    assert destination != library
                    copies[destination.name] = original
                    queue.append((original, destination))
                run(['install_name_tool', '-change', dep, '@loader_path/' + destination.name, target],
                    'change-' + target.name + '-' + destination.name)
            assert own
        for p in runtime.iterdir():
            deps = dependencies(p)
            for dep in deps:
                assert system_path(dep) or (dep.startswith('@loader_path/') and
                    (runtime / dep[len('@loader_path/'):]).is_file()), (p, dep)
            closure[p.name]['packaged_dependencies'] = deps
            run(['codesign', '--force', '--sign', '-', p], 'sign-' + p.name)
            run(['codesign', '--verify', '--strict', p], 'verify-' + p.name)
        harness = out / 'api-test-arm64e'
        run(['xcrun', 'clang', '-arch', 'arm64e', '-mmacosx-version-min=27.0', '-std=c11', '-O1',
            '-I', compiler / 'src', compiler / 'tests/api_test.c', '-L', runtime, '-lAdrenoCompiler',
            '-Wl,-rpath,@executable_path/runtime', '-o', harness], 'link-arm64e')
        run(['codesign', '--force', '--sign', '-', harness], 'sign-arm64e')
        run(['codesign', '--verify', '--strict', harness], 'verify-arm64e')
        magic, cpu, subtype = struct.unpack_from('<III', harness.read_bytes())
        record['caller_macho'] = dict(magic=hex(magic), cputype=hex(cpu), cpusubtype=hex(subtype))
        assert magic == 0xfeedfacf and cpu == 0x100000c and subtype & 0xffffff == 2, 'caller is not arm64e'
        # The library ID is relative to its loader. The executable is outside
        # runtime, so bind this one load command to the matching sibling folder.
        run(['install_name_tool', '-change', '@loader_path/libAdrenoCompiler.dylib',
            '@executable_path/runtime/libAdrenoCompiler.dylib', harness], 'bind-arm64e')
        run(['codesign', '--force', '--sign', '-', harness], 'resign-arm64e')
        record['caller_dependencies'] = dependencies(harness)
        if translation:
            run([harness, 'list', translation.parent / 'jobs.txt', '--repeat', '1',
                '--threads', '2', '--out', out / 'api'], 'compile-arm64e')
            record['variants'] = []
            for index, v in enumerate(translated['variants']):
                assert (out / 'api' / (str(index) + '.ir3v')).read_bytes() == (
                    translation.parent / 'api' / (str(index) + '.ir3v')).read_bytes(), v['stage']
                side, baseline_side = [json.loads((p / 'api' / (str(index) + '.json')).read_text())
                    for p in [out, translation.parent]]
                if args.llvm_build:
                    assert side['compiler_id'] == record['compiler_id']
                    # The actual compiler build identity changes its cache key.
                    for key in ['compiler_id', 'key']:
                        side.pop(key); baseline_side.pop(key)
                assert side == baseline_side, v['stage']
                record['variants'].append(dict(stage=v['stage'], identical=True,
                    blob_sha256=sha(out / 'api' / (str(index) + '.ir3v'))))
        for name, digest in inputs.items(): assert sha(Path(name)) == digest, name
        if translation: assert sha(translation) == record['translation_sha256']
        record['status'] = ('PACKAGED_COMPILER_SOURCE_BUILD' if args.source_build else
            'PACKAGED_COMPILER_ARM64E_C_API_VERIFIED')
    except BaseException as error:
        record.update(status='FAIL', exception=repr(error))
        raise
    finally:
        record['finished'] = time.time()
        record['artifacts_sha256'] = {str(p.relative_to(out)): sha(p) for p in out.rglob('*') if p.is_file()}
        (out / 'qualification.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(dict(status=record['status'], libraries=len(closure))))


if __name__ == '__main__':
    main()
