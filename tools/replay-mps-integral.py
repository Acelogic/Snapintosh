#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Execute captured MPS integral AIR on CPU, retaining exact buffers and hashes.

This checks recovered shader semantics and the captured binding/dispatch contract.
It does not execute NIR, ir3, Adreno packets, or any GPU. The original kernel bodies
are unchanged; only the target triple/layout and four AIR external intrinsics are
adapted for the host. Failure inventory precedes implementation in the companion doc.
"""
import argparse
import ctypes as C
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
LLVM = Path('/opt/homebrew/opt/llvm/bin')
ENTRIES = ('sum_rgba_columns', 'sum_rgba_rows')

def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

class Texture(C.Structure):
    _fields_ = [('width', C.c_uint32), ('height', C.c_uint32),
                ('stride', C.c_uint32), ('pixels', C.POINTER(C.c_float))]

def texture(width, height):
    # Guard rows/ends and non-tight row stride detect addressing errors.
    stride = width * 4 + 12
    data = (C.c_float * ((height + 2) * stride))(*([-8191.0] * ((height + 2) * stride)))
    ptr = C.cast(C.byref(data, stride * 4), C.POINTER(C.c_float))
    return Texture(width, height, stride, ptr), data

def host_ir(ir):
    declarations = re.findall(r'^declare .*$', ir, re.M)
    expected = {'air.convert.f.f32.s.i32', 'air.convert.f.f32.u.i16',
                'air.sample_texture_2d.v4f32', 'air.write_texture_2d.v4f32'}
    require({re.search(r'@([^ (]+)', d)[1] for d in declarations} == expected,
            'Unexpected AIR intrinsic contract')
    for declaration in declarations:
        ir = ir.replace(declaration, '')
    ir = re.sub(r'^target datalayout = .*\n', '', ir, flags=re.M)
    ir = re.sub(r'^target triple = .*$', 'target triple = "arm64-apple-macosx14.0.0"', ir, flags=re.M)
    # Address spaces 1/2 denote Metal device/constant storage. The host ABI uses
    # ordinary pointers. Keep all kernel instructions, metadata and branches.
    ir = ir.replace(' addrspace(1)', '').replace(' addrspace(2)', '')
    return ir + '''
declare <4 x float> @replay_sample(ptr, ptr, <2 x float>, i1, <2 x i32>, i1, float, float, i32)
declare void @replay_write(ptr, <2 x i32>, <4 x float>, i32, i32)
define float @air.convert.f.f32.s.i32(i32 %v) {
  %r = sitofp i32 %v to float
  ret float %r
}
define float @air.convert.f.f32.u.i16(i16 %v) {
  %r = uitofp i16 %v to float
  ret float %r
}
define { <4 x float>, i8 } @air.sample_texture_2d.v4f32(ptr %t, ptr %s, <2 x float> %p, i1 %a, <2 x i32> %o, i1 %b, float %l, float %bias, i32 %m) {
  %v = call <4 x float> @replay_sample(ptr %t, ptr %s, <2 x float> %p, i1 %a, <2 x i32> %o, i1 %b, float %l, float %bias, i32 %m)
  %r = insertvalue { <4 x float>, i8 } poison, <4 x float> %v, 0
  %r2 = insertvalue { <4 x float>, i8 } %r, i8 0, 1
  ret { <4 x float>, i8 } %r2
}
define void @air.write_texture_2d.v4f32(ptr %t, <2 x i32> %p, <4 x float> %v, i32 %l, i32 %a) {
  call void @replay_write(ptr %t, <2 x i32> %p, <4 x float> %v, i32 %l, i32 %a)
  ret void
}
'''

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--capture', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    cap = args.capture.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    capture = json.loads(cap.read_text())
    require(capture['status'] == 'ENCODING_CAPTURE_ONLY', 'Capture did not complete')
    require(capture['intercepted_commits'] == len(capture['cases']), 'Commit count mismatch')
    report = {'status': 'RUNNING', 'boundary': 'Captured AIR executed on host CPU; no Adreno/GPU execution',
              'commands': [], 'sources': {}, 'cases': [], 'artifacts': {}}
    inputs = [Path(__file__), ROOT/'tools/replay-mps-integral.c', cap]
    kernels = {}
    def run(argv, name):
        report['commands'].append([str(a) for a in argv])
        with (out/(name+'.log')).open('w') as f:
            subprocess.run(argv, stdout=f, stderr=subprocess.STDOUT, check=True, timeout=60)
    for entry in ENTRIES:
        rows = [p for p in capture['pipelines'] if p['entry'] == entry]
        require(len(rows) == 1 and rows[0]['compiled'], 'Missing or ambiguous captured pipeline')
        row = rows[0]
        air = cap.parent/row['air_file']
        require(sha(air) == row['air_sha256'], 'Captured AIR hash differs')
        inputs.append(air)
        original = out/(entry+'.ll')
        run([LLVM/'llvm-dis', air, '-o', original], entry+'-disassemble')
        adapted = out/(entry+'-host.ll')
        adapted.write_text(host_ir(original.read_text()))
        library = out/(entry+'.dylib')
        run([LLVM/'clang', '-dynamiclib', '-O0', '-g', adapted, ROOT/'tools/replay-mps-integral.c',
             '-o', library], entry+'-build')
        lib = C.CDLL(str(library))
        fn = getattr(lib, entry)
        fn.argtypes = [C.POINTER(Texture), C.POINTER(Texture), C.c_void_p, C.c_void_p, C.c_uint16]
        fn.restype = None
        kernels[entry] = (lib, fn)
    for case in capture['cases']:
        name = case['name']
        require(re.fullmatch(r'[a-z0-9-]+|\d+x\d+', name), 'Unsafe case name')
        work = case['work']
        require(work['omitted'] == 2 and work['encoded'] == 0 and not work['trace_incomplete'],
                'Expected exactly two accounted compute omissions')
        ops = work['omissions']
        require([o['details']['pipeline']['entry'] for o in ops] == list(ENTRIES), 'Wrong dispatch order')
        constants = [r for r in capture['inline_bytes'] if r['case'] == name]
        samplers = [r for r in capture['samplers'] if r['case'] == name]
        require(len(constants) == 2, 'Missing constants')
        require(samplers and all(r['index'] == 0 and not r['normalized'] and r['min'] == 0 and
                r['mag'] == 0 and r['mip'] == 0 and r['s'] == 4 and r['t'] == 4 for r in samplers),
                'Unsupported sampler: expected nearest unnormalized clamp-to-zero')
        textures = {}
        for op in ops:
            d = op['details']
            require(op['operation'] == 'compute-threadgroups' and d['grid'][1:] == [1,1] and
                    d['threads'] == [64,1,1], 'Unexpected dispatch geometry')
            for slot in ['texture:0','texture:1']:
                b = d['bindings'][slot]
                require(b['bound'] and b['format'] == 125, 'Expected RGBA32Float texture')
                rid = b['resource']
                if rid not in textures:
                    textures[rid] = texture(b['width'], b['height'])
                t,_ = textures[rid]
                require((t.width,t.height) == (b['width'],b['height']), 'Resource metadata drift')
        resources = [(o['details']['bindings']['texture:0']['resource'],
                      o['details']['bindings']['texture:1']['resource']) for o in ops]
        require(len(textures) == 3 and resources[0][1] == resources[1][0] and
                len(set((resources[0][0], resources[0][1], resources[1][1]))) == 3,
                'Intermediate alias/order mismatch')
        src, srcdata = textures[resources[0][0]]
        for y in range(src.height):
            for x in range(src.width):
                for c in range(4):
                    src.pixels[y*src.stride+x*4+c] = ((x*7+y*13+c*3)%17)-8
        before = {rid: bytes(data) for rid,(_,data) in textures.items()}
        expected = {rid: list(data) for rid,(_,data) in textures.items()}
        perpass = []
        decoded = []
        for index,(op,constant) in enumerate(zip(ops,constants)):
            require(constant['index'] == 0 and len(constant['hex']) == 24, 'Wrong IntegralParams')
            params = (C.c_uint16*6).from_buffer_copy(bytes.fromhex(constant['hex']))
            decoded.append(params)
            sx,sy,dx,dy,w,h = params
            source,destination = resources[index]
            st,_ = textures[source];dt,_ = textures[destination]
            require(sx+w<=st.width and sy+h<=st.height and dx+w<=dt.width and dy+h<=dt.height,
                    'This replay requires in-bounds source/destination rectangles')
            require(0<w<=65535 and 0<h<=65535, 'Invalid region')
            # Independent oracle: sum the entire prefix from saved scalar values
            # for each output; it does not copy the shader's four-way unrolled loop.
            values = expected[source]
            for y in range(h):
                for x in range(w):
                    for c in range(4):
                        coords = ((x,k) for k in range(y+1)) if index == 0 else ((k,y) for k in range(x+1))
                        total = sum(values[(sy+yy+1)*st.stride+(sx+xx)*4+c] for xx,yy in coords)
                        expected[destination][(dy+y+1)*dt.stride+(dx+x)*4+c] = total
            lib,fn = kernels[ENTRIES[index]];lib.replay_reset()
            count = op['details']['grid'][0]*64
            require(count>= (w if index == 0 else h) and count<=65535, 'Under/overflow dispatch')
            for gid in range(count):
                fn(C.byref(st), C.byref(dt), None, params, gid)
            require(lib.replay_errors() == 0, 'Intrinsic contract/bounds failure')
            actual = list(textures[destination][1])
            mismatches = sum(a!=b for a,b in zip(actual,expected[destination]))
            require(mismatches == 0, f'{name}/{ENTRIES[index]}: {mismatches} pixel/guard mismatches')
            perpass.append({'entry': ENTRIES[index], 'params_u16':list(params), 'invocations':count,
                            'extra_guarded_invocations':count-(w if index==0 else h), 'mismatches':mismatches})
        require(bytes(srcdata) == before[resources[0][0]], 'Input mutated')
        for rid,(tex,data) in textures.items():
            (out/f'{name}-resource-{rid}.f32').write_bytes(bytes(data))
        # Re-run the actual kernels with missing/reversed dispatches. These are
        # the visible bugs this artifact must detect, not an assertion about the
        # implementation's internal structure.
        controls = []
        final_id = resources[1][1]
        for label,order in [('skip-columns',[1]),('skip-rows',[0]),('reversed',[1,0])]:
            for rid,(_,data) in textures.items():
                C.memmove(data, before[rid], len(before[rid]))
            for index in order:
                st = textures[resources[index][0]][0];dt = textures[resources[index][1]][0]
                lib,fn = kernels[ENTRIES[index]];lib.replay_reset()
                for gid in range(ops[index]['details']['grid'][0]*64):
                    fn(C.byref(st), C.byref(dt), None, decoded[index], gid)
                require(lib.replay_errors() == 0, 'Negative control intrinsic failure')
            differences = sum(a!=b for a,b in zip(textures[final_id][1],expected[final_id]))
            require(differences > 0, f'Oracle missed {label}')
            controls.append({'mutation':label, 'detected_components':differences})
        report['cases'].append({'name':name, 'passes':perpass, 'guards_and_padding':'unchanged',
            'source_unchanged':True, 'negative_controls':controls,
            'resources':{str(rid):{'width':tex.width,'height':tex.height,'stride_floats':tex.stride,
                         'file':f'{name}-resource-{rid}.f32'} for rid,(tex,_) in textures.items()},
            'raw_format':'float32 including guard rows and row padding'})
    report['sources'] = {str(p):sha(p) for p in inputs}
    report['artifacts'] = {str(p.relative_to(out)):sha(p) for p in out.iterdir() if p.is_file()}
    report['status'] = 'PASS_CAPTURED_AIR_CPU_REPLAY'
    (out/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    print(f"{report['status']}: {len(report['cases'])} cases; exact pixels, source and guards")

if __name__ == '__main__':
    main()
