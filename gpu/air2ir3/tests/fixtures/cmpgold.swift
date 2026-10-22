// SPDX-License-Identifier: MIT
// Metal ground truth for constexpr compare functions (regression test "compare_funcs").
// For each MSL compare_func (and none), sample_compare a 2-texel depth texture [0.25, 0.75] with
// reference 0.5 and 0.25; prints "<name> r00 r01 r10 r11".
import Metal
let dev = MTLCreateSystemDefaultDevice()!
for c in ["none","less","less_equal","greater","greater_equal","equal","not_equal","always","never"] {
  let cf = c == "none" ? "" : ", compare_func::\(c)"
  let src = """
  #include <metal_stdlib>
  using namespace metal;
  kernel void k(depth2d<float> d [[texture(0)]], device float *o [[buffer(0)]], uint i [[thread_position_in_grid]]) {
    constexpr sampler s(filter::nearest\(cf));
    o[i] = d.sample_compare(s, float2((i + 0.5) / 2.0, 0.5), 0.5);
    o[i+2] = d.sample_compare(s, float2((i + 0.5) / 2.0, 0.5), 0.25);
  }
  """
  let lib = try! dev.makeLibrary(source: src, options: nil)
  let ps = try! dev.makeComputePipelineState(function: lib.makeFunction(name: "k")!)
  let td = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: .depth32Float, width: 2, height: 1, mipmapped: false); td.storageMode = .shared; td.usage = .shaderRead
  let t = dev.makeTexture(descriptor: td)!; var v: [Float] = [0.25, 0.75]; t.replace(region: MTLRegionMake2D(0,0,2,1), mipmapLevel: 0, withBytes: &v, bytesPerRow: 8)
  let b = dev.makeBuffer(length: 16, options: .storageModeShared)!
  let q = dev.makeCommandQueue()!; let cb = q.makeCommandBuffer()!; let e = cb.makeComputeCommandEncoder()!
  e.setComputePipelineState(ps); e.setTexture(t, index: 0); e.setBuffer(b, offset: 0, index: 0); e.dispatchThreads(MTLSizeMake(2,1,1), threadsPerThreadgroup: MTLSizeMake(2,1,1)); e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
  let o = b.contents().bindMemory(to: Float.self, capacity: 4)
  print(c, Int(o[0]), Int(o[1]), Int(o[2]), Int(o[3]))
}
