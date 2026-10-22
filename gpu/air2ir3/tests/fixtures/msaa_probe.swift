// SPDX-License-Identifier: MIT
// fix3 (verify3 item 4): when does Metal run a fragment function per SAMPLE on a multisampled
// attachment?  4x MSAA rgba32Float.  Pass 1 writes each sample's own id (per-sample by [[sample_id]]).
// Pass 2 (loadAction .load) runs one of the probe functions below over the whole target; a kernel then
// reads every sample back.  Per-sample execution leaves 4 different values in a pixel, per-pixel
// execution one value broadcast to the covered samples.
// Output, one line per probe: "<probe> per_sample|per_pixel <sample values of pixel (1,1)>"
import Metal
let src = """
#include <metal_stdlib>
using namespace metal;
struct V { float4 p [[position]]; float2 uv; };
vertex V vs(uint i [[vertex_id]]) { float2 q[3] = {float2(-1,-1), float2(3,-1), float2(-1,3)}; V o; o.p = float4(q[i], 0, 1); o.uv = q[i]; return o; }
fragment float4 write_id(uint s [[sample_id]]) { return float4(float(s), 0, 0, 1); }
// framebuffer fetch only (programmable blending): no sample_id, no sample interpolation
fragment float4 fbfetch(float4 c [[color(0)]]) { return c + float4(10, 0, 0, 0); }
// neither: a plain constant colour (control, must be per-pixel)
fragment float4 plain() { return float4(20, 0, 0, 1); }
// a varying with sample interpolation (value differs per sample position)
struct VS { float4 p [[position]]; float2 uv [[sample_perspective]]; };
vertex VS vs2(uint i [[vertex_id]]) { float2 q[3] = {float2(-1,-1), float2(3,-1), float2(-1,3)}; VS o; o.p = float4(q[i], 0, 1); o.uv = q[i] * 100.0; return o; }
fragment float4 sample_interp(VS v [[stage_in]]) { return float4(30 + v.uv.x, 0, 0, 1); }
// centre interpolation of the same varying (control: per pixel)
struct VC { float4 p [[position]]; float2 uv; };
fragment float4 center_interp(VC v [[stage_in]]) { return float4(30 + v.uv.x * 100.0, 0, 0, 1); }
kernel void readback(texture2d_ms<float> t [[texture(0)]], device float *o [[buffer(0)]]) {
  for (uint s = 0; s < 4; s++) o[s] = t.read(uint2(1, 1), s).x;
}
"""
let dev = MTLCreateSystemDefaultDevice()!
let q = dev.makeCommandQueue()!
let lib = try! dev.makeLibrary(source: src, options: nil)
func pso(_ fs: String) -> MTLRenderPipelineState {
  let d = MTLRenderPipelineDescriptor(); d.vertexFunction = lib.makeFunction(name: fs == "sample_interp" ? "vs2" : "vs"); d.fragmentFunction = lib.makeFunction(name: fs)
  d.colorAttachments[0].pixelFormat = .rgba32Float; d.rasterSampleCount = 4
  return try! dev.makeRenderPipelineState(descriptor: d)
}
let td = MTLTextureDescriptor(); td.textureType = .type2DMultisample; td.pixelFormat = .rgba32Float; td.width = 4; td.height = 4
td.sampleCount = 4; td.usage = [.renderTarget, .shaderRead]; td.storageMode = .private
let rt = dev.makeTexture(descriptor: td)!
let rb = try! dev.makeComputePipelineState(function: lib.makeFunction(name: "readback")!)
let out = dev.makeBuffer(length: 16, options: .storageModeShared)!
for probe in ["fbfetch", "plain", "sample_interp", "center_interp"] {
  let cb = q.makeCommandBuffer()!
  for (i, fs) in ["write_id", probe].enumerated() {
    let rp = MTLRenderPassDescriptor(); rp.colorAttachments[0].texture = rt
    rp.colorAttachments[0].loadAction = i == 0 ? .clear : .load; rp.colorAttachments[0].storeAction = .store
    let e = cb.makeRenderCommandEncoder(descriptor: rp)!; e.setRenderPipelineState(pso(fs)); e.drawPrimitives(type: .triangle, vertexStart: 0, vertexCount: 3); e.endEncoding()
  }
  let c = cb.makeComputeCommandEncoder()!; c.setComputePipelineState(rb); c.setTexture(rt, index: 0); c.setBuffer(out, offset: 0, index: 0)
  c.dispatchThreadgroups(MTLSize(width: 1, height: 1, depth: 1), threadsPerThreadgroup: MTLSize(width: 1, height: 1, depth: 1)); c.endEncoding()
  cb.commit(); cb.waitUntilCompleted()
  let v = Array(UnsafeBufferPointer(start: out.contents().bindMemory(to: Float.self, capacity: 4), count: 4))
  print(probe, Set(v).count > 1 ? "per_sample" : "per_pixel", v)
}
