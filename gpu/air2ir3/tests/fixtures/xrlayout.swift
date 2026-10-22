// SPDX-License-Identifier: MIT
// xrlayout.swift - measures the memory layout of MTLPixelFormatBGR10_XR / BGRA10_XR (and BGR10A2Unorm)
// on this Mac by rendering known colours and printing the bytes (FORMATS.md 3).  swiftc -O xrlayout.swift

import Metal
let dev = MTLCreateSystemDefaultDevice()!
let src = """
#include <metal_stdlib>
using namespace metal;
struct VO { float4 p [[position]]; };
vertex VO vs(uint vid [[vertex_id]]) { float2 q[3] = {float2(-1,-1), float2(3,-1), float2(-1,3)}; VO o; o.p = float4(q[vid],0,1); return o; }
fragment float4 fs(constant float4 &c [[buffer(0)]]) { return c; }
"""
let lib = try! dev.makeLibrary(source: src, options: nil)
func probe(_ fmt: MTLPixelFormat, _ bpp: Int, _ col: [Float]) {
  let pd = MTLRenderPipelineDescriptor(); pd.vertexFunction = lib.makeFunction(name: "vs"); pd.fragmentFunction = lib.makeFunction(name: "fs")
  pd.colorAttachments[0].pixelFormat = fmt
  let ps = try! dev.makeRenderPipelineState(descriptor: pd)
  let td = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: fmt, width: 4, height: 4, mipmapped: false); td.usage = [.renderTarget, .shaderRead]; td.storageMode = .shared
  let t = dev.makeTexture(descriptor: td)!
  let q = dev.makeCommandQueue()!; let cb = q.makeCommandBuffer()!
  let rp = MTLRenderPassDescriptor(); rp.colorAttachments[0].texture = t; rp.colorAttachments[0].loadAction = .clear; rp.colorAttachments[0].storeAction = .store
  let e = cb.makeRenderCommandEncoder(descriptor: rp)!; e.setRenderPipelineState(ps); var c = col; e.setFragmentBytes(&c, length: 16, index: 0)
  e.drawPrimitives(type: .triangle, vertexStart: 0, vertexCount: 3); e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
  var raw = [UInt8](repeating: 0, count: bpp); t.getBytes(&raw, bytesPerRow: bpp*4, from: MTLRegionMake2D(0,0,1,1), mipmapLevel: 0)
  print(fmt.rawValue, col, raw.map{String(format:"%02x",$0)}.joined())
}
for col in [[0,0,0,0],[1,0,0,1],[0,1,0,1],[0,0,1,1],[1,1,1,1],[-0.5,0.5,1.25,0.5],[2,-2,0.25,0]] as [[Float]] {
  probe(.bgr10_xr, 4, col); probe(.bgra10_xr, 8, col); probe(.bgr10a2Unorm, 4, col)
}
