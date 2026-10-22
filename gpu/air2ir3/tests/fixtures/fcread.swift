// SPDX-License-Identifier: MIT
// fix2 (verify2 item 5): which constant buffers does Metal's specialised fragment function READ?
// Buffer k holds float4(2^k, 0, 0, 0); every buffer 0..7 is bound; the fixture returns the sum of the
// buffers it reads, so the red channel of one rendered pixel is the read set as a bitmask.
// Also prints the reflection's present set.  stdin: one case per line ("0=u 1=1 2=0 3=2"; index 3 is int).
import Metal
let dev = MTLCreateSystemDefaultDevice()!
let q = dev.makeCommandQueue()!
let lib = try! dev.makeLibrary(URL: URL(fileURLWithPath: CommandLine.arguments[1]))
let vs = try! dev.makeLibrary(source: "#include <metal_stdlib>\nusing namespace metal; vertex float4 v(uint i [[vertex_id]]) { float2 p[3] = {float2(-1,-1), float2(3,-1), float2(-1,3)}; return float4(p[i], 0, 1); }", options: nil).makeFunction(name: "v")!
let tdesc = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: .rgba32Float, width: 1, height: 1, mipmapped: false)
tdesc.usage = [.renderTarget]; tdesc.storageMode = .shared
let tex = dev.makeTexture(descriptor: tdesc)!
var bufs: [MTLBuffer] = []
for k in 0..<8 { var v: [Float] = [Float(1 << k), 0, 0, 0]; bufs.append(dev.makeBuffer(bytes: &v, length: 16)!) }
while let line = readLine() {
  let fcv = MTLFunctionConstantValues()
  for tok in line.split(separator: " ") {
    let p = tok.split(separator: "="); let i = Int(p[0])!; let v = String(p[1])
    if v == "u" { continue }
    if i == 3 { var x = Int32(v)!; fcv.setConstantValue(&x, type: .int, index: i) } else { var b = v == "1"; fcv.setConstantValue(&b, type: .bool, index: i) }
  }
  do {
    let f = try lib.makeFunction(name: "f", constantValues: fcv)
    let pd = MTLRenderPipelineDescriptor(); pd.vertexFunction = vs; pd.fragmentFunction = f; pd.colorAttachments[0].pixelFormat = .rgba32Float
    var refl: MTLRenderPipelineReflection?
    let ps = try dev.makeRenderPipelineState(descriptor: pd, options: [.bindingInfo], reflection: &refl)
    let present = refl!.fragmentBindings.filter { $0.type == .buffer }.map { $0.index }.sorted()
    let rp = MTLRenderPassDescriptor(); rp.colorAttachments[0].texture = tex; rp.colorAttachments[0].loadAction = .clear
    rp.colorAttachments[0].clearColor = MTLClearColor(red: 0, green: 0, blue: 0, alpha: 0); rp.colorAttachments[0].storeAction = .store
    let cb = q.makeCommandBuffer()!; let e = cb.makeRenderCommandEncoder(descriptor: rp)!
    e.setRenderPipelineState(ps)
    for k in 0..<8 { e.setFragmentBuffer(bufs[k], offset: 0, index: k) }
    e.drawPrimitives(type: .triangle, vertexStart: 0, vertexCount: 3); e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
    var px = [Float](repeating: 0, count: 4)
    tex.getBytes(&px, bytesPerRow: 16, from: MTLRegionMake2D(0, 0, 1, 1), mipmapLevel: 0)
    let m = Int(px[0]); let read = (0..<8).filter { (m >> $0) & 1 == 1 }
    print(line, "->", present, "read", read)
  } catch { print(line, "-> ERR", error.localizedDescription.prefix(120)) }
}
