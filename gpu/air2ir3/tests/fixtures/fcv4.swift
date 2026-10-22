// SPDX-License-Identifier: MIT
// fix3 (verify3 item 1): Metal side of the randomized unset-constant differential test (tests/fcrand.py).
// stdin: one case per line, "<metallib>\t<case>" with case tokens "i=v" (i = function-constant index,
// v = "u" (unset) or a value; indices 0..2 are bool, 3 is int).  Buffers 0..11 hold float4(2^k, 0, 0, 1);
// one 1x1 rgba32Float pixel is rendered with fragment function "f" and vertex function "v".
// stdout, per line: "<case> -> [present buffer indices] px <x> <y> <z> <w>" (floats as exact hex bit
// patterns), or "<case> -> ERR <message>".
import Metal
let dev = MTLCreateSystemDefaultDevice()!
let q = dev.makeCommandQueue()!
var libs: [String: MTLLibrary] = [:]
let tdesc = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: .rgba32Float, width: 1, height: 1, mipmapped: false)
tdesc.usage = [.renderTarget]; tdesc.storageMode = .shared
let tex = dev.makeTexture(descriptor: tdesc)!
var bufs: [MTLBuffer] = []
for k in 0..<12 { var v: [Float] = [Float(1 << k), 0, 0, 1]; bufs.append(dev.makeBuffer(bytes: &v, length: 16)!) }
while let line = readLine() {
  let parts = line.split(separator: "\t").map(String.init)
  let path = parts[0], cs = parts.count > 1 ? parts[1] : ""
  let fcv = MTLFunctionConstantValues()
  for tok in cs.split(separator: " ") {
    let p = tok.split(separator: "="); let i = Int(p[0])!; let v = String(p[1])
    if v == "u" { continue }
    if i == 3 { var x = Int32(v)!; fcv.setConstantValue(&x, type: .int, index: i) } else if i == 4 { var x = Float(v)!; fcv.setConstantValue(&x, type: .float, index: i) } else if i == 5 { var x = UInt16(v)!; fcv.setConstantValue(&x, type: .ushort, index: i) } else if i == 6 { var x = Int16(v)!; fcv.setConstantValue(&x, type: .short, index: i) } else { var b = v == "1"; fcv.setConstantValue(&b, type: .bool, index: i) }
  }
  do {
    if libs[path] == nil { libs[path] = try dev.makeLibrary(URL: URL(fileURLWithPath: path)) }
    let lib = libs[path]!
    let f = try lib.makeFunction(name: "f", constantValues: fcv)
    let pd = MTLRenderPipelineDescriptor(); pd.vertexFunction = lib.makeFunction(name: "v"); pd.fragmentFunction = f
    pd.colorAttachments[0].pixelFormat = .rgba32Float
    var refl: MTLRenderPipelineReflection?
    let ps = try dev.makeRenderPipelineState(descriptor: pd, options: [.bindingInfo], reflection: &refl)
    let present = refl!.fragmentBindings.filter { $0.type == .buffer }.map { $0.index }.sorted()
    let rp = MTLRenderPassDescriptor(); rp.colorAttachments[0].texture = tex; rp.colorAttachments[0].loadAction = .clear
    rp.colorAttachments[0].clearColor = MTLClearColor(red: 0, green: 0, blue: 0, alpha: 0); rp.colorAttachments[0].storeAction = .store
    let cb = q.makeCommandBuffer()!; let e = cb.makeRenderCommandEncoder(descriptor: rp)!
    e.setRenderPipelineState(ps)
    for k in 0..<12 { e.setFragmentBuffer(bufs[k], offset: 0, index: k) }
    e.drawPrimitives(type: .triangle, vertexStart: 0, vertexCount: 3); e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
    var px = [Float](repeating: 0, count: 4)
    tex.getBytes(&px, bytesPerRow: 16, from: MTLRegionMake2D(0, 0, 1, 1), mipmapLevel: 0)
    print(path + "\t" + cs, "->", present, "px", px.map { String(format: "%08x", $0.bitPattern) }.joined(separator: " "))
  } catch { print(path + "\t" + cs, "-> ERR", error.localizedDescription.prefix(160).replacingOccurrences(of: "\n", with: " ")) }
}
