// SPDX-License-Identifier: MIT
// verify5: Metal side of the unset-constant differential test with 12 constant types.
// stdin "<metallib>\t<case>", case tokens "i=v" (v = u for unset). Types by index:
// 0 A bool,1 B bool,2 C bool,3 N int,4 F float,5 U ushort,6 S short,7 Q uchar,8 K char,9 W uint,10 H half,11 D bool
import Metal
let dev = MTLCreateSystemDefaultDevice()!
let q = dev.makeCommandQueue()!
var libs: [String: MTLLibrary] = [:]
let tdesc = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: .rgba32Float, width: 1, height: 1, mipmapped: false)
tdesc.usage = [.renderTarget]; tdesc.storageMode = .shared
let tex = dev.makeTexture(descriptor: tdesc)!
var bufs: [MTLBuffer] = []
for k in 0..<16 { var v: [Float] = [Float(1 << k), 0.5, 0.25, 1]; bufs.append(dev.makeBuffer(bytes: &v, length: 64)!) }
while let line = readLine() {
  let parts = line.split(separator: "\t").map(String.init)
  let path = parts[0], cs = parts.count > 1 ? parts[1] : ""
  let fcv = MTLFunctionConstantValues()
  for tok in cs.split(separator: " ") {
    let p = tok.split(separator: "="); let i = Int(p[0])!; let v = String(p[1])
    if v == "u" { continue }
    switch i {
    case 3: var x = Int32(v)!; fcv.setConstantValue(&x, type: .int, index: i)
    case 4: var x = Float(v)!; fcv.setConstantValue(&x, type: .float, index: i)
    case 5: var x = UInt16(v)!; fcv.setConstantValue(&x, type: .ushort, index: i)
    case 6: var x = Int16(v)!; fcv.setConstantValue(&x, type: .short, index: i)
    case 7: var x = UInt8(v)!; fcv.setConstantValue(&x, type: .uchar, index: i)
    case 8: var x = Int8(v)!; fcv.setConstantValue(&x, type: .char, index: i)
    case 9: var x = UInt32(v)!; fcv.setConstantValue(&x, type: .uint, index: i)
    case 10: var x = Float16(Float(v)!); fcv.setConstantValue(&x, type: .half, index: i)
    default: var b = v == "1"; fcv.setConstantValue(&b, type: .bool, index: i)
    }
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
    for k in 0..<16 { e.setFragmentBuffer(bufs[k], offset: 0, index: k) }
    e.drawPrimitives(type: .triangle, vertexStart: 0, vertexCount: 3); e.endEncoding(); cb.commit(); cb.waitUntilCompleted()
    var px = [Float](repeating: 0, count: 4)
    tex.getBytes(&px, bytesPerRow: 16, from: MTLRegionMake2D(0, 0, 1, 1), mipmapLevel: 0)
    print(path + "\t" + cs, "->", present, "px", px.map { String(format: "%08x", $0.bitPattern) }.joined(separator: " "))
  } catch { print(path + "\t" + cs, "-> ERR", error.localizedDescription.prefix(160).replacingOccurrences(of: "\n", with: " ")) }
}
