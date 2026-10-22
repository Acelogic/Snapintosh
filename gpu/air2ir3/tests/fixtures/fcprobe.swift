// SPDX-License-Identifier: MIT
import Metal
let dev = MTLCreateSystemDefaultDevice()!
let lib = try! dev.makeLibrary(URL: URL(fileURLWithPath: CommandLine.arguments[1]))
let vs = try! dev.makeLibrary(source: "#include <metal_stdlib>\nusing namespace metal; vertex float4 v(uint i [[vertex_id]]) { return float4(0,0,0,1); }", options: nil).makeFunction(name: "v")!
// args: list of "idx=val" or "idx=u" (unset); each line of stdin is one case
while let line = readLine() {
  let fcv = MTLFunctionConstantValues()
  for tok in line.split(separator: " ") {
    let p = tok.split(separator: "="); let i = Int(p[0])!; let v = String(p[1])
    if v == "u" { continue }
    if i == 3 { var x = Int32(v)!; fcv.setConstantValue(&x, type: .int, index: i) } else { var b = v == "1"; fcv.setConstantValue(&b, type: .bool, index: i) }
  }
  do {
    let f = try lib.makeFunction(name: "f", constantValues: fcv)
    let pd = MTLRenderPipelineDescriptor(); pd.vertexFunction = vs; pd.fragmentFunction = f; pd.colorAttachments[0].pixelFormat = .bgra8Unorm
    var refl: MTLRenderPipelineReflection?
    _ = try dev.makeRenderPipelineState(descriptor: pd, options: [.bindingInfo], reflection: &refl)
    let present = refl!.fragmentBindings.filter { $0.type == .buffer }.map { $0.index }.sorted()
    print(line, "->", present)
  } catch { print(line, "-> ERR", error.localizedDescription.prefix(120)) }
}
