// SPDX-License-Identifier: MIT
// mtlrefl: Metal (M3 Max) binding reflection for function-constant variants.
// stdin: JSON lines {id, metallib, fn, stage, fc:{idx:[vals]}, fcname:{name:[vals]}, vs_candidates:[names], vs_metallib}
// stdout: JSON lines {id, ok, err?, vs?, bindings:[{t, i, used, name}]}
import Foundation
import Metal
let dev = MTLCreateSystemDefaultDevice()!
var libs: [String: MTLLibrary] = [:]
let lk = NSLock()
func lib(_ p: String) -> MTLLibrary { lk.lock(); defer { lk.unlock() }
  if let l = libs[p] { return l }; let l = try! dev.makeLibrary(URL: URL(fileURLWithPath: p)); libs[p] = l; return l }
func setv(_ fcv: MTLFunctionConstantValues, _ t: MTLDataType, _ vals: [Double], idx: Int?, name: String?) {
  var buf = [UInt8]()
  func add<T>(_ x: T) { var y = x; withUnsafeBytes(of: &y) { buf += $0 } }
  let n: Int; let base: String
  switch t {
  case .bool: n=1; base="b"; case .bool2: n=2; base="b"; case .bool3: n=3; base="b"; case .bool4: n=4; base="b"
  case .uchar: n=1; base="u8"; case .uchar2: n=2; base="u8"; case .uchar3: n=3; base="u8"; case .uchar4: n=4; base="u8"
  case .char: n=1; base="i8"; case .char2: n=2; base="i8"; case .char4: n=4; base="i8"
  case .ushort: n=1; base="u16"; case .ushort2: n=2; base="u16"; case .short: n=1; base="i16"
  case .uint: n=1; base="u32"; case .uint2: n=2; base="u32"; case .uint4: n=4; base="u32"
  case .int: n=1; base="i32"; case .int2: n=2; base="i32"; case .int4: n=4; base="i32"
  case .float: n=1; base="f32"; case .float2: n=2; base="f32"; case .float3: n=3; base="f32"; case .float4: n=4; base="f32"
  case .half: n=1; base="f16"; case .half2: n=2; base="f16"; case .half4: n=4; base="f16"
  default: FileHandle.standardError.write("type \(t.rawValue)\n".data(using: .utf8)!); exit(4)
  }
  for k in 0..<n { let v = k < vals.count ? vals[k] : (vals.first ?? 0)
    switch base { case "b": add(v != 0); case "u8": add(UInt8(v)); case "i8": add(Int8(v)); case "u16": add(UInt16(v)); case "i16": add(Int16(v))
    case "u32": add(UInt32(v)); case "i32": add(Int32(v)); case "f32": add(Float(v)); default: add(Float16(v)) } }
  buf.withUnsafeBytes { p in
    if let i = idx { fcv.setConstantValues(p.baseAddress!, type: t, range: i..<(i+1)) ; if n > 1 { } }
    else { fcv.setConstantValue(p.baseAddress!, type: t, withName: name!) } }
}
func mkfn(_ l: MTLLibrary, _ name: String, _ fc: [String: Any], _ fcname: [String: Any]) throws -> MTLFunction {
  let f0 = l.makeFunction(name: name)!
  let fcv = MTLFunctionConstantValues()
  for (k, v) in fc { let i = Int(k)!; let vals = ((v as? [NSNumber]) ?? [v as! NSNumber]).map { $0.doubleValue }
    guard let d = f0.functionConstantsDictionary.values.first(where: { $0.index == i }) else { continue }
    var b = [UInt8](); _ = b
    // vectors: use setConstantValue(_:type:index:)
    var buf = [UInt8](); func add<T>(_ x: T) { var y = x; withUnsafeBytes(of: &y) { buf += $0 } }
    _ = buf
    setIdx(fcv, d.type, vals, i) }
  for (k, v) in fcname { let vals = ((v as? [NSNumber]) ?? [v as! NSNumber]).map { $0.doubleValue }
    guard let d = f0.functionConstantsDictionary[k] else { continue }
    setv(fcv, d.type, vals, idx: nil, name: k) }
  return try l.makeFunction(name: name, constantValues: fcv)
}
func setIdx(_ fcv: MTLFunctionConstantValues, _ t: MTLDataType, _ vals: [Double], _ i: Int) {
  // reuse by-name path semantics via a temp: setConstantValue(_:type:index:)
  var buf = [UInt8](); func add<T>(_ x: T) { var y = x; withUnsafeBytes(of: &y) { buf += $0 } }
  switch t { case .bool: add(vals[0] != 0); case .uchar: add(UInt8(vals[0])); case .int: add(Int32(vals[0])); case .uint: add(UInt32(vals[0]))
  case .float: add(Float(vals[0])); case .half: add(Float16(vals[0])); case .ushort: add(UInt16(vals[0])); case .short: add(Int16(vals[0]))
  case .uchar4: for k in 0..<4 { add(UInt8(k < vals.count ? vals[k] : vals[0])) }
  case .uchar2: for k in 0..<2 { add(UInt8(k < vals.count ? vals[k] : vals[0])) }
  default: FileHandle.standardError.write("idx type \(t.rawValue)\n".data(using: .utf8)!); exit(4) }
  buf.withUnsafeBytes { fcv.setConstantValue($0.baseAddress!, type: t, index: i) }
}
func vdesc(_ f: MTLFunction) -> MTLVertexDescriptor? {
  guard let va = f.vertexAttributes, !va.isEmpty else { return nil }
  let vd = MTLVertexDescriptor(); var off = 0
  for a in va where a.isActive {
    let fmt: MTLVertexFormat; let sz: Int
    switch a.attributeType { case .float: fmt = .float; sz = 4; case .float2: fmt = .float2; sz = 8; case .float3: fmt = .float3; sz = 12
    case .float4: fmt = .float4; sz = 16; case .half2: fmt = .half2; sz = 4; case .half4: fmt = .half4; sz = 8
    case .uchar4: fmt = .uchar4; sz = 4; case .uint: fmt = .uint; sz = 4; case .ushort2: fmt = .ushort2; sz = 4
    default: fmt = .float4; sz = 16 }
    vd.attributes[a.attributeIndex].format = fmt; vd.attributes[a.attributeIndex].offset = off; vd.attributes[a.attributeIndex].bufferIndex = 30; off += sz }
  vd.layouts[30].stride = max(off, 4); return vd }
let dummyFS = try! dev.makeLibrary(source: "#include <metal_stdlib>\nfragment float4 dummyFS() { return float4(0); }", options: nil).makeFunction(name: "dummyFS")!
func flat(_ st: MTLStructType, _ base: Int, _ out: inout [[Int]]) {
  for m in st.members {
    if let ss = m.structType() { flat(ss, base + m.offset, &out) }
    else if let at = m.arrayType() {
      for k in 0..<at.arrayLength { if let es = at.elementStructType() { flat(es, base + m.offset + k * at.stride, &out) } else { out.append([base + m.offset + k * at.stride, Int(at.elementType.rawValue)]) } }
    } else { out.append([base + m.offset, Int(m.dataType.rawValue)]) } }
}
func layout(_ b: MTLBinding) -> [String: Any] {
  guard let bb = b as? MTLBufferBinding else { return [:] }
  var out: [[Int]] = []
  if let st = bb.bufferStructType { flat(st, 0, &out) }
  return ["size": bb.bufferDataSize, "dtype": Int(bb.bufferDataType.rawValue), "members": out]
}
func tname(_ t: MTLBindingType) -> String { switch t { case .buffer: return "buffer"; case .texture: return "texture"; case .sampler: return "sampler"
  case .threadgroupMemory: return "tg"; case .imageblock: return "imageblock"; default: return "other\(t.rawValue)" } }
var lines: [String] = []
while let l = readLine() { lines.append(l) }
var out = [String](repeating: "", count: lines.count)
DispatchQueue.concurrentPerform(iterations: lines.count) { n in
  let j = try! JSONSerialization.jsonObject(with: lines[n].data(using: .utf8)!) as! [String: Any]
  let id = j["id"] as! String
  var r: [String: Any] = ["id": id]
  do {
    let l = lib(j["metallib"] as! String)
    let f = try mkfn(l, j["fn"] as! String, (j["fc"] as? [String: Any]) ?? [:], (j["fcname"] as? [String: Any]) ?? [:])
    var bs: [MTLBinding] = []
    if (j["stage"] as! String) == "kernel" {
      var refl: MTLComputePipelineReflection?
      _ = try dev.makeComputePipelineState(function: f, options: [.bindingInfo], reflection: &refl)
      bs = refl!.bindings
    } else if (j["stage"] as! String) == "fragment" {
      var lastErr = ""
      let vl = lib((j["vs_metallib"] as? String) ?? (j["metallib"] as! String))
      for vsn in (j["vs_candidates"] as! [String]) {
        guard let vf = try? mkfn(vl, vsn, (j["vs_fc"] as? [String: Any]) ?? [:], (j["vs_fcname"] as? [String: Any]) ?? [:]) else { continue }
        let pd = MTLRenderPipelineDescriptor(); pd.vertexFunction = vf; pd.fragmentFunction = f; pd.vertexDescriptor = vdesc(vf)
        let fmts = (j["rt"] as? [Int]) ?? [80]
        for (k, p) in fmts.enumerated() { pd.colorAttachments[k].pixelFormat = MTLPixelFormat(rawValue: UInt(p))! }
        var refl: MTLRenderPipelineReflection?
        do { _ = try dev.makeRenderPipelineState(descriptor: pd, options: [.bindingInfo], reflection: &refl)
          bs = refl!.fragmentBindings; r["vs"] = vsn; r["vbindings"] = refl!.vertexBindings.map { ["t": tname($0.type), "i": $0.index, "used": $0.isUsed, "name": $0.name, "layout": layout($0)] }; r["vattrs"] = (vf.vertexAttributes ?? []).filter { $0.isActive }.map { [$0.attributeIndex, Int($0.attributeType.rawValue)] }; lastErr = ""; break
        } catch { lastErr = "\(error)" }
      }
      if r["vs"] == nil { throw NSError(domain: "novs " + lastErr, code: 1) }
    } else {
      let pd = MTLRenderPipelineDescriptor(); pd.vertexFunction = f; pd.fragmentFunction = dummyFS; pd.colorAttachments[0].pixelFormat = .bgra8Unorm; pd.vertexDescriptor = vdesc(f)
      var refl: MTLRenderPipelineReflection?
      _ = try dev.makeRenderPipelineState(descriptor: pd, options: [.bindingInfo], reflection: &refl)
      bs = refl!.vertexBindings
    }
    r["ok"] = true
    r["bindings"] = bs.map { ["t": tname($0.type), "i": $0.index, "used": $0.isUsed, "name": $0.name, "layout": layout($0)] }
  } catch { r["ok"] = false; r["err"] = "\(error)".prefix(300).description }
  out[n] = String(data: try! JSONSerialization.data(withJSONObject: r), encoding: .utf8)!
}
for o in out { print(o) }
