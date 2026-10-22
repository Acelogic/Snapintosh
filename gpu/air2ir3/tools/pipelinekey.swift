// SPDX-License-Identifier: MIT
// pipelinekey - build REAL MTLRenderPipelineDescriptors on this Mac and derive the air2ir3 cache keys
// from the descriptor objects, the way the Metal plug-in will (CACHE-FORMAT.md 2 and 4; third
// implementation of the key after tools/cachekey.py and the C library).
//
// stdin, one JSON object per line:
//   {"id", "metallib": "@SkyLight"|"@CoreDisplay"|path, "vertex": name, "fragment": name,
//    "vertex_air_hash", "fragment_air_hash", "vs_constants": {name: [v..]}, "fs_constants": {...},
//    "attachments": [{"format": MTLPixelFormat, "blend": {enabled, rgb_op, alpha_op, src_rgb, dst_rgb, src_alpha, dst_alpha}}],
//    "sample_count": n}
// stdout, one line each: {"id", "ok", "err"?, "vs_key", "fs_key", "vs_key_safe", "fs_key_safe", "fs_classes", "fs_formats", "sample_count"}
// The pipeline state is actually created (makeRenderPipelineState) so every descriptor is one Metal
// accepts.  Keys come from what the descriptor reports back (pixelFormat, blending,
// function name/type, functionConstantsDictionary for the declared constants and their MTLDataType);
// the constant VALUES are the ones handed to MTLFunctionConstantValues (the plug-in receives them
// with the specialisation request).
import CryptoKit
import Foundation
import Metal

let dev = MTLCreateSystemDefaultDevice()!
let osLibs = ["@SkyLight": "/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/SkyLightShaders.air64.metallib",
              "@CoreDisplay": "/System/Library/Frameworks/CoreDisplay.framework/Versions/A/Resources/default.metallib"]
var libs: [String: MTLLibrary] = [:]
func lib(_ p: String) throws -> MTLLibrary {
  if let l = libs[p] { return l }
  let l = try dev.makeLibrary(URL: URL(fileURLWithPath: osLibs[p] ?? p)); libs[p] = l; return l
}
var curLib = ""
let CHIP: UInt32 = 0x44070041, FORMAT: UInt32 = 5, ABI: UInt32 = 6   // format 5 (fix round 6: FC values exact in their declared type; same layout) + ABI v6 (UBO indices < 16)

func formatClass(_ f: MTLPixelFormat) -> UInt8 {
  switch f.rawValue { case 554: return 1; case 552: return 2; case 550, 551: return 3; case 508, 510: return 4; case 553, 555: return 5; default: return 0 }
}
// bytes of one constant value in its MTLDataType (CACHE-FORMAT.md 2.1)
func valueBytes(_ t: MTLDataType, _ vals: [Double]) -> [UInt8]? {
  var out = [UInt8]()
  func put<T>(_ x: T) { var y = x; withUnsafeBytes(of: &y) { out += $0 } }
  let (base, n): (String, Int)
  switch t {
  case .bool: (base, n) = ("b", 1); case .bool2: (base, n) = ("b", 2); case .bool3: (base, n) = ("b", 3); case .bool4: (base, n) = ("b", 4)
  case .uchar: (base, n) = ("u8", 1); case .uchar2: (base, n) = ("u8", 2); case .uchar3: (base, n) = ("u8", 3); case .uchar4: (base, n) = ("u8", 4)
  case .char: (base, n) = ("i8", 1); case .ushort: (base, n) = ("u16", 1); case .short: (base, n) = ("i16", 1)
  case .uint: (base, n) = ("u32", 1); case .uint2: (base, n) = ("u32", 2); case .uint4: (base, n) = ("u32", 4)
  case .int: (base, n) = ("i32", 1); case .int2: (base, n) = ("i32", 2); case .int4: (base, n) = ("i32", 4)
  case .float: (base, n) = ("f32", 1); case .float2: (base, n) = ("f32", 2); case .float3: (base, n) = ("f32", 3); case .float4: (base, n) = ("f32", 4)
  case .half: (base, n) = ("f16", 1); case .half2: (base, n) = ("f16", 2); case .half4: (base, n) = ("f16", 4)
  default: return nil
  }
  for k in 0..<n {
    let v = k < vals.count ? vals[k] : (vals.first ?? 0)
    switch base { case "b": put(UInt8(v != 0 ? 1 : 0)); case "u8": put(UInt8(v)); case "i8": put(Int8(v)); case "u16": put(UInt16(v)); case "i16": put(Int16(v))
    case "u32": put(UInt32(v)); case "i32": put(Int32(v)); case "f32": put(Float(v)); default: put(Float16(v)) }
  }
  return out
}
func setConst(_ fcv: MTLFunctionConstantValues, _ c: MTLFunctionConstant, _ vals: [Double]) throws {
  guard var b = valueBytes(c.type, vals) else { throw NSError(domain: "constant type \(c.type.rawValue)", code: 1) }
  b.withUnsafeMutableBytes { fcv.setConstantValue($0.baseAddress!, type: c.type, withName: c.name) }
}
func makeFunction(_ l: MTLLibrary, _ name: String, _ consts: [String: [Double]]) throws -> MTLFunction {
  guard let f0 = l.makeFunction(name: name) else { throw NSError(domain: "no function \(name)", code: 2) }
  let fcv = MTLFunctionConstantValues()
  for (n, v) in consts { guard let c = f0.functionConstantsDictionary[n] else { continue }; try setConst(fcv, c, v) }
  return try l.makeFunction(name: name, constantValues: fcv)
}
func le32(_ v: UInt32) -> [UInt8] { withUnsafeBytes(of: v.littleEndian) { Array($0) } }
func le16(_ v: UInt16) -> [UInt8] { withUnsafeBytes(of: v.littleEndian) { Array($0) } }
func hex(_ s: String) -> [UInt8] { var o = [UInt8](); var i = s.startIndex
  while i < s.endIndex { let j = s.index(i, offsetBy: 2); o.append(UInt8(s[i..<j], radix: 16)!); i = j }; return o }

// CACHE-FORMAT.md section 2, from the descriptor's view of one function
func key(airHash: String, fn: MTLFunction, consts: [String: [Double]], pd: MTLRenderPipelineDescriptor?, safe: Bool = false) throws -> String {
  var m = Array("AIR2IR3-CACHE-KEY".utf8) + [0]
  m += le32(FORMAT) + le32(ABI) + le32(CHIP) + hex(airHash)
  let stage: UInt32 = fn.functionType == .vertex ? 1 : fn.functionType == .fragment ? 2 : 3
  m += le32(stage)
  let nm = Array(fn.name.utf8); m += le32(UInt32(nm.count)) + nm
  // declared constants come from the unspecialised function (a specialised MTLFunction lists none);
  // the plug-in reads the same list from the AIR's !air.function_constants
  let decl = (try lib(curLib).makeFunction(name: fn.name)!).functionConstantsDictionary.values.sorted { $0.index < $1.index }
  m += le32(UInt32(decl.count))
  for c in decl {
    var vb = [UInt8]()
    if let v = consts[c.name] { guard let b = valueBytes(c.type, v) else { throw NSError(domain: "type", code: 3) }; vb = b }
    m += le16(UInt16(c.index)) + le16(UInt16(c.type.rawValue)) + [consts[c.name] != nil ? 1 : 0, 0] + le16(UInt16(vb.count)) + vb
  }
  let frag = stage == 2
  var cls = [UInt8](repeating: 0, count: 8)
  if frag, let pd = pd { for i in 0..<8 { cls[i] = formatClass(pd.colorAttachments[i].pixelFormat) } }
  m += le32(8) + cls
  if frag, let pd = pd {
    for i in 0..<8 where cls[i] != 0 {
      let ca = pd.colorAttachments[i]!
      if ca.isBlendingEnabled {
        m += [1, UInt8(ca.rgbBlendOperation.rawValue), UInt8(ca.alphaBlendOperation.rawValue), UInt8(ca.sourceRGBBlendFactor.rawValue),
              UInt8(ca.destinationRGBBlendFactor.rawValue), UInt8(ca.sourceAlphaBlendFactor.rawValue), UInt8(ca.destinationAlphaBlendFactor.rawValue)]
      } else { m += [UInt8](repeating: 0, count: 7) }
    }
  }
  m += le32(16) + [UInt8](repeating: 0, count: 16)          // draw-time texture classes: native textures
  m += [safe ? 1 : 0]                                       // format 3: safe_constlen (the sample count is not key material)
  return SHA256.hash(data: m).map { String(format: "%02x", $0) }.joined()
}

while let line = readLine() {
  let j = try! JSONSerialization.jsonObject(with: line.data(using: .utf8)!) as! [String: Any]
  var r: [String: Any] = ["id": j["id"]!]
  do {
    curLib = j["metallib"] as! String
    let l = try lib(curLib)
    let dict = { (k: String) -> [String: [Double]] in ((j[k] as? [String: [NSNumber]]) ?? [:]).mapValues { $0.map { $0.doubleValue } } }
    let vsc = dict("vs_constants"), fsc = dict("fs_constants")
    let vf = try makeFunction(l, j["vertex"] as! String, vsc), ff = try makeFunction(l, j["fragment"] as! String, fsc)
    let pd = MTLRenderPipelineDescriptor()
    pd.vertexFunction = vf; pd.fragmentFunction = ff
    pd.rasterSampleCount = (j["sample_count"] as? Int) ?? 1
    for (i, a) in ((j["attachments"] as? [[String: Any]]) ?? []).enumerated() {
      pd.colorAttachments[i].pixelFormat = MTLPixelFormat(rawValue: UInt(a["format"] as! Int))!
      if let b = a["blend"] as? [String: Int], (b["enabled"] ?? 0) != 0 {
        let ca = pd.colorAttachments[i]!
        ca.isBlendingEnabled = true
        ca.rgbBlendOperation = MTLBlendOperation(rawValue: UInt(b["rgb_op"] ?? 0))!; ca.alphaBlendOperation = MTLBlendOperation(rawValue: UInt(b["alpha_op"] ?? 0))!
        ca.sourceRGBBlendFactor = MTLBlendFactor(rawValue: UInt(b["src_rgb"] ?? 1))!; ca.destinationRGBBlendFactor = MTLBlendFactor(rawValue: UInt(b["dst_rgb"] ?? 0))!
        ca.sourceAlphaBlendFactor = MTLBlendFactor(rawValue: UInt(b["src_alpha"] ?? 1))!; ca.destinationAlphaBlendFactor = MTLBlendFactor(rawValue: UInt(b["dst_alpha"] ?? 0))!
      }
    }
    if let vd = j["vertex_descriptor_from_function"] as? Bool, vd, let va = vf.vertexAttributes, !va.isEmpty {
      let d = MTLVertexDescriptor(); var off = 0
      for a in va where a.isActive { d.attributes[a.attributeIndex].format = .float4; d.attributes[a.attributeIndex].offset = off
        d.attributes[a.attributeIndex].bufferIndex = 30; off += 16 }
      d.layouts[30].stride = max(off, 16); pd.vertexDescriptor = d
    }
    _ = try dev.makeRenderPipelineState(descriptor: pd)          // Metal accepts this descriptor
    r["vs_key"] = try key(airHash: j["vertex_air_hash"] as! String, fn: pd.vertexFunction!, consts: vsc, pd: nil)
    r["fs_key"] = try key(airHash: j["fragment_air_hash"] as! String, fn: pd.fragmentFunction!, consts: fsc, pd: pd)
    r["vs_key_safe"] = try key(airHash: j["vertex_air_hash"] as! String, fn: pd.vertexFunction!, consts: vsc, pd: nil, safe: true)
    r["fs_key_safe"] = try key(airHash: j["fragment_air_hash"] as! String, fn: pd.fragmentFunction!, consts: fsc, pd: pd, safe: true)
    r["sample_count"] = pd.rasterSampleCount
    r["fs_classes"] = (0..<8).map { Int(formatClass(pd.colorAttachments[$0].pixelFormat)) }
    r["fs_formats"] = (0..<8).map { Int(pd.colorAttachments[$0].pixelFormat.rawValue) }   // ABI v5: requires_no_attachment check
    r["ok"] = true
  } catch { r["ok"] = false; r["err"] = "\(error)".prefix(300).description }
  print(String(data: try! JSONSerialization.data(withJSONObject: r), encoding: .utf8)!)
}
