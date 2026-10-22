// SPDX-License-Identifier: MIT
// mtlgold - render a scene (scenes/<name>.json, shared with nirexec) with real Metal on this Mac
// (M3 Max) and write the steady-state frame as the colour attachment's raw bytes (BGRA8 unless the
// scene's "rt" names another format: rgba16f, bgr10_xr, bgra10_xr).  "metallib" is a path relative
// to the tree or "@SkyLight" / "@CoreDisplay" for the OS libraries (no absolute paths in scenes).
//
//   swiftc -O tools/mtlgold.swift -o build/mtlgold
//   build/mtlgold scenes/sl_simple_texture.json out.bgra [--frames 3]
//
// Frames 0..N-1 are rendered as separate command buffers into the same target (clear + draw
// each); the last frame (index >= 2) is written.  Frame 0 is also compared to it and the maximum
// difference is reported (frame-0 results can depend on pipeline compile timing in CA; here each
// command buffer waits, so it should be identical).
import Foundation
import Metal

func fail(_ m: String) -> Never { FileHandle.standardError.write(("mtlgold: " + m + "\n").data(using: .utf8)!); exit(3) }

let args = CommandLine.arguments
guard args.count >= 3 else { fail("usage: mtlgold scene.json out.bgra [--frames N]") }
let scenePath = args[1], outPath = args[2]
var frames = 3
if let i = args.firstIndex(of: "--frames"), i + 1 < args.count { frames = Int(args[i + 1])! }
let root = URL(fileURLWithPath: scenePath).standardizedFileURL.deletingLastPathComponent().deletingLastPathComponent().path
func rel(_ p: String) -> String { p.hasPrefix("/") ? p : root + "/" + p }
let osLibs = ["@SkyLight": "/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/Resources/SkyLightShaders.air64.metallib",
              "@CoreDisplay": "/System/Library/Frameworks/CoreDisplay.framework/Versions/A/Resources/default.metallib"]
func libPath(_ p: String) -> String { osLibs[p] ?? rel(p) }

let scene = try! JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: scenePath))) as! [String: Any]
let W = scene["width"] as! Int, H = scene["height"] as! Int
guard let dev = MTLCreateSystemDefaultDevice() else { fail("no Metal device") }
let queue = dev.makeCommandQueue()!

func bytes(_ o: [String: Any]) -> [UInt8] {
    var v = [UInt8]()
    if let f = o["floats"] as? [NSNumber] { for x in f { var y = x.floatValue; withUnsafeBytes(of: &y) { v += $0 } } }
    if let u = o["uints"] as? [NSNumber] { for x in u { var y = x.uint32Value; withUnsafeBytes(of: &y) { v += $0 } } }
    if let p = o["file"] as? String { v += [UInt8](try! Data(contentsOf: URL(fileURLWithPath: rel(p)))) }
    while v.count % 16 != 0 { v.append(0) }
    return v
}

func function(_ st: [String: Any]) -> MTLFunction {
    let lib = try! dev.makeLibrary(URL: URL(fileURLWithPath: libPath(st["metallib"] as! String)))
    let name = st["function"] as! String
    let fcv = MTLFunctionConstantValues()
    if let fc = st["fc"] as? [String: Any] {
        let f0 = lib.makeFunction(name: name)!
        for (k, v) in fc {
            let idx = Int(k)!
            let vals: [NSNumber] = (v as? [NSNumber]) ?? [v as! NSNumber]
            guard let decl = f0.functionConstantsDictionary.values.first(where: { $0.index == idx }) else { continue }
            switch decl.type {
            case .bool: var b: Bool = vals[0].intValue != 0; fcv.setConstantValue(&b, type: .bool, index: idx)
            case .uchar: var b = UInt8(vals[0].intValue); fcv.setConstantValue(&b, type: .uchar, index: idx)
            case .int: var b = Int32(vals[0].intValue); fcv.setConstantValue(&b, type: .int, index: idx)
            case .uint: var b = UInt32(vals[0].intValue); fcv.setConstantValue(&b, type: .uint, index: idx)
            case .float: var b = vals[0].floatValue; fcv.setConstantValue(&b, type: .float, index: idx)
            default: fail("function-constant type \(decl.type.rawValue) not handled")
            }
        }
    }
    return try! lib.makeFunction(name: name, constantValues: fcv)
}

func pixelFormat(_ s: String) -> MTLPixelFormat {
    switch s { case "rgba8": return .rgba8Unorm; case "bgra8": return .bgra8Unorm; case "r8": return .r8Unorm; case "rg8": return .rg8Unorm
    case "rgba16f": return .rgba16Float; case "rgba32f": return .rgba32Float
    case "bgr10_xr": return .bgr10_xr; case "bgra10_xr": return .bgra10_xr; default: fail("format \(s)") }
}
func bpp(_ s: String) -> Int { switch s { case "r8": return 1; case "rg8": return 2; case "rgba16f", "bgra10_xr": return 8; case "rgba32f": return 16; default: return 4 } }
func vertexFormat(_ s: String) -> MTLVertexFormat {
    switch s { case "float": return .float; case "float2": return .float2; case "float3": return .float3
    case "float4": return .float4; case "uchar4n": return .uchar4Normalized; default: fail("vertex format \(s)") }
}

let vsj = scene["vs"] as! [String: Any], fsj = scene["fs"] as! [String: Any]
let pd = MTLRenderPipelineDescriptor()
pd.vertexFunction = function(vsj); pd.fragmentFunction = function(fsj)
let rtj = (scene["rt"] as? [String: Any]) ?? [:]
let rtFmt = (rtj["format"] as? String) ?? "bgra8", rtBpp = bpp(rtFmt)
pd.colorAttachments[0].pixelFormat = pixelFormat(rtFmt)
if (scene["blend_premul_over"] as? Bool) == true {
    pd.colorAttachments[0].isBlendingEnabled = true
    pd.colorAttachments[0].sourceRGBBlendFactor = .one; pd.colorAttachments[0].sourceAlphaBlendFactor = .one
    pd.colorAttachments[0].destinationRGBBlendFactor = .oneMinusSourceAlpha; pd.colorAttachments[0].destinationAlphaBlendFactor = .oneMinusSourceAlpha
}
if let b = scene["blend"] as? [String: Any], (b["enabled"] as? Int ?? 0) != 0 {
    let ca = pd.colorAttachments[0]!
    ca.isBlendingEnabled = true
    ca.rgbBlendOperation = MTLBlendOperation(rawValue: UInt(b["rgb_op"] as? Int ?? 0))!
    ca.alphaBlendOperation = MTLBlendOperation(rawValue: UInt(b["alpha_op"] as? Int ?? 0))!
    ca.sourceRGBBlendFactor = MTLBlendFactor(rawValue: UInt(b["src_rgb"] as? Int ?? 1))!
    ca.destinationRGBBlendFactor = MTLBlendFactor(rawValue: UInt(b["dst_rgb"] as? Int ?? 0))!
    ca.sourceAlphaBlendFactor = MTLBlendFactor(rawValue: UInt(b["src_alpha"] as? Int ?? 1))!
    ca.destinationAlphaBlendFactor = MTLBlendFactor(rawValue: UInt(b["dst_alpha"] as? Int ?? 0))!
}
let vj = scene["vertex"] as! [String: Any]
let attrs = vj["attributes"] as! [[String: Any]]
if !attrs.isEmpty {
    let vd = MTLVertexDescriptor()
    for a in attrs {
        let i = a["index"] as! Int
        vd.attributes[i].format = vertexFormat(a["format"] as! String)
        vd.attributes[i].offset = a["offset"] as! Int
        vd.attributes[i].bufferIndex = 0
    }
    vd.layouts[0].stride = vj["stride"] as! Int
    pd.vertexDescriptor = vd
}
if (vj["primitive"] as? String) == "point" { pd.inputPrimitiveTopology = .point }
let pso = try! dev.makeRenderPipelineState(descriptor: pd)

let rtd = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: pixelFormat(rtFmt), width: W, height: H, mipmapped: false)
rtd.usage = [.renderTarget, .shaderRead]; rtd.storageMode = .shared
let rt = dev.makeTexture(descriptor: rtd)!

var textures: [(Int, MTLTexture)] = []
for t in (scene["textures"] as? [[String: Any]]) ?? [] {
    let w = t["width"] as! Int, h = t["height"] as! Int, depth = (t["depth"] as? Int) ?? 1
    let td = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: pixelFormat(t["format"] as! String), width: w, height: h, mipmapped: false)
    if (t["type"] as? String) == "3d" { td.textureType = .type3D; td.depth = depth }
    td.usage = [.shaderRead]; td.storageMode = .shared
    let tex = dev.makeTexture(descriptor: td)!
    let d = bytes(["file": t["file"]!]), rowBytes = w * bpp(t["format"] as! String)
    d.withUnsafeBytes { tex.replace(region: MTLRegionMake3D(0, 0, 0, w, h, td.depth), mipmapLevel: 0, slice: 0, withBytes: $0.baseAddress!,
                                    bytesPerRow: rowBytes, bytesPerImage: rowBytes * h) }
    textures.append((t["index"] as! Int, tex))
}
var samplers: [(Int, MTLSamplerState)] = []
for s in (scene["samplers"] as? [[String: Any]]) ?? [] {
    let sd = MTLSamplerDescriptor()
    let lin = (s["filter"] as? String) == "linear"
    sd.minFilter = lin ? .linear : .nearest; sd.magFilter = sd.minFilter
    let a = (s["address"] as? String) ?? "clamp_to_edge"
    let am: MTLSamplerAddressMode = a == "repeat" ? .repeat : a == "clamp_to_zero" ? .clampToZero : a == "mirrored_repeat" ? .mirrorRepeat : .clampToEdge
    sd.sAddressMode = am; sd.tAddressMode = am; sd.rAddressMode = am
    func mode(_ k: String) -> MTLSamplerAddressMode? {
        guard let a = s[k] as? String else { return nil }
        return a == "repeat" ? .repeat : a == "clamp_to_zero" ? .clampToZero : a == "mirrored_repeat" ? .mirrorRepeat : .clampToEdge
    }
    if let m = mode("address_s") { sd.sAddressMode = m }
    if let m = mode("address_t") { sd.tAddressMode = m }
    if let m = mode("address_r") { sd.rAddressMode = m }
    if let f = s["min_filter"] as? String { sd.minFilter = f == "linear" ? .linear : .nearest }
    if let f = s["mag_filter"] as? String { sd.magFilter = f == "linear" ? .linear : .nearest }
    samplers.append((s["index"] as! Int, dev.makeSamplerState(descriptor: sd)!))
}
let bufs = (scene["buffers"] as? [String: Any]) ?? [:]
func bind(_ enc: MTLRenderCommandEncoder, _ stage: String) {
    for b in (bufs[stage] as? [[String: Any]]) ?? [] {
        let d = bytes(b), idx = b["index"] as! Int
        let mb = dev.makeBuffer(bytes: d, length: d.count, options: .storageModeShared)!
        if stage == "vertex" { enc.setVertexBuffer(mb, offset: 0, index: idx) } else { enc.setFragmentBuffer(mb, offset: 0, index: idx) }
    }
}
let vdata = bytes(vj["data"] as! [String: Any])
let vbuf = vdata.isEmpty ? nil : dev.makeBuffer(bytes: vdata, length: vdata.count, options: .storageModeShared)
let clear = (scene["clear"] as? [NSNumber]) ?? [0, 0, 0, 0]

var out = [UInt8](repeating: 0, count: W * H * rtBpp), first = [UInt8]()
let rtInit: [UInt8]? = (rtj["init_file"] as? String).map { [UInt8](try! Data(contentsOf: URL(fileURLWithPath: rel($0)))) }
for f in 0..<frames {
    let rp = MTLRenderPassDescriptor()
    rp.colorAttachments[0].texture = rt; rp.colorAttachments[0].loadAction = .clear; rp.colorAttachments[0].storeAction = .store
    if let ini = rtInit {        // loadAction .load of known contents
        ini.withUnsafeBytes { rt.replace(region: MTLRegionMake2D(0, 0, W, H), mipmapLevel: 0, withBytes: $0.baseAddress!, bytesPerRow: W * rtBpp) }
        rp.colorAttachments[0].loadAction = .load
    }
    rp.colorAttachments[0].clearColor = MTLClearColor(red: clear[0].doubleValue, green: clear[1].doubleValue, blue: clear[2].doubleValue, alpha: clear[3].doubleValue)
    let cb = queue.makeCommandBuffer()!
    let enc = cb.makeRenderCommandEncoder(descriptor: rp)!
    enc.setRenderPipelineState(pso)
    enc.setCullMode(.none)
    if let vb = vbuf, !attrs.isEmpty { enc.setVertexBuffer(vb, offset: 0, index: 0) }
    bind(enc, "vertex"); bind(enc, "fragment")
    for (i, t) in textures { enc.setFragmentTexture(t, index: i) }
    for (i, s) in samplers { enc.setFragmentSamplerState(s, index: i) }
    if let v = scene["viewport"] as? [String: Any] {             // an MTLViewport in pixels
        enc.setViewport(MTLViewport(originX: (v["x"] as! NSNumber).doubleValue, originY: (v["y"] as! NSNumber).doubleValue,
                                    width: (v["w"] as! NSNumber).doubleValue, height: (v["h"] as! NSNumber).doubleValue, znear: 0, zfar: 1))
    }
    let pname = vj["primitive"] as? String
    let prim: MTLPrimitiveType = pname == "triangle_strip" ? .triangleStrip : pname == "point" ? .point : .triangle
    if let ix = vj["indices"] as? [String: Any] {                  // 16-bit indices: vertex_id = index
        let d = bytes(ix)
        let ib = dev.makeBuffer(bytes: d, length: d.count, options: .storageModeShared)!
        enc.drawIndexedPrimitives(type: prim, indexCount: vj["count"] as! Int, indexType: .uint16, indexBuffer: ib, indexBufferOffset: 0)
    } else {
        enc.drawPrimitives(type: prim, vertexStart: 0, vertexCount: vj["count"] as! Int)
    }
    enc.endEncoding()
    cb.commit(); cb.waitUntilCompleted()
    rt.getBytes(&out, bytesPerRow: W * rtBpp, from: MTLRegionMake2D(0, 0, W, H), mipmapLevel: 0)
    if f == 0 { first = out }
}
try! Data(out).write(to: URL(fileURLWithPath: outPath))
var d0 = 0
for i in 0..<out.count { d0 = max(d0, abs(Int(out[i]) - Int(first[i]))) }
print("mtlgold: \(outPath) \(W)x\(H) \(rtFmt) on \(dev.name), frame \(frames - 1) written, max |frame0 - frame\(frames - 1)| = \(d0)")
