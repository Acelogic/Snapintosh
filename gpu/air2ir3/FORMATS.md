# Pixel formats with no Adreno equivalent

This document covers the Metal pixel formats that the Adreno X2-90 render backend (RB) and texture unit cannot use directly, and how the driver handles each:

- `MTLPixelFormatBGR10_XR` (554)
- `MTLPixelFormatBGRA10_XR` (552)
- 550 (`RGB10A8_2P_XR10`, two planes)
- packed 10-bit YCbCr, 508 and 510

For each format it answers: does WindowServer use it on the SDR internal-panel path, what does the driver do with it, and which test covers it. The findings come from measurements and from reading SkyLight, QuartzCore and CoreDisplay on macOS 27 (26A428); `vtools/formats_evidence.sh` and `vtools/wsfmtscan.py` regenerate the evidence locally from the host's own dyld shared cache.

## 1. Summary

| Format | Used on the SDR internal-panel path? | Render target | Sampled texture | Tests |
|---|---|---|---|---|
| 554 BGR10_XR | only as a sampled client IOSurface (`w30r`, `&w3r`) | shader lowering (class 1): encode on write, decode on framebuffer fetch; blending on the RB where exact, else in the shader | shader lowering, draw-time texture class 1 | `xr_lowering`, `xr_corners`, XR scenes vs Metal |
| 552 BGRA10_XR | only as a sampled client IOSurface (`w40a`, `&w4a`) | shader lowering (class 2), dual-source where a factor reads the source and only colour(0) is written; else blending in the shader | shader lowering, draw-time texture class 2 | as above |
| 550 RGB10A8_2P_XR10 | no (extended-range displays only); a client `b3a8` surface could still arrive | conversion blit (RGBA16Float shadow); class 3 refused | conversion blit to RGBA16Float | `xr_lowering` (refusal) |
| 508 / 510 packed 10-bit YCbCr | no | never a render target; refused | conversion blit to 16-bit planes | `xr_lowering` (refusal) |

"SDR internal-panel path" means the display service reports no extended colours, no EDR headroom and no 10-bit framebuffer capability, and the Metal device answers `supportsExtendedXR10Formats` = NO. On that path WindowServer renders only into BGRA8Unorm, R8Unorm (shadows) and RGBA16Float, all native. XR formats reach the compositor only as textures it samples from other processes' surfaces. WindowServer aborts on a nil texture, so sampling them must work even though they are rare.

## 2. What WindowServer renders into

1. **Formats WindowServer knows.** `_WSPixelFormatGetMTLPixelFormat` maps WSPixelFormat 1..11 to R8 (10), BGRG422 (241), BGRA8 (80), BGR10A2 (94), RGBA16Unorm (110), RGBA16Float (115), RGBA32Float (125), BGR10_XR (554), BGRA10_XR (552) and 550. This is what it can handle, not what it uses.
2. **Window and layer backings.** `determine_required_pixel_format(WSCALayerBacking*)` returns a forced format if set; otherwise RGBA16Float in the CA manager's float mode; otherwise 550 only if the display is extended-range (`SLCADisplay::is_extended_range()`, set from `[CADisplay supportsExtendedColors]`) and supports extended formats; otherwise BGRA8. So 550 backings exist only when the display reports extended colours.
3. **The framebuffer.** `CA::WindowServer::IOMFBDisplay::framebuffer_pixel_format()` picks RGBA16Float with EDR headroom, BGRA8 when the display's 10-bit / wide-colour flag is clear (inferred meaning), and 550 or 552 otherwise. An SDR panel with no EDR headroom gets BGRA8. CoreDisplay's own surfaces map only to 80, 90, 94 and 115 (`CD_MTLPixelFormatForIOSurface`).
4. **No hard-coded XR.** No SkyLight call site passes WSPixelFormat 9, 10 or 11 as an immediate (`vtools/wsfmtscan.py`). The only producers are `determine_required_pixel_format` and `_WSPixelFormatFromIOSurfaceFormat`, which maps a client surface's fourcc (`w30r`/`&w3r` to 554, `w40a`/`&w4a` to 552, `b3a8`/`&b38` to 550).
5. **Clients are kept off XR.** QuartzCore creates XR10 surfaces and accepts XR10 `CAMetalLayer` formats only if `supportsExtendedXR10Formats` is true; the Adreno device answers NO. A client can still create a `w30r` IOSurface by hand, which is why decode on sample is implemented.
6. **Packed 10-bit YCbCr.** 508 and 510 appear only in `_WSMetalFormatFromFourCC` (`p420`, `pf20` to 508; `p422`, `p444`, `pf22`, `pf44` to 510): output formats of Apple's hardware video decoder, which this machine does not have. The device also answers `supportsYCBCRPackedFormats12` = NO.

## 3. The lowering (554 and 552)

Both XR formats store a code n in [0, 1023] per channel, value = (n - 384) / 510, so the range is [-0.7529, 1.2510]. Bit layouts, measured by rendering known colours in Metal and reading the bytes back:

- **554**: one 32-bit word, B in bits 0-9, G 10-19, R 20-29, bits 30-31 set: exactly `BGR10A2Unorm`, so the Adreno views it as `B10G10R10A2_UNORM` with u = n / 1023 (alpha reads 1).
- **552**: four 16-bit words B, G, R, A with the code in the top 10 bits: viewed as `R16G16B16A16_UNORM` with a B,G,R,A swap, u = 64n / 65535.

In both cases u = k·v + c is affine in the Metal value v (554: k = 510/1023, c = 384/1023; 552: k = 510·64/65535, c = 384·64/65535). That makes a shader lowering possible:

- **Decode on sample** (texture class 1 or 2): the texture unit filters the UNORM view and the shader applies v = (u - c) / k. Linear filtering commutes with an affine map, so the result is exact. For 554 alpha is forced to 1. Formats are not pipeline state, so the command stream picks the variant per draw from the bound textures' classes. Border colours for clamp_to_zero must be given in the u-domain, (c, c, c, c).
- **Encode on write** (attachment class 1 or 2): the attachment is bound as the UNORM view; the shader clamps the source to [-384/510, 638/510] (codes 0..1022, Apple's documented range; Metal clamps before blending, measured), and clamps the source alpha to [0, 1] wherever it is a blend factor (on BGRA10_XR the alpha value too).
  - Blending off: the shader writes the exact code, so the store is bit-exact.
  - **RB blending** only where it is exact for every source value: complementary source-alpha pairs, a zero source factor, (one, zero), and min/max (programmed ONE/ONE). The shader writes an offset-corrected source u_s = k·s + c·(1 - F_dst) so that the RB's u-domain blend equals Metal's. Factors that read the source see the encoded value on the RB path, so the shader also writes the raw colour to `[[color(0), index(1)]]` and the RB uses SRC1 factors (dual-source, colour(0) only, no other attachment written).
  - **Shader blending** for everything else, including premultiplied source-over (exact on the RB only for an in-range premultiplied source), additive, subtract, reverse subtract, destination factors, and source colour as an RGB factor (the RB would clamp the dual-source colour to [0, 1] where Metal clamps to the XR range). RB blending is off; the shader reads the destination through framebuffer fetch, decodes, blends exactly as Metal and stores the exact code. BGRA10_XR alpha is clamped to [0, 1] after blending, as Metal does. The cost is one framebuffer read per pixel, on the EDR path only.
  - Still refused: blend-colour and source-1 factors on an add/subtract channel.
  - For 554 alpha is not stored (the command stream clears the alpha write-mask bit).
  - The sidecar's `reflection.rt_lowering[]` gives the command stream `view_format`, `hw_blend`, `dual_source`, `blend_in_shader` and `hw_write_mask_clear`.
- **Framebuffer fetch** of a lowered attachment decodes v = (u - c) / k (WindowServer's `InPlace*` shaders use it).
- **Clears** of a lowered attachment are programmed in the u-domain.

Attachment class, the blend state of lowered attachments, and texture classes are key material (CACHE-FORMAT.md 2.2).

## 4. Conversion-blit and refusal paths

- **550 (two planes)**: would need two render targets or two T# per Metal object. As a render target, render into an RGBA16Float shadow and convert at the store action (RGB encoded with the 554 formula into plane 0, alpha into plane 1), and back at a load action. As a texture, convert to RGBA16Float once per surface seed. The compiler refuses class 3.
- **553 / 555 (XR sRGB)**: Metal blends them in linear space, so the affine trick does not apply; same RGBA16Float shadow path, class 5 refused. Neither appears in WindowServer's tables.
- **508 / 510**: never render targets (class 4 refused). As textures, a compute blit unpacks them into R16 / RG16 planes before the draw.

## 5. Render checks against Metal

`tools/scenes.py` writes 24 XR scenes and `tools/exec.py` renders each with real Metal into a real XR texture (`build/mtlgold`) and on llvmpipe with the lowered NIR into the UNORM view (`build/nirexec`, programming exactly what `rt_lowering` asks for). Results are compared in XR10 codes (`tools/compare.py`). Scenes cover tinted textures over an XR pattern with blending off, premultiplied over, source alpha, erase, max, additive, reverse subtract and destination colour; a negative tint with partial alpha; bilinear sampling; sampling into XR; and framebuffer-fetch source-over. All 24 are within 2 codes, most at 0 or 1; the framebuffer-fetch and sample-to-XR scenes are bit-identical.

Random and targeted blend states (`tools/xrrand.py`, 281 scenes including source alpha outside [0, 1]) and a grid of 834 states (`tools/xr5.py`: every op, factor position and factor, three source alphas, both formats, plus random states) are all within 1 code of Metal.

Known differences and open points:

- An RB-blended BGRA10_XR store is a 16-bit UNORM result whose 6 low bits are generally not zero, where Metal writes zeros; within 1.2 codes. Shader-blended stores are exact.
- To confirm on hardware: the RB component swap for `R16G16B16A16_UNORM` (without it the lowering writes pre-swapped channels, a compiler-only change), custom border colours on XR views, dual-source blending with a lowered attachment, and framebuffer fetch of a lowered attachment in sysmem and GMEM modes.
