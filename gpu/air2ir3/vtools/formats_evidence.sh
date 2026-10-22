#!/bin/zsh
# SPDX-License-Identifier: MIT
# formats_evidence.sh - regenerate the disassembly behind FORMATS.md section 2 (this Mac's dyld
# shared cache, read-only) with the windowserver-metal-usage tools.  -> results/formats-evidence/
set -e
ROOT=${0:a:h:h}
W=$(python3 -c "import sys; sys.path.insert(0, '$ROOT/tools'); import scrdir; print(scrdir.scratchpad())")/adreno/windowserver-metal-usage
O=$ROOT/results/formats-evidence; mkdir -p $O
cd $W
python3 wsdis.py SkyLight determine_required_pixel_format > $O/SkyLight.determine_required_pixel_format.txt
python3 wsdis.py SkyLight 0x1872a7cf4 8 > $O/SkyLight.SLCADisplay.is_extended_range.txt
python3 wsdis.py SkyLight 0x187282430 12 > $O/SkyLight.SLCADisplay.supports_extended_formats.txt
python3 wsdis.py SkyLight reevaluate_modes 40 > $O/SkyLight.SLCADisplay.reevaluate_modes.head.txt
python3 wsdis.py SkyLight _WSPixelFormatFromIOSurfaceFormat 200 > $O/SkyLight.WSPixelFormatFromIOSurfaceFormat.txt
python3 wsdis.py QuartzCore 0x18ad77644 130 > $O/QuartzCore.IOMFBDisplay.framebuffer_pixel_format.txt
python3 wsdis.py QuartzCore "[CADisplay supportsExtendedColors]" 20 > $O/QuartzCore.CADisplay.supportsExtendedColors.txt
python3 $ROOT/vtools/wsfmtscan.py > $O/SkyLight.WSPixelFormat-call-sites.txt
ls $O
