#!/bin/sh
# SPDX-License-Identifier: MIT
# Build probes.air (the A16 probe module) from probes.metal, beside this script.
# The compiled module is not tracked: it records the build path.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE"
xcrun -sdk macosx metal -c probes.metal -o probes.air
echo "wrote $HERE/probes.air"
