# SPDX-License-Identifier: MIT
"""scrdir.py - locate the shared research scratchpad (the directory holding adreno/local-cts and
adreno/windowserver-metal-usage) by walking up from this tree, so the tree works at any depth
(including the clean copy tools/cleanroom.sh makes under scratch/).  AIR2IR3_SCRATCH overrides."""
import os
def scratchpad():
    if os.environ.get('AIR2IR3_SCRATCH'): return os.environ['AIR2IR3_SCRATCH']
    d = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    while d != '/':
        if os.path.isdir(os.path.join(d, 'adreno', 'local-cts')) and os.path.isdir(os.path.join(d, 'adreno', 'windowserver-metal-usage')):
            return d
        d = os.path.dirname(d)
    raise SystemExit('scrdir: adreno/local-cts not found above this tree (set AIR2IR3_SCRATCH)')
