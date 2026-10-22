# SPDX-License-Identifier: MIT
# verify6: the sidecar's reflection.function_constants must be valid JSON and the key must recompute from it
import json, os, subprocess, sys
T = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..'))   # fix round 6: this tree
BIN = os.environ.get('BIN') or T + '/build/air2ir3'; sys.path.insert(0, T + '/tools'); import cachekey
H = os.environ.get('SCR') or T + '/scratch/v6fixtures'; os.makedirs(H, exist_ok=True)
SRC = os.path.dirname(os.path.abspath(__file__))
subprocess.run(['xcrun', '-sdk', 'macosx', 'metal', '-c', SRC + '/sidecar_values.metal', '-o', H + '/sidecar_values.air'], check=True)
bad = 0
for c in ('9=4294967295 3=5 4=1', '9=5 3=-2147483648 4=1', '9=3000000001 3=5 4=1', '9=5 3=5 4=nan', '9=5 3=5 4=-inf', '9=5 3=5 4=-0.0', '9=5 3=5 4=0.1'):
    args = [BIN, '--quiet', '--entry', 'f', '--json', H + '/sc.json']
    for t in c.split(): args += ['--fc', t]
    subprocess.run(args + [H + '/sidecar_values.air'], check=True, capture_output=True)
    t = open(H + '/sc.json').read()
    try:
        j = json.loads(t); k = cachekey.key_of_sidecar(j); ok = k == j['key']; why = '' if ok else 'key does not recompute'
    except Exception as e: ok, why = False, 'invalid: ' + str(e)[:60]
    bad += not ok; print('OK ' if ok else 'BAD', c, why)
print('sidecar_check:', bad, 'bad of 7')
