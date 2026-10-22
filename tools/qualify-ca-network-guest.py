#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Construct the full guest with restored network startup and installed CA code.

Failure inventory: wrong launch/binary, missing trust, changed monitor/profile,
mixed AuxKC, changed firmware, overlap with GPU arena, and offline success
mistaken for a working desktop. No A16 access and no SSD writes.
"""
from pathlib import Path
import contextlib
import hashlib
import io
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT.parent/'Snapintosh'
RUNTIME = ROOT.parent/'Snapintosh-adreno-sks'
PIPE = ROOT.parent/'Snapintosh-adreno-pipeline'
OUT = ROOT/'build/ca-network-guest-20260928-v1'
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
digest = lambda data: hashlib.sha256(data).hexdigest()
inputs = {}


def bind(path, expected=None):
    path = Path(path)
    actual = sha(path)
    assert expected is None or actual == expected, path
    inputs[str(path)] = actual
    return path


def read(path, expected=None):
    return json.loads(bind(path,expected).read_text())


launch = read(MAIN/'build/installed-metal-ca-3600s-20260928-launch.json',
              '4930edb3f6156957d326058369760b4fb2ba629d8422326c4728bd5eee6acd21')
assert launch['exit_code'] == 9 and launch['finished'] > launch['started']
assert launch['runtime_root'] == launch['observer_root'] == str(RUNTIME)
assert (launch['context_fields'],launch['context_bytes']) == (217,5124736)
for path,value in launch['source_sha256'].items(): bind(path,value)
network_path = ROOT/'build/ca-network-qualification-20260928-v2.json'
network = read(network_path,'0c7936724e05c8ce706ddd9148b72bc060849b1604e8caf2675d8d2e2e7720d3')
assert network['status'] == 'CA_NETWORK_COMBINED_DRIVER_QUALIFIED_NOT_BOOTED'
assert network['linked_collection_personalities_verified']
for path,value in network['inputs_sha256'].items(): bind(path,value)
image = read(PIPE/'build/ca-metal-deploy-20260928/image-v1/qualification.json',
             'd9fb43b433264be82397d373c4de5ca29791c260d793f8b3109e1dda297a6ea6')
for path,value in image['inputs_sha256'].items(): bind(PIPE/path,value)
sys.path.insert(0,str(RUNTIME/'probes'))
import adreno
import xnuboot as xb
from appledt import DeviceTree
profile = launch['guest_profile']
assert profile == 'j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display-sks'
arguments = list(launch['arguments'])
firmware = Path(arguments[arguments.index('--firmware-dir')+1])
additions = bind(arguments[arguments.index('--trust-additions')+1],launch['trust_additions_sha256'])
root_hash = bind(launch['root_hash'],image['root_hash_sha256'])
collection = bind(network['collection'],network['collection_sha256'])
monitor = bind(launch['monitor_path'],launch['monitor_sha256'])
assert launch['monitor_sha256'] == '340bae8fa6cdfc26f65d96003551e79298698ff98b256c25b316f32f3c0ec934'
arguments[arguments.index('--auxkc')+1] = str(collection)
xb.configure_guest(profile,directory=firmware)
assert not xb.check_profile(kernelcache=xb.DEFAULT_KERNELCACHE)
assert xb.GUEST_PROFILE.apfs_without_sep and xb.GUEST_PROFILE.sep_asc.sks_startup
assert sha(root_hash) == xb.GUEST_PROFILE.installed_root.payload_sha256
for name,value in xb.GUEST_PROFILE.hashes(firmware).items():
    assert image['firmware_sha256'][name] == value
OUT.mkdir(exist_ok=False)
xb.place(0x8c0000000,guest_span=8192<<20)
xb.ADRENO_RECORD = adreno.fixture_record()
log = io.StringIO()
with contextlib.redirect_stdout(log):
    built = xb.build(str(xb.DEFAULT_KERNELCACHE),root_hash=str(root_hash),
                     auxkc=str(collection),trust_additions=str(additions))
(OUT/'build.log').write_text(log.getvalue())
tree = built['chunks'][xb.DEVICETREE_PA]
dt = DeviceTree(tree)
assert dt.serialize() == tree
assert dt.nodes['/device-tree/chosen/asmb']['lp-sip0'].value == (2).to_bytes(8,'little')
assert adreno.GPU_NODE in dt.nodes and adreno.DART_NODE in dt.nodes
for capability in ('guest-fence-abi','guest-unmap-abi','guest-cache-abi','guest-fill32-abi','guest-ib-abi'):
    assert dt.nodes[adreno.GPU_NODE]['snapintosh,'+capability].value == (1).to_bytes(4,'little')
slots = [child for child in dt.children['/device-tree/arm-io']
         if bytes(dt.get(child,'device_type') or b'').rstrip(b'\0') in (b'display-subsystem',b'ext-display-subsystem')]
assert slots == ['/device-tree/arm-io/disp0']
trust = xb.trust_cache_spec(additions).load(firmware)
assert digest(trust) == image['trust_cache_sha256']
assert sum(trust in raw for raw in built['chunks'].values()) == 1
ans = xb.ans_reservation()
adreno.check_disjoint(xb.ADRENO_RECORD,[(xb.PHYS_BASE,ans[0]+ans[1]-xb.PHYS_BASE)])
bind(__file__)
for path,value in inputs.items(): assert sha(path) == value, path
(OUT/'device-tree.bin').write_bytes(tree)
(OUT/'params.bin').write_bytes(built['chunks'][xb.PARAMS_PA])
record = dict(status='CA_NETWORK_FULL_GUEST_IMAGE_BUILT_NOT_BOOTED',inputs_sha256=inputs,
              guest_profile=profile,runtime_root=str(RUNTIME),context_bytes=launch['context_bytes'],
              context_fields=launch['context_fields'],flags=launch['build_defines'],
              monitor=dict(path=str(monitor),sha256=sha(monitor)),arguments=arguments,
              collection=str(collection),collection_sha256=sha(collection),kext_sha256=network['kext_sha256'],
              prior_launch=str(MAIN/'build/installed-metal-ca-3600s-20260928-launch.json'),
              network_qualification=str(network_path),trust_additions_sha256=sha(additions),
              trust_cache_sha256=digest(trust),framebuffer_slots=slots,
              chunks=[dict(address=hex(a),bytes=len(b),sha256=digest(b)) for a,b in sorted(built['chunks'].items())],
              upload_bytes=sum(len(b) for b in built['chunks'].values()),
              artifacts_sha256={p.name:sha(p) for p in OUT.iterdir() if p.is_file()},
              hardware_access=False,ssd_writes=False,guest_executed=False,desktop_verified=False,
              boundary='Complete guest image construction with synthetic GPU adoption; existing installed CA plug-in/trust retained, corrected AuxKC supplied by loader')
(OUT/'qualification.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(dict(status=record['status'],output=str(OUT/'qualification.json'),
                      sha256=sha(OUT/'qualification.json'),upload_bytes=record['upload_bytes'])))
