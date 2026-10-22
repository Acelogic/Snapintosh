#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the shader/display guest image offline using a synthetic GPU record."""
from pathlib import Path
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
digest = lambda b: hashlib.sha256(b).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--deployment', type=Path, required=True)
    ap.add_argument('--root-hash', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    helper_path = ROOT/'tools/prepare-adreno-gui-deployment.py'
    spec = importlib.util.spec_from_file_location('gui_deployment', helper_path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    deployment_path = args.deployment.resolve()
    deployment = helper.verify(deployment_path)
    assert deployment['status'] == 'SHADER_DISPLAY_DEPLOYMENT_STAGED_NOT_INSTALLED'
    components_path = Path(deployment['components'])
    assert sha(components_path) == deployment['components_sha256']
    components = helper.verify(components_path)
    assert components['status'] == 'SHADER_DISPLAY_COMPONENTS_BOUND_NOT_INSTALLED'
    assert sha(Path(deployment['monitor'])) == deployment['monitor_sha256']
    sources = {str(p.relative_to(ROOT)): sha(p) for directory in ('probes', 'compat', 'shadow')
        for p in (ROOT/directory).rglob('*') if p.is_file() and p.suffix in ('.py', '.c', '.h', '.S')}
    for p in (Path(__file__), helper_path): sources[str(p.relative_to(ROOT))] = sha(p)
    sys.path.insert(0, str(ROOT/'probes'))
    import adreno
    import xnuboot as xb
    from appledt import DeviceTree
    profile = deployment['guest_profile']
    assert profile == 'j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display'
    firmware = Path(deployment['firmware'])
    xb.configure_guest(profile, directory=firmware)
    assert not xb.check_profile(kernelcache=xb.DEFAULT_KERNELCACHE)
    root_hash = args.root_hash.resolve()
    assert sha(root_hash) == xb.GUEST_PROFILE.installed_root.payload_sha256
    collection = Path(deployment['deployed_collection'])
    assert sha(collection) == deployment['deployed_collection_sha256']
    additions = deployment_path.parent/'trust-additions.json'
    assert sha(additions) == deployment['artifacts_sha256']['trust-additions.json']
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    xb.place(0x8c0000000, guest_span=8192 << 20)
    xb.ADRENO_RECORD = adreno.fixture_record()
    log = io.StringIO()
    with contextlib.redirect_stdout(log):
        built = xb.build(str(xb.DEFAULT_KERNELCACHE), root_hash=str(root_hash),
                         auxkc=str(collection), trust_additions=str(additions))
    (out/'build.log').write_text(log.getvalue())
    tree = built['chunks'][xb.DEVICETREE_PA]
    dt = DeviceTree(tree)
    assert dt.serialize() == tree
    assert dt.nodes['/device-tree/chosen/asmb']['lp-sip0'].value == (2).to_bytes(8, 'little')
    assert adreno.GPU_NODE in dt.nodes and adreno.DART_NODE in dt.nodes
    for capability in ('guest-fence-abi', 'guest-unmap-abi', 'guest-cache-abi', 'guest-fill32-abi', 'guest-ib-abi'):
        assert dt.nodes[adreno.GPU_NODE]['snapintosh,'+capability].value == (1).to_bytes(4, 'little')
    slots = [child for child in dt.children['/device-tree/arm-io']
        if bytes(dt.get(child, 'device_type') or b'').rstrip(b'\0') in
        (b'display-subsystem', b'ext-display-subsystem')]
    assert slots == ['/device-tree/arm-io/disp0']
    for path in ('/device-tree/arm-io/dispext0', '/device-tree/arm-io/dcpext', '/device-tree/arm-io/dcpext-expert'):
        assert not any(n == path or n.startswith(path+'/') for n in dt.nodes)
    trust = xb.trust_cache_spec(additions).load(firmware)
    assert trust == (deployment_path.parent/'trustcache.payload').read_bytes()
    assert digest(trust) == deployment['trust_cache_sha256']
    assert sum(trust in raw for raw in built['chunks'].values()) == 1
    ans = xb.ans_reservation()
    adreno.check_disjoint(xb.ADRENO_RECORD, [(xb.PHYS_BASE, ans[0]+ans[1]-xb.PHYS_BASE)])
    for name, expected in sources.items(): assert sha(ROOT/name) == expected, name
    helper.verify(deployment_path)
    (out/'device-tree.bin').write_bytes(tree)
    (out/'params.bin').write_bytes(built['chunks'][xb.PARAMS_PA])
    result = dict(status='COMPLETE_SHADER_DISPLAY_IMAGE_BUILT_NOT_INSTALLED',
        a16_access=False, guest_executed=False, screen_presented=False, guest_profile=profile,
        sources_sha256=sources, inputs_sha256=deployment['inputs_sha256'],
        deployment=str(deployment_path), deployment_sha256=sha(deployment_path),
        components_sha256=sha(components_path), root_hash=str(root_hash), root_hash_sha256=sha(root_hash),
        firmware=str(firmware), firmware_sha256=xb.GUEST_PROFILE.hashes(firmware),
        monitor=deployment['monitor'], monitor_sha256=deployment['monitor_sha256'],
        context_bytes=components['context_bytes'], framebuffer_slots=slots,
        auxkc_sha256=sha(collection), trust_additions_sha256=sha(additions), trust_cache_sha256=digest(trust),
        chunks=[dict(address=hex(a), bytes=len(b), sha256=digest(b)) for a,b in sorted(built['chunks'].items())],
        upload_bytes=sum(len(b) for b in built['chunks'].values()),
        artifacts_sha256={str(p.relative_to(out)): sha(p) for p in out.rglob('*') if p.is_file()},
        boundary='Complete kernel/collection/trust/device-tree construction with synthetic GPU adoption. No SSD install, physical adoption, A16 shader execution, display swap or desktop.')
    (out/'qualification.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(dict(status=result['status'], upload_bytes=result['upload_bytes'], chunks=len(result['chunks']))))


if __name__ == '__main__':
    main()
