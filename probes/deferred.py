# SPDX-License-Identifier: MIT
"""Describe absent guest peripherals by withdrawing their firmware nodes.

This changes virtual board enumeration, not driver instructions or hardware
status. A deferred device is unavailable; it is never reported as initialized.
"""
from dataclasses import dataclass
import hashlib
import re


@dataclass(frozen=True)
class DeferredSubtree:
    node: str
    sha256: str


@dataclass(frozen=True)
class DeferredFunction:
    node: str
    name: str
    value: bytes


def defer_subtrees(dt, specs, functions=()):
    """Validate the exact generated nodes and provider closure before mutation.

    Firmware function descriptors start with a provider phandle; the remaining
    words are function-specific arguments, such as GPIO pins, not phandles.
    Retain separately backed providers (for example an unused DART) whose
    outgoing references do not depend on the withdrawn consumers.
    """
    roots = [spec.node for spec in specs]
    if len(set(roots)) != len(roots):
        raise ValueError('duplicate deferred subtree')
    removed = set()
    for spec in specs:
        root = spec.node
        if (root == '/device-tree' or not root.startswith('/device-tree/') or
                root not in dt.nodes or not re.fullmatch(r'[0-9a-f]{64}', spec.sha256)):
            raise ValueError('invalid deferred subtree identity')
        if any(root.startswith(other+'/') for other in roots if other != root):
            raise ValueError('overlapping deferred subtrees')
        parent = root.rsplit('/', 1)[0]
        if dt.children.get(parent, []).count(root) != 1:
            raise ValueError('deferred root is not a unique child')
        subtree = {node for node in dt.nodes if node == root or node.startswith(root+'/')}
        for node in subtree:
            children = dt.children.get(node)
            if children is None or len(set(children)) != len(children) or any(
                    child not in subtree or child.rsplit('/', 1)[0] != node for child in children):
                raise ValueError('deferred subtree has invalid children')
            if node != root and dt.children.get(node.rsplit('/', 1)[0], []).count(node) != 1:
                raise ValueError('deferred subtree has an orphan node')
            if any(prop.placeholder for prop in dt.nodes[node].values()):
                raise ValueError('deferred subtree contains unresolved metadata')
        if hashlib.sha256(dt.serialize(root)).hexdigest() != spec.sha256:
            raise ValueError(f'deferred subtree changed: {root}')
        removed.update(subtree)

    phandles = {}
    for node in removed:
        value = dt.get(node, 'AAPL,phandle')
        if value is None:
            continue
        if len(value) != 4 or not any(value) or value in phandles:
            raise ValueError('invalid deferred phandle')
        phandles[value] = node
    withdrawn_functions = set()
    for spec in functions:
        key = (spec.node, spec.name)
        prop = dt.nodes.get(spec.node, {}).get(spec.name)
        if (key in withdrawn_functions or spec.node in removed or
                not spec.name.startswith('function-') or prop is None or
                prop.placeholder or not isinstance(spec.value, bytes) or
                len(spec.value) < 8 or len(spec.value) % 4 or
                spec.value[:4] not in phandles or bytes(prop.value) != spec.value):
            raise ValueError('invalid deferred function declaration')
        withdrawn_functions.add(key)
    for node, props in dt.nodes.items():
        if node in removed:
            continue
        if dt.get(node, 'AAPL,phandle') in phandles:
            raise ValueError('deferred phandle aliases a retained node')
        for name, prop in props.items():
            if (node, name) in withdrawn_functions:
                continue
            provider = (name.startswith('function-') or name.endswith('-parent') or
                        name.endswith('-phandle') or name in
                        ('msi-parent-controller', 'amfm-managed-port-control', 'usb-port'))
            if provider and bytes(prop.value[:4]) in phandles:
                raise ValueError(f'{node}:{name} still references a deferred provider')

    # All validation precedes commit. Backing models remain available to
    # their retained providers; no controller/interrupt state is fabricated.
    for node, name in withdrawn_functions:
        del dt.nodes[node][name]
    for root in roots:
        dt.children[root.rsplit('/', 1)[0]].remove(root)
    for node in removed:
        del dt.children[node]
        del dt.nodes[node]
    return tuple(sorted(removed))
