#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Node-level difference between two flattened Apple device trees.

    python3 tools/diff-devicetree-nodes.py OLD.bin NEW.bin [--json OUT.json]

Prints removed subtrees (by top-most removed node, with node counts), added
nodes with their properties, and every retained node whose properties or child
order differ (removed/added/changed property names, with sizes). Read only.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'probes'))
from appledt import DeviceTree  # noqa: E402


def tops(paths):
    """The top-most members of a set of node paths."""
    return sorted(p for p in paths if p.rsplit('/', 1)[0] not in paths)


def show(value):
    raw = bytes(value)
    text = raw.rstrip(b'\0')
    if text and all(32 <= c < 127 for c in text):
        return text.decode()
    return raw.hex()


def diff(old, new):
    removed = set(old.nodes) - set(new.nodes)
    added = set(new.nodes) - set(old.nodes)
    changed = {}
    for path in sorted(set(old.nodes) & set(new.nodes)):
        a, b = old.nodes[path], new.nodes[path]
        props = dict(
            removed={k: len(a[k]) for k in a if k not in b},
            added={k: len(b[k]) for k in b if k not in a},
            changed={k: [len(a[k]), len(b[k])] for k in a if k in b and bytes(a[k].value) != bytes(b[k].value)})
        kids_a = [k for k in old.children[path] if k not in removed]
        kids_b = [k for k in new.children[path] if k not in added]
        order = kids_a != kids_b
        if any(props.values()) or order:
            changed[path] = dict(props, child_order_changed=order)
    return dict(
        old_nodes=len(old.nodes), new_nodes=len(new.nodes),
        removed_roots={r: sum(1 for p in removed if p == r or p.startswith(r + '/')) for r in tops(removed)},
        added={p: {k: show(v.value) for k, v in new.nodes[p].items()} for p in sorted(added)},
        added_parents={p: new.children[p.rsplit('/', 1)[0]].index(p) for p in tops(added)},
        changed=changed)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('old', type=Path)
    ap.add_argument('new', type=Path)
    ap.add_argument('--json', type=Path)
    args = ap.parse_args()
    blobs = [p.read_bytes() for p in (args.old, args.new)]
    old, new = (DeviceTree(b) for b in blobs)
    for tree, blob in zip((old, new), blobs):
        assert tree.serialize() == blob, 'tree does not round-trip'
    result = dict(old=str(args.old), old_sha256=hashlib.sha256(blobs[0]).hexdigest(), old_bytes=len(blobs[0]),
                  new=str(args.new), new_sha256=hashlib.sha256(blobs[1]).hexdigest(), new_bytes=len(blobs[1]),
                  **diff(old, new))
    print(f"{result['old_nodes']} -> {result['new_nodes']} nodes, "
          f"{result['old_bytes']} -> {result['new_bytes']} bytes")
    print(f"removed {sum(result['removed_roots'].values())} nodes in {len(result['removed_roots'])} subtrees:")
    for root, count in result['removed_roots'].items():
        print(f'  - {root}  ({count})')
    print(f"added {len(result['added'])} node(s):")
    for path, props in result['added'].items():
        print(f'  + {path}  {props}  (child index {result["added_parents"].get(path)})')
    print(f"retained nodes that differ: {len(result['changed'])}")
    for path, d in result['changed'].items():
        print(f'  ~ {path}  ' + ', '.join(f'{k}={v}' for k, v in d.items() if v))
    if args.json:
        args.json.write_text(json.dumps(result, indent=1) + '\n')


if __name__ == '__main__':
    main()
