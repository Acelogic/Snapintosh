# SPDX-License-Identifier: MIT
"""Read-only descriptor density of selected, independently audited shadows."""
import hashlib
import struct


def collect(processes, names, audited_roots, first, allocated, read):
    if not 1 <= len(names) <= 4 or len(set(names)) != len(names):
        raise ValueError('invalid density process selection')
    if (first | allocated) & 4095 or not 0 < first < allocated:
        raise ValueError('invalid density arena bounds')
    roots = {r['root']: r for r in audited_roots}
    if len(roots) != len(audited_roots):
        raise ValueError('duplicate audited roots')
    private = {int(p, 16) for r in audited_roots for p in r['private_table_pages']}
    selected = []
    for name in names:
        matches = [p for p in processes if p['name'] == name]
        if len(matches) != 1:
            raise ValueError('density process is absent or ambiguous')
        process = matches[0]
        root = process.get('user_address_space', {}).get('root')
        if root not in roots:
            raise ValueError('density process has no audited root binding')
        row = roots[root]
        pages = [int(p, 16) for p in row['canonical_table_pages']]
        if (not 1 <= len(pages) <= 1024 or len(set(pages)) != len(pages) or
                int(row['canonical'], 16) not in pages or
                any(p & 4095 or not first <= p <= allocated-4096 or p in private for p in pages)):
            raise ValueError('invalid or aliased density source pages')
        selected.append((process, row, pages))
    cached = {}
    rows = []
    for process, root, pages in selected:
        zero_words = zero_groups = 0
        digest = hashlib.sha256()
        for pa in pages:
            if pa not in cached:
                raw = read(pa, 4096)
                if len(raw) != 4096:
                    raise ValueError('short density table read')
                cached[pa] = raw
            raw = cached[pa];digest.update(struct.pack('<Q', pa));digest.update(raw)
            words = struct.unpack('<512Q', raw)
            zero_words += sum(w == 0 for w in words)
            zero_groups += sum(not any(words[i:i+8]) for i in range(0, 512, 8))
        rows.append(dict(pid=process['pid'], name=process['name'], root=root['root'],
                         canonical=root['canonical'], pages=len(pages), words=len(pages)*512,
                         zero_words=zero_words, groups_of_eight=len(pages)*64,
                         zero_groups_of_eight=zero_groups,
                         zero_group_fraction=zero_groups/(len(pages)*64),
                         address_and_content_sha256=digest.hexdigest()))
    return dict(complete=True, processes=rows, distinct_pages=len(cached), bytes_read=len(cached)*4096,
                boundary='Density of current audited canonical table bytes only, not weighted by '
                         'runtime access frequency. All selected pages are read; any nonzero word '
                         'makes its group nonempty. This does not establish a fast-path speedup.')
