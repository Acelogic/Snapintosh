# SPDX-License-Identifier: MIT
"""Hash-bound boot trust cache for the selected shipped BaseSystem.

This imports Apple's cache, not an allow-all policy or a generated list of
hashes. The root image is authenticated by the caller's RootHashSpec first.
"""
from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
import struct

PAGE = 0x4000
# compat/txm.h TXM_TRUST_MAX_BYTES: BaseSystem's cache is 26,496 bytes, the installed OS's
# static cache (IM4P trst) about 441 KB.
MAX_PAYLOAD = 0x100000


def parse_v2(payload):
    if not 24 <= len(payload) <= MAX_PAYLOAD:
        raise ValueError('trust cache payload length outside supported bounds')
    version, uuid, count = struct.unpack_from('<I16sI', payload)
    if version != 2 or len(payload) != 24 + count * 24:
        raise ValueError('trust cache must be an exact version-2 entry array')
    entries = tuple(payload[off:off + 24] for off in range(24, len(payload), 24))
    if any(a[:20] > b[:20] for a, b in zip(entries, entries[1:])):
        raise ValueError('trust cache entries are not sorted by CDHash')
    return dict(version=version, uuid=uuid.hex(), count=count, entries=entries)


def unwrap_component(component, kind=b'bstc'):
    """kind: the IM4P type, bstc (BaseSystem) or trst (the OS's static trust cache)."""
    """Strictly bound the four required IM4P DER fields before extracting."""
    def element(data, pos):
        if pos + 2 > len(data):
            raise ValueError('truncated trust-cache DER header')
        tag, length = data[pos:pos + 2]
        pos += 2
        if length & 0x80:
            n = length & 0x7f
            if not 1 <= n <= 4 or pos + n > len(data):
                raise ValueError('invalid trust-cache DER length')
            length = int.from_bytes(data[pos:pos + n], 'big')
            pos += n
        end = pos + length
        if end > len(data):
            raise ValueError('truncated trust-cache DER body')
        return tag, data[pos:end], end
    tag, body, end = element(component, 0)
    if tag != 0x30 or end != len(component):
        raise ValueError('trust cache is not one complete IM4P sequence')
    fields, pos = [], 0
    for _ in range(4):
        tag, value, pos = element(body, pos)
        fields.append((tag, value))
    if (fields[0] != (0x16, b'IM4P') or fields[1] != (0x16, kind) or
            fields[2][0] != 0x16 or fields[3][0] != 4):
        raise ValueError('trust-cache IM4P type/field mismatch')
    return fields[3][1]


@dataclass(frozen=True)
class TrustCacheSpec:
    filename: str
    component: str
    member: str
    component_sha256: str
    component_sha384: str
    payload_sha256: str
    entries: int
    im4p_type: str = 'bstc'

    def verify(self, payload):
        if hashlib.sha256(payload).hexdigest() != self.payload_sha256:
            raise ValueError('trust cache does not match the selected guest profile')
        parsed = parse_v2(payload)
        if parsed['count'] != self.entries:
            raise ValueError('trust cache entry count disagrees with profile')
        return payload

    def load(self, directory):
        return self.verify((Path(directory) / self.filename).read_bytes())

    def extract(self, component):
        if (hashlib.sha256(component).hexdigest() != self.component_sha256 or
                hashlib.sha384(component).hexdigest() != self.component_sha384):
            raise ValueError('trust-cache component is not the pinned Apple image')
        return self.verify(unwrap_component(component, self.im4p_type.encode()))


# Trailer after the 20-byte truncated CDHash, as Apple's own entries carry it:
# byte 20 hash type (2 = SHA-256, 1 = SHA-1), byte 21 flags, bytes 22..23 a
# little-endian category (audit-static-trust decodes the same way). The
# stock paravirt Metal plug-in entry ef2b8139... ends 02 00 02 00.
HASH_SHA256 = 2
MAX_APPENDED = 256


def entry(cdhash, *, hash_type=HASH_SHA256, flags=0, category=2):
    """One version-2 entry. A 32-byte SHA-256 CDHash is truncated to 20."""
    if len(cdhash) not in (20, 32) or not isinstance(cdhash, (bytes, bytearray)):
        raise ValueError('CDHash must be 20 bytes or a full 32-byte SHA-256')
    if hash_type not in (1, 2) or not 0 <= flags <= 0xff or not 0 <= category <= 0xffff:
        raise ValueError('invalid trust-cache entry trailer')
    return bytes(cdhash[:20]) + struct.pack('<BBH', hash_type, flags, category)


def augment(base_payload, entries):
    """Base cache plus our entries, sorted by the 20-byte prefix.

    A prefix already present (Apple's or a duplicate of ours) is rejected
    outright: TXM binary-searches on 20 bytes, so two rows sharing a prefix
    make one of them unreachable and the answer depend on the search path.
    The base keeps its UUID; the count is recomputed from the rows.
    """
    parsed = parse_v2(base_payload)
    rows = list(parsed['entries'])
    seen = {row[:20] for row in rows}
    if len(seen) != len(rows):
        raise ValueError('base trust cache already repeats a CDHash prefix')
    added = []
    for row in entries:
        if len(row) != 24 or row[20] not in (1, 2) or row[23]:
            raise ValueError('appended entry is not a version-2 row')
        if row[:20] in seen:
            raise ValueError(f'CDHash {row[:20].hex()} collides with an existing entry')
        seen.add(row[:20])
        added.append(bytes(row))
    if not added:
        raise ValueError('augmented trust cache needs at least one appended entry')
    rows = sorted(rows + added, key=lambda row: row[:20])
    payload = struct.pack('<I16sI', 2, bytes.fromhex(parsed['uuid']), len(rows)) + b''.join(rows)
    parse_v2(payload)
    return payload


@dataclass(frozen=True)
class AugmentedTrustCacheSpec:
    """The pinned Apple cache, verified first, plus appended CDHashes.

    The profile holds the base pin and a bound on how many rows may be
    added; the rows themselves are run input (`bind`). An unbound spec
    refuses to load, so a profile cannot silently boot the plain cache.
    Readback audits call `verify` on the resident bytes, which recomputes
    the exact expected payload rather than trusting its sha256 or count.
    """
    base: TrustCacheSpec
    max_appended: int = 64
    appended: tuple[bytes, ...] = ()

    @property
    def filename(self):
        return self.base.filename

    @property
    def member(self):
        return self.base.member

    @property
    def entries(self):
        return self.base.entries + len(self.appended)

    def bind(self, rows):
        rows = tuple(bytes(row) for row in rows)
        if not 1 <= len(rows) <= min(self.max_appended, MAX_APPENDED):
            raise ValueError('appended trust-cache entries outside the profile bound')
        return replace(self, appended=rows)

    def payload(self, base_payload):
        if not self.appended:
            raise ValueError('augmented trust cache has no bound CDHashes')
        return augment(self.base.verify(base_payload), self.appended)

    def load(self, directory):
        return self.payload((Path(directory) / self.base.filename).read_bytes())

    def verify(self, payload):
        base = struct.pack('<I16sI', 2, payload[4:20], self.base.entries) + b''.join(
            row for row in parse_v2(payload)['entries']
            if row[:20] not in {r[:20] for r in self.appended})
        if bytes(payload) != self.payload(base):
            raise ValueError('trust cache is not the pinned base plus the bound CDHashes')
        return payload


def load_additions(path):
    """JSON rows {"cdhash": hex, "category": int, "name": str}; returns entries."""
    import json
    return addition_entries(json.loads(Path(path).read_text()))


def addition_entries(rows):
    if not isinstance(rows, list):
        raise ValueError('trust additions must be a JSON list')
    result = []
    for row in rows:
        if not isinstance(row, dict) or set(row) - {'cdhash', 'category', 'flags', 'name'}:
            raise ValueError('trust addition has unknown fields')
        digest = bytes.fromhex(row['cdhash'])
        result.append(entry(digest, flags=row.get('flags', 0), category=row.get('category', 2)))
    return result


def reserve_size(payload_size):
    if not payload_size:
        return 0
    if not 24 <= payload_size <= MAX_PAYLOAD:
        raise ValueError('invalid trust-cache reservation size')
    return PAGE + ((payload_size + PAGE - 1) & -PAGE)
