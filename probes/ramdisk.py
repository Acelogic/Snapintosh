# SPDX-License-Identifier: MIT
"""Hash-bound raw APFS media for XNU's md0 and IOKit RAM-image contracts."""
import mmap
from dataclasses import dataclass
import hashlib
from pathlib import Path
import struct


ROOT_HASH_NODE = '/device-tree/chosen/secure-boot-hashes'


@dataclass(frozen=True)
class RootHashSpec:
    """One qualified root image and its raw firmware authentication payload."""
    image_sha256: str
    payload_sha256: str
    payload_bytes: int
    component: str
    component_sha256: str
    property_name: str
    device_class: str
    build_id: str
    boot_uuid: str | None = None
    no_protected_data_recipe: str | None = None
    no_sep_firmware_recipe: str | None = None


@dataclass(frozen=True)
class InstalledRootSpec:
    """Full-install M6: the installed System volume on the virtual ANS2's SSD window.

    The root is not a RAM image: AppleFileSystemDriver selects its APFS volume group from
    /chosen/apfs-preboot-uuid. /chosen/boot-uuid must name the same group: dyld's libignition
    reads it through kern.bootuuid to find the group's directory in Preboot. The System
    volume UUID is a distinct media identity, not that directory name. The forwarded root hash is
    the IPSW's SystemVolume payload, which the M1 manifest checked against the restored image.
    The RAM-disk capability actions (no protected data, no SEP firmware) do not apply: they are
    declared only for the RAM-disk and recovery environments (FULL-INSTALL-DESIGN.md §4)."""
    payload_sha256: str
    payload_bytes: int
    component: str
    component_sha256: str
    property_name: str
    system_uuid: str
    volume_group_uuid: str
    # The virtual board has no working SEP. When set, Apple's own RAM-disk environment recipes
    # (no protected-data access, no SEP firmware load) are applied as for the BaseSystem, so ACM's
    # software path and SEP-dependent services are told the truth instead of waiting forever.
    # A deliberate deviation from FULL-INSTALL-DESIGN.md §4 (which declined them); nothing about
    # signatures, the sealed snapshot or the root hash is relaxed.
    no_protected_data_recipe: str | None = None
    no_sep_firmware_recipe: str | None = None
    # The sealed System volume's snapshot to root from. APFS reads /chosen/root-snapshot-name
    # ("failed to get root-snapshot-name from DT"); without it installed-m6-300s-20260925 panicked
    # "Failed to find the root snapshot" (apfs_vfsops.c:2927). iBoot publishes it; so do we.
    root_snapshot_name: str = ''


def load_installed_root_hash(path, spec):
    """The SystemVolume root-hash payload, bound by the profile (no RAM image to check against)."""
    if spec is None:
        raise ValueError('selected guest has no installed-root contract')
    if not 0 < spec.payload_bytes <= 0x4000:
        raise ValueError('invalid root-hash payload bound')
    with Path(path).open('rb') as stream:
        payload = stream.read(spec.payload_bytes + 1)
    if len(payload) != spec.payload_bytes or hashlib.sha256(payload).hexdigest() != spec.payload_sha256:
        raise ValueError('root-hash payload does not match the installed-root profile')
    return payload


def populate_ramdisk_policy(tree, spec):
    """Apply the selected ephemeral image's audited firmware capability actions.

    The virtual BaseSystem has no provisioned Apple protected-data store.
    Use the shipped no-access recipe; do not synthesize a successful SEP
    initialization or copy the host's private xART records into the guest.
    """
    actions = ((spec.no_protected_data_recipe, 'protected-data-access'),
               (spec.no_sep_firmware_recipe, 'sepfw-load-at-boot'))
    # Validate the entire selected action set before changing either property.
    for recipe, name in actions:
        if recipe is None:
            continue
        expected = {'node_path': b'chosen\0',
                    'property_name': name.encode()+b'\0', 'value': bytes(4)}
        if any(tree.get(recipe, key) != value for key, value in expected.items()):
            raise ValueError(f'RAM disk {name} recipe differs from its audited contract')
    for recipe, name in actions:
        if recipe is not None:
            tree.put('/device-tree/chosen', name, bytes(4))


def load_root_hash(path, media, spec):
    """Bind the raw payload to the selected root image before publishing it.

    Hash matching identifies inputs; the native APFS driver still validates
    the forwarded payload against the mounted filesystem's integrity metadata.
    An IM4P wrapper is not the raw OSData expected by this firmware contract.
    """
    if spec is None:
        raise ValueError('selected guest has no qualified root-hash contract')
    if not 0 < spec.payload_bytes <= 0x4000:
        raise ValueError('invalid root-hash payload bound')
    with Path(path).open('rb') as stream:
        payload = stream.read(spec.payload_bytes+1)
    if len(payload) != spec.payload_bytes or hashlib.sha256(payload).hexdigest() != spec.payload_sha256:
        raise ValueError('root-hash payload does not match the selected guest profile')
    if hashlib.sha256(media).hexdigest() != spec.image_sha256:
        raise ValueError('root image does not match the selected root-hash payload')
    return payload


def load_ramdisk(path, base, end):
    """Return a read-only mapped payload; caller reserves it before avail_start.

    The header check establishes raw-container geometry, not filesystem or
    code-signing trust. UDIF/IM4P/AEA wrappers must be extracted beforehand.
    Keep at least 128 MiB after the media for kernel allocations.
    """
    if base < 0 or base % 0x4000 or end <= base or end > 1 << 36:
        raise ValueError('invalid RAMDisk physical placement')
    with Path(path).open('rb') as stream:
        stream.seek(0,2)
        size=stream.tell()
        stream.seek(0)
        header=stream.read(48)
        if size < 0x4000 or size % 0x4000 or len(header)!=48 or header[32:36]!=b'NXSB':
            raise ValueError('RAMDisk must be a page-aligned raw APFS container')
        block_size,blocks=struct.unpack_from('<IQ',header,36)
        if block_size!=4096 or blocks*block_size!=size:
            raise ValueError('RAMDisk APFS geometry does not match the file')
        if size+0x8000000 > end-base:
            raise ValueError('RAMDisk leaves less than 128 MiB of guest allocator memory')
        # Slices passed to the transport are bounded by its write chunk size;
        # mapping avoids a second multi-gigabyte copy in the host loader.
        return mmap.mmap(stream.fileno(),0,access=mmap.ACCESS_READ)


def root_cmdline(cmdline, mode='md0'):
    if mode not in ('md0', 'iokit'):
        raise ValueError('unknown RAMDisk boot mode')
    if any(word.startswith(('rd=', 'rootdev=', 'boot-uuid=')) for word in cmdline.split()):
        raise ValueError('RAMDisk conflicts with an existing root-device argument')
    return cmdline+' rd=md0' if mode == 'md0' else cmdline
