# SPDX-License-Identifier: MIT
"""Experimental codeless AuxKC for the stock J700 boot framebuffer class.

This serializes loader input, not a loaded service or a signed collection.
The native kernel validates the BootKC identity and defers registration until
kernelmanagerd requests collection loading. No Apple executable is modified.
"""
import copy
import hashlib
import plistlib
import struct
import uuid

PAGE = 0x4000
SPAN = 2 * PAGE
OFFSET = 0x10000
DT_OFFSET = OFFSET + SPAN
NODE = '/device-tree/arm-io/disp0'
MATCH = 'disp0,t8140'
NUB_PARENT = '/device-tree/arm-io'
NUB_NODE = NUB_PARENT + '/snapintosh-boot-display'
NUB_MATCH = 'snapintosh,boot-framebuffer'
KERNEL_SHA256 = 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
HANDOFF_BASE = 0x2d8
HANDOFF_MH = 0x2e0
HANDOFF_END = 0x2e8
BUNDLE_ID = 'org.snapintosh.bootframebuffer'
GRAPHICS_ID = 'com.apple.iokit.IOGraphicsFamily'


def _prelink_info(image):
    if hashlib.sha256(image.data).hexdigest() != KERNEL_SHA256:
        raise ValueError('boot framebuffer AuxKC requires the pinned J700 26A428 kernel')
    for name, va, size, off, length in image.segments:
        if name == '__PRELINK_INFO':
            return plistlib.loads(bytes(image.data[off:off+length]).split(b'\0')[0])
    raise ValueError('kernel has no prelink metadata')


def _personality(info):
    if info.get('CFBundleIdentifier') != BUNDLE_ID or 'CFBundleExecutable' in info:
        raise ValueError('expected the codeless Snapintosh boot framebuffer bundle')
    personalities = info.get('IOKitPersonalities', {})
    expected = {
        'CFBundleIdentifier': GRAPHICS_ID,
        'IOClass': 'IOBootFramebuffer',
        'IOProviderClass': 'AppleARMIODevice',
        'IONameMatch': MATCH,
        # Historical shared-provider experiment; a category does not bypass
        # an existing matching worker blocked inside AppleCLCD2::start().
        'IOMatchCategory': 'SnapintoshBootFramebuffer',
    }
    if personalities != {'SnapintoshBootFramebuffer': expected}:
        raise ValueError('unexpected boot framebuffer matching contract')
    if info.get('OSBundleLibraries') != {GRAPHICS_ID: '1.0.0b1'}:
        raise ValueError('unexpected boot framebuffer library dependency')
    if any(key.startswith('_Prelink') for key in info):
        raise ValueError('bundle already contains prelink metadata')


def build_auxkc(image, info, *, dedicated=False):
    """Build a deterministic 32 KiB MH_FILESET with one codeless dictionary.

    RX header page, followed by RO __PRELINK_INFO. The nonempty RX range is
    required by arm_vm_auxkc_init even though there is no executable kext.
    No fileset entries, relocations, executable entrypoint, or code signature.
    """
    primary = _prelink_info(image)
    _personality(info)
    if type(dedicated) is not bool:
        raise ValueError('dedicated framebuffer provider must be a boolean')
    boot_id = primary.get('_PrelinkKCID')
    if not isinstance(boot_id, bytes) or len(boot_id) != 16:
        raise ValueError('invalid primary collection identity')
    graphics = [k for k in primary['_PrelinkInfoDictionary']
                if k.get('CFBundleIdentifier') == GRAPHICS_ID]
    if len(graphics) != 1 or graphics[0].get('CFBundleVersion') != '600':
        raise ValueError('unexpected IOGraphicsFamily version')
    entry = copy.deepcopy(info)
    if dedicated:
        entry['IOKitPersonalities']['SnapintoshBootFramebuffer']['IONameMatch'] = NUB_MATCH
    entry['_PrelinkBundlePath'] = '/Library/Extensions/SnapintoshBootFramebuffer.kext'
    content = plistlib.dumps(entry, fmt=plistlib.FMT_XML, sort_keys=True)
    digest = hashlib.sha256(b'snapintosh-codeless-auxkc-v1\0' + boot_id + content).digest()
    collection_id = uuid.UUID(bytes=digest[:16], version=5).bytes
    metadata = {
        '_BootKCID': boot_id,
        '_PrelinkKCID': collection_id,
        '_PrelinkInfoDictionary': [entry],
    }
    xml = plistlib.dumps(metadata, fmt=plistlib.FMT_XML, sort_keys=True) + b'\0'
    if len(xml) > PAGE:
        raise ValueError('codeless prelink metadata exceeds its reserved page')

    def segment(name, offset, protection, section=b''):
        return struct.pack('<II16sQQQQiiII', 0x19, 72+len(section), name,
                           offset, PAGE, offset, PAGE,
                           protection, protection, bool(section), 0) + section

    section = struct.pack('<16s16sQQIIIIIIII', b'__info', b'__PRELINK_INFO',
                          PAGE, len(xml), PAGE, 0, 0, 0, 0, 0, 0, 0)
    commands = (segment(b'__TEXT', 0, 5) +
                segment(b'__PRELINK_INFO', PAGE, 1, section) +
                struct.pack('<II16s', 0x1b, 24, collection_id))
    header = struct.pack('<8I', 0xfeedfacf, 0x100000c, 2, 0xc,
                         3, len(commands), 0, 0)
    result = (header + commands).ljust(PAGE, b'\0') + xml.ljust(PAGE, b'\0')
    return result


def admit_provider(tree, *, dedicated=False):
    """Validate the original display identity before either scoped experiment."""
    if tree.get(NODE, 'compatible') != MATCH.encode() + b'\0':
        raise ValueError('boot framebuffer provider identity differs')
    if tree.get(NODE, 'AAPL,boot-display') is not None:
        raise ValueError('boot framebuffer property already exists')
    if dedicated:
        if NUB_PARENT not in tree.nodes or NUB_PARENT not in tree.children:
            raise ValueError('dedicated framebuffer parent is missing')
        if NUB_NODE in tree.nodes or NUB_NODE in tree.children or NUB_NODE in tree.children[NUB_PARENT]:
            raise ValueError('dedicated framebuffer provider already exists')


def kext_info(info, *, dedicated=False):
    """Info.plist for the codeless bundle a kmutil-linked AuxKC carries.

    The same personality build_auxkc serializes, so both collection paths
    publish one matching contract. kmutil adds _Prelink* keys itself.
    """
    _personality(info)
    if type(dedicated) is not bool:
        raise ValueError('dedicated framebuffer provider must be a boolean')
    entry = copy.deepcopy(info)
    if dedicated:
        entry['IOKitPersonalities']['SnapintoshBootFramebuffer']['IONameMatch'] = NUB_MATCH
    return entry


def collection_personality(info, *, dedicated=False):
    return kext_info(info, dedicated=dedicated)['IOKitPersonalities']['SnapintoshBootFramebuffer']


def prepare(tree, image, info, *, dedicated=False):
    # All failures happen before changing the tree.
    admit_provider(tree, dedicated=dedicated)
    payload = build_auxkc(image, info, dedicated=dedicated)
    prepare_tree(tree, dedicated=dedicated)
    return payload


def prepare_tree(tree, *, dedicated=False):
    """The provider-side half: disp0 property or the dedicated nub."""
    admit_provider(tree, dedicated=dedicated)
    if dedicated:
        from appledt import Property
        # No fictitious controller or registers: the driver obtains the real
        # console aperture from PE_Video. This is a virtual display provider.
        props = {'name': b'snapintosh-boot-display\0',
                 'compatible': NUB_MATCH.encode()+b'\0',
                 'device_type': b'display\0', 'AAPL,boot-display': b''}
        tree.nodes[NUB_NODE] = {key: Property(key, value) for key, value in props.items()}
        tree.children[NUB_NODE] = []
        tree.children[NUB_PARENT].append(NUB_NODE)
    else:
        tree.add(NODE, 'AAPL,boot-display', b'')


def handoff_values(handoff_va, image_end):
    """Native auxkc_end also initializes end_kern, so cover the primary KC."""
    base = handoff_va + OFFSET
    if (handoff_va | image_end) & (PAGE-1) or image_end <= base + SPAN:
        raise ValueError('invalid auxiliary/primary collection virtual bounds')
    return base, base, image_end
