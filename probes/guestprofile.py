# SPDX-License-Identifier: MIT
"""Audited guest identities, separate from host hardware and boot transport.

Registration is deliberate. A matching name or new hash is not evidence that
another image implements the same monitor ABI or uses the same addresses.
"""
from dataclasses import dataclass, replace
import hashlib
from pathlib import Path
from nvram import NVRAMBootSpec
from iommu import DARTBootSpec
from pcie import PCIEResetBootSpec
from deferred import DeferredFunction, DeferredSubtree
from devicemodel import (MCCBootSpec, MCCPTDBootSpec, AICBootSpec, WatchdogBootSpec,
                        GPIOBootSpec, GPIOIdleRX, GPIOIdleCLKREQ, GPIOIdleTX, GPIOIdleI2C, AESKeysBootSpec,
                        SPMIBootSpec, DockBootSpec, DockFIFOBootSpec, AOPTimebaseBootSpec, QSPIBootSpec,
                        DWIStartupSpec, I2CEmptySpec, SEPASCSpec, ANSBootSpec)
from clocktree import CounterClockBootSpec
from sepboot import SEPBootSpec
from seppreload import SEPPreloadSpec
from pmgrboot import PMGRBootSpec, VIRTUAL_ANE_STATES
from soctunerboot import SOCTunerBootSpec
from coresight import CoreSightBootSpec
from chipid import ChipIDBootSpec
from ramdisk import InstalledRootSpec, RootHashSpec
from trustcache import TrustCacheSpec, AugmentedTrustCacheSpec
from adreno import AdrenoSpec
from i2cinput import I2CInputSpec


@dataclass(frozen=True)
class VideoConsoleWitness:
    """The measured vinfo layout and state bytes for one guest binary.

    The first four u32s are height, width, depth, and byte stride; +0x10 is
    the mapped VA and +0x40 the physical base. A different layout requires a
    different witness implementation, not just different addresses.
    """
    vinfo: int
    graphics_mode: int
    acquired: int

    def read(self, peek):
        return dict(height=peek(self.vinfo, 4), width=peek(self.vinfo + 4, 4),
                    depth=peek(self.vinfo + 8, 4), stride=peek(self.vinfo + 12, 4),
                    mapped_va=peek(self.vinfo + 0x10),
                    physical_base=peek(self.vinfo + 0x40),
                    graphics_mode=peek(self.graphics_mode, 1),
                    acquired=peek(self.acquired, 1))


@dataclass(frozen=True)
class GuestProfile:
    name: str
    target: str
    build: str
    abi: str
    firmware_subdir: str
    kernelcache: str
    devicetree: str
    monitors: tuple[str, ...]
    firmware: tuple[tuple[str, str], ...]
    vbar: int
    mair: int
    kernel_hcr: int
    boot_cpu: str
    boot_mpidr: int
    console_node: str
    uat_node: str
    critical_addresses: tuple[tuple[str, int], ...]
    early_heap_va: int
    queue_pointer_base: int
    queue_pointer_bits: int
    queue_pointer_shift: int
    frame_type_info_va: int
    monitor_stack_count: int
    cpu_copy_windows: tuple[int, int]  # compiled base VA, temporary pages per CPU
    txm_policy_pointer_offset: int
    txm_csm_disabled_offset: int
    panic_trap_pc: int
    slide_segments: tuple[tuple[str, str], ...] = ()
    nvram_boot: NVRAMBootSpec | None = None
    dart_boot: DARTBootSpec | None = None
    mcc_boot: MCCBootSpec | None = None
    mcc_ptd_boot: MCCPTDBootSpec | None = None
    aic_boot: AICBootSpec | None = None
    watchdog_boot: WatchdogBootSpec | None = None
    gpio_boot: tuple[GPIOBootSpec, ...] = ()
    aes_keys_boot: AESKeysBootSpec | None = None
    spmi_boot: tuple[SPMIBootSpec, ...] = ()
    dock_boot: DockBootSpec | None = None
    dock_fifo_boot: DockFIFOBootSpec | None = None
    mcc_error_node: str | None = None
    aop_timebase_boot: AOPTimebaseBootSpec | None = None
    sep_boot: SEPBootSpec | None = None
    pmgr_boot: PMGRBootSpec | None = None
    soctuner_boot: SOCTunerBootSpec | None = None
    coresight_boot: tuple[CoreSightBootSpec, ...] = ()
    chip_id_boot: ChipIDBootSpec | None = None
    pcie_reset_boot: tuple[PCIEResetBootSpec, ...] = ()
    video_console: VideoConsoleWitness | None = None
    counter_clock: CounterClockBootSpec | None = None
    qspi_boot: QSPIBootSpec | None = None
    dwi_startup: DWIStartupSpec | None = None
    i2c_empty: I2CEmptySpec | None = None
    sep_asc: SEPASCSpec | None = None
    deferred_subtrees: tuple[DeferredSubtree, ...] = ()
    deferred_functions: tuple[DeferredFunction, ...] = ()
    virtual_counter_hz: int = 0
    root_hash: RootHashSpec | None = None
    trust_cache: TrustCacheSpec | AugmentedTrustCacheSpec | None = None
    acm_software_mode: bool = False
    sep_preload: SEPPreloadSpec | None = None
    boot_framebuffer_aux: bool = False
    boot_framebuffer_nub: bool = False
    # Publish cluster 1 (cpu4/cpu5) as type E like cluster 0. Every vCPU runs
    # on the same Snapdragon cores; the label only selects XNU's Edge policy.
    uniform_cpu_clusters: bool = False
    # Hand off a kmutil-linked collection (probes/auxkc.py) through the one
    # AuxKC slot. With boot_framebuffer_aux it replaces the serialized
    # codeless collection and must carry the same boot framebuffer bundle;
    # without it the collection must not carry that bundle.
    aux_collection_linked: bool = False
    # /chosen/asmb lp-sip0, the local-boot-policy csr_config csr_bootstrap
    # reads as a u64 (any other size panics). None publishes nothing.
    sip_lp_sip0: int | None = None
    # Native APFS development setting for the installed test image's
    # unencrypted Data volume. This does not supply SEP keys or guest writes.
    apfs_without_sep: bool = False
    # Stage 4 (probes/adreno.py): the Adreno node, its virtual DART and the
    # monitor's passthrough/IRQ/SMMU/SMC paths, adopting the GPU q1n1 powered.
    adreno: AdrenoSpec | None = None
    # Full-install M2 (docs/ANS2-M2-20260925.md): the monitor answers Apple's
    # own ANS2 stack on the stock /arm-io/ans node with a RAM-backed disk.
    ans_boot: ANSBootSpec | None = None
    # Full-install M6 (docs/FULL-INSTALL-DESIGN.md): root on the installed System volume.
    installed_root: InstalledRootSpec | None = None
    # Built-in keyboard for the SnapI2CHID kext (probes/i2cinput.py): its GENI
    # page at stage 2 and its /arm-io node. Needs a -DSNAP_I2C_INPUT=1 monitor.
    i2c_input: I2CInputSpec | None = None

    def validate_queue_range(self, base, size):
        """The measured queue encoding shifts a VA, stores a narrow integer,
        then ORs it under a fixed base. Both ends must round-trip unchanged.
        This contract belongs to the guest binary, not the host MMU width.
        """
        bits, shift = self.queue_pointer_bits, self.queue_pointer_shift
        if not (0 < bits <= 64 and 0 <= shift < 64 and bits + shift <= 64):
            raise ValueError('invalid guest queue-pointer format')
        if not (0 <= self.queue_pointer_base < 1 << 64) or self.queue_pointer_base & ((1 << (bits + shift)) - 1):
            raise ValueError('guest queue-pointer base overlaps its packed field')
        align = 1 << shift
        if base < 0 or size <= 0 or base + size > 1 << 64 or base % align:
            raise ValueError('invalid packed-pointer range')
        mask = (1 << self.queue_pointer_bits) - 1
        for va in (base, (base + size - 1) & -align):
            decoded = self.queue_pointer_base | (((va >> self.queue_pointer_shift) & mask)
                                                  << self.queue_pointer_shift)
            if decoded != va:
                raise ValueError(f'guest queue pointer {va:#x} reconstructs as '
                                 f'{decoded:#x}; early heap is outside its encoding')

    def hashes(self, directory, kernelcache=None):
        measured = {}
        for name, _ in self.firmware:
            path = Path(kernelcache) if name == self.kernelcache and kernelcache is not None else Path(directory) / name
            if not path.is_file():
                measured[name] = None
                continue
            digest = hashlib.sha256()
            with path.open('rb') as handle:
                for block in iter(lambda: handle.read(1 << 22), b''):
                    digest.update(block)
            measured[name] = digest.hexdigest()
        return measured

    def validate(self, measured):
        bad = []
        for name, expected in self.firmware:
            got = measured.get(name)
            if got is None:
                bad.append(f'{name}: missing from firmware bundle')
            elif got != expected:
                bad.append(f'{name}: sha256 {got[:16]}..., profile {self.name} '
                           f'was measured against {expected[:16]}...')
        return bad


J700_26A428 = GuestProfile(
    name='j700ap-26A428', target='j700ap / T8140', build='macOS 27 build 26A428',
    abi='sptm-mac-v1', firmware_subdir='j700ap',
    kernelcache='kernelcache.release.mac17p', devicetree='DeviceTree.j700ap',
    monitors=('sptm.t8140.release', 'txm.macosx.release'),
    firmware=(
        ('kernelcache.release.mac17p', 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'),
        ('DeviceTree.j700ap', 'b0fbf661a25626403fa1035ba681d5a7ab8ce13130e2a6d2320d4167255d0a88'),
        ('sptm.t8140.release', 'bd5736d4bd98bceaed2b057ebc09094324bf5149491c2922b329f87db23b1bd0'),
        ('txm.macosx.release', 'b746aaba8d3c0874911a53bf51f9591854783aa6e7b02f25494c2d782eecd246'),
    ),
    # SPTM's common start writes this MAIR_EL1 on every CPU before its C code
    # and XNU run (sptm ...270af5c8); the 0x010000FF at ...270a41ec belongs to
    # the exclave re-entry stub, which always continues into that start.
    # XNU's CACHE_ATTRINDX table, FEAT_XS forms: tools/test-sptm-mair.py.
    vbar=0xFFFFFE000B86C000, mair=0x0C0D00FF01A040FF,
    # SPTM ...270f2150..158 restores this on return to XNU: E2H, RW,
    # TGE. mac17p ...b86e7cc..7e0 checks CurrentEL and TGE before choosing
    # the kernel exception path versus the hypervisor's guest-exit path.
    kernel_hcr=0x488000000,
    boot_cpu='cpu0', boot_mpidr=0x80000000, console_node='dockchannel-uart',
    critical_addresses=(
        ('VBAR_EL1', 0xFFFFFE000B86C000),
        ('SP_EL1 (top)', 0xFFFFFE000C84C000 - 8),
        ('SP_EL0 (top)', 0xFFFFFE000C844000 - 8),
        ('self-location', 0xFFFFFE000700C038),
        ('call-gate flag', 0xFFFFFE0007EC02E8),
        ('handoff publish', 0xFFFFFE0007EC0238),
        ('early global', 0xFFFFFE000C6FC000),
        ('first monitor stub', 0xFFFFFE000C22A930),
    ),
    # vm-page queues store VA>>6 in a u32 and unpack with this base (mac17p
    # ...ba12738..76c). The old heap at ...fed000000000 lost two address bits.
    early_heap_va=0xfffffe0200000000,
    aop_timebase_boot=AOPTimebaseBootSpec('/device-tree/arm-io/aop', b'iop,ascwrap-v6', 3, 24000000),
    sep_boot=SEPBootSpec('/device-tree/arm-io/sep',b'iop-sep,ascwrap-v6',
                         '/device-tree/arm-io/sep/iop-sep-nub',b'iop-nub,sep',0x1a8),
    # All three J700 identities in the pinned 26A428 BuildManifest agree.
    # 26A428 macOS Customer BuildIdentity: J700AP, ApChipID=0x8140, ApBoardID=0x64.
    chip_id_boot=ChipIDBootSpec(0x8140, b'J700AP', b'arm-io,t8140', board_id=0x64),
    pmgr_boot=PMGRBootSpec('/device-tree/arm-io/pmgr',b'pmgr1,t8140',
        '9ae7960cd20eca139de2b38146419d9ad3155af5b9bec98312be9769ca592b33',
        ((0,((0,0),(1,0),(2,0))), (1,((65536,0),)),
         (2,((0,0),(1,0),(2,0),(3,0))), (5,((65536,0),)),
          (8,VIRTUAL_ANE_STATES), (10,((0,0),)), (11,((0,0),))),
        omit_hw_dpe_sha256='8e2b67b6886525dfbe1238a3fb904104bac8d4fad7a28e7b4774b461e0f41de8',
        omit_features=tuple((name,'67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450')
            for name in ('cpu-apsc','soc-tvm','disp-tvm','ave-tvm','gfx-tvm','dcs-tvm',
                         'ppt-thrtl','llc-thrtl','amx-thrtl','cpu-fixed-freq-pll-relock'))),
    soctuner_boot=SOCTunerBootSpec('/device-tree/arm-io/pmgr/soc-tuner',b'soc-tuner,t8030',
        '67abdd721024f0ff4e0b3f4c2fc13bc5bad42d0b7851d456d88d203d15aaa450'),
    coresight_boot=tuple(CoreSightBootSpec(f'/device-tree/cpus/cpu{i}',
        b'apple,sawtooth' if i<4 else b'apple,everest',base,0x300c8)
        for i,base in enumerate((0x210010000,0x210110000,0x210210000,
                                0x210310000,0x211010000,0x211110000))),
    queue_pointer_base=0xfffffe0000000000,
    queue_pointer_bits=32, queue_pointer_shift=6,
    # 144-byte descriptors in the audited SPTM __LATE_CONST. XNU's direct
    # frame-reference queries read the class byte and reference policy here.
    frame_type_info_va=0xfffffff02709e230,
    # TXM bootstrap translates six 16K stack entries unconditionally.
    monitor_stack_count=6,
    cpu_copy_windows=(0xfffffecfffd00000, 4),
    # mac17p ...befd714..738. Older J700 builds used +0x318/+0x190.
    txm_policy_pointer_offset=0x158, txm_csm_disabled_offset=0x2d8,
    uat_node='/device-tree/arm-io/sgx',
    panic_trap_pc=0xfffffe000b8c22a0,
    # SPTM SLIDE_REGION callers in ...ba7b598 reclaim these boot-only
    # segments. Resolve their ranges from the Mach-O, not copied addresses.
    slide_segments=(('com.apple.kernel', '__KLDDATA'),
                    ('com.apple.kernel', '__BOOTDATA'),
                    ('fileset', '__LINKEDIT'), ('fileset', '__PRELINK_INFO')),
    # IODTNVRAM ...c15033c reads bank-size and proxy-data; ...c153bb8
    # parses CHRP v1/v2. An empty v2 bank fills the stock 64K reservation.
    # This is our initial virtual store, not a dump of an Apple device.
    nvram_boot=NVRAMBootSpec('chrp-v2', 0x10000, 2, 0x2000),
    qspi_boot=QSPIBootSpec('/device-tree/arm-io/qspi'),
    dwi_startup=DWIStartupSpec('/device-tree/arm-io/dwi'),
    i2c_empty=I2CEmptySpec('/device-tree/arm-io/i2c2',
        '2ddf6ac8f6378343cae48323e776cb5e73e7c9fc27c3260240d83c36f48e5c2a'),
    sep_asc=SEPASCSpec('/device-tree/arm-io/sep',
        'd03070e3a793ce1552b48542efbaa94dacba6e9fe56bf4ecf7a81f2c92afed02'),
    # First-GUI board has no Apple GPU/ANE/camera/HPM, Broadcom PCIe radio
    # or debug UARTs. Physical q1n1 USB transport is a separate host service.
    # Hashes bind the fully resolved firmware subtrees, after PERST completion.
    # RAM-backed root, display and input are separate contracts. Retain the
    # backed DART provider without these clients; no active DMA is promised.
    deferred_subtrees=(
        DeferredSubtree('/device-tree/arm-io/ane',
            '5a67c8db397be617374181bf22ebfb44d64d681f79f9ab03d4dab34a1f3ff384'),
        DeferredSubtree('/device-tree/arm-io/isp',
            '199a66de4d085a1b136c0c365d5018c5a700e597923c668a2bb5236ac402f856'),
        DeferredSubtree('/device-tree/arm-io/sgx',
            'c3d2298ce03ba36cc365beef6c1232155765a713ec5f43bfb6ecf74b7753a421'),
        DeferredSubtree('/device-tree/arm-io/nub-spmi-a0/hpm0',
            '9b6938bb6f8dc957f489db4e1dec47c075d455208c2d09bb4064676d3945317d'),
        DeferredSubtree('/device-tree/arm-io/nub-spmi-a0/hpm1',
            'a9a0f55fd370e7ffeff48d858b7548bf8af30bb375c96f8eaa2795efb95e161d'),
        DeferredSubtree('/device-tree/amfm-sunrise',
            '6d1e38ba14b1d65a641d84242c1ad84a545e26ee0717a06741f6ca603c5841fc'),
        DeferredSubtree('/device-tree/arm-io/wlan',
            'df20239e64e39fcc165ac911180724d4ac81d2145e3d081094b45bd52ac5c558'),
        DeferredSubtree('/device-tree/arm-io/bluetooth',
            'd7830a30fdaadaec223a644633dc2ccb89dddb57684460e748079eb2c5974d8c'),
        DeferredSubtree('/device-tree/arm-io/apcie',
            '337cbbf647ffd757ae3152586e0d2f3be400b90dd1c90a87a57d9eaa4d6d6f2a'),
        DeferredSubtree('/device-tree/arm-io/apcie0-piodma',
            'a6d6d278196536293a906e1fbccea1afa040e3aafc9208ce97411ad691aacbb0'),
        DeferredSubtree('/device-tree/arm-io/uart4',
            '3bb3b4949fd42b31a6bad9217d35524f62cc3e2b01cfe38f83b2085499a649f1'),
        DeferredSubtree('/device-tree/arm-io/uart5',
            '56cbd0f8a276ffc1da055ade90cf4a77daa9eceb377b663dbe2b155d84be5f6a'),
    ),
    # Withdraw only declarations of services supplied by the absent ANE.
    # Keep CLPC, its other functions and all PMGR frequency metadata.
    # The camera's ANE declarations disappear with the camera subtree.
    deferred_functions=(
        DeferredFunction('/device-tree/arm-io/pmgr/clpc', 'function-ane_perf_ctr',
                         bytes.fromhex('0301000052434e41')),
    ),
    dart_boot=DARTBootSpec('sptm-dart-v1', '/device-tree/arm-io', (b'dart,t8110',),
                           0x4000, apf_abi='t8110-52-v1'),
    mcc_boot=MCCBootSpec('/device-tree/arm-io/mcc', b'mcc,t8140', 1, 4, (31, 36, 35)),
    mcc_error_node='/device-tree/arm-io/error-handler',
    mcc_ptd_boot=MCCPTDBootSpec('/device-tree/arm-io/mcc', b'mcc,t8140',
                               '/device-tree/arm-io/pmp/iop-pmp-nub', 8),
    # Virtual counts: 1,280 slots cover the 287 DT interrupt references
    # (highest 1,260); capacity 4,096 preserves AIC3's 0x4a00 bank stride.
    # Revision 10 selects the audited flat register banks, not the newer
    # per-SOC topology. This is a virtual ABI choice, not a T8140 measurement.
    aic_boot=AICBootSpec('/device-tree/arm-io/aic', b'aic,3', 1280, 0x40000, 0xa),
    counter_clock=CounterClockBootSpec('/device-tree/arm-io', b'arm-io,t8140',
                                      '/device-tree/cpus/cpu0',
                                      '/device-tree/arm-io/wdt', b'wdt,t8101', 0, 4),
    virtual_counter_hz=24000000,
    watchdog_boot=WatchdogBootSpec('/device-tree/arm-io/wdt', b'wdt,t8101',
                                   2, 4, 24000000),
    gpio_boot=(GPIOBootSpec('/device-tree/arm-io/gpio0', 216, 7, tuple(range(7)),
                            (GPIOIdleRX('/device-tree/arm-io/uart4',85,1),
                             GPIOIdleRX('/device-tree/arm-io/uart5',169,2)),
                            (GPIOIdleCLKREQ('/device-tree/arm-io/apcie/pci-bridge0',101,1),),
                            (GPIOIdleTX('/device-tree/arm-io/uart0',80,1),),
                            (GPIOIdleI2C('/device-tree/arm-io/i2c2',164,165,1),
                             GPIOIdleI2C('/device-tree/arm-io/i2c0',170,171,1))),
               GPIOBootSpec('/device-tree/arm-io/mtp-gpio', 10, 7, (4, 5, 6)),
               GPIOBootSpec('/device-tree/arm-io/aop-gpio', 57, 7, (4, 5, 6)),
               GPIOBootSpec('/device-tree/arm-io/nub-gpio', 30, 7, (4, 5, 6)),
               GPIOBootSpec('/device-tree/arm-io/smc-gpio', 6, 7, (5, 6))),
    aes_keys_boot=AESKeysBootSpec('/device-tree/arm-io/aes', 1, (0, 0x40, 0x44, 0x48), 5, True),
    spmi_boot=tuple(SPMIBootSpec('/device-tree/arm-io/'+name, '/device-tree/arm-io/aic')
                    for name in ('nub-spmi0', 'nub-spmi1', 'aop-spmi0', 'nub-spmi-a0')),
    dock_boot=DockBootSpec('/device-tree/dock-connect', 1 << 22),
    dock_fifo_boot=DockFIFOBootSpec('/device-tree/arm-io/dockchannel-mtp',
                                  '/device-tree/arm-io/aic'),
    # Explicit virtual-board wiring, not an assertion about the A16 or every
    # physical J700 SKU. Complete the firmware's provider-only PERST prefix
    # with its existing Tupai sequence, backed by virtual GPIO pin 112.
    pcie_reset_boot=(PCIEResetBootSpec('/device-tree/arm-io/apcie/pci-bridge0',
                                     '/device-tree/arm-io/gpio0', 'tupai', 112),),
    # mac17p initialize_screen at 0xfffffe000ba55740. Operation 2 clears
    # graphics_mode at ...ba55f9c; operation 4 acquires at ...ba55e48 and
    # sets acquired at ...ba55fe0. The later caller ...b9411e0 passes 4.
    video_console=VideoConsoleWitness(0xfffffe000c737d08,
                                      0xfffffe000c816078, 0xfffffe000c81607c),
    # This BaseSystem is presented directly as the active root. Native
    # import_iboot_forwarded_roothash(0) consumes system-volume-auth-blob;
    # its separate argument-1 key belongs to mounting a BaseSystem DMG later.
    root_hash=RootHashSpec(
        image_sha256='7cab6d690cf173c194e846079484b524c09da8909607ac808a4f2b936d272416',
        payload_sha256='e3d407ccea8443db1ae557b5477b6cb7cea9309e7f5760c9658a9d1f7b3b0353',
        payload_bytes=208,
        component='BaseSystemVolume',
        component_sha256='3b645ae3404a4b7687f7edf020fad5318a7a0bd84ac9f3ff47433ea88c3bb5c8',
        property_name='system-volume-auth-blob',
        device_class='j700ap', build_id='26A428',
        # All 13 checksum-valid APSB copies in the hash-bound image agree.
        boot_uuid='A9037730-2821-4F3A-90DC-91BA521BB080',
        # This ephemeral image has no provisioned SEP protected-data store.
        # seputil consumes the chosen u32; missing data defaults to enabled.
        no_protected_data_recipe='/device-tree/osenvironments/darwinos-ramdisk-environment/no-protected-data-access',
        # seputil's own boot-mode branch explicitly skips SEP firmware loading.
        no_sep_firmware_recipe='/device-tree/osenvironments/darwinos-ramdisk-environment/no-sepfw-load-at-boot'),
    trust_cache=TrustCacheSpec(
        filename='basesystem-26A428.trustcache', component='Ap,BaseSystemTrustCache',
        member='Firmware/022-20292-673.dmg.aea.trustcache',
        component_sha256='f9382e7ea7ba858c48b033ab71b7fcfb74db6db53c97edaed1ef20893ceb70bc',
        component_sha384='a200251abc0afa673c9b5653e979533f8f427a870a2f7410f61964f777f0de6d2512c9ccf52db0e170b7e39351664c31',
        payload_sha256='09c90cd2bbd3dec0902341a73720da0bd36ce48427e0c1717875ffc4a9bd4ffd',
        entries=1103),
)

# Experimental software-board policy: the A16 does not implement Apple's
# cluster governor, event counters, or frequency/energy feedback loop. Omit
# its exact provider so the native kernel can exercise its no-controller
# path. This does not claim fixed frequencies, thermal control, or CLPC init.
# All firmware images, CPU topology, PMGR providers and memory ABI are shared.
J700_26A428_NO_CLPC = replace(
    J700_26A428,
    name='j700ap-26A428-no-clpc',
    # The no-SEP RAM-image board uses the shipped ACM software dispatcher.
    # This does not provide real SEP keys, authentication or Touch ID.
    acm_software_mode=True,
    # Bidirectional mailbox/IRQ transport for the virtual SEP service backend.
    # An empty queue remains empty; this does not mark firmware boot complete.
    sep_asc=replace(J700_26A428.sep_asc,reply_transport=True),
    deferred_subtrees=J700_26A428.deferred_subtrees + (
        DeferredSubtree('/device-tree/arm-io/pmgr/clpc',
                        '1fe6f4fa47223bbfd0785e4db33231340898184257e1655ad204950aa148a837'),
        # Hardware video decoding is optional for the software-display board.
        # The native AVD version read reached an unbacked accelerator aperture.
        DeferredSubtree('/device-tree/arm-io/avd',
                        'd4eb61ee06b63100f54717f31ed7b10103145737a9c9b558973d2ed3597c5a80'),
        # The scaler kext remains in the stock collection for its library
        # dependents. Only the absent hardware instance is withdrawn; retain
        # its DART and all DCP/display providers for separate qualification.
        DeferredSubtree('/device-tree/arm-io/scaler0',
                        'ae49797bf337ccfbbb91b8b77dbc7f537fde77b497d4d6a31229427db145181a'),
        # Hardware ProRes acceleration is absent on this software board.
        # Retain its DART; do not manufacture successful accelerator POWERUP.
        DeferredSubtree('/device-tree/arm-io/apr',
                        '6665b7e5141c8b7566b18b1408dd328c61dd1bb2093b23146e9352992ad5404c'),
    ),
    # Its outgoing ANE function disappears together with the whole provider.
    deferred_functions=(),
)

# Experimental native preload entry. The bytes are the extracted, unchanged
# 26A428 firmware payload. ROM execution and SEP services remain unimplemented.
J700_26A428_SEP_PRELOAD = replace(
    J700_26A428_NO_CLPC,
    name='j700ap-26A428-sep-preload',
    sep_asc=replace(J700_26A428_NO_CLPC.sep_asc,rom_status=True,service_bootstrap=True,pnon_recovery=True),
    firmware=J700_26A428_NO_CLPC.firmware + (
        ('sep-firmware.j700.RELEASE', '9d6a9636c5a8bc326c27ab21b250b9309e4835f4c057c58c0b795a8bcabef2a1'),),
    sep_preload=SEPPreloadSpec(
        '/device-tree/arm-io/sep/iop-sep-nub', b'iop-nub,sep',
        'sep-firmware.j700.RELEASE',
        '9d6a9636c5a8bc326c27ab21b250b9309e4835f4c057c58c0b795a8bcabef2a1',
        6144000),
)

# Explicit experiment: add a separate codeless AuxKC and a boot-display
# property on disp0. The stock DCP provider and kernel collection stay intact.
J700_26A428_BOOTFB = replace(
    J700_26A428_SEP_PRELOAD,
    name='j700ap-26A428-bootfb',
    boot_framebuffer_aux=True,
)

# Dedicated virtual provider: native disp0 matching is blocked in DCP startup.
# Keep the earlier profile reproducible for already-captured hardware runs.
J700_26A428_BOOTFB_NUB = replace(
    J700_26A428_BOOTFB,
    name='j700ap-26A428-bootfb-nub',
    boot_framebuffer_nub=True,
)

# The RAM-root/software-display board has no Apple USB host/device backend or
# Type-C DisplayPort PHY. Native clients otherwise wait for the missing PHY
# during startup. Keep their DART, PMGR, the built-in display, and all backing
# device models intact. q1n1's physical debug USB is a separate host service.
# Retain the previous profile for exact comparisons and future USB bring-up.
J700_26A428_BOOTFB_NO_USB = replace(
    J700_26A428_BOOTFB_NUB,
    name='j700ap-26A428-bootfb-no-usb',
    deferred_subtrees=J700_26A428_BOOTFB_NUB.deferred_subtrees + (
        DeferredSubtree('/device-tree/arm-io/usb-drd',
                        '0a8013ab02552f127c161c4f1388e173ccf606b4931a3b5a4a7c67aa35cb2392'),
        DeferredSubtree('/device-tree/arm-io/atc0-dpphy',
                        '7a053a83a7071de1c739f243b9c5c873dfd2173b7c1119f1b1635b738367a425'),
        # Its usb-port phandle targets the withdrawn USB controller's HS port.
        DeferredSubtree('/device-tree/arm-io/i2c2/usb-hub-i2c',
                        '39b345e45f13184e58c8682ea35443f4b0794ec356a280668c09df6480cee007'),
    ),
)

J700_26A428_BOOTFB_RTC = replace(
    J700_26A428_BOOTFB_NO_USB,
    name='j700ap-26A428-bootfb-rtc',
    spmi_boot=tuple(replace(s,rtc=True) if s.node=='/device-tree/arm-io/nub-spmi0' else s
                    for s in J700_26A428_BOOTFB_NO_USB.spmi_boot),
)

J700_26A428_BOOTFB_XARS = replace(
    J700_26A428_BOOTFB_RTC,
    name='j700ap-26A428-bootfb-xars',
    sep_asc=replace(J700_26A428_BOOTFB_RTC.sep_asc,xars_refusal=True),
)

# Without CLPC nothing updates the Edge scheduler's thread-group
# recommendations or edge matrix. Every thread group starts preferring pset0
# (cluster 0, type E) and XNU's default E->P edge forbids migration and steal,
# so cpu4/cpu5 (type P) stay idle for the whole boot. Homogeneous types make
# both edges free_spill. PMGR/CoreSight models still validate the shipped
# topology before the label changes; reg/cluster-id/MPIDR are unchanged.
J700_26A428_BOOTFB_XARS_UNIFORM = replace(
    J700_26A428_BOOTFB_XARS,
    name='j700ap-26A428-bootfb-xars-uniform',
    uniform_cpu_clusters=True,
)

# The software board has no Apple audio hardware: no AOP audio firmware, no
# ADMAC engines, no CS42L83 codec on I2C0. Their drivers already attach at
# boot (IOPAudioController, AudioDMAController/Channels, AppleCS42L83Audio)
# with every register window unbacked, so the first playback/capture -- a
# coreaudiod start is enough -- ends the run on a stage-2 absent-IPA stop,
# and the codec's level-low GPIO104 interrupt could never be admitted.
# Withdraw the whole audio graph together (the codec's codecinput_master
# function and the RX proxy's iommu_handler cross-reference it). The I2C0
# controller, the SIO/AOP IOPs, both DARTs, PMGR and DisplayPort-audio stay.
J700_26A428_BOOTFB_XARS_UNIFORM_NO_AUDIO = replace(
    J700_26A428_BOOTFB_XARS_UNIFORM,
    name='j700ap-26A428-bootfb-xars-uniform-no-audio',
    deferred_subtrees=J700_26A428_BOOTFB_XARS_UNIFORM.deferred_subtrees + (
        DeferredSubtree('/device-tree/arm-io/iop-audio-controller',
                        '0c7a60577708ea2d5daa59e4854a4b56e224c217fae621ce56beace56e4ad20b'),
        DeferredSubtree('/device-tree/arm-io/iop-voicetrigger-controller',
                        'd17b39d2c0e9df9ccd0351a841f03ce078029b614550cac551017d7e4b8725d6'),
        DeferredSubtree('/device-tree/arm-io/admac-base-ns',
                        '9a24bfb10f82f4c0837a52f7562b14847283248725fa7719fcf2149cd51ec9dd'),
        DeferredSubtree('/device-tree/arm-io/admac-leap-ns',
                        'c729011853e485a47b95260a0e718f945cfc23f2abdd09a80d9d2ac579abc92a'),
        DeferredSubtree('/device-tree/arm-io/admac-leap-s',
                        '817a228a4e607e1663c028c6f38efb5b3f538d481ef70c0c3e51fe324f359321'),
        DeferredSubtree('/device-tree/arm-io/admac-leap-s-rx-0-proxy',
                        '2eb9c11f4f3c4d2b26dcc4116a79e1e37883cda0d297ab8605c4affe1689b920'),
        DeferredSubtree('/device-tree/arm-io/audio-shared-dart-proxy',
                        'ef772f1d6be49cbfb5d8f1b1d96068ec21f87aa21ced7a375b58b728eb393f16'),
        DeferredSubtree('/device-tree/arm-io/audio-hp-mic-proxy',
                        'bfe00b120f3105f7ac6ec099810a4d944857d3d9ccddfdf7d8062b7fb7cf36c2'),
        DeferredSubtree('/device-tree/arm-io/i2c0/audio-codec-output',
                        'f713792c5e4f32ba7a7d821f25fbf64c1fb9961d61984fd1e0f4692c7a04edcd'),
    ),
)

# Code-bearing AuxKC: the kmutil output built by build/build-auxkc.py carries
# the generated codeless SnapintoshBootFramebuffer.kext (same nub personality
# as above) and our own kexts, handed off through the one AuxKC slot. XNU
# slides/signs it; the loader only places and maps it. Nothing else differs
# from the profile it derives from, so a run isolates the collection change.
J700_26A428_BOOTFB_AUXKC = replace(
    J700_26A428_BOOTFB_XARS_UNIFORM,
    name='j700ap-26A428-bootfb-auxkc',
    aux_collection_linked=True,
)

# First injection proof: the same board with no boot framebuffer experiment,
# so a kmutil collection holding only our kext (build/auxkc-20260925/
# aux-hello.kc) is the whole AuxKC. The display path is the pre-bootfb one.
J700_26A428_XARS_UNIFORM_AUXKC = replace(
    J700_26A428_BOOTFB_XARS_UNIFORM,
    name='j700ap-26A428-xars-uniform-auxkc',
    boot_framebuffer_aux=False,
    boot_framebuffer_nub=False,
    aux_collection_linked=True,
)

# CSR bits from bsd/sys/csr.h. Only the filesystem restriction is lifted:
# rootless_check_trusted_internal asks csr_check(CSR_ALLOW_UNRESTRICTED_FS)
# before trusting /Library/GPUBundles, which lives on the writable Data tmpfs.
CSR_ALLOW_UNRESTRICTED_FS = 1 << 1

# GPU plug-in stage: the linked AuxKC plus the two host-side trust inputs a
# user-space Metal bundle needs -- SIP's filesystem bit through the local boot
# policy, and the pinned Apple trust cache with our CDHashes appended (bound
# per run from --trust-additions; an unbound spec refuses to load).
J700_26A428_BOOTFB_AUXKC_GPU = replace(
    J700_26A428_BOOTFB_AUXKC,
    name='j700ap-26A428-bootfb-auxkc-gpu',
    sip_lp_sip0=CSR_ALLOW_UNRESTRICTED_FS,
    trust_cache=AugmentedTrustCacheSpec(J700_26A428.trust_cache),
)

# Stage 4: the AuxKC board of the first injection proof plus the Adreno node,
# the virtual DART and the monitor paths (probes/adreno.py). The collection is
# the same aux-hello.kc: no driver matches the node yet (Stage 5), so a run
# isolates the tree, stage-2, IRQ and adoption changes. The -nodart variant is
# the bisection step when dart-adreno is suspected.
J700_26A428_XARS_UNIFORM_AUXKC_ADRENO = replace(
    J700_26A428_XARS_UNIFORM_AUXKC,
    name='j700ap-26A428-xars-uniform-auxkc-adreno',
    adreno=AdrenoSpec(),
)
J700_26A428_XARS_UNIFORM_AUXKC_ADRENO_NODART = replace(
    J700_26A428_XARS_UNIFORM_AUXKC,
    name='j700ap-26A428-xars-uniform-auxkc-adreno-nodart',
    adreno=AdrenoSpec(dart=False),
)

# Full-install M2: the AuxKC board of the first injection proof (still booting
# the hash-bound BaseSystem RAM root) plus the monitor's virtual ANS2 on the
# stock /arm-io/ans and /arm-io/sart-ans nodes, backed by a 64 MiB RAM disk
# (build/build-ans-test-disk-20260925.py: a 4 KiB-LBA GPT around one APFS
# container). Apple's AppleASCWrapV6/RTBuddy/IONVMeFamily drivers are
# unchanged; nothing reaches a physical storage device.
ANS2_M2_DISK_SHA256 = 'b5b632f27f6328573491c90d66988d69ca6da23726d255d703eced303e099538'
J700_26A428_XARS_UNIFORM_AUXKC_ANS = replace(
    J700_26A428_XARS_UNIFORM_AUXKC,
    name='j700ap-26A428-xars-uniform-auxkc-ans',
    ans_boot=ANSBootSpec('/device-tree/arm-io/ans',
                         '9129ab41aeec75812260b9aa9ff396d74ed59a4a2990e8dd04e90c86e7dede94',
                         '/device-tree/arm-io/sart-ans',
                         'da3076ef4ff3d97af922e59fb7afec74f732a25afc8246b2648d2640cf71d9fa',
                         ANS2_M2_DISK_SHA256, 64 << 20),
)

# Full-install M6: the same AuxKC board, booting the installed macOS (M1's configured.img, M5
# provisioned into the M4 partition) read-only from the SSD through the virtual ANS2's window
# (probes/answindow.py, compat/nvme-host.c). No RAM disk: the root is the installed System volume,
# its forwarded root hash the IPSW's SystemVolume payload, its static trust cache the OS's own.
FULL_INSTALL_PARTITION = 'ffea9120-5c2e-47ff-a459-3f645a59654e'
FULL_INSTALL_BYTES = 422668402688
J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED = replace(
    J700_26A428_XARS_UNIFORM_AUXKC,
    name='j700ap-26A428-xars-uniform-auxkc-installed',
    root_hash=None,
    apfs_without_sep=True,
    # Fixed virtual J700 identity from the verified 26A428 signing inputs.
    # Native TXM/Image4 replay checks CPRO and SDOM independently; the raw
    # extracted DT leaves them zero/absent. This does not change security mode.
    chip_id_boot=replace(J700_26A428_XARS_UNIFORM_AUXKC.chip_id_boot,
                        certificate_production_status=True, security_domain=1),
    # Independent refusal services let installed BootPolicy/CPSN calls return
    # unsupported without exposing the recovery OS-type response or inventing
    # nonce/key state. See docs/INSTALLED-PNON-POLICY-20260926.md.
    sep_asc=replace(J700_26A428_XARS_UNIFORM_AUXKC.sep_asc, pnon_recovery=False,
                    xars_refusal=True, pnon_refusal=True),
    trust_cache=TrustCacheSpec(
        filename='os-26A428.trustcache', component='StaticTrustCache',
        member='Firmware/043-70867-635.dmg.aea.trustcache',
        component_sha256='91ed6fbc81cd3eb800a7b96ebd3198e27b4ce1b7c184fb0d9f7f9385c9e51d5f',
        component_sha384='ed765b5912dd36591839407f8d0679e3ec6bad1681414bbaecac11d8213b64728569ce6b77c5b5c85defb950846efb87',
        payload_sha256='6b88077c887eea721ca465d294bee558b58c6e37772032cda72bcfdc82619274',
        entries=18375, im4p_type='trst'),
    installed_root=InstalledRootSpec(
        payload_sha256='b91042a4574bfafc84b2cfa7891f536a0a28f4d62409f45829d1d1a2a3fe9591',
        payload_bytes=208, component='SystemVolume',
        component_sha256='d9e99a574f9ea902b09c828932154e3396634fc5fbe5e0833e17903cef2cf5ff',
        property_name='system-volume-auth-blob',
        system_uuid='82095A97-B662-4DB0-AF09-247BEF3B805B',
        volume_group_uuid='501065D4-E49E-4DDA-B4E7-056CA04D4B90',
        no_protected_data_recipe='/device-tree/osenvironments/darwinos-ramdisk-environment/no-protected-data-access',
        no_sep_firmware_recipe='/device-tree/osenvironments/darwinos-ramdisk-environment/no-sepfw-load-at-boot',
        root_snapshot_name='com.apple.os.update-5203530F8BB20B9DABC5CE76A0FFE87CCC885EE69B8A5488C24B458A7555E3AB'),
    ans_boot=replace(J700_26A428_XARS_UNIFORM_AUXKC_ANS.ans_boot, disk_sha256='',
                     disk_bytes=FULL_INSTALL_BYTES, window=True, window_guid=FULL_INSTALL_PARTITION,
                     window_gpt=('d6a684b1-d2e8-433a-864d-e552f3479e17',
                                 '2bc912d7-6d23-4b3e-b77c-a958c19d8567',
                                 '1760dd8e-36ab-4591-b606-f92d75ff4115')),
)

# Stage 5 on the installed system: retain every installed identity, SEP and
# SSD input; add only the qualified Adreno device/DART/adoption contract.
# A fresh GPU adoption record and a linked Adreno AuxKC are launch inputs,
# not defaults supplied by this profile.
J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO = replace(
    J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED,
    name='j700ap-26A428-xars-uniform-auxkc-installed-adreno',
    adreno=AdrenoSpec(ring_test=False, self_irq=False),
)

# Stage 7 uses the installed Adreno boot unchanged, plus the same explicit
# filesystem policy and bound CDHash extension as the recovery GPU profile.
# Bundle bytes and additions are launch/provisioning inputs, never defaults.
J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL = replace(
    J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO,
    name='j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal',
    sip_lp_sip0=CSR_ALLOW_UNRESTRICTED_FS,
    trust_cache=AugmentedTrustCacheSpec(J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED.trust_cache),
)

# Stage 8 on the Stage 7 board: the AuxKC's AdrenoDisplay (an IOMobileFramebufferLegacy
# child of AdrenoAcceleratorX2) CPU-copies swaps into the GOP panel. Only the external
# display graph is withdrawn. IOMobileFramebuffer.framework (26A428) expects one service
# per /arm-io display-subsystem or ext-display-subsystem node and waits up to 30 s for
# the rest; dispext0's AppleCLCD2 parks in DCPLink::wait_for_service. disp0 stays: its
# AppleCLCD2 never registers (UnifiedPipeline2::start waits for the DCP expert), and with
# no such node left the framework would never enumerate AdrenoDisplay at all. dcpext and
# its expert serve only dispext0 (atc0-dpphy is already withdrawn; dp-audio stays).
J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY = replace(
    J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL,
    name='j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display',
    deferred_subtrees=J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL.deferred_subtrees + (
        DeferredSubtree('/device-tree/arm-io/dispext0',
                        '3b2a7757f3b4481326717aa46a2d262dd6e9fd327cc8846610e741ed4678424a'),
        DeferredSubtree('/device-tree/arm-io/dcpext',
                        '4e36d72151edc577c1e9a09f5e5a77dd8db734a58e983c9416848e09f495a004'),
        DeferredSubtree('/device-tree/arm-io/dcpext-expert',
                        '45ec668374b5244c9ad85eef0b20b73354e51f0f324a45067537f5a0fade86b6'),
    ),
)

J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS = replace(
    J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY,
    name='j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display-sks',
    sep_asc=replace(J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY.sep_asc,
                    sks_startup=True),
)

# IOKit never goes quiet on the -sks board: fifteen driver starts wait forever
# for hardware this machine does not have, so configd's InterfaceNamer times out
# and walks the busy registry before naming en0 (docs/IOKIT-QUIESCE-20260928.md).
# Withdraw each absent device and the declarations that name its services.
# Backing models, DARTs and PMGR tables stay; nothing is reported initialized.
#  - DCP, its expert and DisplayPort audio (Exclave route 0xcf, SIO DMA). disp0
#    and its backlight go too: AppleCLCD2 waits for the expert without a deadline
#    and AppleARMBacklight for IONVRAM. adreno.display_slot keeps the one
#    display-subsystem entry IOMobileFramebuffer.framework counts.
#  - AOP/AOP2 (Exclave routes 0x65/0x69), the AOP SPMI bus with its NFC, and the
#    no-audio board's audio graph including the I2C0 codec.
#  - SMC: its firmware never publishes smc-pmu. Consumers are withdrawn (buttons,
#    temperature sensors, Touch ID) or keep all but that declaration (the PMU,
#    which still supplies the RTC; MTP multi-touch).
#  - AVE0/1 encoders: AVE_HwC::Init waits on a PMGR state change.
#  - The PMU's battery-trap monitor (nub-spmi0/btm) and the four PPM CPMS
#    declarations that name it. Once pmu-main's start returns, the SPMI
#    controller publishes btm; AppleBTM starts, and ApplePPMCPMS's AppleBTM
#    arrival handler configures battery sampling through it. That needs PMU
#    power services the SPMI model does not have, and AppleCotaBTM::configSampling
#    panicked ("unable to config PMU") in generations 64 and 65. Before quiet,
#    btm was never published, so this restores the booted state for BTM.
_NO_AUDIO_SUBTREES = J700_26A428_BOOTFB_XARS_UNIFORM_NO_AUDIO.deferred_subtrees[
    len(J700_26A428_BOOTFB_XARS_UNIFORM.deferred_subtrees):]
J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS_QUIET = replace(
    J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS,
    name='j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display-sks-quiet',
    adreno=replace(J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS.adreno,
                   display_slot=True),
    deferred_subtrees=J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS.deferred_subtrees + (
        DeferredSubtree('/device-tree/arm-io/dcp',
                        '8ffe9ad6d6627c9a463351fca857c4b4f7b23cdbb1d44725244b8a7fca80f465'),
        DeferredSubtree('/device-tree/arm-io/dcp0-expert',
                        'e503c6447beb1416c5bb2ba7315e50439a84ba6c18fe24e02e928329fc6bd845'),
        DeferredSubtree('/device-tree/arm-io/dp-audio0',
                        '9ab2fb9b41c799ce0fc7012b5d33431210a7612e7382660d70fc91f66009d8d5'),
        DeferredSubtree('/device-tree/arm-io/dp-audio1',
                        '9d366d0e533718fefa5865100b7f87736732ab26b579cc8f1e0d84e2545bb012'),
        DeferredSubtree('/device-tree/arm-io/disp0',
                        '368ec098a3b94d65500d9bb07800f333adbdea990dc31e5875622fa80b396fc6'),
        DeferredSubtree('/device-tree/backlight',
                        'cda6890851355b3119cc21ba7c7980ab2a22cb688bd82ad254e18c51b71c0a5b'),
        DeferredSubtree('/device-tree/arm-io/aop',
                        'f0361ec3696fc9d422a3779a6841aaa361f16b7a670f244de0bf060c6bea5e5a'),
        DeferredSubtree('/device-tree/arm-io/aop2',
                        '3cc2605e09992524eda1fc907e526cc86c6948849db0354bbc51622dd1919eaf'),
        DeferredSubtree('/device-tree/arm-io/aop-spmi0',
                        '7650667df47c11afec148ecb9414cacf064d93febda7e2c7ca2586b744d7f2fc'),
    ) + _NO_AUDIO_SUBTREES + (
        DeferredSubtree('/device-tree/arm-io/smc',
                        '4bfee5148606691fe870de1dbba5bc9c6f43d7af66b4f92aaf7d080f9d757d53'),
        DeferredSubtree('/device-tree/arm-io/smctempsensor0',
                        'cc19377b0853a8ae47f84471e18bb0247c9c9691f5342e25865c4aebdf7f12b4'),
        DeferredSubtree('/device-tree/buttons',
                        '4b0ea1a45fffde4fdd46d67810b0688325f7edef803168e36c7d8fa8ab9f63e5'),
        DeferredSubtree('/device-tree/arm-io/:j700_has_mesa_0',
                        '0d81cd1c1aee1a718b41a594af80a577322cd38ffed70cdaee80df661950c443'),
        DeferredSubtree('/device-tree/arm-io/ave',
                        '208818d4a1ae386b436455c8b135de0dd55e0ded5266f5c1c64c7e3e3d3b7321'),
        DeferredSubtree('/device-tree/arm-io/ave1',
                        'ed3fa7346ea7159d0c583363ff6f4ac3d209e085d3875985bdf2525cdf6e0fae'),
        DeferredSubtree('/device-tree/arm-io/nub-spmi0/btm',
                        '5f1fdd99b592330e74a36847c95726d1a1a9b6891e7e1419f2f7ac627ff7af5c'),
    ),
    deferred_functions=J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS.deferred_functions + (
        DeferredFunction('/device-tree/arm-io/nub-spmi0/pmu-main', 'function-external_standby',
                         bytes.fromhex('8a0000005779656b4553424d')),
        DeferredFunction('/device-tree/arm-io/dockchannel-mtp/mtp-transport/multi-touch',
                         'function-afe-reset',
                         bytes.fromhex('8a00000038574b704f4963700000010000001300')),
        DeferredFunction('/device-tree/arm-io/dockchannel-mtp/mtp-transport/multi-touch',
                         'function-ipd-pwr-seq-control', bytes.fromhex('8a0000005779656b50496d70')),
        DeferredFunction('/device-tree/arm-io/pmgr/ppm', 'function-btm-config',
                         bytes.fromhex('a60000004f434d42')),
        DeferredFunction('/device-tree/arm-io/pmgr/ppm', 'function-btm-start',
                         bytes.fromhex('a600000054534d42')),
        DeferredFunction('/device-tree/arm-io/pmgr/ppm', 'function-btm-stop',
                         bytes.fromhex('a600000050534d42')),
        DeferredFunction('/device-tree/arm-io/pmgr/ppm', 'function-btm-vthr',
                         bytes.fromhex('a600000054564d42')),
    ),
)

# cycle.py installed-fresh --input: the quiet board plus the built-in keyboard's
# SnapI2CHID node and GENI page (docs/A16-INPUT-INSTALLED-20261017.md). The AuxKC
# then carries AdrenoX2 and SnapI2CHID, both autoload; the monitor needs
# -DSNAP_I2C_INPUT=1. Nothing else of the quiet board changes.
J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS_QUIET_INPUT = replace(
    J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS_QUIET,
    name='j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display-sks-quiet-input',
    i2c_input=I2CInputSpec(keyboard=True),
)

# installed-fresh --input --input-touchpad: the keyboard and the touchpad (TCPD/ASUF1209 on I2C1). The
# loader refuses it until probes/i2cinput.py TOUCHPAD_QUALIFIED (tools/qualify-a16-touchpad.py on hardware).
J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS_QUIET_INPUT_TOUCHPAD = replace(
    J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS_QUIET_INPUT,
    name='j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display-sks-quiet-input-touchpad',
    i2c_input=I2CInputSpec(keyboard=True, touchpad=True),
)

PROFILES = {p.name: p for p in (J700_26A428, J700_26A428_NO_CLPC,
                               J700_26A428_SEP_PRELOAD, J700_26A428_BOOTFB,
                               J700_26A428_BOOTFB_NUB, J700_26A428_BOOTFB_NO_USB,
                               J700_26A428_BOOTFB_RTC, J700_26A428_BOOTFB_XARS,
                               J700_26A428_BOOTFB_XARS_UNIFORM,
                               J700_26A428_BOOTFB_XARS_UNIFORM_NO_AUDIO,
                               J700_26A428_BOOTFB_AUXKC,
                               J700_26A428_BOOTFB_AUXKC_GPU,
                               J700_26A428_XARS_UNIFORM_AUXKC,
                               J700_26A428_XARS_UNIFORM_AUXKC_ADRENO,
                               J700_26A428_XARS_UNIFORM_AUXKC_ADRENO_NODART,
                               J700_26A428_XARS_UNIFORM_AUXKC_ANS,
                               J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED,
                               J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO,
                               J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL,
                               J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY,
                               J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS,
                               J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS_QUIET,
                               J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS_QUIET_INPUT,
                               J700_26A428_XARS_UNIFORM_AUXKC_INSTALLED_ADRENO_METAL_DISPLAY_SKS_QUIET_INPUT_TOUCHPAD)}


def get_profile(name):
    try:
        return PROFILES[name]
    except KeyError:
        raise ValueError(f'unsupported guest profile {name!r}; audited profiles: '
                         + ', '.join(PROFILES)) from None
