#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline ABI declaration experiment; never installed or instantiated.

Failure inventory before implementation:
* wrong KDK/architecture, inheritance, class allocation size or vtable length;
* shifted overrides, unresolved pure methods or wrong authenticated pointer;
* semantic return types/request layouts mistaken for verified call contracts.
The last item remains a runtime prohibition even when all PAC checks pass.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from evidence_guard import start_phase, write_new_bytes, write_new_text
ROOT = Path(__file__).resolve().parents[4]
s = importlib.util.spec_from_file_location('interface_common', ROOT/'tools/gen-iomfb-header.py')
c = importlib.util.module_from_spec(s)
sys.modules[s.name] = c
s.loader.exec_module(c)

CHAIN = [
    ('IOSkywalkInterface', 'IOService', 0xb0, 288, 'IOSkywalkFamily'),
    ('IOSkywalkNetworkInterface', 'IOSkywalkInterface', 0xe0, 344, 'IOSkywalkFamily'),
    ('IOSkywalkEthernetInterface', 'IOSkywalkNetworkInterface', 0x120, 364, 'IOSkywalkFamily'),
    ('IO80211SkywalkInterface', 'IOSkywalkEthernetInterface', 0x128, 474, 'IO80211Family'),
    ('IO80211InfraInterface', 'IO80211SkywalkInterface', 0x130, 483, 'IO80211Family'),
    ('IO80211InfraProtocol', 'IO80211InfraInterface', 0x130, 683, 'IO80211Family'),
]
SDK_RETURN = {
    'free': 'void', 'init': 'bool', 'start': 'bool', 'stop': 'void',
    'willTerminate': 'bool', 'didTerminate': 'bool', 'handleOpen': 'bool',
    'handleClose': 'void', 'handleIsOpen': 'bool', 'joinPMtree': 'void',
    'setAggressiveness': 'IOReturn', 'newUserClient': 'IOReturn',
    'configureReport': 'IOReturn', 'updateReport': 'IOReturn',
    'setProperties': 'IOReturn', 'message': 'IOReturn',
    'registerService': 'void', 'terminate': 'bool', 'attach': 'bool',
    'detach': 'void', 'getWorkLoop': 'IOWorkLoop *',
    'stringFromReturn': 'const char *',
    'maxCapabilityForDomainState': 'unsigned long',
    'initialPowerStateForDomainState': 'unsigned long',
}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--references', type=Path, required=True)
    parser.add_argument('--kdk', type=Path, required=True)
    args = parser.parse_args()
    HERE, KDK = args.out.resolve(), args.kdk.resolve()
    start_phase(HERE, 'generation', [
        'IOSkywalkFamily.arm64e','IO80211Family.arm64e','AppleBCMWLANCore.arm64e',
        'IO80211Interface26A428.candidate.h','offline-interface-abi-probe.cpp',
        'candidate-generation.json'])
    provenance = json.loads((args.references/'provenance.json').read_text())
    pinned_commit = '53c51c2cdd6e4b69beb91f310d74c53422b0f8bd'
    assert provenance['commit'] == pinned_commit, 'wrong historical reference commit'
    reference_prefix = f'https://raw.githubusercontent.com/OpenIntelWireless/itlwm/{pinned_commit}/include/Airport/'
    pinned_headers = {r['url']:r['sha256'] for r in provenance['headers']}
    for cls,*_ in CHAIN:
        assert hashlib.sha256((args.references/(cls+'.h')).read_bytes()).hexdigest() == \
               pinned_headers[reference_prefix+cls+'.h'], 'historical reference hash mismatch'
    images, tables, receipt = {}, {}, {}
    for name in ['IOSkywalkFamily', 'IO80211Family', 'AppleBCMWLANCore']:
        binary = KDK/f'System/Library/Extensions/{name}.kext/Contents/MacOS/{name}'
        thin = HERE/(name+'.arm64e')
        with tempfile.TemporaryDirectory(prefix='snap-interface-thin-') as temporary:
            temporary_thin = Path(temporary)/name
            c.arm64e_slice(binary, temporary_thin)
            write_new_bytes(thin, temporary_thin.read_bytes())
        images[name] = c.MachOKext(thin)
        uuidtext = subprocess.check_output(['/usr/bin/dwarfdump','--uuid',str(binary)],text=True)
        uuid = re.search(r'UUID: ([A-F0-9-]+) \(arm64e\)',uuidtext).group(1)
        receipt[name] = {'path': str(binary), 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                         'uuid': uuid, 'thin_sha256':hashlib.sha256(thin.read_bytes()).hexdigest()}
    assert receipt['IO80211Family']['uuid'] == '697DD7F8-8DDF-313D-8B37-BD25DD09744A'
    assert receipt['AppleBCMWLANCore']['uuid'] == '7503D11C-C083-312A-BF46-BF67364D3D11'
    metaclass_evidence = []
    for cls, parent, size, count, name in CHAIN:
        tables[cls] = images[name].vtable(cls)
        assert len(tables[cls]) == count
        symbol = f'__ZN{len(cls)}{cls}9MetaClassC1Ev'
        asm = subprocess.check_output(['/usr/bin/xcrun','llvm-objdump','--macho','--arch=arm64e',
                                       '-d','--dis-symname',symbol,receipt[name]['path']],text=True)
        assert re.search(r'mov\s+w3, #0x%x\b' % size, asm), f'{cls}: metaclass size mismatch'
        metaclass_evidence.append({'class':cls,'size':size,'assembly':asm})
    concrete = images['AppleBCMWLANCore'].vtable('AppleBCMWLANSkywalkInterface')
    names = c.demangle({r[1] for t in [*tables.values(), concrete] for r in t})
    references = {}
    for cls, *_ in CHAIN:
        text = (args.references/f'{cls}.h').read_text()
        for m in re.finditer(r'virtual\s+([\w:]+\s*\*?)\s+(\w+)\s*\(', text):
            references[cls, m[2]] = m[1].strip()

    models = {}
    alltypes, nested = set(), {cl: set() for cl, *_ in CHAIN}
    parent_methods = {}
    for cls, parent, size, count, name in CHAIN:
        table = tables[cls]
        inherited_count = len(tables[parent]) if parent in tables else 272
        methods = []
        for index, symbol, pac, local, ad, key in table:
            if index in (0, 1, 7):
                continue
            pure = symbol == c.PURE
            impl = concrete[index] if pure else table[index]
            if pure:
                assert impl[1] != c.PURE and impl[2] == pac
            owner, method, params, const = c.parse_demangled(names[impl[1]])
            if not pure and owner != cls:
                continue
            if pure and index < inherited_count:
                continue
            inherited = index < inherited_count
            if inherited and index in parent_methods:
                ret, ret_evidence = parent_methods[index]['return'], 'inherited-declaration'
            elif method in SDK_RETURN:
                ret, ret_evidence = SDK_RETURN[method], 'SDK-override-or-lifecycle'
            elif (cls, method) in references:
                ret, ret_evidence = references[cls, method], 'historical-header-reference'
            elif method.startswith('_RESERVED'):
                ret, ret_evidence = 'void', 'reserved-no-call'
            elif pure:
                ret, ret_evidence = 'IOReturn', 'status-convention-unqualified'
            else:
                ret, ret_evidence = 'IOReturn', 'opaque-return-unqualified'
            if ret == 'UInt':
                ret = 'unsigned int'
            if ret == 'UInt64':
                ret = 'uint64_t'
            sig = f"{method}({', '.join(params)})" + (' const' if const else '')
            record = {'slot':index,'method':sig,'name':method,'params':params,'const':const,
                      'return':ret,'return_evidence':ret_evidence,'pure':pure,
                      'override':inherited,'pac':pac,'address_diversity':ad,'key':key,
                      'implementation':impl[1]}
            methods.append(record)
            parent_methods[index] = record
            for typ in [*params, ret]:
                for ident in c.type_idents(typ):
                    if '::' in ident:
                        cl, tail = ident.split('::',1)
                        if cl in nested:
                            nested[cl].add(tail)
                    else:
                        alltypes.add(ident)
        models[cls] = methods
    known = set(images) | {cl for cl,*_ in CHAIN} | {
        'IOService','IOWorkLoop','IOUserClient','IOMemoryDescriptor','OSObject','OSDictionary','OSArray',
        'OSSet','OSString','OSSymbol','OSNumber','OSData','OSCollection','OSMetaClass',
        'OSMetaClassBase','OSIterator','IORegistryEntry','IORegistryPlane','OSSerialize',
        'IOReturn','SInt32','SInt64','UInt32','UInt64','uint64_t','uint32_t','uint16_t',
        'uint8_t','task','IORPC','IOOptionBits','IOReportChannelList',
    }
    lines = [
        '// OFFLINE ABI EXPERIMENT: no provider, publication, loading or hardware use.',
        '// All opaque return/request layouts remain prohibited for runtime calls.',
        '#ifndef SNAP_OFFLINE_INTERFACE_ABI_26A428_H',
        '#define SNAP_OFFLINE_INTERFACE_ABI_26A428_H',
        '#include <IOKit/IOService.h>',
        '#include <IOKit/IOWorkLoop.h>',
        '#include <IOKit/IOReportTypes.h>',
        '#pragma clang diagnostic push',
        '#pragma clang diagnostic ignored "-Wdeprecated-declarations"',
    ]
    for typ in sorted(alltypes-known):
        lines.append(f'struct {typ};')
    prevsize = 0x88
    for cls, parent, size, count, name in CHAIN:
        lines += [f'class {cls} : public {parent} {{',
                  f'    OSDeclareAbstractStructors({cls})', 'public:']
        for typ in sorted(nested[cls]):
            lines.append(f'    struct {typ};')
        for r in models[cls]:
            suffix = ' override' if r['override'] else ''
            if r['pure']:
                suffix += ' = 0'
            lines.append(f"    // slot {r['slot']}, PAC 0x{r['pac']:04x}; {r['return_evidence']}")
            lines.append(f"    virtual {r['return']} {r['method']}{suffix};")
        if size>prevsize:
            lines += ['private:', f'    unsigned char opaque_{cls}[0x{size-prevsize:x}];']
        lines += ['};',f'static_assert(sizeof({cls}) == 0x{size:x}, "wrong {cls} size");']
        prevsize = size
    lines += ['#pragma clang diagnostic pop','#endif']
    write_new_text(HERE/'IO80211Interface26A428.candidate.h', '\n'.join(lines)+'\n')
    probe = ['// Compile/link evidence only. Never instantiate, load or package as a kext.',
             '#include "IO80211Interface26A428.candidate.h"',
             'class OfflineInterfaceABIProbe : public IO80211InfraProtocol {',
             '    OSDeclareDefaultStructors(OfflineInterfaceABIProbe)', 'public:']
    pure = []
    for r in tables['IO80211InfraProtocol']:
        if r[1] == c.PURE:
            record = parent_methods[r[0]]
            pure.append(record)
            probe.append(f"    {record['return']} {record['method']} override;")
    probe += ['};','OSDefineMetaClassAndStructors(OfflineInterfaceABIProbe, IO80211InfraProtocol)']
    for r in pure:
        probe.append(f"{r['return']} OfflineInterfaceABIProbe::{r['method']} {{ return kIOReturnUnsupported; }}")
    write_new_text(HERE/'offline-interface-abi-probe.cpp', '\n'.join(probe)+'\n')
    report = {'status':'CANDIDATE_NOT_VERIFIED','runtime_qualified':False,
              'reference_binaries':receipt,'classes':models,
              'historical_references':[{'path':str((args.references/(cl+'.h')).resolve()),
                  'sha256':hashlib.sha256((args.references/(cl+'.h')).read_bytes()).hexdigest()}
                  for cl,*_ in CHAIN],
              'metaclass_size_evidence':metaclass_evidence,
              'chain':[{'class':cl,'parent':par,'size':sz,'slots':cnt} for cl,par,sz,cnt,_ in CHAIN],
              'required_pure_overrides':len(pure),
              'unqualified_returns':[{'class':cl,**r} for cl,rows in models.items()
                                     for r in rows if 'unqualified' in r['return_evidence']]}
    write_new_text(HERE/'candidate-generation.json', json.dumps(report,indent=2)+'\n')
    print('Generated candidate; pure overrides',len(pure),'unqualified returns',len(report['unqualified_returns']))

if __name__=='__main__':
    main()
