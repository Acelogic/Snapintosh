#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compare the real linked native controller's vtable with exact 26A428 evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import runpy

HERE = Path(__file__).resolve().parent
recover = runpy.run_path(str(HERE / 'recover-controller-abi.py'))
require = recover['require']

# The controller is allowed exactly these overrides. Extending the
# implementation requires a deliberate corresponding contract review.
# createWorkQueue/getWorkQueue (slots 401/403): the base returns false/null;
# AppleBCMWLANCore overrides both (apple-controller-abi.json), and the
# lifecycle replay in native-controller/ covers the queue's ownership.
OVERRIDES = {
    'free()', 'init(OSDictionary*)', 'start(IOService*)', 'stop(IOService*)',
    'createWorkQueue()', 'getWorkQueue() const',
    'isCommandProhibited(int)',
    'handleCardSpecific(IO80211SkywalkInterface*, unsigned long, void*, bool)',
    'getDRIVER_VERSION(IO80211SkywalkInterface*, apple80211_version_data*)',
    'getHARDWARE_VERSION(IO80211SkywalkInterface*, apple80211_version_data*)',
    'getCARD_CAPABILITIES(IO80211SkywalkInterface*, apple80211_capability_data*)',
    'getPOWER(IO80211SkywalkInterface*, apple80211_power_data*)',
    'setPOWER(IO80211SkywalkInterface*, apple80211_power_data*)',
    'getCOUNTRY_CODE(IO80211SkywalkInterface*, apple80211_country_code_data*)',
    'setCOUNTRY_CODE(IO80211SkywalkInterface*, apple80211_country_code_data*)',
    'setGET_DEBUG_INFO(IO80211SkywalkInterface*, apple80211_debug_command*)',
    'getLogger() const', 'getFaultReporterFromDriver()', 'getMetaClass() const',
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    parser.add_argument('--class-name', default='SnapintoshQCC2072')
    args = parser.parse_args()
    require(not args.report.exists(), 'report already exists')
    reference = json.loads((HERE / 'controller-abi.json').read_text())
    concrete = json.loads((HERE / 'apple-controller-abi.json').read_text())
    base = reference['controller']
    for source in [base, reference['superclass_candidate'], concrete]:
        require(hashlib.sha256(Path(source['path']).read_bytes()).hexdigest() ==
                source['sha256'], 'reference binary has changed')
    actual = recover['inspect'](args.binary.resolve(), args.class_name)
    require(actual['slot_count'] == base['slot_count'], 'controller slot count differs')
    checked = []
    pure_count = 0
    for want, got in zip(base['slots'], actual['slots']):
        slot = want['slot']
        for key in ['diversity', 'address_diversity', 'key']:
            require(want[key] == got[key], f'slot {slot}: {key} differs')
        wanted = want['demangled']
        pure = wanted == '___cxa_pure_virtual'
        if pure:
            pure_count += 1
            child = concrete['slots'][slot]
            require(all(want[k] == child[k] for k in ['diversity', 'address_diversity', 'key']),
                    'concrete reference PAC differs')
            wanted = child['demangled'].replace('AppleBCMWLANCore::', 'IO80211Controller::', 1)
        method = wanted.split('::', 1)[1] if '::' in wanted else wanted
        generated = slot in (0, 1, 7)
        permitted = generated or method in OVERRIDES
        expected_own = args.class_name + '::' + (
            '~' + args.class_name + '()' if slot in (0, 1) else method)
        inherited_match = bool(set(got['symbols']) & set(want['symbols']))
        own_match = permitted and got['demangled'] == expected_own
        require(own_match if pure or generated else (inherited_match or own_match),
                f'slot {slot}: unexpected target {got["demangled"]}; expected {wanted}')
        require(got['demangled'] != '___cxa_pure_virtual', f'slot {slot}: pure virtual remains')
        checked.append({'slot': slot, 'target': got['demangled'],
                        'diversity': got['diversity'], 'address_diversity': got['address_diversity'],
                        'key': got['key'], 'comparison': 'override' if own_match else 'inherited'})
    result = {'status': 'CONTROLLER_VTABLE_PAC_MATCH', 'binary': actual['path'],
              'binary_sha256': actual['sha256'], 'class': args.class_name,
              'slot_count': actual['slot_count'], 'implemented_pure_slots': pure_count,
              'controller_uuid': base['uuid'], 'slots': checked,
              'hardware_access': False, 'native_wifi_runtime_qualified': False,
              'limitations': ['Checks vtable targets and PAC metadata, not method behavior.',
                              'Private request layouts and native interface lifecycle remain unqualified.',
                              'Pointer return semantic types are opaque; do not call unqualified methods.']}
    with args.report.open('x') as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write('\n')
    print(json.dumps({k: result[k] for k in
                      ['status', 'slot_count', 'implemented_pure_slots', 'binary_sha256']}))


if __name__ == '__main__':
    main()
