#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Default Adreno collection linker: password-free staging, normal-user build.

Retain the historical linker byte-for-byte for existing qualification records.
This entry point preserves its verification, autoload packaging and loader pin,
and replaces only the administrator shell step with the checked user builder.
"""
from pathlib import Path
import hashlib

base = Path(__file__).with_name('link-adreno-fill-auxkc.py')
assert hashlib.sha256(base.read_bytes()).hexdigest() == '26bd62e7510dd549940d5adc348e2a7741b261f9675ada229094e648e05605f2'
source = base.read_text()
source = source.replace('Opens one native administrator prompt for kmutil\'s root-owned staging.',
    'Uses existing password-free tar staging; kmutil runs as the normal user.')
old = "             'probes/guestprofile.py']"
assert source.count(old) == 1
source = source.replace(old, "             'probes/guestprofile.py','tools/build-auxkc-user.py']")
start = source.index('    shell=shlex.join(')
end = source.index('    verify()\n', start)
replacement = '''    command=[sys.executable,str(original/'tools/build-auxkc-user.py'),str(raw),str(kext)]
    plan=dict(qualification=str(qualification),qualification_sha256=sha(qualification),
        qualification_kind=kind,kext_sha256=sha(binary),
        original_sources_sha256=original_sources,
        tool_sha256=sha(Path(__file__)),command=command,
        administrator_dialog=False,policy_changed=False)
    (out/'plan.json').write_text(json.dumps(plan,indent=2)+'\\n')
    run('user-build',command)
    build_record=raw.with_name(raw.name+'.build.json')
    built=json.loads(build_record.read_text())
    assert built['status']=='PASSWORDLESS_AUXKC_BUILT'
    assert built['caller_uid']==built['kmutil_uid']==built['collection_owner']!=0
    assert not built['administrator_dialog'] and not built['policy_changed']
    assert built['cleanup']['exit_code']==0 and built['cleanup']['stage_removed']
    assert built['collection_sha256']==sha(raw)
'''
source = source[:start] + replacement + source[end:]
exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))
