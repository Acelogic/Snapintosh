# SPDX-License-Identifier: MIT
"""The pinned stopped-state observer programs, rendered for one run.

Each per-generation wrapper (for example build/collect-ca-memo-20260928.py,
capture-ca-memo-ring-20260928.py, capture-native-startup-gen66-20260928.py and
capture-crash-retention-gen66-20260928.py) is a fixed list of text substitutions over
one pinned base program. The values it pasted in are the run's runtime root, prefix,
generation, image base, context size, guest profile, SWITCH_ROOT memo define, AuxKC
and display-object binding. The renderers below make the same substitutions, in the
same order, from the run's own records. The only intended difference: the rendered
collector runs its ring capture through `cycle.py observe ring` instead of a
per-generation ring file.
"""
from contextlib import redirect_stdout
import ast
import builtins
import io
import sys

from pathlib import Path

from .common import PINS, need, read, matches

SKS_RUNTIME = 'Snapintosh-adreno-sks'
BASE_BYTES, BASE_FIELDS = 5124736, 217
BASE_PREFIX = 'installed-metal-panel-mode-2100s-20260928'
ADMITTED = ("'j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display',"
            "'j700ap-26A428-xars-uniform-auxkc-installed-adreno-metal-display-sks')")
FLAGS_OLD = "'SNAP_CLASS_PROOF_MAPPED','SNAP_ROOT_VALIDATE_WORDS','SNAP_CLASS_LEAF_MEMO')"
# The collector forwards each listed flag only when the launch built with -DFLAG=1.
FLAGS_NEW = ("'SNAP_CLASS_PROOF_MAPPED','SNAP_ROOT_VALIDATE_WORDS','SNAP_CLASS_LEAF_MEMO','SNAP_ROOT_VALIDATE_MEMO',"
             "'SNAP_INACTIVE_MIRROR','SNAP_NATIVE_TABLES')")
GUI_ANCHOR = 'source = base.read_text()'
GUI_INJECT = (GUI_ANCHOR + '\n'
              f'assert source.count({FLAGS_OLD!r}) == 1\n'
              f'source = source.replace({FLAGS_OLD!r}, {FLAGS_NEW!r})')
RING_ENTRY = "'capture-metal-gui-ring-20260927.py': 'capture-panel-mode-ring-20260928.py',"
CYCLE_RING_ENTRY = ("\"str(ROOT / 'build/capture-metal-gui-ring-20260927.py'),\": "
                    "\"str(ROOT / 'tools/cycle.py'), 'observe', 'ring', '--launch', PREFIX, '--',\",")
NATIVE_ANCHOR = "source = source.replace(anchor, injected + '\\n\\n' + anchor)"
DISPATCH = "exec(compile(source, str(base), 'exec'), dict(__file__=__file__, __name__='__main__'))"
MEMO_DEFINE = '-DSNAP_ROOT_VALIDATE_MEMO=1'
# The runtime-root readers the native observers' chain pins by hash: (the chain file
# that pins it, that file's hash as the chain pins it, the pinned digest). An accepted
# reader (substitute.accepted) swaps the digest in that file's text, through the
# native base's own edits of it (EXTRA_ANCHOR), each applied exactly once.
READER_PINS = {'tools/capture-kernel-waits.py': (
    'build/capture-windowserver-extended-gen50-20260927.py',
    '508a05b7af5978f22658a01ec0d960a6767ceed9aa3903ec9ec854ec7fe13be5',
    '88aaf2de70c4d1290055c05afc3640677b251e4b1ee1ccf7e1b28eed5db9f0c5')}
EXTRA_ANCHOR = 'extra = {pid_old: pid_new,'


def pinned(ws, kind):
    entry = PINS['observers'][kind]
    path = ws.path(entry['path'])
    need(matches(path, entry['sha256']), f'pinned observer base {entry["path"]} changed')
    return path


def substitute(source, changes):
    for old, new in changes.items():
        need(source.count(old) == 1, f'observer base no longer contains exactly one {old!r}')
        source = source.replace(old, new)
    return source


class Params:
    """What the per-generation wrappers pasted in, taken from the run's records."""

    def __init__(self, run, display=None, readers=()):
        launch = run.launch
        self.prefix, self.generation, self.image_base = run.prefix, run.generation, run.image_base
        self.runtime_name = run.runtime.name
        self.context_bytes, self.context_fields = launch['context_bytes'], launch['context_fields']
        self.profile = launch['guest_profile']
        self.memo = MEMO_DEFINE in launch['build_defines']
        self.auxkc_sha256 = launch['auxkc_sha256']
        self.display = display
        # {path: digest} of accepted runtime-root readers (verified bindings).
        self.readers = {b['path']: b['sha256'] for b in readers}


def display_binding(ws, run, manifest=None):
    """The kext qualification and AdrenoDisplay.o the native observers check with DWARF.
    From the launch record (cycle launches) or the candidate manifest; verified
    against the run's AuxKC and kext."""
    binding = ((run.cycle or {}).get('observers') or {}).get('display') or \
        (manifest and manifest.observers.get('display'))
    need(binding, 'no display binding: this launch record has no cycle bindings; pass --candidate MANIFEST')
    qualification, obj = ws.path(binding['kext_qualification']), ws.path(binding['display_object'])
    need(matches(qualification, binding['kext_qualification_sha256']), f'{qualification} changed')
    need(matches(obj, binding['display_object_sha256']), f'{obj} changed')
    q = read(qualification)
    need(q['collection_sha256'] == run.launch['auxkc_sha256'], 'kext qualification is for another AuxKC')
    need(q['kext_sha256'] == run.launch['kext_sha256'], 'kext qualification is for another kext')
    need(any(ws.local(k) == obj and v == binding['display_object_sha256'] for k, v in q['inputs_sha256'].items()),
         'display object is not an input of the kext qualification')
    return dict(binding)


def render_collector(ws, p):
    """collect-panel-mode-20260928.py with the per-generation collector's substitutions."""
    changes = {}
    if p.memo:
        changes['changes = {\n'] = 'changes = {\n    ' + repr(GUI_ANCHOR) + ': ' + repr(GUI_INJECT) + ',\n'
    if p.runtime_name != SKS_RUNTIME:
        changes["\"'Snapintosh-adreno-pipeline'\": \"'Snapintosh-adreno-sks'\","] = \
            f"\"'Snapintosh-adreno-pipeline'\": \"'{p.runtime_name}'\","
    changes[BASE_PREFIX] = p.prefix
    if repr(p.profile) not in ADMITTED:
        changes[ADMITTED] = ADMITTED[:-1] + ',' + repr(p.profile) + ')'
    if p.context_bytes != BASE_BYTES:
        changes["'5108352': '5124736'"] = f"'5108352': '{p.context_bytes}'"
    if p.context_fields != BASE_FIELDS:
        changes["\"launch['context_fields'] == 216\": \"launch['context_fields'] == 217\""] = \
            f"\"launch['context_fields'] == 216\": \"launch['context_fields'] == {p.context_fields}\""
    changes[RING_ENTRY] = CYCLE_RING_ENTRY
    return substitute(pinned(ws, 'collector').read_text(), changes)


def render_ring(ws, p):
    changes = {}
    if p.runtime_name != SKS_RUNTIME:
        changes["RUNTIME = ROOT.parent / 'Snapintosh-adreno-sks'"] = f"RUNTIME = ROOT.parent / {p.runtime_name!r}"
    if p.context_bytes != BASE_BYTES:
        changes[f"launch['context_bytes'] == {BASE_BYTES}"] = f"launch['context_bytes'] == {p.context_bytes}"
    if p.context_fields != BASE_FIELDS:
        changes[f"launch['context_fields'] == {BASE_FIELDS}"] = f"launch['context_fields'] == {p.context_fields}"
    changes[BASE_PREFIX] = p.prefix
    changes['== 55'] = f'== {p.generation}'
    changes['generation=55'] = f'generation={p.generation}'
    changes['Generation55 ring observer'] = f'Generation{p.generation} ring observer'
    return substitute(pinned(ws, 'ring').read_text(), changes)


def render_native(ws, p):
    need(p.display, 'the native observers need the display binding (pass --candidate)')
    runtime = []
    if p.runtime_name != SKS_RUNTIME:
        runtime.append(("\"'Snapintosh-adreno-pipeline'\": \"'Snapintosh-adreno-sks'\",",
                        f"\"'Snapintosh-adreno-pipeline'\": \"'{p.runtime_name}'\",", 2))
    if (p.context_fields, p.context_bytes) != (BASE_FIELDS, BASE_BYTES):
        runtime.append(("\"launch['context_fields'] == 217 and launch['context_bytes'] == 5124736\",",
                        f"\"launch['context_fields'] == {p.context_fields} and launch['context_bytes'] == {p.context_bytes}\",", 1))
    changes = {
        "qualification = ROOT / 'build/panel-mode-candidate-20260928-v2/qualification.json'":
            f"qualification = ROOT.parent / {p.display['kext_qualification']!r}",
        '6e936cabf4197912dbc533939b21a3db439f6bd88a5dd37f9e2b2d7b52dc8b1f': p.display['kext_qualification_sha256'],
        "obj = qualification.parent / 'obj/AdrenoDisplay.o'": f"obj = ROOT.parent / {p.display['display_object']!r}",
        "candidate['new_object_sha256']": repr(p.display['display_object_sha256']),
        BASE_PREFIX: p.prefix,
        'generation=55,': f'generation={p.generation},',
        "stage_generation\\'] == 55": f"stage_generation\\'] == {p.generation}",
    }
    if p.image_base != 0xb0000000:
        changes["image_base\\'] == 0xb0000000"] = f"image_base\\'] == {p.image_base:#x}"
    changes['Generation55 native startup observer'] = f'Generation{p.generation} native startup observer'
    changes['59e6012865e4eacd835d86b139d5c3032e46d35592c9d1af4726d3209390fcf2'] = p.auxkc_sha256
    if runtime:
        changes[NATIVE_ANCHOR] = (NATIVE_ANCHOR + '\nfor _old, _new, _count in ' + repr(runtime) + ':\n'
                                  '    assert source.count(_old) == _count, _old\n'
                                  '    source = source.replace(_old, _new)')
    if p.readers:
        # Accepted readers: the pinned digest becomes the declared one, as one more
        # edit of the extended observer's text (the base applies each exactly once).
        edits = ''
        for path, digest in sorted(p.readers.items()):
            chain, chain_sha256, digest_pinned = READER_PINS[path]
            old, new = f'{path!r}: {digest_pinned!r}', f'{path!r}: {digest!r}'
            need(matches(ws.root / chain, chain_sha256) and (ws.root / chain).read_text().count(old) == 1,
                 f'{chain} no longer pins {path} exactly once')
            edits += f' {old!r}: {new!r},'
        changes[EXTRA_ANCHOR] = EXTRA_ANCHOR + edits
    return substitute(pinned(ws, 'native').read_text(), changes)


def render_crash(ws, p):
    """(crash-retention-gen55 text reading NATIVE_SOURCE, rendered native text)."""
    native = render_native(ws, p)
    crash = substitute(pinned(ws, 'crash').read_text(), {'source = native.read_text()': 'source = NATIVE_SOURCE'})
    return crash, native


def rendered(ws, p):
    """{kind: sha256 of the rendered program} for records."""
    out = dict(collector=render_collector(ws, p), ring=render_ring(ws, p))
    if p.display:
        out['native'] = render_native(ws, p)
        out['crash'] = render_crash(ws, p)[0]
    return {k: sha_text(v) for k, v in out.items()}


def sha_text(text):
    import hashlib
    return hashlib.sha256(text.encode()).hexdigest()


def stopped_collector_source(ws, p):
    """The innermost stopped-state collector exactly as the rendered collector would run
    it, captured from its own --check mode (no hardware access)."""
    text = render_collector(ws, p)
    seen, original, saved = [], builtins.compile, sys.argv

    def hook(source, filename, *args, **kwargs):
        if filename == 'gui-stopped-collector':
            seen.append(source)
        return original(source, filename, *args, **kwargs)

    base = pinned(ws, 'collector')
    builtins.compile, sys.argv = hook, [str(base), '--check']
    try:
        with redirect_stdout(io.StringIO()):
            # The collector chain finds collect-auxkc-20260925.py beside its own file, so it
            # runs as the pinned base file in build/, exactly where the wrappers lived.
            exec(original(text, str(base), 'exec'), dict(__file__=str(base), __name__='__main__'))
    finally:
        builtins.compile, sys.argv = original, saved
    need(len(seen) == 1, 'rendered collector did not build exactly one stopped-state collector')
    return seen[0]


def collector_steps(ws, run, p):
    """{step: (runtime script, [arguments])} of the collector's collect() calls, with the
    arguments evaluated from the launch record the way the collector evaluates them;
    plus the panel and verdict commands, checked against the collector's own text."""
    source = stopped_collector_source(ws, p)
    tree = ast.parse(source)
    launch = run.launch
    arguments = launch['arguments']
    profile = arguments[arguments.index('--guest-profile') + 1]
    scope = dict(launch=launch, profile=profile, KC=launch['auxkc'],
                 extra=['--trust-additions', arguments[arguments.index('--trust-additions') + 1]]
                 if '--trust-additions' in arguments else [])
    admitted = installed = None
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', None) == 'INSTALLED':
            # The pinned collector's own INSTALLED rule, evaluated for this profile only.
            installed = eval(compile(ast.Expression(node.value), 'installed', 'eval'), dict(profile=profile))
        if isinstance(node, ast.Assert) and isinstance(node.test, ast.Compare) and \
                getattr(node.test.left, 'id', None) == 'profile' and isinstance(node.test.ops[0], ast.In):
            admitted = ast.literal_eval(node.test.comparators[0])
    need(admitted and profile in admitted, f'the collector does not admit guest profile {profile}')
    need(installed is not None, 'collector has no INSTALLED rule')
    scope['INSTALLED'] = installed
    calls = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, 'id', None) == 'collect':
            name, script, extra = node.args
            if 'cpu{owner}' in ast.unparse(name):
                need(ast.unparse(extra) == "['--cpu', str(owner)]", 'owner-CPU stop arguments changed')
                calls['cpu-stop'] = (ast.literal_eval(script), None)
                continue
            # The pinned collector's own argument expression, evaluated with the launch
            # record's values; it builds a list of strings and runs nothing else.
            calls[ast.literal_eval(name)] = (ast.literal_eval(script),
                                             eval(compile(ast.Expression(extra), 'collect-arguments', 'eval'), dict(scope)))
    need(set(calls) == {'audit', 'cpu-stop', 'service-profile', 'kernel-waits', 'mounts', 'console-tail', 'metal-probe'},
         f'collector steps changed: {sorted(calls)}')
    panel = ("'tools/capture-panel.py',f'build/{PREFIX}-panel.png','--device',DEVICE,\n"
             "        '--block-bytes','65536' if DEVICE.startswith('udp://') else '4096','--reconnects','0']")
    need(source.count(panel) == 1 and source.count(PINS['panel_python']) == 1, 'collector panel command changed')
    need(source.count("[sys.executable,'-B','tools/auxkc-verdict.py','--prefix',PREFIX]") == 1, 'verdict command changed')
    return calls


def gui_historical(ws):
    """The three historical input records collect-metal-gui copies into the runtime root."""
    tree = ast.parse(pinned(ws, 'gui_collector').read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', None) == 'historical':
            return ast.literal_eval(node.value)
    raise AssertionError('collect-metal-gui has no historical map')


def observe(ws, args):
    """Hidden subcommand: run one rendered observer as its own process, exactly as the
    per-generation wrapper file would have run."""
    from .evidence import Run
    from .launch import Manifest
    rest = args.rest
    run = Run(ws, args.launch)
    manifest = Manifest(ws, args.candidate) if args.candidate else None
    kind = args.kind
    from . import substitute
    display = display_binding(ws, run, manifest) if kind in ('native', 'crash') else None
    # Accepted runtime-root readers (substitute.accepted), re-verified in this process.
    readers = substitute.accepted(ws, run, manifest) if kind in ('native', 'crash') else []
    p = Params(run, display, readers)
    uses = None
    if getattr(args, 'replace', None):
        # A reader substitution (substitute.py): the observer compiles the committed
        # copy as the runtime root's file; its own hash pins still read the original.
        need(kind in ('native', 'crash'), f'the {kind} observer runs no replaceable reader')
        b = substitute.binding(ws, run, args.replace)
        need(b['path'] not in p.readers, f'{b["path"]} is both replaced and accepted')
        uses = substitute.install(run.runtime / b['path'], Path(b['file']).read_text())
    namespace = dict(__file__=str(ws.tool), __name__='__main__')
    if kind == 'collector':
        text, base = render_collector(ws, p), pinned(ws, 'collector')
        namespace['__file__'] = str(base)
    elif kind == 'ring':
        text, base = render_ring(ws, p), pinned(ws, 'ring')
    elif kind == 'native':
        text, base = render_native(ws, p), pinned(ws, 'native')
    else:
        text, native = render_crash(ws, p)
        base = pinned(ws, 'crash')
        namespace['NATIVE_SOURCE'] = native
    sys.argv = [str(ws.tool), *rest]
    sys.path[0] = str(ws.build)
    exec(compile(text, str(base), 'exec'), namespace)
    if uses is not None:
        need(uses['read_text'] >= 1 and not uses['run_path'], 'the observer did not compile the substituted reader')
    return 0
