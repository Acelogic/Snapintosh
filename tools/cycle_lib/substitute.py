# SPDX-License-Identifier: MIT
"""One runtime-root reader replaced by a committed copy from another checkout.

For a stopped run whose own stopped-state reader refuses a stop it should read
(generation76: tools/capture-kernel-waits.py did not know native variant tables),
`capture --replace PATH=FILE@COMMIT` runs the runtime root's own steps unchanged
except that PATH executes FILE's text, compiled as the runtime root's PATH (so it
resolves layout, tools and records from the runtime root). FILE must be exactly
its commit's version in its own checkout, and PATH must still be the runtime
root's unchanged file. The capture record carries the binding: launch, audit,
monitor, runtime root, the replaced file's hash, FILE with its hash and commit,
and each substituted step's arguments, which are the standard ones. Evidence and
preservation re-verify it. Only the files in ALLOWED may be replaced.

Accepted readers (accepted() below) are the other way round: the runtime root's own
reader runs, and the native observers' chain, which pins the reader by hash
(observers.READER_PINS), is rendered with the pinned digest swapped for the declared
one. A candidate declares it: "observers": {"readers": {PATH: {"sha256": ..., "commit":
...}}}. It is accepted only when the runtime root's PATH has that hash and is byte for
byte the file at that commit of its own checkout, and that commit descends from the
pinned version (the pinned digest is a version of PATH in the commit's history). The
declaration comes from the launch record (cycle.observers, copied from the manifest at
launch), or, for a run launched before its manifest declared it, from that manifest
amended by exactly this key: the launched version is found by its hash in the
manifest's git history and must equal the amended one without observers.readers.
Capture records carry the bindings, assess re-derives them on every read, and
preservation records them and copies the reader and the amended manifest.
"""
from pathlib import Path
import json
import pathlib
import runpy
import subprocess
import sys

from .common import PINS, Refused, need, sha, sha_bytes, matches, read

ALLOWED = ('tools/capture-kernel-waits.py',)
# Collector steps that run the reader, and the observers whose programs compile it.
RUNTIME_STEPS = ('kernel-waits', 'mounts', 'metal-probe')
OBSERVER_STEPS = ('native-startup', 'crash-retention')


def parse(spec):
    """'PATH=FILE@COMMIT' -> (path, file, commit)."""
    need(isinstance(spec, str) and spec.count('=') == 1 and spec.count('@') == 1 and
         spec.index('=') < spec.index('@'), f'--replace takes PATH=FILE@COMMIT, not {spec!r}')
    path, rest = spec.split('=')
    file, commit = rest.split('@')
    need(path in ALLOWED, f'{path} may not be replaced; allowed: {list(ALLOWED)}')
    need(len(commit) >= 7 and all(c in '0123456789abcdef' for c in commit), f'bad commit {commit!r}')
    return path, Path(file).resolve(), commit


def binding(ws, run, spec):
    """The substitution for this run, checked: the runtime root's file unchanged since
    launch (its hash recorded as replaced), the new file committed and different."""
    from .evidence import _audit, _committed
    path, file, commit = parse(spec)
    audit = _audit(run)
    need(audit, 'a substitution needs the qualified audit of this stop')
    original = run.runtime / path
    need(original.is_file() and file.is_file(), f'{original} or {file} is missing')
    need(file.parent != original.parent, 'the new file is the runtime root\'s own file')
    digest = sha(file)
    need(digest != sha(original), f'{file} is the runtime root\'s {path}; nothing to replace')
    need(_committed(file, commit, digest), f'{file} is not the committed {commit[:12]} version')
    return dict(status='READER_SUBSTITUTED', path=path, replaced_sha256=sha(original), file=str(file),
                file_sha256=digest, commit=commit, runtime_root=str(run.runtime), launch_sha256=run.launch_sha256,
                audit_sha256=audit['sha256'], monitor_sha256=run.launch['monitor_sha256'], spec=spec)


def verify(ws, run, b, audit):
    """A recorded substitution still holds: this run, this audit, unchanged files."""
    from .evidence import _committed
    what = f'reader substitution of {b.get("path")}'
    need(b.get('status') == 'READER_SUBSTITUTED' and b.get('path') in ALLOWED, f'{what}: not a reader substitution')
    need(b['launch_sha256'] == run.launch_sha256, f'{what} is bound to another launch record')
    need(audit and b['audit_sha256'] == audit['sha256'], f'{what} is bound to another audit')
    need(b['monitor_sha256'] == run.launch['monitor_sha256'], f'{what} is bound to another monitor')
    need(ws.local(b['runtime_root']) == run.runtime, f'{what} read another runtime root')
    need(matches(run.runtime / b['path'], b['replaced_sha256']), f'{what}: the runtime root\'s file changed since')
    file = ws.local(b['file'])
    need(matches(file, b['file_sha256']), f'{what}: {file} changed since; restore its commit')
    need(_committed(file, b['commit'], b['file_sha256']), f'{what}: {file} is not the committed {b["commit"][:12]}')
    return b


def install(target, source):
    """Serve `source` for the runtime file `target`: runpy.run_path(target) runs it
    compiled as target; target.read_text() returns it. Every other file, and
    target.read_bytes() (the programs' own hash pins), are untouched. Returns the
    use counts."""
    target = Path(target).resolve()
    real_run_path, real_read_text = runpy.run_path, pathlib.Path.read_text
    # restore() puts both back (host tests); a step process simply exits.
    uses = dict(run_path=0, read_text=0,
                restore=lambda: (setattr(runpy, 'run_path', real_run_path),
                                 setattr(pathlib.Path, 'read_text', real_read_text)))

    def run_path(path_name, init_globals=None, run_name=None):
        if Path(path_name).resolve() == target:
            uses['run_path'] += 1
            namespace = dict(init_globals or {}, __file__=str(target), __name__=run_name or '<run_path>')
            exec(compile(source, str(target), 'exec'), namespace)
            return namespace
        return real_run_path(path_name, init_globals, run_name)

    def read_text(self, *args, **kwargs):
        if Path(self).resolve() == target:
            uses['read_text'] += 1
            return source
        return real_read_text(self, *args, **kwargs)

    runpy.run_path, pathlib.Path.read_text = run_path, read_text
    return uses


def run_step(ws, args):
    """Hidden subcommand: one collector step, run by the runtime root's stopped-read
    helper exactly as capture runs it, with the reader substituted."""
    from .evidence import Run
    run_ = Run(ws, args.launch)
    b = binding(ws, run_, args.replace)
    helper_rel = PINS['observers']['helper']['runtime_path']
    rest = args.rest
    need(len(rest) >= 2 and rest[0] == helper_rel and rest[1] == b['path'],
         f'substituted steps run {helper_rel} {b["path"]}, not {rest[:2]}')
    helper = run_.runtime / helper_rel
    need(matches(helper, PINS['observers']['helper']['sha256']), 'runtime root stopped-read helper changed')
    source = Path(b['file']).read_text()
    real_run_path = runpy.run_path
    uses = install(run_.runtime / b['path'], source)
    # As if started as RUNTIME/build/<helper>: nothing resolves from this checkout.
    sys.path[0] = str(run_.runtime / 'build')
    sys.argv = [str(helper), *rest[1:]]
    real_run_path(str(helper), run_name='__main__')
    need(uses['run_path'] == 1, f'the substituted reader ran {uses["run_path"]} times, not once')
    return 0


def _git(file):
    """(top of the file's own git checkout, the file's path relative to it)."""
    top = subprocess.run(['git', '-C', str(Path(file).parent), 'rev-parse', '--show-toplevel'], capture_output=True,
                         text=True, check=True).stdout.strip()
    return top, str(Path(file).resolve().relative_to(Path(top).resolve()))


def _history(file, start):
    """[(commit, SHA-256 of the file at it)] for the commits from `start` back that changed
    the file in its own checkout, newest first; None where a commit removed it."""
    top, relative = _git(file)
    commits = subprocess.run(['git', '-C', top, 'rev-list', '--full-history', start, '--', relative],
                             capture_output=True, text=True, check=True).stdout.split()
    out = []
    for commit in commits:
        shown = subprocess.run(['git', '-C', top, 'show', f'{commit}:{relative}'], capture_output=True)
        out.append((commit, sha_bytes(shown.stdout) if shown.returncode == 0 else None))
    return out


def declarations(ws, run, manifest=None):
    """({PATH: declaration}, amendment or None): the launch record's reader declarations,
    or those of the launched manifest amended by exactly observers.readers."""
    launched = ((run.cycle or {}).get('observers') or {}).get('readers')
    declared = manifest.observers.get('readers') if manifest else None
    if launched is not None:
        need(declared is None or declared == launched, 'the manifest declares other readers than the launch record')
        return launched, None
    if not declared:
        return {}, None
    need(run.cycle and manifest.path.resolve() == ws.local(run.cycle['manifest']).resolve(),
         'readers declared after the launch must amend the launched manifest itself')
    original = commit = None
    try:
        for commit, digest in _history(manifest.path, 'HEAD'):
            if digest == run.cycle['manifest_sha256']:
                top, relative = _git(manifest.path)
                original = json.loads(subprocess.run(['git', '-C', top, 'show', f'{commit}:{relative}'],
                                                     capture_output=True, check=True).stdout)
                break
    except (subprocess.CalledProcessError, ValueError, OSError):
        original = None
    need(original is not None, f'the launched {manifest.path.name} ({run.cycle["manifest_sha256"][:12]}) is not in its '
         'git history; the amendment cannot be checked')
    amended = json.loads(json.dumps(manifest.data))
    del amended['observers']['readers']
    if not amended['observers'] and 'observers' not in original:
        del amended['observers']
    need(amended == original, f'{manifest.path.name} changed beyond observers.readers since the launch')
    return declared, dict(manifest=str(manifest.path), manifest_sha256=manifest.sha256,
                          launched_manifest_sha256=run.cycle['manifest_sha256'], launched_commit=commit,
                          added='observers.readers')


def accepted(ws, run, manifest=None):
    """The verified acceptance of each declared reader, sorted by path (module docstring)."""
    from .evidence import _committed
    from .observers import READER_PINS
    declared, amendment = declarations(ws, run, manifest)
    need(isinstance(declared, dict), 'observers.readers maps PATH to {"sha256": ..., "commit": ...}')
    out = []
    for path in sorted(declared):
        d = declared[path]
        need(path in READER_PINS, f'the native observers pin no reader {path}; they pin {sorted(READER_PINS)}')
        need(isinstance(d, dict) and set(d) == {'sha256', 'commit'}, f'{path}: a declaration is exactly sha256 and commit')
        pinned = READER_PINS[path][2]
        file = run.runtime / path
        need(matches(file, d['sha256']), f'the runtime root\'s {path} is not the declared {d["sha256"][:12]}')
        need(d['sha256'] != pinned, f'the runtime root\'s {path} is the pinned version; nothing to accept')
        try:
            top, _ = _git(file)
            commit = subprocess.run(['git', '-C', top, 'rev-parse', '--verify', f'{d["commit"]}^{{commit}}'],
                                    capture_output=True, text=True, check=True).stdout.strip()
            history = _history(file, commit)
        except (subprocess.CalledProcessError, ValueError, OSError):
            raise Refused(f'{path}: commit {d["commit"]} is not in the runtime root\'s history') from None
        need(_committed(file, commit, d['sha256']), f'the runtime root\'s {path} is not its commit {commit[:12]}\'s file')
        found = [i for i, (_, digest) in enumerate(history) if digest == pinned]
        need(found, f'{path}: commit {commit[:12]} does not descend from the pinned version {pinned[:12]}')
        out.append(dict(status='READER_ACCEPTED', path=path, sha256=d['sha256'], commit=commit, pinned_sha256=pinned,
                        pinned_commit=history[found[0]][0], changed_by=[c for c, _ in history[:found[0]]],
                        runtime_root=str(run.runtime), launch_sha256=run.launch_sha256,
                        monitor_sha256=run.launch['monitor_sha256'],
                        declared_by='amended manifest' if amendment else 'launch record', amendment=amendment))
    return out


def verify_accepted(ws, run, b):
    """A recorded acceptance still holds: re-derived from the same declaration."""
    what = f'accepted reader {b.get("path")}'
    need(b.get('status') == 'READER_ACCEPTED', f'{what}: not a reader acceptance')
    need(b['launch_sha256'] == run.launch_sha256, f'{what} is bound to another launch record')
    manifest = None
    if b.get('amendment'):
        from .launch import Manifest
        path = ws.local(b['amendment']['manifest'])
        need(matches(path, b['amendment']['manifest_sha256']), f'{what}: the amended manifest {path.name} changed since')
        manifest = Manifest(ws, path)

    def local(x):
        x = dict(x, runtime_root=str(ws.local(x['runtime_root'])))
        if x.get('amendment'):
            x['amendment'] = dict(x['amendment'], manifest=str(ws.local(x['amendment']['manifest'])))
        return x
    fresh = [x for x in accepted(ws, run, manifest) if x['path'] == b['path']]
    need(fresh and local(fresh[0]) == local(b), f'{what} no longer holds as recorded')
    return b
