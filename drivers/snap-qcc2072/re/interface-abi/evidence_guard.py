# SPDX-License-Identifier: MIT
"""Preserve completed and partial offline evidence across repeated invocations."""
import json
from pathlib import Path


def write_new_text(path, text):
    with Path(path).open('x') as stream:
        stream.write(text)


def write_new_bytes(path, data):
    with Path(path).open('xb') as stream:
        stream.write(data)


def start_phase(directory, phase, outputs):
    """Refuse existing evidence and reserve a phase before any output mutation.

    The marker deliberately survives failure. Retry in a new directory so partial
    evidence and logs remain available, and concurrent invocations cannot share
    the same phase's output paths.
    """
    directory = Path(directory)
    marker = directory/f'.{phase}-started.json'
    paths = [marker, *(directory/name for name in outputs)]
    conflicts = [str(path) for path in paths if path.exists() or path.is_symlink()]
    if conflicts:
        raise SystemExit('Refusing to overwrite evidence; choose a NEW output directory: '
                         + ', '.join(conflicts))
    directory.mkdir(parents=True, exist_ok=True)
    try:
        write_new_text(marker, json.dumps({'phase':phase,'reserved_outputs':list(outputs)},
                                         indent=2)+'\n')
    except FileExistsError:
        raise SystemExit('Evidence phase already started; choose a NEW output directory: '
                         + str(marker))
