# SPDX-License-Identifier: MIT
"""Read a source file the way the compiler sees it after its split parts are included.

Large translation units (probes/xnuboot.c, compat/device.c and others) are kept under 1,000 lines per file by
moving ordered parts of them into a directory named after the file's stem, and `#include`-ing those parts back
in their original order. The compiler therefore still sees one translation unit, and the binaries are unchanged.

Tools that inspect source text (pattern checks, function extraction, replays that copy a function verbatim)
must read the whole unit, not just the main file. `read_source(path)` returns the main file with every quoted
`#include "<stem>/<part>"` line replaced by that part's text, recursively. Includes of anything outside the
file's own part directory are left untouched.

    from source_text import read_source
    text = read_source(ROOT / 'probes/xnuboot.c')
"""
import re
from pathlib import Path

_QUOTED_INCLUDE = re.compile(r'^[ \t]*#[ \t]*include[ \t]+"([^"]+)"[^\n]*$', re.M)


def part_directory(path):
    """The directory holding the parts of `path`: probes/xnuboot.c -> probes/xnuboot/."""
    path = Path(path)
    return path.parent / path.stem


def read_source(path):
    """Return the text of `path` with its own split parts expanded inline, in include order."""
    path = Path(path)
    text = path.read_text()
    parts = part_directory(path).resolve()

    def expand(match):
        target = (path.parent / match.group(1)).resolve()
        if target.parent != parts or not target.is_file():
            return match.group(0)
        return read_source(target).rstrip('\n')

    return _QUOTED_INCLUDE.sub(expand, text)


def source_files(path):
    """`path` followed by every part file it includes, in include order (for hashing or watching a unit)."""
    path = Path(path).resolve()
    files = [path]
    parts = part_directory(path).resolve()
    for match in _QUOTED_INCLUDE.finditer(path.read_text()):
        target = (path.parent / match.group(1)).resolve()
        if target.parent == parts and target.is_file():
            files.extend(source_files(target))
    return files
