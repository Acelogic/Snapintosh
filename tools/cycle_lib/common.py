# SPDX-License-Identifier: MIT
"""Workspace, hashing, records and host-side checks shared by every cycle step.

Nothing here touches the A16. The proxy module is only loaded by the callers that
have already passed their offline checks.
"""
from datetime import datetime, timezone
from pathlib import Path
import ast
import hashlib
import importlib.util
import json
import os
import re
import runpy
import subprocess
import sys
import time

LIB = Path(__file__).resolve().parent
PINS_PATH = LIB / 'pins.json'
if not PINS_PATH.exists():
    # pins.json is per machine and not distributed; start from the example.
    print(f'cycle_lib: {PINS_PATH} not found; using pins.example.json. Copy it to '
          'pins.json and set the device, stage hashes and paths for your machine.', file=sys.stderr)
    PINS_PATH = LIB / 'pins.example.json'
PINS = json.loads(PINS_PATH.read_text())
SERROR_KEYS = ('before', 'during', 'unconsumed')
PARKED_SERVICE_WORD = 0x8000000000000003
STOPPED_EXITS = {int(k): v for k, v in PINS['stopped_exits'].items()}
BASES = tuple(int(x, 16) for x in PINS['image_bases'])


class Refused(Exception):
    """A check failed. The message says which; nothing after it was done."""


def need(condition, message):
    if not condition:
        raise Refused(message)


_digests = {}


def sha(path):
    """SHA-256 of a file. Repeated reads of an unchanged file are served from memory."""
    path = Path(path)
    st = path.stat()
    key = (str(path), st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)
    if key not in _digests:
        digest = hashlib.sha256()
        with path.open('rb') as stream:
            for block in iter(lambda: stream.read(1 << 20), b''):
                digest.update(block)
        _digests[key] = digest.hexdigest()
    return _digests[key]


def matches(path, digest):
    """The file exists and has this SHA-256."""
    return Path(path).is_file() and sha(path) == digest


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def write_new(path, record):
    """Create a record; refuse to replace anything that exists."""
    with Path(path).open('x') as stream:
        stream.write(json.dumps(record, indent=2) + '\n')


def rewrite(path, record):
    """Update a record this process created with write_new."""
    Path(path).write_text(json.dumps(record, indent=2) + '\n')


def image_base(generation):
    """q1n1 alternates stage slots on every chainload: odd generations run at
    0xb0000000, even ones at 0xb0800000 (generations 54 through 66 all agree)."""
    return BASES[1] if generation % 2 == 0 else BASES[0]


def alternate(base):
    need(base in BASES, f'image base {base:#x} is not one of the two stage slots')
    return BASES[1] if base == BASES[0] else BASES[0]


def process_table():
    """{pid: (start time UTC seconds, parent pid, command line)} from ps."""
    out = subprocess.run(['ps', '-axo', 'pid=,ppid=,lstart=,command='], capture_output=True, text=True,
                         env=dict(os.environ, TZ='UTC', LC_ALL='C'), check=True).stdout
    table = {}
    for line in out.splitlines():
        m = re.match(r'\s*(\d+)\s+(\d+)\s+(\w{3}\s+\w{3}\s+\d+\s+\d\d:\d\d:\d\d\s+\d{4})\s+(.*)$', line)
        if m:
            start = datetime.strptime(' '.join(m[3].split()), '%a %b %d %H:%M:%S %Y')
            table[int(m[1])] = (start.replace(tzinfo=timezone.utc).timestamp(), int(m[2]), m[4])
    return table


# Command lines that talk to the A16 or will soon. Offline modes are excluded.
CLIENT_PATTERNS = [re.compile(p) for p in (
    r'udp://en\d', r'/dev/cu\.usbmodem', r'q1n1proxy\.py', r'a16gpu\.py', r'a16ctl\.py',
    r'nvme_(m3|window|hash)\.py', r'run-stopped-cdc-read', r'capture-panel\.py', r'probes/run\.py',
    r'(tools|build)/run-[\w.-]+\.py(?!.*--(check|syntax-only|inputs-only))',
    r'(tools|build)/(retire|storage|preserve|collect|capture|request-stop)[\w.-]*\.py(?!.*--(check|syntax-only))',
    r'tools/cycle\.py\s+(status|capture|retire|launch|observe|storage)(?!.*--check)')]


class Workspace:
    """The directory that holds Snapintosh, q1n1 and the runtime roots.

    Records store absolute paths from the workspace they were written in
    (`origin`). In place, origin == parent and local() changes nothing; a
    copied workspace (host tests) maps origin onto its own parent.
    """

    def __init__(self, root, origin=None):
        self.root = Path(root).resolve()
        self.parent = self.root.parent
        self.origin = str(Path(origin) if origin else self.parent)
        self.build = self.root / 'build'
        self.docs = self.root / 'docs'
        self.q = self.parent / 'q1n1'
        self.tool = self.root / 'tools' / 'cycle.py'
        self.processes = process_table
        self.settle_seconds = 6
        self.device = PINS['device']

    def adopt_origin(self, hardware_owner):
        """Records name the checkout that wrote them (launch 'hardware_owner'). When
        that is this checkout's name in another directory, the workspace was copied:
        map that directory onto this one."""
        owner = Path(hardware_owner)
        if owner == self.root or self.origin != str(self.parent):
            return
        need(owner.name == self.root.name, f'record written by another checkout: {owner}')
        self.origin = str(owner.parent)

    def local(self, path):
        text = str(path)
        if text == self.origin or text.startswith(self.origin + '/'):
            text = str(self.parent) + text[len(self.origin):]
        return Path(text)

    def path(self, relative):
        """A workspace-relative path from a manifest or pins.json."""
        need(not str(relative).startswith('/'), f'{relative}: manifest paths are workspace-relative')
        return self.parent / relative

    def relative(self, path):
        return str(Path(path).relative_to(self.parent))

    def prefixed(self, prefix, suffix):
        return self.build / (prefix + suffix)

    def tool_sources(self):
        """The files that make up this tool, for records."""
        files = [self.root / 'tools' / 'cycle.py', *sorted(LIB.glob('*.py')), PINS_PATH]
        return {str(p): sha(p) for p in files if p.is_file()}


def host_absent(ws, launch):
    """The launcher that wrote this record has exited (a reused PID must be newer)."""
    entry = ws.processes().get(launch['pid'])
    if entry:
        need(entry[0] > launch['finished'], f'launcher PID {launch["pid"]} is still present (or reused ambiguously)')


def hardware_clients(ws):
    """Processes other than this one and its ancestors that may be using the A16."""
    table = ws.processes()
    mine, pid = set(), os.getpid()
    while pid in table and pid not in mine:
        mine.add(pid)
        pid = table[pid][1]
    mine.add(os.getpid())
    return [dict(pid=p, command=c[:300]) for p, (_, _, c) in sorted(table.items())
            if p not in mine and any(r.search(c) for r in CLIENT_PATTERNS)]


def require_exclusive(ws):
    clients = hardware_clients(ws)
    need(not clients, 'another hardware client is running: ' + json.dumps(clients))


def serror_clear(state):
    return not any(state[k] for k in SERROR_KEYS)


def downloads_pinned(ws, runtime, image):
    """runtime/downloads -> ../Snapintosh/downloads, resolving to the image's firmware
    with exactly the qualified hashes. Returns the firmware directory."""
    link = runtime / 'downloads'
    need(link.is_symlink(), f'{link} is missing or not a symbolic link')
    need(os.readlink(link) == f'../{ws.root.name}/downloads', f'{link} -> {os.readlink(link)}, expected ../{ws.root.name}/downloads')
    need(link.resolve() == (ws.root / 'downloads').resolve(), f'{link} does not resolve to {ws.root}/downloads')
    firmware = runtime / 'downloads/extracted/j700ap'
    need(firmware.resolve() == ws.local(image['firmware']).resolve(),
         f'{firmware} resolves to {firmware.resolve()}, not the qualified firmware {image["firmware"]}')
    need(len(image['firmware_sha256']) == 5, 'the image must pin exactly five firmware files')
    for name, digest in image['firmware_sha256'].items():
        need(sha(firmware / name) == digest, f'firmware {name} changed')
    return firmware


_layouts = {}


def context_layout(runtime):
    """(MonitorLayout, {field: offset}) of a runtime root's monitor context."""
    key = str(runtime)
    if key not in _layouts:
        layout = runpy.run_path(str(runtime / 'tools/monitor_layout.py'))['MonitorLayout']()
        fields = re.findall(r'^\s*(\d+) \|   \S.* (\w+)$', layout.records['context'], re.M)
        named = {name: int(offset) for offset, name in fields}
        need(len(named) == len(fields), f'{runtime}: duplicate context field names')
        _layouts[key] = (layout, named)
    return _layouts[key]


def battery_minimum(value=None):
    """Required charge without AC: --battery-minimum, else SNAP_BATTERY_MINIMUM, else the pinned default
    (pins.json battery.default_minimum_without_ac: 50 since the user's 2026-10-19 rule; it was 80); floor 50."""
    policy = PINS['battery']
    if value is None:
        value = os.environ.get('SNAP_BATTERY_MINIMUM', policy['default_minimum_without_ac'])
    minimum = int(value)
    need(policy['floor'] <= minimum <= 100, f'battery minimum {minimum} is outside {policy["floor"]}..100')
    return minimum


def battery_ok(status, battery, minimum):
    return status == 0 and battery['plausible'] and (battery['ac'] or battery['percent'] >= minimum)


def load_proxy(ws):
    """q1n1proxy from this workspace's q1n1 checkout."""
    tools = str(ws.q / 'tools')
    if tools not in sys.path:
        sys.path.insert(0, tools)
    spec = importlib.util.spec_from_file_location('q1n1proxy', ws.q / 'tools/q1n1proxy.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules['q1n1proxy'] = module
    spec.loader.exec_module(module)
    return module


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def gpu_steps(ws):
    """The base launcher's GPU preparation steps, read from the pinned launcher itself."""
    base = ws.path(PINS['base_launcher']['path'])
    need(sha(base) == PINS['base_launcher']['sha256'], f'{base} changed')
    for node in ast.parse(base.read_text()).body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], 'id', None) == 'STEPS':
            return [name for name, _ in ast.literal_eval(node.value)]
    raise Refused(f'{base}: no STEPS list')


def stage_pair(ws, stages=None):
    """{absolute path: sha256} of the two chainload images, verified now."""
    stages = stages or PINS['stages']
    need(len(stages) == 2, 'a stage pair has exactly two images')
    pair = {}
    for relative, digest in stages.items():
        path = ws.path(relative)
        need(path.is_file() and sha(path) == digest, f'stage image {relative} is missing or changed')
        pair[str(path)] = digest
    paths = sorted(Path(p) for p in pair)
    primary = [p for p in paths if not p.name.endswith('-alt.bin')]
    need(len(primary) == 1 and primary[0].with_name(primary[0].name[:-4] + '-alt.bin') in paths,
         f'stage images {[p.name for p in paths]} are not a NAME.bin / NAME-alt.bin pair in one directory')
    return pair


def primary_stage(pair):
    """The NAME.bin of a stage pair (q1n1's pick_stage finds NAME-alt.bin beside it)."""
    return next(Path(p) for p in pair if not p.endswith('-alt.bin'))


def now():
    return time.time()
