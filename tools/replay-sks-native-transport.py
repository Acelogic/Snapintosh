#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Native SKS packing, startup and reply reception through real monitor DMA."""
from pathlib import Path
import argparse
import ast
import ctypes as C
import hashlib
import importlib.util
import json
import struct
import subprocess
import types
from source_text import read_source, source_files

ROOT = Path(__file__).resolve().parents[1]
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
spec = importlib.util.spec_from_file_location('mailbox', ROOT/'tools/replay-sks-mailbox.py')
mailbox = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mailbox)
startup = mailbox.startup


def fixture_classes(path, names, namespace):
    """Reuse DMA fixtures, not their superseded transport qualification gates."""
    source = path.read_text()
    selected = [n for n in ast.parse(source).body if isinstance(n, ast.ClassDef) and n.name in names]
    assert {n.name for n in selected} == set(names)
    for node in selected:
        exec(compile(ast.get_source_segment(source, node), str(path), 'exec'), namespace)
    return types.SimpleNamespace(**namespace)


ns = dict(C=C, mailbox=mailbox, startup=startup)
endpoint_source = (ROOT/'tools/replay-sks-endpoint.py').read_text()
# ctypes callback signatures are data shared with the unchanged native bridge.
begin, end = endpoint_source.index('class Endpoint('), endpoint_source.index('\nclass EndpointModel:')
exec(compile(endpoint_source[begin:end], 'endpoint-ctypes', 'exec'), ns)
endpoint = fixture_classes(ROOT/'tools/replay-sks-endpoint.py', ['EndpointModel'], ns)
device = fixture_classes(ROOT/'tools/replay-sks-device.py', ['Device'], dict(C=C, endpoint=endpoint))
monitor = fixture_classes(ROOT/'tools/replay-sks-monitor.py', ['Monitor'],
    dict(C=C, device=device, mailbox=mailbox, struct=struct))


class Sender:
    def __init__(self):
        self.native = mailbox.base.Native()
        # Bind every executed packing instruction and the command/sequence origins.
        sites = list(range(0x12844, 0x1285c, 4)) + [0x12134, 0x1230c, 0x12310,
            0x12730, 0x12744, 0x12b60, 0x12b64, 0x12b68, 0x12b6c, 0x12b70, 0x12b74]
        self.binding = mailbox.keystore_binding(self.native, sites)

    def pack(self, command, sequence, length):
        assert 0 <= command < 128 and 0 <= sequence < 256 and 0 <= length < 65536
        b = mailbox.base
        fp = b.STACK - 0x300
        for register, value in [(b.reg.UC_ARM64_REG_X29, fp), (b.reg.UC_ARM64_REG_X20, 0),
                (b.reg.UC_ARM64_REG_X23, command), (b.reg.UC_ARM64_REG_X24, sequence),
                (b.reg.UC_ARM64_REG_X21, length)]:
            self.native.u.reg_write(register, value)
        self.native.u.emu_start(0x12844, 0x1285c, count=6)
        word = struct.unpack('<Q', self.native.u.mem_read(fp-0x60, 8))[0]
        assert word & 255 == 0
        return word | 3  # Manager transport fills the negotiated endpoint ID.


class NativeTransport(monitor.Monitor):
    def __init__(self, library, sender):
        super().__init__(library)
        self.sender = sender
        self.sequence = 1
        self.transport = []

    def exchange(self, command, request):
        assert len(request) <= 0x8000
        C.memset(self.tx, 0x6d, 0x8000)
        C.memmove(self.tx, request, len(request))
        sequence = self.sequence
        word = self.sender.pack(command, sequence, len(request))
        self.sequence = (sequence+1) & 255
        result, response = self.submit(word)
        assert result == 0, (result, hex(word))
        # Historical helper's expected_command parameter is actually the sequence.
        observed = mailbox.KeyStoreReceiver().run(response, expected_command=sequence)
        status, length = response >> 24 & 255, response >> 48
        row = dict(command=command, sequence=sequence, request=hex(word), reply=hex(response),
            status=status, length=length, decision=observed['decision'])
        self.transport.append(row)
        assert response & 0xffffff == (word & 0xffffff) | 0x8000
        assert observed['wakes'] == 1
        assert observed['decision'] == ('return-status' if status else 'decode-payload')
        assert observed['result'] == hex(status)
        wrong = mailbox.KeyStoreReceiver().run(response, expected_command=(sequence+1)&255)
        assert wrong['decision'] == 'continue-wait'
        return status, self.rx.raw[:length]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output-dir', type=Path, required=True)
    args = ap.parse_args()
    out = args.output_dir.resolve()
    out.mkdir(exist_ok=False)
    crypto = ROOT.parent/'q1n1/platform/uefi'
    names = ['device','aic','watchdog','clock','dart','aes-engine','aes','mmio','sep-bootstrap',
        'sep-pnon','sep-xars','sep-sks','sep-sks-endpoint','ans','ans-window','nvme-host',
        'sptm-dart','sptm','sptm-refs']
    sources = [ROOT/'tools/sks-monitor-e2e-bridge.c'] + [ROOT/'compat'/f'{n}.c' for n in names] + [crypto/'sha256.c']
    helpers = ['replay-sks-native.py','replay-sks-replies.py','replay-sks-startup-model.py',
        'replay-sks-mailbox.py','replay-sks-endpoint.py','replay-sks-device.py','replay-sks-monitor.py',
        'sks-device-e2e-bridge.c','test-sptm-dart-sep.c','kc-xref.py','audit_sep_sks.py']
    pins = sources + [ROOT/'tools'/p for p in helpers] + [Path(__file__), ROOT/'probes/xnuboot.c',
        ROOT/'docs/SKS-GEN53-FAILURE-20260928.md'] + list((ROOT/'compat').glob('*.h'))
    pins += [q for p in pins if p.suffix == '.c' for q in source_files(p)[1:]]
    record = dict(status='RUNNING', hardware_access=False, inputs_sha256={str(p):sha(p) for p in pins})
    try:
        sender = Sender()
        record['native_binding'] = sender.binding
        assert sender.pack(0x2a, 2, 1128) == 0x0468000000022a03
        record['generation53_failed_request_reproduced'] = True
        source = read_source(ROOT/'probes/xnuboot.c')
        begin = source.index('struct sep_rom_dma_context {')
        end = source.index('\n};', begin)+3
        cb = source.index('static int sep_service_admit(')
        ce = source.index('static int sep_entropy32(', cb)
        header = out/'sks-monitor-callbacks.h'
        header.write_text(source[begin:end]+'\n'+source[cb:ce])
        record['callback_sha256'] = sha(header)
        command = ['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function',
            '-dynamiclib','-I'+str(ROOT/'compat'),'-I'+str(ROOT/'shadow'),'-I'+str(ROOT/'tools'),
            '-I'+str(crypto),'-I'+str(out),*[str(p) for p in sources],'-o',str(out/'monitor.dylib')]
        compiled = subprocess.run(command, text=True, capture_output=True)
        (out/'build.log').write_text(compiled.stdout+compiled.stderr)
        record['build'] = dict(command=command, exit=compiled.returncode)
        assert compiled.returncode == 0, compiled.stderr
        model = NativeTransport(out/'monitor.dylib', sender)
        model.negotiate()
        native = startup.Startup(model)
        result = native.invoke(0x1359c)
        assert result == 0 and model.state.wire.updates == 1 and model.state.queries == 2
        assert model.library.sks_monitor_scratch_clear() == 1
        assert model.library.sks_monitor_publications() == 2
        request = bytes.fromhex(native.exchanges[1]['request_hex'])
        model.sequence = 255
        for sequence in [255, 0]:
            status, reply = model.exchange(0x2a, request)
            assert status == 0 and len(reply) == 88 and model.transport[-1]['sequence'] == sequence
        audit_spec = importlib.util.spec_from_file_location('audit_sks', ROOT/'tools/audit_sep_sks.py')
        audit = importlib.util.module_from_spec(audit_spec)
        audit_spec.loader.exec_module(audit)
        assert all(audit.reply_shape(int(row['reply'],16)) for row in model.transport)
        counters = model.counters()
        assert counters['pending'] == counters['replies'] == 0
        assert counters['submitted'] == counters['consumed'] and counters['published'] == counters['delivered']
        assert model.state.wire.updates == 3 and model.library.sks_monitor_scratch_clear() == 1
        record.update(status='NATIVE_SKS_TRANSPORT_DMA_QUALIFIED', startup_result=result,
            counters=counters, environment_updates=model.state.wire.updates,
            cache_publications=model.library.sks_monitor_publications(), wrong_sequence_rejected=True,
            library_sha256=sha(out/'monitor.dylib'))
    except Exception as error:
        record.update(status='FAILED', error=repr(error))
        raise
    finally:
        if 'model' in locals():
            record.update(transport=model.transport, events=model.events, counters=model.counters())
        record['boundary'] = 'Native packing instructions and startup/receiver through actual device and monitor DMA; RAM and kernel imports are fixtures. No hardware startup or GUI qualification.'
        (out/'qualification.json').write_text(json.dumps(record, indent=2)+'\n')
        print(json.dumps(dict(status=record['status'], output=str(out/'qualification.json'))))


if __name__ == '__main__':
    main()
