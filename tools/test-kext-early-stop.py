#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The Adreno kext's early-stop request, host side. No hardware.

Harness: the real gpu/adreno-kext/kext/src/AdrenoEarlyStop.cpp, compiled for user space against minimal
IOService/OSData/IOLog stand-ins written below, with the monitor played by a SIGILL handler
(tools/test-kext-early-stop.cpp): inert without the launch's advertisement, one request per boot, the
registers the monitor reads, its answer passed back, and one request out of many racing threads. ASan/UBSan
for every scenario, TSan for the race.

Build: the real kext from gpu/adreno-kext/kext/build.sh, in a temporary directory. The request is exactly the
instruction compat/early-stop.c admits (hvc #0xad16) with x0 = ADRENO_GUEST_STOP, and the hooks are linked
where they belong: AdrenoDisplay::presentGated asks on the first present, configureDevice reads the
advertisement, the accelerator's setProperties override takes the plug-in's report, and AdrenoTask::free
reports the end of WindowServer's GPU task (reason 3) before IOGPUTask::free.

    python3 tools/test-kext-early-stop.py
"""
from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
KEXT = ROOT / 'gpu/adreno-kext/kext'
HARNESS = ROOT / 'tools/test-kext-early-stop.cpp'
SCENARIOS = ('inert', 'refused', 'present', 'failure', 'died', 'after', 'race')
OBJDUMP = '/opt/homebrew/opt/llvm/bin/llvm-objdump'

# Only what AdrenoEarlyStop.cpp uses of each kernel header.
STANDINS = {
    'libkern/c++/OSData.h': '''#pragma once
#include <stdint.h>
#include <vector>
class OSObject { public: virtual ~OSObject() {} };
class OSData : public OSObject {
public:
    std::vector<uint8_t> bytes;
    unsigned int getLength() const { return (unsigned int)bytes.size(); }
    const void *getBytesNoCopy() const { return bytes.data(); }
};
#define OSDynamicCast(type, instance) dynamic_cast<type *>(instance)
''',
    'IOKit/IOService.h': '''#pragma once
#include <libkern/c++/OSData.h>
#include <map>
#include <string>
class IOService : public OSObject {
public:
    std::map<std::string, OSObject *> properties;
    OSObject *getProperty(const char *name) const
    {
        auto found = properties.find(name);
        return found == properties.end() ? nullptr : found->second;
    }
};
''',
    'IOKit/IOLib.h': '''#pragma once
#include <stdio.h>
#include <strings.h>
#define IOLog(...) printf(__VA_ARGS__)
''',
}


class Harness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix='kext-early-stop-')
        directory = Path(cls.scratch.name)
        for name, text in STANDINS.items():
            (directory / 'include' / name).parent.mkdir(parents=True, exist_ok=True)
            (directory / 'include' / name).write_text(text)
        cls.binaries = {}
        for variant, sanitizers in (('asan', 'address,undefined'), ('tsan', 'thread')):
            binary = directory / f'harness-{variant}'
            subprocess.run(['xcrun', 'clang++', '-std=gnu++17', '-O1', '-g', f'-fsanitize={sanitizers}',
                            '-Wall', '-Wextra', '-Werror', '-I' + str(directory / 'include'),
                            str(HARNESS), str(KEXT / 'src/AdrenoEarlyStop.cpp'), '-o', str(binary)],
                           check=True, timeout=300)
            cls.binaries[variant] = binary

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def run_scenario(self, variant, name):
        result = subprocess.run([str(self.binaries[variant]), name], capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f'PASS {name}', result.stdout)
        return result.stdout

    def test_scenarios_under_asan_and_ubsan(self):
        for name in SCENARIOS:
            with self.subTest(name):
                self.run_scenario('asan', name)

    def test_race_under_tsan(self):
        self.run_scenario('tsan', 'race')

    def test_the_request_is_logged(self):
        output = self.run_scenario('asan', 'present')
        self.assertIn('early stop enabled by this launch', output)
        self.assertIn('early stop requested: reason 1, detail 0x2a, delay 20s -> status 0, accepted 20s', output)


class Build(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(prefix='kext-early-stop-build-')
        env = dict(os.environ, OUT=cls.scratch.name)
        subprocess.run(['sh', str(KEXT / 'build.sh')], check=True, timeout=900, env=env, capture_output=True)
        cls.binary = Path(cls.scratch.name) / 'AdrenoX2.kext/Contents/MacOS/AdrenoX2'
        cls.text = subprocess.run([OBJDUMP, '-d', '--no-show-raw-insn', str(cls.binary)], capture_output=True,
                                  text=True, check=True).stdout
        cls.raw = subprocess.run([OBJDUMP, '-d', str(cls.binary)], capture_output=True, text=True,
                                 check=True).stdout

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def function(self, text, pattern):
        found = re.search(r'<(' + pattern + r')>:\n(.*?)\n\n', text, re.S)
        self.assertIsNotNone(found, pattern)
        return found[2]

    def test_request_is_the_admitted_instruction(self):
        # compat/early-stop.c admits only the word HVC_WORD(ADRENO_GUEST_HVC) = hvc #0xad16.
        request = self.function(self.raw, r'__Z\d+AdrenoEarlyStopRequest\w*')
        self.assertIn('d415a2c2', request.replace(' ', ''))
        self.assertRegex(request, r'mov\s+[wx]0, #0x6\b')               # x0 = ADRENO_GUEST_STOP 0x00010006
        self.assertRegex(request, r'movk\s+[wx]0, #0x1, lsl #16')

    def test_hooks_are_linked_where_they_belong(self):
        present = self.function(self.text, r'__ZN13AdrenoDisplay12presentGatedEP\w+')
        self.assertRegex(present, r'bl\s+\S+ <__Z\d+AdrenoEarlyStopPresented\w*>')
        configure = self.function(self.text, r'__ZN19AdrenoAcceleratorX215configureDeviceEP9IOService')
        self.assertRegex(configure, r'bl\s+\S+ <__Z\d+AdrenoEarlyStopConfigure\w*>')
        report = self.function(self.text, r'__ZN19AdrenoAcceleratorX213setPropertiesEP8OSObject')
        self.assertRegex(report, r'bl\s+\S+ <__Z\d+AdrenoEarlyStopRequest\w*>')
        ended = self.function(self.text, r'__ZN10AdrenoTask4freeEv')
        self.assertRegex(ended, r'bl\s+\S+ <__Z\d+AdrenoEarlyStopClientDied\w*>')



if __name__ == '__main__':
    unittest.main()
