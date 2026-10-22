#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'probes'))
import run


class ServiceLock(unittest.TestCase):
    def test_native_ownership_stop_and_contention(self):
        with tempfile.TemporaryDirectory() as directory:
            binary=str(Path(directory)/'lock-test')
            subprocess.run(['clang','-std=gnu11','-O1','-g','-pthread',
                '-fsanitize=address,undefined','-Icompat','tools/test-service-lock.c',
                'compat/service-lock.c','-o',binary],cwd=ROOT,check=True,timeout=30)
            subprocess.run([binary],check=True,timeout=30)

    def test_native_executor_lifecycle(self):
        with tempfile.TemporaryDirectory() as directory:
            binary=str(Path(directory)/'lifecycle-test')
            subprocess.run(['clang','-std=gnu11','-O1','-g','-pthread',
                '-fsanitize=address,undefined','-Icompat','tools/test-executor-lifecycle.c',
                'compat/service-lock.c','-o',binary],cwd=ROOT,check=True,timeout=30)
            subprocess.run([binary],check=True,timeout=30)

    def test_failure_overrides_old_log_and_panic_text(self):
        cases=[{'service_owner':1}, {'service_stop':2<<32|1},
               {'service_stop':1<<32|7}, {'service_stop':1},
               {'service_faults':(0,0,0,0,0,6)},
               {'service_reusable':0}, {'service_lifecycle':0},
               {'service_lifecycle':(1<<63)|3|(1<<3)},
               {'service_lifecycle':(1<<63)|3|(2<<3)},
               {'service_lifecycle':(1<<63)|3|(3<<3)},
               {'service_lifecycle':(1<<63)|2},
               {'service_lifecycle':(1<<63)|3|(1<<40)},
               {'service_lifecycle':(1<<63)|3,'service_reusable':1},
               {'service_lifecycle':(1<<63)|3,'service_stop':1<<32|1},
               {'service_reusable':1,'service_stop':1<<32|1}]
        for tally in cases:
            code, reason=run.conclude(1,0,'',[],tally=tally,dropped=500,
                                     panic_said='old guest panic')
            self.assertEqual(code,run.EXIT_EL2_FAULT)
            self.assertIn('service lock failure',reason)

    def test_normal_stop_does_not_invent_monitor_failure(self):
        for cpu in range(6):
            tally={'service_owner':0,'service_stop':1<<32|(cpu+1),
                   'service_faults':(0,)*6, 'service_lifecycle':(1<<63)|3,
                   'service_reusable':1}
            code,reason=run.classify(1,0,'',[],tally=tally)
            self.assertNotEqual(code,run.EXIT_EL2_FAULT)
            self.assertNotIn('service lock',reason)


if __name__=='__main__': unittest.main()
