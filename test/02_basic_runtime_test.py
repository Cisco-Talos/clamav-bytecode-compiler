# Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
The tests in this file check that clambcc is able to compile the example
bytecode signatures.
"""

import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import time
import unittest

import testcase


os_platform = platform.platform()
operating_system = os_platform.split('-')[0].lower()


class TC(testcase.TestCase):
    @classmethod
    def setUpClass(cls):
        super(TC, cls).setUpClass()

    @classmethod
    def tearDownClass(cls):
        super(TC, cls).tearDownClass()

    def setUp(self):
        super(TC, self).setUp()

    def tearDown(self):
        super(TC, self).tearDown()
        self.verify_valgrind_log()

    def test_00_run_test(self):
        self.step_name('Test that clamscan can run a specific signature.')

        testPath = os.path.join(TC.path_source , 'test' , '02' , 'Sig.c')

        SIGDIR = 'sigs'
        os.mkdir(SIGDIR)

        self.execute_command(f'{TC.clambcc} {testPath} -o {SIGDIR} {TC.headers}')

        SAMPLEDIR = 'samples'
        os.mkdir (SAMPLEDIR)

        SIGSTRING='CLAMAV-TEST-STRING-NOT-EICAR'
        outFile = os.path.join(SAMPLEDIR, 'file')
        self.execute_command (f'echo {SIGSTRING} > {outFile}')

        command = f'{self.clamscan} --bytecode-unsigned -d {SIGDIR} {SAMPLEDIR}'
        output = self.execute_command (command)

        self.verify_output(output.out, expected='Clamav-Unit-Test-Signature.02 FOUND')





