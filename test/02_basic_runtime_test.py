# Copyright (C) 2021-2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

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

        testsig_src_file = self.path_source / 'test' / 'examples' / 'in' / 'lsig_simple2.c'
        testsig_out_file = self.path_tmp / 'sigs' / 'lsig_simple2.cbc'
        os.makedirs(testsig_out_file.parent, exist_ok=True)

        self.execute_command(f'{TC.clambcc} {testsig_src_file} -o {testsig_out_file} {TC.headers}')

        test_sample_path = self.path_tmp / 'samples'
        os.mkdir (test_sample_path)

        test_string='CLAMAV-TEST-STRING-NOT-EICAR'
        test_file = test_sample_path / 'testfile'
        self.execute_command(f'echo {test_string} > {test_file}')

        command = f'{TC.clamscan} --bytecode-unsigned -d {testsig_out_file} {test_sample_path}'
        output = self.execute_command(command)

        self.verify_output(output.out, expected='Clamav-Unit-Test-Signature.02 FOUND')
