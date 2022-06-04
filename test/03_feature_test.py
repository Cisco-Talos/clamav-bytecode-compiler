# Copyright (C) 2022 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

"""
The tests in this file are to verify behavior for assorted signature features.
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

    def test_00_no_copyright(self):
        self.step_name('Test that without COPYRIGHT() function, source is included with compiled sig.')

        testsig_src_file = self.path_source / 'test' / 'examples' / 'in' / 'lsig_simple2.c'
        testsig_out_file = self.path_tmp / 'sigs' / 'lsig_simple2.cbc'
        os.makedirs(testsig_out_file.parent, exist_ok=True)

        self.execute_command(f'{self.clambcc} {testsig_src_file} -o {testsig_out_file} {self.headers}')

        command = f'{self.clambc} --printsrc {testsig_out_file}'
        output = self.execute_command(command)

        self.verify_output(
            output.out,
            expected=r'VIRUSNAME_PREFIX\("Clamav-Unit-Test-Signature.02"\)',
            unexpected='Cisco 2022'
        )

    def test_01_has_copyright(self):
        self.step_name('Test that with COPYRIGHT() function, source is excluded from compiled sig.')

        testsig_src_file = self.path_source / 'test' / 'examples' / 'in' / 'lsig_copyright.c'
        testsig_out_file = self.path_tmp / 'sigs' / 'lsig_copyright.cbc'
        os.makedirs(testsig_out_file.parent, exist_ok=True)

        self.execute_command(f'{self.clambcc} {testsig_src_file} -o {testsig_out_file} {self.headers}')

        command = f'{self.clambc} --printsrc {testsig_out_file}'
        output = self.execute_command(command)

        self.verify_output(
            output.out,
            expected='Cisco 2022',
            unexpected=r'VIRUSNAME_PREFIX\("Clamav-Unit-Test-Signature.02"\)'
        )
