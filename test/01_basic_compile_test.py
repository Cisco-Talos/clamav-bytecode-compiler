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

    @unittest.expectedFailure
    def test_00_version(self):
        self.step_name('clambcc version test')

        command = '{clambcc} -V'.format(
            clambcc=TC.clambcc
        )
        output = self.execute_command(command)

        assert output.ec == 0  # success

        expected_results = [
            'ClamBC-Compiler {}'.format(TC.version),
        ]
        self.verify_output(output.out, expected=expected_results)

    def test_01_compile_all_o0_examples(self):
        self.step_name('Test that clambcc can compile a basic signature')

        testpaths = list((TC.path_source / 'test' / 'examples' / 'in').glob('*.o0.c')) # A list of Path()'s of each of our generated test files

        testfiles = ' '.join([str(testpath) for testpath in testpaths])
        for testfile in testpaths:

            outfile = (TC.path_tmp / testfile.name).with_suffix('.cbc')

            command = '{clambcc} -O0 {testfile} -o {outfile} {headers}'.format(
                clambcc=TC.clambcc,
                testfile=testfile,
                outfile=outfile,
                headers=TC.headers
            )
            output = self.execute_command(command)

            expected_results = []
            unexpected_results = ["error: "]
            self.verify_output(output.err, expected=expected_results, unexpected=unexpected_results)

            assert output.ec == 0
            assert outfile.exists()

#Removed the following tests because -O1 and -O2, when run by clang, currently inserts unsupported intrinsic
#calls into the IR, that need to be investigated.
#    def test_01_compile_all_o1_examples(self):
#        self.step_name('Test that clambcc can compile a basic signature')
#
#        testpaths = list((TC.path_source / 'test' / 'examples' / 'in').glob('*.o1.c')) # A list of Path()'s of each of our generated test files
#
#        testfiles = ' '.join([str(testpath) for testpath in testpaths])
#        for testfile in testpaths:
#
#            outfile = (TC.path_tmp / testfile.name).with_suffix('.cbc')
#
#            command = '{clambcc} -O1 {testfile} -o {outfile} {headers}'.format(
#                clambcc=TC.clambcc,
#                testfile=testfile,
#                outfile=outfile,
#                headers=TC.headers
#            )
#            output = self.execute_command(command)
#
#            expected_results = []
#            unexpected_results = ["error: "]
#            self.verify_output(output.err, expected=expected_results, unexpected=unexpected_results)
#
#            assert output.ec == 0
#            assert outfile.exists()
#
#    def test_01_compile_all_o2_examples(self):
#        self.step_name('Test that clambcc can compile a basic signature')
#
#        testpaths = list((TC.path_source / 'test' / 'examples' / 'in').glob('*.o2.c')) # A list of Path()'s of each of our generated test files
#
#        testfiles = ' '.join([str(testpath) for testpath in testpaths])
#        for testfile in testpaths:
#
#            outfile = (TC.path_tmp / testfile.name).with_suffix('.cbc')
#
#            command = '{clambcc} -O2 {testfile} -o {outfile} {headers}'.format(
#                clambcc=TC.clambcc,
#                testfile=testfile,
#                outfile=outfile,
#                headers=TC.headers
#            )
#            output = self.execute_command(command)
#
#            expected_results = []
#            unexpected_results = ["error: "]
#            self.verify_output(output.err, expected=expected_results, unexpected=unexpected_results)
#
#            assert output.ec == 0
#            assert outfile.exists()
