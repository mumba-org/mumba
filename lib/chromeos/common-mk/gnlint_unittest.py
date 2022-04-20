#!/usr/bin/env python3
# Copyright 2019 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Unittests for gnlint."""

import logging
import os
import sys
import unittest

import gnlint

# Find chromite!
sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.realpath(__file__)), '..', '..', '..'))

# pylint: disable=wrong-import-position
from chromite.lib import commandline
from chromite.lib import cros_test_lib
from chromite.lib import osutils
# pylint: enable=wrong-import-position

# stub error location dict.
# Used by test data to verify the right node is included in an error.
STUB_ERROR_LOCATION = {
    'begin_column': 4,
    'begin_line': 5,
    'end_column': 6,
    'end_line': 7,
}


class LintTestCase(cros_test_lib.TestCase):
    """Helper for running linters."""

    def _CheckLinter(self, functor, inputs, is_bad_input=True):
        """Make sure |functor| rejects or accepts every input in |inputs|.

        When is_bad_input is true, the expected error location in the input
        should be filled with STUB_ERROR_LOCATION and the other nodes should
        not have it as the location of the node.
        """
        # First run a sanity check.
        ret = functor(self.STUB_DATA)
        self.assertEqual(ret, [])

        # Then run through all the bad inputs.
        for x in inputs:
            ret = functor(x)
            if is_bad_input:
                self.assertNotEqual(ret, [])
                for e in ret:
                    self.assertEqual(e.location, STUB_ERROR_LOCATION)
            else:
                self.assertEqual(ret, [])


class UtilityTests(cros_test_lib.MockTestCase):
    """Tests for utility funcs."""

    def testFilterFiles(self):
        """Check filtering of files based on extension works."""
        exp = [
            'cow.gn',
            'cow.gni',
        ]
        files = [
            '.gitignore',
            '.gitignore.gn',
            'cow.gn',
            'cow.gn.orig',
            'cow.gni',
            'gn',
            'README.md',
        ]
        extensions = set(('gn', 'gni'))
        result = sorted(gnlint.FilterFiles(files, extensions))
        self.assertEqual(result, exp)

    def testGetParser(self):
        """Make sure it doesn't crash."""
        parser = gnlint.GetParser()
        self.assertTrue(isinstance(parser, commandline.ArgumentParser))

    def testMain(self):
        """Make sure it doesn't crash."""
        gnlint.main(['foo'])

    def testMainErrors(self):
        """Make sure outputting results doesn't crash."""
        self.PatchObject(
            gnlint,
            'CheckGnFile',
            return_value=[
                gnlint.LintResult('LintFunc', 'foo.gn', None, 'msg!',
                                  logging.ERROR),
            ])
        gnlint.main(['foo.gn'])


class FilesystemUtilityTests(cros_test_lib.MockTempDirTestCase):
    """Tests for utility funcs that access the filesystem."""

    @unittest.skipIf(not os.path.exists(gnlint.GetGnPath()),
                     'Skipping since gn is not available: crbug.com/1078990.')
    def testCheckGnFile(self):
        """Check CheckGnFile tails down correctly."""
        content = '# gn file\n'
        gnfile = os.path.join(self.tempdir, 'asdf')
        osutils.WriteFile(gnfile, content)
        self.assertExists(gnlint.GetGnPath())
        ret = gnlint.CheckGnFile(gnfile)
        self.assertEqual(ret, [])

    @unittest.skipIf(not os.path.exists(gnlint.GetGnPath()),
                     'Skipping since gn is not available: crbug.com/1078990.')
    def testGnFileOption(self):
        """Check CheckGnFile processes file options correctly."""
        static_library_with_visibility_flag = (
            'static_library("a") {\n'
            '  cflags = [ "-fvisibility=default" ]\n'
            '}\n')
        gn_options = '#gnlint: disable=GnLintVisibilityFlags\n'
        gnfile = os.path.join(self.tempdir, 'asdf')
        osutils.WriteFile(gnfile, static_library_with_visibility_flag)
        self.assertExists(gnlint.GetGnPath())
        ret = gnlint.CheckGnFile(gnfile)
        self.assertEqual(len(ret), 1)
        osutils.WriteFile(gnfile,
                          gn_options + static_library_with_visibility_flag)
        ret = gnlint.CheckGnFile(gnfile)
        self.assertEqual(ret, [])

    @unittest.skipIf(not os.path.exists(gnlint.GetGnPath()),
                     'Skipping since gn is not available: crbug.com/1078990.')
    def testCheckFormatDetectError(self):
        """Check CheckGnFile detects non-standard format."""
        content = 'executable("foo"){\n}\n'  # no space after ')'
        gnfile = os.path.join(self.tempdir, 'asdf')
        osutils.WriteFile(gnfile, content)
        self.assertExists(gnlint.GetGnPath())
        ret = gnlint.CheckGnFile(gnfile)
        self.assertEqual(len(ret), 1)

    def testFilterPaths(self):
        """Check filtering of files in subdirs."""
        subfile = os.path.join(self.tempdir, 'a/b/c.gn')
        osutils.Touch(subfile, makedirs=True)
        subdir = os.path.join(self.tempdir, 'src')
        for f in ('blah.gni', 'Makefile', 'source.cc'):
            osutils.Touch(os.path.join(subdir, f), makedirs=True)

        exp = sorted([
            os.path.join(subdir, 'blah.gni'),
            subfile,
        ])
        paths = [
            subdir,
            subfile,
        ]
        extensions = set(('gn', 'gni'))
        result = sorted(gnlint.FilterPaths(paths, extensions))
        self.assertEqual(result, exp)


def CreateTestData(flag_name, operator, value):
    """Creates dictionary for testing simple assignment in a static_library.

    The assigned literal is set to be the error location when an error is
    expected for the input.
    """
    # static_library("my_static_library") {
    #   <flag_name> <operator> [ <value> ]
    # }
    #
    # for example, when flag_name='cflags', operator='+=', value='"-lfoo"',
    # the result stands for a gn file like this:
    # static_library("my_static_library") {
    #   cflags += [ "-lfoo" ]
    # }
    if not isinstance(value, list):
        value = [value]
    value_list = []
    for item in value:
        value_list.append({
            'location': STUB_ERROR_LOCATION,
            'type': 'LITERAL',
            'value': item,
        })
    return {
        'child': [{
            'child': [{
                'child': [{
                    'type': 'LITERAL',
                    'value': '\"my_static_library\"'
                }],
                'type': 'LIST'
            }, {
                'child': [{
                    'child': [{
                        'type': 'IDENTIFIER',
                        'value': flag_name
                    }, {
                        'child': value_list,
                        'type': 'LIST'
                    }],
                    'type': 'BINARY',
                    'value': operator
                }],
                'type': 'BLOCK'
            }],
            'type': 'FUNCTION',
            'value': 'static_library'
        }],
        'type': 'BLOCK'
    }


class GnLintTests(LintTestCase):
    """Tests of various gn linters."""
    STUB_DATA = {'type': 'BLOCK'}

    def testGnLintLibFlags(self):
        """Verify GnLintLibFlags catches bad inputs."""

        self._CheckLinter(gnlint.GnLintLibFlags, [
            CreateTestData('ldflags', '=', '-lfoo'),
            CreateTestData('ldflags', '+=', '-lfoo'),
            CreateTestData('ldflags', '-=', '-lfoo'),
        ])

    def testGnLintVisibilityFlags(self):
        """Verify GnLintVisibilityFlags catches bad inputs."""
        self._CheckLinter(gnlint.GnLintVisibilityFlags, [
            CreateTestData('cflags', '=', '"-fvisibility"'),
            CreateTestData('cflags', '+=', '"-fvisibility"'),
            CreateTestData('cflags', '-=', '"-fvisibility=default"'),
            CreateTestData('cflags_c', '-=', '"-fvisibility=hidden"'),
            CreateTestData('cflags_cc', '-=', '"-fvisibility=internal"'),
        ])

    def testGnLintDefineFlags(self):
        """Verify GnLintDefineFlags catches bad inputs."""
        self._CheckLinter(gnlint.GnLintDefineFlags, [
            CreateTestData('cflags', '=', '"-D_FLAG"'),
            CreateTestData('cflags', '+=', '"-D_FLAG"'),
            CreateTestData('cflags', '-=', '"-D_FLAG=1"'),
            CreateTestData('cflags_c', '=', '"-D_FLAG=0"'),
            CreateTestData('cflags_cc', '=', '"-D_FLAG=\"something\""'),
        ])

    def testGnLintCommonTesting(self):
        """Verify GnLintCommonTesting catches bad inputs."""
        self._CheckLinter(gnlint.GnLintCommonTesting, [
            CreateTestData('libs', '=', '"gmock"'),
            CreateTestData('libs', '=', '"gtest"'),
            CreateTestData('libs', '=', ['"gmock"', '"gtest"'])
        ])

    def testGnLintDefines(self):
        """Verify GnLintDefines catches bad inputs."""
        self._CheckLinter(gnlint.GnLintDefines, [
            CreateTestData('defines', '=', '"-DDEBUG_FLAG"'),
            CreateTestData('defines', '=', '"DEBUG-FLAG"'),
            CreateTestData('defines', '=', '"-DTEST_VALUE=1"'),
            CreateTestData('defines', '=', '"TEST-VALUE=1"'),
        ])

    def testGnLintStaticSharedLibMixing(self):
        """Verify GnLintStaticSharedLibMixing catches bad inputs."""
        # static_library("static_pie") {
        #   configs += [ "//common-mk:pie" ]
        # }
        # shared_library("shared") {
        #   deps = [ ":static_pie" ]
        # }
        self._CheckLinter(gnlint.GnLintStaticSharedLibMixing, [{
            'child': [{
                'child': [{
                    'child': [{
                        'type': 'LITERAL',
                        'value': '\"static_pie\"'
                    }],
                    'type': 'LIST'
                }, {
                    'child': [{
                        'child': [{
                            'type': 'IDENTIFIER',
                            'value': 'configs'
                        }, {
                            'child': [{
                                'type': 'LITERAL',
                                'value': '\"//common-mk:pie\"'
                            }],
                            'type': 'LIST'
                        }],
                        'type': 'BINARY',
                        'value': '+='
                    }],
                    'type': 'BLOCK'
                }],
                'location': STUB_ERROR_LOCATION,
                'type': 'FUNCTION',
                'value': 'static_library'
            }, {
                'child': [{
                    'child': [{
                        'type': 'LITERAL',
                        'value': '\"shared\"'
                    }],
                    'type': 'LIST'
                }, {
                    'child': [{
                        'child': [{
                            'type': 'IDENTIFIER',
                            'value': 'deps'
                        }, {
                            'child': [{
                                'type': 'LITERAL',
                                'value': '\":static_pie\"'
                            }],
                            'type': 'LIST'
                        }],
                        'type': 'BINARY',
                        'value': '='
                    }],
                    'type': 'BLOCK'
                }],
                'type': 'FUNCTION',
                'value': 'shared_library'
            }],
            'type': 'BLOCK'
        }])

        # Negative test case which makes linked library PIC. Should be accepted.
        # static_library("static_pic") {
        #   configs += [ "//common-mk:pic" ]
        #   configs -= [ "//common-mk:pie" ]
        # }
        # shared_library("shared") {
        #   deps = [ ":static_pic" ]
        # }
        self._CheckLinter(
            gnlint.GnLintStaticSharedLibMixing, [{
                'child': [{
                    'child': [{
                        'child': [{
                            'type': 'LITERAL',
                            'value': '\"static_pic\"'
                        }],
                        'type': 'LIST'
                    }, {
                        'child': [{
                            'child': [{
                                'type': 'IDENTIFIER',
                                'value': 'configs'
                            }, {
                                'child': [{
                                    'type': 'LITERAL',
                                    'value': '\"//common-mk:pic\"'
                                }],
                                'type': 'LIST'
                            }],
                            'type': 'BINARY',
                            'value': '+='
                        }, {
                            'child': [{
                                'type': 'IDENTIFIER',
                                'value': 'configs'
                            }, {
                                'child': [{
                                    'type': 'LITERAL',
                                    'value': '\"//common-mk:pie\"'
                                }],
                                'type': 'LIST'
                            }],
                            'type': 'BINARY',
                            'value': '-='
                        }],
                        'type': 'BLOCK'
                    }],
                    'type': 'FUNCTION',
                    'value': 'static_library'
                }, {
                    'child': [{
                        'child': [{
                            'type': 'LITERAL',
                            'value': '\"shared\"'
                        }],
                        'type': 'LIST'
                    }, {
                        'child': [{
                            'child': [{
                                'type': 'IDENTIFIER',
                                'value': 'deps'
                            }, {
                                'child': [{
                                    'type': 'LITERAL',
                                    'value': '\":static_pic\"'
                                }],
                                'type': 'LIST'
                            }],
                            'type': 'BINARY',
                            'value': '='
                        }],
                        'type': 'BLOCK'
                    }],
                    'type': 'FUNCTION',
                    'value': 'shared_library'
                }],
                'type': 'BLOCK'
            }],
            is_bad_input=False)

    def testGnLintSourceFileNames(self):
        """Verify GnLintSourceFileNames catches bad inputs."""
        self._CheckLinter(gnlint.GnLintSourceFileNames, [
            CreateTestData('sources', '=', 'foo_unittest.c'),
            CreateTestData('sources', '=', 'foo_unittest.cc'),
            CreateTestData('sources', '=', 'foo_unittest.h'),
        ])

    def testGnLintPkgConfigs(self):
        """Verify GnLintPkgConfigs catches bad inputs."""
        self._CheckLinter(gnlint.GnLintPkgConfigs, [
            CreateTestData('libs', '=', 'z'),
            CreateTestData('libs', '=', 'ssl'),
        ])

    def testGnLintOrderingWithinTarget(self):
        """Verify GnLintOrderingWithinTarget catches bad inputs."""
        # static_library("my_static_library") {
        #   configs = [ "foo" ]
        #   sources = [ "bar" ]
        # }
        self._CheckLinter(gnlint.GnLintOrderingWithinTarget, [{
            'child': [{
                'child': [{
                    'child': [{
                        'type': 'LITERAL',
                        'value': '\"my_static_library\"'
                    }],
                    'type': 'LIST'
                }, {
                    'child': [{
                        'child': [{
                            'type': 'IDENTIFIER',
                            'value': 'configs'
                        }, {
                            'child': ['foo'],
                            'type': 'LIST'
                        }],
                        'type': 'BINARY',
                        'value': '='
                    }, {
                        'child': [{
                            'type': 'IDENTIFIER',
                            'value': 'sources'
                        }, {
                            'child': ['bar'],
                            'type': 'LIST'
                        }],
                        'location': STUB_ERROR_LOCATION,
                        'type': 'BINARY',
                        'value': '='
                    }],
                    'type': 'BLOCK'
                }],
                'type': 'FUNCTION',
                'value': 'static_library'
            }],
            'type': 'BLOCK'
        }])

        # static_library("my_static_library") {
        #   sources = [ "foo" ]
        #   configs = [ "bar" ]
        # }
        self._CheckLinter(
            gnlint.GnLintOrderingWithinTarget, [{
                'child': [{
                    'child': [{
                        'child': [{
                            'type': 'LITERAL',
                            'value': '\"my_static_library\"'
                        }],
                        'type': 'LIST'
                    }, {
                        'child': [{
                            'child': [{
                                'type': 'IDENTIFIER',
                                'value': 'sources'
                            }, {
                                'child': ['foo'],
                                'type': 'LIST'
                            }],
                            'type': 'BINARY',
                            'value': '='
                        }, {
                            'child': [{
                                'type': 'IDENTIFIER',
                                'value': 'configs'
                            }, {
                                'child': ['bar'],
                                'type': 'LIST'
                            }],
                            'type': 'BINARY',
                            'value': '='
                        }],
                        'type': 'BLOCK'
                    }],
                    'type': 'FUNCTION',
                    'value': 'static_library'
                }],
                'type': 'BLOCK'
            }],
            is_bad_input=False)


if __name__ == '__main__':
    cros_test_lib.main(module=__name__)
