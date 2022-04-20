#!/usr/bin/env python3
# Copyright 2019 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Linter for checking GN files used in platform2 projects."""

# This linter utilizes the token tree parser of the gn binary.
# For example,
#
# executable("my_target") {
#   sources = [ "foo.cc", "bar.cc" ]
# }
#
# is parsed to a token tree by gn-format subcommand, like this:
#
# BLOCK
#  FUNCTION(executable)
#   LIST
#    LITERAL("my_target")
#   BLOCK
#    BINARY(=)
#     IDENTIFIER(sources)
#     LIST
#      LITERAL("foo.cc")
#      LITERAL("bar.cc")
#
# The above example is expressed as a JSON like this and imported into dict:
# {
#    "type": "BLOCK",
#    "child": [ {
#       "type": "FUNCTION",
#       "value": "executable"
#       "child": [ {
#          "type": "LIST",
#          "child": [ {
#             "type": "LITERAL"],
#             "value": "\"my_target\""
#          } ]
#       }, {
#          "type": "BLOCK",
#          "child": [ {
#             "type": "BINARY",
#             "value": "=",
#             "child": [ {
#                "type": "IDENTIFIER",
#                "value": "sources"
#             }, {
#                "type": "LIST",
#                "child": [ {
#                   "type": "LITERAL",
#                   "value": "\"foo.cc\""
#                }, {
#                   "type": "LITERAL",
#                   "value": "\"bar.cc\""
#                } ]
#             } ]
#          } ]
#       } ]
#    } ]
# }
# The tree structure is expressed by "child" key having list of nodes in it.
# Every dict in the nested structure represents a single node.

import json
import logging
import os
import re
import subprocess
import sys
import typing

# Find chromite!
chromite_root = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), '..', '..', '..')
sys.path.insert(0, chromite_root)

# pylint: disable=wrong-import-position
from chromite.lib import commandline
from chromite.lib import cros_build_lib
# pylint: enable=wrong-import-position


class LintResult(typing.NamedTuple):
    """Object holding the result of a lint check."""
    # The name of the linter checking.
    linter: str
    # The file the issue was found in.
    file: str
    # The location in the file where the issue was found.
    # None when it's not tied to a specific line (e.g. file not found).
    location: typing.Dict
    # The message for this check.
    msg: str
    # The type of result -- logging.ERROR or logging.WARNING.
    type: int


class Issue(typing.NamedTuple):
    """Object holding an issue found by a linter."""
    # The location in the file where the issue was found.
    location: typing.Dict
    # The message for this check.
    msg: str


class LintSettings(typing.NamedTuple):
    """Object holding linter settings."""
    # Linters to skip.
    skip: set
    # Problems we found in the lint settings themselves.
    issues: typing.List


def FormatLocation(file, location):
    """Formats the file name and the node location"""
    return '%s:%d:%d' % (
        file,
        location.get('begin_line'),
        location.get('begin_column'),
    )


def GetNodeValue(node):
    """Extracts the string value from a node of a GN syntax tree node"""
    # Literal nodes of a string value contains double quotes.
    return Unquote(node.get('value'))


def FilterFiles(files, extensions):
    """Filter out |files| based on |extensions|."""
    for f in files:
        # Chop of the leading period as we'll get back ".bin".
        extension = os.path.splitext(f)[1][1:]
        if extension not in extensions or os.path.basename(f).startswith('.'):
            logging.debug('Skipping %s', f)
            continue
        yield f


def FilterPaths(paths, extensions):
    """Walk |paths| recursively and filter out content in it."""
    for path in paths:
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for gnfile in FilterFiles(files, extensions):
                    yield os.path.join(root, gnfile)
        else:
            for gnfile in FilterFiles([path], extensions):
                yield gnfile


def GetParser():
    """Return an argument parser."""
    parser = commandline.ArgumentParser(description=__doc__)
    parser.add_argument(
        '--extensions',
        default='gn,gni',
        help='Comma delimited file extensions to check. '
        '(default: %(default)s)')
    parser.add_argument('files', nargs='*', help='Files to run lint.')
    return parser


def CheckFormat(gnfile):
    """Check if the .gn file is formatted in the standard way by gn format."""
    issues = []
    linter = 'CheckFormat'

    def AppendError(msg):
        issues.append(
            LintResult(
                linter=linter,
                file=gnfile,
                location=None,
                msg=msg,
                type=logging.ERROR))

    try:
        gn_path = os.path.join(chromite_root, 'chroot', 'usr', 'bin', 'gn')
        result = cros_build_lib.run([gn_path, 'format', '--dry-run', gnfile],
                                    check=False,
                                    debug_level=logging.DEBUG)
    except cros_build_lib.RunCommandError as e:
        AppendError('Failed to run gn format: %s' % e)
    else:
        if result.returncode == 0:
            # successful format, matches on disk.
            pass
        elif result.returncode == 1:
            AppendError('General failure while running gn format '
                        '(e.g. parse error)')
        elif result.returncode == 2:
            AppendError(
                'Needs reformatting. Run following command: %s format %s' %
                (gn_path, gnfile))
        else:
            AppendError('Unknown error with gn format: '
                        'returncode=%i error=%s output=%s' %
                        (result.returncode, result.stderr, result.stdout))
    return issues


def WalkGn(functor, node):
    """Walk the token tree under |node|, calling |functor| on each node.

    Args:
        functor: A function to be applied.
        node: A dict representing a token subtree containing the target nodes.
    """
    if not isinstance(node, dict):
        logging.warning('Reached non-dict node. Skipping: %s', node)
        return
    functor(node)
    for n in node.get('child', []):
        WalkGn(functor, n)


def Unquote(string_with_quotes):
    """Returns the content of a quoted string.

    Args:
        string_with_quotes: String containing double quote characters at the
            start and the end.

    Returns:
        String with the double-quote characters stripped, or the original string
        if it's not quoted.
    """
    if (len(string_with_quotes) < 2 or not string_with_quotes.startswith('"') or
            not string_with_quotes.endswith('"')):
        logging.error('Quoted string expected, but found: %s',
                      string_with_quotes)
        return string_with_quotes
    return string_with_quotes[1:-1]


def ExtractLiteralAssignment(node, target_variable_names, operators=None):
    """Returns list of literals assigned, added or removed to either variable.

    If |node| assigns, adds or removes string literal values by a list to either
    of the target variable, returns list of all strings literals. Otherwise
    returns an empty list.

    Args:
        node: A dict representing a token subtree.
        target_variable_names: List of strings representing variable names to be
            detected for its modification.
        operators: Optional list of assignment operators to detect. Defaults to
            ['=', '+=', '-='].

    Returns:
        List of nodes used with the assignment operators to either variable.
    """
    if operators is None:
        operators = ['=', '+=', '-=']
    if node.get('type') != 'BINARY' or node.get('value') not in operators:
        return []
    # Detected pattern is like:
    #    BINARY(=)
    #     IDENTIFIER(ldflags)
    #     LIST
    #      LITERAL("-l")
    child = node.get('child')
    # BINARY assignment node should have LHS and RHS.
    if not isinstance(child, list) or len(child) != 2:
        logging.warning('Unexpected tree structure. Skipping: %s', node)
        return []
    if child[0].get('value') not in target_variable_names:
        return []
    if child[1].get('type') != 'LIST':
        return []
    literals = []
    for element in child[1].get('child'):
        if element.get('type') != 'LITERAL':
            continue
        literals.append(element)
    return literals


def FindAllLiteralAssignments(node, target_variable_names, operators=None):
    """Lists all potential literal assignment to variable."""
    literals = []

    def CheckNode(node):
        literals.extend(
            ExtractLiteralAssignment(node, target_variable_names, operators))

    WalkGn(CheckNode, node)
    return literals


ANY_CONFIGS = ['configs', 'public_configs', 'all_dependent_configs']


def GnLintLibFlags(gndata):
    """-lfoo flags belong in 'libs' and not 'ldflags'.

    Args:
        gndata: A dict representing a token tree.

    Returns:
        List of detected Issue.
    """

    def CheckNode(node):
        for n in ExtractLiteralAssignment(node, ['ldflags']):
            flag = GetNodeValue(n)
            if flag.startswith('-l'):
                issues.append(
                    Issue(
                        n.get('location'),
                        ('Libraries should be specified by "libs", '
                         'not -l flags in "ldflags": %s') % flag))

    issues = []
    WalkGn(CheckNode, gndata)
    return issues


def GnLintVisibilityFlags(gndata):
    """Packages should not change -fvisibility settings.

    Args:
        gndata: A dict representing a token tree.

    Returns:
        List of detected Issue.
    """

    def CheckNode(node):
        for n in ExtractLiteralAssignment(node,
                                          ['cflags', 'cflags_c', 'cflags_cc']):
            flag = GetNodeValue(n)
            if flag.startswith('-fvisibility'):
                issues.append(
                    Issue(
                        n.get('location'), 'do not use -fvisibility; to '
                        'export symbols, use brillo/brillo_export.h instead'))

        for n in ExtractLiteralAssignment(node, ANY_CONFIGS):
            name = GetNodeValue(n)
            if name == '//common-mk:visibility_default':
                issues.append(
                    Issue(
                        n.get('location'), 'do not use '
                        '//common-mk:visibility_default; to export '
                        'symbols, use brillo/brillo_export.h instead'))

    issues = []
    WalkGn(CheckNode, gndata)
    return issues


def GnLintDefineFlags(gndata):
    """-D flags should be in 'defines', not cflags.

    Args:
        gndata: A dict representing a token tree.

    Returns:
        List of detected Issue.
    """

    def CheckNode(node):
        for n in ExtractLiteralAssignment(node,
                                          ['cflags', 'cflags_c', 'cflags_cc']):
            name = GetNodeValue(n)
            if name.startswith('-D'):
                issues.append(
                    Issue(
                        n.get('location'),
                        '-D flags should be in "defines": %s' % name))

    issues = []
    WalkGn(CheckNode, gndata)
    return issues


def GnLintDefines(gndata):
    """Flags in 'defines' should have valid names.

    Args:
        gndata: A dict representing a token tree.

    Returns:
        List of detected Issue.
    """

    def CheckNode(node):
        flags = ExtractLiteralAssignment(node, ['defines'])
        for n in flags:
            flag = GetNodeValue(n)
            # People sometimes typo the name.
            if flag.startswith('-D'):
                issues.append(
                    Issue(
                        n.get('location'),
                        'defines do not use -D prefixes: use "%s" instead of '
                        '"%s"' % (flag[2:], flag)))
            else:
                # Make sure the name is valid CPP.
                name = flag.split('=', 1)[0]
                if not re.match(r'^[a-zA-Z0-9_]+$', name):
                    issues.append(
                        Issue(
                            n.get('location'),
                            'invalid define name: %s' % (name,)))

    issues = []
    WalkGn(CheckNode, gndata)
    return issues


def GnLintCommonTesting(gndata):
    """Packages should use //common-mk:test instead of -lgtest/-lgmock.

    Args:
        gndata: A dict representing a token tree.

    Returns:
        List of detected Issue.
    """

    def CheckNode(node):
        for n in ExtractLiteralAssignment(node, ['libs']):
            flag = GetNodeValue(n)
            if flag in ['gmock', 'gtest']:
                issues.append(
                    Issue(
                        n.get('location'),
                        'use //common-mk:test for tests instead of '
                        'linking against -lgtest/-lgmock directly'))

    issues = []
    WalkGn(CheckNode, gndata)
    return issues


# Helper functions for GnLintStaticSharedLibMixing.
def IsFunctionNode(node):
    """Returns True if the node type is FUNCTION."""
    if not isinstance(node, dict):
        logging.warning('Reached non-dict node. Skipping: %s', node)
        return False
    return node.get('type') == 'FUNCTION'


def GnLintStaticSharedLibMixing(gndata):
    """Static libs linked into shared libs need special PIC handling.

    Normally static libs are built using PIE because they only get linked into
    PIEs.  But if someone tries linking the static libs into a shared lib, we
    need to make sure the code is built using PIC.

    Note: We don't do an inverse check (PIC static libs not used by shared libs)
    as the static libs might be installed by the ebuild.  Not that we want to
    encourage that situation, but it is what it is ...

    Args:
        gndata: A dict representing a token tree of a GN file.

    Returns:
        List of detected Issue.
    """
    # Record static_libs that build as PIE, and all the deps of shared_libs.
    # Afterwards, we'll sanity check all the shared lib deps.
    pie_static_libs = []
    shared_lib_deps = {}

    def ProcessFunctionNode(node):
        """Scans content of a function node and memorize if PIC/PIE."""
        if not IsFunctionNode(node):
            return
        child = node.get('child', [])
        if len(child) != 2:
            return
        # 1st child of FUNCTION node is the name of the function.
        # We only check for a simple literal node name.
        # For example:
        #  FUNCTION(static_library)
        #   LIST
        #    LITERAL("my_static_library")
        #   BLOCK
        #    BINARY(+=)
        #     IDENTIFIER(configs)
        #     LIST
        #      LITERAL("//common-mk:pic")
        #    BINARY(-=)
        #     IDENTIFIER(configs)
        #     LIST
        #      LITERAL("//common-mk:pie")
        name_expression, block = child
        if len(name_expression.get('child', [])) != 1:
            return
        name_literal = name_expression['child'][0]
        if name_literal.get('type') != 'LITERAL':
            return
        name = name_literal.get('value')
        if name is None:
            return
        name = Unquote(name)
        target_type = node.get('value')
        if target_type == 'static_library':
            configs = [
                GetNodeValue(n)
                for n in FindAllLiteralAssignments(block, ANY_CONFIGS, ['+='])
            ]
            removed_configs = [
                GetNodeValue(n)
                for n in FindAllLiteralAssignments(block, ANY_CONFIGS, ['-='])
            ]
            if ('//common-mk:pie' not in removed_configs or
                    '//common-mk:pic' not in configs):
                pie_static_libs.append((name, node.get('location')))
        elif target_type == 'shared_library':
            assert name not in shared_lib_deps, 'duplicate target: %s' % name
            deps = ExtractLiteralAssignment(block.get('child')[0], 'deps')
            shared_lib_deps[name] = [
                GetNodeValue(t).lstrip(':')
                for t in deps
                if GetNodeValue(t).startswith(':')
            ]

    # We build up the full state first rather than check it as we go as gyp
    # files do not force target ordering.
    WalkGn(ProcessFunctionNode, gndata)

    # Now with the full state, run the checks.
    ret = []
    for pie_lib, location in pie_static_libs:
        # Pull out all shared libs that depend on static PIE libs.
        dependency_libs = [
            shared_lib for shared_lib, deps in shared_lib_deps.items()
            if pie_lib in deps
        ]
        if dependency_libs:
            ret.append(
                Issue(location,
                      ('static library "%(pie)s" must be compiled as PIC, not '
                       'PIE, because it is linked into the shared libraries '
                       '%(pic)s; add this to the "%(pie)s" target to fix:\n'
                       'configs += [\"//common-mk:pic\"]\n'
                       'configs -= [\"//common-mk:pie\"]') % {
                           'pie': pie_lib,
                           'pic': dependency_libs
                       }))
    return ret


# The regex used to find gnlint options in the file.
# This matches the regex pylint uses.
OPTIONS_RE = re.compile(r'^\s*#.*\bgnlint:\s*([^\n;]+)', flags=re.MULTILINE)

# The regex used to find unit test source files having wrong suffix.
UNITTEST_SOURCE_RE = re.compile(r'_unittest\.(cc|c|h)$')


def GnLintSourceFileNames(gndata):
    """Enforce various filename conventions."""

    ret = []

    def CheckNode(node):
        for n in ExtractLiteralAssignment(node, ['sources']):
            path = GetNodeValue(n)
            # Enforce xxx_test.cc naming.
            if UNITTEST_SOURCE_RE.search(path):
                ret.append(
                    Issue(
                        n.get('location'), '%s: rename unittest file to "%s"' %
                        (path, path.replace('_unittest', '_test'))))

    WalkGn(CheckNode, gndata)
    return ret


# It's not easy to auto-discover pkg-config files as we don't require a chroot
# or a fully installed sysroot to run this linter.  Plus, there's no clean way
# to correlate -lfoo names with pkg-config .pc file names.  List the packages
# that we tend to use in platform2 projects.
KNOWN_PC_FILES = {
    'blkid': 'blkid',
    'cap': 'libcap',
    'crypto': 'libcrypto',
    'dbus-1': 'dbus-1',
    'dbus-c++-1': 'dbus-c++-1',
    'dbus-glib-1': 'dbus-glib-1',
    'expat': 'expat',
    'fuse': 'fuse',
    'glib-2.0': 'glib-2.0',
    'gobject-2.0': 'gobject-2.0',
    'gthread-2.0': 'gthread-2.0',
    'minijail': 'libminijail',
    'pcre': 'libpcre',
    'pcrecpp': 'libpcrecpp',
    'pcreposix': 'libpcreposix',
    'protobuf': 'protobuf',
    'protobuf-lite': 'protobuf-lite',
    'ssl': 'libssl',
    'udev': 'libudev',
    'usb-1.0': 'libusb-1.0',
    'uuid': 'uuid',
    'vboot_host': 'vboot_host',
    'z': 'zlib',
}
KNOWN_PC_LIBS = frozenset(KNOWN_PC_FILES.keys())


def GnLintPkgConfigs(gndata):
    """Use pkg-config files for known libs instead of adding to libs."""
    ret = []

    def CheckNode(node):
        # detect addition to libraries.
        # ldflags is already detected as errors by GnLintLibFlags.
        for n in ExtractLiteralAssignment(node, ['libs']):
            lib = GetNodeValue(n)
            if lib not in KNOWN_PC_LIBS:
                continue
            ret.append(
                Issue(
                    n.get('location'),
                    ('use pkg-config instead: delete "%s" from "libs" and add '
                     '"%s" to either "pkg_deps", "public_pkg_deps", or '
                     '"all_dependent_pkg_deps"') % (lib, KNOWN_PC_FILES[lib])))

    WalkGn(CheckNode, gndata)
    return ret


# Helper functions for GnLintOrderingWithinTarget.
def IsBinaryNode(node):
    """Returns True if the node type is BINARY."""
    if not isinstance(node, dict):
        logging.warning('Reached non-dict node. Skipping: %s', node)
        return False
    return node.get('type') == 'BINARY'


def IsConditionNode(node):
    """Returns True if the node type is CONDITION."""
    if not isinstance(node, dict):
        logging.warning('Reached non-dict node. Skipping: %s', node)
        return False
    return node.get('type') == 'CONDITION'


def GnLintOrderingWithinTarget(gndata):
    """Enforce the order of identifiers within a target."""
    ret = []
    checked_function = {
        'executable',
        'group',
        'shared_library',
        'static_library',
    }
    order = [
        {'output_name', 'visibility', 'testonly'},
        {'sources'},
        {
            'aliased_deps', 'all_dependent_configs',
            'allow_circular_includes_from', 'arflags', 'args', 'asmflags',
            'assert_no_deps', 'bundle_contents_dir', 'bundle_deps_filter',
            'bundle_executable_dir', 'bundle_resources_dir', 'bundle_root_dir',
            'cflags', 'cflags_c', 'cflags_cc', 'cflags_objc', 'cflags_objcc',
            'check_includes', 'code_signing_args', 'code_signing_outputs',
            'code_signing_script', 'code_signing_sources',
            'complete_static_lib', 'configs', 'contents', 'crate_name',
            'crate_root', 'crate_type', 'data', 'data_deps', 'data_keys',
            'defines', 'depfile', 'friend', 'include_dirs', 'inputs', 'ldflags',
            'lib_dirs', 'libs', 'metadata', 'output_conversion', 'output_dir',
            'output_extension', 'output_prefix_override', 'outputs',
            'partial_info_plist', 'pool', 'precompiled_header',
            'precompiled_header_type', 'precompiled_source', 'product_type',
            'public', 'public_configs', 'rebase', 'response_file', 'script',
            'walk_keys', 'write_runtime_deps', 'xcode_extra_attributes',
            'xcode_test_application_name'
        },
        {'public_deps'},
        {'deps'},
    ]

    def OrderStep(identifier):
        # Find the order of the identifier.
        for i, identifiers in enumerate(order):
            if identifier in identifiers:
                return i
        return -1

    def CheckFunction(node):
        # Detect misordering of identifiers within a target.

        def CheckCondition(node):
            # Detect misordering of identifiers in conditionals.
            if not IsConditionNode(node):
                return
            child = node.get('child', [])
            if len(child) != 2:
                return
            _condition, block = child
            CheckBlock(block)

        def CheckBlock(node):
            # Detect misordering of identifiers in blocks.
            before_step = 0
            for child in node.get('child', []):
                CheckCondition(child)
                if not IsBinaryNode(child):
                    continue
                grandchild = child.get('child', [])
                if len(grandchild) != 2:
                    continue

                identifier = grandchild[0].get('value')
                step = OrderStep(identifier)
                if step == -1:
                    continue
                if before_step > step:
                    ret.append(
                        Issue(
                            child.get('location'),
                            ('wrong parameter order in %s(%s): '
                             'put parameters in the following order: '
                             'output_name/visibility/testonly, sources, '
                             'other parameters, public_deps '
                             'and deps') % (function, name)))
                    return
                before_step = step

        if not IsFunctionNode(node):
            return
        function = node.get('value')
        if function is None:
            return

        if function not in checked_function:
            return
        child = node.get('child', [])
        if len(child) != 2:
            return
        # 1st child of FUNCTION node is the name of the function.
        # For example:
        #  FUNCTION(static_library)
        #   LIST
        #    LITERAL("my_static_library")
        #   BLOCK
        #    BINARY(+=)
        #     IDENTIFIER(configs)
        #     LIST
        #      LITERAL("")
        #    BINARY(-=)
        #     IDENTIFIER(configs)
        #     LIST
        #      LITERAL("")
        name_expression, block = child
        if len(name_expression.get('child', [])) != 1:
            return
        name_literal = name_expression['child'][0]
        if name_literal.get('type') != 'LITERAL':
            return
        name = name_literal.get('value')
        if name is None:
            return
        name = Unquote(name)
        CheckBlock(block)

    WalkGn(CheckFunction, gndata)
    return ret


def ParseOptions(options, name=None):
    """Parse out the linter settings from |options|.

    Currently we support:
        disable=<linter name>

    Args:
        options: A list of linter options (e.g. ['foo=bar']).
        name: The file we're parsing.

    Returns:
        A LintSettings object.
    """
    skip = set()
    issues = []

    # Parse all the gnlint directives.
    for option in options:
        key, value = option.split('=', 1)
        key = key.strip()
        value = value.strip()

        # Parse each sub-option.
        if key == 'disable':
            skip.update(x.strip() for x in value.split(','))
        else:
            issues.append(
                LintResult(
                    linter='ParseOptions',
                    file=name,
                    location=None,
                    msg='unknown gnlint option: %s' % (key,),
                    type=logging.ERROR))

    # Validate the options.
    all_linters = FindLinters([])
    bad_linters = skip - set(all_linters.keys())
    if bad_linters:
        issues.append(
            LintResult(
                linter='ParseOptions',
                file=name,
                location=None,
                msg='unknown linters: %s' % (bad_linters,),
                type=logging.ERROR))

    return LintSettings(skip, issues)


_ALL_LINTERS = {
    'GnLintLibFlags': GnLintLibFlags,
    'GnLintVisibilityFlags': GnLintVisibilityFlags,
    'GnLintDefineFlags': GnLintDefineFlags,
    'GnLintDefines': GnLintDefines,
    'GnLintCommonTesting': GnLintCommonTesting,
    'GnLintStaticSharedLibMixing': GnLintStaticSharedLibMixing,
    'GnLintSourceFileNames': GnLintSourceFileNames,
    'GnLintPkgConfigs': GnLintPkgConfigs,
    'GnLintOrderingWithinTarget': GnLintOrderingWithinTarget,
}


def FindLinters(skip):
    """Return all linters excluding ones in |skip|.

    Args:
        skip: A string list of linter names to be skipped.

    Returns:
        A dict of linters, in which the key is the name and the value is the
        linter function.
    """
    return {name: f for name, f in _ALL_LINTERS.items() if name not in skip}


def RunLinters(name, gndata, settings=None):
    """Run linters against |gndata|.

    Args:
        name: A string representing the filename. For printing issues.
        gndata: A dict representing a token tree. See the comment in "Linters
            and its helper functions" section for details.
        settings: An optional LintSettings object.

    Returns:
        List of detected LintResult.
    """
    issues = []

    if settings is None:
        settings = ParseOptions([])
        issues += settings.issues

    for linter_name, linter in FindLinters(settings.skip).items():
        for result in linter(gndata):
            issues.append(
                LintResult(
                    linter=linter_name,
                    file=name,
                    location=result[0],
                    msg=result[1],
                    type=logging.ERROR))
    return issues


def GetGnPath():
    """Get path to gn executable.

    Returns:
        Path string.
    """
    return os.path.join(chromite_root, 'chroot', 'usr', 'bin', 'gn')


def CheckGnFile(gnfile):
    """Check |gnfile| for common mistakes.

    Args:
        gnfile: A string representing the filename of the GN file.

    Returns:
        List of detected LintResult.
    """
    if not os.path.exists(gnfile):
        # The file has been deleted.
        return
    issues = []
    issues += CheckFormat(gnfile)
    # Parse the gnlint flags in the file.
    with open(gnfile) as fp:
        data = fp.read()
    settings = ParseOptions(OPTIONS_RE.findall(data))
    issues += settings.issues

    # Parse and check
    gn_path = GetGnPath()
    if not os.path.exists(gn_path):
        logging.error('gn command not found: "%s"; make sure it is installed.',
                      gn_path)
        sys.exit(1)

    try:
        command_result = cros_build_lib.run(
            [gn_path, 'format', '--dump-tree=json', gnfile],
            stderr=subprocess.STDOUT,
            stdout=True,
            debug_level=logging.DEBUG)
    except cros_build_lib.RunCommandError as e:
        issues.append(
            LintResult(
                linter='gn.input.CheckedEval',
                file=gnfile,
                location=None,
                msg='Failed to run gn format: %s' % e,
                type=logging.ERROR))
        return issues

    try:
        data = json.loads(command_result.stdout)
    except Exception as e:
        issues.append(
            LintResult(
                linter='gn.input.CheckedEval',
                file=gnfile,
                location=None,
                msg='invalid format: %s' % e,
                type=logging.ERROR))
        return issues
    issues += RunLinters(gnfile, data, settings)
    return issues


def main(argv):
    parser = GetParser()
    opts = parser.parse_args(argv)

    if not opts.files:
        logging.warning('No files provided to lint.  Doing nothing.')
        return 0

    extensions = set(opts.extensions.split(','))
    num_files = 0
    for gnfile in FilterPaths(opts.files, extensions):
        logging.debug('Checking %s', gnfile)
        issues = CheckGnFile(gnfile)
        if issues:
            logging.error('**** %s: found %i issue(s)', gnfile, len(issues))
            for issue in issues:
                if issue.location is not None:
                    logging.log(issue.type, '%s: %s: %s',
                                FormatLocation(issue.file, issue.location),
                                issue.linter, issue.msg)
                else:
                    logging.log(issue.type, '%s: %s', issue.linter, issue.msg)
            num_files += 1
    if num_files:
        logging.error('%i file(s) failed linting', num_files)
    return 1 if num_files else 0


if __name__ == '__main__':
    commandline.ScriptWrapperMain(lambda _: main)
