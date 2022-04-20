#!/usr/bin/env python3
# Copyright 2022 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Linter for various DIR_METADATA files."""

from __future__ import division

import logging
from pathlib import Path
import sys
from typing import Generator, List, Optional

TOP_DIR = Path(__file__).resolve().parent.parent

# Find chromite!
sys.path.insert(0, str(TOP_DIR.parent.parent))

# pylint: disable=wrong-import-position
from chromite.lib import commandline
from chromite.lib import git
# pylint: enable=wrong-import-position


def GetActiveProjects() -> Generator[Path, None, None]:
    """Return the list of active projects."""
    # Look at all the paths (files & dirs) in the top of the git repo.  This way
    # we ignore local directories devs created that aren't actually committed.
    cmd = ['ls-tree', '--name-only', '-z', 'HEAD']
    result = git.RunGit(TOP_DIR, cmd)

    # Split the output on NULs to avoid whitespace/etc... issues.
    paths = result.stdout.split('\0')

    # ls-tree -z will include a trailing NUL on all entries, not just
    # separation, so filter it out if found (in case ls-tree behavior changes on
    # us).
    for path in [Path(x) for x in paths if x]:
        if (TOP_DIR / path).is_dir():
            yield path


# Legacy projects that don't have a DIR_METADATA file.
# Someone should claim them :D.
LEGACYLIST = {
    'arc',
    'authpolicy',
    'avtest_label_detect',
    'bootid-logger',
    'bootstat',
    'camera',
    'cfm-dfu-notification',
    'chromeos-common-script',
    'chromeos-config',
    'chromeos-dbus-bindings',
    'chromeos-nvt-tcon-updater',
    'client_id',
    'codelab',
    'cronista',
    'crosdns',
    'crosh',
    'croslog',
    'cups_proxy',
    'disk_updater',
    'dlcservice',
    'dlp',
    'dns-proxy',
    'easy-unlock',
    'featured',
    'feedback',
    'fitpicker',
    'foomatic_shell',
    'glib-bridge',
    'goldfishd',
    'hammerd',
    'hardware_verifier',
    'hermes',
    'hiberman',
    'iioservice',
    'image-burner',
    'imageloader',
    'init',
    'installer',
    'ippusb_bridge',
    'kerberos',
    'libbrillo',
    'libchromeos-rs',
    'libchromeos-ui',
    'libcontainer',
    'libipp',
    'libmems',
    'libpasswordprovider',
    'login_manager',
    'lorgnette',
    'media_capabilities',
    'media_perception',
    'mems_setup',
    'metrics',
    'midis',
    'minios',
    'missive',
    'mist',
    'ml_benchmark',
    'modemfwd',
    'modem-utilities',
    'mojo_service_manager',
    'nnapi',
    'ocr',
    'oobe_config',
    'os_install_service',
    'p2p',
    'patchpanel',
    'pciguard',
    'perfetto_simple_producer',
    'permission_broker',
    'policy_proto',
    'policy_utils',
    'power_manager',
    'print_tools',
    'regions',
    'resourced',
    'rmad',
    'run_oci',
    'runtime_probe',
    'screen-capture-utils',
    'secanomalyd',
    'secure_erase_file',
    'secure-wipe',
    'sepolicy',
    'shill',
    'sirenia',
    'smogcheck',
    'spaced',
    'st_flash',
    'storage_info',
    'syslog-cat',
    'system_api',
    'system-proxy',
    'timberslide',
    'touch_firmware_calibration',
    'trim',
    'typecd',
    'ureadahead-diff',
    'usb_bouncer',
    'userfeedback',
    'verity',
    'virtual_file_provider',
    'vm_tools',
    'vpn-manager',
    'webserver',
    'wifi-testbed',
}

def CheckSubdirs() -> int:
    """Check the subdir DIR_METADATA files exist.

    Returns:
        0 if no issues are found, 1 otherwise.
    """

    ret = 0
    for proj in GetActiveProjects():
        path = TOP_DIR / proj / 'DIR_METADATA'
        if path.exists():
            if str(proj) in LEGACYLIST:
                logging.error(
                    '*** Project "%s" is in no-DIR_METADATA LEGACYLIST, but '
                    'actually has one. Please remove it from %s:LEGACYLIST!',
                    proj, __file__)
                ret = 1
        else:
            if str(proj) not in LEGACYLIST:
                logging.error(
                    '*** Project "%s" needs a DIR_METADATA file; see common-mk/'
                    'DIR_METADATA for an example', proj)
                ret = 1
            continue

        data = path.read_text()
        for i, line in enumerate(data.splitlines(), start=1):
            if line.rstrip() != line:
                logging.error('*** %s:%i: Trim trailing whitespace', path, i)
                ret = 1

        if not data:
            logging.error('*** %s: File is empty', path)
            ret = 1

        if not data.endswith('\n'):
            logging.error('*** %s: Missing trailing newline', path)
            ret = 1

        if data.startswith('\n'):
            logging.error('*** %s: Trim leading blanklines', path)
            ret = 1

        if data.endswith('\n\n'):
            logging.error('*** %s: Trim trailing blanklines', path)
            ret = 1

    return ret


def GetParser() -> commandline.ArgumentParser:
    """Return an argument parser."""
    parser = commandline.ArgumentParser(description=__doc__)
    return parser


def main(argv: List[str]) -> Optional[int]:
    """The main func!"""
    parser = GetParser()
    opts = parser.parse_args(argv)
    opts.Freeze()

    return CheckSubdirs()


if __name__ == '__main__':
    commandline.ScriptWrapperMain(lambda _: main)
