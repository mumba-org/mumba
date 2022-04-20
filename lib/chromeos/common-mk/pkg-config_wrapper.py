#!/usr/bin/env python3
# Copyright 2018 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Wrapper of pkg-config command line to format output for gn.

Parses the pkg-config output and format it into json,
so that it can be used in GN files easily.

Usage:
  pkg-config_wrapper.py pkg-config pkg1 pkg2 ...

Specifically, this script does not expect any additional flags.
"""

import json
import shlex
import subprocess
import sys


def get_shell_output(cmd):
  """Run |cmd| and return output as a list."""
  output = subprocess.check_output(cmd, encoding='utf-8')
  return shlex.split(output)


def main(argv):
  cflags = get_shell_output(argv + ['--cflags'])
  libs = []
  lib_dirs = []
  ldflags = []
  for ldflag in get_shell_output(argv + ['--libs']):
    if ldflag.startswith('-l'):
      # Strip -l.
      libs.append(ldflag[2:])
    elif ldflag.startswith('-L'):
      # Strip -L.
      lib_dirs.append(ldflag[2:])
    else:
      ldflags.append(ldflag)

  # Set sort_keys=True for stabilization.
  result = {
      'cflags': cflags,
      'libs': libs,
      'lib_dirs': lib_dirs,
      'ldflags': ldflags,
  }
  json.dump(result, sys.stdout, sort_keys=True)


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
