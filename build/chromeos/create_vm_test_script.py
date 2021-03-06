#!/usr/bin/env python
#
# Copyright 2018 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Creates a script that runs a CrOS VM test by delegating to
build/chromeos/run_vm_test.py.
"""

import argparse
import os
import re
import sys


SCRIPT_TEMPLATE = """\
#!/usr/bin/env python
#
# This file was generated by build/chromeos/create_vm_test_script.py

import os
import sys

def main():
  script_directory = os.path.dirname(__file__)
  def ResolvePath(path):
    return os.path.abspath(os.path.join(script_directory, path))

  vm_test_script = os.path.abspath(
      os.path.join(script_directory, '{vm_test_script}'))

  vm_args = {vm_test_args}
  path_args = {vm_test_path_args}
  for arg, path in path_args:
    vm_args.extend([arg, ResolvePath(path)])

  os.execv(vm_test_script,
           [vm_test_script] + vm_args + sys.argv[1:])

if __name__ == '__main__':
  sys.exit(main())
"""

def main(args):
  parser = argparse.ArgumentParser()
  parser.add_argument('--script-output-path')
  parser.add_argument('--output-directory')
  parser.add_argument('--test-exe')
  parser.add_argument('--runtime-deps-path')
  parser.add_argument('--cros-cache')
  parser.add_argument('--board')
  args = parser.parse_args(args)


  def RelativizePathToScript(path):
    return os.path.relpath(path, os.path.dirname(args.script_output_path))

  run_test_path = RelativizePathToScript(
      os.path.join(os.path.dirname(__file__), 'run_vm_test.py'))
  vm_test_args = [
      '--board', args.board,
      '--test-exe', args.test_exe,
      '-v',
  ]
  vm_test_path_args = [
      ('--path-to-outdir', RelativizePathToScript(args.output_directory)),
      ('--runtime-deps-path', RelativizePathToScript(args.runtime_deps_path)),
      ('--cros-cache', RelativizePathToScript(args.cros_cache)),
  ]
  with open(args.script_output_path, 'w') as script:
    script.write(SCRIPT_TEMPLATE.format(
        vm_test_script=run_test_path,
        vm_test_args=str(vm_test_args),
        vm_test_path_args=str(vm_test_path_args)))

  os.chmod(args.script_output_path, 0750)


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
