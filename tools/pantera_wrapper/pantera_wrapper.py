#!/usr/bin/env python
# Copyright (c) 2018 Pantera. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from __future__ import print_function
import argparse
import os.path
import subprocess
import sys
import tempfile

def main(argv):
  parser = argparse.ArgumentParser()
  parser.add_argument("--pantera",
                      help="Relative path to executable.")

  parser.add_argument("--command",
                      help="command to execute.")

  parser.add_argument("--subcommand",
                      help="subcommand to execute with command.") 

  parser.add_argument("--out_app",
                      help="output app.")

  parser.add_argument("--input_executable",
                      help="input executable.")
  
  options = parser.parse_args()

  command = options.command
  pantera_cmd = [os.path.realpath(options.pantera)]
  pantera_cmd += [command]
  
  if command == "pack":
    pantera_cmd += ["--type=" + options.subcommand]

  if options.out_app:
    pantera_cmd += [options.out_app]  
  if options.input_executable:
    pantera_cmd += [options.input_executable]
  
  ret = subprocess.call(pantera_cmd)
  
  if ret != 0:
    if ret <= -100:
      # Windows error codes such as 0xC0000005 and 0xC0000409 are much easier to
      # recognize and differentiate in hex. In order to print them as unsigned
      # hex we need to add 4 Gig to them.
      error_number = "0x%08X" % (ret + (1 << 32))
    else:
      error_number = "%d" % ret
    raise RuntimeError("Pantera has returned non-zero status: "
                       "{0}".format(error_number))


if __name__ == "__main__":
  try:
    main(sys.argv)
  except RuntimeError as e:
    print(e, file=sys.stderr)
    sys.exit(1)
