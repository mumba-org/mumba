#!/usr/bin/env python

import sys
import optparse
import subprocess

def main(argv):
  path = './mumba_bundle'
  args = [path] + argv[1:]
  ret = subprocess.call(args)
  if ret != 0:
    print '%s failed with exit code %d' % (argv[1], ret)
  return ret
if __name__ == '__main__':
  sys.exit(main(sys.argv))