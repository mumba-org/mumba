import errno
import os
import os.path
import subprocess
import sys

inputFile = sys.argv[1]
outputFile = sys.argv[2]
xdrcExe = sys.argv[3]

returnCode = subprocess.call([xdrcExe, '-hh', '-o', outputFile, inputFile ])
assert returnCode == 0
