import errno
import os
import os.path
import subprocess
import sys

Dir = sys.argv[1]
inputFile = Dir + "/" + sys.argv[2]
outputFile = Dir + "/" + sys.argv[3]

# get the input string with grep
cmd = "grep \'    KW_.* = \' " + inputFile
p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
output, err = p.communicate()

# write the output file
f = open(outputFile, "a")
f.write(output)
f.close()