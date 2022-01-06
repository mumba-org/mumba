#!/usr/bin/python
#
# Copyright (C) 2009 Google Inc. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following disclaimer
# in the documentation and/or other materials provided with the
# distribution.
#     * Neither the name of Google Inc. nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Copyright (c) 2009 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# usage: rule_bison.py INPUT_FILE OUTPUT_DIR BISON_EXE [DEVELOPER_DIR]
# INPUT_FILE is a path to either XPathGrammar.y.
# OUTPUT_DIR is where the bison-generated .cpp and .h files should be placed.

import errno
import os
import os.path
import subprocess
import sys

assert len(sys.argv) == 4

inputFile = sys.argv[1]
outputDir = sys.argv[2]
flexExe = sys.argv[3]

pathToFlex = os.path.split(flexExe)[0]
if pathToFlex:
    # Make sure this path is in the path so that it can find its auxiliary
    # binaries (in particular, m4). To avoid other 'm4's being found, insert
    # at head, rather than tail.
    os.environ['PATH'] = pathToFlex + os.pathsep + os.environ['PATH']


inputName = os.path.basename(inputFile)

(inputRoot, inputExt) = os.path.splitext(inputName)

outputCpp = os.path.join(outputDir, inputRoot + '.flex.cc')

returnCode = subprocess.call([flexExe, '-o', outputCpp, '-f', inputFile ])
assert returnCode == 0