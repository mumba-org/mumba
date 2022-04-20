#!/bin/bash

# Copyright 2020 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -e

v=$1
include_dir=$2
out=$3

sed \
  -e "s/@BSLOT@/${v}/g" \
  -e "s:@INCLUDE_DIR@:${include_dir}:g" \
  "libpatchpanel-client.pc.in" > "${out}/libpatchpanel-client.pc"
