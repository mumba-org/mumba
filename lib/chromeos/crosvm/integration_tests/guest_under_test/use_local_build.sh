#!/bin/bash
# Copyright 2020 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Exports env variables to make the integration_tests use a locally built
# kernel / rootfs.
#
# Note: `source` this file, do not run it if you want it to set the environmens
# variables for you.

CARGO_TARGET=$(cargo metadata --no-deps --format-version 1 |
    jq -r ".target_directory")
LOCAL_BZIMAGE=${CARGO_TARGET}/guest_under_test/bzImage
LOCAL_ROOTFS=${CARGO_TARGET}/guest_under_test/rootfs

cd "${0%/*}" && make "${LOCAL_BZIMAGE}" "${LOCAL_ROOTFS}"

export CROSVM_CARGO_TEST_KERNEL_BINARY="${LOCAL_BZIMAGE}"
export CROSVM_CARGO_TEST_ROOTFS_IMAGE="${LOCAL_ROOTFS}"
