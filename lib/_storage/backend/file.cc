// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/backend/file.h"

namespace storage {

// Cross platform constructors. Platform specific code is in
// file_{win,posix}.cc.

File::File() : init_(false), mixed_(false) {}

File::File(bool mixed_mode) : init_(false), mixed_(mixed_mode) {}

}  // namespace storage
