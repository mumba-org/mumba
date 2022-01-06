// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/child_process_host_delegate.h"

namespace common {

bool ChildProcessHostDelegate::CanShutdown() {
  return true;
}

}  // namespace common
