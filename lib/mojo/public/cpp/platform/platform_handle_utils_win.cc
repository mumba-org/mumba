// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mojo/public/cpp/platform/platform_handle_utils.h"

#include <windows.h>

#include "base/logging.h"

namespace mojo {

ScopedPlatformHandle DuplicatePlatformHandle(PlatformHandle platform_handle) {
  DCHECK(platform_handle.is_valid());

  HANDLE new_handle;
  CHECK_NE(platform_handle.handle, INVALID_HANDLE_VALUE);
  if (!DuplicateHandle(GetCurrentProcess(), platform_handle.handle,
                       GetCurrentProcess(), &new_handle, 0, TRUE,
                       DUPLICATE_SAME_ACCESS))
    return ScopedPlatformHandle();
  DCHECK_NE(new_handle, INVALID_HANDLE_VALUE);
  return ScopedPlatformHandle(PlatformHandle(new_handle));
}

}  // namespace mojo
