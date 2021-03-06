// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_PLATFORM_UTIL_INTERNAL_H_
#define CHROME_BROWSER_PLATFORM_UTIL_INTERNAL_H_

#include "core/host/ui/platform_util.h"

namespace base {
class FilePath;
}

namespace platform_util {
namespace internal {

// Called by platform_util.cc on desktop platforms to invoke platform specific
// logic to open |path| using a suitable handler. |path| has been verified to be
// of type |type|.
// Always called on the blocking pool.
void PlatformOpenVerifiedItem(const base::FilePath& path, OpenItemType type);

// Prevent shell or external applications from being invoked during testing.
void DisableDomainOperationsForTesting();

}  // namespace internal
}  // namespace platform_util

#endif  // CHROME_BROWSER_PLATFORM_UTIL_INTERNAL_H_
