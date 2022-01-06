// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_BUNDLE_BUNDLE_INFO_H_
#define MUMBA_HOST_BUNDLE_BUNDLE_INFO_H_

#include <memory>

#include "base/macros.h"

namespace host {

enum class BundlePlatform {
  WINDOWS = 0,
  MACOS = 1,
  IOS = 2,
  ANDROID = 3,
  LINUX = 4,
  WEB = 5
};

enum class BundleArchitecture {
  X86 = 0,
  ARM = 5,
  X64 = 9,
  NEUTRAL = 11,
  ARM64 = 12
};

enum class BundlePackageType {
  APPLICATION = 0,
  RESOURCE = 1
};


}

#endif