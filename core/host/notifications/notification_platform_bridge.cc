// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/notifications/notification_platform_bridge.h"

#include "build/build_config.h"
#include "core/host/application/domain.h"
#include "core/host/workspace/workspace.h"

#if defined(OS_WIN)
#include "base/strings/utf_string_conversions.h"
#endif

namespace host {

// static
std::string NotificationPlatformBridge::GetProfileId(Domain* domain) {
#if defined(OS_WIN)
  return base::WideToUTF8(domain->workspace()->root_path().BaseName().value());
#elif defined(OS_POSIX)
  return domain->workspace()->root_path().BaseName().value();
#else
#error "Not implemented for !OS_WIN && !OS_POSIX."
#endif
}

}