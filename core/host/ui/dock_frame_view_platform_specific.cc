// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/dock_frame_view_platform_specific.h"

#include "build/build_config.h"

namespace host {

bool DockFrameViewPlatformSpecific::IsUsingSystemTheme() {
  return false;
}

#if !defined(OS_LINUX)
// static
DockFrameViewPlatformSpecific* DockFrameViewPlatformSpecific::Create(
    DockFrameView* view,
    DockFrameViewLayout* layout) {
  return new DockFrameViewPlatformSpecific();
}
#endif

}
