// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/native_dock_frame_factory.h"

#import "core/host/ui/dock_frame_mac.h"

namespace host {

NativeDockFrame* NativeDockFrameFactory::Create(
    DockFrame* dock_frame,
    DockWindow* dock_window) {
  return new DockFrameMac(dock_frame, dock_window);
}

}