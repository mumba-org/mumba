// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/native_dock_frame_factory.h"

#include "core/host/chromeos/ash_config.h"
#include "core/host/ui/dock_frame_ash.h"
#include "core/host/ui/dock_frame_mus.h"
#include "services/service_manager/runner/common/client_util.h"

namespace host {

NativeDockFrame* NativeDockFrameFactory::Create(
    DockFrame* dock_frame,
    DockWindow* dock_window) {
  if (chromeos::GetAshConfig() == ash::Config::MASH)
    return new DockFrameMus(dock_frame, dock_window);
  return new DockFrameAsh(dock_frame, dock_window);
}

}