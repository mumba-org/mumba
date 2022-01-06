// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/native_dock_frame_factory.h"

#include "core/host/ui/dock_frame_mus.h"
#include "core/host/ui/dock_frame_aurax11.h"
#include "ui/aura/env.h"

namespace host {

NativeDockFrame* NativeDockFrameFactory::Create(
    DockFrame* dock_frame,
    DockWindow* dock_window) {
  if (aura::Env::GetInstance()->mode() == aura::Env::Mode::MUS)
    return new DockFrameMus(dock_frame, dock_window);
  return new DockFrameAuraX11(dock_frame, dock_window);
}

}