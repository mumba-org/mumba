// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/ui/native_dock_frame_factory.h"

#include "build/build_config.h"
#include "core/host/ui/native_dock_frame.h"

namespace host {

namespace {

NativeDockFrameFactory* factory = nullptr;

}

// static
NativeDockFrame* NativeDockFrameFactory::CreateNativeDockFrame(
    DockFrame* dock_frame,
    DockWindow* dock_window) {
  if (!factory)
    factory = new NativeDockFrameFactory;
  return factory->Create(dock_frame, dock_window);
}

// static
void NativeDockFrameFactory::Set(NativeDockFrameFactory* new_factory) {
  delete factory;
  factory = new_factory;
}

}