// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_UI_NATIVE_WINDOW_HOST_FRAME_FACTORY_H_
#define MUMBA_HOST_UI_NATIVE_WINDOW_HOST_FRAME_FACTORY_H_

#include "base/macros.h"

namespace host {
class DockFrame;
class DockWindow;
class NativeDockFrame;

// Factory for creating a NativeBrowserFrame.
class NativeDockFrameFactory {
 public:
  // Construct a platform-specific implementation of this interface.
  static NativeDockFrame* CreateNativeDockFrame(
      DockFrame* dock_frame,
      DockWindow* dock_window);

  // Sets the factory. Takes ownership of |new_factory|, deleting existing
  // factory. Use null to go back to default factory.
  static void Set(NativeDockFrameFactory* new_factory);

  virtual NativeDockFrame* Create(DockFrame* dock_frame,
                                        DockWindow* dock_window);

 protected:
  NativeDockFrameFactory() {}
  virtual ~NativeDockFrameFactory() {}

 private:
  DISALLOW_COPY_AND_ASSIGN(NativeDockFrameFactory);
};

}

#endif  // CHROME_BROWSER_UI_VIEWS_FRAME_NATIVE_BROWSER_FRAME_FACTORY_H_
