// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

public final class X11TouchFactory : TouchFactory {

  public init() {}

  public func shouldProcessXI2Event(xev: XEvent) -> Bool {
    return false
  }

  public func setupXI2ForXWindow(window: Window) {

  }

  public func updateDeviceList(display: XDisplayHandle) {

  }

  public func isTouchDevice(device: Int) -> Bool {
    return false
  }

  internal static var _instance: X11TouchFactory?
}


internal class TouchEventCalibrate {
  init() {}

  func calibrate(event: TouchEvent, _ bounds: IntRect) {

  }
}

extension TouchFactory {
  public static func instance() -> X11TouchFactory? {
    if X11TouchFactory._instance == nil {
      X11TouchFactory._instance = X11TouchFactory()
    }
    return X11TouchFactory._instance
  }
}
