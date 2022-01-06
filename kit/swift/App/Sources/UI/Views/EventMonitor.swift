// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class EventMonitor {

  public static var lastMouseLocation: IntPoint {
    return IntPoint()
  }

  private var handler: EventHandler
  private var target: EventTarget

  public init(handler: EventHandler, target: EventTarget) {
    self.handler = handler
    self.target = target
  }

}
