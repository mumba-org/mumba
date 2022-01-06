// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class DesktopScreenPositionClient : DefaultScreenPositionClient {

  private var rootWindow: Window

  public init(rootWindow: Window) {
    self.rootWindow = rootWindow
  }

  public override func setBounds(window: Window,
                                 bounds: IntRect,
                                 display: Display) {
    assert(false)
  }

}
