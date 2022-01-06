// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class DesktopWindowMoveClientX11 {

}

extension DesktopWindowMoveClientX11 : WindowMoveClient {

  public func runMoveLoop(window: Window,
                          dragOffset: IntVec2,
                          source: WindowMoveSource) -> WindowMoveResult {
    assert(false)
    return .MoveSuccessful
  }

  public func endMoveLoop() {
    assert(false)
  }

}
