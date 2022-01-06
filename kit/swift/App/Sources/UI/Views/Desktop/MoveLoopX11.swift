// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Platform
import Foundation

public protocol MoveLoopX11Delegate {

  func onMouseMovement(screenPoint: IntPoint,
                       flags: Int,
                       eventTime: TimeTicks)

  func onMouseReleased()

  func onMoveLoopEnded()

}

public protocol MoveLoopX11 {
 func runMoveLoop(window: Window, cursor: PlatformCursor) -> Bool
 func updateCursor(cursor: PlatformCursor)
 func endMoveLoop()
}
