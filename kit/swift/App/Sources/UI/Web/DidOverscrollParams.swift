// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Compositor

public struct DidOverscrollParams {
  public var accumulatedOverscroll: FloatVec2
  public var latestOverscrollDelta: FloatVec2
  public var currentFlingVelocity: FloatVec2
  public var causalEventViewportPoint: FloatPoint
  public var overscrollBehavior: OverscrollBehavior
}