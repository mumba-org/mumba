// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol TooltipClient {
  func getMaxWidth(point: IntPoint, context: Window) -> Int
  func updateTooltip(target: Window)
  func setTooltipShownTimeout(target: Window, timeoutInMs: Int)
  func setTooltipsEnabled(enable: Bool)
}
