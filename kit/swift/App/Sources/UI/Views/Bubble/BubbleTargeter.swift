// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class BubbleWindowTargeter : WindowTargeter {

  fileprivate var bubble: BubbleDialogDelegateView

  public init(bubble: BubbleDialogDelegateView) {
    self.bubble = bubble
  }

  public func getHitTestMask(window: Window, mask: Path) -> Bool {
    if let bounds = bubble.bubbleFrameView?.contentsBounds {
      mask.addRect(FloatRect(bounds))
      return true
    }
    return false
  }

}