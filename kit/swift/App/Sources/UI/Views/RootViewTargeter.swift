// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

class RootViewTargeter: ViewTargeter {

  var rootView: RootView

  init(delegate: ViewTargeterDelegate, rootView: RootView) {
    self.rootView = rootView
    super.init(delegate: delegate)
  }

  override func findTargetForGestureEvent(root: View, gesture: GestureEvent) -> View? {
    return nil
  }

  override func findNextBestTargetForGestureEvent(previousTarget: EventTarget, gesture: GestureEvent) -> EventTarget? {
    return nil
  }

}
