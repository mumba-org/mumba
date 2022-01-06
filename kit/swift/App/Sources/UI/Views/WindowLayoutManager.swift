// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class WindowLayoutManager {
  public func onWindowResized() {}
  public func onWindowAddedToLayout(child: Window) {}
  public func onWillRemoveWindowFromLayout(child: Window) {}
  public func onWindowRemovedFromLayout(child: Window) {}
  public func onChildWindowVisibilityChanged(child: Window, visible: Bool) {}
  public func setChildBounds(child: Window, requestedBounds: IntRect) {}
  init() {}
}
