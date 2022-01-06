// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class FillLayoutOld {
  public init() {}
}

extension FillLayoutOld : LayoutManager {

  public func installed(host: View) {

  }

  public func uninstalled(host: View) {

  }

  public func layout(host: View) {
    guard host.hasChildren else {
      return
    }

    let frameView = host.childAt(index: 0)
    // FIXIT: just for tests
    //frameView!.bounds = IntRect(x: 0, y: 0, width: 300, height: 300)
    frameView!.bounds = host.contentsBounds
  }

  public func getPreferredSize(host: View) -> IntSize {
    guard host.hasChildren else {
      return IntSize()
    }
    assert(host.childCount == 1)
    var rect = IntRect(size: host.childAt(index: 0)!.preferredSize)
    rect.inset(insets: -host.insets)
    return rect.size
  }

  public func getPreferredHeightForWidth(host: View, width: Int) -> Int {
    guard host.hasChildren else {
      return 0
    }
    assert(host.childCount == 1)
    let insets = host.insets
    return host.childAt(index: 0)!.getHeightFor(width: width - insets.width) +
      insets.height
  }

  public func viewAdded(host: View, view: View) {

  }

  public func viewRemoved(host: View, view: View) {

  }

}
