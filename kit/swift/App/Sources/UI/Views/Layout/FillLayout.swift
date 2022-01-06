// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class FillLayout {
  public init() {}
}

extension FillLayout : LayoutManager {
  
  public func installed(host: View) {}
  
  public func uninstalled(host: View) {}
  
  public func layout(host: View) {
    if !host.hasChildren {
      return
    }

    if let frameView = host.childAt(index: 0) {
      frameView.bounds = host.contentsBounds
    }
  }

  public func getPreferredSize(host: View) -> IntSize {
    if !host.hasChildren {
      return IntSize()
    }
    
    assert(host.childCount == 1)
    var rect = IntRect(size: host.childAt(index: 0)!.preferredSize)
    rect.inset(insets: -host.insets)
    return rect.size
  }

  public func getPreferredHeightForWidth(host: View, width: Int) -> Int {
    if !host.hasChildren {
      return 0 
    }
    
    assert(host.childCount == 1)
    let insets = host.insets
    return host.childAt(index: 0)!.getHeightFor(width: width - insets.width) + insets.height
  }

  public func viewAdded(host: View, view: View) {}
  public func viewRemoved(host: View, view: View) {}
}