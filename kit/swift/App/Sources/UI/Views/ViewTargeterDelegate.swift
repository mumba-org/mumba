// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol ViewTargeterDelegate {
  func doesIntersectRect(target: View, rect: IntRect) -> Bool
  func targetForRect(root: View, rect: IntRect) -> View?
}

extension ViewTargeterDelegate {

  public func doesIntersectRect(target: View, rect: IntRect) -> Bool {
    return false
  }

  public func targetForRect(root: View, rect: IntRect) -> View? {
    return nil
  }

}
