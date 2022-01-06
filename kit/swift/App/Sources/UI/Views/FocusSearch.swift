// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class FocusSearch {

  // own us
  weak var root: View?

  var cycle: Bool

  var accessibilityMode: Bool

  public init(root: View, cycle: Bool, accessibilityMode: Bool) {
    self.root = root
    self.cycle = cycle
    self.accessibilityMode = accessibilityMode
  }

}
