// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol WindowParentingClient : class {
  // Called by the Window when it looks for a default parent. Returns the
  // window that |window| should be added to instead. NOTE: this may have
  // side effects. It should only be used when |window| is going to be
  // immediately added.
  func getDefaultParent(window: Window, compositor: UIWebWindowCompositor, bounds: IntRect) -> Window?
}