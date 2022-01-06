// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

public struct SelectionBoundsParams {
  public var anchorRect: IntRect = IntRect()
  public var anchorDir: TextDirection = TextDirection.LeftToRight
  public var focusRect: IntRect = IntRect()
  public var focusDir: TextDirection = TextDirection.LeftToRight
  public var isAnchorFirst: Bool = false
}
