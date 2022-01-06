// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class PropertyTrees {
  private var reference: PropertyTreesRef

  public init(reference: PropertyTreesRef) {
    self.reference = reference
  }

  deinit {
    _PropertyTreesDestroy(reference)
  }
}
