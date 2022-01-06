// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class LayerTreeMutator {
  
  internal var reference: LayerTreeHostRef!

  public init(reference: LayerTreeHostRef) {
    self.reference = reference
  }

}