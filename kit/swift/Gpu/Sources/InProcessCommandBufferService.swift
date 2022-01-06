// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class InProcessCommandBufferService {

  var reference: InProcessCommandBufferServiceRef

  public init(reference: InProcessCommandBufferServiceRef) {
    self.reference = reference
  }

}
