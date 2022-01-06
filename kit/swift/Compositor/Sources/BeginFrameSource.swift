// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base

public class BeginFrameSource {

  internal var reference: BeginFrameSourceRef

  internal init(reference: BeginFrameSourceRef) {
    self.reference = reference
  }

  deinit {
    _BeginFrameSourceDestroy(reference)
  }

}

public class DelayBasedBeginFrameSource : BeginFrameSource {

  public init(delta: TimeDelta) {
    let ref = _BeginFrameSourceCreateDelayBased(delta.microseconds)
    super.init(reference: ref!)
  }

}

public class BackToBackBeginFrameSource : BeginFrameSource {

  public init() {
    let ref = _BeginFrameSourceCreateBackToBack()
    super.init(reference: ref!)
  }

}