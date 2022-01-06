// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class TestGpuMemoryBufferManager {

  var reference: GpuMemoryBufferManagerRef

  public init(reference: GpuMemoryBufferManagerRef) {
    self.reference = reference
  }

  public convenience init() {
    let manager = _TestGpuMemoryManagerCreate()
    self.init(reference: manager!)
  }

  deinit {
    _TestGpuMemoryManagerDestroy(reference)
  }

}

extension TestGpuMemoryBufferManager : GpuMemoryBufferManager {
  
}
