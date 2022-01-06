// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

public class TestImageFactory {
  var reference: ImageFactoryRef

  public init(reference: ImageFactoryRef) {
    self.reference = reference
  }

  deinit {
    _TestImageFactoryDestroy(reference)
  }

  public convenience init() {
    let factory = _TestImageFactoryCreate()
    self.init(reference: factory!)
  }
}

extension TestImageFactory : ImageFactory {

  /*public func createImageForGpuMemoryBuffer(
     reference: GpuMemoryBufferHandle,
     size: IntSize,
     format: BufferFormat,
     internalformat: UInt,
     clientId: Int) -> GLImage? {
       return nil
     }*/

}
