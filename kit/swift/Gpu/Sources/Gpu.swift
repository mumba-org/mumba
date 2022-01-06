// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Graphics

public enum PriorityCutoff : Int {
  case allowRequiredOnly = 0
  case allowNiceToHave = 1
  case allowEverything = 2
}

public func createCommandBufferSkiaGLBinding() -> GrGLInterface {
  let reference: GrGLInterfaceRef = _CreateCommandBufferSkiaGLBinding()
  //assert(reference != nil)
  return GrGLInterface(reference: reference)
}

extension Bool {
  public init(_ i: Int32) {
    self.init(i != 0)
  }

  public init(_ i: Int) {
    self.init(i != 0)
  }

  public var intValue: Int32 {
    if self == true {
      return Int32(1)
    } else {
      return Int32(0)
    }
  }
}
