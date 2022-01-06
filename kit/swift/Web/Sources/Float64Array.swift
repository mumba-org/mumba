// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims

public class Float64Array : ArrayBufferView {

  public init(size: UInt) {
    let ref = _Float64ArrayCreateWithSize(UInt32(size))
    super.init(reference: ref!)
  }

  public init(buffer: ArrayBuffer, offset: UInt, size: UInt) {
    let ref = _Float64ArrayCreateWithBuffer(buffer.reference, UInt32(offset), UInt32(size))
    super.init(reference: ref!)
  }

  public init(data: UnsafePointer<Double>?, size: UInt) {
    let ref = _Float64ArrayCreateWithData(data, UInt32(size))
    super.init(reference: ref!)
  }

}