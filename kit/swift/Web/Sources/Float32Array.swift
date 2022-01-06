// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims

public class Float32Array : ArrayBufferView {
  
  public init(size: UInt) {
    let ref = _Float32ArrayCreateWithSize(UInt32(size))
    super.init(reference: ref!)
  }

  public init(buffer: ArrayBuffer, offset: UInt, size: Int) {
    let ref = _Float32ArrayCreateWithBuffer(buffer.reference, UInt32(offset), UInt32(size))
    super.init(reference: ref!)
  }

  public init(data: UnsafePointer<Float>?, size: Int) {
    let ref = _Float32ArrayCreateWithData(data, UInt32(size))
    super.init(reference: ref!)
  }

  public init(_ array: [Float]) {
    let ref = array.withUnsafeBufferPointer {
      return _Float32ArrayCreateWithData($0.baseAddress!, UInt32(array.count))
    }
    super.init(reference: ref!)
  }

}