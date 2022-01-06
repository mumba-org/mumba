// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims

public class Uint8ClampedArray : ArrayBufferView {
  
  public init(size: Int) {
    let ref = _Uint8ClampedArrayCreateWithSize(UInt32(size))
    super.init(reference: ref!)
  }

  public init(buffer: ArrayBuffer, offset: UInt, size: UInt) {
    let ref = _Uint8ClampedArrayCreateWithBuffer(buffer.reference, UInt32(offset), UInt32(size))
    super.init(reference: ref!)
  }

  public init(data: UnsafePointer<UInt8>?, size: UInt) {
    let ref = _Uint8ClampedArrayCreateWithData(data, UInt32(size))
    super.init(reference: ref!)
  }

  internal override init(reference: DOMArrayBufferViewRef) {
    super.init(reference: reference)
  }

}