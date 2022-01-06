// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims

public class Uint8Array : ArrayBufferView {

  public init(size: UInt) {
    let ref = _Uint8ArrayCreateWithSize(UInt32(size))
    super.init(reference: ref!)
  }

  public init(buffer: ArrayBuffer, offset: UInt, size: UInt) {
    let ref = _Uint8ArrayCreateWithBuffer(buffer.reference, UInt32(offset), UInt32(size))
    super.init(reference: ref!)
  }

  public init(data: UnsafePointer<UInt8>?, size: UInt) {
    let ref = _Uint8ArrayCreateWithData(data, UInt32(size))
    super.init(reference: ref!)
  }

}