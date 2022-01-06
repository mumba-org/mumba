// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims

public class ArrayBufferView {

  public enum Kind : Int {
    case int8 = 0
    case uint8 = 1
    case uint8Clamped = 2
    case int16 = 3
    case uint16 = 4
    case int32 = 5
    case uint32 = 6
    case float32 = 7
    case float64 = 8
    case bigInt64 = 9
    case bigUint64 = 10
    case dataView = 11
  }

  public var type: Kind {
    return Kind(rawValue: Int(_DOMArrayBufferViewGetType(reference)))!
  }

  public var buffer: ArrayBuffer {
    return ArrayBuffer(reference: _DOMArrayBufferViewGetBuffer(reference))
  }

  public var byteLength: UInt {
    return UInt(_DOMArrayBufferViewGetByteLenght(reference))
  }

  public var byteOffset: UInt {
    return UInt(_DOMArrayBufferViewGetByteOffset(reference))
  }

  var reference: DOMArrayBufferViewRef

  internal init (reference: DOMArrayBufferViewRef) {
    self.reference = reference
  }

}

public struct ArrayBuffer {
  
  public var data: UnsafeMutableRawPointer? {
      return _DOMArrayBufferGetData(reference)
  } 

  public var byteLength: UInt {
      return UInt(_DOMArrayBufferGetByteLength(reference))
  }

  public var isNeutered: Bool {
      return _DOMArrayBufferIsNeutered(reference) != 0
  }

  public var isShared: Bool {
      return _DOMArrayBufferIsShared(reference) != 0
  }

  public static func create(numElements: UInt,
                            elementByteSize: UInt) -> ArrayBuffer {
    return ArrayBuffer(reference: _DOMArrayBufferCreate(UInt32(numElements), UInt32(elementByteSize))!)
  }

  public static func create(source: UnsafeRawPointer? , byteLength: UInt) -> ArrayBuffer {
    return ArrayBuffer(reference: _DOMArrayBufferCreateWithBuffer(source, UInt32(byteLength))!)
  }

  var reference: DOMArrayBufferRef

  init(reference: DOMArrayBufferRef) {
    self.reference = reference
  }

  public func slice(begin: Int, end: Int) -> ArrayBuffer {
    return ArrayBuffer(reference: _DOMArrayBufferSlice(reference, CInt(begin), CInt(end))!)
  }
  
  public func slice(begin: Int) -> ArrayBuffer {
    return ArrayBuffer(reference: _DOMArrayBufferSliceBegin(reference, CInt(begin))!)
  }

  public func base64EncodedString() -> String {
    return Data(bytesNoCopy: data!, count: Int(byteLength), deallocator: .none).base64EncodedString()
  }

}