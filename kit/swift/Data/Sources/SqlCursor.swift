// Copyright (c) 2022 Mumba. All rights reserved.
// Use of the source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Foundation
import Base

public class SqlCursor {
  
  public var isValid: Bool {
    let state = SingleValue<Bool>(false)
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _SQLCursorIsValidBlocking(reference, selfPtr, {
    //_DatabaseCursorIsValid(reference, selfPtr, { 
      (handle: UnsafeMutableRawPointer?, valid: CInt) in
      let stateRef = unsafeBitCast(handle, to: SingleValue<Bool>.self)
      stateRef.value = valid != 0
    })
    return state.value
  }

  internal var reference: SQLCursorRef
  
  init(reference: SQLCursorRef) {
    self.reference = reference
  }

  deinit {
    _SQLCursorDestroy(reference)
  }
  
  @discardableResult
  public func first() -> Bool {
    let state = SingleValue<Int>()
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _SQLCursorFirstBlocking(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt) in
        let stateRef = unsafeBitCast(handle, to: SingleValue<Int>.self)
        stateRef.value = Int(status)
    })
    return state.value == 0
  }

  @discardableResult
  public func last() -> Bool {
    let state = SingleValue<Int>()
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _SQLCursorLastBlocking(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt) in 
        let stateRef = unsafeBitCast(handle, to: SingleValue<Int>.self)
        stateRef.value = Int(status)
    })
    return state.value == 0
  }

  @discardableResult
  public func previous() -> Bool {
    let state = SingleValue<Int>()
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _SQLCursorPreviousBlocking(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt) in
      let stateRef = unsafeBitCast(handle, to: SingleValue<Int>.self)
      stateRef.value = Int(status)
    })
    return state.value == 0
  }

  @discardableResult
  public func next() -> Bool {
    let state = SingleValue<Int>()
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _SQLCursorNextBlocking(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt) in
      let stateRef = unsafeBitCast(handle, to: SingleValue<Int>.self)
      stateRef.value = Int(status)
    })
    return state.value == 0
  }
  
  public func getString(_ k: String) -> String? {
    let state = SingleValue<String?>()
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    k.withCString { cstr in
      cstr.withMemoryRebound(to: UInt8.self, capacity: k.count) {
        _SQLCursorGetStringBlocking(reference, $0, CInt(k.count), selfPtr, {
          (handle: UnsafeMutableRawPointer?, status: CInt, value: UnsafePointer<Int8>?, size: CInt) in 
          let stateRef = unsafeBitCast(handle, to: SingleValue<String?>.self)
          status == 0 ? stateRef.value = String(cString: value!) : nil
        })
      }
    }
    return state.value ?? nil
  }

  public func getInt(_ k : String) -> Int? {
    let state = SingleValue<Int?>()
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    k.withCString { cstr in
      cstr.withMemoryRebound(to: UInt8.self, capacity: k.count) {
        _SQLCursorGetIntBlocking(reference, $0, CInt(k.count), selfPtr, {
          (handle: UnsafeMutableRawPointer?, status: CInt, value: CInt) in 
          let stateRef = unsafeBitCast(handle, to: SingleValue<Int?>.self)
          status == 0 ? stateRef.value = Int(value) : nil
        })
      }
    }
    return state.value ?? nil
  }

  public func getDouble(_ k : String) -> Double? {
    let state = SingleValue<Double?>()
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    k.withCString { cstr in
      cstr.withMemoryRebound(to: UInt8.self, capacity: k.count) {
        _SQLCursorGetDoubleBlocking(reference, $0, CInt(k.count), selfPtr, {
          (handle: UnsafeMutableRawPointer?, status: CInt, value: Double) in 
          let stateRef = unsafeBitCast(handle, to: SingleValue<Double?>.self)
          status == 0 ? stateRef.value = value : nil
        })
      }
    }
    return state.value ?? nil
  }

  public func getBlob(_ k: String) -> Data? {
    let state = SingleValue<Data?>()
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    k.withCString { cstr in
      cstr.withMemoryRebound(to: UInt8.self, capacity: k.count) {
        _SQLCursorGetBlobBlocking(reference, $0, CInt(k.count), selfPtr, {
          (handle: UnsafeMutableRawPointer?, status: CInt, value: UnsafePointer<UInt8>?, size: CInt) in 
          let stateRef = unsafeBitCast(handle, to: SingleValue<Data?>.self)
          status == 0 ? stateRef.value = Data(bytes: value!, count: Int(size)) : nil
        })
      }
    }
    return state.value ?? nil
  }

}