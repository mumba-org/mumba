// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base

public class SharedMemory : CallbackOwner {

  public var size: Int {
    return Int(_SharedMemoryGetSize(reference))
  }
  
  var callbacks: [Int : CallbackState]
  var sequence: AtomicSequence  
  let reference: SharedMemoryRef

  init(reference: SharedMemoryRef) {
    self.reference = reference
    callbacks = [:]
    sequence = AtomicSequence()
  }

  deinit {
    _SharedMemoryDestroy(reference)
  }

  public func map(_ callback: @escaping (_: UnsafeMutablePointer<Int8>?, _: Int) -> Void) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _SharedMemoryMap(reference, statePtr, { (handle: UnsafeMutableRawPointer?, buffer: UnsafeMutablePointer<Int8>?, size: CInt) in
      let cb = unsafeBitCast(handle, to: CallbackState.self)
      cb.bufferCallback!(buffer, Int(size))
      cb.deallocate()
    })
  }

  public func constMap(_ callback: @escaping (_: UnsafePointer<Int8>?, _: Int) -> Void) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _SharedMemoryConstMap(reference, statePtr, { (handle: UnsafeMutableRawPointer?, buffer: UnsafePointer<Int8>?, size: CInt) in
      let cb = unsafeBitCast(handle, to: CallbackState.self)
      cb.constBufferCallback!(buffer, Int(size))
      cb.deallocate()
    }) 
  }

  public func readToString() -> String {
    var result: String?
    constMap({ (buf, size) in
      result = String(cString: buf!)
    })
    return result!
  }

  public func add(_ state : CallbackState) {
    callbacks[state.id] = state
  }
  
  public func remove(_ state : CallbackState) {
    let _ = callbacks.removeValue(forKey: state.id)
  }
  
  public func generateId() -> Int {
    return sequence.next
  }

}