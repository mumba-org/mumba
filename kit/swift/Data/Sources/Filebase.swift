// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Foundation
import MumbaShims

public class Filebase : CallbackOwner {

  //public let name: String
  var reference: FilebaseRef
  var callbacks: [Int : CallbackState]
  var sequence: AtomicSequence
  weak var storage: Storage?

  init(storage: Storage, reference: FilebaseRef) {
    self.storage = storage
    self.reference = reference
    callbacks = [:]
    sequence = AtomicSequence()
  }

  deinit {
    _FilebaseDestroy(reference)
  }

  public func readAll(from file: String, _ callback: @escaping ReadCallback) {
    readAll(from: file, offset: 0, size: -1, callback)
  }

  public func readAll(from file: String, offset: Int, size: Int, _ callback: @escaping ReadCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    file.withCString { fileCString in
      _FilebaseReadOnce(reference, fileCString, CInt(offset), CInt(size), statePtr, { (handle: UnsafeMutableRawPointer?, statusCode: CInt, shmem: SharedMemoryRef?) in
        let cb = unsafeBitCast(handle, to: CallbackState.self)
        cb.readCallback!(Int(statusCode), statusCode == 0 ? SharedMemory(reference: shmem!) : nil)
        cb.deallocate()
      })
    }
  }

  public func write(to file: String, data: String, _ callback: @escaping SizeCallback) {
    write(to: file, offset: 0, data: Data(data.utf8), callback)
  }

  public func write(to file: String, offset: Int, data: String, _ callback: @escaping SizeCallback) {
    write(to: file, offset: offset, data: Data(data.utf8), callback)
  }

  public func write(to file: String, data: Data, _ callback: @escaping SizeCallback) {
    write(to: file, offset: 0, data: data, callback)
  }

  public func write(to file: String, offset: Int, data: Data, _ callback: @escaping SizeCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    file.withCString { fileCString in
      data.withUnsafeBytes { dataBytes in
        _FilebaseWriteOnce(reference, fileCString, CInt(offset), CInt(data.count), dataBytes, statePtr, { (handle: UnsafeMutableRawPointer?, statusCode: CInt, bytesWritten: CInt) in
          let cb = unsafeBitCast(handle, to: CallbackState.self)
          cb.sizeCallback!(Int(statusCode), Int(bytesWritten))
          cb.deallocate()
        })
      }
    }
  }

  public func close(_ callback: @escaping StatusCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _FilebaseClose(reference, statePtr, { (handle: UnsafeMutableRawPointer?, statusCode: CInt) in
      let cb = unsafeBitCast(handle, to: CallbackState.self)
      cb.statusCallback!(Int(statusCode))
      cb.deallocate()
      let this = cb.context as? Filebase
      this!.storage!.onFilebaseClose(this!)
    })
  }
 
  public func generateId() -> Int {
    return sequence.next + 1
  }

  public func add(_ state: CallbackState) {
    callbacks[state.id] = state
  }

  public func remove(_ state: CallbackState) {
    let _ = callbacks.removeValue(forKey: state.id)
  }

}