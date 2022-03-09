// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Foundation
import MumbaShims

// TODO: use URL instead of names
// like "self://hello" or "tweedy://hello"

public class Database : CallbackOwner {

  //public let name: String
  var reference: DatabaseRef
  var callbacks: [Int : CallbackState]
  var sequence: AtomicSequence
  weak var storage: Storage?

  init(storage: Storage, reference: DatabaseRef) {
    self.storage = storage
    self.reference = reference
    callbacks = [:]
    sequence = AtomicSequence()
  }

  deinit {
    _DatabaseDestroy(reference)
  }

  public func close(_ callback: @escaping StatusCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _DatabaseClose(reference, statePtr, { (handle: UnsafeMutableRawPointer?, statusCode: CInt) in
      let cb = unsafeBitCast(handle, to: CallbackState.self)
      cb.statusCallback!(Int(statusCode))
      cb.deallocate()
      let this = cb.context as? Database
      this!.storage!.onDatabaseClose(this!)
    })
  }

  public func createCursor(keyspace: String, order: Order, write: Bool, _ callback: @escaping CursorCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    keyspace.withCString { ksBytes in
      _DatabaseCursorCreate(reference, ksBytes, CInt(order.rawValue), write ? 1 : 0, statePtr, { (handle: UnsafeMutableRawPointer?, cursor: DatabaseCursorRef?) in
        let cb = unsafeBitCast(handle, to: CallbackState.self)
        if cursor != nil {
          cb.cursorCallback!(DatabaseCursor(reference: cursor!))
        } else {
          cb.cursorCallback!(nil)
        }
        cb.deallocate()
      })
    }
  }

  public func executeQuery(_ sqlQuery: String, _ callback: @escaping SqlCursorCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    sqlQuery.withCString { sqlQueryBytes in
      _DatabaseExecuteQuery(reference, sqlQueryBytes, statePtr, { (handle: UnsafeMutableRawPointer?, cursor: SQLCursorRef?) in
        let cb = unsafeBitCast(handle, to: CallbackState.self)
        if cursor != nil {
          cb.sqlCursorCallback!(SqlCursor(reference: cursor!))
        } else {
          cb.sqlCursorCallback!(nil)
        }
        cb.deallocate()
      })
    }
  }

  public func createKeyspace(keyspace: String, _ callback: @escaping StatusCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    keyspace.withCString { keyCString in 
      _DatabaseKeyspaceCreate(reference, statePtr, keyCString, { (handle: UnsafeMutableRawPointer?, statusCode: CInt) in
        let cb = unsafeBitCast(handle, to: CallbackState.self)
        cb.statusCallback!(Int(statusCode))
        cb.deallocate()
      })
    }
  }

  public func dropKeyspace(keyspace: String, _ callback: @escaping StatusCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    keyspace.withCString { keyCString in 
      _DatabaseKeyspaceDrop(reference, statePtr, keyCString, { (handle: UnsafeMutableRawPointer?, statusCode: CInt) in
        let cb = unsafeBitCast(handle, to: CallbackState.self)
        cb.statusCallback!(Int(statusCode))
        cb.deallocate()
      })
    }
  }

  public func listKeyspaces(_ callback: @escaping StringListCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _DatabaseKeyspaceList(reference, statePtr, { (handle: UnsafeMutableRawPointer?, 
        statusCode: CInt, 
        count: CInt,
        keyspaces: UnsafeMutablePointer<UnsafePointer<Int8>?>?) in
      var keyspaceList: [String] = []
      let cb = unsafeBitCast(handle, to: CallbackState.self)
      for i in 0..<Int(count) {
        keyspaceList.append(String(cString: keyspaces![i]!))
      }
      cb.stringListCallback!(Int(statusCode), keyspaceList)
      cb.deallocate()
    })
  }

  public func get(key: String, _ callback: @escaping ReadCallback) {
    get(keyspace: ".global", key: Data(key.utf8), callback)
  }

  public func get(keyspace: String, key: String, _ callback: @escaping ReadCallback) {
    get(keyspace: keyspace, key: Data(key.utf8), callback)
  }

  public func get(keyspace: String, key: Data, _ callback: @escaping ReadCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    keyspace.withCString { keyspaceCString in
      key.withUnsafeBytes { keyBytes in
        _DatabaseGet(reference, statePtr, keyspaceCString, keyBytes, { (handle: UnsafeMutableRawPointer?, statusCode: CInt, shmem: SharedMemoryRef?) in
          let cb = unsafeBitCast(handle, to: CallbackState.self)
          if statusCode == 0 {
            cb.readCallback!(Int(statusCode), SharedMemory(reference: shmem!))
          } else {
            cb.readCallback!(Int(statusCode), nil)
          }
          cb.deallocate()
        })
      }
    }
  }

  public func put(key: String, value: String, _ callback: @escaping StatusCallback) {
    put(keyspace: ".global", key: Data(key.utf8), value: Data(value.utf8), callback)
  }

  public func put(key: Data, value: Data, _ callback: @escaping StatusCallback) {
    put(keyspace: ".global", key: key, value: value, callback)
  }

  public func put(keyspace: String, key: String, value: String, _ callback: @escaping StatusCallback) {
    put(keyspace: keyspace, key: Data(key.utf8), value: Data(value.utf8), callback)
  }

  public func put(keyspace: String, key: Data, value: Data, _ callback: @escaping StatusCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    keyspace.withCString { keyspaceCString in 
      key.withUnsafeBytes { keyBytes in
        value.withUnsafeBytes { valBytes in 
          _DatabasePut(reference, statePtr, keyspaceCString, keyBytes, valBytes, CInt(value.count), { (handle: UnsafeMutableRawPointer?, statusCode: CInt) in
            let cb = unsafeBitCast(handle, to: CallbackState.self)
            cb.statusCallback!(Int(statusCode))
            cb.deallocate()
          })
        }
      }
    }
  }

  public func delete(key: String, _ callback: @escaping StatusCallback) {
    delete(keyspace: ".global", key: Data(key.utf8), callback)
  }

  public func delete(keyspace: String, key: String, _ callback: @escaping StatusCallback) {
    delete(keyspace: keyspace, key: Data(key.utf8), callback)
  }

  public func delete(keyspace: String, key: Data, _ callback: @escaping StatusCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)  
    keyspace.withCString { keyspaceCString in 
      key.withUnsafeBytes { keyBytes in
        _DatabaseDelete(reference, statePtr, keyspaceCString, keyBytes, { (handle: UnsafeMutableRawPointer?, statusCode: CInt) in
          let cb = unsafeBitCast(handle, to: CallbackState.self)
          cb.statusCallback!(Int(statusCode))
          cb.deallocate()
        })
      }
    }
  }

  public func deleteAll(keyspace: String, _ callback: @escaping StatusCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)    
    keyspace.withCString { keyspaceCString in
      _DatabaseDeleteAll(reference, statePtr, keyspaceCString, { (handle: UnsafeMutableRawPointer?, statusCode: CInt) in
        let cb = unsafeBitCast(handle, to: CallbackState.self)
        cb.statusCallback!(Int(statusCode))
        cb.deallocate()
      })  
    }
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