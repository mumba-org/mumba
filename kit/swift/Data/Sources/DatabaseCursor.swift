// Copyright (c) 2020 Mumba. All rights reserved.
// Use of stateRef source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Foundation
import Base

// TODO: use URL instead of names
// like "self://hello" or "tweedy://hello"

// Remember: we need to resolve the name
// and if the app is not installed..
// we need to download the dataset

public enum Seek : Int {
  case EQ = 0
  case LT = 1
  case LE = 2
  case GT = 3
  case GE = 4
}

public enum Order : Int {
  case ANY = 0
  case ASC = 1
  case DESC = 3
}

internal class SingleValue<T> {
  internal var value: T {
    get {
      // if its done waiting just handle the value
      guard !doneWaiting else {
        return _value!
      }
      event.wait()
      return _value!
    }
    set {
      _value = newValue
      doneWaiting = true
      event.signal() 
    }
  }

  private var _value: T?
  private let event = WaitableEvent(resetPolicy: .manual, initialState: .notSignaled)
  private var doneWaiting: Bool = false

  internal init() {}

  internal init(_ value: T) {
    self._value = value
  }

}


internal class TupleValue<T1, T2> {

  private var _first: T1?
  private var _second: T2?
  private let event = WaitableEvent(resetPolicy: .manual, initialState: .notSignaled)
  private var doneWaiting: Bool = false

  internal init() {}
  
  internal init(_ first: T1, _ second: T2) {
    self._first = first
    self._second = second
  }

  // a way to set both values and release the waitable event blocking
  internal func set(_ first: T1, _ second: T2) {
    self._first = first
    self._second = second
    doneWaiting = true
    event.signal()
  }

  internal func get() -> (T1, T2) {
    guard !doneWaiting else {
      return (_first!, _second!)
    }
    event.wait()
    return (_first!, _second!)
  }

}

public class DatabaseCursor {
  
  public var isValid: Bool {
    let state = SingleValue<Bool>(false)
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _DatabaseCursorIsValidBlocking(reference, selfPtr, {
    //_DatabaseCursorIsValid(reference, selfPtr, { 
      (handle: UnsafeMutableRawPointer?, valid: CInt) in
      let stateRef = unsafeBitCast(handle, to: SingleValue<Bool>.self)
      stateRef.value = valid != 0
    })
    return state.value
  }

  public var dataSize: Int {
    let state = SingleValue<Int>(0)
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    //_DatabaseCursorDataSize(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt, size: CInt) in
    _DatabaseCursorDataSizeBlocking(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt, size: CInt) in
      let stateRef = unsafeBitCast(handle, to: SingleValue<Int>.self)
      if status == 0 {
        stateRef.value = Int(size) 
      } else {
        stateRef.value = -1
      }
    });
    return state.value  
  }
  

  internal var reference: DatabaseCursorRef
  // TODO: instead of caching stateRef here maybe a scheme
  // like StorageContext do with CallbackState would be better
 
  init(reference: DatabaseCursorRef) {
    self.reference = reference
  }

  deinit {
    _DatabaseCursorDestroy(reference)
  }
  
  @discardableResult
  public func first() -> Bool {
    let state = SingleValue<Int>()
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _DatabaseCursorFirstBlocking(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt) in
    //_DatabaseCursorFirst(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt) in 
        let stateRef = unsafeBitCast(handle, to: SingleValue<Int>.self)
        stateRef.value = Int(status)
    })
    return state.value == 0
  }

  @discardableResult
  public func last() -> Bool {
    let state = SingleValue<Int>()
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _DatabaseCursorLastBlocking(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt) in 
    //_DatabaseCursorLast(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt) in 
        let stateRef = unsafeBitCast(handle, to: SingleValue<Int>.self)
        stateRef.value = Int(status)
    })
    return state.value == 0
  }

  @discardableResult
  public func previous() -> Bool {
    let state = SingleValue<Int>()
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _DatabaseCursorPreviousBlocking(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt) in
    //_DatabaseCursorPrevious(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt) in 
      let stateRef = unsafeBitCast(handle, to: SingleValue<Int>.self)
      stateRef.value = Int(status)
    })
    return state.value == 0
  }

  @discardableResult
  public func next() -> Bool {
    let state = SingleValue<Int>()
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _DatabaseCursorNextBlocking(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt) in
    //_DatabaseCursorNext(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt) in 
      let stateRef = unsafeBitCast(handle, to: SingleValue<Int>.self)
      stateRef.value = Int(status)
    })
    return state.value == 0
  }


  public func seek(_ to: String, op: Seek) -> (Int, Bool) {
    return seek(Data(to.utf8), op: op)
  }

  public func seek(_ to: Data, op: Seek) -> (Int, Bool) {
    let state = TupleValue<Int, Bool>()
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    to.withUnsafeBytes {
      _DatabaseCursorSeekToBlocking(reference, $0, CInt(to.count), CInt(op.rawValue), selfPtr, {
      //_DatabaseCursorSeekTo(reference, $0, CInt(key.count), CInt(seek.rawValue), selfPtr, { 
          (handle: UnsafeMutableRawPointer?, r: CInt, match: CInt) in 
        let stateRef = unsafeBitCast(handle, to: TupleValue<Int, Bool>.self)
        stateRef.set(Int(r), match != 0)
      })
    }
    return state.get()
  }
  
  public func count() -> Int {
    let state = SingleValue<Int>()
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _DatabaseCursorCountBlocking(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt, count: CInt) in
    //_DatabaseCursorCount(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt, count: CInt) in
       let stateRef = unsafeBitCast(handle, to: SingleValue<Int>.self)
       //if status == 0 { 
       stateRef.value = Int(count)
       //} else {
       // stateRef.value = -1
       //}
    })
    return state.value
  }

  public func getData() -> Data? {
    let state =  SingleValue<Data?>()
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _DatabaseCursorGetDataBlocking(reference, selfPtr, {
    //_DatabaseCursorGetData(reference, selfPtr, {
      (handle: UnsafeMutableRawPointer?, status: CInt, data: UnsafePointer<UInt8>?, count: CInt) in 
      let stateRef = unsafeBitCast(handle, to: SingleValue<Data?>.self)
      // NOTE: we will need to copy/own the bytes, as it will
      // became invalid as soon is gets out of stateRef callback scope
      status == 0 ? stateRef.value = Data(bytes: data!, count: Int(count)) : nil
    })
    return state.value ?? nil
  }

  public func getKeyValue() -> (Data?, Data?) {
    let state = TupleValue<Data?, Data?>()
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _DatabaseCursorGetKeyValueBlocking(reference, selfPtr, {
    //_DatabaseCursorGetKeyValue(reference, selfPtr, { 
      (handle: UnsafeMutableRawPointer?, status: CInt, key: UnsafePointer<UInt8>?, keylen: CInt, value: UnsafePointer<UInt8>?, valuelen: CInt) in
        let stateRef = unsafeBitCast(handle, to: TupleValue<Data?, Data?>.self)
        if status == 0 {
          stateRef.set(Data(bytes: key!, count: Int(keylen)), Data(bytes: value!, count: Int(valuelen)))
        } else {
          stateRef.set(nil, nil)
        }
    })
    return state.get()
  }
  
  public func getValue(key k: Data) -> Data? {
    let state = SingleValue<Data?>()
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    let keybytes = k.withUnsafeBytes {
      return $0
    } 
    _DatabaseCursorGetBlocking(reference, keybytes.baseAddress!.bindMemory(to: UInt8.self, capacity: k.count), CInt(k.count), selfPtr, {
    //_DatabaseCursorGet(reference, keybytes.baseAddress!.bindMemory(to: UInt8.self, capacity: k.count), CInt(k.count), selfPtr, { 
      (handle: UnsafeMutableRawPointer?, status: CInt, value: UnsafePointer<UInt8>?, size: CInt) in 
      let stateRef = unsafeBitCast(handle, to: SingleValue<Data?>.self)
      // NOTE: we will need to copy/own the bytes, as it will
      // became invalid as soon is gets out of stateRef callback scope
      print("Cursor.getValue: done. signalling.")
      status == 0 ? stateRef.value = Data(bytes: value!, count: Int(size)) : nil
    })
    print("Cursor.getValue: waiting...")
    return state.value ?? nil
  }
  
  public func insert(key k: String, value v: String) -> Bool {
    return insert(key: Data(k.utf8), value: Data(v.utf8))
  }

  public func insert(key k: Data, value v: Data) -> Bool {
    let state = SingleValue<Int>()
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    k.withUnsafeBytes { kbytes in 
      v.withUnsafeBytes { vbytes in 
        //_DatabaseCursorInsertBlocking(reference, kbytes.baseAddress!.bindMemory(to: UInt8.self, capacity: k.count), CInt(k.count), vbytes.baseAddress!.bindMemory(to: UInt8.self, capacity: v.count), CInt(v.count),
        _DatabaseCursorInsertBlocking(reference, kbytes, CInt(k.count), vbytes, CInt(v.count),
        //_DatabaseCursorInsert(reference, kbytes.baseAddress!.bindMemory(to: UInt8.self, capacity: k.count), CInt(k.count), vbytes.baseAddress!.bindMemory(to: UInt8.self, capacity: v.count), CInt(v.count), 
          selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt) in 
            let stateRef = unsafeBitCast(handle, to: SingleValue<Int>.self)
            stateRef.value = Int(status)
          })
      }
    }
    return state.value == 0
  }
  
  @discardableResult
  public func delete() -> Bool {
    let state = SingleValue<Int>()
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _DatabaseCursorDeleteBlocking(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt) in
    //_DatabaseCursorDelete(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt) in 
      let stateRef = unsafeBitCast(handle, to: SingleValue<Int>.self)
      stateRef.value = Int(status)
    })
    return state.value == 0
  }
  
  @discardableResult
  public func commit() -> Bool {
    let state = SingleValue<Int>()
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _DatabaseCursorCommitBlocking(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt) in
    //_DatabaseCursorCommit(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt) in 
      let stateRef = unsafeBitCast(handle, to: SingleValue<Int>.self)
      stateRef.value = Int(status)
    })
    return state.value == 0
  }
  
  @discardableResult
  public func rollback() -> Bool {
    let state = SingleValue<Int>()
    let selfPtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _DatabaseCursorRollbackBlocking(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt) in
    //_DatabaseCursorRollback(reference, selfPtr, { (handle: UnsafeMutableRawPointer?, status: CInt) in 
       let stateRef = unsafeBitCast(handle, to: SingleValue<Int>.self)
       stateRef.value = Int(status)
    })
    return state.value == 0
  }

}