// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Foundation
import MumbaShims

public typealias AllocatedSizeCallback = (_: Int64) -> Void
public typealias ListSharesCallback = (_: [ShareInfo]) -> Void
public typealias StatusCallback = (_: Int) -> Void
public typealias SizeCallback = (_: Int, _: Int) -> Void
public typealias DatabaseCallback = (_: Int, _: Database?) -> Void
public typealias FilebaseCallback = (_: Int, _: Filebase?) -> Void
public typealias GetCallback = (_: Int, _: Data?) -> Void
public typealias ExistsCallback = (_: Bool) -> Void
public typealias StringListCallback = (_: Int, _: [String]) -> Void
public typealias CursorCallback = (_: DatabaseCursor?) -> Void
public typealias SqlCursorCallback = (_: SqlCursor?) -> Void
public typealias ListFilesCallback = (_: [ShareEntry]) -> Void
public typealias ReadCallback = (_: Int, _: SharedMemory?) -> Void
public typealias BufferCallback = (_: UnsafeMutablePointer<Int8>?, _: Int) -> Void
public typealias ConstBufferCallback = (_: UnsafePointer<Int8>?, _: Int) -> Void

public protocol CallbackOwner : class {
  func add(_ : CallbackState)
  func remove(_ : CallbackState)
  func generateId() -> Int
}

public class CallbackState {
  public var id: Int
  public var allocatedSizeCallback: AllocatedSizeCallback?
  public var listSharesCallback: ListSharesCallback?
  public var listFilesCallback: ListFilesCallback?
  public var statusCallback: StatusCallback?
  public var sizeCallback: SizeCallback?
  public var getCallback: GetCallback?
  public var existsCallback: ExistsCallback?
  public var databaseCallback: DatabaseCallback?
  public var filebaseCallback: FilebaseCallback?
  public var stringListCallback: StringListCallback?
  public var cursorCallback: CursorCallback?
  public var sqlCursorCallback: SqlCursorCallback?
  public var readCallback: ReadCallback?
  public var bufferCallback: BufferCallback?
  public var constBufferCallback: ConstBufferCallback?
  private var keyspaces: UnsafeMutablePointer<UnsafeMutablePointer<Int8>?>?
  private var keyspacesCount: Int = 0

  public unowned var context: CallbackOwner?

  public init(_ context: CallbackOwner, _ callback: @escaping AllocatedSizeCallback) {
    self.context = context
    self.id = context.generateId()
    self.allocatedSizeCallback = callback
    self.context!.add(self)
  }

  public init(_ context: CallbackOwner, _ callback: @escaping DatabaseCallback) {
    self.context = context
    self.id = context.generateId()
    self.databaseCallback = callback
    self.context!.add(self)
  }

  public init(_ context: CallbackOwner, _ callback: @escaping FilebaseCallback) {
    self.context = context
    self.id = context.generateId()
    self.filebaseCallback = callback
    self.context!.add(self)
  }

  public init(_ context: CallbackOwner, _ callback: @escaping ListSharesCallback) {
    self.context = context
    self.id = context.generateId()
    self.listSharesCallback = callback
    self.context!.add(self)
  }

  public init(_ context: CallbackOwner, _ callback: @escaping ListFilesCallback) {
    self.context = context
    self.id = context.generateId()
    self.listFilesCallback = callback
    self.context!.add(self)
  }

  public init(_ context: CallbackOwner, _ callback: @escaping StatusCallback) {
    self.context = context
    self.id = context.generateId()
    self.statusCallback = callback
    self.context!.add(self)
  }

  public init(_ context: CallbackOwner, _ callback: @escaping SizeCallback) {
    self.context = context
    self.id = context.generateId()
    self.sizeCallback = callback
    self.context!.add(self)
  }

  public init(_ context: CallbackOwner, _ callback: @escaping DatabaseCallback, keyspaces: UnsafeMutablePointer<UnsafeMutablePointer<Int8>?>, count: Int) {
    self.context = context
    self.id = context.generateId()
    self.databaseCallback = callback
    self.keyspaces = keyspaces
    self.keyspacesCount = count
    self.context!.add(self)
  }

  public init(_ context: CallbackOwner, _ callback: @escaping GetCallback) {
    self.context = context
    self.id = context.generateId()
    self.getCallback = callback
    self.context!.add(self)
  }

  public init(_ context: CallbackOwner, _ callback: @escaping ExistsCallback) {
    self.context = context
    self.id = context.generateId()
    self.existsCallback = callback
    self.context!.add(self)
  }


  public init(_ context: CallbackOwner, _ callback: @escaping StringListCallback) {
    self.context = context
    self.id = context.generateId()
    self.stringListCallback = callback
    self.context!.add(self)
  }

  public init(_ context: CallbackOwner, _ callback: @escaping CursorCallback) {
    self.context = context
    self.id = context.generateId()
    self.cursorCallback = callback
    self.context!.add(self)
  }

  public init(_ context: CallbackOwner, _ callback: @escaping SqlCursorCallback) {
    self.context = context
    self.id = context.generateId()
    self.sqlCursorCallback = callback
    self.context!.add(self)
  }

  public init(_ context: CallbackOwner, _ callback: @escaping ReadCallback) {
    self.context = context
    self.id = context.generateId()
    self.readCallback = callback
    self.context!.add(self)
  }

  public init(_ context: CallbackOwner, _ callback: @escaping BufferCallback) {
    self.context = context
    self.id = context.generateId()
    self.bufferCallback = callback
    self.context!.add(self) 
  }
  
  public init(_ context: CallbackOwner, _ callback: @escaping ConstBufferCallback) {
    self.context = context
    self.id = context.generateId()
    self.constBufferCallback = callback
    self.context!.add(self)
  }
  
  public func deallocate() {
    if keyspaces != nil {
      free(keyspaces)
    }
    context!.remove(self)
  }
}

// Mostly for share events now
public protocol StorageDelegate {
  func onShareDHTAnnounceReply(uuid: String, peers: Int)
  func onShareMetadataReceived(uuid: String)
  func onShareMetadataError(uuid: String, error: Int)
  func onSharePieceReadError(uuid: String, piece: Int, error: Int)
  func onSharePiecePass(uuid: String, piece: Int)
  func onSharePieceFailed(uuid: String, piece: Int)
  func onSharePieceRead(uuid: String, piece: Int, offset: Int, size: Int, blockSize: Int, result: Int)
  func onSharePieceWrite(uuid: String, piece: Int, offset: Int, size: Int, blockSize: Int, result: Int)
  func onSharePieceHashFailed(uuid: String, piece: Int)
  func onShareCheckingFiles(uuid: String)
  func onShareDownloadingMetadata(uuid: String)
  func onShareFileRenamed(uuid: String, fileOffset: Int, name: String, error: Int)
  func onShareResumed(uuid: String)
  func onShareChecked(uuid: String, result: Int)
  func onSharePieceComplete(uuid: String, piece: Int)
  func onShareFileComplete(uuid: String, fileOffset: Int)
  func onShareDownloading(uuid: String)
  func onShareComplete(uuid: String) 
  func onShareSeeding(uuid: String) 
  func onSharePaused(uuid: String)
}

public class Storage : CallbackOwner {

  var reference: StorageRef
  var callbacks: [Int : CallbackState]
  var sequence: AtomicSequence
  var filebases: ContiguousArray<Filebase>
  var databases: ContiguousArray<Database>

  public init(reference: StorageRef) {
    self.reference = reference
    callbacks = [:]
    sequence = AtomicSequence()
    filebases = ContiguousArray<Filebase>()
    databases = ContiguousArray<Database>()
  }

  deinit {
    _StorageDestroy(reference)
  }

  public func getAllocatedSize() -> Int64 {
    var size: Int64 = 0
    let event = WaitableEvent(resetPolicy: .manual, initialState: .notSignaled)
    getAllocatedSize( {
      size = $0
      event.signal()
    })
    event.wait()
    return size
  }

  public func getAllocatedSize(_ callback: @escaping AllocatedSizeCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _StorageGetAllocatedSize(reference, statePtr, { (handle: UnsafeMutableRawPointer?, size: Int64) in
       let cb = unsafeBitCast(handle, to: CallbackState.self)
       cb.allocatedSizeCallback!(size)
       cb.deallocate()
    })
  }

  public func listShares() -> [ShareInfo] {
    var shares: [ShareInfo]?
    let event = WaitableEvent(resetPolicy: .manual, initialState: .notSignaled)
    listShares( {
      shares = $0
      event.signal()
    })
    event.wait()
    return shares!
  }

  public func listShares(_ callback: @escaping ListSharesCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _StorageListShares(reference, statePtr, { (
      handle: UnsafeMutableRawPointer?,
      count: CInt,
      uuid: UnsafeMutablePointer<UnsafePointer<Int8>?>?,
      path: UnsafeMutablePointer<UnsafePointer<Int8>?>?,
      kind: UnsafeMutablePointer<Int32>?,
      state: UnsafeMutablePointer<Int32>?,
      rootHash: UnsafeMutablePointer<UnsafePointer<Int8>?>?,
      size: UnsafeMutablePointer<Int64>?,
      blocks: UnsafeMutablePointer<Int32>?,
      blockSize: UnsafeMutablePointer<Int32>?,
      createdTime: UnsafeMutablePointer<Int64>?,
      entryCount: UnsafeMutablePointer<Int32>?) in
       var infos: [ShareInfo] = []
       let cb = unsafeBitCast(handle, to: CallbackState.self)
       for i in 0..<Int(count) {
          let info = ShareInfo()
          info.uuid = String(cString: uuid![i]!)
          info.path = String(cString: path![i]!)
          info.kind = ShareInfoKind(rawValue: Int(kind![i]))!
          info.state = ShareInfoState(rawValue: Int(state![i]))!
          info.rootHash = String(cString: rootHash![i]!)
          info.size = size![i]
          info.blocks = Int(blocks![i])
          info.blockSize = Int(blockSize![i])
          info.createdTime = createdTime![i]
          info.entryCount = Int(entryCount![i])
          infos.append(info)
       }
       cb.listSharesCallback!(infos)
       cb.deallocate()
    })
  }

  public func createDatabase(_ db: String, _ inMemory: Bool = false, _ callback: @escaping DatabaseCallback) {
    createDatabase(db, inMemory, keyspace: nil, callback)
  }

  public func createDatabase(_ db: String, _ inMemory: Bool = false, keyspace: String?, _ callback: @escaping DatabaseCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    db.withCString { nameCString in 
      if let ks = keyspace {
        ks.withCString { keyspaceCString in
          _StorageDatabaseCreate(reference, statePtr, nameCString, keyspaceCString, inMemory ? 1 : 0, { (handle: UnsafeMutableRawPointer?, statusCode: CInt, db: UnsafeMutableRawPointer?) in
            let cb = unsafeBitCast(handle, to: CallbackState.self)
            var database: Database?
            if statusCode == 0 {
              let this = cb.context as? Storage
              database = Database(storage: this!, reference: db!)
              this!.databases.append(database!) 
            }
            cb.databaseCallback!(Int(statusCode), database)
            cb.deallocate()
          })       
        }
      } else {
        _StorageDatabaseCreate(reference, statePtr, nameCString, nil, inMemory ? 1 : 0, { (handle: UnsafeMutableRawPointer?, statusCode: CInt, db: UnsafeMutableRawPointer?) in
          let cb = unsafeBitCast(handle, to: CallbackState.self)
          var database: Database?
          if statusCode == 0 {
            let this = cb.context as? Storage
            database = Database(storage: this!, reference: db!)
            this!.databases.append(database!) 
          }
          cb.databaseCallback!(Int(statusCode), database)
          cb.deallocate()
        })
      }
    }
    
  }

  public func createDatabase(_ db: String, keyspaces: [String], _ callback: @escaping DatabaseCallback) {
    let keyspacesCString = malloc(keyspaces.count * MemoryLayout<UnsafeMutablePointer<Int8>>.stride).bindMemory(to: UnsafeMutablePointer<Int8>?.self, capacity: keyspaces.count)
    for (i, keyspace) in keyspaces.enumerated() {
      keyspace.withCString {
        let len = keyspace.count
        keyspacesCString[i] = malloc(len + 1 * MemoryLayout<Int8>.stride).bindMemory(to: Int8.self, capacity: len + 1)
        memcpy(keyspacesCString[i]!, $0, len)
        // officially make it a c string by adding a null byte at the end of it
        let lastByte = keyspacesCString[i]! + len
        lastByte.pointee = 0
      }   
    }
    let state = CallbackState(self, callback, keyspaces: keyspacesCString, count: keyspaces.count)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    db.withCString { nameCString in 
      _StorageDatabaseCreateWithKeyspaces(reference, statePtr, nameCString, keyspacesCString, CInt(keyspaces.count), { (handle: UnsafeMutableRawPointer?, statusCode: CInt, db: UnsafeMutableRawPointer?) in
        let cb = unsafeBitCast(handle, to: CallbackState.self)
        var database: Database?
        if statusCode == 0 {
          let this = cb.context as? Storage
          database = Database(storage: this!, reference: db!)
          this!.databases.append(database!) 
        }
        cb.databaseCallback!(Int(statusCode), database)
        cb.deallocate()
      })
    }
  }

  public func openDatabase(_ db: String, _ callback: @escaping DatabaseCallback) {
    openDatabase(db, create: false, callback)
  }

  public func openDatabase(_ db: String, create: Bool, _ callback: @escaping DatabaseCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    db.withCString { nameCString in 
      _StorageDatabaseOpen(reference, statePtr, nameCString, create ? 1 : 0, { (handle: UnsafeMutableRawPointer?, statusCode: CInt, db: UnsafeMutableRawPointer?) in
        let cb = unsafeBitCast(handle, to: CallbackState.self)
        var database: Database?
        if statusCode == 0 {
          let this = cb.context as? Storage
          database = Database(storage: this!, reference: db!)
          this!.databases.append(database!) 
        }
        cb.databaseCallback!(Int(statusCode), database)
        cb.deallocate()
      })
    }
  }

  public func dropDatabase(_ db: String, _ callback: @escaping StatusCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    db.withCString { 
      _StorageDatabaseDrop(reference, statePtr, $0, { (handle: UnsafeMutableRawPointer?, statusCode: CInt) in
        let cb = unsafeBitCast(handle, to: CallbackState.self)
        cb.statusCallback!(Int(statusCode))
        cb.deallocate()
      })
    }
  }

  public func databaseExists(_ db: String, _ callback: @escaping ExistsCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    db.withCString { 
      _StorageDatabaseExists(reference, statePtr, $0, { (handle: UnsafeMutableRawPointer?, exists: CInt) in
        let cb = unsafeBitCast(handle, to: CallbackState.self)
        cb.existsCallback!(exists != 0)
        cb.deallocate()
      })
    }
  }

  public func filebaseExists(_ file: String, _ callback: @escaping ExistsCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    file.withCString { 
      _StorageFilebaseExists(reference, statePtr, $0, { (handle: UnsafeMutableRawPointer?, exists: CInt) in
        let cb = unsafeBitCast(handle, to: CallbackState.self)
        cb.existsCallback!(exists != 0)
        cb.deallocate()
      })
    }
  }

  public func createFilebase(_ file: String, path: String, _ callback: @escaping FilebaseCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    file.withCString { nameCString in 
      path.withCString { pathCString in
        _StorageFilebaseCreateWithPath(reference, statePtr, nameCString, pathCString, { (handle: UnsafeMutableRawPointer?, statusCode: CInt, db: UnsafeMutableRawPointer?) in
          let cb = unsafeBitCast(handle, to: CallbackState.self)
          var filebase: Filebase?
          if statusCode == 0 {
            let this = cb.context as? Storage
            filebase = Filebase(storage: this!, reference: db!)
            this!.filebases.append(filebase!)
          }
          cb.filebaseCallback!(Int(statusCode), filebase)
          cb.deallocate()
        })
      }
    }
  }

  public func createFilebase(_ file: String, infohash: String, _ callback: @escaping FilebaseCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    file.withCString { nameCString in 
      infohash.withCString { pathCString in
        _StorageFilebaseCreateWithInfohash(reference, statePtr, nameCString, pathCString, { (handle: UnsafeMutableRawPointer?, statusCode: CInt, db: UnsafeMutableRawPointer?) in
          let cb = unsafeBitCast(handle, to: CallbackState.self)
          var filebase: Filebase?
          if statusCode == 0 {
            let this = cb.context as? Storage
            filebase = Filebase(storage: this!, reference: db!)
            this!.filebases.append(filebase!)
          }
          cb.filebaseCallback!(Int(statusCode), filebase)
          cb.deallocate()
        })
      }
    }
  }

  public func openFilebase(_ file: String, _ callback: @escaping FilebaseCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    file.withCString { nameCString in 
      _StorageFilebaseOpen(reference, statePtr, nameCString, 0, { (handle: UnsafeMutableRawPointer?, statusCode: CInt, db: UnsafeMutableRawPointer?) in
        let cb = unsafeBitCast(handle, to: CallbackState.self)
        var filebase: Filebase?
        if statusCode == 0 {
          let this = cb.context as? Storage
          filebase = Filebase(storage: this!, reference: db!)
          this!.filebases.append(filebase!)
        }
        cb.filebaseCallback!(Int(statusCode), filebase)
        cb.deallocate()
      })
    }
  }

  public func listFilebaseFiles(_ file: String, _ callback: @escaping ListFilesCallback) {
    let state = CallbackState(self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    file.withCString { nameCString in 
      _StorageFilebaseListFiles(reference, statePtr, nameCString, { (
        handle: UnsafeMutableRawPointer?,
        count: CInt,
        name: UnsafeMutablePointer<UnsafePointer<Int8>?>?,
        path: UnsafeMutablePointer<UnsafePointer<Int8>?>?,
        contentType: UnsafeMutablePointer<UnsafePointer<Int8>?>?,
        offset: UnsafeMutablePointer<Int32>?,
        size: UnsafeMutablePointer<Int64>?,
        blocks: UnsafeMutablePointer<Int32>?,
        startBlock: UnsafeMutablePointer<Int32>?,
        endBlock: UnsafeMutablePointer<Int32>?,
        createdTime: UnsafeMutablePointer<Int64>?) in
         var entries: [ShareEntry] = []
         let cb = unsafeBitCast(handle, to: CallbackState.self)
         for i in 0..<Int(count) {
            var entry = ShareEntry()
            entry.name = String(cString: name![i]!)
            entry.path = String(cString: path![i]!)
            entry.contentType = String(cString: contentType![i]!)
            entry.offset = Int(offset![i])
            entry.size = size![i]
            entry.blocks = Int(blocks![i])
            entry.startBlock = Int(startBlock![i])
            entry.endBlock = Int(endBlock![i])
            entry.createdTime = createdTime![i]
            entries.append(entry)
         }
         cb.listFilesCallback!(entries)
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

  func onDatabaseClose(_ db: Database) {
    for (index, database) in databases.enumerated() {
      if db === database {
        databases.remove(at: index)
      }
    }
  }

  func onFilebaseClose(_ fb: Filebase) {
    for (index, filebase) in filebases.enumerated() {
      if fb === filebase {
        filebases.remove(at: index)
      }
    }
  }

}