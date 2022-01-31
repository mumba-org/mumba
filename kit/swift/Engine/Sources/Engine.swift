// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base
import Net
import Data
import Route
import Service
import Channel
import Web
import Collection

public class ContainerContext {
  
  public var reference: ShellContextRef

  public init(reference: ShellContextRef) {
    self.reference = reference
  }

}

open class EngineContext : Delegate,
                           ApplicationHostDelegate {
 
  public private(set) var containerContext: ContainerContext?
  public private(set) var applications: ContiguousArray<ApplicationHost> = ContiguousArray<ApplicationHost>()
  public private(set) var contexts: ContiguousArray<Storage> = ContiguousArray<Storage>()
  public private(set) var channelRegistry: ChannelRegistry!
  public private(set) var serviceRegistry: ServiceRegistry!
  public private(set) var routes: RouteManager!
  public private(set) var collection: Collection!
  public private(set) var repos: RepoRegistry!
  public private(set) var storageDelegate: StorageDelegate?
  public private(set) weak var applicationDelegate: ApplicationHostDelegate?
  public private(set) var routeRequestHandler: RouteRequestHandlerInterface?
  public var serviceWorkerContextClient: ServiceWorkerContextClient?

  public init () {

  }

  public func initialize(containerContext: ContainerContext, routeRequestHandler: RouteRequestHandlerDelegate) {
    self.containerContext = containerContext
    self.routeRequestHandler = RouteRequestHandlerInterface(delegate: routeRequestHandler)
    
    try! TaskScheduler.createAndStartWithDefaultParams()
    NetworkHost.initialize(context: containerContext.reference)

    routes = RouteManager(routeRegistry: RouteRegistry(reference: _RouteRegistryCreateFromEngine(Instance.instance().state, self.routeRequestHandler!.state, self.routeRequestHandler!.callbacks)))
    channelRegistry = ChannelRegistry(reference: _ChannelRegistryCreateFromEngine(Instance.instance().state))
    serviceRegistry = ServiceRegistry(reference: _ServiceRegistryCreateFromEngine(Instance.instance().state))
    collection = Collection(reference: _CollectionCreateFromEngine(Instance.instance().state))
    repos = RepoRegistry(reference: _RepoRegistryCreateFromEngine(Instance.instance().state))
  }

  public func shutdown() {
    applications.removeAll()
    contexts.removeAll()
    TaskScheduler.instance!.shutdown()
  }

  public func createStorage(delegate: StorageDelegate) -> Storage {
    self.storageDelegate = delegate
    let selfInstance = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    var callbacks = StorageShareCallbacks()
    // void(*OnShareDHTAnnounceReply)(void*, const uint8_t*, int);
    callbacks.OnShareDHTAnnounceReply = { (state: UnsafeMutableRawPointer?, uuid: UnsafePointer<UInt8>?, peers: CInt) in
      let this = unsafeBitCast(state, to: EngineContext.self)
      uuid!.withMemoryRebound(to: Int8.self, capacity: 36) {
        this.storageDelegate?.onShareDHTAnnounceReply(uuid: String(cString: $0), peers: Int(peers))
      }
    }
    // void(*OnShareMetadataReceived)(void*, const uint8_t*);
    callbacks.OnShareMetadataReceived = { (state: UnsafeMutableRawPointer?, uuid: UnsafePointer<UInt8>?) in
      let this = unsafeBitCast(state, to: EngineContext.self)
      uuid!.withMemoryRebound(to: Int8.self, capacity: 36) {
        this.storageDelegate?.onShareMetadataReceived(uuid: String(cString: $0))
      }
    }
    // void(*OnShareMetadataError)(void*, const uint8_t*, int);
    callbacks.OnShareMetadataError = { (state: UnsafeMutableRawPointer?, uuid: UnsafePointer<UInt8>?, error: CInt) in
      let this = unsafeBitCast(state, to: EngineContext.self)
      uuid!.withMemoryRebound(to: Int8.self, capacity: 36) {
        this.storageDelegate?.onShareMetadataError(uuid: String(cString: $0), error: Int(error))
      }
    }
    // void(*OnSharePieceReadError)(void*, const uint8_t*, int, int);
    callbacks.OnSharePieceReadError = { (state: UnsafeMutableRawPointer?, uuid: UnsafePointer<UInt8>?, piece: CInt, error: CInt) in
      let this = unsafeBitCast(state, to: EngineContext.self)
      uuid!.withMemoryRebound(to: Int8.self, capacity: 36) {
        this.storageDelegate?.onSharePieceReadError(uuid: String(cString: $0), piece: Int(piece), error: Int(error))
      }
    }
    // void(*OnSharePiecePass)(void*, const uint8_t*, int);
    callbacks.OnSharePiecePass = { (state: UnsafeMutableRawPointer?, uuid: UnsafePointer<UInt8>?, piece: CInt) in
      let this = unsafeBitCast(state, to: EngineContext.self)
      uuid!.withMemoryRebound(to: Int8.self, capacity: 36) {
        this.storageDelegate?.onSharePiecePass(uuid: String(cString: $0), piece: Int(piece))
      }
    }
    // void(*OnSharePieceFailed)(void*, const uint8_t*, int);
    callbacks.OnSharePieceFailed = { (state: UnsafeMutableRawPointer?, uuid: UnsafePointer<UInt8>?, piece: CInt) in
      let this = unsafeBitCast(state, to: EngineContext.self)
      uuid!.withMemoryRebound(to: Int8.self, capacity: 36) {
        this.storageDelegate?.onSharePieceFailed(uuid: String(cString: $0), piece: Int(piece))
      }
    }
    // void(*OnSharePieceRead)(void*, const uint8_t*, int, int, int, int, int);
    callbacks.OnSharePieceRead = { (state: UnsafeMutableRawPointer?, uuid: UnsafePointer<UInt8>?, piece: CInt, offset: CInt, size: CInt, blockSize: CInt, result: CInt) in
      let this = unsafeBitCast(state, to: EngineContext.self)
      uuid!.withMemoryRebound(to: Int8.self, capacity: 36) {
        this.storageDelegate?.onSharePieceRead(uuid: String(cString: $0), piece: Int(piece), offset: Int(offset), size: Int(size), blockSize: Int(blockSize), result: Int(result))
      }
    }
    // void(*OnSharePieceWrite)(void*, const uint8_t*, int, int, int, int, int);
    callbacks.OnSharePieceWrite = { (state: UnsafeMutableRawPointer?, uuid: UnsafePointer<UInt8>?, piece: CInt, offset: CInt, size: CInt, blockSize: CInt, result: CInt) in
      let this = unsafeBitCast(state, to: EngineContext.self)
      uuid!.withMemoryRebound(to: Int8.self, capacity: 36) {
        this.storageDelegate?.onSharePieceWrite(uuid: String(cString: $0), piece: Int(piece), offset: Int(offset), size: Int(size), blockSize: Int(blockSize), result: Int(result))
      }
    }
    // void(*OnSharePieceHashFailed)(void*, const uint8_t*, int);
    callbacks.OnSharePieceHashFailed = { (state: UnsafeMutableRawPointer?, uuid: UnsafePointer<UInt8>?, piece: CInt) in
      let this = unsafeBitCast(state, to: EngineContext.self)
      uuid!.withMemoryRebound(to: Int8.self, capacity: 36) {
        this.storageDelegate?.onSharePieceHashFailed(uuid: String(cString: $0), piece: Int(piece))
      }
    }
    // void(*OnShareCheckingFiles)(void*, const uint8_t*);
    callbacks.OnShareCheckingFiles = { (state: UnsafeMutableRawPointer?, uuid: UnsafePointer<UInt8>?) in
      let this = unsafeBitCast(state, to: EngineContext.self)
      uuid!.withMemoryRebound(to: Int8.self, capacity: 36) {
        this.storageDelegate?.onShareCheckingFiles(uuid: String(cString: $0))
      }
    }
    // void(*OnShareDownloadingMetadata)(void*, const uint8_t*);
    callbacks.OnShareDownloadingMetadata = { (state: UnsafeMutableRawPointer?, uuid: UnsafePointer<UInt8>?) in
      let this = unsafeBitCast(state, to: EngineContext.self)
      uuid!.withMemoryRebound(to: Int8.self, capacity: 36) {
        this.storageDelegate?.onShareDownloadingMetadata(uuid: String(cString: $0))
      }
    }
    // void(*OnShareFileRenamed)(void*, const uint8_t*, int, const char*, int);
    callbacks.OnShareFileRenamed = { (state: UnsafeMutableRawPointer?, uuid: UnsafePointer<UInt8>?, offset: CInt, name: UnsafePointer<Int8>?, error: CInt) in
      let this = unsafeBitCast(state, to: EngineContext.self)
      uuid!.withMemoryRebound(to: Int8.self, capacity: 36) {
        this.storageDelegate?.onShareFileRenamed(uuid: String(cString: $0), fileOffset: Int(offset), name: String(), error: Int(error))
      }
    }
    // void(*OnShareResumed)(void*, const uint8_t*);
    callbacks.OnShareResumed = { (state: UnsafeMutableRawPointer?, uuid: UnsafePointer<UInt8>?) in
      let this = unsafeBitCast(state, to: EngineContext.self)
      uuid!.withMemoryRebound(to: Int8.self, capacity: 36) {
        this.storageDelegate?.onShareResumed(uuid: String(cString: $0))
      }
    }
    // void(*OnShareChecked)(void*, const uint8_t*, int);
    callbacks.OnShareChecked = { (state: UnsafeMutableRawPointer?, uuid: UnsafePointer<UInt8>?, result: CInt) in
      let this = unsafeBitCast(state, to: EngineContext.self)
      uuid!.withMemoryRebound(to: Int8.self, capacity: 36) {
        this.storageDelegate?.onShareChecked(uuid: String(cString: $0), result: Int(result))
      }
    }
    // void(*OnSharePieceComplete)(void*, const uint8_t*, int);
    callbacks.OnSharePieceComplete = { (state: UnsafeMutableRawPointer?, uuid: UnsafePointer<UInt8>?, piece: CInt) in
      let this = unsafeBitCast(state, to: EngineContext.self)
      uuid!.withMemoryRebound(to: Int8.self, capacity: 36) {
        this.storageDelegate?.onSharePieceComplete(uuid: String(cString: $0), piece: Int(piece))
      }
    }
    // void(*OnShareFileComplete)(void*, const uint8_t*, int);
    callbacks.OnShareFileComplete = { (state: UnsafeMutableRawPointer?, uuid: UnsafePointer<UInt8>?, offset: CInt) in
      let this = unsafeBitCast(state, to: EngineContext.self)
      uuid!.withMemoryRebound(to: Int8.self, capacity: 36) {
        this.storageDelegate?.onShareFileComplete(uuid: String(cString: $0), fileOffset: Int(offset))
      }
    }
    // void(*OnShareDownloading)(void*, const uint8_t*);
    callbacks.OnShareDownloading = { (state: UnsafeMutableRawPointer?, uuid: UnsafePointer<UInt8>?) in
      let this = unsafeBitCast(state, to: EngineContext.self)
      uuid!.withMemoryRebound(to: Int8.self, capacity: 36) {
        this.storageDelegate?.onShareDownloading(uuid: String(cString: $0))
      }
    }
    // void(*OnShareComplete)(void*, const uint8_t*);
    callbacks.OnShareComplete = { (state: UnsafeMutableRawPointer?, uuid: UnsafePointer<UInt8>?) in
      let this = unsafeBitCast(state, to: EngineContext.self)
      uuid!.withMemoryRebound(to: Int8.self, capacity: 36) {
        this.storageDelegate?.onShareComplete(uuid: String(cString: $0))
      }
    }
    // void(*OnShareSeeding)(void*, const uint8_t*);
    callbacks.OnShareSeeding = { (state: UnsafeMutableRawPointer?, uuid: UnsafePointer<UInt8>?) in
      let this = unsafeBitCast(state, to: EngineContext.self)
      uuid!.withMemoryRebound(to: Int8.self, capacity: 36) {
        this.storageDelegate?.onShareSeeding(uuid: String(cString: $0))
      }
    }
    // void(*OnSharePaused)(void*, const uint8_t*);
    callbacks.OnSharePaused = { (state: UnsafeMutableRawPointer?, uuid: UnsafePointer<UInt8>?) in
      let this = unsafeBitCast(state, to: EngineContext.self)
      uuid!.withMemoryRebound(to: Int8.self, capacity: 36) {
        this.storageDelegate?.onSharePaused(uuid: String(cString: $0))
      }
    }

    let ref = _EngineStorageCreate(Instance.instance().state, selfInstance, callbacks)
    let context = Storage(reference: ref!)
    contexts.append(context)
    return context
  }

  open func onInit(containerContext: ContainerContext) {}
  open func onShutdown() {}

  open func onApplicationInstanceLaunched(instance: ApplicationInstance) {
    print("Engine.onApplicationInstanceLaunch")
  }
  
  open func onApplicationInstanceLaunchFailed(status: Engine.Status, instance: ApplicationInstance) {
    print("Engine.onApplicationInstanceLaunchFailed")
  }
  
  open func onApplicationInstanceKilled(status: Engine.Status, instance: ApplicationInstance) {
    print("Engine.onApplicationInstanceKilled")
  }

  open func onApplicationInstanceClosed(status: Engine.Status, instance: ApplicationInstance) {
    print("Engine.onApplicationInstanceClosed")
  }

  open func onApplicationInstanceActivated(instance: ApplicationInstance) {
    print("Engine.onApplicationInstanceActivated")
  }

  public func foreachApplication(
    handle: ApplicationHostRef,
    name: String,
    uuid: String,
    url: String) {
    applications.append(
      ApplicationHost(
        delegate: self,
        name: name,
        uuid: uuid,
        url: url,
        kind: ApplicationKind.UI,
        reference: handle))
  }

}
