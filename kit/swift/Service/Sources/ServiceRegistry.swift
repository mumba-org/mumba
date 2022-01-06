// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims

public struct ServiceEntry {
  
  public var scheme: String
  public var name: String
  public var uuid: String
  public var host: String
  public var port: Int

  public init(scheme: String, name: String, uuid: String, host: String, port: Int) {
    self.scheme = scheme
    self.name = name
    self.uuid = uuid
    self.host = host
    self.port = port
  }

}

public protocol ServiceSubscriber : class {
  var unsafeReference: UnsafeMutableRawPointer { get }
  func onServiceAdded(entry: ServiceEntry)
  func onServiceRemoved(entry: ServiceEntry)
  func onServiceChanged(entry: ServiceEntry)
  func onServiceStateChanged(entry: ServiceEntry)
}

internal class ServiceSubscriberState {
  
  var id: Int
  var watcher: ServiceSubscriber
  var reference: UnsafeMutableRawPointer

  init(id: Int, watcher: ServiceSubscriber, reference: UnsafeMutableRawPointer) {
    self.id = id
    self.watcher = watcher
    self.reference = reference
  }

  init(watcher: ServiceSubscriber, reference: UnsafeMutableRawPointer) {
    self.id = -1
    self.watcher = watcher
    self.reference = reference
  }

  deinit {
    _ServiceSubscriberDestroy(reference)
  }
}

public class ServiceRegistry {
  
  internal var reference: ServiceRegistryRef
  internal var callbacks: [ServiceCallbackState]
  private var watchers: [Int : ServiceSubscriberState]

  public init(reference: ServiceRegistryRef) {
    self.reference = reference
    callbacks = []
    watchers = [:]
  }

  deinit {
    _ServiceRegistryDestroy(reference)
  }

  public func haveService(scheme: String, name: String, _ callback: @escaping (_: Bool) -> Void) {
    scheme.withCString { scstr in
      name.withCString { ncstr in
        let callbackState = ServiceCallbackState(self, have: callback)
        callbacks.append(callbackState)
        let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _ServiceRegistryHaveServiceByName(reference, scstr, ncstr, statePtr, { (handle: UnsafeMutableRawPointer?, have: CInt) in
            let cb = unsafeBitCast(handle, to: ServiceCallbackState.self)
            cb.haveCallback!(have != 0)
            cb.dispose()
        })
      }
    }
  }

  public func haveService(uuid: String, _ callback: @escaping (_: Bool) -> Void) {
    uuid.withCString { ucstr in
      let callbackState = ServiceCallbackState(self, have: callback)
      callbacks.append(callbackState)
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _ServiceRegistryHaveServiceByUUID(reference, ucstr, statePtr, { (handle: UnsafeMutableRawPointer?, have: CInt) in
          let cb = unsafeBitCast(handle, to: ServiceCallbackState.self)
          cb.haveCallback!(have != 0)
          cb.dispose()
      })
    }
  }

  public func lookupService(scheme: String, name: String, _ callback: @escaping (_: ServiceEntry?) -> Void) {
    scheme.withCString { scstr in
      name.withCString { pcstr in
        let callbackState = ServiceCallbackState(self, lookup: callback)
        callbacks.append(callbackState)
        let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _ServiceRegistryLookupServiceByName(reference, scstr, pcstr, statePtr, { (handle: UnsafeMutableRawPointer?, status: CInt, scheme: UnsafePointer<CChar>?, name: UnsafePointer<CChar>?, uuid: UnsafePointer<CChar>?, host: UnsafePointer<CChar>?, port: CInt) in
           let cb = unsafeBitCast(handle, to: ServiceCallbackState.self)
           cb.lookupCallback!(status == 0 ? ServiceEntry(scheme: String(cString: scheme!), name: String(cString: name!), uuid: String(cString: uuid!), host: String(cString: host!), port: Int(port)) : nil)
           cb.dispose()
        })
      }
    }
  }

  public func lookupService(uuid: String, _ callback: @escaping (_: ServiceEntry?) -> Void) {
    uuid.withCString { ucstr in
      let callbackState = ServiceCallbackState(self, lookup: callback)
      callbacks.append(callbackState)
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _ServiceRegistryLookupServiceByUUID(reference, ucstr, statePtr, { (handle: UnsafeMutableRawPointer?, status: CInt, scheme: UnsafePointer<CChar>?, name: UnsafePointer<CChar>?, uuid: UnsafePointer<CChar>?, host: UnsafePointer<CChar>?, port: CInt) in
          let cb = unsafeBitCast(handle, to: ServiceCallbackState.self)
          cb.lookupCallback!(status == 0 ? ServiceEntry(scheme: String(cString: scheme!), name: String(cString: name!), uuid: String(cString: uuid!), host: String(cString: host!), port: Int(port)) : nil)
          cb.dispose()
      })
    }
  }

  public func listServices(scheme: String, _ callback: @escaping (_: [ServiceEntry]?) -> Void) {
    scheme.withCString { scstr in
      let callbackState = ServiceCallbackState(self, list: callback)
      callbacks.append(callbackState)
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _ServiceRegistryListServicesWithScheme(reference, scstr, statePtr, { (handle: UnsafeMutableRawPointer?, status: CInt, count: CInt, schemes: UnsafeMutablePointer<UnsafePointer<Int8>?>?, names: UnsafeMutablePointer<UnsafePointer<Int8>?>?, uuids: UnsafeMutablePointer<UnsafePointer<Int8>?>?, hosts: UnsafeMutablePointer<UnsafePointer<Int8>?>?, ports: UnsafeMutablePointer<CInt>?) in
          let cb = unsafeBitCast(handle, to: ServiceCallbackState.self)
          if count > 0 {
            var entries: [ServiceEntry] = []
            for i in 0..<Int(count) {
              entries.append(ServiceEntry(scheme: String(cString: schemes![i]!), name: String(cString: names![i]!), uuid: String(cString: uuids![i]!), host: String(cString: hosts![i]!), port: Int(ports![i])))
            }
            cb.listCallback!(entries)
          
          } else {
            cb.listCallback!(nil)
          }
          cb.dispose()
      })
    }
  }

  public func listServices(_ callback: @escaping (_: [ServiceEntry]?) -> Void) {
    let callbackState = ServiceCallbackState(self, list: callback)
    callbacks.append(callbackState)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ServiceRegistryListAllServices(reference, statePtr, { (handle: UnsafeMutableRawPointer?, status: CInt, count: CInt, schemes: UnsafeMutablePointer<UnsafePointer<Int8>?>?, names: UnsafeMutablePointer<UnsafePointer<Int8>?>?, uuids: UnsafeMutablePointer<UnsafePointer<Int8>?>?, hosts: UnsafeMutablePointer<UnsafePointer<Int8>?>?, ports: UnsafeMutablePointer<CInt>?) in
        let cb = unsafeBitCast(handle, to: ServiceCallbackState.self)
        if count > 0 {
          var entries: [ServiceEntry] = []
          for i in 0..<Int(count) {
            entries.append(ServiceEntry(scheme: String(cString: schemes![i]!), name: String(cString: names![i]!), uuid: String(cString: uuids![i]!), host: String(cString: hosts![i]!), port: Int(ports![i])))
          }
          cb.listCallback!(entries)
        
        } else {
          cb.listCallback!(nil)
        }
        cb.dispose()
    })
  }

  public func getServiceCount(_ callback: @escaping (_: Int) -> Void) {
    let callbackState = ServiceCallbackState(self, count: callback)
    callbacks.append(callbackState)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ServiceRegistryGetServiceCount(reference, statePtr, { (handle: UnsafeMutableRawPointer?, count: CInt) in
      let cb = unsafeBitCast(handle, to: ServiceCallbackState.self)
      cb.countCallback!(Int(count))
      cb.dispose()
    })
  }

  public func addSubscriber(scheme: String, _ watcher: ServiceSubscriber) {
    scheme.withCString {
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      let watcherPtr = watcher.unsafeReference
      _ServiceRegistryAddSubscriber(reference, $0, 
        statePtr,
        watcherPtr,
        // onSubscriberAdded
        { (handle: UnsafeMutableRawPointer?, id: CInt, w: UnsafeMutableRawPointer? , ref: UnsafeMutableRawPointer?) in
          let this = unsafeBitCast(handle, to: ServiceRegistry.self)
          let localSubscriber = unsafeBitCast(w, to: ServiceSubscriber.self)
          this.onSubscriberAdded(id: Int(id), reference: ref!, watcher: localSubscriber)
        }, 
        // onServiceAdded
        { (handle: UnsafeMutableRawPointer?, scheme: UnsafePointer<Int8>?, name: UnsafePointer<Int8>?, uuid: UnsafePointer<Int8>?, host: UnsafePointer<Int8>?, port: CInt) in 
          let watcher = unsafeBitCast(handle, to: ServiceSubscriber.self)
          watcher.onServiceAdded(entry: ServiceEntry(scheme: String(cString: scheme!), name: String(cString: name!), uuid: String(cString: uuid!), host: String(cString: host!), port: Int(port)))
        },
        // onServiceRemoved
        { (handle: UnsafeMutableRawPointer?, scheme: UnsafePointer<Int8>?, name: UnsafePointer<Int8>?, uuid: UnsafePointer<Int8>?, host: UnsafePointer<Int8>?, port: CInt) in 
          let watcher = unsafeBitCast(handle, to: ServiceSubscriber.self)
          watcher.onServiceRemoved(entry: ServiceEntry(scheme: String(cString: scheme!), name: String(cString: name!), uuid: String(cString: uuid!), host: String(cString: host!), port: Int(port)))
        },
        //void(*OnServiceChanged)(void*, const char*, const char*, const char*, const char*, int)
        { (handle: UnsafeMutableRawPointer?, scheme: UnsafePointer<Int8>?, name: UnsafePointer<Int8>?, uuid: UnsafePointer<Int8>?, host: UnsafePointer<Int8>?, port: CInt) in 
          let watcher = unsafeBitCast(handle, to: ServiceSubscriber.self)
          watcher.onServiceChanged(entry: ServiceEntry(scheme: String(cString: scheme!), name: String(cString: name!), uuid: String(cString: uuid!), host: String(cString: host!), port: Int(port)))
        },
        //void(*OnServiceStateChanged)(void*, const char*, const char*, const char*, const char*, int, int)
        { (handle: UnsafeMutableRawPointer?, scheme: UnsafePointer<Int8>?, name: UnsafePointer<Int8>?, uuid: UnsafePointer<Int8>?, host: UnsafePointer<Int8>?, port: CInt, state: CInt) in 
          let watcher = unsafeBitCast(handle, to: ServiceSubscriber.self)
          watcher.onServiceStateChanged(entry: ServiceEntry(scheme: String(cString: scheme!), name: String(cString: name!), uuid: String(cString: uuid!), host: String(cString: host!), port: Int(port)))
        }
      )
    }
  }

  public func removeSubscriber(id: Int) {
    _ServiceRegistryRemoveSubscriber(reference, CInt(id))
    onSubscriberRemoved(id: Int(id))
  }

  public func removeSubscriber(_ watcher: ServiceSubscriber) {
    for (id, w) in watchers {
      if w.watcher === watcher {
        removeSubscriber(id: id)
        return
      }
    }
  }

  private func onSubscriberAdded(id: Int, reference: UnsafeMutableRawPointer, watcher: ServiceSubscriber) {
    watchers[id] = ServiceSubscriberState(id: id, watcher: watcher, reference: reference)
  }

  private func onSubscriberRemoved(id: Int) {
    watchers.removeValue(forKey: id)
  }

}

internal class ServiceCallbackState {
  
  internal var haveCallback: ((_: Bool) -> Void)?
  internal var lookupCallback: ((_: ServiceEntry?) -> Void)?
  internal var listCallback: ((_: [ServiceEntry]?) -> Void)?
  internal var countCallback: ((_: Int) -> Void)?
  private weak var owner: ServiceRegistry?

  init(_ owner: ServiceRegistry, lookup: @escaping (_: ServiceEntry?) -> Void) {
    self.owner = owner
    self.lookupCallback = lookup
  }

  init(_ owner: ServiceRegistry, list: @escaping (_: [ServiceEntry]?) -> Void) {
    self.owner = owner
    self.listCallback = list
  }

  init(_ owner: ServiceRegistry, have: @escaping (_: Bool) -> Void) {
    self.owner = owner
    self.haveCallback = have
  }

  init(_ owner: ServiceRegistry, count: @escaping (_: Int) -> Void) {
    self.owner = owner
    self.countCallback = count
  }

  func dispose() {
    for (index, elem) in owner!.callbacks.enumerated() {
      if elem === self {
        owner!.callbacks.remove(at: index)
        return
      }
    }
  }
}