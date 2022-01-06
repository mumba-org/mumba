// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims

public enum RouteEntryType : Int {
  case Scheme = 0
  case Entry = 1
}

public enum RouteTransportType : Int {
  case Ipc = 0
  case Rpc = 1
  case Http = 2
}

public enum RouteRpcTransportMode : Int {
  case Unary                = 0
  case ClientStream         = 1
  case ServerStream         = 2
  case BidirectionalStream  = 3
}

public struct RouteEntry {
  
  public var type: RouteEntryType
  public var transportType: RouteTransportType
  public var rpcTransportMode: RouteRpcTransportMode
  public var name: String
  public var scheme: String
  public var path: String
  public var url: String
  public var title: String
  public var contentType: String
  public var iconData: Data

  public init(type: RouteEntryType, transportType: RouteTransportType, transportMode: RouteRpcTransportMode, scheme: String, name: String) {
    self.type = type
    self.transportType = transportType
    self.rpcTransportMode = transportMode
    self.scheme = scheme
    self.name = name
    self.path = "/" + name
    self.url = scheme + "://" + name
    self.iconData = Data()
    self.title = String()
    self.contentType = String()
  }

  public init(type: RouteEntryType, transportType: RouteTransportType, transportMode: RouteRpcTransportMode, name: String, path: String, url: String) {
    let schemeOffset = url.firstIndex(of: ":") ?? url.endIndex
    self.type = type
    self.transportType = transportType
    self.rpcTransportMode = transportMode
    self.scheme = String(url[..<schemeOffset])
    self.name = name
    self.path = path
    self.url = url
    self.iconData = Data()
    self.title = String()
    self.contentType = String()
  }

  public init(type: RouteEntryType, transportType: RouteTransportType, transportMode: RouteRpcTransportMode, name: String, path: String, url: String, title: String, contentType: String) {
    let schemeOffset = url.firstIndex(of: ":") ?? url.endIndex
    self.type = type
    self.transportType = transportType
    self.rpcTransportMode = transportMode
    self.scheme = String(url[..<schemeOffset])
    self.name = name
    self.path = path
    self.url = url
    self.iconData = Data()
    self.title = title
    self.contentType = contentType
  }

  public init(type: RouteEntryType, transportType: RouteTransportType, transportMode: RouteRpcTransportMode, scheme: String, name: String, title: String, contentType: String) {
    self.type = type
    self.transportType = transportType
    self.rpcTransportMode = transportMode
    self.scheme = scheme
    self.name = name
    self.path = "/" + name
    self.url = scheme + "://" + name
    self.iconData = Data()
    self.title = title
    self.contentType = contentType
  }

  public init(type: RouteEntryType, transportType: RouteTransportType, transportMode: RouteRpcTransportMode, scheme: String, name: String, title: String, contentType: String, icon: Data) {
    self.type = type
    self.transportType = transportType
    self.rpcTransportMode = transportMode
    self.scheme = scheme
    self.name = name
    self.path = "/" + name
    self.url = scheme + "://" + name
    self.iconData = icon
    self.title = title
    self.contentType = contentType
  }

}

public protocol RouteSubscriber : class {
  var unsafeReference: UnsafeMutableRawPointer { get }
  func onRouteHeaderChanged(header: String)
  func onRouteAdded(route: RouteEntry)
  func onRouteRemoved(route: RouteEntry)
  func onRouteChanged(route: RouteEntry)
}

// Its sad that this has to be a class while it should be a struct
// just because of the deinit {} destructor is necessary to cleanup the C++ side

internal class RouteSubscriberState {
  
  var id: Int
  var subscriber: RouteSubscriber
  var reference: UnsafeMutableRawPointer

  init(id: Int, subscriber: RouteSubscriber, reference: UnsafeMutableRawPointer) {
    self.id = id
    self.subscriber = subscriber
    self.reference = reference
  }

  init(subscriber: RouteSubscriber, reference: UnsafeMutableRawPointer) {
    self.id = -1
    self.subscriber = subscriber
    self.reference = reference
  }

  deinit {
    _RouteSubscriberDestroy(reference)
  }
}

public class RouteRegistry {
  
  internal var reference: RouteRegistryRef
  internal var callbacks: [RouteCallbackState]
  private var watchers: [Int : RouteSubscriberState]

  // public init(instance: Instance) {
  //   reference = _RouteRegistryCreate(instance.state)
  //   callbacks = []
  //   watchers = [:]
  // }

  public init(reference: RouteRegistryRef) {
    self.reference = reference
    callbacks = []
    watchers = [:]
  }

  deinit {
    _RouteRegistryDestroy(reference)
  }

  public func addRoute(_ entry: RouteEntry) {
    entry.scheme.withCString { sstr in
      entry.name.withCString { nstr in
        entry.path.withCString { pstr in
          entry.url.withCString { ustr in
            entry.title.withCString { tstr in
              entry.contentType.withCString { cstr in
                entry.iconData.withUnsafeBytes {
                  _RouteRegistryAddRoute(reference, CInt(entry.type.rawValue), CInt(entry.transportType.rawValue), CInt(entry.rpcTransportMode.rawValue), sstr, nstr, pstr, ustr, tstr, cstr, $0, CInt(entry.iconData.count))
                }
              }
            }
          }
        }
      }
    }
  }

  public func addRoutes(_ entries: [RouteEntry]) {
    for entry in entries {
      addRoute(entry)
    }
  }

  public func removeRoute(path: String) {
    path.withCString {
      _RouteRegistryRemoveRoute(reference, $0)
    }
  }

  public func removeRoute(url: String) {
    url.withCString {
      _RouteRegistryRemoveRouteByUrl(reference, $0)
    }
  }

  public func removeRoute(uuid: String) {
    uuid.withCString {
      _RouteRegistryRemoveRouteByUUID(reference, $0)
    }
  }

  public func haveRoute(path: String, _ callback: @escaping (_: Bool) -> Void) {
    path.withCString { pcstr in
      let callbackState = RouteCallbackState(self, have: callback)
      callbacks.append(callbackState)
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _RouteRegistryHaveRouteByPath(reference, pcstr, statePtr, { (handle: UnsafeMutableRawPointer?, have: CInt) in
          let cb = unsafeBitCast(handle, to: RouteCallbackState.self)
          cb.haveCallback!(have != 0)
          cb.dispose()
      })
    }
  }

  public func haveRoute(url: String, _ callback: @escaping (_: Bool) -> Void) {
    url.withCString { pcstr in
      let callbackState = RouteCallbackState(self, have: callback)
      callbacks.append(callbackState)
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _RouteRegistryHaveRouteByUrl(reference, pcstr, statePtr, { (handle: UnsafeMutableRawPointer?, have: CInt) in
          let cb = unsafeBitCast(handle, to: RouteCallbackState.self)
          cb.haveCallback!(have != 0)
          cb.dispose()
      })
    }
  }

  public func haveRoute(uuid: String, _ callback: @escaping (_: Bool) -> Void) {
    uuid.withCString { pcstr in
      let callbackState = RouteCallbackState(self, have: callback)
      callbacks.append(callbackState)
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _RouteRegistryHaveRouteByUUID(reference, pcstr, statePtr, { (handle: UnsafeMutableRawPointer?, have: CInt) in
          let cb = unsafeBitCast(handle, to: RouteCallbackState.self)
          cb.haveCallback!(have != 0)
          cb.dispose()
      })
    }
  }

  public func lookupRoute(scheme: String, path: String, _ callback: @escaping (_: RouteEntry?) -> Void) {
    scheme.withCString { scstr in
      path.withCString { pcstr in
        let callbackState = RouteCallbackState(self, lookup: callback)
        callbacks.append(callbackState)
        let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _RouteRegistryLookupRoute(reference, scstr, pcstr, statePtr, { (handle: UnsafeMutableRawPointer?, status: CInt, type: CInt, transportType: CInt, transportMode: CInt, name: UnsafePointer<CChar>?, path: UnsafePointer<CChar>?, url: UnsafePointer<CChar>?) in
           let cb = unsafeBitCast(handle, to: RouteCallbackState.self)
           cb.lookupCallback!(status == 0 ? RouteEntry(type: RouteEntryType(rawValue: Int(type))!, transportType: RouteTransportType(rawValue: Int(transportType))!, transportMode: RouteRpcTransportMode(rawValue: Int(transportMode))!, name: String(cString: name!), path: String(cString: path!), url: String(cString: url!)) : nil)
           cb.dispose()
        })
      }
    }
  }

  public func lookupRoute(path: String, _ callback: @escaping (_: RouteEntry?) -> Void) {
    path.withCString { pcstr in
      let callbackState = RouteCallbackState(self, lookup: callback)
      callbacks.append(callbackState)
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _RouteRegistryLookupRouteByPath(reference, pcstr, statePtr, { (handle: UnsafeMutableRawPointer?, status: CInt, type: CInt, transportType: CInt, transportMode: CInt, name: UnsafePointer<CChar>?, path: UnsafePointer<CChar>?, url: UnsafePointer<CChar>?) in
          let cb = unsafeBitCast(handle, to: RouteCallbackState.self)
          cb.lookupCallback!(status == 0 ? RouteEntry(type: RouteEntryType(rawValue: Int(type))!, transportType: RouteTransportType(rawValue: Int(transportType))!, transportMode: RouteRpcTransportMode(rawValue: Int(transportMode))!, name: String(cString: name!), path: String(cString: path!), url: String(cString: url!)) : nil)
          cb.dispose()
      })
    }
  }

  public func lookupRoute(url: String, _ callback: @escaping (_: RouteEntry?) -> Void) {
    url.withCString { ucstr in
      let callbackState = RouteCallbackState(self, lookup: callback)
      callbacks.append(callbackState)
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _RouteRegistryLookupRouteByUrl(reference, ucstr, statePtr, { (handle: UnsafeMutableRawPointer?, status: CInt, type: CInt, transportType: CInt, transportMode: CInt, name: UnsafePointer<CChar>?, path: UnsafePointer<CChar>?, url: UnsafePointer<CChar>?) in
          let cb = unsafeBitCast(handle, to: RouteCallbackState.self)
          cb.lookupCallback!(status == 0 ? RouteEntry(type: RouteEntryType(rawValue: Int(type))!, transportType: RouteTransportType(rawValue: Int(transportType))!, transportMode: RouteRpcTransportMode(rawValue: Int(transportMode))!, name: String(cString: name!), path: String(cString: path!), url: String(cString: url!)) : nil)
          cb.dispose()
      })
    }
  }

  public func lookupRoute(uuid: String, _ callback: @escaping (_: RouteEntry?) -> Void) {
    uuid.withCString { ucstr in
      let callbackState = RouteCallbackState(self, lookup: callback)
      callbacks.append(callbackState)
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _RouteRegistryLookupRouteByUUID(reference, ucstr, statePtr, { (handle: UnsafeMutableRawPointer?, status: CInt, type: CInt, transportType: CInt, transportMode: CInt, name: UnsafePointer<CChar>?, path: UnsafePointer<CChar>?, url: UnsafePointer<CChar>?) in
          let cb = unsafeBitCast(handle, to: RouteCallbackState.self)
          cb.lookupCallback!(status == 0 ? RouteEntry(type: RouteEntryType(rawValue: Int(type))!, transportType: RouteTransportType(rawValue: Int(transportType))!, transportMode: RouteRpcTransportMode(rawValue: Int(transportMode))!, name: String(cString: name!), path: String(cString: path!), url: String(cString: url!)) : nil)
          cb.dispose()
      })
    }
  }

  public func listRoutes(scheme: String, _ callback: @escaping (_: [RouteEntry]?) -> Void) {
    scheme.withCString { scstr in
      let callbackState = RouteCallbackState(self, list: callback)
      callbacks.append(callbackState)
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _RouteRegistryListRoutesWithScheme(reference, scstr, statePtr, { (handle: UnsafeMutableRawPointer?, status: CInt, count: CInt, types: UnsafeMutablePointer<CInt>?, transportTypes: UnsafeMutablePointer<CInt>?, transportModes: UnsafeMutablePointer<CInt>?, name: UnsafeMutablePointer<UnsafePointer<Int8>?>?, path: UnsafeMutablePointer<UnsafePointer<Int8>?>?, url: UnsafeMutablePointer<UnsafePointer<Int8>?>?) in
          let cb = unsafeBitCast(handle, to: RouteCallbackState.self)
          if count > 0 {
            var entries: [RouteEntry] = []
            for i in 0..<Int(count) {
              entries.append(RouteEntry(type: RouteEntryType(rawValue: Int(types![i]))!, transportType: RouteTransportType(rawValue: Int(transportTypes![i]))!, transportMode: RouteRpcTransportMode(rawValue: Int(transportModes![i]))!, name: String(cString: name![i]!), path: String(cString: path![i]!), url: String(cString: url![i]!)))
            }
            cb.listCallback!(entries)
          
          } else {
            cb.listCallback!(nil)
          }
          cb.dispose()
      })
    }
  }

  public func listRoutes(_ callback: @escaping (_: [RouteEntry]?) -> Void) {
    let callbackState = RouteCallbackState(self, list: callback)
    callbacks.append(callbackState)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _RouteRegistryListAllRoutes(reference, statePtr, { (handle: UnsafeMutableRawPointer?, status: CInt, count: CInt, types: UnsafeMutablePointer<CInt>?, transportTypes: UnsafeMutablePointer<CInt>?, transportModes: UnsafeMutablePointer<CInt>?, name: UnsafeMutablePointer<UnsafePointer<Int8>?>?, path: UnsafeMutablePointer<UnsafePointer<Int8>?>?, url: UnsafeMutablePointer<UnsafePointer<Int8>?>?) in
        let cb = unsafeBitCast(handle, to: RouteCallbackState.self)
        if count > 0 {
          var entries: [RouteEntry] = []
          for i in 0..<Int(count) {
            entries.append(RouteEntry(type: RouteEntryType(rawValue: Int(types![i]))!, transportType: RouteTransportType(rawValue: Int(transportTypes![i]))!, transportMode: RouteRpcTransportMode(rawValue: Int(transportModes![i]))!, name: String(cString: name![i]!), path: String(cString: path![i]!), url: String(cString: url![i]!)))
          }
          cb.listCallback!(entries)
        
        } else {
          cb.listCallback!(nil)
        }
        cb.dispose()
    })
  }

  public func getRouteCount(_ callback: @escaping (_: Int) -> Void) {
    let callbackState = RouteCallbackState(self, count: callback)
    callbacks.append(callbackState)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _RouteRegistryGetRouteCount(reference, statePtr, { (handle: UnsafeMutableRawPointer?, count: CInt) in
      let cb = unsafeBitCast(handle, to: RouteCallbackState.self)
      cb.countCallback!(Int(count))
      cb.dispose()
    })
  }

  public func addSubscriber(scheme: String, _ watcher: RouteSubscriber) {
    scheme.withCString {
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      let watcherPtr = watcher.unsafeReference
      _RouteRegistryAddSubscriber(reference, $0, 
        statePtr,
        watcherPtr,
        // onSubscriberAdded
        { (handle: UnsafeMutableRawPointer?, id: CInt, w: UnsafeMutableRawPointer? , ref: UnsafeMutableRawPointer?) in
          let this = unsafeBitCast(handle, to: RouteRegistry.self)
          let localSubscriber = unsafeBitCast(w, to: RouteSubscriber.self)
          this.onSubscriberAdded(id: Int(id), reference: ref!, watcher: localSubscriber)
        }, 
        { (handle: UnsafeMutableRawPointer?, header: UnsafePointer<Int8>?) in 
          let watcher = unsafeBitCast(handle, to: RouteSubscriber.self)
          watcher.onRouteHeaderChanged(header: String(cString: header!))
        },
        // onRouteAdded
        { (handle: UnsafeMutableRawPointer?, type: CInt, transportType: CInt, transportMode: CInt, name: UnsafePointer<Int8>?, path: UnsafePointer<Int8>?, url: UnsafePointer<Int8>?) in 
          let watcher = unsafeBitCast(handle, to: RouteSubscriber.self)
          watcher.onRouteAdded(route: RouteEntry(type: RouteEntryType(rawValue: Int(type))!, transportType: RouteTransportType(rawValue: Int(transportType))!, transportMode: RouteRpcTransportMode(rawValue: Int(transportMode))!, name: String(cString: name!), path: String(cString: path!), url: String(cString: url!)))
        },
        // onRouteRemoved
        { (handle: UnsafeMutableRawPointer?, type: CInt, transportType: CInt, transportMode: CInt, name: UnsafePointer<Int8>?, path: UnsafePointer<Int8>?, url: UnsafePointer<Int8>?) in 
          let watcher = unsafeBitCast(handle, to: RouteSubscriber.self)
          watcher.onRouteRemoved(route: RouteEntry(type: RouteEntryType(rawValue: Int(type))!, transportType: RouteTransportType(rawValue: Int(transportType))!, transportMode: RouteRpcTransportMode(rawValue: Int(transportMode))!, name: String(cString: name!), path: String(cString: path!), url: String(cString: url!)))
        },
        // void(*OnRouteChanged)(void*, int, int, int, const char*, const char*, const char*)
        { (handle: UnsafeMutableRawPointer?, type: CInt, transportType: CInt, transportMode: CInt, name: UnsafePointer<Int8>?, path: UnsafePointer<Int8>?, url: UnsafePointer<Int8>?) in 
          let watcher = unsafeBitCast(handle, to: RouteSubscriber.self)
          watcher.onRouteChanged(route: RouteEntry(type: RouteEntryType(rawValue: Int(type))!, transportType: RouteTransportType(rawValue: Int(transportType))!, transportMode: RouteRpcTransportMode(rawValue: Int(transportMode))!, name: String(cString: name!), path: String(cString: path!), url: String(cString: url!)))
        }
      )
    }
  }

  public func removeSubscriber(id: Int) {
    _RouteRegistryRemoveSubscriber(reference, CInt(id))
    onSubscriberRemoved(id: Int(id))
  }

  public func removeSubscriber(_ watcher: RouteSubscriber) {
    for (id, w) in watchers {
      if w.subscriber === watcher {
        removeSubscriber(id: id)
        return
      }
    }
  }

  private func onSubscriberAdded(id: Int, reference: UnsafeMutableRawPointer, watcher: RouteSubscriber) {
    watchers[id] = RouteSubscriberState(id: id, subscriber: watcher, reference: reference)
  }

  private func onSubscriberRemoved(id: Int) {
    watchers.removeValue(forKey: id)
  }

}

internal class RouteCallbackState {
  
  internal var haveCallback: ((_: Bool) -> Void)?
  internal var lookupCallback: ((_: RouteEntry?) -> Void)?
  internal var listCallback: ((_: [RouteEntry]?) -> Void)?
  internal var countCallback: ((_: Int) -> Void)?
  private weak var owner: RouteRegistry?

  init(_ owner: RouteRegistry, lookup: @escaping (_: RouteEntry?) -> Void) {
    self.owner = owner
    self.lookupCallback = lookup
  }

  init(_ owner: RouteRegistry, list: @escaping (_: [RouteEntry]?) -> Void) {
    self.owner = owner
    self.listCallback = list
  }

  init(_ owner: RouteRegistry, have: @escaping (_: Bool) -> Void) {
    self.owner = owner
    self.haveCallback = have
  }

  init(_ owner: RouteRegistry, count: @escaping (_: Int) -> Void) {
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