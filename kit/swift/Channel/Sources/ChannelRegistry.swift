// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims
import Web

public class ChannelRegistry {

  internal var reference: ChannelRegistryRef
  internal var callbacks: [ChannelRegistryCallbackState]

  public init(reference: ChannelRegistryRef) {
    self.reference = reference
    callbacks = []
  }

  deinit {
    _ChannelRegistryDestroy(reference)
  }

  public func haveChannel(scheme: String, name: String, _ cb: @escaping (_: Bool) -> Void) {
    scheme.withCString { scstr in
      name.withCString { ncstr in
        let callbackState = ChannelRegistryCallbackState(self, have: cb)
        callbacks.append(callbackState)
        let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _ChannelRegistryHaveChannel(reference, scstr, ncstr, statePtr, { (handle: UnsafeMutableRawPointer?, have: CInt) in
          let cb = unsafeBitCast(handle, to: ChannelRegistryCallbackState.self)
          cb.haveCallback!(have != 0)
          cb.dispose()
        })
      }
    }
  }
  
  public func haveChannel(uuid: String, _ cb: @escaping (_: Bool) -> Void) {
    uuid.withCString { pcstr in
      let callbackState = ChannelRegistryCallbackState(self, have: cb)
      callbacks.append(callbackState)
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _ChannelRegistryHaveChannelByUUID(reference, pcstr, statePtr, { (handle: UnsafeMutableRawPointer?, have: CInt) in
          let cb = unsafeBitCast(handle, to: ChannelRegistryCallbackState.self)
          cb.haveCallback!(have != 0)
          cb.dispose()
      })
    }
  }

  public func getChannelCount(_ cb: @escaping (_: Int) -> Void) {
    let callbackState = ChannelRegistryCallbackState(self, count: cb)
    callbacks.append(callbackState)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ChannelRegistryGetChannelCount(reference, statePtr, { (handle: UnsafeMutableRawPointer?, count: CInt) in
      let cb = unsafeBitCast(handle, to: ChannelRegistryCallbackState.self)
      cb.countCallback!(Int(count))
      cb.dispose()
    })
  }

  public func lookupChannel(scheme: String, name: String, _ cb: @escaping (_: ChannelInfo?) -> Void) {
    scheme.withCString { scstr in
      name.withCString { ncstr in
        let callbackState = ChannelRegistryCallbackState(self, lookup: cb)
        callbacks.append(callbackState)
        let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _ChannelRegistryLookupChannel(reference, scstr, ncstr, statePtr, { (handle: UnsafeMutableRawPointer?, status: CInt, uuid: UnsafePointer<CChar>?, scheme: UnsafePointer<CChar>?, name: UnsafePointer<CChar>?) in
          let cb = unsafeBitCast(handle, to: ChannelRegistryCallbackState.self)
          cb.lookupCallback!(status == 0 ? ChannelInfo(uuid: String(cString: uuid!), scheme: String(cString: scheme!), name: String(cString: name!)) : nil)
          cb.dispose()
        })
      }
    }
  }
  
  public func lookupChannel(uuid: String, _ cb: @escaping (_: ChannelInfo?) -> Void) {
    uuid.withCString { ucstr in
      let callbackState = ChannelRegistryCallbackState(self, lookup: cb)
      callbacks.append(callbackState)
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _ChannelRegistryLookupChannelByUUID(reference, ucstr, statePtr, { (handle: UnsafeMutableRawPointer?, status: CInt, uuid: UnsafePointer<CChar>?, scheme: UnsafePointer<CChar>?, name: UnsafePointer<CChar>?) in
          let cb = unsafeBitCast(handle, to: ChannelRegistryCallbackState.self)
          cb.lookupCallback!(status == 0 ? ChannelInfo(uuid: String(cString: uuid!), scheme: String(cString: scheme!), name: String(cString: name!)) : nil)
          cb.dispose()
      })
    }
  }

  public func listChannels(_ cb: @escaping (_: [ChannelInfo]?) -> Void) {
    let callbackState = ChannelRegistryCallbackState(self, list: cb)
    callbacks.append(callbackState)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ChannelRegistryListAllChannels(reference, statePtr, { (handle: UnsafeMutableRawPointer?, status: CInt, count: CInt, uuids: UnsafeMutablePointer<UnsafePointer<Int8>?>?, schemes: UnsafeMutablePointer<UnsafePointer<Int8>?>?, names: UnsafeMutablePointer<UnsafePointer<Int8>?>?) in
        let cb = unsafeBitCast(handle, to: ChannelRegistryCallbackState.self)
        if count > 0 {
          var entries: [ChannelInfo] = []
          for i in 0..<Int(count) {
            entries.append(ChannelInfo(uuid: String(cString: uuids![i]!), scheme: String(cString: schemes![i]!), name: String(cString: names![i]!)))
          }
          cb.listCallback!(entries)
        } else {
          cb.listCallback!(nil)
        }
        cb.dispose()
    })
  }

  public func connectToChannel(delegate: ChannelClient, scope: ServiceWorkerGlobalScope, scheme: String, name: String, _ cb: @escaping (_: ChannelClient?) -> Void) {
    scheme.withCString { scstr in
      name.withCString { ncstr in  
        let client = ChannelClientAdapter(scope: scope, scheme: scheme, name: name)
        let callbackState = ChannelRegistryCallbackState(self, scheme: scheme, name: name, connect: cb, client: client, delegate: delegate)
        callbacks.append(callbackState)
        let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        let clientStatePtr = unsafeBitCast(Unmanaged.passUnretained(client).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _ChannelRegistryConnectChannel(reference, scstr, ncstr, statePtr, clientStatePtr, { (handle: UnsafeMutableRawPointer?, status: CInt, clientHandle: UnsafeMutableRawPointer?) in
            let cb = unsafeBitCast(handle, to: ChannelRegistryCallbackState.self)
            let thisClient = cb.client!
            if status == 0 {
              thisClient.reference = clientHandle!
              thisClient.client = cb.delegate
            }
            cb.connectCallback!(status == 0 ? thisClient : nil)
            cb.dispose()
        },
        { (handle: UnsafeMutableRawPointer?, messageHandle: UnsafeMutableRawPointer?) in 
            let client = unsafeBitCast(handle, to: ChannelClientAdapter.self)
            let serializedMessage = SerializedScriptValue(owned: messageHandle!, scope: client.scope!)
            client.onMessage(message: serializedMessage)
        })
      }
    }
  }

  public func connectToChannel(delegate: ChannelClient, window: WebWindow, scheme: String, name: String, _ cb: @escaping (_: ChannelClient?) -> Void) {
    scheme.withCString { scstr in
      name.withCString { ncstr in  
        let client = ChannelClientAdapter(window: window, scheme: scheme, name: name)
        let callbackState = ChannelRegistryCallbackState(self, scheme: scheme, name: name, connect: cb, client: client, delegate: delegate)
        callbacks.append(callbackState)
        let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        let clientStatePtr = unsafeBitCast(Unmanaged.passUnretained(client).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _ChannelRegistryConnectChannel(reference, scstr, ncstr, statePtr, clientStatePtr, { (handle: UnsafeMutableRawPointer?, status: CInt, clientHandle: UnsafeMutableRawPointer?) in
            let cb = unsafeBitCast(handle, to: ChannelRegistryCallbackState.self)
            let thisClient = cb.client!
            if status == 0 {
              thisClient.reference = clientHandle!
              thisClient.client = cb.delegate
            }
            cb.connectCallback!(status == 0 ? thisClient : nil)
            cb.dispose()
        },
        { (handle: UnsafeMutableRawPointer?, messageHandle: UnsafeMutableRawPointer?) in 
            let client = unsafeBitCast(handle, to: ChannelClientAdapter.self)
            let serializedMessage = SerializedScriptValue(owned: messageHandle!, window: client.window!)
            client.onMessage(message: serializedMessage)
        })
      }
    }
  }

  public func connectToChannel(delegate: ChannelClient, worker: WebWorker, scheme: String, name: String, _ cb: @escaping (_: ChannelClient?) -> Void) {
    scheme.withCString { scstr in
      name.withCString { ncstr in  
        let client = ChannelClientAdapter(worker: worker, scheme: scheme, name: name)
        let callbackState = ChannelRegistryCallbackState(self, scheme: scheme, name: name, connect: cb, client: client, delegate: delegate)
        callbacks.append(callbackState)
        let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        let clientStatePtr = unsafeBitCast(Unmanaged.passUnretained(client).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _ChannelRegistryConnectChannel(reference, scstr, ncstr, statePtr, clientStatePtr, { (handle: UnsafeMutableRawPointer?, status: CInt, clientHandle: UnsafeMutableRawPointer?) in
            let cb = unsafeBitCast(handle, to: ChannelRegistryCallbackState.self)
            let thisClient = cb.client!
            if status == 0 {
              thisClient.reference = clientHandle!
              thisClient.client = cb.delegate
            }
            cb.connectCallback!(status == 0 ? thisClient : nil)
            cb.dispose()
        },
        { (handle: UnsafeMutableRawPointer?, messageHandle: UnsafeMutableRawPointer?) in 
            let client = unsafeBitCast(handle, to: ChannelClientAdapter.self)
            let serializedMessage = SerializedScriptValue(owned: messageHandle!, worker: client.worker!)
            client.onMessage(message: serializedMessage)
        })
      }
    }
  }

  public func removeChannel(scheme: String, name: String, _ cb: @escaping (_: ChannelStatus) -> Void)  {
    scheme.withCString { scstr in
      name.withCString { ncstr in
        let callbackState = ChannelRegistryCallbackState(self, remove: cb)
        callbacks.append(callbackState)
        let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
        _ChannelRegistryRemoveChannel(reference, scstr, ncstr, statePtr, { (handle: UnsafeMutableRawPointer?, status: CInt) in
          let cb = unsafeBitCast(handle, to: ChannelRegistryCallbackState.self)
          cb.removeCallback!(ChannelStatus(rawValue: Int(status))!)
          cb.dispose()
        })
      }
    }
  } 

  public func removeChannel(uuid: String, _ cb: @escaping (_: ChannelStatus) -> Void) {
    uuid.withCString { ucstr in
      let callbackState = ChannelRegistryCallbackState(self, remove: cb)
      callbacks.append(callbackState)
      let statePtr = unsafeBitCast(Unmanaged.passUnretained(callbackState).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
      _ChannelRegistryRemoveChannelByUUID(reference, ucstr, statePtr, { (handle: UnsafeMutableRawPointer?, status: CInt) in
          let cb = unsafeBitCast(handle, to: ChannelRegistryCallbackState.self)
          cb.removeCallback!(ChannelStatus(rawValue: Int(status))!)
          cb.dispose()
      })
    }
  }

}

internal class ChannelRegistryCallbackState {
  
  internal var haveCallback: ((_: Bool) -> Void)?
  internal var connectCallback: ((_: ChannelClient?) -> Void)?
  internal var lookupCallback: ((_: ChannelInfo?) -> Void)?
  internal var listCallback: ((_: [ChannelInfo]?) -> Void)?
  internal var countCallback: ((_: Int) -> Void)?
  internal var removeCallback: ((_: ChannelStatus) -> Void)?
  internal var scheme: String = String()
  internal var name: String = String()
  internal var client: ChannelClientAdapter?
  internal var delegate: ChannelClient?
  private weak var owner: ChannelRegistry?

  init(_ owner: ChannelRegistry, lookup: @escaping (_: ChannelInfo?) -> Void) {
    self.owner = owner
    self.lookupCallback = lookup
  }

  init(_ owner: ChannelRegistry, scheme: String, name: String, connect: @escaping (_: ChannelClient?) -> Void, client: ChannelClientAdapter, delegate: ChannelClient) {
    self.owner = owner
    self.scheme = scheme
    self.name = name
    self.connectCallback = connect
    self.client = client
    self.delegate = delegate
  }

  init(_ owner: ChannelRegistry, list: @escaping (_: [ChannelInfo]?) -> Void) {
    self.owner = owner
    self.listCallback = list
  }

  init(_ owner: ChannelRegistry, have: @escaping (_: Bool) -> Void) {
    self.owner = owner
    self.haveCallback = have
  }

  init(_ owner: ChannelRegistry, count: @escaping (_: Int) -> Void) {
    self.owner = owner
    self.countCallback = count
  }

  init(_ owner: ChannelRegistry, remove: @escaping (_: ChannelStatus) -> Void) {
    self.owner = owner
    self.removeCallback = remove
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