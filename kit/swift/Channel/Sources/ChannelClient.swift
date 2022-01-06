// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims
import Web

public protocol ChannelClient : class {
  func onMessage(message: SerializedScriptValue)
  func postMessage(_ string: String)
}

internal class ChannelClientAdapter : ChannelClient {
  
  // public var uuid: String {
  //   return impl.uuid
  // }

  internal var reference: ChannelClientRef!
  internal var client: ChannelClient?
  internal var window: WebWindow?
  internal var worker: WebWorker?
  internal var scope: ServiceWorkerGlobalScope?
  private var info: ChannelInfo
  
  // init(impl: ChannelClient) {
  //   self.impl = impl
  //   let instance = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
  //   reference = _ChannelClientCreate(feed.reference, instance, { (state: UnsafeMutableRawPointer?, pubid: UnsafePointer<CChar>?, content: UnsafePointer<CChar>?, len: CInt, data: UnsafeMutableRawPointer?) in 
  //     let this = unsafeBitCast(state, to: ChannelClientAdapter.self)
  //     this.onDataAvailable(publisher: String(cString: pubid!), contentType: String(cString: content!), data: Data(bytes: data!, count: Int(len)))
  //   })
  // }

  // public init(reference: ChannelClientRef, scheme: String, name: String) {
  //   info = ChannelInfo(scheme: scheme, name: name)
  //   self.reference = reference
  // }

  public init(scope: ServiceWorkerGlobalScope, scheme: String, name: String) {
    info = ChannelInfo(scheme: scheme, name: name)
    self.scope = scope
  }

  public init(window: WebWindow, scheme: String, name: String) {
    info = ChannelInfo(scheme: scheme, name: name)
    self.window = window
  }

  public init(worker: WebWorker, scheme: String, name: String) {
    info = ChannelInfo(scheme: scheme, name: name)
    self.worker = worker
  }

  deinit {
    if reference != nil {
      _ChannelClientDestroy(reference)
    }
  }

  public func close() {
    _ChannelClientClose(reference)
  }

  public func postMessage(_ string: String) {
    string.withCString {
      if let w = window {
        _ChannelClientPostMessageString(reference, w.reference, $0)
      }
      if let w = worker {
        _ChannelClientPostMessageStringFromWorker(reference, w.reference, $0)
      }
      if let s = scope {
        _ChannelClientPostMessageStringFromServiceWorker(reference, s.reference, $0)
      }
    }
  }

  internal func onMessage(message: SerializedScriptValue) {
    client?.onMessage(message: message)
  }

}
