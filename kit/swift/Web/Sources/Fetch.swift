// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims


public typealias FetchCallback = (_: Response) -> ()

public protocol FetchCallbackHolder : class {
  func addCallback(_: FetchCallbackState)
  func removeCallback(_: FetchCallbackState)
}

extension WebWorker : FetchCallbackHolder {

  public func fetch(url: String, _ callback: @escaping FetchCallback) {
    let state = FetchCallbackState(worker: self, self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    url.withCString {
      FetchFromWorker(reference, $0, statePtr, { (handle: UnsafeMutableRawPointer?, response: UnsafeMutableRawPointer?) in
        let cbState = unsafeBitCast(handle, to: FetchCallbackState.self)
        cbState.run(Response(reference: response!, worker: cbState.worker!))
        cbState.dispose()
      })
    }
  }

  public func addCallback(_ state: FetchCallbackState) {
    callbacks.append(state)
  }

  public func removeCallback(_ state: FetchCallbackState) {
    for (index, callback) in callbacks.enumerated() {
      if state === callback {
        callbacks.remove(at: index)
        return
      }
    }
  }

}

extension WebNavigator : FetchCallbackHolder {

  // fixme: this is broken given the runtime is only implemented for webworkers context
  public func fetch(url: String, _ callback: @escaping FetchCallback) {
    let state = FetchCallbackState(window: self.window, self, callback)
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(state).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    url.withCString {
      FetchFromWindow(window.reference, $0, statePtr, { (handle: UnsafeMutableRawPointer?, response: UnsafeMutableRawPointer?) in
        let cbState = unsafeBitCast(handle, to: FetchCallbackState.self)
        cbState.run(Response(reference: response!, window: cbState.window!))
        cbState.dispose()
      })
    }
  }

  public func addCallback(_ state: FetchCallbackState) {
    callbacks.append(state)
  }

  public func removeCallback(_ state: FetchCallbackState) {
    for (index, callback) in callbacks.enumerated() {
      if state === callback {
        callbacks.remove(at: index)
        return
      }
    }
  }

}

public class FetchCallbackState {
  
  public weak var parent: FetchCallbackHolder?
  var callback: FetchCallback
  weak var window: WebWindow?
  weak var worker: WebWorker?
  weak var scope: ServiceWorkerGlobalScope?

  init(window: WebWindow, _ parent: FetchCallbackHolder, _ callback: @escaping FetchCallback) {
    self.parent = parent
    self.callback = callback
    self.window = window
    self.parent!.addCallback(self)
  }

  init(worker: WebWorker, _ parent: FetchCallbackHolder, _ callback: @escaping FetchCallback) {
    self.parent = parent
    self.callback = callback
    self.worker = worker
    self.parent!.addCallback(self)
  }

  init(scope: ServiceWorkerGlobalScope, _ parent: FetchCallbackHolder, _ callback: @escaping FetchCallback) {
    self.parent = parent
    self.callback = callback
    self.scope = scope
    self.parent!.addCallback(self)
  }

  func run(_ response: Response) {
    callback(response)
  }

  func dispose() {
    parent!.removeCallback(self)
  }

}