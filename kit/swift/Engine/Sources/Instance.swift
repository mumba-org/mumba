// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//import _
import Base
import MumbaShims
import Web

public protocol Delegate {

  var serviceWorkerContextClient: ServiceWorkerContextClient? { get }

  //var completionQueue: ControlCompletionQueue? { get }
  // give the delegate a chance to hook on the initialization process
  func onInit(containerContext: ContainerContext)
  // to run
  //func onRun()
  // give the delegate a chance to hook on the shutdown process
  func onShutdown()

  func foreachApplication(
    handle: ApplicationHostRef,
    name: String,
    uuid: String,
    url: String)
}

public class Instance {

  internal static func instance() -> Instance {
    if Instance.global == nil {
      Instance.global = Instance(delegate: nil)
    }
    return Instance.global!
  }

  public var delegate: Delegate?
  internal var state: EngineInstanceRef?

  internal static var global: Instance?
  internal var initialized: Bool = false

  init(delegate: Delegate?) { 
    if let d = delegate {
      setup(delegate: d)
    }
    Instance.global = self
  }

  internal func setup(delegate: Delegate) {
    self.delegate = delegate
    var callbacks = Callbacks()

    callbacks.OnInit = { (handle: UnsafeMutableRawPointer?, contextRef: ShellContextRef?) in
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: Instance.self)
      state.delegate!.onInit(containerContext: ContainerContext(reference: contextRef!))
      postTask {
        state.fetchMetadata()
      }
    }

    // callbacks.OnRun = { (handle: UnsafeMutableRawPointer?) in
    //   guard handle != nil else {
    //     return
    //   }
    //   let state = unsafeBitCast(handle, to: Instance.self)
    //   state.delegate!.onRun()
    // }

    callbacks.OnShutdown = { (handle: UnsafeMutableRawPointer?) in
      guard handle != nil else {
        return
      }
      let state = unsafeBitCast(handle, to: Instance.self)
      state.delegate!.onShutdown()
    }

    callbacks.GetServiceWorkerContextClientState = { (handle: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? in
      return handle
    }

    callbacks.GetServiceWorkerContextClientCallbacks = { (handle: UnsafeMutableRawPointer?) -> ServiceWorkerContextClientCallbacks in
      var cbs = ServiceWorkerContextClientCallbacks()
      cbs.GetWorkerNativeClientState = { (handle: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? in
        let state = unsafeBitCast(handle, to: Instance.self)
        return state.delegate!.serviceWorkerContextClient!.unsafeState
      }
      cbs.GetWorkerNativeClientCallbacks = { (handle: UnsafeMutableRawPointer?) -> WorkerNativeClientCallbacks in
        let state = unsafeBitCast(handle, to: Instance.self)
        return state.delegate!.serviceWorkerContextClient!.callbacks
      }
      return cbs
    }

    // callbacks.GetEventQueue = { (handle: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? in
    //   guard handle != nil else {
    //     return nil
    //   }
    //   let state = unsafeBitCast(handle, to: Instance.self)
    //   if let queue = state.delegate?.completionQueue {
    //     return queue.reference
    //   }
    //   return nil
    // }

    let selfInstance = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    self.state = engineCreate(selfInstance, callbacks)


    initialized = true
  }

  deinit {
    if let s = state {
      engineDestroy(s)
    }
  }

  private func fetchMetadata() {
    let selfInstance = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    
    // ForeachApplication: We ask for the list of (registered) applications
    // so we can add and manage them on the swift side 
    _EngineForeachApplication(self.state!, 
        selfInstance, { 
        (handle: UnsafeMutableRawPointer?, 
        app: UnsafeMutableRawPointer?,
        name: UnsafePointer<Int8>?,
        uuid: UnsafePointer<Int8>?,
        url: UnsafePointer<Int8>?) in
          let instance = unsafeBitCast(handle, to: Instance.self)
          instance.delegate!.foreachApplication(
            handle: app!,
            name: String(cString: name!),
            uuid: String(cString: uuid!),
            url: String(cString: url!))
      })
  }

}

public func initialize(delegate: Delegate) {
  let instance = Instance.instance()
  instance.setup(delegate: delegate)
}

public func destroy() {
  Instance.global = nil
}

public func getDelegate() -> Delegate? {
  return Instance.global?.delegate
}

public func getClient() -> UnsafeMutableRawPointer {
  let instance = Instance.instance()
  return engineGetClient(instance.state!)
}

