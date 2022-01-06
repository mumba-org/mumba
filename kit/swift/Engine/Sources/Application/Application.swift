// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base
import Graphics

public enum ApplicationKind : Int {
  // the application works as a UI renderer
  case UI
  // for batch/utility applications
  case Batch
}

public protocol ApplicationHostDelegate : class {
  func onApplicationInstanceLaunched(instance: ApplicationInstance)
  func onApplicationInstanceLaunchFailed(status: Status, instance: ApplicationInstance)
  func onApplicationInstanceKilled(status: Status, instance: ApplicationInstance)
  func onApplicationInstanceActivated(instance: ApplicationInstance)
  func onApplicationInstanceClosed(status: Status, instance: ApplicationInstance)
}

// extension ApplicationHostDelegate {
//   public func onApplicationInstanceLaunched(instance: ApplicationInstance) {}
//   public func onApplicationInstanceLaunchFailed(status: Status, instance: ApplicationInstance) {}
//   public func onApplicationInstanceKilled(status: Status, instance: ApplicationInstance) {}
//   public func onApplicationInstanceClosed(status: Status, instance: ApplicationInstance) {}
// }

public class ApplicationHost {

  public private(set) var instances: ContiguousArray<ApplicationInstance> = ContiguousArray<ApplicationInstance>()

  public let kind: ApplicationKind
  public private(set) var name: String = String()
  public private(set) var uuid: String = String()
  public private(set) var url: String = String()

  private weak var delegate: ApplicationHostDelegate?
  internal var reference: ApplicationHostRef?

  init(delegate: ApplicationHostDelegate, name: String, uuid: String, url: String, kind: ApplicationKind, reference: ApplicationHostRef) {
    self.delegate = delegate
    self.name = name
    self.kind = kind
    self.reference = reference

    let selfInstance = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    _ApplicationHostBindCallbacks(reference, selfInstance, createCallbacks())
  }

  deinit {
    _ApplicationHostDestroy(reference) 
  }

  public func launch(
    id: Int, 
    url: String, 
    windowMode: WindowMode,
    initialBounds: IntRect,
    windowDisposition: WindowOpenDisposition,
    fullscreen: Bool,
    headless: Bool) {
    print("ApplicationHost.launch url = \(url)")
    url.withCString {
      _ApplicationHostInstanceLaunch(reference, 
        CInt(id), 
        $0, 
        CInt(windowMode.rawValue), 
        CInt(initialBounds.x), 
        CInt(initialBounds.y), 
        CInt(initialBounds.width), 
        CInt(initialBounds.height),
        CInt(windowDisposition.rawValue), 
        fullscreen ? 1 : 0,
        headless ? 1 : 0)
    }
  }

  public func kill(id: Int) {
    print("ApplicationHost.kill id = \(id)")
    for instance in instances {
      // check if its a valid id and if its really running
      if instance.id == id && instance.state == .Running {
        _ApplicationHostInstanceKill(reference, CInt(id))
      }
    }
  }

  public func activate(id: Int) {
    print("ApplicationHost.activate id = \(id)")
    for instance in instances {
      // check if its a valid id
      if instance.id == id {
        _ApplicationHostInstanceActivate(reference, CInt(id))
      }
    }
  }

  public func close(id: Int) {
    //print("ApplicationHost.close id = \(id)")
    for instance in instances {
      //print("ApplicationHost.close -> instance.state = \(instance.state)")
      // check if its a valid id and if its really running
      if instance.id == id && instance.state == .Running {
        _ApplicationHostInstanceClose(reference, CInt(id))
      }
    }
  }

  public func kill(instance: ApplicationInstance) {
    //print("ApplicationHost.kill -> instance.state = \(instance.state)")
    if instance.state == .Running {
      _ApplicationHostInstanceKill(reference, CInt(instance.id)) 
    }
  }

  public func getInstance(id: Int) -> ApplicationInstance? {
    for instance in instances {
      if instance.id == id {
        return instance
      }
    }
    return nil
  }

  // callbacks
  
  private func onApplicationInstanceCreated( 
    id: Int, 
    name: String, 
    url: String, 
    uuid: String) {
    //print("ApplicationHost.onApplicationInstanceCreated id = \(id) url = \(url)")

    addInstance(ApplicationInstance(
      host: self,
      id: id,
      name: name,
      url: url,
      uuid: uuid))
  }

  private func onApplicationInstanceDestroyed(id: Int) {
    //print("ApplicationHost.onApplicationInstanceDestroyed id = \(id)")
    removeInstance(id: id)
  }

  private func onApplicationInstanceLaunched(id: Int) {
    //print("ApplicationHost.onApplicationInstanceLaunched id = \(id)")
    if let instance = getInstance(id: id) {
      delegate?.onApplicationInstanceLaunched(instance: instance)
    }
  }

  private func onApplicationInstanceLaunchFailed(status: Status, id: Int) {
    //print("ApplicationHost.onApplicationInstanceLaunchFailed id = \(id)")
    if let instance = getInstance(id: id) {
      delegate?.onApplicationInstanceLaunchFailed(status: status, instance: instance)
    }
  }

  private func onApplicationInstanceKilled(status: Status, id: Int) {
    //print("ApplicationHost.onApplicationInstanceKilled id = \(id)")
    
    if let instance = getInstance(id: id) {
      delegate?.onApplicationInstanceKilled(status: status, instance: instance)
    }
    //postDelayedTask ({
    //  print("calling launch ...")
    //  self.launch(url: "tweedy://hello?path=jeca")
    //}, delay: TimeDelta.from(milliseconds: 1000 * 3))
  }

  private func onApplicationInstanceActivated(id: Int) {
    if let instance = getInstance(id: id) {
      delegate?.onApplicationInstanceActivated(instance: instance)
    }
  }

  private func onApplicationInstanceClosed(status: Status, id: Int) {
    //print("ApplicationHost.onApplicationInstanceClosed id = \(id)")
    
    if let instance = getInstance(id: id) {
      delegate?.onApplicationInstanceClosed(status: status, instance: instance)
    }
  }

  private func onApplicationInstanceStateChanged(id: Int, state: ApplicationState) {
    guard let instance = getInstance(id: id) else {
      return
    }
    instance.state = state
  }

  private func onApplicationInstanceBoundsChanged(id: Int, bounds: IntRect) {
    guard let instance = getInstance(id: id) else {
      return
    }
    instance.onBoundsChanged(bounds: bounds)
  }

  private func onApplicationInstanceVisible(id: Int) {
    guard let instance = getInstance(id: id) else {
      return
    }
    instance.onVisible()
  }

  private func onApplicationInstanceHidden(id: Int) {
    guard let instance = getInstance(id: id) else {
      return
    }
    instance.onHidden()
  }

  private func addInstance(_ instance: ApplicationInstance) {
    instances.append(instance)
  }

  private func removeInstance(id: Int) {
    for (index, instance) in instances.enumerated() {
      if instance.id == id {
        instances.remove(at: index)
        return
      }
    }
  }

  private func createCallbacks() -> CApplicationHostCallbacks {
    var callbacks = CApplicationHostCallbacks()

    callbacks.OnApplicationInstanceCreated = { (
      handle: UnsafeMutableRawPointer?, 
      id: CInt,
      url: UnsafePointer<Int8>?,
      uuid: UnsafePointer<Int8>?) in
      
      let state = unsafeBitCast(handle, to: ApplicationHost.self)      
      state.onApplicationInstanceCreated( 
        id: Int(id), 
        name: state.name,
        url: url == nil ? String() : String(cString: url!), 
        uuid: uuid == nil ? String() : String(cString: uuid!))
    }

    callbacks.OnApplicationInstanceDestroyed = { (handle: UnsafeMutableRawPointer?, id: CInt) in 
      let state = unsafeBitCast(handle, to: ApplicationHost.self)
      state.onApplicationInstanceDestroyed(id: Int(id))
    }

    callbacks.OnApplicationInstanceLaunched = { (handle: UnsafeMutableRawPointer?, id: CInt) in
      let state = unsafeBitCast(handle, to: ApplicationHost.self)
      state.onApplicationInstanceLaunched(id: Int(id))
    }

    callbacks.OnApplicationInstanceLaunchFailed = { (handle: UnsafeMutableRawPointer?, id: CInt, status: CInt, message: UnsafePointer<Int8>?) in
      let state = unsafeBitCast(handle, to: ApplicationHost.self)
      state.onApplicationInstanceLaunchFailed(status: Status(code: StatusCode(rawValue: Int(status)) ?? StatusCode.Unknown, message: String()), id: Int(id))//message == nil ? String() : String(cString: message!)), id: Int(id))
    }

    callbacks.OnApplicationInstanceKilled = { (handle: UnsafeMutableRawPointer?, id: CInt, status: CInt, message: UnsafePointer<Int8>?) in
      let state = unsafeBitCast(handle, to: ApplicationHost.self)
      state.onApplicationInstanceKilled(status: Status(code: StatusCode(rawValue: Int(status)) ?? StatusCode.Unknown, message: String()), id: Int(id)) //message == nil ? String() : String(cString: message!)), id: Int(id))
    }

    callbacks.OnApplicationInstanceActivated = { (handle: UnsafeMutableRawPointer?, id: CInt) in
      let state = unsafeBitCast(handle, to: ApplicationHost.self)
      state.onApplicationInstanceActivated(id: Int(id))
    }

    callbacks.OnApplicationInstanceClosed = { (handle: UnsafeMutableRawPointer?, id: CInt, status: CInt, message: UnsafePointer<Int8>?) in
      let state = unsafeBitCast(handle, to: ApplicationHost.self)
      state.onApplicationInstanceClosed(status: Status(code: StatusCode(rawValue: Int(status)) ?? StatusCode.Unknown, message: String()), id: Int(id)) //message == nil ? String() : String(cString: message!)), id: Int(id))
    }

    callbacks.OnApplicationInstanceStateChanged = { (handle: UnsafeMutableRawPointer?, id: CInt, app_state: CInt) in
      let state = unsafeBitCast(handle, to: ApplicationHost.self)
      state.onApplicationInstanceStateChanged(id: Int(id), state: ApplicationState(rawValue: Int(app_state))!)
    }

    callbacks.OnApplicationInstanceBoundsChanged = { (handle: UnsafeMutableRawPointer?, id: CInt, width: CInt, height: CInt) in
      let state = unsafeBitCast(handle, to: ApplicationHost.self)
      state.onApplicationInstanceBoundsChanged(id: Int(id), bounds: IntRect(width: Int(width), height: Int(height)))
    }

    callbacks.OnApplicationInstanceVisible = { (handle: UnsafeMutableRawPointer?, id: CInt) in
      let state = unsafeBitCast(handle, to: ApplicationHost.self)
      state.onApplicationInstanceVisible(id: Int(id))
    }

    callbacks.OnApplicationInstanceHidden = { (handle: UnsafeMutableRawPointer?, id: CInt) in
      let state = unsafeBitCast(handle, to: ApplicationHost.self)
      state.onApplicationInstanceHidden(id: Int(id))
    }
  
    return callbacks
  }

}