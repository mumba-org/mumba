// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import Foundation
import MumbaShims

public protocol ApplicationDelegate: class {
  
  var application: Application? { get }

  func onInit() throws
  func onRun() throws
  func onMessage(message: EventMessage)
  func onExit()

}

open class Application {
  
  public var url: URL? // twitter/app
  
  //public var channelId: String

  //public var channel: IPCChannelRef?

  public weak var delegate: ApplicationDelegate?

  fileprivate var initialized: Bool

  fileprivate var connected: Bool

  public init(delegate: ApplicationDelegate?) {
    //let argPrefix = "--channel-id="
    //channelId = String() 
    self.delegate = delegate
    url = URL(string: "")
    initialized = false
    connected = false
    
    _RuntimeInit()
    
    //for arg in CommandLine.arguments {
    //  if arg.hasPrefix(argPrefix) {
    //    channelId.append(contentsOf: arg.characters[argPrefix.characters.endIndex ..< arg.characters.endIndex])
    //  }
    //}
    _SandboxEnter()

    try! TaskScheduler.createAndStartWithDefaultParams()
  }

  open func initialize() throws {
    // if !channelId.isEmpty {
    //   channel = _IPCChannelConnect(channelId)
    //   guard channel != nil else {
    //     throw ApplicationError.OnIPCConnection(exception: ApplicationException.IPCConnectionFailed)
    //   }


    //   let selfptr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    //   _IPCChannelSetCaller(channel, selfptr)
      
    //   let shutdown_cb: CIPCShutdownCallback = { (reference: UnsafeMutableRawPointer?) in
    //     guard reference != nil else {
    //       return
    //     }
    //     let app = unsafeBitCast(reference, to: Application.self)
    //     app.processShutdown()
    //   }

    //   _IPCChannelSetShutdownHandler(channel, shutdown_cb)

    //   connected = true
    // } 

    if let impl = delegate {
     try impl.onInit() 
    }
    
    initialized = true
  }
  
  public func run() throws {
    if let impl = delegate {
     try impl.onRun()
     impl.onExit()
    }
    //if let ch = channel {
    //  _IPCChannelCleanup(ch)
   // }
    TaskScheduler.instance!.shutdown()
    _RuntimeShutdown()
  }

  /// process incoming messages from the IPC Channel
  func processShutdown() {
   if let impl = delegate {
     impl.onMessage(message: EventMessage.Shutdown(.Now))
   }
  }

}
