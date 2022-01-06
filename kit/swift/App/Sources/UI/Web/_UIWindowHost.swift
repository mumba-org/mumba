// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This is meant to be a transitory middle ground connecting the remote managed
// widget on the host process and the local client widget on the application process

// TODO: We can create a "UIWindow" interface and a "ClientUIWindow" and a "HostUIWindow"
//       so it make it easy for us to reuse UIWindow independently if the application
//       process is running its own "unmanaged" widget or if its using a managed one
//       and communicating via IPC to the host process

// But for now its this alienated reality where we have both UIWindow and ClientUIWindow
// and they are not that much alike as we want

// Also: We will need to set a common ground between the native window features
//       and the ipc client window.. now the client window have a couple of features
//       out of scope for a widget, that will need to get scattered around more objects
//       like 'View's, DragnDrop, etc..
//              
//       So we will also need to set them apart as we will do to the UIWindow class later
//
//       The idea is that we dont have to mind if its local or remote, and can use both
//       without worrying about the actual implementation

import Base
import Graphics
import Compositor
import Application
import Text
import Web

public class UIWindowHost : UIDispatcherDelegate,
                            UIDispatcherSender,
                            UIWindowDelegate {

  
  private let dispatcher: UIDispatcher
  private var widget: UIWindow?
  private var closing = false
  private var autoResizeMode: Bool = false
  private var pageWasShown: Bool = false
  private var lastWindowScreenRect: IntRect?
  private var disableScrollbarsSizeLimit: IntSize = IntSize()
  private weak var application: UIApplication?
  

  // public func setNeedsLowLatencyInput(_ needsLowLatency: Bool) {
  //   //if let inputQueue = inputEventQueue {
  //   //  inputQueue.setNeedsLowLatency(needsLowLatency)
  //   //}
  // }

  //public func requestUnbufferedInputEvents() {
    //if let inputQueue = inputEventQueue {
    //  inputQueue.requestUnbufferedInputEvents()
    //}
  //}  

  
}
