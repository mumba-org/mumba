// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims

public class UrlRunnable {

  var reference: Cronet_RunnablePtr
  private var owned: Bool

  public init() {
    owned = true
    reference = Cronet_Runnable_CreateWith({ (ptr: Cronet_RunnablePtr?) in
      print("UrlRunnable run callback called. nothing here")
      //let context = Cronet_Runnable_GetClientContext(ptr)
      //Cronet_BufferPtr buffer = static_cast<Cronet_BufferPtr>(context)
      //Cronet_Buffer_Destroy(buffer);
    })
    let statePtr = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    Cronet_Runnable_SetClientContext(reference, statePtr)
  }

  init(reference: Cronet_RunnablePtr) {
    owned = false
    self.reference = reference
  }

  deinit {
    if owned {
      Cronet_Runnable_Destroy(reference)
    }
  }

  public func run() {
    Cronet_Runnable_Run(reference)
  }

}