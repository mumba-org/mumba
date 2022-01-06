// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import MumbaShims

public class UrlExecutor {

  var reference: Cronet_ExecutorPtr

  public init () {
    reference = Cronet_Executor_CreateWith(
      // Cronet_Executor_ExecuteFunc
      { (this: Cronet_ExecutorPtr?, runnablePtr: Cronet_RunnablePtr?) in
         print("UrlExecutor execute callback called.")
         let runnable = UrlRunnable(reference: runnablePtr!)
         runnable.run()
      }
    )
    let this = unsafeBitCast(Unmanaged.passUnretained(self).takeUnretainedValue(), to: UnsafeMutableRawPointer.self)
    Cronet_Executor_SetClientContext(reference, this)
  }

  deinit {
    Cronet_Executor_Destroy(reference)
  }

  public func execute(runnable: UrlRunnable) {
    Cronet_Executor_Execute(reference, runnable.reference)
  }

}