// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics
import MumbaShims

public class WebNavigator {

  public var serviceWorker: WebServiceWorkerContainer {
    return WebServiceWorkerContainer(reference: WebNavigatorGetServiceWorker(reference, window.reference), window: window)
  }
  
  var reference: WebNavigatorRef
  let window: WebWindow
  internal var callbacks: [FetchCallbackState] = []

  init(window: WebWindow, reference: WebNavigatorRef) {
    self.reference = reference
    self.window = window
  }
  
}