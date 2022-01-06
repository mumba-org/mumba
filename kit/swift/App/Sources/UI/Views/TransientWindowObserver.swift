// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol TransientWindowObserver {

  func onTransientChildAdded(window: Window, transient: Window)
  func onTransientChildRemoved(window: Window, transient: Window)
  
}
