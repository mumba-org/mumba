// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

public protocol UICompositorVSyncManagerObserver {

}

public class UICompositorVSyncManager {

  public init() {
    
  }

  public func setAuthoritativeVSyncInterval(interval: TimeDelta) {

  }

  public func updateVSyncParameters(timebase: TimeTicks, interval: TimeDelta) {

  }

  public func addObserver(observer: UICompositorVSyncManagerObserver) {

  }

  public func removeObserver(observer: UICompositorVSyncManagerObserver) {

  }
}
