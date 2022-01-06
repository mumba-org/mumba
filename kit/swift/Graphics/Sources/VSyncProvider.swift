// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Foundation
import Base

public typealias UpdateVSyncCallback = (_: TimeTicks, _: TimeInterval) -> Void

public protocol VSyncProvider {
  func getVSyncParameters(callback: UpdateVSyncCallback)
}
