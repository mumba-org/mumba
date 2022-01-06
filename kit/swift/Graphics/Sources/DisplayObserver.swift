// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol DisplayObserver {
  func onWillProcessDisplayChanges()
  func onDidProcessDisplayChanges()
  func onDisplayAdded(newDisplay: Display)
  func onDisplayRemoved(oldDisplay: Display)
  func onDisplayMetricsChanged(display: Display,
                               changedMetrics: UInt32)

}

extension DisplayObserver {
  public func onWillProcessDisplayChanges() {}
  public func onDidProcessDisplayChanges() {}
  public func onDisplayAdded(newDisplay: Display) {}
  public func onDisplayRemoved(oldDisplay: Display) {}
  public func onDisplayMetricsChanged(display: Display,
                               changedMetrics: UInt32) {}
}