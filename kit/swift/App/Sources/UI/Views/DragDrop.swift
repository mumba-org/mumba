// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol DragDropDelegate {
  func onDragEntered(event: DropTargetEvent)
  func onDragUpdated(event: DropTargetEvent) -> DragOperation
  func onDragExited()
  func onPerformDrop(event: DropTargetEvent) -> DragOperation
}

public struct DragEventSourceInfo {
  public var eventLocation: IntPoint
  public var eventSource: DragEventSource

  public init () {
    eventLocation = IntPoint()
    eventSource = .None
  }
}