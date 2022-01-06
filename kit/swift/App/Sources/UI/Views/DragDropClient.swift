// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol DragDropClient {

  func startDragAndDrop(data: OSExchangeData,
                        rootWindow: Window,
                        sourceWindow: Window,
                        screenLocation: IntPoint,
                        operation: Int,
                        source: DragEventSource) -> DragOperation

  func dragUpdate(target: Window, event: LocatedEvent)

  func drop(target: Window, event: LocatedEvent)

  func dragCancel()

  func isDragDropInProgress() -> Bool

}
