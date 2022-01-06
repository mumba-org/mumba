// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol DragController {

  func writeDragDataForView(sender: View,
                            pressPoint: IntPoint,
                            data: OSExchangeData)

  func getDragOperationsForView(sender: View,
                                point: IntPoint) -> DragOperation

  func canStartDragForView(sender: View,
                           pressPoint: IntPoint,
                           point: IntPoint) -> Bool

}
