// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class DropHelper {

  private(set) public var targetView: View?
  private(set) public var rootView: View

  public init(rootView: View) {
    self.rootView = rootView
  }

  public func resetTargetViewIfEquals(view: View) {

  }

  public func onDragOver(data: OSExchangeData,
                         rootViewLocation: IntPoint,
                         dragOperation: DragOperation) -> DragOperation {
    return .DragNone
  }

  public func onDragExit() {

  }

  public func onDrop(data: OSExchangeData,
                     rootViewLocation: IntPoint,
                     dragOperation: DragOperation) -> DragOperation {
    return .DragNone
  }

  public func calculateTargetView(rootViewLocation: IntPoint,
                                  data: OSExchangeData,
                                  checkCanDrop: Bool) -> View? {
    return nil
  }

}
