// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class DesktopFrameView : NonClientFrameView {

  public override var boundsForClientView: IntRect {
    return IntRect(x: 0, y: 0, width: width, height: height)
  }

  public override var className: String {
    return "DesktopFrameView"
  }

  public override var preferredSize: IntSize {
    get {
      let clientPreferredSize = frame.clientView!.preferredSize
      return frame.nonClientView!.getWindowBoundsForClientBounds(clientBounds: IntRect(size: clientPreferredSize)).size
    }
    set {
      frame.clientView!.preferredSize = newValue
    }
  }

  public override var minimumSize: IntSize {
    return frame.clientView!.minimumSize
  }

  public override var maximumSize: IntSize {
    return frame.clientView!.maximumSize
  }

  var frame: UIWidget

  public init(frame: UIWidget) {
    self.frame = frame
    super.init()
  }

  public override func getWindowBoundsForClientBounds(clientBounds: IntRect) -> IntRect {

   var windowBounds = clientBounds

   if windowBounds.isEmpty {
     windowBounds.size = IntSize(width: 1, height: 1)
   }

   return windowBounds
 }

  public override func nonClientHitTest(point: IntPoint) -> HitTest {
    return frame.clientView!.nonClientHitTest(point: point)
  }

  public func getWindowMask(size: IntSize, windowMask: inout Path) {

  }

  public override func resetWindowControls() {}
  public override func updateWindowIcon() {}
  public override func updateWindowTitle() {}
  public override func sizeConstraintsChanged() {}

}
