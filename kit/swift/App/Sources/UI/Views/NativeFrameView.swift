// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class NativeFrameView : NonClientFrameView {
  
  public static let viewClassName = "NativeFrameView"

  public override var className: String {
    return NativeFrameView.viewClassName
  }

  public override var boundsForClientView: IntRect {
    return IntRect(x: 0, y: 0, width: self.width, height: self.height)
  }

  public override var minimumSize: IntSize {
    return frame!.clientView!.minimumSize
  }

  public override var maximumSize: IntSize {
    return frame!.clientView!.maximumSize
  }

  weak var frame: UIWidget?

  public init(frame: UIWidget) {
    self.frame = frame
    super.init()
  }

  public override func getWindowBoundsForClientBounds(clientBounds: IntRect) -> IntRect {
#if os(Windows)
  return UI.getWindowBoundsForClientBounds(self, clientBounds)
#else
  /// Enforce minimum size (1, 1) in case that clientBounds is passed with
  /// empty size.
  var windowBounds = clientBounds
  if windowBounds.isEmpty {
    windowBounds.size = IntSize(width: 1, height: 1)
  }
  return windowBounds
#endif
  }

  public override func nonClientHitTest(point: IntPoint) -> HitTest {
    return frame!.clientView!.nonClientHitTest(point: point)
  }

  public override func getWindowMask(size: IntSize) -> Path? {
    // TODO: It can be confusing if the caller defines a default Path..
    //       if this returns null, the caller should use a default as mask instead
    //       as this might make the code correctly understand that this is a 'fail'
    return nil
  }

  public override func resetWindowControls() {}
  public override func updateWindowIcon() {}
  public override func updateWindowTitle() {}
  public override func sizeConstraintsChanged() {}

  open override func calculatePreferredSize() -> IntSize {
    let clientPreferredSize = frame!.clientView!.preferredSize
#if os(Windows)
    return clientPreferredSize
#else
    return frame!.nonClientView!.getWindowBoundsForClientBounds(clientBounds: IntRect(size: clientPreferredSize)).size
#endif
  }

}