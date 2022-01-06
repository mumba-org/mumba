// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class ClientView : View {

 // public override var preferredSize: IntSize {
 //   if let view = contentsView {
 //     return view.preferredSize
 //   }
 //   return IntSize()
 // }

  public override var minimumSize: IntSize {
    if let view = contentsView {
      return view.minimumSize
    }
    return IntSize()
  }

  public override var maximumSize: IntSize {
    if let view = contentsView {
      return view.maximumSize
    }
    return IntSize()
  }

  public override var className: String { return "ClientView" }

  public var canClose: Bool {
    return true
  }

  var contentsView: View?

  public init(owner: UIWidget, contentsView: View?) {
    self.contentsView = contentsView
  }

  public func windowClosing() {}

  public func asDialogClientView() -> DialogClientView? {
    return nil
  }

  public func nonClientHitTest(point: IntPoint) -> HitTest {
    return bounds.contains(point: point) ? .HTCLIENT : .HTNOWHERE
  }

  public override func layout() {
    if let view = contentsView {
      view.bounds = IntRect(x: 0, y: 0, width: width, height: height)
    }
  }

  public override func getAccessibleState(state: inout AXViewState) {

  }

  public override func onBoundsChanged(previousBounds: IntRect) {}

  open override func calculatePreferredSize() -> IntSize {
    if let view = contentsView {
      return view.preferredSize
    }
    return IntSize()  
  }

  public override func viewHierarchyChanged(details: ViewHierarchyChangedDetails) {
    if details.isAdd && details.child === self {
      assert(widget != nil)
      assert(contentsView != nil) // |contents_view_| must be valid now!
      // Insert |contents_view_| at index 0 so it is first in the focus chain.
      // (the OK/Cancel buttons are inserted before contents_view_)
      addChildAt(view: contentsView!, index: 0)
    }
  }

}
