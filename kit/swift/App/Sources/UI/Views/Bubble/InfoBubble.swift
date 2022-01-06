// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

fileprivate let bubbleBorderVisibleWidth = 1

class InfoBubbleFrame : BubbleFrameView {

  // Bounds that this frame should try to keep bubbles within (screen coords).  
  var availableBounds: IntRect = IntRect()

  init(contentMargins: IntInsets) {
    super.init(titleMargins: IntInsets(), contentMargins: contentMargins) 
  }

  internal override func getAvailableScreenBounds(rect: IntRect) -> IntRect {
    return availableBounds
  }

}

public class InfoBubble : BubbleDialogDelegateView {
  
  public var dialogButtons: Int {
    return DialogButton.None.rawValue
  }

  public private(set) var anchor: View?

  internal var frame: InfoBubbleFrame?

  public var preferredWidth: Int

  private var _widget: UIWidget?
  private let compositor: UIWebWindowCompositor

  public init(anchor: View?, compositor: UIWebWindowCompositor, message: String) {
    self.compositor = compositor
    self.anchor = anchor 
    preferredWidth = 0
    super.init(anchorView: nil, arrow: BubbleBorder.Arrow.TopLeft)
    self.margins = LayoutProvider.instance().getInsetsMetric(InsetsMetric.TooltipBubble)
    self.anchorView = anchor
 
    canActivate = false

    self.layoutManager = FillLayout()
    
    let label = Label(text: message)
    label.horizontalAlignment = .AlignLeft
    label.multiline = true
    addChild(view: label)
  }

  public func hide() {
    if let w = widget, !w.isClosed {
      w.close()
    }
  }

  public func show() {
    _widget = BubbleDialogDelegateView.createBubble(delegate: self, compositor: compositor)
    updatePosition()
  }

  public override func createNonClientFrameView(widget: UIWidget) -> NonClientFrameView? {
    self.frame = InfoBubbleFrame(contentMargins: margins)
    self.frame!.availableBounds = anchorWidget!.windowBoundsInScreen
    self.frame!.bubbleBorder = BubbleBorder(arrow: self.arrow, shadow: self.shadow, color: self.color)
    return self.frame
  }

  open override func calculatePreferredSize() -> IntSize {
    if preferredWidth == 0 {
      return super.calculatePreferredSize()
    }

    var prefWidth = preferredWidth
    prefWidth -= frame!.insets.width
    prefWidth -= 2 * bubbleBorderVisibleWidth
    return IntSize(width: prefWidth, height: getHeightFor(width: prefWidth))
  }

  public func onWidgetDestroyed(widget: UIWidget) {
    if widget === _widget {
      _widget = nil
    }
  }

  public override func onWidgetBoundsChanged(widget: UIWidget, newBounds: IntRect) {
    super.onWidgetBoundsChanged(widget: widget, newBounds: newBounds)
    if anchorWidget === widget {
      self.frame!.availableBounds = widget.windowBoundsInScreen
    }
  }

  private func updatePosition() {
    guard let w = _widget else {
      return
    }
    // if let view = anchor, !view.visibleBounds.isEmpty {
    //   sizeToContents()
    //   w.setVisibilityChangedAnimationsEnabled(value: true)
    //   w.showInactive()
    // } else {
    //   w.setVisibilityChangedAnimationsEnabled(value: false)
    //   w.hide()
    // }
    sizeToContents()
    w.setVisibilityChangedAnimationsEnabled(value: true)
    w.show()
  }

}