// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Base

open class BubbleDelegateView : WidgetDelegateView {

  public enum CloseReason {
    case Deactivation
    case Escape
    case CloseButton
    case Unknown
  }

  open override var shouldShowCloseButton: Bool {
    return false
  }

  open override var contentsView: View? {
    return self
  }

  open override var className: String {
    return "BubbleDelegateView"
  }

  open var closeOnEsc: Bool

  open var closeOnDeactivate: Bool

  open var anchorView: View? {
    get {
      return ViewStorage.instance.retrieveView(storageId: anchorViewStorageId)
    }
    set {
      if anchorView  == nil || anchorWidget !== anchorView!.widget {
        if let widget = anchorWidget {
          widget.removeObserver(observer: self)
          anchorWidget = nil
        }
        if let view = anchorView, let widget = view.widget {
          widget.addObserver(observer: self)
        }
      }

      // Remove the old storage item and set the new (if there is one).
      let viewStorage = ViewStorage.instance
      if viewStorage.retrieveView(storageId: anchorViewStorageId) != nil {
        viewStorage.removeView(storageId: anchorViewStorageId)
      }
      if let view = anchorView {
        viewStorage.storeView(storageId: anchorViewStorageId, view: view)
      }

      // Do not update anchoring for NULL views; this could indicate that our
      // NativeWindow is being destroyed, so it would be dangerous for us to update
      // our anchor bounds at that point. (It's safe to skip this, since if we were
      // to update the bounds when |anchor_view| is NULL, the bubble won't move.)
      if anchorView != nil && widget != nil {
        onAnchorBoundsChanged()
      }
    }
  }

  private(set) open var anchorWidget: UIWidget?

  open var arrow: BubbleBorder.Arrow

  open var shadow: BubbleBorder.Shadow

  open var color: Color {
    didSet {
     colorExplicitlySet = true
    }
  }

  open var margins: IntInsets

  open var anchorViewInsets: IntInsets

  open var anchorRect: IntRect {
    get {
      guard let view = anchorView else {
        return _anchorRect
      }
      _anchorRect = view.boundsInScreen
      _anchorRect.inset(insets: anchorViewInsets)
      return _anchorRect
    }
    set {
      _anchorRect = newValue
      if widget != nil {
        onAnchorBoundsChanged()
      }
    }
  }

  open var parentWindow: Window?

  open var acceptEvents: Bool

  open var borderAcceptsEvents: Bool

  open var adjustIfOffscreen: Bool

  open var bubbleFrameView: BubbleFrameView? {
    if let view = widget?.nonClientView {
      return view.frameView as? BubbleFrameView
    }
    return nil
  }

  open var closeReason: CloseReason

  private var bubbleBounds: IntRect {
    let anchorMinimized = anchorWidget != nil && anchorWidget!.minimized

    if let frameView = bubbleFrameView {
      return frameView.getUpdatedWindowBounds(anchorRect: anchorRect,
        clientSize: preferredSize,
        adjustIfOffscreen: adjustIfOffscreen && !anchorMinimized)
    }

    return IntRect(origin: IntPoint(x: 0, y : 0), size: IntSize(width: 900, height: 600))
  }

  private var titleFontList: FontList {
    //ui::ResourceBundle rb = ui::ResourceBundle::GetSharedInstance()
    //return rb.GetFontList(ui::ResourceBundle::MediumFont)
    return FontList()
  }

  private var colorExplicitlySet: Bool

  private var anchorViewStorageId: Int

  private var _anchorRect: IntRect

  private let defaultMargin: Int = 6

  public static func createBubble(bubbleDelegate: BubbleDelegateView, bounds: IntRect) throws -> UIWidget? {
    bubbleDelegate.onInit()
    // Get the latest anchor widget from the anchor view at bubble creation time.
    let view = bubbleDelegate.anchorView
    bubbleDelegate.anchorView = view
    let bubbleWidget = try createBubbleWindow(bubble: bubbleDelegate, bounds: bounds)
    bubbleDelegate.adjustIfOffscreen = false
    bubbleDelegate.sizeToContents()
    bubbleWidget.addObserver(observer: bubbleDelegate)
    return bubbleWidget
  }

  public override convenience init() {
    self.init(anchor: nil, arrow: BubbleBorder.Arrow.TopLeft)
  }

  public init(anchor: View?, arrow: BubbleBorder.Arrow) {
    closeOnEsc = true
    closeOnDeactivate = true
    anchorViewStorageId = ViewStorage.instance.createStorageID()
    self.arrow = arrow
    shadow = BubbleBorder.Shadow.SmallShadow
    colorExplicitlySet = false
    margins = IntInsets(top: defaultMargin, left: defaultMargin, bottom: defaultMargin, right: defaultMargin)
    acceptEvents = true
    borderAcceptsEvents = true
    adjustIfOffscreen = true
    anchorViewInsets = IntInsets()
    closeReason = CloseReason.Unknown
    _anchorRect = IntRect()
    color = Color()
    super.init()

    if let view = anchor {
      anchorView = view
    }

    addAccelerator(accelerator: Accelerator(keycode: KeyboardCode.KeyEscape, modifiers: EventFlags.None.rawValue))
  }

  deinit {
    if let w = widget {
      w.removeObserver(observer: self)
    }
    layoutManager = nil
    anchorView = nil
  }

  open override func asBubbleDelegate() -> BubbleDelegateView? {
    return self
  }

  open override func createNonClientFrameView(widget: UIWidget) -> NonClientFrameView? {
    let frame = BubbleFrameView(contentMargins: self.margins)
    // Note: In createBubble, the call to sizeToContents() will cause
    // the relayout that this call requires.
    frame.setTitleFontList(fontList: titleFontList)
    var adjustedArrow = arrow
    if i18n.isRTL() {
      adjustedArrow = BubbleBorder.horizontalMirror(a: adjustedArrow)
    }
    frame.bubbleBorder = BubbleBorder(arrow: adjustedArrow, shadow: self.shadow, color: self.color)
    return frame
  }

  open override func acceleratorPressed(accelerator: Accelerator) -> Bool {
    if !closeOnEsc || accelerator.keycode != KeyboardCode.KeyEscape {
      return false
    }
    closeReason = CloseReason.Escape
    widget!.close()
    return true
  }

  open func onBeforeBubbleWindowInit(params: UIWidget.InitParams,
                                     widget: UIWidget) {}

  open func setAlignment(alignment: BubbleBorder.BubbleAlignment) {
    if let frameView = bubbleFrameView {
      frameView.bubbleBorder!.alignment = alignment
    }
    sizeToContents()
  }

  open func setArrowPaintType(paintType: BubbleBorder.ArrowPaintType) {
    if let frameView = bubbleFrameView {
      frameView.bubbleBorder!.paintArrow = paintType
    }
    sizeToContents()
  }

  open func onAnchorBoundsChanged() {
    sizeToContents()
  }

  open func onInit() {}

  open func sizeToContents() {
    if let w = widget {
      w.bounds = bubbleBounds
    }
  }

  // WidgetObserver

  open func onWidgetClosing(widget: UIWidget) {
    if widget === self.widget && closeReason == CloseReason.Unknown &&
       bubbleFrameView!.closeButtonClicked {
      closeReason = CloseReason.CloseButton
    }
  }

  open func onWidgetDestroying(widget: UIWidget) {
    if anchorWidget === widget {
      anchorView = nil
    }
  }

  open func onWidgetVisibilityChanging(widget: UIWidget, visible: Bool) {
    handleVisibilityChanged(widget: widget, visible: visible)
  }

  open func onWidgetActivationChanged(widget: UIWidget, active: Bool) {
    if closeOnDeactivate && widget === self.widget && !active {
      if closeReason == CloseReason.Unknown {
        closeReason = CloseReason.Deactivation
      }
      self.widget!.close()
    }
  }

  open func onWidgetBoundsChanged(widget: UIWidget, newBounds: IntRect) {
    if bubbleFrameView != nil && anchorWidget === widget {
      sizeToContents()
    }
  }

  func handleVisibilityChanged(widget: UIWidget, visible: Bool) {
    if let topWindow = anchorWidget?.topLevelWidget {
      if widget === self.widget {
        if visible {
          topWindow.disableInactiveRendering()
        } else {
          topWindow.enableInactiveRendering()
        }
      }
    }

  // Fire AX_EVENT_ALERT for bubbles marked as AX_ROLE_ALERT_DIALOG; this
  // instructs accessibility tools to read the bubble in its entirety rather
  // than just its title and initially focused view.  See
  // http://crbug.com/474622 for details.
  //if (widget == GetWidget() && visible) {
  //  ui::AXViewState state;
  //  GetAccessibleState(&state);
  //  if (state.role == ui::AX_ROLE_ALERT_DIALOG)
  //    NotifyAccessibilityEvent(ui::AX_EVENT_ALERT, true);
  //}
  }

}

func createBubbleWindow(bubble: BubbleDelegateView, bounds: IntRect) throws -> UIWidget {
  let bubbleWidget = UIWidget()
  var bubbleParams = UIWidget.InitParams()

  bubbleParams.type = .Bubble
  // TODO: mudar assim que corrigirmos para o tipo Bubble
  //bubbleParams.type = .Frameless
  bubbleParams.delegate = bubble
  bubbleParams.bounds = bounds
  //bubbleParams.opacity = UIWidget.WindowOpacity.Translucent
  bubbleParams.opacity = UIWidget.WindowOpacity.Opaque
  bubbleParams.acceptEvents = bubble.acceptEvents
  bubbleParams.layerType = .Textured
  if bubble.parentWindow != nil {
    bubbleParams.parent = bubble.parentWindow
  } else if bubble.anchorWidget != nil {
    bubbleParams.parent = bubble.anchorWidget!.window
  }
  bubbleParams.activatable = bubble.canActivate ?
      UIWidget.Activatable.Yes : UIWidget.Activatable.No
  //bubble.onBeforeBubbleWindowInit(params: bubbleParams, widget: bubbleWidget)
  ////print("createBubbleWindow: bubbleWidget.initialize()")
  //try bubbleWidget.initialize(params: bubbleParams)
  if let parent = bubbleParams.parent {
    bubbleWidget.stackAbove(window: parent)
  }
  return bubbleWidget
}