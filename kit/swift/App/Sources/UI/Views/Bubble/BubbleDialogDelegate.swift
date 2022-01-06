// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

fileprivate func createBubbleWidget(compositor: UIWebWindowCompositor, bubble: BubbleDialogDelegateView) -> UIWidget {
  let bubbleWidget = UIWidget()
  var bubbleParams = UIWidget.InitParams()
 
  bubbleParams.type = WindowType.Normal
  bubbleParams.layerType = .PictureLayer//.Textured
  //bubbleParams.opacity = UIWidget.WindowOpacity.Translucent
  bubbleParams.opacity = UIWidget.WindowOpacity.Opaque
  
  //bubbleParams.type = WindowType.Bubble
  //bubbleParams.opacity = UIWidget.WindowOpacity.Translucent
  bubbleParams.delegate = bubble
  bubbleParams.bounds = IntRect(width: 400, height: 400)
  bubbleParams.acceptEvents = bubble.acceptEvents
  // Use a window default shadow if the bubble doesn't provides its own.
  bubbleParams.shadowType = bubble.shadow == BubbleBorder.Shadow.NoAssets
                                  ? UIWidget.ShadowType.Default
                                  : UIWidget.ShadowType.None
  if bubble.parentWindow != nil {
    bubbleParams.parent = bubble.parentWindow
  } else if bubble.anchorWidget != nil {
    bubbleParams.parent = bubble.anchorWidget!.window//bubble.anchorWidget.nativeView
  }
  bubbleParams.activatable = UIWidget.Activatable.Yes//bubble.canActivate
                              //? UIWidget.Activatable.Yes
                              //: UIWidget.Activatable.No
  bubble.onBeforeBubbleWidgetInit(params: bubbleParams, widget: bubbleWidget)
  try! bubbleWidget.initialize(compositor: compositor, params: bubbleParams)
#if !os(macOS)
  // On Mac, having a parent window creates a permanent stacking order, so
  // there's no need to do this. Also, calling StackAbove() on Mac shows the
  // bubble implicitly, for which the bubble is currently not ready.
  if let parent = bubbleParams.parent  {
    bubbleWidget.stackAbove(window: parent)
  }
#endif
  return bubbleWidget
}

open class BubbleDialogDelegateView : DialogDelegateView,
                                      UIWidgetObserver {

   public static let ViewClassName = "BubbleDialogDelegateView"

   public enum CloseReason {
     case Deactivation
     case CloseButton
     case Unknown
   }

   public var shouldShowCloseButton: Bool { 
     return false
   }

   open override var className: String {
    return BubbleDialogDelegateView.ViewClassName
   }

   public var anchorView: View? {
     get {
       return anchorViewTracker.view
     }
     set (view) {
       if view == nil || anchorWidget !== view!.widget {
        if let widget = anchorWidget {
          widget.removeObserver(self)
          anchorWidget = nil
        }
        if let v = view {
          if let anchorWidget = v.widget {
            anchorWidget.addObserver(self)
          }
        }
      }

      anchorViewTracker.view = view

      if anchorView != nil && widget != nil {
        onAnchorBoundsChanged()
      }
     }
   }

   public var alignment: BubbleBorder.BubbleAlignment {
     get { 
       return bubbleFrameView!.bubbleBorder!.alignment
     }
     set {
       bubbleFrameView!.bubbleBorder!.alignment = newValue
       sizeToContents()
     }
   }

   public var arrowPaintType: BubbleBorder.ArrowPaintType {
     get { 
       return bubbleFrameView!.bubbleBorder!.paintArrow
     }
     set {
      bubbleFrameView!.bubbleBorder!.paintArrow = newValue
      sizeToContents()
     }
   }

   public var borderInteriorThickness: Int {
     get {
       return bubbleFrameView!.bubbleBorder!.borderInteriorThickness
     }
     set {
       bubbleFrameView!.bubbleBorder!.borderInteriorThickness = newValue
       sizeToContents()
     }
   }

   public var bubbleFrameView: BubbleFrameView? {
      let view: NonClientView? = widget?.nonClientView ?? nil
      return view?.frameView as? BubbleFrameView ?? nil
   }

   public var bubbleBounds: IntRect {
      let anchorMinimized: Bool = anchorWidget?.isMinimized ?? false
      // If GetAnchorView() returns nullptr or GetAnchorRect() returns an empty rect
      // at (0, 0), don't try and adjust arrow if off-screen.
      let anchorRect = getAnchorRect()
      let hasAnchor = anchorView != nil || anchorRect != IntRect()
      return bubbleFrameView!.getUpdatedWindowBounds(
          anchorRect: anchorRect, 
          clientSize: widget!.clientView!.preferredSize,
          adjustIfOffscreen: adjustIfOffscreen && !anchorMinimized && hasAnchor)
   }

   public private(set) var anchorRect: IntRect {
     didSet {
       if widget != nil {
        onAnchorBoundsChanged()
       }
     }
   }

   // public var accessibleWindowRole: Role {}

   public var closeOnDeactivate: Bool
   public var arrow: BubbleBorder.Arrow
   public var mirrorArrowInRtl: Bool
   public var shadow: BubbleBorder.Shadow
   public var color: Color
   public var titleMargins: IntInsets
   public var anchorViewInsets: IntInsets
   public var parentWindow: Window?
   public var acceptEvents: Bool
   public var adjustIfOffscreen: Bool
   public private(set) var anchorWidget: UIWidget?
   private let anchorViewTracker: ViewTracker
   private var colorExplicitlySet: Bool

#if os(macOS)
  private let macBubbleCloser: BubbleCloser = BubbleCloser()
#endif

   public static func createBubble(delegate: BubbleDialogDelegateView, compositor: UIWebWindowCompositor) -> UIWidget {
      //delegate.initialize()
      // Get the latest anchor widget from the anchor view at bubble creation time.
      let anchorView = delegate.anchorView
      delegate.anchorView = anchorView
      let widget = createBubbleWidget(compositor: compositor, bubble: delegate)

#if os(Windows)
      // If glass is enabled, the bubble is allowed to extend outside the bounds of
      // the parent frame and let DWM handle compositing.  If not, then we don't
      // want to allow the bubble to extend the frame because it will be clipped.
      delegate.adjustIfOffscreen = UI.Win.isAeroGlassEnabled
#elseif os(Linux) || os(macOS)
      // Linux clips bubble windows that extend outside their parent window bounds.
      // Mac never adjusts.
      delegate.adjustIfOffscreen = false
#endif

      delegate.sizeToContents()
      widget.addObserver(delegate)
      return widget
   }

   public override convenience init() {
     self.init(anchorView: nil, arrow: BubbleBorder.Arrow.TopLeft)
   }

   public init(anchorView: View?, arrow: BubbleBorder.Arrow, shadow: BubbleBorder.Shadow = .DialogShadow) {
      self.closeOnDeactivate = true
      self.anchorViewTracker = ViewTracker()
      self.anchorRect = IntRect()
      self.color = Color()
      self.titleMargins = IntInsets()
      self.anchorViewInsets = IntInsets()
      self.arrow = arrow
      self.shadow = shadow
      self.colorExplicitlySet = false
      self.acceptEvents = true
      self.adjustIfOffscreen = true
      mirrorArrowInRtl = ViewsDelegate.instance.shouldMirrorArrowsInRTL
      super.init()
      
      let provider: LayoutProvider = LayoutProvider.instance()
      // An individual bubble should override these margins if its layout differs
      // from the typical title/text/buttons.
      self.margins = provider.getDialogInsetsForContentType(
        leading: DialogContentType.Text, 
        trailing: DialogContentType.Text)
      self.titleMargins = provider.getInsetsMetric(InsetsMetric.DialogTitle)
      if anchorView != nil {
        self.anchorView = anchorView
      }
      updateColorsFromTheme(theme: self.theme)
   }

   deinit {
      if let w = widget {
        w.removeObserver(self)
      }
      layoutManager = nil
      anchorView = nil
   }

   public func asDialogDelegate() -> DialogDelegate? { 
      return self
   }

   public func createClientView(widget: UIWidget) -> ClientView? {
     let client = DialogClientView(owner: widget, contentsView: contentsView!)
     widget.nonClientView!.mirrorClientInRtl = self.mirrorArrowInRtl
     return client
   }
  
   public func createNonClientFrameView(widget: UIWidget) -> NonClientFrameView? {
      let frame = BubbleFrameView(titleMargins: self.titleMargins, contentMargins: IntInsets())
      frame.footnoteMargins = LayoutProvider.instance().getInsetsMetric(InsetsMetric.DialogSubsection)
      frame.setFootnoteView(createFootnoteView())

      var adjustedArrow = self.arrow
      if i18n.isRTL() && mirrorArrowInRtl {
        adjustedArrow = BubbleBorder.horizontalMirror(adjustedArrow)
      }
      frame.bubbleBorder = BubbleBorder(arrow: adjustedArrow, shadow: self.shadow, color: self.color)
      return frame
   }

   public func onWidgetDestroying(widget: UIWidget) {
     if anchorWidget === widget {
       anchorView = nil
     }
   }
   
   public func onWidgetVisibilityChanging(widget: UIWidget, visible: Bool) {
#if os(Windows)
    // On Windows we need to handle this before the bubble is visible or hidden.
    // Please see the comment on the OnWidgetVisibilityChanging function. On
    // other platforms it is fine to handle it after the bubble is shown/hidden.
    handleVisibilityChanged(widget, visible)
#endif
   }
   
   public func onWidgetVisibilityChanged(widget: UIWidget, visible: Bool) {
#if !os(Windows)
    handleVisibilityChanged(widget: widget, visible: visible)
#endif
   }
   
   public func onWidgetActivationChanged(widget: UIWidget, active: Bool) {
#if os(macOS)
      // Install |mac_bubble_closer_| the first time the widget becomes active.
      if let w = UIWidget, active && macBubbleCloser == nil {
        macBubbleCloser = BubbleCloser(
            w.window,
            { self.onDeactivate() })
      }
#endif
      if widget === self.widget && !active {
        onDeactivate()
      }
   }
   
   public func onWidgetBoundsChanged(widget: UIWidget, newBounds: IntRect) {
      if bubbleFrameView != nil && self.anchorWidget === widget {
        sizeToContents()
      }
   }

   public func getAnchorRect() -> IntRect {
      guard let anchor = anchorView else {
        return anchorRect
      }

      anchorRect = anchor.boundsInScreen
      anchorRect.inset(insets: anchorViewInsets)
      return anchorRect
   }

   public func onBeforeBubbleWidgetInit(params: UIWidget.InitParams, widget: UIWidget) {}

   public func useCompactMargins() {
     let compactMargin = 6
     self.margins = IntInsets(all: compactMargin)
   }

   public func onAnchorBoundsChanged() {
     sizeToContents()
   }

   open override func onThemeChanged(theme: Theme) {
     updateColorsFromTheme(theme: theme)
   }

   //public func initialize() {}

   internal func sizeToContents() {
     if let w = widget {
       w.bounds = bubbleBounds
     }
   }

   private func updateColorsFromTheme(theme: Theme) {
      if !colorExplicitlySet {
        color = theme.getSystemColor(id: Theme.ColorId.BubbleBackground)
      }
      
      if let frameView = bubbleFrameView {
        frameView.bubbleBorder!.backgroundColor = self.color
      }
      // When there's an opaque layer, the bubble border background won't show
      // through, so explicitly paint a background color.
      if layer != nil && layer!.fillsBoundsOpaquely {
        background = BackgroundFactory.makeSolidBackground(color: self.color)
      } else {
        background = nil  
      }
   }

   private func handleVisibilityChanged(widget: UIWidget, visible: Bool) {
     if let topLevelWidget = anchorWidget?.topLevelWidget, widget === self.widget {
       topLevelWidget.isAlwaysRenderAsActive = visible
     }

     //if widget === self.widget && isVisible {
     // if accessibleWindowRole == AX.Role.Alert ||
     //    accessibleWindowRole == AX.Role.AlertDialog {
     //   widget.rootView.notifyAccessibilityEvent(AX.Event.Alert, true)
     // }
     //}
   }

   private func onDeactivate() {
     if let w = widget, closeOnDeactivate {
       w.close()
     }
   }

}