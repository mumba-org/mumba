// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

fileprivate let IDS_APP_OK: Int = 1
fileprivate let IDS_APP_ANCEL: Int = 1
fileprivate let IDS_APP_LOSE: Int = 1

public protocol DialogDelegate : DialogModel,
                                 UIWidgetDelegate {

   var extraViewPadding: Int? { get }
   var shouldSnapFrameWidth: Bool { get }
   var shouldUseCustomFrame: Bool { get }
   var margins: IntInsets { get set }
   var dialogClientView: DialogClientView? { get }
   func createExtraView() -> View?
   func createFootnoteView() -> View?
   func cancel() -> Bool
   func accept() -> Bool
   func close() -> Bool
   func updateButton(button: LabelButton, type: DialogButton)
   func dialogModelChanged()
   func addObserver(_ observer: DialogObserver)
   func removeObserver(_ observer: DialogObserver)
}

extension DialogDelegate {
  
  public static func createDialogWidget(delegate: UIWidgetDelegate,
                                        compositor: UIWebWindowCompositor,
                                        context: Window?,
                                        parent: Window?) -> UIWidget {
    let widget = UIWidget()
    let params = Self.getDialogWidgetInitParams(
      delegate: delegate, 
      context: context, 
      parent: parent,
      bounds: IntRect())
    try! widget.initialize(compositor: compositor, params: params)
    return widget
  }

  public static func getDialogWidgetInitParams(delegate: UIWidgetDelegate,
                                               context: Window?,
                                               parent: Window?,
                                               bounds: IntRect) -> UIWidget.InitParams {
    var shouldUseCustomFrame = false
    var params = UIWidget.InitParams()
    params.delegate = delegate
    params.bounds = bounds
    if let dialog = delegate.asDialogDelegate() {
      shouldUseCustomFrame = dialog.shouldUseCustomFrame
//#if os(Linux)
//      dialog.supportsCustomFrame = dialog.supportsCustomFrame && (parent != nil)
//#elseif os(Windows)
//      if UI.Windows.isAeroGlassEnabled {
//        dialog.supportsCustomFrame = dialog.supportsCustomFrame && (parent != nil)
//      }
//#endif
    }

    if delegate.asDialogDelegate() == nil || shouldUseCustomFrame {
      params.opacity = UIWidget.WindowOpacity.Translucent
      params.removeStandardFrame = true
#if !os(macOS)
      // Except on Mac, the bubble frame includes its own shadow; remove any
      // native shadowing. On Mac, the window server provides the shadow.
      params.shadowType = UIWidget.ShadowType.None
#endif
    }

    params.context = context
    params.parent = parent
#if !os(macOS)
    // Web-modal (ui::MODAL_TYPE_HILD) dialogs with parents are marked as child
    // widgets to prevent top-level window behavior (independent movement, etc).
    // On Mac, however, the parent may be a native window (not a views::UIWidget),
    // and so the dialog must be considered top-level to gain focus and input
    // method behaviors.
    params.child = parent != nil && (delegate.modalType == ModalType.Child)
#endif
    return params
  }

  public static func createDialogFrameView(widget: UIWidget) -> NonClientFrameView {
    
    let frame = BubbleFrameView(
      titleMargins: LayoutProvider.instance().getInsetsMetric(InsetsMetric.DialogTitle),
      contentMargins: IntInsets())

    let shadow = BubbleBorder.Shadow.DialogShadow
    let border = BubbleBorder(arrow: BubbleBorder.Arrow.Float, shadow: shadow, color: Graphics.placeholderColor)
    border.useThemeBackgroundColor = true
    frame.bubbleBorder = border
    if let delegate = widget.widgetDelegate?.asDialogDelegate() {
      frame.setFootnoteView(delegate.createFootnoteView())
    }
    return frame
  }

  public var shouldUseCustomFrame: Bool {
    return true
  }

  public var extraViewPadding: Int? {
    return nil
  }
  
  //public var margins: IntInsets { get set }


  // DialogModel default impl
  public var dialogButtons: Int {
    return DialogButton.Ok.rawValue | DialogButton.Cancel.rawValue
  }

  public var defaultDialogButton: Int {
    if (dialogButtons & DialogButton.Ok.rawValue) != 0 {
      return DialogButton.Ok.rawValue
    }
    if (dialogButtons & DialogButton.Cancel.rawValue) != 0 {
      return DialogButton.Cancel.rawValue
    }
    return DialogButton.None.rawValue
  }

  public var shouldSnapFrameWidth: Bool {
    return dialogButtons != DialogButton.None.rawValue
  }

  public func getDialogButtonLabel(button: DialogButton) -> String {
    if button == DialogButton.Ok {
      return l10n.getStringUTF16(IDS_APP_OK)
    }
    if button == DialogButton.Cancel {
      if dialogButtons & DialogButton.Ok.rawValue != 0 {
        return l10n.getStringUTF16(IDS_APP_ANCEL)
      }
      return l10n.getStringUTF16(IDS_APP_LOSE)
    }
    return String()
  }

  public func isDialogButtonEnabled(button: DialogButton) -> Bool {
    return true
  }

  public func createExtraView() -> View? {
    return nil
  }

  public func createFootnoteView() -> View? {
    return nil
  }


  // UIWidgetDelegate defaults
  public var initiallyFocusedView: View? { 
    let dcv = dialogClientView!
    let defaultButton = defaultDialogButton
    if defaultButton == DialogButton.None.rawValue {
      return nil
    }

    if defaultButton & dialogButtons == 0 {
      // The default button is a button we don't have.
      return nil
    }

    if defaultButton & DialogButton.Ok.rawValue != 0 {
      return dcv.okButton
    }
    
    if defaultButton & DialogButton.Cancel.rawValue != 0 {
      return dcv.cancelButton
    }
    return nil
  } 

  public func asDialogDelegate() -> DialogDelegate? {
    return self
  }

  public func createClientView(widget: UIWidget) -> ClientView? {
    return DialogClientView(owner: widget, contentsView: contentsView!)
  }
  
  public func createNonClientFrameView(widget: UIWidget) -> NonClientFrameView? {
    if shouldUseCustomFrame {
      return Self.createDialogFrameView(widget: widget)
    }
    return nil//super.createNonClientFrameView(widget: widget)
  }
  
  public func cancel() -> Bool {
    return true
  }
  
  public func accept() -> Bool {
    return true
  }

  public func close() -> Bool {
    let buttons = dialogButtons
    if (buttons & DialogButton.Cancel.rawValue) != 0 || (buttons == DialogButton.None.rawValue) {
      return cancel()
    }
    return accept()
  }

  public func updateButton(button: LabelButton, type: DialogButton) {
    button.text = getDialogButtonLabel(button: type)
    button.isEnabled = isDialogButtonEnabled(button: type)
    var isDefault = type.rawValue == defaultDialogButton
    if !PlatformStyle.dialogDefaultButtonCanBeCancel && type == DialogButton.Cancel {
      isDefault = false
    }
    button.isDefault = isDefault
  }

}


// defaults for UIWidgetDelegate 
extension DialogDelegate {

  public var canActivate: Bool { get { return false } set {} }
  //public var initiallyFocusedView: View? { return nil }
  public var canResize: Bool { return false }
  public var canMaximize: Bool { return false }
  public var canMinimize: Bool { return false }
  public var windowName: String { return "" }
  public var modalType: ModalType { return .None }
  public var windowTitle: String { return "" }
  public var shouldShowWindowTitle: Bool { return false }
  public var shouldShowCloseButton: Bool { return false }
  public var shouldHandleSystemCommands: Bool { return false }
  public var windowAppIcon: Image? { return nil }
  public var windowIcon: Image? { return nil }
  public var shouldShowWindowIcon: Bool { return false }
  public var shouldRestoreWindowSize: Bool { return false }
  public var widget: UIWidget? { return nil }
  public var contentsView: View? { return nil }
  public var shouldAdvanceFocusToTopLevelWindow: Bool { return false }
  public var widgetHasHitTestMask: Bool { return false }
  public var willProcessWorkAreaChange: Bool { return false }

  public func asBubbleDialogDelegate() -> BubbleDialogDelegateView? { return nil }
  //public func asDialogDelegate() -> DialogDelegate? { return nil }
  public func onWidgetMove() {}
  public func onDisplayChanged() {}

  public func onWorkAreaChanged() {}

  public func executeWindowsCommand(commandId: Int) -> Bool { return false }

  public func saveWindowPlacement(bounds: IntRect,
                           showState: WindowShowState) {}

  public func getSavedWindowPlacement(widget: UIWidget,
                               bounds: inout IntRect,
                               showState: inout WindowShowState) -> Bool { return false }
  public func windowClosing() {}
  public func deleteDelegate() {}
  public func onWindowBeginUserBoundsChange() {}
  public func onWindowEndUserBoundsChange() {}
  //public func createClientView(widget: UIWidget) -> ClientView? { return nil }
  //public func createNonClientFrameView(widget: UIWidget) -> NonClientFrameView? { return nil }
  public func createOverlayView() -> View? { return nil }
  public func getWidgetHitTestMask(mask: inout Path) {}
  public func shouldDescendIntoChildForEventHandling(child: Window, location: IntPoint) -> Bool { return false }
  public func getAccessiblePanes(panes: inout [View] ) {}
}
