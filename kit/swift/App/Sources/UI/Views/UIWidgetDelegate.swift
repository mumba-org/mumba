// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public struct ResizeBehavior : OptionSet {
  
  public static let none = ResizeBehavior(rawValue: 1)
  public static let canResize = ResizeBehavior(rawValue: 2)
  public static let canMaximize = ResizeBehavior(rawValue: 3)
  public static let canMinimize = ResizeBehavior(rawValue: 4)
  
  public var rawValue: Int

  public init(rawValue: Int) {
    self.rawValue = rawValue
  }
}

public protocol UIWidgetDelegate : class {

  var canActivate: Bool { get set } 
  var initiallyFocusedView: View? { get }  
  var resizeBehavior: ResizeBehavior { get }  
  var canResize: Bool { get } 
  var canMaximize: Bool { get } 
  var canMinimize: Bool { get } 
  var windowName: String { get } 
  var modalType: ModalType { get } 
  // var accessibleWindowRole: AXRole { get }
  // var accessibleWindowTitle: String { get }
  var windowTitle: String { get } 
  var shouldShowWindowTitle: Bool { get } 
  var shouldShowCloseButton: Bool { get } 
  //var shouldHandleSystemCommands: Bool { get }
  var windowAppIcon: ImageSkia? { get }
  var windowIcon: ImageSkia? { get }
  var shouldShowWindowIcon: Bool { get }  
  var shouldRestoreWindowSize: Bool { get }
  var widget: UIWidget? { get }
  var contentsView: View? { get }
  var shouldAdvanceFocusToTopLevelWidget: Bool { get } 
  var widgetHasHitTestMask: Bool { get } 
  var willProcessWorkAreaChange: Bool { get } 
  var widgetHitTestMask: Path? { get }
  var accessiblePanes: [View]? { get }

  func asBubbleDialogDelegate() -> BubbleDialogDelegateView?
  func asDialogDelegate() -> DialogDelegate?
  func onWidgetMove()
  func onDisplayChanged()
  func onWorkAreaChanged()
  func executeWindowsCommand(commandId: Int) -> Bool
  func saveWindowPlacement(bounds: IntRect,
                           showState: WindowShowState)
  func getSavedWindowPlacement(widget: UIWidget,
                               bounds: inout IntRect,
                               showState: inout WindowShowState) -> Bool 
  func windowClosing()
  func deleteDelegate()
  func onWindowBeginUserBoundsChange()
  func onWindowEndUserBoundsChange()
  func createClientView(widget: UIWidget) -> ClientView?
  func createNonClientFrameView(widget: UIWidget) -> NonClientFrameView?
  func createOverlayView() -> View?
  func shouldDescendIntoChildForEventHandling(child: Window, location: IntPoint) -> Bool 
}

extension UIWidgetDelegate {

  public var canActivate: Bool { get { return false } set {} }
  public var initiallyFocusedView: View? { return nil }
  public var canResize: Bool { return false }
  public var canMaximize: Bool { return false }
  public var canMinimize: Bool { return false }
  public var windowName: String { return "" }
  public var modalType: ModalType { return .None }
  public var windowTitle: String { return "" }
  public var shouldShowWindowTitle: Bool { return false }
  public var shouldShowCloseButton: Bool { return false }
  public var shouldHandleSystemCommands: Bool { return false }
  public var shouldShowWindowIcon: Bool { return false }
  public var shouldRestoreWindowSize: Bool { return false }
  public var willProcessWorkAreaChange: Bool { return false }
  public var widgetHasHitTestMask: Bool { return false }

  public var windowAppIcon: ImageSkia? {
    return windowIcon
  }

  public var windowIcon: ImageSkia? {
    return ImageSkia()
  }

  public var accessiblePanes: [View]? {
    return nil  
  }

  public var widgetHitTestMask: Path? {
    return nil
  }

  public var shouldAdvanceFocusToTopLevelWidget: Bool {
    return false
  }
  
  public var contentsView: View? {
    return nil
  }

  public var resizeBehavior: ResizeBehavior {
    var behavior = ResizeBehavior.none
    if canResize {
      behavior.insert(ResizeBehavior.canResize)
    }
    if canMaximize {
      behavior.insert(ResizeBehavior.canMaximize)
    }
    if canMinimize {
      behavior.insert(ResizeBehavior.canMinimize)
    }
    return behavior
  }

  public func asBubbleDialogDelegate() -> BubbleDialogDelegateView? { return nil }
  public func asDialogDelegate() -> DialogDelegate? { return nil }
  public func onWidgetMove() {}
  public func onDisplayChanged() {}
  public func onWorkAreaChanged() {}
  public func executeWindowsCommand(commandId: Int) -> Bool { return false }
  public func saveWindowPlacement(bounds: IntRect, showState: WindowShowState) {
    if windowName.isEmpty {
      return
    }

    ViewsDelegate.instance.saveWindowPlacement(widget: widget!, windowName: windowName, bounds: bounds, showState: showState)
  }
  public func getSavedWindowPlacement(widget: UIWidget,
                                      bounds: inout IntRect,
                                      showState: inout WindowShowState) -> Bool {
   if windowName.isEmpty {
    return false
   }

   return ViewsDelegate.instance.getSavedWindowPlacement(
     widget: widget, windowName: windowName, bounds: &bounds, showState: &showState)
  }
  public func windowClosing() {}
  public func deleteDelegate() {}
  public func onWindowBeginUserBoundsChange() {}
  public func onWindowEndUserBoundsChange() {}
  public func createClientView(widget: UIWidget) -> ClientView? {
    return ClientView(owner: widget, contentsView: contentsView)
  }
  public func createNonClientFrameView(widget: UIWidget) -> NonClientFrameView? { return nil }
  public func createOverlayView() -> View? { return nil }
  public func getWidgetHitTestMask(mask: inout Path) {}
  public func shouldDescendIntoChildForEventHandling(child: Window, location: IntPoint) -> Bool { return false }
  public func getAccessiblePanes(panes: inout [View] ) {}
}


open class WidgetDelegateView: View,
                               UIWidgetDelegate {
  
  open override var className: String {
    return "WidgetDelegateView"
  }

  open var contentsView: View? {
    return self
  }

  open override var widget: UIWidget? {
    return super.widget
  }

  public override init() {

  }

}
