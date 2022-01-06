// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public protocol FocusTraversable: class {
  var focusSearch: FocusSearch? { get }
  var focusTraversableParent: FocusTraversable? { get set }
  var focusTraversableParentView: View? { get set }
}

public protocol FocusManagerDelegate: class {
  func processAccelerator(accelerator: Accelerator) -> Bool
  func getCurrentTargetForAccelerator(accelerator: Accelerator) -> AcceleratorTarget?
}

public protocol FocusChangeListener: class {
  func onWillChangeFocus(focusedBefore: View, focusedNow: View)
  func onDidChangeFocus(focusedBefore: View, focusedNow: View)
};


public class FocusManager : ViewObserver {

  public enum FocusChangeReason {
   case FocusTraversal
   case FocusRestore
   case DirectFocusChange
 }

  public enum Direction {
   case Forward
   case Backward
  }

  public enum FocusCycleWrappingBehavior {
   case Wrap
   case NoWrap
  }

  public var focusedView: View?

  private (set) public var focusChangeReason: FocusChangeReason
  private (set) public var changingFocus: Bool

  private var widget: UIWidget
  private var delegate: FocusManagerDelegate?
  private var storedFocusedViewStorageId: Int
  private var acceleratorManager: AcceleratorManager
  private var focusChangeListeners: [FocusChangeListener]

  public var storedFocusView: View? {
    get {
      return nil
    }
    set {

    }
  }

  public var shortcutHandlingSuspended: Bool

  static var arrowKeyTraversalEnabled: Bool = false

  public init(widget: UIWidget, delegate: FocusManagerDelegate?) {
    self.widget = widget
    self.delegate = delegate
    focusChangeReason = .DirectFocusChange
    changingFocus = false
    storedFocusedViewStorageId = -1
    acceleratorManager = AcceleratorManager()
    focusChangeListeners = [FocusChangeListener]()
    shortcutHandlingSuspended = false
  }

  // check this if its not too much specific to be here
  public static func isTabTraversalKeyEvent(keyEvent: KeyEvent) -> Bool {
    return false
  }

  public func onKeyEvent(event: KeyEvent) -> Bool {
    return false
  }

  public func containsView(view: View) -> Bool {
    return false
  }

  public func advanceFocus(direction: Direction) {

  }

  public func advanceFocus(reverse: Bool) {

  }

  public func setFocusedViewWithReason(view: View, reason: FocusChangeReason) {

  }

  public func clearFocus() {

  }

  public func advanceFocusIfNecessary() {

  }

  public func validateFocusedView() {

  }

  public func storeFocusedView(clearNativeFocus: Bool) {

  }

  public func restoreFocusedView() -> Bool {
    return false
  }

  public func clearStoredFocusedView() {

  }

  public func registerAccelerator(accelerator: Accelerator,
                                  priority: AcceleratorManager.HandlerPriority,
                                  target: AcceleratorTarget) {

  }

  public func unregisterAccelerator(accelerator: Accelerator, target: AcceleratorTarget) {

  }

  public func unregisterAccelerators(target: AcceleratorTarget) {

  }

  public func processAccelerator(accelerator: Accelerator) -> Bool {
    return false
  }

  public func maybeResetMenuKeyState(key: KeyEvent) {

  }

  public func viewRemoved(removed: View) {

  }

  public func addFocusChangeListener(listener: FocusChangeListener) {

  }

  public func removeFocusChangeListener(listener: FocusChangeListener) {

  }

  public func getCurrentTargetForAccelerator(accelerator: Accelerator) -> AcceleratorTarget? {
    return nil
  }

  public func hasPriorityHandler(accelerator: Accelerator) -> Bool {
    return false
  }

  public func clearNativeFocus() {

  }

  public func rotatePaneFocus(direction: Direction, wrap: FocusCycleWrappingBehavior) -> Bool {
    return false
  }

  public func nextFocusableView(startingView view: View,
                                startingWidget: UIWidget,
                                reverse: Bool,
                                dontLoop: Bool) -> View? {
    return nil
  }
}


public class FocusManagerEventHandler : EventHandler {
  

  private let widget: UIWidget?
  private let window: Window

  public init(widget: UIWidget?, window: Window) {
    self.widget = widget
    self.window = window
    window.addPreTargetHandler(handler: self)
  }

  deinit {
    window.removePreTargetHandler(handler: self)
  }

  public func onEvent(event: inout Event) {
    if let focusManager = widget?.focusManager {
      let keyEvent = event as! KeyEvent
      if focusManager.focusedView != nil && !focusManager.onKeyEvent(event: keyEvent) {
        event.stopPropagation()  
      }
    }
  }
}