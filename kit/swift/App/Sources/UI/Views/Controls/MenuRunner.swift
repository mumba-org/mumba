// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Base

public enum MenuAnchorPosition {
  case TopLeft
  case TopRight
  case BottomCenter
  case FixedBottomCenter
  case FixedSideCenter
  case BubbleLeft
  case BubbleRight
  case BubbleAbove
  case BubbleBelow
  case BubbleTouchableAbove
  case BubbleTouchableLeft
}

// Used during drag and drop to indicate where the drop indicator should
// be rendered.
public enum DropPosition : Int {
  case DropUnknown = -1
  // Indicates a drop is not allowed here.
  case DropNone
  // Indicates the drop should occur before the item.
  case DropBefore
  // Indicates the drop should occur after the item.
  case DropAfter
  // Indicates the drop should occur on the item.
  case DropOn
}

public protocol MenuDelegate : class {
  // Returns true if the menu should close upon a drag completing. Defaults to
  // true. This is only invoked for drag and drop operations performed on child
  // Views that are not MenuItemViews.
  var shouldCloseOnDragComplete: Bool { get }
  // Returns true if the labels should reserve additional spacing for e.g.
  // submenu indicators at the end of the line.
  var shouldReserveSpaceForSubmenuIndicator: Bool { get }

  // Whether or not an item should be shown as checked. This is invoked for
  // radio buttons and check buttons.
  func isItemChecked(id: Int) -> Bool

  // The string shown for the menu item. This is only invoked when an item is
  // added with an empty label.
  func getLabel(id: Int) -> String

  // The font for the menu item label.
  func getLabelFontList(id: Int) -> FontList?

  // Whether this item should be displayed with the normal text color, even if
  // it's disabled.
  func getShouldUseNormalForegroundColor(commandId: Int) -> Bool

  // The tooltip shown for the menu item. This is invoked when the user
  // hovers over the item, and no tooltip text has been set for that item.
  func getTooltipText(id: Int, screenLoc: IntPoint) -> String

  // If there is an accelerator for the menu item with id |id| it is set in
  // |accelerator| and true is returned.
  func getAccelerator(id: Int) -> Accelerator?

  // Shows the context menu with the specified id. This is invoked when the
  // user does the appropriate gesture to show a context menu. The id
  // identifies the id of the menu to show the context menu for.
  // is_mouse_gesture is true if this is the result of a mouse gesture.
  // If this is not the result of a mouse gesture |p| is the recommended
  // location to display the content menu at. In either case, |p| is in
  // screen coordinates.
  // Returns true if a context menu was displayed, otherwise false
  func showContextMenu(source: MenuItemView,
                       id: Int,
                       p: IntPoint,
                       sourceType: MenuSourceType) -> Bool

  // Controller
  func supportsCommand(id: Int) -> Bool
  func isCommandEnabled(id: Int) -> Bool
  func isCommandVisible(id: Int) -> Bool
  func getContextualLabel(id: Int) -> String?
  func executeCommand(id: Int)

  // If nested menus are showing (nested menus occur when a menu shows a context
  // menu) this is invoked to determine if all the menus should be closed when
  // the user selects the menu with the command |id|. This returns true to
  // indicate that all menus should be closed. Return false if only the
  // context menu should be closed.
  func shouldCloseAllMenusOnExecute(id: Int) -> Bool

  // Executes the specified command. mouse_event_flags give the flags of the
  // mouse event that triggered this to be invoked (ui::MouseEvent
  // flags). mouse_event_flags is 0 if this is triggered by a user gesture
  // other than a mouse event.
  func executeCommand(id: Int, mouseEventFlags: Int) -> Bool

  // Returns true if ExecuteCommand() should be invoked while leaving the
  // menu open. Default implementation returns false.
  func shouldExecuteCommandWithoutClosingMenu(id: Int,
                                              e: Graphics.Event) -> Bool
  // Returns true if the specified event is one the user can use to trigger, or
  // accept, the item. Defaults to left or right mouse buttons or tap.
  func isTriggerableEvent(view: MenuItemView, e: Graphics.Event) -> Bool

  // Invoked to determine if drops can be accepted for a submenu. This is
  // ONLY invoked for menus that have submenus and indicates whether or not
  // a drop can occur on any of the child items of the item. For example,
  // consider the following menu structure:
  //
  // A
  //   B
  //   C
  //
  // Where A has a submenu with children B and C. This is ONLY invoked for
  // A, not B and C.
  //

  // To restrict which children can be dropped on override GetDropOperation.
  func canDrop(menu: MenuItemView, data: OSExchangeData) -> Bool

  // See view for a description of this method.
  func getDropFormats(
      menu: MenuItemView,
      formats: inout Int,
      formatTypes: inout [ClipboardFormatType]) -> Bool

  // See view for a description of this method.
  func areDropTypesRequired(menu: MenuItemView) -> Bool

  // Returns the drop operation for the specified target menu item. This is
  // only invoked if CanDrop returned true for the parent menu. position
  // is set based on the location of the mouse, reset to specify a different
  // position.
  //
  // If a drop should not be allowed, returned ui::DragDropTypes::DRAG_NONE.
  func getDropOperation(item: MenuItemView,
                        event: DropTargetEvent,
                        position: inout DropPosition) -> Int

  // Invoked to perform the drop operation. This is ONLY invoked if CanDrop()
  // returned true for the parent menu item, and GetDropOperation() returned an
  // operation other than ui::DragDropTypes::DRAG_NONE.
  //
  // |menu| is the menu the drop occurred on.
  func onPerformDrop(menu: MenuItemView,
                     position: DropPosition,
                     event: DropTargetEvent) -> Int

  // Invoked to determine if it is possible for the user to drag the specified
  // menu item.
  func canDrag(menu: MenuItemView) -> Bool

  // Invoked to write the data for a drag operation to data. sender is the
  // MenuItemView being dragged.
  func writeDragData(sender: MenuItemView, data: OSExchangeData)

  func getDragOperations(sender: MenuItemView) -> Int

  // Invoked to determine the drag operations for a drag session of sender.
  // See DragDropTypes for possible values.
  func setDragOperations(sender: MenuItemView) -> Int

  // Notification that the user has highlighted the specified item.
  func selectionChanged(menu: MenuItemView)

  // Notification the menu has closed. This will not be called if MenuRunner is
  // deleted during calls to ExecuteCommand().
  func onMenuClosed(menu: MenuItemView)

  // If the user drags the mouse outside the bounds of the menu the delegate
  // is queried for a sibling menu to show. If this returns non-null the
  // current menu is hidden, and the menu returned from this method is shown.
  //
  // The delegate owns the returned menu, not the controller.
  func getSiblingMenu(menu: MenuItemView,
                      screenPoint: IntPoint,
                      anchor: inout MenuAnchorPosition,
                      hasMnemonics: inout Bool,
                      button: inout MenuButton?) -> MenuItemView?

  // Returns the max width menus can grow to be.
  func getMaxWidthForMenu(menu: MenuItemView) -> Int

  // Invoked prior to a menu being shown.
  func willShowMenu(menu: MenuItemView)

  // Invoked prior to a menu being hidden.
  func willHideMenu(menu: MenuItemView)

  // Returns additional horizontal spacing for the icon of the given item.
  // The |command_id| specifies the item of interest, the |icon_size| tells the
  // function the size of the icon and it will then return |left_margin|
  // and |right_margin| accordingly. Note: Negative values can be returned.
  func getHorizontalIconMargins(commandId: Int,
                                iconSize: Int,
                                leftMargin: inout Int,
                                rightMargin: inout Int)
}

extension MenuDelegate {

  public var shouldCloseOnDragComplete: Bool { 
    return true
  }

  public var shouldReserveSpaceForSubmenuIndicator: Bool { 
    return true
  }

  public func isItemChecked(id: Int) -> Bool {
    return false
  }

  public func getLabel(id: Int) -> String {
    return String()
  }

  // The font for the menu item label.
  public func getLabelFontList(id: Int) -> FontList? {
    return nil
  }

  public func getShouldUseNormalForegroundColor(commandId: Int) -> Bool {
    return false
  }

  public func getTooltipText(id: Int, screenLoc: IntPoint) -> String {
    return String()
  }

  public func getAccelerator(id: Int) -> Accelerator? {
    return nil
  }

  public func showContextMenu(source: MenuItemView,
                       id: Int,
                       p: IntPoint,
                       sourceType: MenuSourceType) -> Bool {
    return false
  }

  public func supportsCommand(id: Int) -> Bool {
    return false
  }

  public func isCommandEnabled(id: Int) -> Bool  {
    return false
  }
 
  public func isCommandVisible(id: Int) -> Bool  {
    return false
  }
 
  public func getContextualLabel(id: Int) -> String? {
    return nil
  }
 
  public func executeCommand(id: Int, mouseEventFlags: Int) -> Bool {
    executeCommand(id: id)
    return false
  }

  public func shouldExecuteCommandWithoutClosingMenu(id: Int,
                                                     e: Graphics.Event) -> Bool {
   return false
  }

  public func isTriggerableEvent(view: MenuItemView, e: Graphics.Event) -> Bool {
    return e.type == .GestureTap ||
          e.type == .GestureTapDown ||
          (e.isMouseEvent && (e.flags.contains(EventFlags.LeftMouseButton) || 
            e.flags.contains(EventFlags.RightMouseButton)))
  }

  public func canDrop(menu: MenuItemView, data: OSExchangeData) -> Bool {
    return false
  }

  public func getDropFormats(
      menu: MenuItemView,
      formats: inout Int,
      formatTypes: inout [ClipboardFormatType]) -> Bool {

    return false
  }

  public func areDropTypesRequired(menu: MenuItemView) -> Bool {
    return false
  }

  public func getDropOperation(item: MenuItemView,
                        event: DropTargetEvent,
                        position: inout DropPosition) -> Int {
    return DragOperation.DragNone.rawValue
  }

  public func onPerformDrop(menu: MenuItemView,
                     position: DropPosition,
                     event: DropTargetEvent) -> Int {
    return DragOperation.DragNone.rawValue
  }

  public func canDrag(menu: MenuItemView) -> Bool {
    return false
  }

  public func writeDragData(sender: MenuItemView, data: OSExchangeData) {
  }

  public func getDragOperations(sender: MenuItemView) -> Int {
    return 0
  }


  public func getSiblingMenu(menu: MenuItemView,
                      screenPoint: IntPoint,
                      anchor: inout MenuAnchorPosition,
                      hasMnemonics: inout Bool,
                      button: inout MenuButton?) -> MenuItemView? {
    return nil
  }

  public func getMaxWidthForMenu(menu: MenuItemView) -> Int {
    // NOTE: this needs to be large enough to accommodate the wrench menu with
    // big fonts.
    return 800
  }
 
  public func willShowMenu(menu: MenuItemView) {}

  public func willHideMenu(menu: MenuItemView) {}

  public func getHorizontalIconMargins(commandId: Int,
                                iconSize: Int,
                                leftMargin: inout Int,
                                rightMargin: inout Int) {

    leftMargin = 0
    rightMargin = 0
  }

  public func onMenuClosed(menu: MenuItemView) {

  }
}

public protocol MenuRunnerHandler {
  func runMenuAt(parent: UIWidget,
                 button: MenuButton?,
                 bounds: IntRect,
                 anchor: MenuAnchorPosition,
                 sourceType: MenuSourceType,
                 types: Int32)
}

public protocol DisplayChangeListener: class {
  static func create(parent: UIWidget?, runner: MenuRunner?) -> DisplayChangeListener?
}

public class EmptyMenuDelegate : MenuDelegate {
  public init() {}
  public func executeCommand(id: Int){}
  public func shouldCloseAllMenusOnExecute(id: Int) -> Bool {
    return true
  }
  public func setDragOperations(sender: MenuItemView) -> Int {
    return 0
  }
  public func selectionChanged(menu: MenuItemView) {}
}

public class MenuRunner : MenuControllerDelegate {
  
  public struct RunTypes : OptionSet {
    public static let HasMnemonics = RunTypes(rawValue: 1 << 0)
    public static let IsNested = RunTypes(rawValue: 1 << 1)
    public static let ForDrop = RunTypes(rawValue: 1 << 2)
    public static let ContextMenu = RunTypes(rawValue: 1 << 3)
    public static let Combobox = RunTypes(rawValue: 1 << 4)
    public static let NestedDrag = RunTypes(rawValue: 1 << 5)
    public static let FixedAnchor = RunTypes(rawValue: 1 << 6)
    public static let SendGestureEventsToOwner = RunTypes(rawValue: 1 << 7)
    public static let UseTouchableLayout = RunTypes(rawValue: 1 << 8)

    public let rawValue: Int

    public init(rawValue: Int) { self.rawValue = rawValue }
  }

    // The timestamp of the event which closed the menu - or 0.
  public internal(set) var closingEventTime: TimeTicks

  public internal(set) var runTypes: RunTypes

  // Are we in run waiting for it to return?
  public internal(set) var isRunning: Bool

  fileprivate var menu: MenuItemView?

  // Any sibling menus. Does not include |menu_|. We own these too.
  fileprivate var siblingMenus: [MenuItemView?]

  // Created and set as the delegate of the MenuItemView if Release() is
  // invoked.  This is done to make sure the delegate isn't notified after
  // Release() is invoked. We do this as we assume the delegate is no longer
  // valid if MenuRunner has been deleted.
  fileprivate var emptyDelegate: MenuDelegate?

  // Set if |running_| and Release() has been invoked.
  fileprivate var deleteAfterRun: Bool

  // Are we running for a drop?
  fileprivate var forDrop: Bool

  // The controller.
  fileprivate weak var controller: MenuController?

  // An implementation of RunMenuAt. This is usually NULL and ignored. If this
  // is not NULL, this implementation will be used.
  public private(set) var runnerHandler: MenuRunnerHandler?

  fileprivate var displayChangeListener: DisplayChangeListener?

  public init(menuModel: MenuModel,
              runTypes: Int32) {
    self.runTypes = RunTypes(rawValue: Int(runTypes))
    // TODO: MenuModelAdapter
    //self.menuModel
    isRunning = false
    deleteAfterRun = false
    forDrop = false
    siblingMenus = []
    closingEventTime = TimeTicks()
  }

  public init(menu: MenuItemView, 
              runTypes: Int32) {
    self.runTypes = RunTypes(rawValue: Int(runTypes))
    self.menu = menu
    isRunning = false
    deleteAfterRun = false
    forDrop = false
    siblingMenus = []
    closingEventTime = TimeTicks()
  }

  deinit {
     if isRunning {

      if deleteAfterRun {
        return  // We already canceled.
      }
      // The menu is running a nested run loop, we can't delete it now
      // otherwise the stack would be in a really bad state (many frames would
      // have deleted objects on them). Instead cancel the menu, when it returns
      // Holder will delete itself.
      deleteAfterRun = true

      // Swap in a different delegate. That way we know the original MenuDelegate
      // won't be notified later on (when it's likely already been deleted).
      if emptyDelegate == nil {
        emptyDelegate = EmptyMenuDelegate()
      }

      menu!.delegate = emptyDelegate

      // Verify that the MenuController is still active. It may have been
      // destroyed out of order.
      if let c = controller {
        // Release is invoked when MenuRunner is destroyed. Assume this is
        // happening because the object referencing the menu has been destroyed
        // and the menu button is no longer valid.
        c.cancel(type: .Destroyed)
        return
      }
    }

  }

  public func runMenuAt(parent: UIWidget?,
                        button: MenuButton?,
                        bounds: IntRect,
                        anchor: MenuAnchorPosition,
                        sourceType: MenuSourceType) {
    
    if let rootView = parent?.rootView {
      rootView.setMouseHandler(handler: nil)
    }

    if let handler = runnerHandler {
      handler.runMenuAt(parent: parent!, button: button, bounds: bounds, anchor: anchor, sourceType: sourceType, types: Int32(runTypes.rawValue))
      return
    }

    // The parent of the nested menu will have created a DisplayChangeListener, so
    // we avoid creating a DisplayChangeListener if nested. Drop menus are
    // transient, so we don't cancel in that case.
    if !runTypes.contains(RunTypes(rawValue: RunTypes.IsNested.rawValue | RunTypes.ForDrop.rawValue)) && parent != nil {
      displayChangeListener = DisplayChangeListenerImpl.create(parent: parent, runner: self)
    }

    var newAnchor = anchor

    if runTypes.contains(.ContextMenu) && !runTypes.contains(.FixedAnchor) {
      switch sourceType {
     // case .None:
    //    fallthrough
        case .Keyboard:
          fallthrough
        case .Mouse:
          newAnchor = .TopLeft
        case .Touch:
          fallthrough
        case .TouchEditMenu:
          newAnchor = .BottomCenter
      }
    }
    // impl:
      closingEventTime = TimeTicks()
      if isRunning {
        // Ignore requests to show the menu while it's already showing. MenuItemView
        // doesn't handle this very well (meaning it crashes).
        return
      }
      var localController: MenuController!
      localController = MenuController.activeInstance
      if localController != nil {
        if runTypes.contains(.IsNested) {
          if localController.isBlockingRun {
            localController.cancelAll()
            localController = nil
          } else {
            // Only nest the delegate when not cancelling drag-and-drop. When
            // cancelling this will become the root delegate of the new
            // MenuController
            localController.addNestedDelegate(delegate: self)
          }
        } else {
          // There's some other menu open and we're not nested. Cancel the menu.
          localController.cancelAll()
          if !runTypes.contains(.ForDrop) {
            // We can't open another menu, otherwise the message loop would become
            // twice nested. This isn't necessarily a problem, but generally isn't
            // expected.
            return
          }
          // Drop menus don't block the message loop, so it's ok to create a new
          // MenuController.
          localController = nil
        }
      }

      isRunning = true
      forDrop = runTypes.contains(.ForDrop)
      let hasMnemonics = runTypes.contains(.HasMnemonics)
      var isFirstMenu = false
      if localController == nil {
        // No menus are showing, show one.
        localController = MenuController(blocking: !forDrop, delegate: self)
        isFirstMenu = true
      }

      localController.isCombobox = runTypes.contains(.Combobox)
      localController.sendGestureEventsToOwner = runTypes.contains(.SendGestureEventsToOwner)
      localController.useTouchableLayout = runTypes.contains(.UseTouchableLayout)
      
      menu!.controller = localController
      menu!.prepareForRun(isFirstMenu: isFirstMenu, hasMnemonics: hasMnemonics, showMnemonics: !forDrop && shouldShowMnemonics(button: button))

      localController.run(parent: parent, 
                          button: button, 
                          root: menu!, 
                          bounds: bounds, 
                          position: newAnchor,
                          contextMenu: runTypes.contains(.ContextMenu),
                          isNestedDrag: runTypes.contains(.NestedDrag))
  }

  // Hides and cancels the menu. This does nothing if the menu is not open.
  public func cancel() {
    if isRunning {
      if let c = controller {
        c.cancel(type: .All)
      }
    }
  }

  public func onMenuClosed(type: NotifyType,
                           menu targetMenu: MenuItemView?,
                           mouseEventFlags: Int) {
    
    guard let m = menu else {
      return
    }

    if let c = controller {
      closingEventTime = c.closingEventTime
    }
    
    m.removeEmptyMenus()
    m.controller = nil

    controller = nil
    // Make sure all the windows we created to show the menus have been
    // destroyed.
    m.destroyAllMenuHosts()
    if deleteAfterRun {
      //delete this;
      return
    }
    isRunning = false
    if let d = m.delegate {
      // Executing the command may also delete this.
      if let target = targetMenu {
        if !forDrop {
          // Do not execute the menu that was dragged/dropped.
          let _ = d.executeCommand(id: target.command, mouseEventFlags: mouseEventFlags)
        }
      }
      // Only notify the delegate if it did not delete this.
      if type == .NotifyDelegate {
        d.onMenuClosed(menu: m)
      }
    }
  }
  
  public func siblingMenuCreated(menu target: MenuItemView)  {
    if target !== menu && !siblingMenus.contains(target) {
      siblingMenus.append(target)
    }
  }

  func shouldShowMnemonics(button: MenuButton?) -> Bool {
   // Show mnemonics if the button has focus or alt is pressed.
    let showMnemonics = button != nil ? button!.hasFocus : false
    // TODO: implement
    // showMnemonics |= UI.isAltPressed
    return showMnemonics
  }

}

public class DisplayChangeListenerImpl : DisplayChangeListener,
                                         WindowObserver {
  
  fileprivate weak var menuRunner: MenuRunner?
  fileprivate var rootWindow: Window?

  public class func create(parent: UIWidget?, runner: MenuRunner?) -> DisplayChangeListener? {
    return DisplayChangeListenerImpl(widget: parent, menuRunner: runner)
  }
  
  public init(widget: UIWidget?, menuRunner: MenuRunner?) {
    self.menuRunner = menuRunner

    if let root = widget?.window.rootWindow {
      self.rootWindow = root
      root.addObserver(observer: self) 
    }
  }

  deinit {
    if let window = rootWindow {
      window.removeObserver(observer: self) 
    }
  }

  public func onWindowBoundsChanged(window: Window, oldBounds: IntRect, newBounds: IntRect) {
    if let runner = menuRunner {
      runner.cancel()
    }
  }
  
  public func onWindowDestroying(window: Window) {
    if let root = rootWindow {
      root.removeObserver(observer: self)
      rootWindow = nil
    }
  }

}