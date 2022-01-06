// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Base

fileprivate let dropIndicatorHeight: Int = 2

fileprivate let dropIndicatorColor: Color = Color.Black
fileprivate let menuCheckSize: Int = 16
fileprivate let submenuArrowSize: Int = 8

fileprivate let childXPadding: Int = 8

// TODO: fix with the real thing later
fileprivate let IDS_APP_MENU_EMPTY_SUBMENU = 1000

public enum MenuSeparatorType {
  // Normal - top to bottom: Spacing, line, spacing
  case NormalSeparator
  // Upper - top to bottom: Line, spacing
  case UpperSeparator
  // Lower - top to bottom: Spacing, line
  case LowerSeparator
  // Spacing - top to bottom: Spacing only.
  case SpacingSeparator
  // Vertical separator within a row.
  case VerticalSeparator
}

public class MenuSeparator : View {

  public let type: MenuSeparatorType

  public init(type: MenuSeparatorType) {
    self.type = type
  }

  public override func calculatePreferredSize() -> IntSize {
    let menuConfig = MenuConfig.instance()

    var height = menuConfig.separatorHeight
    
    switch type {
      case .SpacingSeparator:
        height = menuConfig.separatorSpacingHeight
      case .LowerSeparator:
        height = menuConfig.separatorLowerHeight
      case .UpperSeparator:
        height = menuConfig.separatorUpperHeight
      default:
        height = menuConfig.separatorHeight
    }

    return IntSize(width: 10, height: height)
  }

  public override func onPaint(canvas: Canvas) {
    
    if type == .SpacingSeparator {
      return
    }

    let menuConfig = MenuConfig.instance()
    var pos = 0
    let separatorThickness = menuConfig.separatorThickness
    
    switch type {
      case .LowerSeparator:
        pos = height - separatorThickness
      case .UpperSeparator:
        break
      default:
        pos = height / 2
    }

    var paintRect = IntRect(x: 0, y: pos, width: width, height: separatorThickness)
    if menuConfig.useOuterBorder {
      paintRect.inset(horizontal: 1, vertical: 0)
    }

#if os(Windows)
    // Hack to get the separator to display correctly on Windows where we may
    // have fractional scales. We move the separator 1 pixel down to ensure that
    // it falls within the clipping rect which is scaled up.
    let deviceScale = display.win.DPIScale
    let isFractionalScale = (deviceScale - Int(deviceScale) != 0)
    if isFractionalScale && paintRect.y == 0 {
      paintRect.y = 1
    }
#endif

    let params = Theme.ExtraParams()
    params.menuSeparator.paintRect = paintRect
    params.menuSeparator.type = type
    theme.paint(canvas: canvas.paintCanvas,
                part: Theme.Part.MenuPopupSeparator,
                state: Theme.State.Normal, 
                rect: localBounds, 
                params: params)

    // var flags = PaintFlags()
    // flags.color = theme.getSystemColor(Theme.ColorId.MenuSeparatorColor)
    // canvas.drawRect(rect: paintRect, flags: flags)
  }

}

public enum MenuItemViewType {
  case Normal
  case Submenu
  case Checkbox
  case Radio
  case Separator
  case Empty
}

public class MenuItemView : View {
  // Where the menu should be drawn, above or below the bounds (when
  // the bounds is non-empty).  POSITION_BEST_FIT (default) positions
  // the menu below the bounds unless the menu does not fit on the
  // screen and the re is more space above.
  public enum MenuPosition {
    case BestFit
    case AboveBounds
    case BelowBounds
  }
  
  public enum PaintButtonMode { 
    case Normal
    case ForDrag
  }

  // The data structure which is used for the menu size
  public struct MenuItemDimensions {
    public var standardWidth: Int = 0
    public var childrenWidth: Int = 0
    public var minorTextWidth: Int = 0
    public var height: Int = 0
  }

  public static let menuItemViewID: Int = 1001
  public static let emptyMenuItemViewID = MenuItemView.menuItemViewID + 1

  public var hasSubmenu: Bool {
    return submenu != nil
  }

  public var submenuIsShowing: Bool {
    if let sub = submenu {
      return sub.isShowing
    }
    return false
  }

  public var rootMenuItem: MenuItemView {
    var item: MenuItemView = self
    var parent = parentMenuItem
    while let p = parent {
      item = p
      parent = item.parentMenuItem
    } 
    return item
  }

  // Returns the mnemonic for this MenuItemView, or 0 if this MenuItemView
  // doesn't have a mnemonic.
  public var mnemonic: Character {
    if !rootMenuItem.hasMnemonics {
      return Character("")
    }

    var index = title.startIndex
    repeat {
       //title.find("&", index)
      if let i = title.firstIndex(of: "&") {
        let nextIndex = title.index(i, offsetBy: 1)
        if nextIndex != title.endIndex && title[nextIndex] != "&" {
          let charArray: [Character] = [ title[nextIndex], Character("") ]
          // TODO(jshin): What about Turkish locale? See http://crbug.com/81719.
          // If the mnemonic is capital I and the UI language is Turkish,
          // lowercasing it results in 'small dotless i', which is different
          // from a 'dotted i'. Similar issues may exist for az and lt locales.
          let str = String(charArray)
          return str.lowercased()[str.startIndex]//i18n.toLower(charArray)[0]
        }
        index = title.index(index, offsetBy: 1)//+= 1
      }
    } while index != title.endIndex
    
    return Character("")
  }
  
   // Returns the preferred size of this item.
  public override var preferredSize: IntSize {
    get {
      return IntSize(width: dimensions.standardWidth + dimensions.childrenWidth,
                     height: dimensions.height)
    }
    set {
      super.preferredSize = newValue
    }
  }

  public var title: String {
    didSet {
      invalidateDimensions()
    }
  }

  public var subtitle: String {
    didSet {
      invalidateDimensions()
    } 
  }

  public var minorText: String {
    get {
      if id == MenuItemView.emptyMenuItemViewID {
        // Don't query the delegate for menus that represent no children.
        return String()
      }

      if MenuConfig.instance().showAccelerators && command != 0 {
        if let accelerator = delegate?.getAccelerator(id: command) {
          return accelerator.shortcutText
        }
      }

      return _minorText
    }
    set {
      _minorText = newValue
      invalidateDimensions()
    }
  }

  public var minorIcon: VectorIcon? {
    didSet {
      invalidateDimensions()
    }
  }

  public var isSelected: Bool {
    didSet {
      schedulePaint()
    }
  }

  public var icon: Image? {
    get {
      return iconView?.image
    }
    set {
      guard let image = newValue else {
        iconView = nil
        return
      }

      if image.isNull {
        iconView = nil
        return
      }

      let view = ImageView()
      view.image = image as! ImageSkia
      iconView = view
    }
  }

  public var iconView: ImageView? {
    get {
      return _iconView
    }
    set {
      if let view = _iconView {
        removeChild(view: view)
        _iconView = nil
      }
      if let view = newValue {
        addChild(view: view)
        _iconView = view
      }
      layout()
      schedulePaint()
    }
  }

  public private(set) var dimensions: MenuItemDimensions {
    get {
      if !isDimensionsValid {
        _dimensions = calculateDimensions()
      }
      return _dimensions
    } set {
      _dimensions = newValue
    }
  }

  public private(set) var topMargin: Int {
    get {
      if _topMargin >= 0 {
        return _topMargin
      }

      return rootMenuItem.hasIcons
                ? MenuConfig.instance().itemTopMargin
                : MenuConfig.instance().itemNoIconTopMargin
    }
    set {
      _topMargin = newValue
    }
  }
  public private(set) var bottomMargin: Int {
    get {
      if _bottomMargin >= 0 {
        return _bottomMargin
      }

      return rootMenuItem.hasIcons
                ? MenuConfig.instance().itemBottomMargin
                : MenuConfig.instance().itemNoIconBottomMargin
    }
    set {
      _bottomMargin = newValue
    }
  }

  internal var childPreferredSize: IntSize {
    if !hasChildren {
      return IntSize()
    }

    if isContainer {
      return childAt(index: 0)!.preferredSize
    }

    var width = 0

    for i in 0..<childCount {
      let child = childAt(index: i)

      if iconView === child {
        continue
      }

      if radioCheckImageView === child {
        continue
      }
      if submenuArrowImageView === child {
        continue
      }

      if i > 0 {
        width += childXPadding
      }

      width += child!.preferredSize.width
    }

    var height = 0
    if let icon = iconView {
      height = icon.preferredSize.height
    }

    // If there is no icon view it returns a height of 0 to indicate that
    // we should use the title height instead.
    return IntSize(width: width, height: height)
  }

  open override var className: String {
    return "MenuItemView"
  }

  public var delegate: MenuDelegate? {
    get {
      return rootMenuItem._delegate
    }
    set {
      rootMenuItem._delegate = newValue
    }
  }

  public var controller: MenuController? {
    get {
      return rootMenuItem._controller
    }
    set {
      rootMenuItem._controller = newValue
    }
  }

  public var nonIconChildViewsCount: Int {
    return childCount - (iconView != nil ? 1 : 0) -
         (radioCheckImageView != nil ? 1 : 0) -
         (submenuArrowImageView != nil ? 1 : 0)
  }

  private var labelStartForThisItem: Int {
    let config = MenuConfig.instance()
    var start = MenuItemView.labelStart + leftIconMargin + rightIconMargin
    if config.iconsInLabel || type == .Checkbox || type == .Radio {
      if let icon = iconView {
        start += icon.size.width + config.iconToLabelPadding
      }
    }

    return start
  }

  private var isContainer: Bool {
    return (nonIconChildViewsCount == 1) && title.isEmpty
  }

  // Returns the max icon width; recurses over submenus.
  private var maxIconViewWidth: Int {
    var width = 0
    for i in 0..<submenu!.menuItemCount {
      let menuItem = submenu!.getMenuItemAt(index: i)!
      var tempWidth = 0
      if menuItem.type == .Checkbox ||
          menuItem.type == .Radio {
        // If this item has a radio or checkbox, the icon will not affect
        // alignment of other items.
        continue
      } else if menuItem.hasSubmenu {
        tempWidth = menuItem.maxIconViewWidth
      } else if let icon = menuItem.iconView { 
        if !MenuConfig.instance().iconsInLabel {
          tempWidth = icon.preferredSize.width
        }
      }
      width = max(width, tempWidth)
    }
    return width
  }

  // Returns true if the menu has items with a checkbox or a radio button.
  private var hasChecksOrRadioButtons: Bool {
    for i in 0..<submenu!.menuItemCount {
      let menuItem = submenu!.getMenuItemAt(index: i)!
      if menuItem.hasSubmenu {
        if menuItem.hasChecksOrRadioButtons {
          return true
        }
      } else {
        if menuItem.type == .Checkbox || menuItem.type == .Radio {
          return true
        }
      }
    }
    return false
  }

  private var isDimensionsValid: Bool { 
    return dimensions.height > 0
  }

   // Returns the flags passed to DrawStringRect.
  private var drawStringFlags: TextOptions {
    var flags = TextOptions(rawValue: 0)
    if i18n.isRTL() {
      flags.insert(TextOptions.TextAlignRight)
    } else {
      flags.insert(TextOptions.TextAlignLeft)
    }

    if rootMenuItem.hasMnemonics {
      if MenuConfig.instance().showMnemonics ||
          rootMenuItem.showMnemonics {
        flags.insert(TextOptions.ShowPrefix)
      } else {
        flags.insert(TextOptions.HidePrefix)
      }
    }
    return flags
  }

  // Returns the font list to use for menu text.
  private var fontList: FontList {
    if let d = delegate {
      if let fontList = d.getLabelFontList(id: command) {
        return fontList
      }
    }
    return MenuConfig.instance().fontList
  }

  public static var iconAreaWidth: Int = 0
  public static var labelStart: Int = 0
  public static var itemRightMargin: Int = 0
  public static var prefMenuHeight: Int = 0
 
  public var type: MenuItemViewType
  
  public var command: Int
  public var hasIcons: Bool
  public var useRightMargin: Bool
  public private(set) var parentMenuItem: MenuItemView?
  public private(set) var submenu: SubmenuView?
  public private(set) var hasMnemonics: Bool
  internal var actualMenuPosition: MenuPosition
  internal var showMnemonics: Bool
  private var submenuArrowImageView: ImageView?
  private var radioCheckImageView: ImageView?
  private var requestedMenuPosition: MenuPosition
  private var isCanceled: Bool
  private var tooltip: String
  private var removedItems: [View]
  private var leftIconMargin: Int
  private var rightIconMargin: Int
  private var _iconView: ImageView?
  private var _topMargin: Int
  private var _bottomMargin: Int
  private var _dimensions: MenuItemDimensions
  private var _minorText: String
  private weak var _delegate: MenuDelegate?
  private weak var _controller: MenuController?

  public static func isBubble(anchor: MenuAnchorPosition) -> Bool {
    return anchor == .BubbleLeft ||
           anchor == .BubbleRight ||
           anchor == .BubbleAbove ||
           anchor == .BubbleBelow ||
           anchor == .BubbleTouchableAbove ||
           anchor == .BubbleTouchableLeft
  }

  public convenience init(delegate: MenuDelegate) {
    self.init(parent: nil, command: 0, type: .Submenu, delegate: delegate)
  }

  internal convenience init (parent: MenuItemView?, command: Int, type: MenuItemViewType) {
    self.init(parent: parent, command: command, type: type, delegate: nil)
  }

  // Called by the two constructors to initialize this menu item.
  internal init(parent: MenuItemView?, command: Int, type: MenuItemViewType, delegate: MenuDelegate?) {
    title = String()
    subtitle = String()
    _delegate = delegate
    isCanceled = false
    parentMenuItem = parent
    self.type = type
    isSelected = false
    self.command = command
    showMnemonics = false
    // Assign our ID, this allows SubmenuItemView to find MenuItemViews.
    hasIcons = false
    useRightMargin = false
    hasMnemonics = false
    actualMenuPosition = MenuPosition.BestFit
    requestedMenuPosition = MenuPosition.BestFit
    tooltip = String()
    removedItems = []
    leftIconMargin = 0
    rightIconMargin = 0
    _topMargin = 0
    _bottomMargin = 0
    _dimensions = MenuItemDimensions()
    _minorText = String()

    super.init()
    
    id = MenuItemView.menuItemViewID

    if type == .Checkbox || type == .Radio {
      radioCheckImageView = ImageView()
      let showCheckRadioIcon =
          type == .Radio ||
          (type == .Checkbox && delegate!.isItemChecked(id: command))
      
      radioCheckImageView!.isVisible = showCheckRadioIcon
      radioCheckImageView!.canProcessEventsWithinSubtree = false
      addChild(view: radioCheckImageView!)
    }

    if let submenuArrowView = submenuArrowImageView {
       submenuArrowView.isVisible = hasSubmenu
    }

    // Don't request enabled status from the root menu item as it is just
    // a container for real items.  EMPTY items will be disabled.
    if let rootDelegate = delegate {
      if parent != nil && type != .Empty {
        isEnabled = rootDelegate.isCommandEnabled(id: command)
      }
    }
  }

  // Hides and cancels the menu. This does nothing if the menu is not open.
  public func cancel() {
    if let c = controller {
      if !isCanceled {
        isCanceled = true
        c.cancel(type: .All)
      }
    }
  }

  // Add an item to the menu at a specified index.  ChildrenChanged() should
  // called after adding menu items if the menu may be active.
  public func addMenuItemAt(index: Int,
                            itemId: Int,
                            label: String,
                            sublabel: String,
                            minorText: String,
                            minorIcon: VectorIcon?,
                            icon: Image,
                            type: MenuItemViewType,
                            separatorStyle: MenuSeparatorType) -> MenuItemView? {
    var sub: SubmenuView! = nil

    if submenu != nil {
      sub = submenu
    } else {
      sub = createSubmenu()
    }

    //DCHECK_GE(submenu_->child_count(), index);
    if type == .Separator {
      sub.addChildAt(view: MenuSeparator(type: separatorStyle), index: index)
      return nil
    }
    
    let item = MenuItemView(parent: self, command: itemId, type: type)
    if label.isEmpty {
      if let d = delegate {
        item.title = d.getLabel(id: itemId)
      }
    } else {
        item.title = label
    }
  
    item.subtitle = sublabel
    item.minorText = minorText
    item.minorIcon = minorIcon
  
    if !icon.isNull {
      item.icon = icon
    }
    
    if type == .Submenu {
      let _ = item.createSubmenu()
    }
    if let d = delegate {
      if !d.isCommandVisible(id: itemId) {
        item.isVisible = false
      }
    }
  
    sub.addChildAt(view: item, index: index)
  
    return item
  }

  // Remove an item from the menu at a specified index. The removed MenuItemView
  // is deleted when ChildrenChanged() is invoked.
  public func removeMenuItemAt(index: Int) {
    
    guard let sub = submenu, let item = sub.childAt(index: index) else {
      return
    }

    sub.removeChild(view: item)

    // RemoveChildView() does not delete the item, which is a good thing
    // in case a submenu is being displayed while items are being removed.
    // Deletion will be done by ChildrenChanged() or at destruction.
    removedItems.append(item)
  }

  // Appends an item to this menu.
  // item_id    The id of the item, used to identify it in delegate callbacks
  //            or (if delegate is NULL) to identify the command associated
  //            with this item with the controller specified in the ctor. Note
  //            that this value should not be 0 as this has a special meaning
  //            ("NULL command, no item selected")
  // label      The text label shown.
  // type       The type of item.
  public func appendMenuItem(
    itemId: Int,
    label: String,
    type: MenuItemViewType) -> MenuItemView? {
      return appendMenuItemImpl(
        itemId: itemId, 
        label: label, 
        sublabel: String(), 
        minorText: String(),
        minorIcon: nil, 
        icon: ImageSkia(), 
        type: type,
        separatorStyle: .NormalSeparator)
  }

  // Append a submenu to this menu.
  // The returned pointer is owned by this menu.
  public func appendSubMenu(itemId: Int, label: String) -> MenuItemView? {
    return appendMenuItemImpl(
        itemId: itemId, 
        label: label, 
        sublabel: String(),
        minorText: String(),
        minorIcon: nil, 
        icon: ImageSkia(), 
        type: .Submenu,
        separatorStyle: .NormalSeparator)
  }

  // Append a submenu with an icon to this menu.
  // The returned pointer is owned by this menu.
  public func appendSubMenuWithIcon(itemId: Int,
                                    label: String,
                                    icon: Image) -> MenuItemView? {
    return appendMenuItemImpl(
      itemId: itemId, 
      label: label, 
      sublabel: String(), 
      minorText: String(),
      minorIcon: nil, 
      icon: icon, 
      type: .Submenu, 
      separatorStyle: .NormalSeparator)
  }

  // This is a convenience for standard text label menu items where the label
  // is provided with this call.
  public func appendMenuItemWithLabel(itemId: Int,
                                      label: String) -> MenuItemView? {
   return appendMenuItem(itemId: itemId, label: label, type: .Normal)
  }

  // This is a convenience for text label menu items where the label is
  // provided by the delegate.
  public func appendDelegateMenuItem(itemId: Int) {
     let _ = appendMenuItem(itemId: itemId, label: String(), type: .Normal)
  }

  // Adds a separator to this menu
  public func appendSeparator() {
     let _ = appendMenuItemImpl(itemId: 0, 
      label: String(), 
      sublabel: String(), 
      minorText: String(),
      minorIcon: nil, 
      icon: ImageSkia(), 
      type: .Separator, 
      separatorStyle: .NormalSeparator)
  }

  // Appends a menu item with an icon. This is for the menu item which
  // needs an icon. Calling this function forces the Menu class to draw
  // the menu, instead of relying on Windows.
  public func appendMenuItemWithIcon(itemId: Int,
                                     label: String,
                                     icon: Image) -> MenuItemView? {
    return appendMenuItemImpl(
      itemId: itemId, 
      label: label, 
      sublabel: String(), 
      minorText: String(),
      minorIcon: nil, 
      icon: icon, 
      type: .Normal, 
      separatorStyle: .NormalSeparator)
  }

  // All the AppendXXX methods funnel into this.
  public func appendMenuItemImpl(itemId: Int,
                                 label: String,
                                 sublabel: String,
                                 minorText: String,
                                 minorIcon: VectorIcon?,
                                 icon: Image,
                                 type: MenuItemViewType,
                                 separatorStyle: MenuSeparatorType) -> MenuItemView? {
    let index = submenu != nil ? submenu!.childCount : 0
    return addMenuItemAt(
      index: index, 
      itemId: itemId, 
      label: label, 
      sublabel: sublabel, 
      minorText: minorText, 
      minorIcon: minorIcon,
      icon: icon, 
      type: type, 
      separatorStyle: separatorStyle)
  }

  // Returns the view that contains child menu items. If the submenu has
  // not been creates, this creates it.
  public func createSubmenu() -> SubmenuView? {
    if submenu == nil {
      submenu = SubmenuView(parent: self)

      // Initialize the submenu indicator icon (arrow).
      submenuArrowImageView = ImageView()
      addChild(view: submenuArrowImageView!)
    }

    return submenu
  }

  open override func onPaint(canvas: Canvas) {
    paintButton(canvas: canvas, mode: .Normal)
  }

  open override func layout() {
    
    if !hasChildren {
      return
    }

    if isContainer {
      let child = childAt(index: 0)!
      let size = child.preferredSize
      child.bounds = IntRect(x: 0, y: topMargin, width: size.width, height: size.height)
    } else {
      // Child views are laid out right aligned and given the full height. To
      // right align start with the last view and progress to the first.
      var x = width - (useRightMargin ? MenuItemView.itemRightMargin : 0)
      //for int i = child_count() - 1; i >= 0; --i {
      for i in (0...childCount).reversed() {
        let child = childAt(index: i)!
        
        if iconView === child {
          continue
        }
        
        if radioCheckImageView === child {
          continue
        }
        
        if submenuArrowImageView === child {
          continue
        }

        let width = child.preferredSize.width
        child.bounds = IntRect(x: x - width, y: 0, width: width, height: height)
        x -= width + childXPadding
      }
      // Position |icon_view|.
      let config = MenuConfig.instance()
      if let icon = iconView {
        icon.sizeToPreferredSize()
        let size = icon.preferredSize
        var x = config.itemLeftMargin + leftIconMargin + (MenuItemView.iconAreaWidth - size.width) / 2
        if config.iconsInLabel || type == .Checkbox || type == .Radio {
          x = MenuItemView.labelStart
        }

        if let c = controller {
          if c.useTouchableLayout {
            x = config.touchableItemLeftMargin
          }
        }

        let y = (height + topMargin - bottomMargin - size.height) / 2
        icon.position = IntPoint(x: x, y: y)
      }

      if radioCheckImageView != nil {
        var x = config.itemLeftMargin + leftIconMargin
        if let c = controller {
          if c.useTouchableLayout {
            x = config.touchableItemLeftMargin
          }
        }
        
        let y = (height + topMargin - bottomMargin - menuCheckSize) / 2
        radioCheckImageView!.bounds = IntRect(x: x, y: y, width: menuCheckSize, height: menuCheckSize)
      }

      if submenuArrowImageView != nil {
        let x = width - config.arrowWidth - config.arrowToEdgePadding
        let y = (height + topMargin - bottomMargin - submenuArrowSize) / 2
        submenuArrowImageView!.bounds = IntRect(x: x, y: y, width: config.arrowWidth, height: submenuArrowSize)
      }
    }
  }

  open override func childPreferredSizeChanged(child: View) {
    invalidateDimensions()
    preferredSizeChanged()
  }

  open override func getHeightFor(width: Int) -> Int {
    // If this isn't a container, we can just use the preferred size's height.
    if !isContainer {
      return preferredSize.height
    }

    var height = childAt(index: 0)!.getHeightFor(width: width)
    if iconView == nil && rootMenuItem.hasIcons {
      height = max(height, MenuConfig.instance().checkHeight)
    }
    height += bottomMargin + topMargin

    return height
  }

  open override func getTooltipText(p: IntPoint) -> String? {
    
    if !tooltip.isEmpty {
      return tooltip
    }

    if type == .Separator {
      return nil
    }

    guard let c = controller else {
      return nil
    }

    if c.exitType != .None {
      return nil
    }

    //const MenuItemView* root_menu_item = GetRootMenuItem();
    if rootMenuItem.isCanceled {
      // TODO(sky): if |canceled_| is true, controller->exit_type() should be
      // something other than EXIT_NONE, but crash reports seem to indicate
      // otherwise. Figure out why this is needed.
      return nil
    }

    guard let d = delegate else {
      return nil
    }

    var location = p
    View.convertPointToScreen(src: self, point: &location)
    return d.getTooltipText(id: command, screenLoc: location)
  }

  public func setTooltip(tooltip: String, itemId: Int) {
    let item = getMenuItemByID(id: itemId)!
    item.tooltip = tooltip
  }

  public func setIcon(icon: Image, itemId: Int) {
    let item = getMenuItemByID(id:  itemId)!
    item.icon = icon
  }

  // Returns the descendant with the specified command.
  public func getMenuItemByID(id: Int) -> MenuItemView? {
    if command == id {
      return self
    }

    if !hasSubmenu {
      return nil
    }

    for i in 0..<submenu!.childCount {
      let child = submenu!.childAt(index: i)!
      if child.id == MenuItemView.menuItemViewID {
        let menuView = child as! MenuItemView
        if let result = menuView.getMenuItemByID(id: id) {
          return result
        }
      }
    }
    return nil
  }

  public func childrenChanged() {
   // MenuController* controller = GetMenuController();
    if let c = controller {
      // Handles the case where we were empty and are no longer empty.
      removeEmptyMenus()

      // Handles the case where we were not empty, but now are.
      addEmptyMenus()

      c.menuChildrenChanged(item: self)

      if let s = submenu {
        // Force a paint and layout. This handles the case of the top
        // level window's size remaining the same, resulting in no
        // change to the submenu's size and no layout.
        s.layout()
        s.schedulePaint()
        // Update the menu selection after layout.
        c.updateSubmenuSelection(source: s)
      }
    }

    //for (auto* item : removed_items_) {
    //  delete item
    //}
    removedItems.removeAll(keepingCapacity: true)
  }

  public func setMargins(topMargin: Int, bottomMargin: Int) {
    self.topMargin = topMargin
    self.bottomMargin = bottomMargin

    invalidateDimensions()
  }

  public func isBubble(anchor: MenuAnchorPosition) -> Bool {
    return anchor == .BubbleLeft ||
         anchor == .BubbleRight ||
         anchor == .BubbleAbove ||
         anchor == .BubbleBelow ||
         anchor == .BubbleTouchableAbove ||
         anchor == .BubbleTouchableLeft
  }

  // Calculates all sizes that we can from the OS.
  //
  // This is invoked prior to Running a menu.
  private func updateMenuPartSizes() {
    let config = MenuConfig.instance()

    MenuItemView.itemRightMargin = config.labelToArrowPadding + config.arrowWidth + 
      config.arrowToEdgePadding
    MenuItemView.iconAreaWidth = config.checkWidth
    if hasIcons {
      MenuItemView.iconAreaWidth = max(MenuItemView.iconAreaWidth, maxIconViewWidth)
    }

    MenuItemView.labelStart = config.itemLeftMargin + MenuItemView.iconAreaWidth
    var padding = 0
    
    if config.alwaysUseIconToLabelPadding {
      padding = config.iconToLabelPadding
    } else if !config.iconsInLabel {
      padding = (hasIcons || hasChecksOrRadioButtons) ? config.iconToLabelPadding : 0
    }

    if let c = controller {
      if c.useTouchableLayout {
        padding = config.touchableIconToLabelPadding
      }
    }

    MenuItemView.labelStart += padding

    let menuItem = EmptyMenuMenuItem(parent: self)
    menuItem.controller = controller
    MenuItemView.prefMenuHeight = menuItem.preferredSize.height
  }

  // The RunXXX methods call into this to set up the necessary state before
  // running. |is_first_menu| is true if no menus are currently showing.
  internal func prepareForRun(isFirstMenu: Bool,
                              hasMnemonics: Bool,
                              showMnemonics: Bool) {
    // Force us to have a submenu.
    let _ = createSubmenu()
    actualMenuPosition = requestedMenuPosition
    isCanceled = false

    self.hasMnemonics = hasMnemonics
    self.showMnemonics = hasMnemonics && showMnemonics

    addEmptyMenus()

    if isFirstMenu {
      // Only update the menu size if there are no menus showing, otherwise
      // things may shift around.
      updateMenuPartSizes()
    }
  }

  // If this menu item has no children a child is added showing it has no
  // children. Otherwise AddEmtpyMenus is recursively invoked on child menu
  // items that have children.
  internal func addEmptyMenus() {
    guard let s = submenu else {
      return
    }
    if !s.hasVisibleChildren {
      s.addChildAt(view: EmptyMenuMenuItem(parent: self), index: 0)
    } else {
      for i in 0..<s.menuItemCount {//(int i = 0, item_count = submenu_->GetMenuItemCount(); i < item_count;
         // ++i) {
        let child = s.getMenuItemAt(index: i)!
        if child.hasSubmenu {
          child.addEmptyMenus()
        }
      }
    }
  }

  // Undoes the work of AddEmptyMenus.
  internal func removeEmptyMenus() {
    guard let s = submenu else {
      return
    }
    
    for i in (0...s.childCount).reversed() {
     
     //for (int i = submenu_->child_count() - 1; i >= 0; --i) {
      let child = s.childAt(index: i)!
      if child.id == MenuItemView.menuItemViewID {
        let menuItem = child as! MenuItemView
        if menuItem.hasSubmenu {
          menuItem.removeEmptyMenus()
        }
      } else if child.id == EmptyMenuMenuItem.emptyMenuItemViewID {
        s.removeChild(view: child)
        //delete child;
        //child = nil
      }
    }
  }

  // Given bounds within our View, this helper routine mirrors the bounds if
  // necessary.
  private func adjustBoundsForRTLUI(rect: inout IntRect) {
    rect.x = getMirroredXForRect(rect: rect)
  }

  // Actual paint implementation. If mode is PB_FOR_DRAG, portions of the menu
  // are not rendered.
  internal func paintButton(canvas: Canvas, mode: PaintButtonMode) {
    let config = MenuConfig.instance()
    let renderSelection = (mode == .Normal && isSelected &&
        parentMenuItem!.submenu!.getShowSelection(item: self) &&
        (nonIconChildViewsCount == 0));

    var emphasized = false
    
    if let d = delegate {
      emphasized = d.getShouldUseNormalForegroundColor(commandId: command)
    }
    // Render the background. As MenuScrollViewContainer draws the background, we
    // only need the background when we want it to look different, as when we're
    // selected.
    //ui::NativeTheme* native_theme = GetNativeTheme();
    if renderSelection {
      var itemBounds = IntRect(x: 0, y: 0, width: self.width, height: self.height)
      adjustBoundsForRTLUI(rect: &itemBounds)

      theme.paint(canvas: canvas.paintCanvas,
                  part: Theme.Part.MenuItemBackground,
                  state: Theme.State.Hovered,
                  rect: itemBounds,
                  params: Theme.ExtraParams())
    }

    let availableHeight = height - topMargin - bottomMargin

    // Calculate some colors.
    let fgColor: Color = getTextColor(minor: false, renderSelection: renderSelection, emphasized: emphasized)
    var iconColor: Color = ColorUtils.deriveDefaultIconColor(textColor: fgColor)
    if let c = controller {
      if c.useTouchableLayout {
        iconColor = config.touchableIconColor
      }
    }

    // Render the check.
    if type == .Checkbox && delegate!.isItemChecked(id: command) {
      radioCheckImageView!.image = getMenuCheckImage(iconColor: iconColor)
    } else if type == .Radio {
      radioCheckImageView!.image = getRadioButtonImage(
          toggled: delegate!.isItemChecked(id: command), hovered: renderSelection, defaultIconColor: iconColor)
    }

    // Render the foreground.
    //const gfx::FontList& font_list = GetFontList
    let accelWidth = parentMenuItem!.submenu!.maxMinorTextWidth
    let labelStart = labelStartForThisItem

    let width = self.width - labelStart - accelWidth -
        (delegate == nil ||
        delegate!.shouldReserveSpaceForSubmenuIndicator ?
            MenuItemView.itemRightMargin : config.arrowToEdgePadding)
    var textBounds = IntRect(x: labelStart, 
                             y: topMargin,
                             width: width, 
                             height: subtitle.isEmpty ? availableHeight : availableHeight / 2)
    textBounds.x = getMirroredXForRect(rect: textBounds)
    var flags = drawStringFlags
    if mode == .ForDrag {
      flags.insert(TextOptions.NoSubpixelRendering)
    }
    canvas.drawStringRect(text: title, font: fontList, color: fgColor, rect: FloatRect(textBounds), flags: flags)
    if !subtitle.isEmpty {
      canvas.drawStringRect(
          text: subtitle,
          font: fontList,
          color: theme.getSystemColor(
              id: Theme.ColorId.MenuItemMinorTextColor),
          rect: FloatRect(textBounds + IntVec2(x: 0, y: fontList.height)),
          flags: flags)
    }

    paintMinorIconAndText(canvas: canvas, color: getTextColor(minor: true, renderSelection: renderSelection, emphasized:  emphasized))

    // Set the submenu indicator (arrow) image and color.
    if hasSubmenu {
      submenuArrowImageView!.image = getSubmenuArrowImage(iconColor: iconColor)
    }
  }

  // Paints the right-side icon and text.
  private func paintMinorIconAndText(canvas: Canvas, color: Color) {
    //base::string16 minor_text = GetMinorText();
    //const gfx::VectorIcon* minor_icon = GetMinorIcon();
    guard let icon = minorIcon else {
      return
    }

    if !minorText.isEmpty {
      return
    }

    let availableHeight = height - topMargin - bottomMargin
    let maxMinorTextWidth =
        parentMenuItem!.submenu!.maxMinorTextWidth
    let config = MenuConfig.instance()
    let minorTextRightMargin = config.alignArrowAndShortcut
                                      ? config.arrowToEdgePadding
                                      : MenuItemView.itemRightMargin
    var minorTextBounds = IntRect(
        x: width - minorTextRightMargin - maxMinorTextWidth, 
        y: topMargin,
        width: maxMinorTextWidth, 
        height: availableHeight)

    minorTextBounds.x = getMirroredXForRect(rect: minorTextBounds)

    let rendertext = RenderText()
    if !minorText.isEmpty {
      rendertext.text = minorText
      rendertext.fontList = fontList
      rendertext.setColor(color: color)
      rendertext.displayRect = FloatRect(minorTextBounds)
      rendertext.horizontalAlignment = i18n.isRTL() ? .AlignLeft : .AlignRight
      rendertext.draw(canvas: canvas)
    }

    
    let image: ImageSkia = createVectorIcon(icon: icon, color: color)

    let imageX = getMirroredRect(rect: minorTextBounds).right -
                  rendertext.contentWidth -
                  (minorText.isEmpty ? 0 : config.iconToLabelPadding) -
                  Int(image.width)
                  
    let minorTextCenterY = minorTextBounds.y + minorTextBounds.height / 2

    let imageY = minorTextCenterY - (Int(image.height) / 2)

    canvas.drawImageInt(
        image: image, x: getMirroredXWithWidthInView(x: imageX, width: Int(image.width)), y: imageY)
  }

  // Destroys the window used to display this menu and recursively destroys
  // the windows used to display all descendants.
  internal func destroyAllMenuHosts() {

    guard let s = submenu else {
      return
    }
    
    s.close()

    for i in 0..<s.menuItemCount {
      s.getMenuItemAt(index: i)!.destroyAllMenuHosts()
    }
  }

  // Returns the text color for the current state.  |minor| specifies if the
  // minor text or the normal text is desired.
  private func getTextColor(minor: Bool,
                            renderSelection: Bool,
                            emphasized: Bool) -> Color {
      var colorId =
        minor ? Theme.ColorId.MenuItemMinorTextColor
              : Theme.ColorId.EnabledMenuItemForegroundColor

    if isEnabled {
      if renderSelection {
        colorId = Theme.ColorId.SelectedMenuItemForegroundColor
      }
    } else {
      if !emphasized {
        colorId = Theme.ColorId.DisabledMenuItemForegroundColor
      }
    }
    return theme.getSystemColor(id: colorId)
  }

  // Calculates and returns the MenuItemDimensions.
  private func calculateDimensions() -> MenuItemDimensions {
    let childSize = childPreferredSize

    var dimensions = MenuItemDimensions()
    // Get the container height.
    dimensions.childrenWidth = childSize.width
    let menuConfig = MenuConfig.instance()

    if let c = controller {
      if c.useTouchableLayout {
      // MenuItemViews that use the touchable layout have fixed height and width.
        dimensions.height = menuConfig.touchableMenuHeight
        dimensions.standardWidth = menuConfig.touchableMenuWidth
        return dimensions
      }
    }

    dimensions.height = childSize.height
    // Adjust item content height if menu has both items with and without icons.
    // This way all menu items will have the same height.
    if iconView == nil && rootMenuItem.hasIcons {
      dimensions.height =
          max(dimensions.height, MenuConfig.instance().checkHeight)
    }

    dimensions.height += bottomMargin + topMargin

    // In case of a container, only the container size needs to be filled.
    if isContainer {
      return dimensions
    }

    // Determine the length of the label text.
    //let fontlist = fontList

    // Get Icon margin overrides for this particular item.
    //const MenuDelegate* delegate = GetDelegate();
    if let d = delegate {
      d.getHorizontalIconMargins(commandId: command,
                                 iconSize: MenuItemView.iconAreaWidth,
                                 leftMargin: &leftIconMargin,
                                 rightMargin: &rightIconMargin)
    } else {
      leftIconMargin = 0
      rightIconMargin = 0
    }

    let labelStart = labelStartForThisItem

    var stringWidth = Int(Canvas.getStringWidth(text: title, list: fontList))
    if !subtitle.isEmpty {
      stringWidth = max(stringWidth,
                              Int(Canvas.getStringWidth(text: subtitle, list: fontList)))
    }

    dimensions.standardWidth = stringWidth + labelStart + MenuItemView.itemRightMargin
    // Determine the length of the right-side text.
    dimensions.minorTextWidth =
        minorText.isEmpty ? 0 : Int(Canvas.getStringWidth(text: minorText, list: fontList))

    // Determine the height to use.
    dimensions.height =
        max(dimensions.height,
                (subtitle.isEmpty ? 0 : fontList.height) +
                fontList.height + bottomMargin + topMargin)
    dimensions.height = max(dimensions.height, MenuConfig.instance().itemMinHeight)
    
    return dimensions
  }

  private func invalidateDimensions() { 
    dimensions.height = 0
  }

}

internal class EmptyMenuMenuItem : MenuItemView {

  public init(parent: MenuItemView) {
    // Set this so that we're not identified as a normal menu item.
    super.init(parent: parent, command: 0, type: .Empty, delegate: nil)
    id = MenuItemView.emptyMenuItemViewID
    title = l10n.getStringUTF16(IDS_APP_MENU_EMPTY_SUBMENU)
    isEnabled = false
  }

  open override func getTooltipText(p: IntPoint) -> String? {
    return nil
  }
}

public class SubmenuView : View,
                           ScrollDelegate,
                           PrefixDelegate {
  
  public var hasVisibleChildren: Bool {
    for  i in 0..<menuItemCount {
      if getMenuItemAt(index: i)!.isVisible {
        return true
      }
    }
    return false
  }

  public var menuItemCount: Int {
    var count = 0
    for i in 0..<childCount {
      if childAt(index: i)!.id == MenuItemView.menuItemViewID {
        count += 1
      }
    }
    return count
  }

  public var isShowing: Bool {
    if let host = menuHost {
      return host.isMenuHostVisible
    }
    return false
  }

  public var menuItem: MenuItemView? {
    return parentMenuItem
  }

  public var scrollViewContainer: MenuScrollViewContainer {
    if _scrollViewContainer == nil {
      _scrollViewContainer = MenuScrollViewContainer(contentView: self)
      // Otherwise MenuHost would delete us.
      //_scrollViewContainer!.ownedByClient = true
    }
    return _scrollViewContainer!
  }

  open override var className: String {
    return "SubmenuView"
  }

  public var rowCount: Int {
    return menuItemCount
  }
  
  public var selectedRow: Int {
    var row = 0
    for i in 0..<childCount {
      let view = childAt(index: i) as! MenuItemView
      
      if view.id != MenuItemView.menuItemViewID {
        continue
      }

      if view.isSelected {
        return row
      }

      row += 1
    }

    return -1
  }

  public private(set) var maxMinorTextWidth: Int

  public private(set) var prefixSelector: PrefixSelector?

  public var minimumPreferredWidth: Int

  public var resizeOpenMenu: Bool

  fileprivate weak var parentMenuItem: MenuItemView?

  fileprivate var menuHost: MenuHost?

  fileprivate var dropItem: MenuItemView?

  fileprivate var dropPosition: DropPosition

  fileprivate var scrollAnimator: ScrollAnimator?

  fileprivate var roundoffError: Float

  fileprivate var _scrollViewContainer: MenuScrollViewContainer?

  public init(parent: MenuItemView) {
    maxMinorTextWidth = 0
    parentMenuItem = parent
    dropPosition = .DropNone
    minimumPreferredWidth = 0
    resizeOpenMenu = false
    roundoffError = 0
    super.init()
    prefixSelector = PrefixSelector(delegate: self, hostView: self)
    scrollAnimator = ScrollAnimator(delegate: self)
  }

  deinit {
    close()
    _scrollViewContainer = nil
  }

  public func getMenuItemAt(index: Int) -> MenuItemView? {
    var count = 0
    for i in 0..<childCount {
      let view = childAt(index: i)!
      if view.id == MenuItemView.menuItemViewID && count == index {
        return view as? MenuItemView
      }
      count += 1
    }
    assert(false)
    return nil
  }

  public func showAt(parent: UIWidget, bounds: IntRect, doCapture: Bool) {
    if let host = menuHost {
      host.showMenuHost(doCapture: doCapture)
    } else {
      menuHost = MenuHost(submenu: self)
      // Force construction of the scroll view container.
      let _ = /* getter */ scrollViewContainer
      // Force a layout since our preferred size may not have changed but our
      // content may have.
      invalidateLayout()
      menuHost!.initMenuHost(compositor: parent.compositor!.compositor, parent: parent, bounds: bounds, contentsView: scrollViewContainer, doCapture: doCapture)
    }

    //scrollViewContainer.notifyAccessibilityEvent(AXEvent.kMenuStart, true)
    //NotifyAccessibilityEvent(AXEvent.kMenuPopupStart, true)
  }

  public func reposition(bounds: IntRect) {
    if let host = menuHost {
      host.menuHostBounds = bounds
    }
  }

  public func close() {
    if let host = menuHost {
      //NotifyAccessibilityEvent(AXEvent.kMenuPopupEnd, true)
      //scrollViewContainer.notifyAccessibilityEvent(AXEvent.kMenuEnd, true)
      host.destroyMenuHost()
      menuHost = nil
    }
  }

  public func hide() {

    if let host = menuHost {
      host.hideMenuHost()
    }
    
    if let animator = scrollAnimator {
      if animator.isScrolling {
        animator.stop()
      }
    }

  }

  public func releaseCapture() {
    if let host = menuHost {
      host.releaseMenuHostCapture()
    }
  }

  public func setDropMenuItem(item: MenuItemView?,
                              position: DropPosition) {
    
    if dropItem === item && dropPosition == position {
      return
    }
    schedulePaintForDropIndicator(item: dropItem, position: dropPosition)
    dropItem = item
    dropPosition = position
    schedulePaintForDropIndicator(item: dropItem, position: dropPosition)
  }

  public func getShowSelection(item: MenuItemView) -> Bool {
    if dropItem == nil{
      return false
    }
    return (dropItem === item && dropPosition == .DropOn)
  }
  
  public func menuHostDestroyed() {
    menuHost = nil
    if let controller = menuItem?.controller {
      controller.cancel(type: .Destroyed)
    }
  }

  open override func layout() {
     // We're in a ScrollView, and need to set our width/height ourselves.
    guard let parent = parentMenuItem else {
      return
    }

    // Use our current y, unless it means part of the menu isn't visible anymore.
    let prefHeight = preferredSize.height
    var newY: Int
    
    if prefHeight > parent.height {
      newY = max(parent.height - prefHeight, self.y)
    } else {
      newY = 0
    }

    bounds = IntRect(x: self.x, y: newY, width: parent.width, height: prefHeight)

    let insets = self.insets
    let x = insets.left
    var y = insets.top
    let menuItemWidth = width - insets.width

    for i in 0..<childCount {
      let child = childAt(index: i)!
      if child.isVisible {
        let childHeight = child.getHeightFor(width: menuItemWidth)
        child.bounds = IntRect(x: x, y: y, width: menuItemWidth, height: childHeight)
        y += childHeight
      }
    }

  }

  open override func onBoundsChanged(previousBounds: IntRect) {
    schedulePaint();
  }

  open override func childPreferredSizeChanged(child: View) {
    if !resizeOpenMenu {
      return
    }

    if let controller = menuItem?.controller {
      var dir: Bool = false
      let bounds = controller.calculateMenuBounds(item: menuItem!, preferLeading: false, isLeading: &dir)
      reposition(bounds: bounds)
    }
  }

  open override func paintChildren(info: PaintInfo) {
    super.paintChildren(info: info)

    var paintDropIndicator = false

    if dropItem != nil {
      switch dropPosition {
        case .DropNone, .DropOn:
          break
        case .DropUnknown, .DropBefore, .DropAfter:
          paintDropIndicator = true
      }
    }

    if paintDropIndicator {
      let bounds = calculateDropIndicatorBounds(item: dropItem!, position: dropPosition)
      let recorder = PaintRecorder(context: info.context, recordingSize: size)
      recorder.canvas.fillRect(rect: FloatRect(bounds), color: dropIndicatorColor)
    }
  }

  open override func getDropFormats(formats: inout Int, formatTypes: inout [ClipboardFormatType]) -> Bool {
    if let controller = menuItem?.controller {
      return controller.getDropFormats(source: self, formats: &formats, formatTypes: &formatTypes)
    }
    return false
  }

  open override func areDropTypesRequired() -> Bool {
    if let controller = menuItem?.controller {
      return controller.areDropTypesRequired(source: self)
    }
    return false
  }

  open override func canDrop(data: OSExchangeData) -> Bool {
    if let controller = menuItem?.controller {
      return controller.canDrop(source: self, data: data)
    }
    return false
  }

  open override func onMouseWheel(event: MouseWheelEvent) -> Bool {
    var visBounds = visibleBounds
    
    if visBounds.height == height || menuItemCount == 0 {
      // All menu items are visible, nothing to scroll.
      return true
    }

    // Find the index of the first menu item whose y-coordinate is >= visible
    // y-coordinate.
    var i = 0

    while (i < menuItemCount) && (getMenuItemAt(index: i)!.y < visBounds.y) {
      i += 1
    }

    if i == menuItemCount {
      return true
    }

    var firstVisIndex = max(0, (getMenuItemAt(index: i)!.y == visBounds.y) ? i : i - 1)

    // If the first item isn't entirely visible, make it visible, otherwise make
    // the next/previous one entirely visible. If enough wasn't scrolled to show
    // any new rows, then just scroll the amount so that smooth scrolling using
    // the trackpad is possible.
    let delta = abs(event.yOffset / MouseWheelEvent.wheelDelta)
    
    if delta == 0 {
      return onScroll(dx: 0, dy: Float(event.yOffset))
    }
    
    let scrollUp = event.yOffset > 0

    for _ in (0...delta).reversed() {
      var scrollTarget: Int
      if scrollUp {
        if getMenuItemAt(index: firstVisIndex)!.y == visBounds.y {
          if firstVisIndex == 0 {
            break
          }
          firstVisIndex -= 1
        }
        scrollTarget = getMenuItemAt(index: firstVisIndex)!.y
      } else {
        if firstVisIndex + 1 == menuItemCount {
          break
        }
        scrollTarget = getMenuItemAt(index: firstVisIndex + 1)!.y
        if getMenuItemAt(index: firstVisIndex)!.y == visBounds.y {
          firstVisIndex += 1
        }
      }
      scrollRectToVisible(rect: IntRect(origin: IntPoint(x: 0, y: scrollTarget), size: visBounds.size))
      visBounds = visibleBounds
    }

    return true
  }

  open override func onGestureEvent(event: inout GestureEvent) {
    var handled = true
    
    switch event.type {
      case .GestureScrollBegin:
        scrollAnimator!.stop()
      case .GestureScrollUpdate:
        handled = onScroll(dx: 0, dy: event.details.scrollY)
      case .GestureScrollEnd:
        break
      case .ScrollFlingStart:
        if event.details.velocityY != 0.0 {
          scrollAnimator!.start(velocityX: 0, velocityY: event.details.velocityY)
        }
      case .GestureTapDown, .ScrollFlingCancel:
        if scrollAnimator!.isScrolling {
           scrollAnimator!.stop()
        } else {
          handled = false
        }
      default:
        handled = false
    }

    if handled {
      event.handled = true
    }
  }

  public override func calculatePreferredSize() -> IntSize {
  
    if !hasChildren {
      return IntSize()
    }

    maxMinorTextWidth = 0
    // The maximum width of items which contain maybe a label and multiple views.
    var maxComplexWidth = 0
    // The max. width of items which contain a label and maybe an accelerator.
    var maxSimpleWidth = 0
    // The minimum width of touchable items.
    var touchableMinimumWidth = 0

    // We perform the size calculation in two passes. In the first pass, we
    // calculate the width of the menu. In the second, we calculate the height
    // using that width. This allows views that have flexible widths to adjust
    // accordingly.
    for i in 0..<childCount {
      let child = childAt(index: i)!
      if !child.isVisible {
        continue
      }
      if child.id == MenuItemView.menuItemViewID {
        let menu = child as! MenuItemView
        let dimensions = menu.dimensions
        maxSimpleWidth = max(maxSimpleWidth, dimensions.standardWidth);
        maxMinorTextWidth = max(maxMinorTextWidth, dimensions.minorTextWidth)
        maxComplexWidth = max(maxComplexWidth,
            dimensions.standardWidth + dimensions.childrenWidth)
        touchableMinimumWidth = dimensions.standardWidth
      } else {
        maxComplexWidth = max(maxComplexWidth, child.preferredSize.width)
      }
    }
    if maxMinorTextWidth > 0 {
      maxMinorTextWidth += MenuConfig.instance().labelToMinorTextPadding
    }

    // Finish calculating our optimum width.
    let ins = insets
    var width = max(maxComplexWidth, max(maxSimpleWidth + maxMinorTextWidth + ins.width,
      minimumPreferredWidth - 2 * ins.width))

    if let controller = menuItem?.controller {
      if controller.useTouchableLayout {
        width = max(touchableMinimumWidth, width)
      }
    }

    // Then, the height for that width.
    var height = 0
    let menuItemWidth = width - insets.width
    for i in 0..<childCount {
      let child = childAt(index: i)!
      height += child.isVisible ? child.getHeightFor(width: menuItemWidth) : 0
    }

    return IntSize(width: width, height: height + insets.height)
  }

  public override func onDragEntered(event: DropTargetEvent) {
    if let controller = menuItem?.controller {
      controller.onDragEntered(source: self, event: event)
    }
  }

  public override func onDragUpdated(event: DropTargetEvent) -> DragOperation {
    if let controller = menuItem?.controller {
      return controller.onDragUpdated(source: self, event: event)
    }
    return DragOperation.DragNone
  }

  public override func onDragExited() {
    if let controller = menuItem?.controller {
      controller.onDragExited(source: self)
    }
  }

  public override func onPerformDrop(event: DropTargetEvent) -> DragOperation {
    if let controller = menuItem?.controller {
      return controller.onPerformDrop(source: self, event: event)
    }
    return DragOperation.DragNone
  }

  public func onScroll(dx: Float, dy: Float) -> Bool {
    let visBounds: IntRect = visibleBounds
    let fullBounds = bounds
    let x = visBounds.x
    let yf: Float = Float(visBounds.y) - dy - roundoffError
    var y = yf.roundedInt
    roundoffError = Float(y) - yf
    // clamp y to [0, full_height - vis_height)
    y = min(y, fullBounds.height - visBounds.height - 1)
    y = max(y, 0)
    let newVisBounds = IntRect(x: x, y: y, width: visBounds.width, height: visBounds.height)
    if newVisBounds != visBounds {
      scrollRectToVisible(rect: newVisBounds)
      return true
    }
    return false
  }

  public func setSelectedRow(row: Int) {
    if let controller = menuItem?.controller {
      controller.setSelection(menuItem: getMenuItemAt(index: row), types: MenuController.SetSelectionTypes.SelectionDefault)
    }
  }
  
  public func getTextForRow(row: Int) -> String? {
    if let item = getMenuItemAt(index: row) {
      return item.title
    }
    return String()
  }

  fileprivate func skipDefaultKeyEventProcessing(e: KeyEvent) -> Bool {
    return FocusManager.isTabTraversalKeyEvent(keyEvent: e)
  }

  fileprivate func schedulePaintForDropIndicator(item menuItem: MenuItemView?, position: DropPosition) {
    guard let item = menuItem else {
      return
    }

    if position == DropPosition.DropOn {
      item.schedulePaint()
    } else if position != DropPosition.DropNone {
      schedulePaintInRect(rect: calculateDropIndicatorBounds(item: item, position: position))
    }
  }

  // Calculates the location of th edrop indicator.
  fileprivate func calculateDropIndicatorBounds(item: MenuItemView, position: DropPosition) -> IntRect {
    var itemBounds: IntRect = item.bounds
    
    switch position {
      case DropPosition.DropBefore:
        itemBounds.offset(horizontal: 0, vertical: -dropIndicatorHeight / 2)
        itemBounds.height = dropIndicatorHeight
        return itemBounds

      case DropPosition.DropAfter:
        itemBounds.offset(horizontal: 0, vertical: itemBounds.height - dropIndicatorHeight / 2)
        itemBounds.height = dropIndicatorHeight
        return itemBounds

      default:
        // Don't render anything for on.
        return IntRect()
    }
  }

}