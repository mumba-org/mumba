// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

fileprivate let SeparatorId: Int = -1

public protocol MenuModelDelegate : class {
  func onIconChanged(index: Int)
  func onMenuStructureChanged()
}


public enum MenuModelItemType {
    case Command
    case Check
    case Radio
    case Separator
    case ButtonItem
    case Submenu
}

public protocol MenuModel {

  var menuModelDelegate: MenuModelDelegate? {
    get
    set
  }

  var hasIcons: Bool {
    get
  }

  // Returns the number of items in the menu.
  var itemCount: Int {
    get
  }

  // Returns the type of item at the specified index.
  func getType(at: Int) -> MenuModelItemType?

  // Returns the separator type at the specified index.
  func getSeparatorType(at: Int) -> MenuSeparatorType?

  // Returns the command id of the item at the specified index.
  func getCommandId(at: Int) -> Int?

  // Returns the label of the item at the specified index.
  func getLabel(at: Int) -> String?

  // Returns the sublabel of the item at the specified index. The sublabel
  // is rendered beneath the label and using the font GetLabelFontAt().
  func getSublabel(at: Int) -> String?

  // Returns the minor text of the item at the specified index. The minor text
  // is rendered to the right of the label and using the font GetLabelFontAt().
  func getMinorText(at: Int) -> String?

  // Returns the minor icon of the item at the specified index. The minor icon
  // is rendered to the left of the minor text.
  func getMinorIcon(at: Int) -> VectorIcon?

  // Returns true if the menu item (label/sublabel/icon) at the specified
  // index can change over the course of the menu's lifetime. If this function
  // returns true, the label, sublabel and icon of the menu item will be
  // updated each time the menu is shown.
  func isItemDynamic(at: Int) -> Bool?

  // Returns the font list used for the label at the specified index.
  // If NULL, then the default font list should be used.
  func getLabelFontList(at: Int) -> FontList?

  // Gets the accelerator information for the specified index, returning true if
  // there is a shortcut accelerator for the item, false otherwise.
  func getAccelerator(at: Int) -> Accelerator?

  // Returns the checked state of the item at the specified index.
  func isItemChecked(at: Int) -> Bool?

  // Returns the id of the group of radio items that the item at the specified
  // index belongs to.
  func getGroupId(at: Int) -> Int?

  // Gets the icon for the item at the specified index, returning true if there
  // is an icon, false otherwise.
  func getIcon(at: Int) -> Image?

  // Returns the model for a menu item with a line of buttons at |index|.
  func getButtonMenuItem(at: Int) -> ButtonMenuItemModel?

  // Returns the enabled state of the item at the specified index.
  func isEnabled(at: Int) -> Bool?

  // Returns true if the menu item is visible.
  func isVisible(at: Int) -> Bool?

  // Returns the model for the submenu at the specified index.
  func getSubmenuModel(at: Int) -> MenuModel?

  // Called when the highlighted menu item changes to the item at the specified
  // index.
  func highlightChangedTo(index: Int)

  // Called when the item at the specified index has been activated.
  func activated(at: Int)

  // Called when the item has been activated with given event flags.
  // (for the case where the activation involves a navigation).
  // |event_flags| is a bit mask of ui::EventFlags.
  func activated(at: Int, eventFlags: Int)

  // Called when the menu is about to be shown.
  func menuWillShow()

  // Called when the menu is about to be closed. The MenuRunner, and |this|
  // should not be deleted here.
  func menuWillClose()

  static func getModelAndIndexForCommandId(commandId: Int,
                                           model: inout MenuModel,
                                           index: inout Int) -> Bool
}

extension MenuModel {

  public static func getModelAndIndexForCommandId(commandId: Int,
                                           model: inout MenuModel,
                                           index: inout Int) -> Bool {
    return false
  }

}

public protocol SimpleMenuModelDelegate : MenuModelDelegate, AcceleratorProvider {
    
  func isCommandIdChecked(commandId: Int) -> Bool  
  func isCommandIdEnabled(commandId: Int) -> Bool
  func isCommandIdVisible(commandId: Int) -> Bool
  func isItemForCommandIdDynamic(commandId: Int) -> Bool
  func getLabelForCommandId(commandId: Int) -> String
  func getSublabelForCommandId(commandId: Int) -> String
  func getMinorTextForCommandId(commandId: Int) -> String
  func getIconForCommandId(commandId: Int) -> Image?
  func commandIdHighlighted(commandId: Int)
  func executeCommand(commandId: Int, eventFlags: Int)
  func menuWillShow(source: SimpleMenuModel)
  func menuClosed(source: SimpleMenuModel)
}

extension SimpleMenuModelDelegate {

  public func isCommandIdVisible(commandId: Int) -> Bool {
    return true
  }

  public func isItemForCommandIdDynamic(commandId: Int) -> Bool {
    return false
  }
  
  public func getLabelForCommandId(commandId: Int) -> String {
    return String()
  }
  
  public func getSublabelForCommandId(commandId: Int) -> String {
    return String()
  }
  
  public func getMinorTextForCommandId(commandId: Int) -> String {
    return String()
  }

  public func getIconForCommandId(commandId: Int) -> Image? {
    return nil
  }

  public func commandIdHighlighted(commandId: Int) {
  
  }

  public func menuWillShow(source: SimpleMenuModel) {
  
  }
  
  public func menuClosed(source: SimpleMenuModel) {
  
  }

  public func getAcceleratorForCommandId(
      commandId: Int) -> Accelerator? {
    return nil
  }
}

public struct MenuConfig {
  
  static var _instance: MenuConfig?

  var fontList: FontList = FontList()

  // Color for the arrow to scroll bookmarks.
  var arrowColor: Color = Color()

  // Menu border sizes.
  var menuVerticalBorderSize: Int = 0
  var menuHorizontalBorderSize: Int = 0

  // Submenu horizontal inset with parent menu. This is the horizontal overlap
  // between the submenu and its parent menu, not including the borders of
  // submenu and parent menu.
  var submenuHorizontalInset: Int = 0

  // Margins between the top of the item and the label.
  var itemTopMargin: Int = 0

  // Margins between the bottom of the item and the label.
  var itemBottomMargin: Int = 0

  // Margins used if the menu doesn't have icons.
  var itemNoIconTopMargin: Int = 0
  var itemNoIconBottomMargin: Int = 0

  // Margins between the left of the item and the icon.
  var itemLeftMargin: Int = 0

  // Margins between the left of the touchable item and the icon.
  var touchableItemLeftMargin: Int = 0
  
  var touchableMenuShadowElevation: Int = 0
  
  // Padding between the label and submenu arrow.
  var labelToArrowPadding: Int = 0

  // Padding between the arrow and the edge.
  var arrowToEdgePadding: Int = 0

  // Padding between the icon and label.
  var iconToLabelPadding: Int = 0

  // Padding between the icon and label for touchable menu items.
  var touchableIconToLabelPadding: Int = 0

  // The icon size used for icons in touchable menu items.
  var touchableIconSize: Int = 0

  // The color used for icons in touchable menu items.
  var touchableIconColor: Color = Color()

  // The space reserved for the check. The actual size of the image may be
  // different.
  var checkWidth: Int = 0
  var checkHeight: Int = 0

  // The horizontal space reserved for submenu arrow. The actual width of the
  // image may be different.
  var arrowWidth: Int = 0

  // Height of a normal separator (ui::NORMAL_SEPARATOR).
  var separatorHeight: Int = 0

  // Height of a ui::UPPER_SEPARATOR.
  var separatorUpperHeight: Int = 0

  // Height of a ui::LOWER_SEPARATOR.
  var separatorLowerHeight: Int = 0

  // Height of a ui::SPACING_SEPARATOR.
  var separatorSpacingHeight: Int = 0

  // Thickness of the drawn separator line in pixels.
  var separatorThickness: Int = 0

  // Are mnemonics shown?
  var showMnemonics: Bool = false

  // Height of the scroll arrow.
  var scrollArrowHeight: Int = 0

  // Padding between the label and minor text. Only used if there is an
  // accelerator or sublabel.
  var labelToMinorTextPadding: Int = 0

  // Minimum height of menu item.
  var itemMinHeight: Int = 0

  // Whether the keyboard accelerators are visible.
  var showAccelerators: Bool = false

  // True if icon to label padding is always added with or without icon.
  var alwaysUseIconToLabelPadding: Bool = false

  // True if submenu arrow and shortcut right edge should be aligned.
  var alignArrowAndShortcut: Bool = false

  // True if the context menu's should be offset from the cursor position.
  var offsetContextMenus: Bool = false

  // True if the scroll container should add a border stroke around the menu.
  var useOuterBorder: Bool = false

  // True if the icon is part of the label rather than in its own column.
  var iconsInLabel: Bool = false

  // True if a combobox menu should put a checkmark next to the selected item.
  var checkSelectedComboboxItem: Bool = false

  // Delay, in ms, between when menus are selected or moused over and the menu
  // appears.
  var showDelay: Int = 0

  // Radius of the rounded corners of the menu border. Must be >= 0.
  var cornerRadius: Int = 0

  // Radius of the rounded corners of the touchable menu border
  var touchableCornerRadius: Int = 0

  // Height of child MenuItemViews for touchable menus.
  var touchableMenuHeight: Int = 0

  // Width of touchable menus.
  var touchableMenuWidth: Int = 0

  // Vertical padding for touchable menus.
  var verticalTouchableMenuItemPadding: Int = 0

  static func instance() -> MenuConfig {
    if MenuConfig._instance == nil {
      MenuConfig._instance = MenuConfig()
    }
    return MenuConfig._instance!
  }

  public init() {}
}

public protocol ButtonMenuItemModelDelegate : class, AcceleratorProvider {
  func isItemForCommandIdDynamic(commandId: Int) -> Bool
  func getLabelForCommandId(commandId: Int) -> String
  func executeCommand(commandId: Int, eventFlags: Int)
  func isCommandIdEnabled(commandId: Int) -> Bool
  func doesCommandIdDismissMenu(commandId: Int) -> Bool
}

extension ButtonMenuItemModelDelegate {
  public func isItemForCommandIdDynamic(commandId: Int) -> Bool { return false }
  public func getLabelForCommandId(commandId: Int) -> String { return String() }
  public func executeCommand(commandId: Int, eventFlags: Int) {}
  public func isCommandIdEnabled(commandId: Int) -> Bool { return false }
  public func doesCommandIdDismissMenu(commandId: Int) -> Bool { return false }
  public func getAcceleratorForCommandId(commandId: Int) -> Accelerator? {
    return nil
  }
}

public class ButtonMenuItemModel {

  public enum ButtonType {
    case Space
    case Button
    case ButtonLabel
  }

  public struct Item {
    var commandId: Int
    var type: ButtonType
    var label: String
    var iconIdr: Int
    var partOfGroup: Bool
  }

  // The non-clickable label to the left of the buttons.
  public private(set) var label: String

  // Returns the number of items for iteration.
  public var itemCount: Int {
    return items.count
  }
  
  private var items: [Item]

  private let delegate: ButtonMenuItemModelDelegate?

  public init(stringId: Int, delegate: ButtonMenuItemModelDelegate?) {
    self.delegate = delegate
    self.label = l10n.getStringUTF16(stringId)
    items = []
  }

  public func addGroupItemWithStringId(commandId: Int, stringId: Int) {
    
    let item = Item (
      commandId: commandId, 
      type: .Button, 
      label: l10n.getStringUTF16(stringId), 
      iconIdr: -1, 
      partOfGroup: true)

    items.append(item)
  }

  // Adds a button that has an icon instead of a label.
  public func addItemWithImage(commandId: Int, iconIdr: Int) {
    let item = Item (
      commandId: commandId, 
      type: .Button, 
      label: String(), 
      iconIdr: iconIdr, 
      partOfGroup: false)

    items.append(item)
  }

  // Adds a non-clickable button with a desensitized label that doesn't do
  // anything. Usually combined with IsItemForCommandIdDynamic() to add
  // information.
  public func addButtonLabel(commandId: Int, stringId: Int) {
    let item = Item (
      commandId: commandId,
      type: .ButtonLabel, 
      label: l10n.getStringUTF16(stringId),
      iconIdr: -1, 
      partOfGroup: false)

    items.append(item)
  }

  // Adds a small horizontal space.
  public func addSpace() {
    let item = Item (
      commandId: 0,
      type: .Space, 
      label: String(),
      iconIdr: -1, 
      partOfGroup: false)

    items.append(item)
  }

  // Returns what kind of item is at |index|.
  public func getType(at index: Int) -> ButtonType? {
    return items[index].type
  }

  // Changes a position into a command ID.
  public func getCommandId(at index: Int) -> Int? {
    return items[index].commandId
  }

  // Whether the label for item |index| changes.
  public func isItemDynamic(at index: Int) -> Bool? {
     if let d = delegate {
      if let commandId = getCommandId(at: index) {
        return d.isItemForCommandIdDynamic(commandId: commandId)
      }
    }
    return false
  }

  // Gets the accelerator information for the specified index, returning true if
  // there is a shortcut accelerator for the item, false otherwise.
  public func getAccelerator(at index: Int) -> Accelerator? {
    if let d = delegate {
      if let commandId = getCommandId(at: index) {
        return d.getAcceleratorForCommandId(commandId: commandId)
      }
    }
    return nil
  }

  // Returns the current label value for the button at |index|.
  public func getLabel(at index: Int) -> String? {
    if let d = delegate {
      if let isDynamic = isItemDynamic(at: index) {
        if isDynamic {
          return d.getLabelForCommandId(commandId: getCommandId(at: index)!)
        }
      }
    }
    return items[index].label
  }

  // If the button at |index| should have an icon instead, returns true and
  // sets the IDR |icon|.
  public func getIcon(at index: Int) -> Int? {
    
    let item = items[index]

    if item.iconIdr == -1 {
      return nil
    }
    
    return item.iconIdr
  }

  // If the button at |index| should have its size equalized along with all
  // other items that have their PartOfGroup bit set.
  public func partOfGroup(at index: Int) -> Bool? {
    return items[index].partOfGroup
  }
  
  // Called when the item at the specified index has been activated.
  public func activated(at index: Int) {
    if let d = delegate {
      d.executeCommand(commandId: getCommandId(at: index)!, eventFlags: 0)
    }
  }

  // Returns the enabled state of the button at |index|.
  public func isEnabled(at index: Int) -> Bool? {
    let item = items[index]
    return isCommandIdEnabled(commandId: item.commandId)
  }
  
  // Returns whether clicking on the button at |index| dismisses the menu.
  public func dismissesMenu(at index: Int) -> Bool {
    let item = items[index]
    return doesCommandIdDismissMenu(commandId: item.commandId)
  }
  
  // Returns the enabled state of the command specified by |command_id|.
  public func isCommandIdEnabled(commandId: Int) -> Bool {
    if let d = delegate {
      return d.isCommandIdEnabled(commandId: commandId)
    }
    return true
  }
  
  // Returns whether clicking on |command_id| dismisses the menu.
  public func doesCommandIdDismissMenu(commandId: Int) -> Bool {
    if let d = delegate {
      return d.doesCommandIdDismissMenu(commandId: commandId)
    }
    return true
  }

}

public class SimpleMenuModel : MenuModel {
  
  public struct Item {
    public var commandId: Int = 0
    public var type: MenuModelItemType = .Command
    public var label: String
    public var sublabel: String = String()
    public var minorText: String = String()
    public var minorIcon: VectorIcon?
    public var icon: ImageSkia = ImageSkia()
    public var groupId: Int = -1
    public var submenu: MenuModel?
    public var buttonModel: ButtonMenuItemModel?
    public var separatorType: MenuSeparatorType = .NormalSeparator

    public init(commandId: Int, type: MenuModelItemType, label: String) {
       self.label = label
       self.commandId = commandId
       self.type = type
    }
  }

  public weak var delegate: SimpleMenuModelDelegate?

  public weak var menuModelDelegate: MenuModelDelegate?

  public var hasIcons: Bool {
    for item in items {
      if !item.icon.isEmpty {
        return true
      }
    }
    return false
  }

  public var itemCount: Int {
    return items.count
  }

  public var items: [Item]
  
  public init (delegate: SimpleMenuModelDelegate?) {
    self.delegate = delegate
    items = []
  }

  // Methods for adding items to the model.
  public func addItem(_ commandId: Int, label: String) {
    appendItem(Item(commandId: commandId, type: .Command, label: label))
  }
  
  public func addItem(_ commandId: Int, stringId: Int) {
    addItem(commandId, label: l10n.getStringUTF16(stringId))
  }
  
  public func addCheckItem(_ commandId: Int, label: String) {
    appendItem(Item(commandId: commandId, type: .Check, label: label))
  }
  
  public func addCheckItem(_ commandId: Int, stringId: Int) {
    addCheckItem(commandId, label: l10n.getStringUTF16(stringId))
  } 
 
  public func addRadioItem(_ commandId: Int, label: String, groupId: Int) {
    var item = Item(commandId: commandId, type: .Radio, label: label)
    item.groupId = groupId
    appendItem(item)
  }
  
  public func addRadioItem(_ commandId: Int, stringId: Int, groupId: Int) {
    addRadioItem(commandId, label: l10n.getStringUTF16(stringId), groupId: groupId)
  }

  // Adds a separator of the specified type to the model.
  // - Adding a separator after another separator is always invalid if they
  //   differ in type, but silently ignored if they are both NORMAL.
  // - Adding a separator to an empty model is invalid, unless they are NORMAL
  //   or SPACING. NORMAL separators are silently ignored if the model is empty.
  public func addSeparator(separatorType: MenuSeparatorType) {
    if items.isEmpty {
      if separatorType == .NormalSeparator {
        return
      }
      //assert(.SpacingSeparator, separatorType)
    } else if items.last!.type == .Separator {
      //assert(.NormalSeparator == separatorType)
      //assert(.NormalSeparator == items.last!.separatorType)
      return
    }
    var item = Item(commandId: SeparatorId, type: .Separator, label: String())
    item.separatorType = separatorType
    appendItem(item)
  }

  // These three methods take pointers to various sub-models. These models
  // should be owned by the same owner of this SimpleMenuModel.
  public func addButtonItem(_ commandId: Int, model: ButtonMenuItemModel) {
    var item = Item(commandId: commandId, type: .ButtonItem, label: String())
    item.buttonModel = model
    appendItem(item)
  }
  
  public func addSubMenu(_ commandId: Int,
                         label: String,
                         model: MenuModel) {
    var item = Item(commandId: commandId, type: .Submenu, label: label)
    item.submenu = model
    appendItem(item)
  }
  
  public func addSubMenu(_ commandId: Int, stringId: Int , model: MenuModel) {
    addSubMenu(commandId, label: l10n.getStringUTF16(stringId), model: model)
  }

  // Methods for inserting items into the model.
  public func insertItem(at: Int, commandId: Int, label: String) {
    insertItem(Item(commandId: commandId, type: .Command, label: label), at: at)
  }
  
  public func insertItem(at: Int, commandId: Int, stringId: Int) {
    insertItem(at: at, commandId: commandId, label: l10n.getStringUTF16(stringId))
  }
  
  public func insertSeparator(at: Int, separatorType: MenuSeparatorType) {
    var item = Item(commandId: SeparatorId, type: .Separator, label: String())
    item.separatorType = separatorType
    insertItem(item, at: at)
  }
  
  public func insertCheckItem(
                         at: Int,
                         commandId: Int,
                         label: String) {
    insertItem(Item(commandId: commandId, type: .Check, label: label), at: at)
  }
  
  public func insertCheckItem(at: Int, commandId: Int, stringId: Int) {
    insertCheckItem(at: at, commandId: commandId, label: l10n.getStringUTF16(stringId))
  }
  
  public func insertRadioItem(at: Int,
                         commandId: Int,
                         label: String,
                         groupId: Int) {
    var item = Item(commandId: commandId, type: .Radio, label: label)
    item.groupId = groupId
    insertItem(item, at: at) 
  }
  
  public func insertRadioItem(
      at: Int, commandId: Int, stringId: Int, groupId: Int) {
    insertRadioItem(
      at: at, commandId: commandId, label: l10n.getStringUTF16(stringId), groupId: groupId)
  }
  
  public func insertSubMenu(at: Int,
                       commandId: Int,
                       label: String,
                       model: MenuModel) {
    var item = Item(commandId: commandId, type: .Submenu, label: label)
    item.submenu = model
    insertItem(item, at: at)
  }
  
  public func insertSubMenu(
      at: Int, commandId: Int, stringId: Int, model: MenuModel) {
    insertSubMenu(at: at, commandId: commandId, label: l10n.getStringUTF16(stringId),
                  model: model)
  }

  // Remove item at specified index from the model.
  public func removeItem(at: Int) {
    items.remove(at: at)//validateItemIndex(at))
    menuItemsChanged()
  }

  // Sets the icon for the item at |index|.
  public func setIcon(at: Int, icon: ImageSkia) {
    var it = items[at]
    it.icon = icon
    menuItemsChanged()
  }

  // Sets the sublabel for the item at |index|.
  public func setSublabel(at: Int, sublabel: String) {
    var it = items[at]
    it.sublabel = sublabel
    menuItemsChanged()
  }

  // Sets the minor text for the item at |index|.
  public func setMinorText(at: Int, minorText: String) {
    var it = items[at]
    it.minorText = minorText
    menuItemsChanged()
  }

  // Sets the minor icon for the item at |index|.
  public func setMinorIcon(at: Int, minorIcon: VectorIcon) {
    var it = items[at]
    it.minorIcon = minorIcon
    menuItemsChanged()
  }

  // Clears all items. Note that it does not free MenuModel of submenu.
  public func clear() {
    items.removeAll()
    menuItemsChanged()
  }

  // Returns the index of the item that has the given |command_id|. Returns
  // -1 if not found.
  public func getIndexOfCommandId(_ commandId: Int) -> Int {
    for (i, item) in items.enumerated() {
      if item.commandId == commandId {
        return i
      }
    }
    return -1
  }

  public func getType(at: Int) -> MenuModelItemType? {
    return items[at].type
  }

  public func getSeparatorType(at: Int) -> MenuSeparatorType? {
    return items[at].separatorType
  }

  public func getCommandId(at: Int) -> Int? {
    return items[at].commandId
  }

  public func getLabel(at: Int) -> String? {
    return items[at].label
  }

  public func getSublabel(at: Int) -> String? {
    return items[at].sublabel
  }

  public func getMinorText(at: Int) -> String? {
    return items[at].minorText
  }

  public func getMinorIcon(at: Int) -> VectorIcon? {
    return items[at].minorIcon
  }

  public func isItemDynamic(at: Int) -> Bool? {
    if let d = delegate {
      return d.isItemForCommandIdDynamic(commandId: getCommandId(at: at)!)
    }
    return false
  }

  public func getLabelFontList(at: Int) -> FontList? {
    return nil
  }


  public func getAccelerator(at: Int) -> Accelerator? {
    if let d = delegate {
      return d.getAcceleratorForCommandId(commandId: getCommandId(at: at)!)
    }
    return nil
  }

  public func isItemChecked(at index: Int) -> Bool? {
    if let d = delegate {
      if let itemType: MenuModelItemType = getType(at: index) {
        if itemType == .Check || itemType == .Radio {
          return d.isCommandIdChecked(commandId: getCommandId(at: index)!)
        }
      }
    }
    return nil
  }

  public func getGroupId(at: Int) -> Int? {
    return items[at].groupId    
  }

  public func getIcon(at: Int) -> Image? {
    if let d = delegate {
      if let dyn = isItemDynamic(at: at) {
        if dyn {
          return d.getIconForCommandId(commandId: getCommandId(at: at)!)
        }
      }
    }

    let item = items[at]

    if item.icon.isEmpty {
      return nil
    }

    return item.icon
  }

  public func getButtonMenuItem(at: Int) -> ButtonMenuItemModel? {
    return items[at].buttonModel
  }

  public func isEnabled(at: Int) -> Bool? {
    guard let commandId = getCommandId(at: at) else {
      return nil
    }
 
    if let d = delegate {
      return d.isCommandIdEnabled(commandId: commandId)
    }

    if commandId == SeparatorId || getButtonMenuItem(at: at) != nil {
      return true
    }

    return nil
  }

  public func isVisible(at: Int) -> Bool? {
    guard let commandId = getCommandId(at: at) else {
      return nil
    }
 
    if let d = delegate {
      return d.isCommandIdVisible(commandId: commandId)
    }

    if commandId == SeparatorId || getButtonMenuItem(at: at) != nil {
      return true
    }

    return nil
  }

  public func getSubmenuModel(at: Int) -> MenuModel? {
     return items[at].submenu
  }

  public func highlightChangedTo(index at: Int) {
    if let d = delegate {
      if let commandId = getCommandId(at: at) {
        d.commandIdHighlighted(commandId: commandId)
      }
    }
  }

  public func activated(at: Int) {
    activated(at: at, eventFlags: 0)
  }

  public func activated(at: Int, eventFlags: Int) {
    if let d = delegate {
      if let commandId = getCommandId(at: at) {
        // recordHistogram(commandId)
        d.executeCommand(commandId: commandId, eventFlags: eventFlags)
      }
    }
   }

  public func menuWillShow() {
    if let d = delegate {
      d.menuWillShow(source: self)
    }
  }

  public func menuWillClose() {
    // TODO: should be async and posted to another/same thread
    if let d = delegate {
      d.menuClosed(source: self)
    }
  }

  func menuItemsChanged() {}

  // Functions for inserting items into |items_|.
  func appendItem(_ item: Item) {
    items.append(item)
    menuItemsChanged()
  }
  
  func insertItem(_ item: Item, at: Int) {
    items.insert(item, at: at)
    menuItemsChanged()
  }
  
  //fileprivate func validateItem(_ item: Item) {
  //}

  // Notify the delegate that the menu is closed.
  // fileprivate func onMenuClosed() {
  // }

}