// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Compositor

public protocol ThemeDelegate {

  var themePart: Theme.Part { get }
  var themePaintRect: IntRect { get }
  var themeAnimation: Animation? { get }

  func getThemeState(params: inout Theme.ExtraParams) -> Theme.State
  func getBackgroundThemeState(params: inout Theme.ExtraParams) -> Theme.State
  func getForegroundThemeState(params: inout Theme.ExtraParams) -> Theme.State
}

public class Theme {

  public enum State : Int {
    case Disabled = 0
    case Hovered  = 1
    case Normal   = 2
    case Pressed  = 3
  }

  public enum Part {
    case Checkbox
    case InnerSpinButton
    case MenuList
    case MenuPopupBackground
    case MenuPopupSeparator
    case MenuItemBackground
    case ProgressBar
    case PushButton
    case Radio

    case ScrollbarDownArrow
    case ScrollbarLeftArrow
    case ScrollbarRightArrow
    case ScrollbarUpArrow

    case ScrollbarHorizontalThumb
    case ScrollbarVerticalThumb
    case ScrollbarHorizontalTrack
    case ScrollbarVerticalTrack
    case ScrollbarHorizontalGripper
    case ScrollbarVerticalGripper
   
    case ScrollbarCorner
    case SliderTrack
    case SliderThumb
    case TabPanelBackground
    case TextField
    case TrackbarThumb
    case TrackbarTrack
    case WindowResizeGripper
  }

  public enum ColorId {
    // Windows
    case WindowBackground
    // Dialogs
    case DialogBackground
    case BubbleBackground
    // FocusableBorder
    case FocusedBorderColor
    case UnfocusedBorderColor
    // Button
    case ButtonEnabledColor
    case ButtonDisabledColor
    case ButtonHoverColor
    case ButtonPressedShade
    case BlueButtonEnabledColor
    case BlueButtonDisabledColor
    case BlueButtonPressedColor
    case BlueButtonHoverColor
    case BlueButtonShadowColor
    case ProminentButtonColor
    case TextOnProminentButtonColor
    // MenuItem
    case EnabledMenuItemForegroundColor
    case DisabledMenuItemForegroundColor
    case SelectedMenuItemForegroundColor
    case FocusedMenuItemBackgroundColor
    case MenuItemMinorTextColor
    case MenuSeparatorColor
    case MenuBackgroundColor
    case MenuBorderColor
    // Label
    case LabelEnabledColor
    case LabelDisabledColor
    case LabelTextSelectionColor
    case LabelTextSelectionBackgroundFocused
    // Link
    case LinkDisabled
    case LinkEnabled
    case LinkPressed
    // Separator
    case SeparatorColor
    // TabbedPane
    case TabTitleColorActive
    case TabTitleColorInactive
    case TabBottomBorder
    // Textfield
    case TextfieldDefaultColor
    case TextfieldDefaultBackground
    case TextfieldReadOnlyColor
    case TextfieldReadOnlyBackground
    case TextfieldSelectionColor
    case TextfieldSelectionBackgroundFocused
    // Tooltip
    case TooltipBackground
    case TooltipText
    // Tree
    case TreeBackground
    case TreeText
    case TreeSelectedText
    case TreeSelectedTextUnfocused
    case TreeSelectionBackgroundFocused
    case TreeSelectionBackgroundUnfocused
    // Table
    case TableBackground
    case TableText
    case TableSelectedText
    case TableSelectedTextUnfocused
    case TableSelectionBackgroundFocused
    case TableSelectionBackgroundUnfocused
    case TableGroupingIndicatorColor
    // Table Header
    case TableHeaderText
    case TableHeaderBackground
    case TableHeaderSeparator
    // Results Tables such as the omnibox.
    case ResultsTableNormalBackground
    case ResultsTableHoveredBackground
    case ResultsTableSelectedBackground
    case ResultsTableNormalText
    case ResultsTableHoveredText
    case ResultsTableSelectedText
    case ResultsTableNormalDimmedText
    case ResultsTableHoveredDimmedText
    case ResultsTableSelectedDimmedText
    case ResultsTableNormalUrl
    case ResultsTableHoveredUrl
    case ResultsTableSelectedUrl
    // Positive text refers to good (often rendered in green) text such as the
    // stock value went up.
    case ResultsTablePositiveText
    case ResultsTablePositiveHoveredText
    case ResultsTablePositiveSelectedText
    // Negative text refers to something alarming (often rendered in red) such
    // as the stock value went down.
    case ResultsTableNegativeText
    case ResultsTableNegativeHoveredText
    case ResultsTableNegativeSelectedText
    // Colors for the material spinner (aka throbber).
    case ThrobberSpinningColor
    case ThrobberWaitingColor
    case ThrobberLightColor
    // Colors for icons that alert e.g. upgrade reminders.
    case AlertSeverityLow
    case AlertSeverityMedium
    case AlertSeverityHigh
  }

  public struct ButtonExtraParams {
    public var checked: Bool = false
    public var indeterminate: Bool = true
    public var isDefault: Bool = false
    public var isFocused: Bool = false
    public var hasBorder: Bool = false
    public var classicState: Int = -1
    public var backgroundColor: Color = Color()
  }

  public struct FrameTopAreaExtraParams {
    public var isActive: Bool = false
    public var incognito: Bool = false
    public var useCustomFrame: Bool = false
    public var defaultBackgroundColor: Color = Color()
  }

  public struct InnerSpinButtonExtraParams {
    public var spinUp: Bool = false
    public var readOnly: Bool = false
    public var classicState: Int = 0
  }

  public struct MenuArrowExtraParams {
    public var pointingRight: Bool = false
    public var isSelected: Bool = false
  }

  public struct MenuCheckExtraParams {
    public var isRadio: Bool = false
    public var isSelected: Bool = false
  }

  public struct MenuSeparatorExtraParams {
    public var paintRect: IntRect?
    public var type: MenuSeparatorType = .NormalSeparator
  }

  public struct MenuItemExtraParams {
    public var isSelected: Bool = false
    public var cornerRadius: Int = 0
  }

  public struct MenuListExtraParams {
    public var hasBorder: Bool = false
    public var hasBorderRadius: Bool = false
    public var arrowX: Int = 0
    public var arrowY: Int = 0
    public var arrowSize: Int = 0
    public var arrowColor: Color = Color()
    public var backgroundColor: Color = Color()
    public var classicState: Int = 0
  }

  public struct MenuBackgroundExtraParams {
    public var cornerRadius: Int = 0
  }

  public struct ProgressBarExtraParams {
    public var animatedSeconds: Double = 0.0
    public var determinate: Bool = false
    public var valueRectX: Int = 0
    public var valueRectY: Int = 0
    public var valueRectWidth: Int = 0
    public var valueRectHeight: Int = 0
  }

  public struct ScrollbarArrowExtraParams {
    public var isHovering: Bool = false
  }

  public struct ScrollbarTrackExtraParams {
    public var isUpper: Bool = false
    public var trackX: Int = 0
    public var trackY: Int = 0
    public var trackWidth: Int = 0
    public var trackHeight: Int = 0
    public var classicState: Int = 0  // Used on Windows when uxtheme is not available.
  }

  public enum ScrollbarOverlayColorTheme {
    case Dark
    case Light
  }

  public struct ScrollbarThumbExtraParams {
    public var isHovering: Bool = false
    public var scrollbarTheme: ScrollbarOverlayColorTheme = .Light
  }

  public struct SliderExtraParams {
    public var vertical: Bool = false
    public var inDrag: Bool = false
  }

  public struct TextFieldExtraParams {
    public var isTextArea: Bool = false
    public var isListbox: Bool = false
    public var backgroundColor: Color = Color()
    public var isReadOnly: Bool = false
    public var isFocused: Bool = false
    public var fillContentArea: Bool = false
    public var drawEdges: Bool = false
    public var classicState: Int = 0
  }

  public struct TrackbarExtraParams {
    public var vertical: Bool = false
    public var classicState: Int = 0
  }

 // class: we dont want a pass-by-value in this case
  public class ExtraParams {
   
    public var button: ButtonExtraParams = ButtonExtraParams()
    public var frameTopArea: FrameTopAreaExtraParams = FrameTopAreaExtraParams()
    public var innerSpin: InnerSpinButtonExtraParams = InnerSpinButtonExtraParams()
    public var menuArrow: MenuArrowExtraParams = MenuArrowExtraParams()
    public var menuCheck: MenuCheckExtraParams = MenuCheckExtraParams()
    public var menuItem: MenuItemExtraParams = MenuItemExtraParams()
    public var menuSeparator: MenuSeparatorExtraParams = MenuSeparatorExtraParams()
    public var menuList: MenuListExtraParams = MenuListExtraParams()
    public var menuBackground: MenuBackgroundExtraParams = MenuBackgroundExtraParams()
    public var progressBar: ProgressBarExtraParams = ProgressBarExtraParams()
    public var scrollbarArrow: ScrollbarArrowExtraParams = ScrollbarArrowExtraParams()
    public var scrollbarTrack: ScrollbarTrackExtraParams = ScrollbarTrackExtraParams()
    public var scrollbarThumb: ScrollbarThumbExtraParams = ScrollbarThumbExtraParams()
    public var slider: SliderExtraParams = SliderExtraParams()
    public var textfield: TextFieldExtraParams = TextFieldExtraParams()
    public var trackbar: TrackbarExtraParams = TrackbarExtraParams()

    public init() {}
  }

  public class func instanceForNativeUi() -> Theme {
    if Theme._instance == nil {
      Theme._instance = Theme()
    }
    return Theme._instance!
  }

  public var usesHighContrastColors: Bool {
    return false
  }

  fileprivate static var _instance: Theme?

  var painter: ThemePainter
  var scrollbarButtonLength: Int = 0
  var scrollbarWidth: Int = 0

  public init() {
//#if os(Linux)
//    painter = ThemePainterLinux()
// #if os(Windows) etc...    
//#else
    painter = ThemePainterDefault()
//#endif
  }

  public init(painter: ThemePainter) {
    self.painter = painter
  }

  public func paint(canvas: PaintCanvas,
                    part: Part,
                    state: State,
                    rect: IntRect,
                    params extra: ExtraParams) {

    guard !rect.isEmpty else {
      return
    }

    let _ = canvas.save()
    canvas.clipRect(FloatRect(rect))

    switch part {
      case .Checkbox:
        painter.paintCheckbox(canvas: canvas, state: state, rect: rect, params: extra.button)
      case .InnerSpinButton:
        painter.paintInnerSpinButton(canvas: canvas, state: state, rect: rect, params: extra.innerSpin)
      case .MenuList:
        painter.paintMenuList(canvas: canvas, state: state, rect: rect, params: extra.menuList)
      case .MenuPopupBackground:
        painter.paintMenuPopupBackground(canvas: canvas, size: rect.size, params: extra.menuBackground)
      case .MenuPopupSeparator:
        painter.paintMenuSeparator(canvas: canvas, state: state, rect: rect, params: extra.menuSeparator)
      case .MenuItemBackground:
        painter.paintMenuItemBackground(canvas: canvas, state: state, rect: rect, params: extra.menuItem)
      case .ProgressBar:
        painter.paintProgressBar(canvas: canvas, state: state, rect: rect, params: extra.progressBar)
      case .PushButton:
        painter.paintButton(canvas: canvas, state: state, rect: rect, params: extra.button)
      case .Radio:
        painter.paintRadio(canvas: canvas, state: state, rect: rect, params: extra.button)
      case .ScrollbarDownArrow:
        fallthrough
      case .ScrollbarLeftArrow:
        fallthrough
      case .ScrollbarRightArrow:
        fallthrough
      case .ScrollbarUpArrow:
        if scrollbarButtonLength > 0 {
          painter.paintArrowButton(canvas: canvas, rect: rect, direction: part, state: state)
        }
      case .ScrollbarHorizontalThumb:
        fallthrough
      case .ScrollbarVerticalThumb:
        painter.paintScrollbarThumb(canvas: canvas, part: part, state: state, rect: rect, theme: extra.scrollbarThumb.scrollbarTheme)
      case .ScrollbarHorizontalTrack:
        fallthrough
      case .ScrollbarVerticalTrack:
        painter.paintScrollbarTrack(canvas: canvas, part: part, state: state, params: extra.scrollbarTrack, rect: rect)
      case .ScrollbarHorizontalGripper:
        break    
      case .ScrollbarVerticalGripper:
        break
      case .ScrollbarCorner:
        painter.paintScrollbarCorner(canvas: canvas, state: state, rect: rect)
      case .SliderTrack:
        painter.paintSliderTrack(canvas: canvas, state: state, rect: rect, params: extra.slider)
      case .SliderThumb:
        painter.paintSliderThumb(canvas: canvas, state: state, rect: rect, params: extra.slider)
      case .TabPanelBackground:
        break
      case .TextField:
        painter.paintTextField(canvas: canvas, state: state, rect: rect, params: extra.textfield)
      case .TrackbarThumb:
        break
      case .TrackbarTrack:
        break
      case .WindowResizeGripper:
        break
    }

    canvas.restore()
  }

  public func getSystemColor(id: ColorId) -> Color {
    // TODO: implement
    let defaultColor = Color.White
    switch id {
      case .WindowBackground:
        return defaultColor
      case .DialogBackground:
        return defaultColor
      case .BubbleBackground:
        return defaultColor
      case .FocusedBorderColor:
        return defaultColor
      case .UnfocusedBorderColor:
        return defaultColor
      case .ButtonEnabledColor:
        return defaultColor
      case .ButtonDisabledColor:
        return defaultColor
      case .ButtonHoverColor:
        return defaultColor
      case .ButtonPressedShade:
        return defaultColor
      case .BlueButtonEnabledColor:
        return defaultColor
      case .BlueButtonDisabledColor:
        return defaultColor
      case .BlueButtonPressedColor:
        return defaultColor
      case .BlueButtonHoverColor:
        return defaultColor
      case .BlueButtonShadowColor:
        return defaultColor
      case .ProminentButtonColor:
        return defaultColor
      case .TextOnProminentButtonColor:
        return defaultColor
      case .EnabledMenuItemForegroundColor:
        return defaultColor
      case .DisabledMenuItemForegroundColor:
        return defaultColor
      case .SelectedMenuItemForegroundColor:
        return defaultColor
      case .FocusedMenuItemBackgroundColor:
        return defaultColor
      case .MenuItemMinorTextColor:
        return defaultColor
      case .MenuSeparatorColor:
        return defaultColor
      case .MenuBackgroundColor:
        return defaultColor
      case .MenuBorderColor:
        return defaultColor
      case .LabelEnabledColor:
        return defaultColor
      case .LabelDisabledColor:
        return defaultColor
      case .LabelTextSelectionColor:
        return defaultColor
      case .LabelTextSelectionBackgroundFocused:
        return defaultColor
      case .LinkDisabled:
        return defaultColor
      case .LinkEnabled:
        return defaultColor
      case .LinkPressed:
        return defaultColor
      case .SeparatorColor:
        return defaultColor
      case .TabTitleColorActive:
        return defaultColor
      case .TabTitleColorInactive:
        return defaultColor
      case .TabBottomBorder:
        return defaultColor
      case .TextfieldDefaultColor:
        return defaultColor
      case .TextfieldDefaultBackground:
        return defaultColor
      case .TextfieldReadOnlyColor:
        return defaultColor
      case .TextfieldReadOnlyBackground:
        return defaultColor
      case .TextfieldSelectionColor:
        return defaultColor
      case .TextfieldSelectionBackgroundFocused:
        return defaultColor
      case .TooltipBackground:
        return defaultColor
      case .TooltipText:
        return defaultColor
      case .TreeBackground:
        return defaultColor
      case .TreeText:
        return defaultColor
      case .TreeSelectedText:
        return defaultColor
      case .TreeSelectedTextUnfocused:
        return defaultColor
      case .TreeSelectionBackgroundFocused:
        return defaultColor
      case .TreeSelectionBackgroundUnfocused:
        return defaultColor
      case .TableBackground:
        return defaultColor
      case .TableText:
        return defaultColor
      case .TableSelectedText:
        return defaultColor
      case .TableSelectedTextUnfocused:
        return defaultColor
      case .TableSelectionBackgroundFocused:
        return defaultColor
      case .TableSelectionBackgroundUnfocused:
        return defaultColor
      case .TableGroupingIndicatorColor:
        return defaultColor
      case .TableHeaderText:
        return defaultColor
      case .TableHeaderBackground:
        return defaultColor
      case .TableHeaderSeparator:
        return defaultColor
      case .ResultsTableNormalBackground:
        return defaultColor
      case .ResultsTableHoveredBackground:
        return defaultColor
      case .ResultsTableSelectedBackground:
        return defaultColor
      case .ResultsTableNormalText:
        return defaultColor
      case .ResultsTableHoveredText:
        return defaultColor
      case .ResultsTableSelectedText:
        return defaultColor
      case .ResultsTableNormalDimmedText:
        return defaultColor
      case .ResultsTableHoveredDimmedText:
        return defaultColor
      case .ResultsTableSelectedDimmedText:
        return defaultColor
      case .ResultsTableNormalUrl:
        return defaultColor
      case .ResultsTableHoveredUrl:
        return defaultColor
      case .ResultsTableSelectedUrl:
        return defaultColor
      case .ResultsTablePositiveText:
        return defaultColor
      case .ResultsTablePositiveHoveredText:
        return defaultColor
      case .ResultsTablePositiveSelectedText:
        return defaultColor
      case .ResultsTableNegativeText:
        return defaultColor
      case .ResultsTableNegativeHoveredText:
        return defaultColor
      case .ResultsTableNegativeSelectedText:
        return defaultColor
      case .ThrobberSpinningColor:
        return defaultColor
      case .ThrobberWaitingColor:
        return defaultColor
      case .ThrobberLightColor:
        return defaultColor
      case .AlertSeverityLow:
        return defaultColor
      case .AlertSeverityMedium:
        return defaultColor
      case .AlertSeverityHigh:
        return defaultColor
    }
  }

}