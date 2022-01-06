// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

fileprivate let styleButtonTextColor: Color = Color.Black
fileprivate let styleButtonShadowColor: Color = Color.White

public struct PlatformStyle {

  public static let useRipples: Bool = true
  public static let returnClicksFocusedControl: Bool = true
  public static let keyClickActionOnSpace: Button.KeyClickAction = Button.KeyClickAction.ClickOnKeyRelease
  public static let textfieldScrollsToStartOnFocusChange: Bool = false
  public static let textfieldUsesDragCursorWhenDraggable: Bool = false
  public static let selectAllOnRightClickWhenUnfocused: Bool = false
  public static let selectWordOnRightClick: Bool = false
  public static let dialogDefaultButtonCanBeCancel: Bool = true
  public static let isOkButtonLeading: Bool = false

  public static func createThemedLabelButtonBorder(button: LabelButton) -> Border {
    return button.createDefaultBorder()
  }

  public static func applyLabelButtonTextStyle(
    label: inout Label,
    colors: inout [Color]) {
     
      colors[Button.State.Normal.rawValue] = styleButtonTextColor
      colors[Button.State.Hovered.rawValue] = styleButtonTextColor
      colors[Button.State.Pressed.rawValue] = styleButtonTextColor

      var shadowValue = ShadowValue()
      
      shadowValue.offset = FloatVec2(x: 0, y: 1)
      shadowValue.blur = 0
      shadowValue.color = styleButtonShadowColor

      var shadowValues = ShadowValues()
      shadowValues.append(shadowValue)
      
      label.shadows = shadowValues
  }

  public static func onTextfieldEditFailed() {}

}