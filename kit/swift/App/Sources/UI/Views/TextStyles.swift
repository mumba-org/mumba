// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public enum TextContext {
  case button
  case buttonMd
  case dialogTitle
  case label
  case messageBox
  case tableRow
  case textfield
  case touchMenu
}

public enum TextStyle {
  case primary
  case dialogButtonDefault
  case disabled
  case link
  case tabActive
  case tabHovered
  case tabInactive
}

public struct TextStyles {
 
  public static func getFont(context: TextContext, style: TextStyle) -> FontList {
    return FontList()
  }

  public static func getLineHeight(context: TextContext, style: TextStyle) -> Int {
    return 0
  }

  public static func getColor(view: View, context: TextContext, style: TextStyle) -> Color {
    return Color()
  }

}