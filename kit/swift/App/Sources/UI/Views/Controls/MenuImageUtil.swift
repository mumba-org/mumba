// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

// TODO: those are actually generated stuff

fileprivate let menuCheckIcon: VectorIcon = VectorIcon()
fileprivate let menuRadioSelectedIcon: VectorIcon = VectorIcon()
fileprivate let menuRadioEmptyIcon: VectorIcon = VectorIcon()
fileprivate let submenuArrowIcon: VectorIcon = VectorIcon()
fileprivate let menuCheckSize: Int = 1

public func getMenuCheckImage(iconColor: Color) -> ImageSkia {
  return Graphics.createVectorIcon(icon: menuCheckIcon, color: iconColor)
}

public func getRadioButtonImage(toggled: Bool,
                                hovered: Bool,
                                defaultIconColor: Color) -> ImageSkia {
  let icon: VectorIcon = toggled ? menuRadioSelectedIcon : menuRadioEmptyIcon
  let color: Color = toggled && !hovered ? Color.Blue : defaultIconColor
  return Graphics.createVectorIcon(icon: icon, dipSize: menuCheckSize, color: color)
}

public func getSubmenuArrowImage(iconColor: Color) -> ImageSkia {
  return Graphics.createVectorIcon(icon: submenuArrowIcon, color: iconColor)
}