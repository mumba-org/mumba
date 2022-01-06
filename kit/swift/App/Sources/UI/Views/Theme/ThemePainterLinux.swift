// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Compositor

public class ThemePainterLinux : ThemePainter {
  
  public init() {}

  public func paintArrow(
    canvas: PaintCanvas,
    rect: IntRect,
    direction: Theme.Part,
    color: Color) {

  }

  public func paintArrowButton(
    canvas: PaintCanvas,
    rect: IntRect,
    direction: Theme.Part,
    state: Theme.State) {

  }

  public func paintCheckbox(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.ButtonExtraParams) {}
  public func paintInnerSpinButton(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.InnerSpinButtonExtraParams) {}
  public func paintMenuList(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.MenuListExtraParams) {}
  public func paintMenuPopupBackground(canvas: PaintCanvas, size: IntSize, params: Theme.MenuBackgroundExtraParams) {}
  public func paintMenuSeparator(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.MenuSeparatorExtraParams) {}
  public func paintMenuItemBackground(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.MenuItemExtraParams) {}
  public func paintProgressBar(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.ProgressBarExtraParams) {}
  public func paintButton(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.ButtonExtraParams) {}
  public func paintRadio(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.ButtonExtraParams) {}
  public func paintScrollbarThumb(canvas: PaintCanvas, part: Theme.Part, state: Theme.State, rect: IntRect, theme: Theme.ScrollbarOverlayColorTheme) {}
  public func paintScrollbarTrack(canvas: PaintCanvas, part: Theme.Part, state: Theme.State, params: Theme.ScrollbarTrackExtraParams, rect: IntRect) {}
  public func paintScrollbarCorner(canvas: PaintCanvas, state: Theme.State, rect: IntRect) {}
  public func paintSliderTrack(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.SliderExtraParams) {}
  public func paintSliderThumb(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.SliderExtraParams) {}
  public func paintTextField(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.TextFieldExtraParams) {}

}