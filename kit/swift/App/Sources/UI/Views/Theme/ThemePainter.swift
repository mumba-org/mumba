// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Compositor

// the specific implementation that will paint the themed components
// like windows, android, etc..
public protocol ThemePainter : class {

  func paintArrow(canvas: PaintCanvas, rect: IntRect, direction: Theme.Part, color: Color)
  func paintArrowButton(canvas: PaintCanvas, rect: IntRect, direction: Theme.Part, state: Theme.State)
  func paintCheckbox(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.ButtonExtraParams)
  func paintInnerSpinButton(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.InnerSpinButtonExtraParams)
  func paintMenuList(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.MenuListExtraParams)
  func paintMenuPopupBackground(canvas: PaintCanvas, size: IntSize, params: Theme.MenuBackgroundExtraParams)
  func paintMenuSeparator(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.MenuSeparatorExtraParams)
  func paintMenuItemBackground(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.MenuItemExtraParams)
  func paintProgressBar(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.ProgressBarExtraParams)
  func paintButton(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.ButtonExtraParams)
  func paintRadio(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.ButtonExtraParams)
  func paintScrollbarThumb(canvas: PaintCanvas, part: Theme.Part, state: Theme.State, rect: IntRect, theme: Theme.ScrollbarOverlayColorTheme)
  func paintScrollbarTrack(canvas: PaintCanvas, part: Theme.Part, state: Theme.State, params: Theme.ScrollbarTrackExtraParams, rect: IntRect)
  func paintScrollbarCorner(canvas: PaintCanvas, state: Theme.State, rect: IntRect)
  func paintSliderTrack(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.SliderExtraParams)
  func paintSliderThumb(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.SliderExtraParams)
  func paintTextField(canvas: PaintCanvas, state: Theme.State, rect: IntRect, params: Theme.TextFieldExtraParams)
  
}

// TODO: maybe using ADT's for the implementations can do the trick
// like 'case paintButton(canvas)'
