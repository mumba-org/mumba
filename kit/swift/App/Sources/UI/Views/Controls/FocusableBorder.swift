// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

public class FocusableBorder : Border {

  public static let cornerRadiusDp: Float = 2.0
  
  public var minimumSize: IntSize {
    return IntSize()
  }
  
  public var insets: IntInsets
  
  private var overrideColorId: Theme.ColorId?

  public init() {
    insets = IntInsets(all: insetSize)
  }

  public func setColorId(_ colorId: Theme.ColorId) {
    overrideColorId = colorId
  }

  public func setInsets(vertical: Int, horizontal: Int) {
    insets.set(top: vertical, left: horizontal, bottom: vertical, right: horizontal)
  }

  public func paint(view: View, canvas: Canvas) {
    let flags = PaintFlags()
    flags.style = Paint.Style.Stroke
    flags.color = getCurrentColor(view: view)

    let _ = ScopedCanvas(canvas: canvas)
    let dsf = canvas.undoDeviceScaleFactor()

    let strokeWidthPx = Int(floor(dsf))
     // MaterialDesignController.isSecondaryUiMaterial
     //     ? 1
     //     : Int(floor(dsf))
    flags.strokeWidth = Float(strokeWidthPx)

    // Scale the rect and snap to pixel boundaries.
    var rect = scaleToEnclosingRect(rect: view.localBounds, xScale: dsf, yScale: dsf)
    rect.inset(insets: IntInsets(all: strokeWidthPx / 2))

    let path = Path()
    //if MaterialDesignController.isSecondaryUiMaterial {
    //  flags.antiAlias = true
    //  let cornerRadiusPx = FocusableBorder.cornerRadiusDp * dsf
    //  path.addRoundRect(rect, cornerRadiusPx, cornerRadiusPx)
    //} else {
      path.addRect(FloatRect(rect), direction: Path.Direction.CWDirection)
    //}
    canvas.drawPath(path: path, flags: flags)
  }

  private func getCurrentColor(view: View) -> Color {
    var colorId = Theme.ColorId.UnfocusedBorderColor
    if let maybeColor = overrideColorId {
      colorId = maybeColor
    } //else if view.hasFocus &&
     //        !MaterialDesignController.isSecondaryUiMaterial {
     // colorId = ColorId.FocusedBorderColor
    //}

    let color = view.theme.getSystemColor(id: colorId)
    //if MaterialDesignController.isSecondaryUiMaterial &&
    //  !view.isEnabled {
    //  return ColorUtils.blendTowardOppositeLuma(color, disabledControlAlpha)
    //}
    return color
  }

}

fileprivate let insetSize: Int = 1