// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class TooltipManager {

  public static func updateTooltipManagerForCapture(source: UIWidget) {
    
  }

  public var fontList: FontList? { return nil }

  private var widget: UIWidget

  public init(widget: UIWidget) {
    self.widget = widget
  }

  public func getmaxWidth(location: IntPoint,
                          context: Window) -> Int {
    return 0
  }

  public func updateTooltip() {

  }

  public func tooltipTextChanged(view: View) {

  }

}
