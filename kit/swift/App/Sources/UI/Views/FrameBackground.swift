// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class FrameBackground {
  
  public var frameColor: Color = Color()
  public var useCustomFrame: Bool = true
  public var isActive: Bool = true
  public var topAreaHeight: Int = 0 
  public var themeImage: ImageSkia

  public init() {
    themeImage = ImageSkia()
  }

  public func setSideImages(left: ImageSkia,
                            top: ImageSkia,
                            right: ImageSkia,
                            bottom: ImageSkia) {

  }

  public func setCornerImages(topLeft: ImageSkia,
                              topRight: ImageSkia,
                              bottomLeft: ImageSkia,
                              bottomRight: ImageSkia) {

  }

  public func paintRestored(canvas: Canvas, view: View) {

  }

  public func paintMaximized(canvas: Canvas, view: View) {

  }


}
