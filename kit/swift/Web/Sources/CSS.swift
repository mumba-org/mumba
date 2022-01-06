// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct CSS {
  
  public static func paintWorklet(window: WebWindow) -> PaintWorklet {
    if CSS.instance == nil {
      CSS.instance = CSS(window: window)
    }
    return CSS.instance!.cssPaintWorklet!
  }

  private static var instance: CSS?
  private var cssPaintWorklet: CSSPaintWorklet?

  internal init(window: WebWindow) {
    cssPaintWorklet = CSSPaintWorklet(window: window)
  }
  
  // FIXME
  internal init() {
    //cssPaintWorklet = CSSPaintWorklet(window: window)
  }

}