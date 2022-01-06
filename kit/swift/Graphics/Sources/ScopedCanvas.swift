// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base

public class ScopedCanvas {
  
  var canvas: Canvas?

  public init(canvas: Canvas?) {
    self.canvas = canvas
    if let c = canvas {
      c.save()
    }
  }
  
  deinit {
    if let c = canvas {
      c.restore()
    }
  }
}


public class ScopedRTLFlipCanvas {
  
  var canvas: ScopedCanvas

  public init(canvas: Canvas, width: Int, flip: Bool = true) {
    self.canvas = ScopedCanvas(canvas: canvas)
    if flip && i18n.isRTL() {
      canvas.translate(offset: IntVec2(x: width, y: 0))
      canvas.scale(x: -1, y: 1)
    }
  }
}

extension Canvas {
  
  public func withinScope(width: Int, flip: Bool, _ closure: (_ canvas: Canvas) -> Void) {
    let scoped = ScopedRTLFlipCanvas(canvas: self, width: width, flip: flip)
    closure(self)
  }

}