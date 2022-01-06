// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Compositor

public class TransformRecorder {
  
  var context: PaintContext
  var transformed: Bool

  public init(context: PaintContext) {
    self.context = context
    transformed = false
  }

  deinit {
    guard transformed else {
      return
    }

    context.list.startPaint()
    context.list.push(.restore)
    context.list.endPaintOfPairedEnd()
  }

  public func transform(transform: Transform) {
    guard !transformed && !transform.isIdentity else {
      return  
    }
    
    context.list.startPaint()
    context.list.push(.save)
    context.list.push(.concat(matrix: transform.matrix.toMat3()))
    context.list.endPaintOfPairedBegin()

    transformed = true
  }
}