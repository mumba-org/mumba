// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import Compositor

public class ClipRecorder {

  var context: PaintContext
  var numClosers: Int

  public init(context: PaintContext) {
    numClosers = 0
    self.context = context
  }

  deinit {
    for _ in 0..<numClosers {
      if !context.externalDisplayList {
        context.list.startPaint()
      }
      context.list.push(.restore)
      if !context.externalDisplayList {
        context.list.endPaintOfPairedEnd()
      }
    }
  }

  public func clipRect(clipRect: IntRect) {
    let antiAlias = false
    let clipRectf = FloatRect(clipRect)
    if !context.externalDisplayList {
      context.list.startPaint()
    } 
    context.list.push(.save)
    context.list.push(.clipRect(clipRectf, clip: ClipOp.intersect, antiAlias: antiAlias))
    if !context.externalDisplayList {
      context.list.endPaintOfPairedBegin()
    }
    numClosers += 1
  }

  public func clipPath(clipPath: Path) {
    let antiAlias = false
    if !context.externalDisplayList {
      context.list.startPaint()
    }
    context.list.push(.save)
    context.list.push(.clipPath(clipPath, clip: ClipOp.intersect, antiAlias: antiAlias))
    if !context.externalDisplayList {
      context.list.endPaintOfPairedBegin()
    }
    numClosers += 1
  }

  public func clipPathWithAntiAliasing(clipPath: Path) {
    let antiAlias = true
    if !context.externalDisplayList {
      context.list.startPaint()
    }
    context.list.push(.save)
    context.list.push(.clipPath(clipPath, clip: ClipOp.intersect, antiAlias: antiAlias))
    if !context.externalDisplayList {
      context.list.endPaintOfPairedBegin()
    }
    numClosers += 1
  }

}
