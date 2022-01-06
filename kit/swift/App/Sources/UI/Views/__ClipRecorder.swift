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
      context.list.push(.restore)
    }
  }

  public func clipRect(clipRect: IntRect) {
    let antiAlias = false
    let clipRectf = FloatRect(clipRect)
    context.list.push(.save)
    context.list.push(.clipRect(clipRectf, clip: ClipOp.intersect, antiAlias: antiAlias))
    numClosers += 1
  }

  public func clipPath(clipPath: Path) {
    let antiAlias = false
    context.list.push(.save)
    context.list.push(.clipPath(clipPath, clip: ClipOp.intersect, antiAlias: antiAlias))
    numClosers += 1
  }

  public func clipPathWithAntiAliasing(clipPath: Path) {
    let antiAlias = true
    context.list.push(.save)
    context.list.push(.clipPath(clipPath, clip: ClipOp.intersect, antiAlias: antiAlias))
    numClosers += 1
  }

}
