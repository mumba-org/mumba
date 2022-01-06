// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public protocol Drawable {
  func onGetBounds() -> IntRect
  // warning: should never keep canvas reference for later use
  func onDraw(canvas: Canvas)
  func onNewPictureSnapshot() -> Picture?
}

extension Drawable {

  public func onGetBounds() -> IntRect { return IntRect() }
  // warning: should never keep canvas reference for later use
  public func onDraw(canvas: Canvas) {}
  public func onNewPictureSnapshot() -> Picture? { return nil }
}

public class DrawableSkia : Drawable {
  
  public var generationID: UInt32 {
    return _DrawableGetGenerationID(reference)
  }
  
  public var bounds: IntRect {
    var x: Int32  = 0, y: Int32 = 0, w: Int32 = 0, h: Int32 = 0
    _DrawableGetBounds(reference, &x, &y, &w, &h)
    return IntRect(x: Int(x), y: Int(y), width: Int(w), height: Int(h))
  }

  var reference: DrawableRef

  public init(reference: DrawableRef) {
    self.reference = reference

    // Todo: Tem que registrar os metodos do drawable como callbacks
    // pois será o codigo C++ do skia que deverá chamá-los e onde
    // temos que repassar para o código implementado em swift
  }

  public func draw(canvas: Canvas) {
    if let skiaCanvas = canvas.paintCanvas as? SkiaPaintCanvas {
      _DrawableDraw(reference, skiaCanvas.nativeCanvas.reference)
    }
  }
  
  public func draw(canvas: Canvas, at: IntPoint) {
    if let skiaCanvas = canvas.paintCanvas as? SkiaPaintCanvas {
      _DrawableDrawAt(reference, skiaCanvas.nativeCanvas.reference, Int32(at.x), Int32(at.y))
    }
  }
  
  public func newPictureSnapshot() -> Picture {
    let ptr = _DrawableNewPictureSnapshot(reference)
    return Picture(reference: ptr!)
  }
 
  public func notifyDrawingChanged() {
    _DrawableNotifyDrawingChanged(reference)
  }

}