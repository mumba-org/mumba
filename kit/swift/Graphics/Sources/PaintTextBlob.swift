// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class PaintTextBlob {

  //private var glyphs: ContiguousArray<UInt16>
  //private var x: ContiguousArray<Float>
  //private var y: ContiguousArray<Float>
    
  public var reference: PaintTextBlobRef?

  public init(glyphs: ContiguousArray<UInt16>, len: Int, pos: [FloatPoint], flags: PaintFlags) {
    //self.glyphs = glyphs
    var x = ContiguousArray<Float>(repeating: 0.0, count: pos.count)
    var y = ContiguousArray<Float>(repeating: 0.0, count: pos.count)
    
     // This is not very good and unnecessary copy.. we need to find a better way
    for (i, point) in pos.enumerated() {
      x[i] = point.x
      y[i] = point.y
    }

    var maybeHandle: PaintTextBlobRef?

    x.withUnsafeBufferPointer { xbuf in
      y.withUnsafeBufferPointer { ybuf in
        glyphs.withUnsafeBufferPointer { glyphbuf in
          maybeHandle = _PaintTextBlobCreate(glyphbuf.baseAddress, len , xbuf.baseAddress, ybuf.baseAddress, Int32(pos.count), flags.reference)
        }
      }
    }

    reference = maybeHandle!
  }
  
  internal init(reference: PaintTextBlobRef) {
    //glyphs = ContiguousArray<UInt16>()
    //x = ContiguousArray<Float>()
    //y = ContiguousArray<Float>()
  
    self.reference = reference
  }

  deinit {
    _PaintTextBlobDestroy(reference)
  }
  
}