// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class PaintRecord {

  public var reference: PaintRecordRef
  
  internal init(reference: PaintRecordRef) {
    self.reference = reference
  }

  deinit {
    _PaintRecordDestroy(reference)
  }

  public func playback(canvas: SkiaCanvas) {
    _PaintRecordPlayback(reference, canvas.reference)
  }

  public func playback(canvas: SkiaCanvas, params: PlaybackParams) {
    _PaintRecordPlaybackParams(reference, canvas.reference, params.originalCtm.reference)
  }
  
}