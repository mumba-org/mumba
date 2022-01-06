// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class PathEffect {

  public class func makeDash(intervals: [Float], count: Int, phase: Float) -> PathEffect {
    var ref: PathEffectRef? 
     intervals.withUnsafeBufferPointer { intervalsPtr in 
        ref = _PathEffectCreateDash(intervalsPtr.baseAddress, Int32(count), phase)!
     }
    return PathEffect(reference: ref!)
  }

  public class func makeSum(first: PathEffect, second: PathEffect) -> PathEffect {
    let ref = _PathEffectCreateSum(first.reference, second.reference)!
    return PathEffect(reference: ref)
  }

  public class func makeCompose(outer: PathEffect, inner: PathEffect) -> PathEffect {
    let ref = _PathEffectCreateCompose(outer.reference, inner.reference)!
    return PathEffect(reference: ref)
  }

  var reference: PathEffectRef
  
  internal init(reference: PathEffectRef) {
    self.reference = reference
  }

  deinit {
    _PathEffectDestroy(reference)
  }
  
}