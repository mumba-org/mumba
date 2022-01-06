// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public class AnimationTimeline {

  public class func create(id: Int) -> AnimationTimeline {
    let ref = _AnimationTimelineCreate(CInt(id))
    return AnimationTimeline(reference: ref!, owned: true)
  }
  
  internal var reference: AnimationTimelineRef
  internal var owned: Bool

  internal init(reference: AnimationTimelineRef, owned: Bool) {
    self.reference = reference
    self.owned = owned
  }

  deinit {
    //if owned {
      // we always get rid of the timeline handle
      // its a wrapper over the real ref-counted cc::AnimationTimeline
      _AnimationTimelineDestroy(reference)
    //}
  }

  public func attachAnimation(_ animation: Animation) {
    _AnimationTimelineAttachAnimation(reference, animation.reference)
  }

  public func detachAnimation(_ animation: Animation) {
    _AnimationTimelineDetachAnimation(reference, animation.reference)
  }

}
