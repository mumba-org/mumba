// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims
import Base
import Graphics

public class SingleKeyframeEffectAnimation : Animation {
  
  public var elementId: UInt64 {
    return _SingleKeyframeEffectAnimationGetElementId(reference)
  }
 
  //public var keyframeEffect: KeyframeEffect? {
  //  let ref = _SingleKeyframeEffectAnimationGetKeyframeEffect(reference)
  //  return ref!
  //}
 
  public init(id: Int) {
    let reference = _SingleKeyframeEffectAnimationCreate(CInt(id))!
    super.init(reference: reference)
  }

  public override init(reference: AnimationRef) {
    super.init(reference: reference)
  }

  public func attachElement(id elementId: UInt64) {
    _SingleKeyframeEffectAnimationAttachElement(reference, elementId)
  }

  public func addKeyframeModel(_ keyframeModel: KeyframeModel) {
    // this keyframe model reference is now owned by this animation
    // so it should not delete its own handle when the reference is gone
    keyframeModel.owned = false
    _SingleKeyframeEffectAddKeyframeModel(reference, keyframeModel.reference)
  }

  public func pauseKeyframeModel(_ keyframeModelId: Int, timeOffset: Double) {
    _SingleKeyframeEffectAnimationPauseKeyframeModel(reference, CInt(keyframeModelId), timeOffset) 
  }
  
  public func removeKeyframeModel(_ keyframeModelId: Int) {
    _SingleKeyframeEffectAnimationRemoveKeyframeModel(reference, CInt(keyframeModelId))
  }
  
  public func abortKeyframeModel(_ keyframeModelId: Int) {
    _SingleKeyframeEffectAnimationAbortKeyframeModel(reference, CInt(keyframeModelId))
  }

  public func getKeyframeModel(targetProperty: TargetProperty) -> KeyframeModel? {
    if let ref = _SingleKeyframeEffectAnimationGetKeyframeModel(reference, CInt(targetProperty.rawValue)) {
      return KeyframeModel(reference: ref, owned: false)
    }
    return nil
  }

}
