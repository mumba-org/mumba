// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base

public enum AnimationIdProvider {
  
  public static var nextKeyframeModelId: Int {
    return AnimationIdProvider.nextKeyframeModelIdGen.next + 1
  }

  public static var nextGroupId: Int {
    return AnimationIdProvider.nextGroupIdGen.next + 1
  }

  public static var nextTimelineId: Int {
    return AnimationIdProvider.nextTimelineIdGen.next + 1
  }

  public static var nextAnimationId: Int {
    return AnimationIdProvider.nextAnimationIdGen.next + 1
  }

  private static let nextKeyframeModelIdGen = AtomicSequence()
  private static let nextGroupIdGen = AtomicSequence()
  private static let nextTimelineIdGen = AtomicSequence()
  private static let nextAnimationIdGen = AtomicSequence()
}