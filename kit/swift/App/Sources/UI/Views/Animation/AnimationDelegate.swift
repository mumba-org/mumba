// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public protocol AnimationDelegate {
 func animationEnded(animation: Animation)
 func animationProgressed(animation: Animation)
 func animationCanceled(animation: Animation)
}

extension AnimationDelegate {
  public func animationEnded(animation: Animation) {}
  public func animationProgressed(animation: Animation) {}
  public func animationCanceled(animation: Animation) {}
}