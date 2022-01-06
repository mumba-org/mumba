// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base

public protocol AnimationContainerElement: class {
  var startTime: TimeTicks { get set }
  var timerInterval: TimeDelta { get }
  func step(timeNow: TimeTicks)
}