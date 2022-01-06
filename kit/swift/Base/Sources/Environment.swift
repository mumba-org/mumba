// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

internal enum EnvironmentType : Int {
  case background = 0
  case backgroundBlocking = 1
  case foreground = 2
  case foregroundBlocking = 3

  static func getEnvironmentIndexForTraits(_ traits: TaskTraits) -> Int {
    let isBackground = traits.priority == TaskPriority.background
    
    if traits.mayBlock || traits.withSyncPrimitives {
      return isBackground ? EnvironmentType.backgroundBlocking.rawValue : EnvironmentType.foregroundBlocking.rawValue
    }
    return isBackground ? EnvironmentType.background.rawValue : EnvironmentType.foreground.rawValue
  }
}

extension EnvironmentType: CaseIterable {}

// Order must match the EnvironmentType enum.
internal struct EnvironmentParam {
  let nameSuffix: String
  let priorityHint: ThreadPriority
} 

internal let environmentParams: [EnvironmentParam] = [
  EnvironmentParam(nameSuffix: "Background", priorityHint: ThreadPriority.background),
  EnvironmentParam(nameSuffix: "BackgroundBlocking", priorityHint: ThreadPriority.background),
  EnvironmentParam(nameSuffix: "Foreground", priorityHint: ThreadPriority.normal),
  EnvironmentParam(nameSuffix: "ForegroundBlocking", priorityHint: ThreadPriority.normal)
]