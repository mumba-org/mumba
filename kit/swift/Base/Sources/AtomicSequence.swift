// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct AtomicSequence {
  
  public var next: Int {
    return number.add(1)
  }

  private var number: Atomic<Int>

  public init() {
    number = Atomic<Int>(value: 0)
  }

}