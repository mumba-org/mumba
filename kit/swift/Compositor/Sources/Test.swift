// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Gpu

// TaskGraphRunner
public class TestTaskGraphRunner {
  public init() {}
}

extension TestTaskGraphRunner : TaskGraphRunner {
  public func run() {}
}

// ImageFactory

//public class TestImageFactory {
//  public init() {}
//}

//extension TestImageFactory: ImageFactory {

//}

// SharedBitmapManager

public class TestSharedBitmapManager {
  public init() {}
}

extension TestSharedBitmapManager : SharedBitmapManager {
  public func doSomething() {}
}

// GpuMemoryBufferManager

//public class TestGpuMemoryBufferManager {
//  public init() {}
//}

//extension TestGpuMemoryBufferManager : GpuMemoryBufferManager {

//}
