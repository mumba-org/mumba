// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base

public protocol Watchable : class {
  var isOpen: Bool { get }
  func close() throws
}

// meant for native poll implementations
public protocol PlatformWatchable : Watchable {
 func withUnsafeFileDescriptor<T>(_ body: (FileDescriptor) throws -> T) throws -> T
}

// already implements watchable
extension PlatformFile : PlatformWatchable {}

/// A Channel that auto-handle and pre-process the IO event comming from the event poll's
public protocol EventWatcher {
  associatedtype Watched
  // this will dispatch a dedicated thread to handle the IO
  func register(watchable: Watched) throws
  func unregister(watchable: Watched) throws
}