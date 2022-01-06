// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if os(Linux)
import PosixShim
#endif

public func createLocalNonBlockingPipe() -> (readEnd: FileDescriptor, writeEnd: FileDescriptor, error: FileDescriptor) {
#if os(Linux)
  var fds: [FileDescriptor] = [0, 0]
  let ret = fds.withUnsafeMutableBufferPointer { unsafeFds -> FileDescriptor in
    return posix_pipe2(unsafeFds.baseAddress, O_CLOEXEC | O_NONBLOCK)
  }
  
  posix_fcntl(fds[0], F_SETFL, O_CLOEXEC | O_NONBLOCK)
  posix_fcntl(fds[1], F_SETFL, O_CLOEXEC | O_NONBLOCK)
  
  return (readEnd: fds[0], writeEnd: fds[1], error: ret)
#endif
}