// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//import NIO
#if os(Linux) || os(macOS)
import PosixShim

public typealias FileDescriptor = CInt
#elseif os(Windows)
public typealias FileDescriptor = HANDLE
#endif

public class PlatformFile {

    var descriptor: FileDescriptor

    public var isOpen: Bool {
      return descriptor >= 0
    }

    public func withUnsafeFileDescriptor<T>(_ body: (FileDescriptor) throws -> T) throws -> T {
      guard self.isOpen else {
          throw SystemError.IOError(code: EBADF, reason: "file descriptor already closed!")
      }
      return try body(descriptor)
    }

    public init(descriptor: FileDescriptor) {
      #if os(Linux) || os(macOS)      
      precondition(descriptor >= 0, "invalid file descriptor")
      #endif
      self.descriptor = descriptor
    }
    
    deinit {
      //precondition(!self.isOpen, "leak of open BaseSocket")
    }

    public final func setNonBlocking() throws {
      #if os(Linux) || os(macOS)  
      return try withUnsafeFileDescriptor { fd in
        let ret = posix_fcntl(fd, F_SETFL, O_NONBLOCK)
        assert(ret == 0, "unexpectedly, fcntl(\(fd), F_SETFL, O_NONBLOCK) returned \(ret)")
      }
      #endif    
    }

    public func close() throws {
      #if os(Linux) || os(macOS)  
      try withUnsafeFileDescriptor { fd in
        //let rc = posix_close(fd)
        let rc = try! Posix.close(fd)
        if rc != 0 {
          throw SystemError.IOError(code: rc, reason: "file descriptor close failed")
        }
      }

      self.descriptor = -1
      #endif    
    }
}

public typealias WakeupPipe = PlatformFile