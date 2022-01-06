// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if os(Linux) || os(Android)
@_exported import Glibc
@_exported import PosixShim
#endif

@inline(__always)
@discardableResult
public func wrapSyscall<T: FixedWidthInteger>(where function: String = #function, _ body: () throws -> T) throws -> T {
    while true {
        let res = try body()
        if res == -1 {
            let err = errno
            if err == EINTR {
                continue
            }
            //assertIsNotBlacklistedErrno(err: err, where: function)
            throw SystemError.OSError(code: err, function: function)
        }
        return res
    }
}

#if os(Linux) || os(Android) || os(macOS)
public enum PrctlFlag : CInt {
  case PR_SET_NAME = 15 /* Set process name */
  case PR_GET_NAME = 16 /* Get process name */
}

public let sysPrctl1P: @convention(c) (CInt, CUnsignedLong) -> CInt = posix_prctl1
public let sysPrctl1PP: @convention(c) (CInt, UnsafeRawPointer?) -> CInt = posix_prctl1p
public let sysPrctl2P: @convention(c) (CInt, CUnsignedLong, CUnsignedLong) -> CInt = posix_prctl2
public let sysPrctl3P: @convention(c) (CInt, CUnsignedLong, CUnsignedLong, CUnsignedLong) -> CInt = posix_prctl3
public let sysPrctl4P: @convention(c) (CInt, CUnsignedLong, CUnsignedLong, CUnsignedLong, CUnsignedLong) -> CInt = posix_prctl4

public let sysClose: @convention(c) (CInt) -> CInt = posix_close
public let sysRead: @convention(c) (CInt, UnsafeMutablePointer<Int8>?, Int) -> CInt = posix_read
public let sysWrite: @convention(c) (CInt, UnsafeMutablePointer<Int8>?, Int) -> CInt = posix_write

#endif

public struct SysInfo {

  public static var numberOfCores: Int {
  #if os(Linux)
    return sysconf(CInt(_SC_NPROCESSORS_ONLN))
  #else
    return -1
  #endif
  }

}

public enum Posix {
#if os(Linux) || os(Android) || os(macOS)
    public static func read(_ descriptor: FileDescriptor, _ buf: UnsafeMutablePointer<Int8>?, _ count: Int) throws -> CInt {
      return try wrapSyscall {
        sysRead(descriptor, buf, count)
      }
    }
    
    public static func write(_ descriptor: FileDescriptor, _ buf: UnsafeMutablePointer<Int8>?, _ count: Int) throws -> CInt {
      return try wrapSyscall {
        sysWrite(descriptor, buf, count)
      }
    }

    public static func close(_ descriptor: FileDescriptor) throws -> CInt {
      return try wrapSyscall {
        sysClose(descriptor)
      }
    }

    @inline(never)
    public static func prctl(flag: PrctlFlag, value: CUnsignedLong) throws -> CInt {
        return try wrapSyscall {
            sysPrctl1P(flag.rawValue, value)
        }
    }

    @inline(never)
    public static func prctl(flag: PrctlFlag, buf: UnsafePointer<Int8>) throws -> CInt {
        return try wrapSyscall {
            let rawPointer = UnsafeRawPointer(buf)
            //return sysPrctl1P(flag.rawValue, rawPointer.load(as: UInt.self))
            return sysPrctl1PP(flag.rawValue, rawPointer)
        }
    }

    // TODO: fcntl
#endif
}

public enum Linux {
#if os(Android)
    static let SOCK_CLOEXEC = Glibc.SOCK_CLOEXEC
    static let SOCK_NONBLOCK = Glibc.SOCK_NONBLOCK
#elseif os(Linux)
    static let SOCK_CLOEXEC = CInt(bitPattern: Glibc.SOCK_CLOEXEC.rawValue)
    static let SOCK_NONBLOCK = CInt(bitPattern: Glibc.SOCK_NONBLOCK.rawValue)
#endif
}
