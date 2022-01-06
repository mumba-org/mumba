//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2017-2018 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// This is a companion to System.swift that provides only Linux specials: either things that exist
// only on Linux, or things that have Linux-specific extensions.
//import CNIOLinux
import Base
import PosixShim

#if os(Linux)
internal enum TimerFd {
    public static let TFD_CLOEXEC = PosixShim.TFD_CLOEXEC
    public static let TFD_NONBLOCK = PosixShim.TFD_NONBLOCK

    @inline(never)
    public static func timerfd_settime(fd: Int32, flags: Int32, newValue: UnsafePointer<itimerspec>, oldValue: UnsafeMutablePointer<itimerspec>?) throws  {
        try wrapSyscall {
            PosixShim.timerfd_settime(fd, flags, newValue, oldValue)
        }
    }

    @inline(never)
    public static func timerfd_create(clockId: Int32, flags: Int32) throws -> Int32 {
        return try wrapSyscall {
            PosixShim.timerfd_create(clockId, flags)
        }
    }
}

internal enum EventFd {
    public static let EFD_CLOEXEC = PosixShim.EFD_CLOEXEC
    public static let EFD_NONBLOCK = PosixShim.EFD_NONBLOCK
    public typealias eventfd_t = PosixShim.eventfd_t

    @inline(never)
    public static func eventfd_write(fd: Int32, value: UInt64) throws -> Int32 {
        return try wrapSyscall {
            PosixShim.eventfd_write(fd, value)
        }
    }

    @inline(never)
    public static func eventfd_read(fd: Int32, value: UnsafeMutablePointer<UInt64>) throws -> Int32 {
        return try wrapSyscall {
            PosixShim.eventfd_read(fd, value)
        }
    }

    @inline(never)
    public static func eventfd(initval: Int32, flags: Int32) throws -> Int32 {
        return try wrapSyscall {
            PosixShim.eventfd(0, Int32(EFD_CLOEXEC | EFD_NONBLOCK))
        }
    }
}

internal enum Epoll {
    public typealias epoll_event = PosixShim.epoll_event

    public static let EPOLL_CTL_ADD: CInt = numericCast(PosixShim.EPOLL_CTL_ADD)
    public static let EPOLL_CTL_MOD: CInt = numericCast(PosixShim.EPOLL_CTL_MOD)
    public static let EPOLL_CTL_DEL: CInt = numericCast(PosixShim.EPOLL_CTL_DEL)

    #if os(Android)
    public static let EPOLLIN: CUnsignedInt = numericCast(PosixShim.EPOLLIN)
    public static let EPOLLOUT: CUnsignedInt = numericCast(PosixShim.EPOLLOUT)
    public static let EPOLLERR: CUnsignedInt = numericCast(PosixShim.EPOLLERR)
    public static let EPOLLRDHUP: CUnsignedInt = numericCast(PosixShim.EPOLLRDHUP)
    public static let EPOLLHUP: CUnsignedInt = numericCast(PosixShim.EPOLLHUP)
    public static let EPOLLET: CUnsignedInt = numericCast(PosixShim.EPOLLET)
    #else
    public static let EPOLLIN: CUnsignedInt = numericCast(PosixShim.EPOLLIN.rawValue)
    public static let EPOLLOUT: CUnsignedInt = numericCast(PosixShim.EPOLLOUT.rawValue)
    public static let EPOLLERR: CUnsignedInt = numericCast(PosixShim.EPOLLERR.rawValue)
    public static let EPOLLRDHUP: CUnsignedInt = numericCast(PosixShim.EPOLLRDHUP.rawValue)
    public static let EPOLLHUP: CUnsignedInt = numericCast(PosixShim.EPOLLHUP.rawValue)
    public static let EPOLLET: CUnsignedInt = numericCast(PosixShim.EPOLLET.rawValue)
    #endif

    public static let ENOENT: CUnsignedInt = numericCast(PosixShim.ENOENT)


    @inline(never)
    public static func epoll_create(size: Int32) throws -> Int32 {
        return try wrapSyscall {
            PosixShim.epoll_create(size)
        }
    }

    @inline(never)
    @discardableResult
    public static func epoll_ctl(epfd: Int32, op: Int32, fd: Int32, event: UnsafeMutablePointer<epoll_event>) throws -> Int32 {
        return try wrapSyscall {
            PosixShim.epoll_ctl(epfd, op, fd, event)
        }
    }

    @inline(never)
    public static func epoll_wait(epfd: Int32, events: UnsafeMutablePointer<epoll_event>, maxevents: Int32, timeout: Int32) throws -> Int32 {
        return try wrapSyscall {
            PosixShim.epoll_wait(epfd, events, maxevents, timeout)
        }
    }
}

#endif
