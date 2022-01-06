// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MOJO_PUBLIC_CPP_PLATFORM_PLATFORM_HANDLE_H_
#define MOJO_PUBLIC_CPP_PLATFORM_PLATFORM_HANDLE_H_

#include "build/build_config.h"
#include "base/component_export.h"
#include "mojo/public/c/system/platform_handle.h"

#if defined(OS_WIN)
#include <windows.h>

#include "base/process/process_handle.h"
#elif defined(OS_MACOSX) && !defined(OS_IOS)
#include <mach/mach.h>
#elif defined(OS_FUCHSIA)
#include <fdio/limits.h>
#include <zircon/syscalls.h>
#endif

#if defined(OS_POSIX) || defined(OS_FUCHSIA)
#include "base/files/scoped_file.h"
#endif

#include "base/logging.h"

namespace mojo {

#if defined(OS_FUCHSIA)
// TODO(fuchsia): Find a clean way to share this with the POSIX version.
// |zx_handle_t| is a typedef of |int|, so we only allow PlatformHandle to be
// created via explicit For<type>() creator functions.
struct COMPONENT_EXPORT(MOJO_CPP_PLATFORM) PlatformHandle {
 public:
  
  static PlatformHandle ForHandle(zx_handle_t handle) {
    PlatformHandle platform_handle;
    platform_handle.handle = handle;
    return platform_handle;
  }

  static PlatformHandle ForFd(int fd) {
    PlatformHandle platform_handle;
    DCHECK_LT(fd, FDIO_MAX_FD);
    platform_handle.fd = fd;
    return platform_handle;
  }

  void CloseIfNecessary();
  bool is_valid() const { return is_valid_fd() || is_valid_handle(); }
  bool is_valid_handle() const { return handle != ZX_HANDLE_INVALID && fd < 0; }
  zx_handle_t as_handle() const { return handle; }
  bool is_valid_fd() const { return fd >= 0 && handle == ZX_HANDLE_INVALID; }
  int as_fd() const { return fd; }

 private:
  zx_handle_t handle = ZX_HANDLE_INVALID;
  int fd = -1;
};
#elif defined(OS_POSIX)
struct COMPONENT_EXPORT(MOJO_CPP_PLATFORM) PlatformHandle {
  PlatformHandle() {}
  explicit PlatformHandle(int handle) : handle(handle) {}
   //type_(Type::kFd), 
  // fd(std::move(fd)) {}

  // Takes ownership of |handle|'s underlying platform handle and fills in
  // |mojo_handle| with a representation of it. The caller assumes ownership of
  // the platform handle.
  static COMPONENT_EXPORT(MOJO_CPP_PLATFORM) void ToMojoPlatformHandle(PlatformHandle handle,
                                   MojoPlatformHandle* mojo_handle);

  // Closes the underlying platform handle.
  // Assumes ownership of the platform handle described by |handle|, and returns
  // it as a new PlatformHandle.
  static COMPONENT_EXPORT(MOJO_CPP_PLATFORM) PlatformHandle FromMojoPlatformHandle(
      const MojoPlatformHandle* handle);

#if defined(OS_MACOSX) && !defined(OS_IOS)
  explicit PlatformHandle(mach_port_t port)
      : type(Type::MACH), port(port) {}
#endif

//#if defined(OS_POSIX) || defined(OS_FUCHSIA)
  // bool is_valid_fd() const { return fd.is_valid(); }
  // bool is_fd() const { return is_valid_fd(); }//return type_ == Type::kFd; }
  // const base::ScopedFD& GetFD() const { return fd; }
  // base::ScopedFD TakeFD() {
  //   //if (type_ == Type::kFd)
  //   //  type_ = Type::kNone;
  //   return std::move(fd);
  // }
  // int ReleaseFD() WARN_UNUSED_RESULT {
  //   //if (type_ == Type::kFd)
  //   //  type_ = Type::kNone;
  //   return fd.release();
  // }
//#endif


  void CloseIfNecessary();

  PlatformHandle Clone() const;

  bool is_valid() const {
#if defined(OS_MACOSX) && !defined(OS_IOS)
    if (type == Type::MACH || type == Type::MACH_NAME)
      return port != MACH_PORT_NULL;
#endif
    return handle != -1;
  }

  enum class Type {
    POSIX,
#if defined(OS_MACOSX) && !defined(OS_IOS)
    MACH,
    // MACH_NAME isn't a real Mach port. But rather the "name" of one that can
    // be resolved to a real port later. This distinction is needed so that the
    // "port" doesn't try to be closed if CloseIfNecessary() is called. Having
    // this also allows us to do checks in other places.
    MACH_NAME,
#endif
  };
  Type type = Type::POSIX;

  int handle = -1;

//#if defined(OS_POSIX) || defined(OS_FUCHSIA)
//  base::ScopedFD fd;
//#endif

  // A POSIX handle may be a listen handle that can accept a connection.
  bool needs_connection = false;

#if defined(OS_MACOSX) && !defined(OS_IOS)
  mach_port_t port = MACH_PORT_NULL;
#endif
};
#elif defined(OS_WIN)
struct COMPONENT_EXPORT(MOJO_CPP_PLATFORM) PlatformHandle {

  static  COMPONENT_EXPORT(MOJO_CPP_PLATFORM) void ToMojoPlatformHandle(PlatformHandle handle,
                                   MojoPlatformHandle* mojo_handle);

  // Closes the underlying platform handle.
  // Assumes ownership of the platform handle described by |handle|, and returns
  // it as a new PlatformHandle.
  static  COMPONENT_EXPORT(MOJO_CPP_PLATFORM) PlatformHandle FromMojoPlatformHandle(
      const MojoPlatformHandle* handle);

  PlatformHandle() : PlatformHandle(INVALID_HANDLE_VALUE) {}
  explicit PlatformHandle(HANDLE handle)
      : handle(handle), owning_process(base::GetCurrentProcessHandle()) {}

  void CloseIfNecessary();
 
  bool is_valid() const { return handle != INVALID_HANDLE_VALUE; }

  PlatformHandle Clone() const;
  
  HANDLE handle;

  // A Windows HANDLE may be duplicated to another process but not yet sent to
  // that process. This tracks the handle's owning process.
  base::ProcessHandle owning_process;

  // A Windows HANDLE may be an unconnected named pipe. In this case, we need to
  // wait for a connection before communicating on the pipe.
  bool needs_connection = false;
};
#else
#error "Platform not yet supported."
#endif

}  // namespace mojo

#endif  // MOJO_EDK_EMBEDDER_PLATFORM_HANDLE_H_
