// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mojo/public/cpp/platform/platform_handle.h"

#include "build/build_config.h"
#if defined(OS_FUCHSIA)
#include <zircon/status.h>
#include <zircon/syscalls.h>
#endif
#if defined(OS_POSIX)
#include <unistd.h>
#elif defined(OS_WIN)
#include <windows.h>
#include "base/win/scoped_handle.h"
#else
#error "Platform not yet supported."
#endif

#include "base/logging.h"

namespace mojo {

namespace {

#if defined(OS_WIN)
HANDLE CloneHandle(HANDLE handle) {
 // DCHECK(handle.IsValid());

  HANDLE dupe;
  BOOL result = ::DuplicateHandle(::GetCurrentProcess(), handle,
                                  ::GetCurrentProcess(), &dupe, 0, FALSE,
                                  DUPLICATE_SAME_ACCESS);
  if (!result)
    return INVALID_HANDLE_VALUE;
  DCHECK_NE(dupe, INVALID_HANDLE_VALUE);
  return dupe;
}
#elif defined(OS_FUCHSIA)
zx::handle CloneHandle(const zx::handle& handle) {
  DCHECK(handle.is_valid());

  zx::handle dupe;
  zx_status_t result = handle.duplicate(ZX_RIGHT_SAME_RIGHTS, &dupe);
  if (result != ZX_OK)
    ZX_DLOG(ERROR, result) << "zx_duplicate_handle";
  return std::move(dupe);
}
#elif defined(OS_MACOSX) && !defined(OS_IOS)
base::mac::ScopedMachSendRight CloneMachPort(
    const base::mac::ScopedMachSendRight& mach_port) {
  DCHECK(mach_port.is_valid());

  kern_return_t kr = mach_port_mod_refs(mach_task_self(), mach_port.get(),
                                        MACH_PORT_RIGHT_SEND, 1);
  if (kr != KERN_SUCCESS) {
    MACH_DLOG(ERROR, kr) << "mach_port_mod_refs";
    return base::mac::ScopedMachSendRight();
  }
  return base::mac::ScopedMachSendRight(mach_port.get());
}
#endif

#if defined(OS_POSIX) || defined(OS_FUCHSIA)
int CloneFD(int fd) {//const base::ScopedFD& fd) {
  //DCHECK(fd.is_valid());
  return //base::ScopedFD(dup(fd.get()));
   dup(fd);
}
#endif


}  

void PlatformHandle::CloseIfNecessary() {
  if (!is_valid())
    return;

#if defined(OS_FUCHSIA)
  if (handle != ZX_HANDLE_INVALID) {
    zx_status_t result = zx_handle_close(handle);
    DCHECK_EQ(ZX_OK, result) << "CloseIfNecessary(zx_handle_close): "
                             << zx_status_get_string(result);
    handle = ZX_HANDLE_INVALID;
  }
  if (fd >= 0) {
    bool success = (close(fd) == 0);
    DPCHECK(success);
    fd = -1;
  }
#elif defined(OS_POSIX)
  if (type == Type::POSIX) {
    //bool success = (close(handle) == 0);
    close(handle);
    //DPCHECK(success);
    handle = -1;
  }
#if defined(OS_MACOSX) && !defined(OS_IOS)
  else if (type == Type::MACH) {
    kern_return_t rv = mach_port_deallocate(mach_task_self(), port);
    DPCHECK(rv == KERN_SUCCESS);
    port = MACH_PORT_NULL;
  }
#endif  // defined(OS_MACOSX) && !defined(OS_IOS)
#elif defined(OS_WIN)
  if (owning_process != base::GetCurrentProcessHandle()) {
    // This handle may have been duplicated to a new target process but not yet
    // sent there. In this case CloseHandle should NOT be called. From MSDN
    // documentation for DuplicateHandle[1]:
    //
    //    Normally the target process closes a duplicated handle when that
    //    process is finished using the handle. To close a duplicated handle
    //    from the source process, call DuplicateHandle with the following
    //    parameters:
    //
    //    * Set hSourceProcessHandle to the target process from the
    //      call that created the handle.
    //    * Set hSourceHandle to the duplicated handle to close.
    //    * Set lpTargetHandle to NULL.
    //    * Set dwOptions to DUPLICATE_CLOSE_SOURCE.
    //
    // [1] https://msdn.microsoft.com/en-us/library/windows/desktop/ms724251
    //
    // NOTE: It's possible for this operation to fail if the owning process
    // was terminated or is in the process of being terminated. Either way,
    // there is nothing we can reasonably do about failure, so we ignore it.
    DuplicateHandle(owning_process, handle, NULL, &handle, 0, FALSE,
                    DUPLICATE_CLOSE_SOURCE);
    return;
  }

  //bool success = !!CloseHandle(handle);
  CloseHandle(handle);
  //DPCHECK(success);
  handle = INVALID_HANDLE_VALUE;
#else
#error "Platform not yet supported."
#endif
}

// static
void PlatformHandle::ToMojoPlatformHandle(PlatformHandle handle,
                                          MojoPlatformHandle* out_handle) {
  DCHECK(out_handle);
  out_handle->struct_size = sizeof(MojoPlatformHandle);
 // if (handle.type == Type::kNone) {
 //   out_handle->type = MOJO_PLATFORM_HANDLE_TYPE_INVALID;
 //   out_handle->value = 0;
 //   return;
 // }

  do {
#if defined(OS_WIN)
    out_handle->type = MOJO_PLATFORM_HANDLE_TYPE_WINDOWS_HANDLE;
    out_handle->value = static_cast<uint64_t>(HandleToLong(handle.handle));
        //static_cast<uint64_t>(HandleToLong(handle.TakeHandle().Take()));
    break;
#elif defined(OS_FUCHSIA)
    if (handle.is_handle()) {
      out_handle->type = MOJO_PLATFORM_HANDLE_TYPE_FUCHSIA_HANDLE;
      out_handle->value = handle.TakeHandle().release();
      break;
    }
#elif defined(OS_MACOSX) && !defined(OS_IOS)
    if (handle.is_mach_port()) {
      out_handle->type = MOJO_PLATFORM_HANDLE_TYPE_MACH_PORT;
      out_handle->value =
          static_cast<uint64_t>(handle.TakeMachPort().release());
      break;
    }
#endif

#if defined(OS_POSIX) || defined(OS_FUCHSIA)
    //DCHECK(handle.is_fd());
    out_handle->type = MOJO_PLATFORM_HANDLE_TYPE_FILE_DESCRIPTOR;
    out_handle->value = static_cast<uint64_t>(handle.handle);
    handle.handle = -1;
    //static_cast<uint64_t>(handle.TakeFD().release());
#endif
  } while (false);

  // One of the above cases must take ownership of |handle|.
  DCHECK(!handle.is_valid());
}

// static
PlatformHandle PlatformHandle::FromMojoPlatformHandle(
    const MojoPlatformHandle* handle) {
  if (handle->struct_size < sizeof(*handle) ||
      handle->type == MOJO_PLATFORM_HANDLE_TYPE_INVALID) {
    return PlatformHandle();
  }

#if defined(OS_WIN)
  if (handle->type != MOJO_PLATFORM_HANDLE_TYPE_WINDOWS_HANDLE)
    return PlatformHandle();
  return PlatformHandle(LongToHandle(static_cast<long>(handle->value)));
#elif defined(OS_FUCHSIA)
  if (handle->type == MOJO_PLATFORM_HANDLE_TYPE_FUCHSIA_HANDLE)
    return PlatformHandle(zx::handle(handle->value));
#elif defined(OS_MACOSX) && !defined(OS_IOS)
  if (handle->type == MOJO_PLATFORM_HANDLE_TYPE_MACH_PORT) {
    return PlatformHandle(base::mac::ScopedMachSendRight(
        static_cast<mach_port_t>(handle->value)));
  }
#endif

#if defined(OS_POSIX) || defined(OS_FUCHSIA)
  if (handle->type != MOJO_PLATFORM_HANDLE_TYPE_FILE_DESCRIPTOR)
    return PlatformHandle();
  //return PlatformHandle(base::ScopedFD(static_cast<int>(handle->value)));
  return PlatformHandle(static_cast<int>(handle->value));
#endif
}

PlatformHandle PlatformHandle::Clone() const {
#if defined(OS_WIN)
  return PlatformHandle(CloneHandle(handle));
#elif defined(OS_FUCHSIA)
  if (is_valid_handle())
    return PlatformHandle(CloneHandle(handle_));
  return PlatformHandle(CloneFD(fd_));
#elif defined(OS_MACOSX) && !defined(OS_IOS)
  if (is_valid_mach_port())
    return PlatformHandle(CloneMachPort(mach_port_));
  return PlatformHandle(CloneFD(fd_));
#elif defined(OS_POSIX)
  return PlatformHandle(CloneFD(handle));
#endif
}

}  // namespace mojo
