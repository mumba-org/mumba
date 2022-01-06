// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MOJO_PUBLIC_CPP_PLATFORM_PLATFORM_HANDLE_UTILS_H_
#define MOJO_PUBLIC_CPP_PLATFORM_PLATFORM_HANDLE_UTILS_H_

#include "base/memory/platform_shared_memory_region.h"
#include "base/component_export.h"
#include "mojo/public/cpp/platform/platform_handle.h"
#include "mojo/public/cpp/platform/scoped_platform_handle.h"

namespace mojo {

// Closes all the |PlatformHandle|s in the given container.
template <typename PlatformHandleContainer>
COMPONENT_EXPORT(MOJO_CPP_PLATFORM) inline void CloseAllPlatformHandles(
    PlatformHandleContainer* platform_handles) {
  for (typename PlatformHandleContainer::iterator it =
           platform_handles->begin();
       it != platform_handles->end(); ++it)
    it->CloseIfNecessary();
}

// Duplicates the given |PlatformHandle| (which must be valid). (Returns an
// invalid |ScopedPlatformHandle| on failure.)
COMPONENT_EXPORT(MOJO_CPP_PLATFORM) ScopedPlatformHandle
DuplicatePlatformHandle(PlatformHandle platform_handle);

// Converts a base shared memory platform handle into one (maybe two on POSIX)
// EDK ScopedPlatformHandles.
COMPONENT_EXPORT(MOJO_CPP_PLATFORM) void ExtractPlatformHandlesFromSharedMemoryRegionHandle(
    base::subtle::PlatformSharedMemoryRegion::ScopedPlatformHandle handle,
    ScopedPlatformHandle* extracted_handle,
    ScopedPlatformHandle* extracted_readonly_handle);

// Converts one (maybe two on POSIX) EDK ScopedPlatformHandles to a base
// shared memory platform handle.
COMPONENT_EXPORT(MOJO_CPP_PLATFORM)
base::subtle::PlatformSharedMemoryRegion::ScopedPlatformHandle
CreateSharedMemoryRegionHandleFromPlatformHandles(
    ScopedPlatformHandle handle,
    ScopedPlatformHandle readonly_handle);

}  // namespace mojo

#endif  // MOJO_EDK_EMBEDDER_PLATFORM_HANDLE_UTILS_H_
