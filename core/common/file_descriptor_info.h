// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PUBLIC_BROWSER_FILE_DESCRIPTOR_INFO_H_
#define CONTENT_PUBLIC_BROWSER_FILE_DESCRIPTOR_INFO_H_

#include "base/files/file.h"
#include "base/process/launch.h"

namespace common {

// FileDescriptorInfo is a collection of file descriptors which is
// needed to launch a process. You should tell FileDescriptorInfo
// which FD should be closed and which shouldn't so that it can take care
// of the lifetime of FDs.
//
// See base/process/launcher.h for more details about launching a
// process.
class FileDescriptorInfo {
 public:
  virtual ~FileDescriptorInfo() {}

 #if defined(OS_WIN)
  // Add an FD associated with an ID, without delegating the ownerhip
  // of ID.
  virtual void Share(base::PlatformFile fd) = 0;
  virtual void Transfer(int id, base::ScopedFILE fd) = 0;
  // A vector backed map of registered ID-FD pairs.
  virtual const base::HandlesToInheritVector& GetMapping() const = 0;
  // A GetMapping() variant what adjusts the ID value by |delta|.
  // Some environments need this trick.
  virtual base::HandlesToInheritVector GetMappingWithIDAdjustment(int delta) const = 0;
#elif defined(OS_POSIX)
  // Add an FD associated with an ID, without delegating the ownerhip
  // of ID.
  virtual void Share(int id, base::PlatformFile fd) = 0;

  virtual void Transfer(int id, base::ScopedFD fd) = 0;
  // A vector backed map of registered ID-FD pairs.
  virtual const base::FileHandleMappingVector& GetMapping() const = 0;
  // A GetMapping() variant what adjusts the ID value by |delta|.
  // Some environments need this trick.
  virtual base::FileHandleMappingVector GetMappingWithIDAdjustment(
      int delta) const = 0;
#endif
  
  // API for iterating registered ID-FD pairs.
  virtual base::PlatformFile GetFDAt(size_t i) const = 0;
#if defined(OS_POSIX)
  virtual int GetIDAt(size_t i) const = 0;
#endif  
  virtual size_t GetMappingSize() const = 0;

  // True if |this| has an ownership of |file|.
  virtual bool OwnsFD(base::PlatformFile file) const = 0;
  // Assuming |OwnsFD(file)|, release the ownership.
#if defined(OS_WIN)
  virtual base::ScopedFILE ReleaseFD(base::PlatformFile file) = 0;
#elif defined(OS_POSIX)
  virtual base::ScopedFD ReleaseFD(base::PlatformFile file) = 0;
#endif

};

}

#endif  // CONTENT_PUBLIC_BROWSER_FILE_DESCRIPTOR_INFO_H_
