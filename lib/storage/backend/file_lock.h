// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// See net/disk_cache/disk_cache.h for the public interface of the cache.

#ifndef STORAGE_STORAGE_BACKEND_BLOCKFILE_FILE_LOCK_H_
#define STORAGE_STORAGE_BACKEND_BLOCKFILE_FILE_LOCK_H_

#include <stdint.h>

#include "storage/storage_export.h"
#include "storage/backend/storage_format_base.h"

namespace storage {

// This class implements a file lock that lives on the header of a memory mapped
// file. This is NOT a thread related lock, it is a lock to detect corruption
// of the file when the process crashes in the middle of an update.
// The lock is acquired on the constructor and released on the destructor.
// The typical use of the class is:
//    {
//      BlockFileHeader* header = GetFileHeader();
//      FileLock lock(header);
//      header->max_entries = num_entries;
//      // At this point the destructor is going to release the lock.
//    }
// It is important to perform Lock() and Unlock() operations in the right order,
// because otherwise the desired effect of the "lock" will not be achieved. If
// the operations are inlined / optimized, the "locked" operations can happen
// outside the lock.
class STORAGE_EXPORT_PRIVATE FileLock {
 public:
  explicit FileLock(BlockFileHeader* header);
  virtual ~FileLock();

  // Virtual to make sure the compiler never inlines the calls.
  virtual void Lock();
  virtual void Unlock();
 private:
  bool acquired_;
  volatile int32_t* updating_;
};

}  // namespace storage

#endif  // STORAGE_STORAGE_BACKEND_BLOCKFILE_FILE_LOCK_H_
