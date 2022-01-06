// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// See net/disk_cache/disk_cache.h for the public interface of the cache.

#ifndef STORAGE_STORAGE_BACKEND_BLOCKFILE_MAPPED_FILE_H_
#define STORAGE_STORAGE_BACKEND_BLOCKFILE_MAPPED_FILE_H_

#include <stddef.h>

#include "base/macros.h"
#include "storage/storage_export.h"
#include "storage/backend/file.h"
#include "storage/backend/file_block.h"
#include "net/net_buildflags.h"

namespace base {
class FilePath;
}

namespace storage {

// This class implements a memory mapped file used to access block-files. The
// idea is that the header and bitmap will be memory mapped all the time, and
// the actual data for the blocks will be access asynchronously (most of the
// time).
class STORAGE_EXPORT_PRIVATE MappedFile : public File {
 public:
  MappedFile() : File(true), init_(false) {}

  // Performs object initialization. name is the file to use, and size is the
  // amount of data to memory map from the file. If size is 0, the whole file
  // will be mapped in memory.
  void* Init(const base::FilePath& name, size_t size);

  void* buffer() const {
    return buffer_;
  }

  // Loads or stores a given block from the backing file (synchronously).
  bool Load(const FileBlock* block);
  bool Store(const FileBlock* block);

  // Flush the memory-mapped section to disk (synchronously).
  void Flush();

  // Heats up the file system cache and make sure the file is fully
  // readable (synchronously).
  bool Preload();

 private:
  ~MappedFile() override;

  bool init_;
#if defined(OS_WIN)
  HANDLE section_;
#endif
  void* buffer_;  // Address of the memory mapped buffer.
  size_t view_size_;  // Size of the memory pointed by buffer_.
#if BUILDFLAG(POSIX_AVOID_MMAP)
  void* snapshot_;  // Copy of the buffer taken when it was last flushed.
#endif

  DISALLOW_COPY_AND_ASSIGN(MappedFile);
};

// Helper class for calling Flush() on exit from the current scope.
class ScopedFlush {
 public:
  explicit ScopedFlush(MappedFile* file) : file_(file) {}
  ~ScopedFlush() {
    file_->Flush();
  }
 private:
  MappedFile* file_;
};

}  // namespace storage

#endif  // STORAGE_STORAGE_BACKEND_BLOCKFILE_MAPPED_FILE_H_
