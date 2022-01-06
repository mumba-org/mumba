// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// See net/disk_cache/disk_cache.h for the public interface of the cache.

#ifndef STORAGE_STORAGE_BACKEND_BACKEND_UTILS_H_
#define STORAGE_STORAGE_BACKEND_BACKEND_UTILS_H_

#include "base/files/file_path.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "storage/storage_export.h"
#include "net/log/net_log_parameters_callback.h"

namespace net {
struct NetLogSource;
}

namespace storage {
class StorageEntry;

extern STORAGE_EXPORT_PRIVATE const int64_t kDefaultCacheSize;

STORAGE_EXPORT_PRIVATE bool MoveCache(const base::FilePath& from_path, const base::FilePath& to_path);
STORAGE_EXPORT_PRIVATE void DeleteStorage(const base::FilePath& path, bool remove_folder);
STORAGE_EXPORT_PRIVATE bool DelayedCacheCleanup(const base::FilePath& full_path);
STORAGE_EXPORT_PRIVATE int64_t PreferredCacheSize(int64_t available);
STORAGE_EXPORT_PRIVATE bool DeleteStorageFile(const base::FilePath& name);

net::NetLogParametersCallback CreateNetLogReadWriteDataCallback(int index,
                                                                int offset,
                                                                int buf_len,
                                                                bool truncate);

net::NetLogParametersCallback CreateNetLogReadWriteCompleteCallback(int bytes_copied);

net::NetLogParametersCallback CreateNetLogEntryCreationCallback(const scoped_refptr<StorageEntry>& entry, bool created);

// Creates a NetLog callback that returns parameters for when a sparse
// operation is started.
net::NetLogParametersCallback CreateNetLogSparseOperationCallback(
    int64_t offset,
    int buf_len);

// Creates a NetLog callback that returns parameters for when a read or write
// for a sparse entry's child is started.
net::NetLogParametersCallback CreateNetLogSparseReadWriteCallback(
    const net::NetLogSource& source,
    int child_len);

// Creates a NetLog callback that returns parameters for when a call to
// GetAvailableRange returns.
net::NetLogParametersCallback CreateNetLogGetAvailableRangeResultCallback(
    int64_t start,
    int result);

}  // namespace storage

#endif