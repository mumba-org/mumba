// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/filesystem_backend.h"

#include "core/shared/domain/storage/cache/cache_filesystem_backend.h"
//#include "core/shared/domain/storage/executable/executable_filesystem_backend.h"

namespace domain {

//static 
FilesystemBackend* FilesystemBackend::Create(
    //FilesystemType type,
    int fs_id,
    const base::UUID& namespace_id, 
    const base::FilePath& namespace_path,
    bool in_memory) {
  //if (type == FilesystemType::kExecutable) {
  //  return new ExecutableFilesystemBackend(fs_id, namespace_id, namespace_path, in_memory);
 // } else if (type == FilesystemType::kCache) {
    return new CacheFilesystemBackend(fs_id, namespace_id, namespace_path, in_memory);
 // }
 // return nullptr;
}

}