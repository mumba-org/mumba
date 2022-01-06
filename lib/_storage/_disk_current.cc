// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/storage_current.h"

#include "build/build_config.h"
#include "base/files/file_util.h"
#include "base/memory/singleton.h"
#include "base/lazy_instance.h"
#include "base/strings/utf_string_conversions.h"
#include "base/threading/thread_local.h"
#include "base/threading/thread_task_runner_handle.h"
#include "storage/manifest_proto.h"
#include "storage/storage.h"
//#include "storage/storage_factory.h"

namespace storage {

namespace {

base::LazyInstance<base::ThreadLocalPointer<StorageCurrent>>::Leaky
    disk_instance = LAZY_INSTANCE_INITIALIZER;

}  // namespace

// static
Storage* StorageCurrent::Get() {
  StorageCurrent* current = disk_instance.Pointer()->Get();
  CHECK(current) << "Error: instance for Storage was not created properly. use StorageInstance::Load() first";
  return current->disk_.get();
}

// static 
Storage* StorageCurrent::Open(const base::FilePath& path) {
  Storage* disk = StorageCurrent::Get(); 
  // already loaded
  if (disk) {
    return disk;
  }

  std::unique_ptr<Storage> disk_handle = Storage::Open(path);

  StorageCurrent* current = new StorageCurrent(std::move(disk_handle));
  return current->disk_.get();
}

StorageCurrent::StorageCurrent(std::unique_ptr<Storage> current):
 disk_(std::move(current)) {
  disk_instance.Pointer()->Set(this);
}

StorageCurrent::~StorageCurrent() {
  disk_instance.Pointer()->Set(nullptr); 
}

}