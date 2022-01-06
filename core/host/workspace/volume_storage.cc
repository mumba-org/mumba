// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/workspace/volume_storage.h"

#include "base/files/file_util.h"
#include "base/task_scheduler/post_task.h"
#include "base/files/file_util.h"
#include "base/threading/thread_restrictions.h"
#include "base/strings/string_number_conversions.h"
#include "core/host/volume/volume.h"
#include "storage/storage.h"
#include "storage/torrent.h"
#include "storage/storage_manager.h"

namespace host {

VolumeStorage::VolumeStorage(const base::FilePath& path): 
  path_(path),
  storage_manager_(new storage::StorageManager(path_)) {

}

VolumeStorage::~VolumeStorage() {

}

const base::FilePath& VolumeStorage::path() const {
  return path_;
}

size_t VolumeStorage::total_size() {
  return static_cast<size_t>(ComputeDirectorySize(path_));
}

void VolumeStorage::Shutdown() {
  storage_manager_->Shutdown();
}

bool VolumeStorage::IsEmpty() const {
  base::ScopedAllowBlockingForTesting allow_blocking;
  return !base::DirectoryExists(path_);
}

bool VolumeStorage::Empty() {
  base::ScopedAllowBlockingForTesting allow_blocking;
  return base::DeleteFile(path_, true);
}

bool VolumeStorage::Create() {
  base::ScopedAllowBlockingForTesting allow_blocking;
  if (!base::CreateDirectory(path_)) {
  	return false;
  }
  storage_manager_->Init(
  	base::Bind(&VolumeStorage::OnStorageManagerInit, 
  		base::Unretained(this)), 
  	false);
  return true;
}

bool VolumeStorage::Open() {
  base::ScopedAllowBlockingForTesting allow_blocking;
  if (!base::PathExists(path_)) {
  	return false;
  }
  storage_manager_->Init(
  	base::Bind(&VolumeStorage::OnStorageManagerInit, 
  		base::Unretained(this)), 
  	false);
  return true;
}

void VolumeStorage::OnStorageManagerInit(int result) {
  if (result != 0) {
  	DLOG(ERROR) << "VolumeStorage: failed the storage manager on " << path_;
  }
}

bool VolumeStorage::VolumeExists(const base::UUID& id) {
  return false;
}

void VolumeStorage::PutVolume(Volume* container, bool sync) {
  if (sync) {
    PutVolumeImpl(container);
  } else {
    base::PostTaskWithTraits(
      FROM_HERE,
      {base::MayBlock()},
      base::Bind(
        &VolumeStorage::PutVolumeImpl,
          base::Unretained(this),
          base::Unretained(container)));
  }
}

void VolumeStorage::DropVolume(const std::string& name, bool sync) {
  if (sync) {
    DropVolumeImpl(name);
  } else {
    base::PostTaskWithTraits(
      FROM_HERE,
      {base::MayBlock()},
      base::Bind(
        &VolumeStorage::DropVolumeImpl,
          base::Unretained(this),
          name));
  }
}

scoped_refptr<storage::Torrent> VolumeStorage::OpenTorrent(
  const std::string& pack_name, 
  const std::string& torrent_name, 
  base::Callback<void(int64_t)> cb) {
  return storage_manager_->OpenTorrent(pack_name, torrent_name, std::move(cb));
}

storage::Storage* VolumeStorage::GetStorage(const std::string& name) {
  return storage_manager_->GetStorage(name);
}

void VolumeStorage::PutVolumeImpl(Volume* container) {
  //auto torrent = container->container_torrent();

}

void VolumeStorage::DropVolumeImpl(const std::string& name) {
  
}

}