// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/workspace/volume_storage.h"

#include "base/files/file_util.h"

namespace host {

VolumeStorage::VolumeStorage(const base::FilePath& path): 
  path_(path) {

}

VolumeStorage::~VolumeStorage() {

}

const base::FilePath& VolumeStorage::path() const {
  return path_;
}

size_t VolumeStorage::total_size() {
  return static_cast<size_t>(ComputeDirectorySize(path_));
}

bool VolumeStorage::IsEmpty() const {
  return !base::DirectoryExists(path_);
}

bool VolumeStorage::Empty() {
  return base::DeleteFile(path_, true);
}

bool VolumeStorage::Create() {
  return base::CreateDirectory(path_);
}

}