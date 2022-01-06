// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/module/snapshot_file_loader.h"

namespace domain {

SnapshotFileLoader::SnapshotFileLoader():
 library_loaded_(false) {

}

SnapshotFileLoader::~SnapshotFileLoader() {
  
}

bool SnapshotFileLoader::is_loaded() const {
  return library_loaded_;
}

bool SnapshotFileLoader::LoadFromLocalFile(const base::FilePath& path) {
  return false;
}

bool SnapshotFileLoader::LoadFromMemoryBuffer(void* buffer, size_t size) {
  return false;
}

void SnapshotFileLoader::Unload() {
}
  
Address SnapshotFileLoader::GetCodeEntry(const std::string& name) {
  return kNullAddress;
}

}