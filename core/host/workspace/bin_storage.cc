// Copyright (c) 2022 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/workspace/bin_storage.h"

#include "base/files/file_util.h"
#include "base/task_scheduler/post_task.h"
#include "base/files/file_util.h"
#include "base/threading/thread_restrictions.h"
#include "base/strings/string_number_conversions.h"
#include "core/host/volume/volume.h"

namespace host {

BinStorage::BinStorage(const base::FilePath& path): 
  path_(path) {

}

BinStorage::~BinStorage() {

}

const base::FilePath& BinStorage::path() const {
  return path_;
}

size_t BinStorage::total_size() {
  return static_cast<size_t>(ComputeDirectorySize(path_));
}

bool BinStorage::IsEmpty() const {
  base::ScopedAllowBlockingForTesting allow_blocking;
  return !base::DirectoryExists(path_);
}

bool BinStorage::Empty() {
  base::ScopedAllowBlockingForTesting allow_blocking;
  return base::DeleteFile(path_, true);
}

bool BinStorage::Create() {
  base::ScopedAllowBlockingForTesting allow_blocking;
  if (!base::CreateDirectory(path_)) {
  	return false;
  }
  return true;
}

bool BinStorage::Open() {
  base::ScopedAllowBlockingForTesting allow_blocking;
  if (!base::PathExists(path_)) {
  	return false;
  }
  return true;
}

bool BinStorage::CreateDirectory(const base::UUID& id) {
  base::ScopedAllowBlockingForTesting allow_blocking;
  base::FilePath uuid_path = path_.AppendASCII(id.to_string());
  if (!base::PathExists(uuid_path)) {
    return base::CreateDirectory(uuid_path);  
  }
  return false;
}

base::FilePath BinStorage::GetDirectory(const base::UUID& id) {
  return path_.AppendASCII(id.to_string());
}

}