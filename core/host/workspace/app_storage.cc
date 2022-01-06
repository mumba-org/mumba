// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/workspace/app_storage.h"

#include "base/files/file_util.h"
#include "base/task_scheduler/post_task.h"
#include "base/files/file_util.h"
#include "base/threading/thread_restrictions.h"
#include "base/strings/string_number_conversions.h"
#include "core/host/volume/volume.h"

namespace host {

AppStorage::AppStorage(const base::FilePath& path): 
  path_(path) {

}

AppStorage::~AppStorage() {

}

const base::FilePath& AppStorage::path() const {
  return path_;
}

size_t AppStorage::total_size() {
  return static_cast<size_t>(ComputeDirectorySize(path_));
}

bool AppStorage::IsEmpty() const {
  base::ScopedAllowBlockingForTesting allow_blocking;
  return !base::DirectoryExists(path_);
}

bool AppStorage::Empty() {
  base::ScopedAllowBlockingForTesting allow_blocking;
  return base::DeleteFile(path_, true);
}

bool AppStorage::Create() {
  base::ScopedAllowBlockingForTesting allow_blocking;
  if (!base::CreateDirectory(path_)) {
  	return false;
  }
  return true;
}

bool AppStorage::Open() {
  base::ScopedAllowBlockingForTesting allow_blocking;
  if (!base::PathExists(path_)) {
  	return false;
  }
  return true;
}

bool AppStorage::CreateDirectory(const base::UUID& id) {
  base::ScopedAllowBlockingForTesting allow_blocking;
  base::FilePath uuid_path = path_.AppendASCII(id.to_string());
  if (!base::PathExists(uuid_path)) {
    return base::CreateDirectory(uuid_path);  
  }
  return false;
}

base::FilePath AppStorage::GetDirectory(const base::UUID& id) {
  return path_.AppendASCII(id.to_string());
}

}