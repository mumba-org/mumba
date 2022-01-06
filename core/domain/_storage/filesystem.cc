// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/domain/storage/filesystem.h"

#include "core/shared/domain/storage/filesystem_backend.h"

namespace domain {

Filesystem::Filesystem(
 // FilesystemType type,
  int id,
  const base::UUID& namespace_id, 
  const base::FilePath& fs_path,
  bool in_memory): 
  backend_(FilesystemBackend::Create(id, namespace_id, fs_path, in_memory)),
  id_(id),
  state_(kUndefined) {
  
}

Filesystem::~Filesystem() {

}

// FilesystemType Filesystem::type() const {
//   return backend_->type();
// }

bool Filesystem::in_memory() const {
  return backend_->in_memory();
}

int32_t Filesystem::GetFileCount() const {
  return backend_->GetFileCount();
}

void Filesystem::Initialize(const base::Callback<void(int, int)>& result) {
  backend_->Initialize(result);
}

void Filesystem::Shutdown() {
  backend_->Shutdown();
}

}