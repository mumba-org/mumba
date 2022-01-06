// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_NAMESPACE_EXTENT_BACKEND_H_
#define MUMBA_DOMAIN_NAMESPACE_NAMESPACE_EXTENT_BACKEND_H_

#include "base/macros.h"
#include "base/callback.h"
#include "base/files/file_path.h"
#include "base/uuid.h"

//#include "core/shared/domain/storage/filesystem_type.h"

namespace domain {

class FilesystemBackend {
public:
  static FilesystemBackend* Create(
    //FilesystemType type,
    int fs_id,
    const base::UUID& namespace_id, 
    const base::FilePath& namespace_path, 
    bool in_memory);
  
  virtual ~FilesystemBackend() {}
  
  virtual int id() const = 0;
  //virtual FilesystemType type() const = 0;
  virtual bool in_memory() const = 0;
  virtual int32_t GetFileCount() const = 0;
  virtual void Initialize(const base::Callback<void(int, int)>& callback) = 0;
  virtual void Shutdown() = 0;
};

}

#endif