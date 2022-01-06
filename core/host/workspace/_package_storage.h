// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_WORKSPACE_CONTAINER_STORAGE_H_
#define MUMBA_HOST_WORKSPACE_CONTAINER_STORAGE_H_

#include <memory>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "core/host/workspace/storage_layer.h"

namespace host {

class VolumeStorage : public StorageLayer {
public:
  VolumeStorage(const base::FilePath& path);
  ~VolumeStorage() override;
  
  const base::FilePath& path() const override;
  size_t total_size() override;
  bool Create() override;
  bool IsEmpty() const override;
  bool Empty() override;
  
private:
  
  base::FilePath path_;
  
  DISALLOW_COPY_AND_ASSIGN(VolumeStorage);
};

}

#endif
