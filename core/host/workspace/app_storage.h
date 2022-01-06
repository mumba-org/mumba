// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_WORKSPACE_APP_STORAGE_H_
#define MUMBA_HOST_WORKSPACE_APP_STORAGE_H_

#include <memory>

#include "base/macros.h"
#include "base/uuid.h"
#include "base/callback.h"
#include "base/memory/ref_counted.h"
#include "base/files/file_path.h"
#include "base/strings/string_piece.h"
#include "core/host/workspace/storage_layer.h"

namespace host {

class AppStorage : public StorageLayer {
public:
  AppStorage(const base::FilePath& path);
  ~AppStorage() override;

  // StorageLayer
  const base::FilePath& path() const override;
  size_t total_size() override;
  bool Create() override;
  bool Open() override;
  bool IsEmpty() const override;
  bool Empty() override;

  bool CreateDirectory(const base::UUID& id);
  base::FilePath GetDirectory(const base::UUID& id);

private:

  base::FilePath path_;
  
  DISALLOW_COPY_AND_ASSIGN(AppStorage);
};

}

#endif
