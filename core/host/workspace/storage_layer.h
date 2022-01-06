// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_WORKSPACE_STORAGE_LAYER_H_
#define MUMBA_HOST_WORKSPACE_STORAGE_LAYER_H_

#include <memory>

#include "base/macros.h"
#include "base/files/file_path.h"
#include "base/strings/string_piece.h"

namespace host {

class StorageLayer {
public:
  virtual ~StorageLayer() {}

  virtual const base::FilePath& path() const = 0;
  virtual size_t total_size() = 0;
  virtual bool Create() = 0;
  virtual bool Open() = 0;
  virtual bool IsEmpty() const = 0;
  virtual bool Empty() = 0;
};

}

#endif
