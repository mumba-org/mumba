// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_LIB_STORAGE_STORAGE_CURRENT_H_
#define MUMBA_LIB_STORAGE_STORAGE_CURRENT_H_

#include <memory>
#include <vector>

#include "base/macros.h"
#include "url/gurl.h"
#include "base/files/file_path.h"

namespace base {
class SingleThreadTaskRunner;
}

namespace storage {
class Storage;

class StorageCurrent {
public:
  // only useful if called from inside a disk
  // (inside a container process or app process)
  static Storage* Get();
  static Storage* Open(const base::FilePath& path);
  
private:
  StorageCurrent(std::unique_ptr<Storage> current);
  ~StorageCurrent();

  std::unique_ptr<Storage> disk_;

  DISALLOW_COPY_AND_ASSIGN(StorageCurrent);
};

}

#endif
