// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_STORAGE_INFO_H_
#define MUMBA_STORAGE_STORAGE_INFO_H_

#include <string>

#include "base/macros.h"
#include "base/files/file_path.h"

namespace storage {

struct StorageInfo {
  int64_t entry_count = 0;
  int64_t disk_size = 0;
  std::string version;
  std::string profile;
  std::string identifier;
  std::string address;
  std::string pubkey;
  std::string privkey;
  std::string creator;
};

}

#endif