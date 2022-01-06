// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_DOMAIN_NAMESPACE_CACHE_CACHE_FILESYSTEM_CREATOR_H_
#define MUMBA_DOMAIN_NAMESPACE_CACHE_CACHE_FILESYSTEM_CREATOR_H_

#include "base/macros.h"
#include "base/files/file_path.h"

namespace domain {

class CacheFilesystemCreator {
public:
  struct Options {
    int64_t size = 0;
    bool in_memory = false;
  };
  
  CacheFilesystemCreator();
  ~CacheFilesystemCreator();

  bool Create(const base::FilePath& path, const Options& options);

private:
  
  DISALLOW_COPY_AND_ASSIGN(CacheFilesystemCreator);
};

}

#endif