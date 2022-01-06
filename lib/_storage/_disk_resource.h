// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_LIB_STORAGE_STORAGE_RESOURCE_H_
#define MUMBA_LIB_STORAGE_STORAGE_RESOURCE_H_

#include "base/macros.h"
#include "base/files/file_path.h"
#include "storage/proto/storage.pb.h"

namespace storage {

class StorageResource {
public:
  // any disk resource should be able to 'instantiate itself'
  // with only the Resource proto to describe it
  static std::unique_ptr<StorageResource> New(storage_proto::Resource resource);

  virtual ~StorageResource() {}
  virtual storage_proto::ResourceKind resource_type() const = 0;
  virtual const base::FilePath& path() const = 0;
};

}

#endif