// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_BLOB_ADDRESS_H_
#define MUMBA_STORAGE_BLOB_ADDRESS_H_

#include <string>
#include "base/files/file_path.h"
#include "storage/proto/storage.pb.h"
#include "base/uuid.h"
#include "url/gurl.h"

namespace storage {

struct BlobAddress {

  enum Source {
    kFILESYSTEM = 0,
    kHTTP = 1,
    kTORRENT = 2,
    kBLOB = 3
  };

  Source source;
  std::string key;
  base::FilePath path;
  
  // auto create from a path
  BlobAddress(const base::FilePath& path):
    source(kFILESYSTEM),
    path(path) {
     
  }

  BlobAddress(Source source, const base::FilePath& path):
    source(source),
    path(path) {
    
  }
 
  BlobAddress(Source source, const std::string& key, const base::FilePath& path):
    source(source),
    key(key),
    path(path) {

  }

  BlobAddress(const std::string& key):
    source(kFILESYSTEM),
    key(key) {
     
  }
};

}

#endif
