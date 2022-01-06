// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/blob_info.h"

namespace storage {

BlobInfo::BlobInfo(): Info(storage_proto::BLOB_INFO) {

}

BlobInfo::BlobInfo(std::unique_ptr<storage_proto::Info> info_proto): 
  Info(std::move(info_proto)) {

}

BlobInfo::BlobInfo(storage_proto::Info* proto): 
  Info(proto) {

}

BlobInfo::~BlobInfo() {

}

}