// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_STORAGE_BLOB_INFO_H_
#define MUMBA_STORAGE_BLOB_INFO_H_

#include <string>
#include <memory>

#include "base/macros.h"
#include "base/files/file_path.h"
#include "storage/proto/storage.pb.h"
#include "storage/info.h"
#include "url/gurl.h"

namespace storage {

/*
 * A blob info is a metadata about a blob, and all the information
 * needed to deal with a particular blob contents
 * this is a blob index node, or inode and are not meant
 * to hold the content of a blob
 *
 * NOTE: A blob info should be easily 'translatable' 
 *       to a libtorrent 'file_entry' (file_storage.hpp). We should be able
 *       to create a 'file_entry' reference from a blob info
 */

class BlobInfo : public Info {
public:
  BlobInfo();
  BlobInfo(std::unique_ptr<storage_proto::Info> info_proto);
  BlobInfo(storage_proto::Info* proto);
  ~BlobInfo();

  // offset inside according to the disk
  // positional offset

  int64_t offset() const {
    return info_proto_->offset();
  }

  void set_offset(int64_t offset) {
    info_proto_->set_offset(offset);
  }

};

}

#endif