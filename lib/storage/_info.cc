// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/info.h"

namespace storage {

Info::Info(storage_proto::InfoKind type)
: info_proto_(new storage_proto::Info()) {
  handle_ = info_proto_.get();
  handle_->set_kind(type);
}

Info::Info(std::unique_ptr<storage_proto::Info> info_proto):
 info_proto_(std::move(info_proto)) {
  handle_ = info_proto_.get();
}

// unowned
Info::Info(storage_proto::Info* info_proto) {
  handle_ = info_proto;
}

Info::~Info() {
  
}

scoped_refptr<net::IOBufferWithSize> Info::Serialize() {
  scoped_refptr<net::IOBufferWithSize> buf = new net::IOBufferWithSize(ComputeEncodedSize());
  if (!handle_->SerializeToArray(buf->data(), buf->size())) {
    return {};
  }
  return buf;
}

bool Info::SerializeTo(net::IOBuffer* io_buffer) {
  return handle_->SerializeToArray(io_buffer->data(), ComputeEncodedSize());
}

bool Info::Deserialize(const void* data, size_t len) {
  return handle_->ParseFromArray(data, len);
}

}