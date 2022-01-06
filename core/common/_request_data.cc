// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/common/request_data.h"

namespace common {

RequestData::RequestData(): 
  is_shared_(false), 
  encoding_(kENCODING_FLATBUFFERS) {
 
}

RequestData::RequestData(std::unique_ptr<base::SharedMemory> mem): 
  shmem_(std::move(mem)),
  is_shared_(true),
  encoding_(kENCODING_FLATBUFFERS) {
 
}

RequestData::RequestData(const MessageDescriptor& descriptor): 
  is_shared_(descriptor.shared), 
  encoding_(static_cast<MessageEncoding>(descriptor.body_encoding)) {
 if(descriptor.shared) {
   shmem_.reset(new base::SharedMemory(descriptor.handle, false));
 } else if (!descriptor.body.empty()) {
   std::copy(descriptor.body.begin(), descriptor.body.end(), std::back_inserter(data_));
 }
}

RequestData::~RequestData() {

}

MessageDescriptor RequestData::descriptor() const {
  MessageDescriptor descr;
  descr.body_size = size();

  if (is_shared_) {
    descr.handle = shmem_->handle();
  } else {
    descr.body = std::string(reinterpret_cast<const char *>(data()), size());
  }
  descr.shared = is_shared_; 
  descr.body_encoding = encoding_; 

  return descr;
}

bool RequestData::has_data() const {
  if(is_shared_) {
    return shmem_->requested_size() > 0;
  }
  return !data_.empty();
}

uint8_t* RequestData::data() {
  if(is_shared_) {
    return reinterpret_cast<uint8_t *>(shmem_->memory());
  }
  return &data_[0];
}

const uint8_t* RequestData::data() const {
  if(is_shared_) {
    return reinterpret_cast<const uint8_t *>(shmem_->memory());
  }
  return &data_[0];
}

size_t RequestData::size() const {
  if (is_shared_) {
    return shmem_->requested_size();
  } 
  return data_.size();
}

void RequestData::Write(const uint8_t* data, uint32_t size) {
  if (!is_shared_) {
    std::copy(data, reinterpret_cast<const uint8_t *>(data + size), std::back_inserter(data_));
  } else {
    memcpy(shmem_->memory(), data, size);
  }
}

// const request::Request* RequestData::GetRequest() const {
//   return request::GetRequest(reinterpret_cast<const void *>(data()));
// }

// request::Request* RequestData::GetMutableRequest() {
//   return request::GetMutableRequest(reinterpret_cast<void *>(data()));
// }

}