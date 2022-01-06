// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef COMMON_REQUEST_DATA_H_
#define COMMON_REQUEST_DATA_H_

#include <vector>

#include "base/memory/ref_counted.h"
#include <memory>
#include "core/common/message_descriptor.h"
//#include "core/common/request_generated.h"
#include "base/memory/shared_memory.h"

namespace common {

// TODO: Maybe create a RequestIterator?
class RequestData : public base::RefCountedThreadSafe<RequestData> {
public:
  RequestData();
  RequestData(std::unique_ptr<base::SharedMemory> mem);
  RequestData(const MessageDescriptor& descriptor);

  MessageEncoding encoding() const { return encoding_; }

  bool is_shared() const { return is_shared_; }
 
  //TODO: automate the process of building a request::Request from a flatbuffer payload

  MessageDescriptor descriptor() const;

  bool has_data() const;

  const uint8_t* data() const;

  uint8_t* data();

  size_t size() const;

  void Write(const uint8_t* data, uint32_t size);

  //const request::Request* GetRequest() const;
  //request::Request* GetMutableRequest();

private:
  friend class base::RefCountedThreadSafe<RequestData>;
  ~RequestData();
  
  std::unique_ptr<base::SharedMemory> shmem_;
  bool is_shared_;
  std::vector<uint8_t> data_;
  MessageEncoding encoding_;
};

}

#endif