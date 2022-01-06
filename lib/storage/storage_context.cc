// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "storage/storage_context.h"

#include "storage/torrent.h"
#include "net/base/net_errors.h"
#include "net/base/io_buffer.h"

namespace storage {

IOBufferWrapper::IOBufferWrapper(void* data, int64_t size)
    : IOBuffer(static_cast<char*>(NULL)),
      real_data_(data),
      size_(size) {
  data_ = reinterpret_cast<char*>(real_data_);
}

IOBufferWrapper::IOBufferWrapper(const void* data, int64_t size)
    : IOBuffer(static_cast<char*>(NULL)),
      real_data_(const_cast<void *>(data)),
      size_(size) {
  data_ = reinterpret_cast<char*>(real_data_);
}

IOBufferWrapper::~IOBufferWrapper() {
  // We haven't allocated the buffer, so remove it before the base class
  // destructor tries to delete[] it.
  data_ = NULL;
}

}