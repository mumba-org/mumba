// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/common/data/data_common.h"

namespace common {

namespace {

const int kVARLENGTH_MEDIAN_SIZE = 255;

}

ColumnData::ColumnData() {}

ColumnData::~ColumnData() {}

void ColumnData::Init(BufferAllocator* allocator, size_t length, bool is_var_length) {
  Init(allocator, length, is_var_length, length * kVARLENGTH_MEDIAN_SIZE);
}

void ColumnData::Init(BufferAllocator* allocator, size_t length, bool is_var_length, size_t var_length_size) {
  is_var_length_ = is_var_length;
  if (is_var_length) {
    arena_.reset(new Arena(allocator, var_length_size, std::numeric_limits<size_t>::max()));
  }
  //LOG(INFO) << "allocando " << length << " bytes";
  data_buffer_.reset(allocator->Allocate(length));
}

void ColumnData::GrowBuffer(BufferAllocator* allocator, size_t len) {
  base::AutoLock lock(lock_);
  CHECK(allocator);
  Buffer* buf = data_buffer_.get();
  CHECK(buf);
  size_t newsize = len + data_buffer_->size();
  //LOG(INFO) << "reallocando " << newsize << " bytes";
  allocator->Reallocate(newsize, buf);
  //LOG(INFO) << "saindo de growbuffer. buf at: " << buf->data();
}

TableSchema::TableSchema(): cur_pos_(0) {

}

TableSchema::~TableSchema() {
  for (auto it = schemas_.begin(); it != schemas_.end(); ++it) {
    delete *it;
  }
}


}