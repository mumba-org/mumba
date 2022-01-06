// Copyright 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/execution/stream.h"

namespace domain {

ReadIOBuffer::ReadIOBuffer()
    : base_(new net::GrowableIOBuffer()),
      max_buffer_size_(kDefaultMaxBufferSize) {
  SetCapacity(kInitialBufSize);
}

ReadIOBuffer::~ReadIOBuffer() {
  data_ = NULL;  // base_ owns data_.
}

int ReadIOBuffer::GetCapacity() const {
  return base_->capacity();
}

void ReadIOBuffer::SetCapacity(int capacity) {
  DCHECK_LE(GetSize(), capacity);
  base_->SetCapacity(capacity);
  data_ = base_->data();
}

bool ReadIOBuffer::IncreaseCapacity() {
  if (GetCapacity() >= max_buffer_size_) {
    LOG(ERROR) << "Too large read data is pending: capacity=" << GetCapacity()
               << ", max_buffer_size=" << max_buffer_size_
               << ", read=" << GetSize();
    return false;
  }

  int new_capacity = GetCapacity() * kCapacityIncreaseFactor;
  if (new_capacity > max_buffer_size_)
    new_capacity = max_buffer_size_;
  SetCapacity(new_capacity);
  return true;
}

char* ReadIOBuffer::StartOfBuffer() const {
  return base_->StartOfBuffer();
}

int ReadIOBuffer::GetSize() const {
  return base_->offset();
}

void ReadIOBuffer::DidRead(int bytes) {
  DCHECK_GE(RemainingCapacity(), bytes);
  base_->set_offset(base_->offset() + bytes);
  data_ = base_->data();
}

int ReadIOBuffer::RemainingCapacity() const {
  return base_->RemainingCapacity();
}

void ReadIOBuffer::DidConsume(int bytes) {
  int previous_size = GetSize();
  int unconsumed_size = previous_size - bytes;
  DCHECK_LE(0, unconsumed_size);
  if (unconsumed_size > 0) {
    // Move unconsumed data to the start of buffer.
    memmove(StartOfBuffer(), StartOfBuffer() + bytes, unconsumed_size);
  }
  base_->set_offset(unconsumed_size);
  data_ = base_->data();

  // If capacity is too big, reduce it.
  if (GetCapacity() > kMinimumBufSize &&
      GetCapacity() > previous_size * kCapacityIncreaseFactor) {
    int new_capacity = GetCapacity() / kCapacityIncreaseFactor;
    if (new_capacity < kMinimumBufSize)
      new_capacity = kMinimumBufSize;
    // realloc() within GrowableIOBuffer::SetCapacity() could move data even
    // when size is reduced. If unconsumed_size == 0, i.e. no data exists in
    // the buffer, free internal buffer first to guarantee no data move.
    if (!unconsumed_size)
      base_->SetCapacity(0);
    SetCapacity(new_capacity);
  }
}

QueuedWriteIOBuffer::QueuedWriteIOBuffer()
    : total_size_(0),
      max_buffer_size_(kDefaultMaxBufferSize) {
}

QueuedWriteIOBuffer::~QueuedWriteIOBuffer() {
  data_ = NULL;  // pending_data_ owns data_.
}

bool QueuedWriteIOBuffer::IsEmpty() const {
  return pending_data_.empty();
}

bool QueuedWriteIOBuffer::Append(const std::string& data) {
  if (data.empty())
    return true;

  if (total_size_ + static_cast<int>(data.size()) > max_buffer_size_) {
    LOG(ERROR) << "Too large write data is pending: size="
               << total_size_ + data.size()
               << ", max_buffer_size=" << max_buffer_size_;
    return false;
  }

  pending_data_.push(std::make_unique<std::string>(data));
  total_size_ += data.size();

  // If new data is the first pending data, updates data_.
  if (pending_data_.size() == 1)
    data_ = const_cast<char*>(pending_data_.front()->data());
  return true;
}

void QueuedWriteIOBuffer::DidConsume(int size) {
  DCHECK_GE(total_size_, size);
  DCHECK_GE(GetSizeToWrite(), size);
  if (size == 0)
    return;

  if (size < GetSizeToWrite()) {
    data_ += size;
  } else {  // size == GetSizeToWrite(). Updates data_ to next pending data.
    pending_data_.pop();
    data_ = IsEmpty() ? NULL : const_cast<char*>(pending_data_.front()->data());
  }
  total_size_ -= size;
}

int QueuedWriteIOBuffer::GetSizeToWrite() const {
  if (IsEmpty()) {
    DCHECK_EQ(0, total_size_);
    return 0;
  }
  DCHECK_GE(data_, pending_data_.front()->data());
  int consumed = static_cast<int>(data_ - pending_data_.front()->data());
  DCHECK_GT(static_cast<int>(pending_data_.front()->size()), consumed);
  return pending_data_.front()->size() - consumed;
}


Stream::Stream():
  read_buf_(new ReadIOBuffer()),
  write_buf_(new QueuedWriteIOBuffer()) {

}

Stream::~Stream() {

}

}