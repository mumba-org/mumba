// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/rpc/client/rpc_stream_buffer.h"

#include "rpc/support/alloc.h"
#include "rpc/byte_buffer.h"
#include "rpc/byte_buffer_reader.h"
#include "net/base/io_buffer.h"
#include "net/rpc/client/rpc_unidirectional_stream.h"

namespace net {

RpcStreamBuffer::RpcStreamBuffer(RpcStreamBuffer::Delegate* delegate):
  delegate_(delegate),
  buffer_(nullptr), 
  pending_read_(false),
  buffer_binded_(false),
  lazy_reading_(true),
  bytes_readed_(0),
  bytes_written_(0) {

  grpc_metadata_array_init(&begin_metadata_);
  grpc_metadata_array_init(&end_metadata_);
  reader_.BindSource(this);
}

RpcStreamBuffer::~RpcStreamBuffer() {
  if (buffer_ && buffer_binded_)
    grpc_byte_buffer_destroy(buffer_);
  
  grpc_metadata_array_destroy(&begin_metadata_);
  grpc_metadata_array_destroy(&end_metadata_);

  observers_.clear();
}

Error RpcStreamBuffer::OnDataAvailable() {
  Error rv = OK;
  if (buffer_binded_ && buffer_) {
    //DLOG(INFO) << "RpcStreamBuffer::OnDataAvailable: buffer_binded_ && buffer_ " 
    //  << " returning rv = " << rv;
    pending_read_ = true;
    NotifyDataAvailable();
    return rv;
  }
  rv = ERR_FAILED; 
  //(INFO) << "RpcStreamBuffer::OnDataAvailable: buffer_binded_ " << buffer_binded_ << 
  //  " && buffer_ = " << buffer_ << " returning rv = " << rv;
  //bytes_readed_ = 0;  
  delegate_->OnDoneReading(rv);
  return rv;
}

void RpcStreamBuffer::AddObserver(RpcStreamBufferObserver* observer) {
  observers_.push_back(observer);
}

void RpcStreamBuffer::RemoveObserver(RpcStreamBufferObserver* observer) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == *it) {
      observers_.erase(it);
      return;
    }
  }
}

void RpcStreamBuffer::BindBuffer(grpc_op* op) {
  // check if we are reusing the buffer
  // in this case destroy the old one
  if (buffer_) {
    grpc_byte_buffer_destroy(buffer_);
    buffer_ = nullptr;
    buffer_binded_ = false;
  }
  op->data.recv_message.recv_message = &buffer_;
  buffer_binded_ = true;
}

int RpcStreamBuffer::Read(IOBuffer* buf, int buf_len) {
  return reader_.Read(buf, buf_len);
}

int RpcStreamBuffer::Read(std::string* out) {
  return reader_.Read(out);
}

int RpcStreamBuffer::Read(const scoped_refptr<base::RefCountedBytes>& data, int buf_len) {
  return reader_.Read(data, buf_len);
}

void RpcStreamBuffer::Write(const std::string& string) {
  if (buffer_) {
    grpc_byte_buffer_destroy(buffer_);
    buffer_ = nullptr;
    buffer_binded_ = false;
  }
  bytes_written_ = string.size();
  grpc_slice buffer_slice = grpc_slice_from_copied_string(string.c_str());
  buffer_ = grpc_raw_byte_buffer_create(&buffer_slice, 1);
  grpc_slice_unref(buffer_slice);
  buffer_binded_ = true;
  //OnDataAvailable();
}

void RpcStreamBuffer::OnBufferReaded(int bytes) {
  pending_read_ = false;
  bytes_readed_ = bytes > 0 ? bytes : 0;
  // if (bytes > 0 && buffer_) {
  //   grpc_byte_buffer_destroy(buffer_);
  //   buffer_ = nullptr;
  //   buffer_binded_ = false;
  // }
  delegate_->OnDoneReading(bytes);
}

void RpcStreamBuffer::NotifyDataAvailable() {
  if (buffer_ == nullptr) {
    pending_read_ = false;
    //buffer_binded_ = false;
    return;
  }
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    (*it)->OnDataAvailable(this, lazy_reading_);
  }
}

int64_t RpcStreamBuffer::last_bytes_copied() const {
  return reader_.last_bytes_copied();
}


RpcStreamBufferReader::RpcStreamBufferReader(): 
  output_(nullptr), 
  bytes_readed_(0),
  last_bytes_copied_(0),
  bytes_left_(0),
  pending_read_(false) {
  
}

RpcStreamBufferReader::~RpcStreamBufferReader() {
  if (source_)
    source_->RemoveObserver(this);
  
  source_ = nullptr;
  if (output_) {
    gpr_free(output_);
  }
}

void RpcStreamBufferReader::BindSource(RpcStreamBuffer* source) {
  source_ = source;
  source_->AddObserver(this);
}

void RpcStreamBufferReader::OnDataAvailable(RpcStreamBuffer* buffer, bool lazy_reading) {
  //DLOG(INFO) << "RpcStreamBufferReader::OnDataAvailable";
  pending_read_ = true;
  //if (!lazy_reading) {
  ReadBuffer();
  //}
}

int RpcStreamBufferReader::Read(IOBuffer* buf, int buf_len) {
  int available = static_cast<int>(bytes_readed_);
  if (pending_read_) {
    DLOG(INFO) << "Buffer::Read: pending read = true";
    available = ReadBuffer();
  }
  bytes_left_ = bytes_left_ - last_bytes_copied_;
  bytes_consumed_ = available - bytes_left_;
  int bytes_to_copy = bytes_left_ <= buf_len ? bytes_left_ : buf_len; 
  DLOG(INFO) << "Buffer::Read(" << this << "): buffer = " << source_ << " \n  available: " << available <<
     "\n  bytes_consumed: " << bytes_consumed_ << 
     "\n  last_bytes_copied: " << last_bytes_copied_ << 
     "\n  bytes_left: " << bytes_left_ << 
     "\n  buf_len: " << buf_len <<
     "\n  bytes_to_copy: " << bytes_to_copy;
  if (bytes_to_copy > 0) {
    memcpy(buf->data(), output_ + bytes_consumed_, bytes_to_copy);
    last_bytes_copied_ = bytes_to_copy;
    DLOG(INFO) << "Buffer::Read: bytes_to_copy > 0 => last_bytes_copied_ = " << last_bytes_copied_;
  }
  return bytes_to_copy;
}

int RpcStreamBufferReader::Read(std::string* out) {
  int available = static_cast<int>(bytes_readed_);
  if (pending_read_) {
    available = ReadBuffer();
  }
  int bytes_to_copy = available - last_bytes_copied_;
  if (bytes_to_copy > 0) {
    out->assign(output_, bytes_to_copy);
    last_bytes_copied_ = bytes_to_copy;
  }
  return bytes_to_copy;
}

int RpcStreamBufferReader::Read(const scoped_refptr<base::RefCountedBytes>& data, int buf_len) {
  int available = static_cast<int>(bytes_readed_);
  if (pending_read_) {
    available = ReadBuffer();
  }
  int rest = available - last_bytes_copied_;
  int bytes_to_copy = rest <= buf_len ? rest : buf_len;
  if (bytes_to_copy > 0) {
    memcpy(data->front(), output_, bytes_to_copy);
    last_bytes_copied_ = bytes_to_copy;
  }
  return bytes_to_copy;
}

int RpcStreamBufferReader::ReadBuffer() {
  // reset this
  last_bytes_copied_ = 0;

  grpc_byte_buffer_reader reader;  
  grpc_byte_buffer_reader_init(&reader, source_->c_buffer());
  grpc_slice resp_slice = grpc_byte_buffer_reader_readall(&reader);
  grpc_byte_buffer_reader_destroy(&reader);

  bytes_readed_ = GRPC_SLICE_LENGTH(resp_slice);
  //DLOG(INFO) << "RpcStreamBufferReader::ReadBuffer(" << this << ") : bytes_readed_ = " << bytes_readed_;
  bytes_left_ = bytes_readed_;

  // TODO: see if in this case we can go straight to the 
  // bytes on the slice, given this gives us a copy we dont actually need
  // ( the insert() later will copy the data into its own memory)
  output_ = grpc_slice_to_c_string(resp_slice);
  
  grpc_slice_unref(resp_slice);
  
  pending_read_ = false;

  source_->OnBufferReaded(bytes_readed_);

  return bytes_readed_;
}


}