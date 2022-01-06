// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_CLIENT_RPC_STREAM_BUFFER_H_
#define NET_RPC_CLIENT_RPC_STREAM_BUFFER_H_

#include <string>
#include <vector>

#include "base/macros.h"
#include "base/memory/ref_counted_memory.h"
#include "rpc/grpc.h"
#include "net/base/net_export.h"
#include "net/base/net_errors.h"
#include "rpc/impl/codegen/grpc_types.h"

namespace net {
class IOBuffer;
class RpcUnidirectionalStream;
class RpcBidirectionalStream;
class RpcStreamBuffer;

class RpcStreamBufferObserver {
public: 
  virtual ~RpcStreamBufferObserver() {}
  virtual void OnDataAvailable(RpcStreamBuffer* buffer, bool lazy_reading) = 0;
};

class RpcStreamBufferReader : public RpcStreamBufferObserver {
public:
  RpcStreamBufferReader();
  ~RpcStreamBufferReader() override;

  char* output() const {
    return output_;
  }

  size_t bytes_readed() const {
    return bytes_readed_;
  }

  int64_t last_bytes_copied() const {
    return last_bytes_copied_;
  }

  void BindSource(RpcStreamBuffer* source);

  int Read(IOBuffer* buf, int buf_len);
  int Read(std::string* out);
  int Read(const scoped_refptr<base::RefCountedBytes>& data, int buf_len);

private:

  void OnDataAvailable(RpcStreamBuffer* buffer, bool lazy_reading) override; 
  int ReadBuffer();

  char* output_;
  size_t bytes_readed_;
  int64_t last_bytes_copied_;
  int64_t bytes_left_;
  int64_t bytes_consumed_;
  bool pending_read_;
  RpcStreamBuffer* source_;
};


class NET_EXPORT RpcStreamBuffer {
public:
  class Delegate {
  public:
    virtual ~Delegate() {}
    virtual void OnDoneReading(int code) = 0;
  };
  RpcStreamBuffer(Delegate* delegate);
  ~RpcStreamBuffer();

  int64_t bytes_readed() const {
    return bytes_readed_;
  }

  int64_t bytes_written() const {
    return bytes_written_;
  }

  int64_t last_bytes_copied() const;

  bool pending_read() const { return pending_read_; }  

  grpc_byte_buffer* c_buffer() { return buffer_; }
  grpc_metadata_array* c_begin_metadata() { return &begin_metadata_; }
  grpc_metadata_array* c_end_metadata() { return &end_metadata_; }

  void AddObserver(RpcStreamBufferObserver* observer);
  void RemoveObserver(RpcStreamBufferObserver* observer);

  void BindBuffer(grpc_op* op);

  int Read(IOBuffer* buf, int buf_len);
  int Read(std::string* out);
  int Read(const scoped_refptr<base::RefCountedBytes>& data, int buf_len);

  void Write(const std::string& string);

  Error OnDataAvailable();
  void OnBufferReaded(int bytes);

private:
  friend class RpcUnidirectionalStream;
  friend class RpcBidirectionalStream;
  
  void NotifyDataAvailable();

  Delegate* delegate_;

  RpcStreamBufferReader reader_;

  grpc_metadata_array begin_metadata_;
  grpc_metadata_array end_metadata_;
  grpc_byte_buffer* buffer_;

  std::vector<RpcStreamBufferObserver *> observers_;

  bool pending_read_;
  bool buffer_binded_;
  bool lazy_reading_;
  int64_t bytes_readed_;
  int64_t bytes_written_;

  DISALLOW_COPY_AND_ASSIGN(RpcStreamBuffer);
};


}

#endif