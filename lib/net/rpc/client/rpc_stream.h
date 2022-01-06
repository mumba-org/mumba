// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_CLIENT_RPC_STREAM_H_
#define NET_RPC_CLIENT_RPC_STREAM_H_

#include <memory>

#include "base/macros.h"
#include "base/logging.h"
#include "base/callback.h"
#include "base/single_thread_task_runner.h"
#include "base/memory/ref_counted_memory.h"
#include "base/synchronization/waitable_event.h"
#include "rpc/grpc.h"
#include "net/base/net_errors.h"
#include "net/rpc/rpc.h"
#include "net/rpc/client/rpc_stream_buffer.h"
#include "core/shared/common/url.h"
#include "base/uuid.h"

namespace net {
class RpcContinuation;
class RpcUnidirectionalStream;
class RpcBidirectionalStream;
class RpcChannel;
class RpcCall;
class IOBuffer;

class NET_EXPORT RpcStream : public RpcStreamBuffer::Delegate {
public:

  typedef base::Callback<void(int)> StreamReadDataAvailableCallback;

  virtual ~RpcStream();
  const base::UUID& uuid() const { return uuid_; }
  const std::string& name() const { return name_; }
  const std::string& host() const { return host_; }
  const std::string& port() const { return port_; }
  const std::string& params() const { return params_; }
  RpcChannel* channel() const { return channel_.get(); }
  // FIXME: having the buffers as a fixed state on the stream
  //        is a bad approach.. see ways to make this better
  virtual RpcStreamBuffer* input_buffer() const = 0; //{ return input_buffer_.get(); }
  virtual RpcStreamBuffer* output_buffer() const = 0;// { return output_buffer_.get(); }
 
  virtual int64_t output_length() const = 0;
  virtual int64_t input_length() const = 0;
  virtual int64_t total_content_length() const = 0;
  virtual bool is_encoded() const = 0;
  virtual const std::string& encoding() const = 0;
  
  // maybe not ideal, but for now..
  bool DataAvailable() const;

  virtual void Cancel();
  virtual void Shutdown() = 0;
  virtual bool was_cleanly_shutdown() const = 0;

  virtual RpcContinuation* continuation() const = 0;
  virtual void Init() = 0;
  virtual int Read(IOBuffer* buf, int buf_len) = 0;
  virtual int Read(std::string* out) = 0;
  virtual int Read(const scoped_refptr<base::RefCountedBytes>& data, int buf_len) = 0;

  void OnDoneReading(int code) override;

  void BindStreamReadDataAvailable(StreamReadDataAvailableCallback stream_read_data_available) {
    stream_read_data_available_ = std::move(stream_read_data_available);
  }

protected:
  RpcStream(std::unique_ptr<RpcChannel> channel, const std::string& host, const std::string& port, const std::string& name, const std::string& params);

  //std::unique_ptr<RpcStreamBuffer> input_buffer_;
  //std::unique_ptr<RpcStreamBuffer> output_buffer_;
  std::unique_ptr<RpcChannel> channel_;
  StreamReadDataAvailableCallback stream_read_data_available_;
  bool done_reading_;
  int done_reading_code_;
  
private:
  friend class RpcUnidirectionalStream;
  friend class RpcBidirectionalStream;

  base::UUID uuid_;
  std::string host_;
  std::string port_;
  std::string name_;
  std::string params_;

  DISALLOW_COPY_AND_ASSIGN(RpcStream);
};

}

#endif