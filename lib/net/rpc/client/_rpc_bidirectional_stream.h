// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_CLIENT_RPC_BIDIRECTIONAL_STREAM_H_
#define NET_RPC_CLIENT_RPC_BIDIRECTIONAL_STREAM_H_

#include "base/macros.h"
#include "base/logging.h"
#include "base/single_thread_task_runner.h"
#include "rpc/grpc.h"
#include "core/shared/common/url.h"
#include "net/rpc/client/rpc_stream.h"
#include "net/rpc/client/rpc_continuation.h"
#include "net/rpc/client/rpc_stream_buffer.h"

namespace net {

class NET_EXPORT RpcBidirectionalStream : public RpcStream,
                                          public RpcContinuation::Delegate {
public:

  static std::unique_ptr<RpcStream> Create(
    std::unique_ptr<RpcChannel> channel, 
    const std::string& host,
    const std::string& port, 
    const std::string& name, 
    const std::string& params,
    const scoped_refptr<base::TaskRunner>& task_runner);


  RpcBidirectionalStream(
    std::unique_ptr<RpcChannel> channel, 
    const std::string& host,
    const std::string& port, 
    const std::string& name, 
    const std::string& params,
    const scoped_refptr<base::TaskRunner>& io_task_runner);

  ~RpcBidirectionalStream() override;

  RpcCall* call() const {
    return call_.get(); 
  }

  const scoped_refptr<base::TaskRunner>& io_task_runner() const {
    return io_task_runner_;
  }

  RpcContinuation* continuation() const override;
  void Call(Callback cb, void* data = nullptr) override;
  int64_t output_length() const override;
  int64_t input_length() const override;
  int Read(IOBuffer* buf, int buf_len) const override;
  int Read(std::string* out) const override;
  int Read(const scoped_refptr<base::RefCountedBytes>& data, int buf_len) const override;

  void Shutdown();

  void OnContinue(bool ok, RpcCall* call) override;
  void OnTimeout() override;
  void OnShutdown() override;

private:
  void Init();
  void CreateContinuation();
  void CallImpl(void* data, Callback cb);
  
  void ProcessReceivedData(RpcCall* call, base::WaitableEvent* event);
  void SendReceivedAck(RpcCall* call);
  void FillOutputBuffer(RpcCall* call);
  void FillInputBuffer(const std::string& data);

  //grpc_status_code call_status_;
  //grpc_slice call_status_details_;

  grpc_byte_buffer* recv_message_payload_ = nullptr;
  grpc_byte_buffer* send_message_payload_ = nullptr;
  //grpc_closure on_response_received_;
  //grpc_closure on_initial_request_sent_;
  //grpc_closure on_status_received_;
  grpc_metadata_array begin_metadata_;
  grpc_metadata_array end_metadata_;

  std::unique_ptr<RpcContinuation> continuation_;

  //RpcBytesMemoryStreamWriter stream_writer_;

  char* output_;
  int64_t output_length_ = 0;
  int64_t input_length_ = 0;

  std::unique_ptr<RpcCall> call_;

  //bool first_call_;

  scoped_refptr<base::SequencedTaskRunner> delegate_task_runner_;

  scoped_refptr<base::TaskRunner> io_task_runner_;

  base::WeakPtrFactory<RpcBidirectionalStream> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(RpcBidirectionalStream);
};

}

#endif