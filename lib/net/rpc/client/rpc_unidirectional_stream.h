// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_CLIENT_RPC_UNIDIRECTIONAL_STREAM_H_
#define NET_RPC_CLIENT_RPC_UNIDIRECTIONAL_STREAM_H_

#include "base/macros.h"
#include "base/logging.h"
#include "base/synchronization/waitable_event.h"
#include "rpc/grpc.h"
#include "core/shared/common/url.h"
#include "net/rpc/client/rpc_stream.h"
#include "net/rpc/client/rpc_continuation.h"
#include "net/rpc/client/rpc_stream_buffer.h"

namespace net {

class NET_EXPORT RpcUnidirectionalStream : public RpcStream,
                                           public RpcContinuation::Delegate {
public:
  enum State {
    kSTREAM_NONE = 0,
    kSTREAM_INIT = 1,
    kSTREAM_SEND_CALL = 2,
    kSTREAM_READ = 3,
    kSTREAM_REPLY_READ_DATA_AVAILABLE = 4,
    kSTREAM_DONE = 5
  };
  static std::unique_ptr<RpcStream> Create(
    std::unique_ptr<RpcChannel> channel, 
    const std::string& host,
    const std::string& port, 
    const std::string& name, 
    const std::string& params,
    const scoped_refptr<base::SequencedTaskRunner>& task_runner);

  RpcUnidirectionalStream(
    std::unique_ptr<RpcChannel> channel,
    const std::string& host,
    const std::string& port, 
    const std::string& name, 
    const std::string& params,
    const scoped_refptr<base::SequencedTaskRunner>& task_runner);

  ~RpcUnidirectionalStream() override;

  RpcContinuation* continuation() const override;
  RpcStreamBuffer* input_buffer() const override;
  RpcStreamBuffer* output_buffer() const override;
  int64_t output_length() const override;
  int64_t input_length() const override;
  int64_t total_content_length() const override;
  bool is_encoded() const override;
  const std::string& encoding() const override;
  int Read(IOBuffer* buf, int buf_len) override;
  int Read(std::string* out) override;
  int Read(const scoped_refptr<base::RefCountedBytes>& data, int buf_len) override;
  
  bool was_cleanly_shutdown() const override {
    return shutting_down_;
  }

  void Init() override;
  void Shutdown() override;

  const scoped_refptr<base::SequencedTaskRunner>& io_task_runner() const override {
    return io_task_runner_;
  }

private:
  
  void Run();

  //void CreateContinuation(base::WeakPtr<RpcUnidirectionalStream> weak_ptr);
  void OnContinue(bool ok, RpcCall* call) override;
  void OnTimeout() override;
  void OnShutdown() override;

  //void CallUnary(const std::string& host, const std::string& method, void* data, Callback cb);
  void OnContinueImpl(bool ok);
  void OnShutdownImpl();
    
  int DoLoop();
  int DoInit();
  int DoSendCall();
  int DoRead();
  int DoReplyReadDataAvailable();
  int DoFinish();
  void ScheduleIOLoop();

  std::unique_ptr<RpcCall> CreateCall();
  void BuildOps(RpcCall* call);

  State next_state_;

  grpc_status_code status_;
  grpc_slice status_details_;

  bool pending_call_;

  mutable bool shutting_down_;

  int read_data_available_code_;
  int64_t content_lenght_;
  int32_t encoded_;
  std::string encoding_;

  bool inside_loop_;

  //grpc_call* call_;

  std::unique_ptr<RpcCall> call_;
    
  std::unique_ptr<RpcContinuation> continuation_;//, base::OnTaskRunnerDeleter> continuation_;

  scoped_refptr<base::SingleThreadTaskRunner> delegate_task_runner_;
  
  //scoped_refptr<base::SequencedTaskRunner> loop_task_runner_;
 
  scoped_refptr<base::SequencedTaskRunner> io_task_runner_;

  base::WaitableEvent shutdown_event_;

  base::WeakPtrFactory<RpcUnidirectionalStream> loop_weak_factory_;

  base::WeakPtrFactory<RpcUnidirectionalStream> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(RpcUnidirectionalStream);
};

}

#endif