// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_CLIENT_RPC_BIDIRECTIONAL_STREAM_H_
#define NET_RPC_CLIENT_RPC_BIDIRECTIONAL_STREAM_H_

#include "base/macros.h"
#include "base/logging.h"
#include "base/single_thread_task_runner.h"
#include "base/synchronization/waitable_event.h"
#include "rpc/grpc.h"
#include "core/shared/common/url.h"
#include "net/rpc/client/rpc_stream.h"
#include "net/rpc/client/rpc_continuation.h"
#include "net/rpc/client/rpc_stream_buffer.h"

namespace net {

class NET_EXPORT RpcBidirectionalStream : public RpcStream,
                                          public RpcContinuation::Delegate {
public:
  enum State {
    kSTREAM_NONE = 0,
    kSTREAM_INIT = 1,
    kSTREAM_SEND_CALL = 2,
    kSTREAM_READ = 3,
    kSTREAM_REPLY_READ_DATA_AVAILABLE = 4,
    kSTREAM_SEND_READ_ACK = 5,
    kSTREAM_SEND_CLOSE = 6,
    kSTREAM_DONE = 7
  };
  static std::unique_ptr<RpcStream> Create(
    std::unique_ptr<RpcChannel> channel, 
    const std::string& host,
    const std::string& port, 
    const std::string& name, 
    const std::string& params,
    const scoped_refptr<base::SequencedTaskRunner>& task_runner,
    RpcMethodType type);


  RpcBidirectionalStream(
    std::unique_ptr<RpcChannel> channel, 
    const std::string& host,
    const std::string& port, 
    const std::string& name, 
    const std::string& params,
    const scoped_refptr<base::SequencedTaskRunner>& io_task_runner,
    RpcMethodType type);

  ~RpcBidirectionalStream() override;

  RpcMethodType type() const {
    return type_;
  }

  RpcCall* call() const {
    return call_.get(); 
  }

  const scoped_refptr<base::SequencedTaskRunner>& io_task_runner() const override {
    return io_task_runner_;
  }

  const scoped_refptr<base::SequencedTaskRunner>& delegate_task_runner() const {
    return delegate_task_runner_;
  }

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

  State next_state() const {
    return next_state_;
  }

  void set_next_state(State next) {
    next_state_ = next;
  }

  bool was_cleanly_shutdown() const override {
    return shutting_down_;
  }
  
  void Init() override;
  void Shutdown() override;

  void OnContinue(bool ok, RpcCall* call) override;
  void OnTimeout() override;
  void OnShutdown() override;

  void OnReadCompletion();
  void OnCloseCompletion();

private:
  
  void Run();
  void BuildCallOps(RpcCall* call, bool first_time);
  void OnContinueImpl(bool ok);
  void OnShutdownImpl();
  int DoLoop();
  int DoInit();
  int DoSendCall();
  int DoRead();
  int DoReplyReadDataAvailable();
  int DoSendReadAck();
  int DoSendClose();
  int DoFinish();
  
  void ScheduleIOLoop();

  void OnRead(int rv);
  void SendClose(int status);
  void ShutdownOnIO();
  //void FillOutputBuffer(RpcCall* call);
  //void FillInputBuffer(const std::string& data);

  //grpc_status_code call_status_;
  //grpc_slice call_status_details_;

  grpc_byte_buffer* recv_message_payload_ = nullptr;
  grpc_byte_buffer* send_message_payload_ = nullptr;
  grpc_closure on_response_received_;
  grpc_closure on_close_received_;
  //grpc_closure on_initial_request_sent_;
  //grpc_closure on_status_received_;
  //grpc_metadata_array begin_metadata_;
  //grpc_metadata_array end_metadata_;

  std::unique_ptr<RpcCall> CreateCall();

  State next_state_;

  RpcMethodType type_;

  std::unique_ptr<RpcContinuation> continuation_;//, base::OnTaskRunnerDeleter> continuation_;

  //RpcBytesMemoryStreamWriter stream_writer_;

  bool pending_call_;

  bool first_call_;

  bool shutting_down_;

  bool inside_loop_;

  bool reply_async_io_;

  bool close_was_sent_;

  int read_data_available_code_;
  int last_bytes_readed_;
  int last_read_code_;
  int64_t content_lenght_;
  int32_t buffer_size_;
  int32_t buffer_count_;
  int32_t encoded_;
  std::string encoding_;

  grpc_status_code close_status_;
  grpc_slice close_status_details_;
  
  //int close_cancelled_;
  //char* output_;
  //int64_t output_length_ = 0;
  //int64_t input_length_ = 0;

  std::unique_ptr<RpcCall> call_;

  base::Lock input_buffer_lock_;
  base::Lock output_buffer_lock_;
  std::unique_ptr<RpcStreamBuffer> input_buffer_;
  std::unique_ptr<RpcStreamBuffer> output_buffer_;
  std::vector<std::unique_ptr<RpcStreamBuffer>> back_buffers_;
  base::Lock back_buffer_vec_lock_;

  scoped_refptr<base::SequencedTaskRunner> delegate_task_runner_;

  //scoped_refptr<base::SequencedTaskRunner> loop_task_runner_;

  scoped_refptr<base::SequencedTaskRunner> io_task_runner_;

  base::WaitableEvent shutdown_event_;

  base::WeakPtrFactory<RpcBidirectionalStream> loop_weak_factory_;

  base::WeakPtrFactory<RpcBidirectionalStream> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(RpcBidirectionalStream);
};

}

#endif