// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/rpc/server/rpc_socket.h"

#include "base/threading/thread_task_runner_handle.h"
#include "base/synchronization/waitable_event.h"
#include "net/socket/tcp_client_socket.h"
#include "net/rpc/server/rpc_service.h"
#include "rpc/surface/call.h"
#include "rpc/iomgr/closure.h"
//#include "storage/db/sqliteInt.h"
#include <google/protobuf/io/coded_stream.h>

namespace net {

constexpr uint32_t kMagic = 0x6d328498;
constexpr uint32_t kVersion = 0x01;

namespace {

void* tag(intptr_t i) { return (void*)i; }

void RpcServerOnSendMessage(grpc_exec_ctx* ctx, void* call, grpc_error *) {
  RpcCallState* call_state = reinterpret_cast<RpcCallState*>(call);
  RpcSocket* socket = call_state->socket;
  
  socket->service()->io_thread()->PostTask(
    FROM_HERE,
    base::BindOnce(
      &RpcSocket::OnSendMessageComplete, 
      socket->GetWeakPtr(), 
      call_state->id, 
      call_state->last_type));
}

void RpcServerOnSendBufferedMessage(grpc_exec_ctx* ctx, void* call, grpc_error *) {
  RpcCallState* call_state = reinterpret_cast<RpcCallState*>(call);
  RpcSocket* socket = call_state->socket;
  socket->service()->io_thread()->PostTask(
    FROM_HERE,
    base::BindOnce(
      &RpcSocket::OnSendBufferedMessageComplete, 
      socket->GetWeakPtr(), 
      call_state->id, 
      call_state->last_type));
}

void RecvInitialMetadataBatchComplete(grpc_exec_ctx* ctx, void* call, grpc_error *) {
  RpcCallState* call_state = reinterpret_cast<RpcCallState*>(call);
  RpcSocket* socket = call_state->socket;
  socket->service()->io_thread()->PostTask(
    FROM_HERE,
    base::BindOnce(
      &RpcSocket::OnReceiveInitialMetadataComplete, 
      socket->GetWeakPtr(), 
      call_state->id));
}

// void RecvMessageBatchComplete(grpc_exec_ctx* ctx, void* call, grpc_error *) {
//   DLOG(INFO) << "RecvMessageBatchComplete";
//   RpcCallState* call_state = reinterpret_cast<RpcCallState*>(call);
//   RpcSocket* socket = call_state->socket;
//   socket->OnRecvMessageComplete(call_state);
// }

RpcState FromMethodType(int method_type) {
  // FROM:
  // normal = 0
  // serverStream = 2
 // TO:  
  //kCALL_UNARY_READ = 1,
  //kCALL_STREAM_READ = 2,
  if (method_type == 0) { // normal -> unary mode
    return kCALL_UNARY_READ;
  } else if (method_type == 2) { // serverStream -> stream mode
    return kCALL_STREAM_READ;
  }
  // should break here
  DCHECK(false);
  return kCALL_NOOP;
}

}

RpcSocket::RpcSocket(RpcSocket::Delegate* delegate, RpcService* service, int socket_id, std::unique_ptr<net::StreamSocket> socket): 
 delegate_(delegate),
 socket_id_(socket_id),
 socket_(std::move(socket)),
 service_(service),
 weak_factory_(this) {
 
}

RpcSocket::RpcSocket(RpcSocket::Delegate* delegate, int socket_id, std::unique_ptr<net::StreamSocket> socket): 
 delegate_(delegate),
 socket_id_(socket_id),
 socket_(std::move(socket)),
 service_(nullptr),
 weak_factory_(this) {
 
}

RpcSocket::~RpcSocket() {
  //DLOG(INFO) << "~RpcSocket";
}

int RpcSocket::Read(net::IOBuffer* buf,
                    int buf_len,
                    net::CompletionOnceCallback callback) {
 return socket_->Read(buf, buf_len, std::move(callback));
}

int RpcSocket::Write(net::IOBuffer* buf,
          int buf_len,
          net::CompletionOnceCallback callback,
          const net::NetworkTrafficAnnotationTag& traffic_annotation) {
 return socket_->Write(buf, buf_len, std::move(callback), traffic_annotation);
}

int RpcSocket::SetReceiveBufferSize(int32_t size) {
  return socket_->SetReceiveBufferSize(size);
}

int RpcSocket::SetSendBufferSize(int32_t size) {
  return socket_->SetSendBufferSize(size);
}

void RpcSocket::DetachFromThread() {
  static_cast<net::TCPClientSocket *>(socket_.get())->DetachFromThread();
}

int RpcSocket::Connect(net::CompletionOnceCallback callback) {
  return socket_->Connect(std::move(callback));
}

void RpcSocket::Disconnect() {
  socket_->Disconnect();
}

bool RpcSocket::IsConnected() const {
  return socket_->IsConnected();
}

bool RpcSocket::IsConnectedAndIdle() const {
  return socket_->IsConnectedAndIdle();
}

int RpcSocket::GetPeerAddress(net::IPEndPoint* address) const {
  return socket_->GetPeerAddress(address);
}

int RpcSocket::GetLocalAddress(net::IPEndPoint* address) const  {
  return socket_->GetLocalAddress(address);
}

const net::NetLogWithSource& RpcSocket::NetLog() const {
  return net_log_;
}

void RpcSocket::SetSubresourceSpeculation() {
  socket_->SetSubresourceSpeculation();
}

void RpcSocket::SetOmniboxSpeculation() {
  socket_->SetOmniboxSpeculation();
}

bool RpcSocket::WasEverUsed() const {
  return socket_->WasEverUsed();
}

bool RpcSocket::WasAlpnNegotiated() const {
  return socket_->WasAlpnNegotiated();
}

net::NextProto RpcSocket::GetNegotiatedProtocol() const {
  return socket_->GetNegotiatedProtocol();
}

bool RpcSocket::GetSSLInfo(net::SSLInfo* ssl_info) {
  return socket_->GetSSLInfo(ssl_info);
}

void RpcSocket::GetConnectionAttempts(net::ConnectionAttempts* out) const {
  socket_->GetConnectionAttempts(out);
}

void RpcSocket::ClearConnectionAttempts() {
  socket_->ClearConnectionAttempts();
}

void RpcSocket::AddConnectionAttempts(const net::ConnectionAttempts& attempts) {
  socket_->AddConnectionAttempts(attempts);
}

int64_t RpcSocket::GetTotalReceivedBytes() const {
  return socket_->GetTotalReceivedBytes();
}

void RpcSocket::ApplySocketTag(const net::SocketTag& tag) {
  return socket_->ApplySocketTag(tag);
}

void RpcSocket::DispatchReceiveMessage(int call_id, int type) {
  if (!service_)
    return;

  service_->io_thread()->PostTask(
    FROM_HERE, 
    base::BindOnce(&RpcSocket::ReceiveMessage, weak_factory_.GetWeakPtr(), call_id, type));
}

void RpcSocket::DispatchSendMessage(int call_id, std::vector<char> data, int method_type) {
  if (!service_)
    return;

  service_->io_thread()->PostTask(
    FROM_HERE,
    base::BindOnce(&RpcSocket::SendMessage, 
      weak_factory_.GetWeakPtr(), 
      call_id, 
      base::Passed(std::move(data)), 
      method_type));
}

void RpcSocket::ReceiveMessage(int call_id, int type) {
  if (!service_)
    return;

  RpcState method_type = FromMethodType(type);
  // TODO: Implement a "CallHandler"
  base::WeakPtr<RpcCallState> call = service_->GetCallStateForCall(call_id);
  if (!call) {
    LOG(ERROR) << "Call state not found for socket " << socket_id_;
    return;
  }
  call->last_type = method_type;
  call->last_method = "ReceiveMessage";
  if (!ReadData(call, method_type)) {
    LOG(ERROR) << "failed to read data for socket " << socket_id_;
    return;
  }
}

void RpcSocket::SendMessage(int call_id, std::vector<char> data, int method_type) {
  if (!service_)
    return;
  RpcState type = FromMethodType(method_type);
  // TODO: Implement a "CallHandler"
  base::WeakPtr<RpcCallState> call = service_->GetCallStateForCall(call_id);
  if (!call) {
    LOG(ERROR) << "SendMessage: Call state not found for call_id = " << call_id << " socket " << socket_id_;
    return;
  }
  call->last_method = "SendMessage";
  // if the header was not processed, this is the first payload and migth be it
  // if this returns false, just keep going as it might be a content payload
  // (not a flaw)
  if (!call->header_readed && data.size() > 0) {
    if (ReadHeader(call, data)) {
      return;
    }
  }

  if (type == RpcState::kCALL_UNARY_READ) {
    if (!HandleUnaryCall(call, std::move(data))) {
      LOG(ERROR) << "failed to send data for socket " << socket_id_ << " for unary call";
    }
  } else if (type == RpcState::kCALL_STREAM_READ) {
    // if (call->is_new && !SendRecvCloseOnServer(call)) {
    //   DLOG(ERROR) << "failed to send recv_close_on_server";
    // }
    //DLOG(INFO) << "RpcSocket::SendMessage: type = CALL_STREAM_READ =>SendNow(call, data)";
    //ReadData(call_id, method_type);
    if (!Send(call, type, std::move(data))) {
      LOG(ERROR) << "failed to send data for socket " << socket_id_ << " for stream call id: " << call->id;
    }
  } else {
    DLOG(ERROR) << "Rpc SendMessage for type " << type << " not handled. "; 
  }
}

void RpcSocket::SendMessageNow(int call_id, std::vector<char> data, int method_type) {
  if (!service_)
    return;
  //DLOG(INFO) << "RpcSocket::SendMessageNow: call = " << call_id << " size: " << data.size();
  RpcState type = FromMethodType(method_type);
  base::WeakPtr<RpcCallState> call = service_->GetCallStateForCall(call_id);
  if (!call) {
    LOG(ERROR) << "Call state not found for socket " << socket_id_;
    return;
  }
  call->last_method = "SendMessageNow";
  if (type == RpcState::kCALL_STREAM_READ) {
    size_t pending_writes_size = pending_writes_count();
    bool send_all_in_one_batch = data.size() < 16376 && pending_writes_size == 0;
    bool last_buffer = data.size() < 16376 && pending_writes_size > 0;
    if (!SendNow(std::move(call), type, std::move(data), send_all_in_one_batch || last_buffer)) {
      LOG(ERROR) << "failed to send data for socket " << socket_id_ << " for stream call id: " << call->id;
    }
  }
}

void RpcSocket::SendRpcStatus(int call_id, int status_code) {
  if (!service_)
    return;
  base::WeakPtr<RpcCallState> call = service_->GetCallStateForCall(call_id);
  if (!call) {
    //LOG(ERROR) << "SendRpcStatus: status_code = " << status_code << ". Call state not found for call_id = " << call_id << " socket " << socket_id_;
    return;
  }
  call->last_method = "SendRpcStatus";
  call->done = true;
  // the send message was sent but done was false as SendRpcStatus came later
  // if (call->close_stream && !call->status_was_sent && !have_pending_writes()) {
  //   SendStatus(std::move(call), status_code);
  // }
  //SendStatus(call, status_code);
}

bool RpcSocket::ReadData(base::WeakPtr<RpcCallState> call, RpcState next_state) {
  call->last_method = "ReadData";
  // if (call->recv_message) {
  //   grpc_byte_buffer_destroy(call->recv_message);
  // }

  int num_ops = 1;

  call->state = next_state;
  call->unary_ops[0].op = GRPC_OP_RECV_MESSAGE;
  call->unary_ops[0].data.recv_message.recv_message = &call->recv_message;

  // grpc_exec_ctx exec_ctx = GRPC_EXEC_CTX_INIT;
  // GRPC_CLOSURE_INIT(&call->server_on_recv_message,
  //                   RecvMessageBatchComplete,
  //                   call,
  //                   grpc_schedule_on_exec_ctx);

  // grpc_call_error rc = grpc_call_start_batch_and_execute(&exec_ctx,
  //                                        call->call, 
  //                                        &call->read_op, 
  //                                        1,
  //                                        tag(next_state),
  //                                        &call->server_on_recv_message);
  // grpc_exec_ctx_finish(&exec_ctx);

  grpc_call_error rc = grpc_call_start_batch(call->call, call->unary_ops, num_ops, tag(next_state), nullptr);

  if (rc != GRPC_CALL_OK) {
    DLOG(ERROR) << "error grpc_call_start_batch: " << grpc_call_error_to_string(rc) << " call? " << call->call;
  }

  return rc == GRPC_CALL_OK;
}


bool RpcSocket::HandleUnaryCall(base::WeakPtr<RpcCallState> call, std::vector<char> data) {
  call->last_method = "HandleUnaryCall";
  grpc_op* op;
  grpc_call_error error;

  grpc_slice output_slice = grpc_slice_from_static_buffer(&data.begin()[0], data.size());
 
  op = call->unary_ops;

  std::string content_size_str = base::IntToString(call->content_size);
  std::string buffer_size_str = base::IntToString(call->buffer_size);
  std::string encoded_str = base::IntToString(call->encoded);
  std::string pieces_str = base::IntToString(call->piece_count);

  grpc_metadata* header = reinterpret_cast<grpc_metadata*>(gpr_malloc(sizeof(grpc_metadata) * 5));

  header[0] = { grpc_slice_from_static_string("content-lenght"),
                grpc_slice_from_static_string(content_size_str.c_str()),
                0,
                {{NULL, NULL, NULL, NULL}}};
  header[1] = { grpc_slice_from_static_string("piece-size"),
                grpc_slice_from_static_string(buffer_size_str.c_str()),
                0,
                {{NULL, NULL, NULL, NULL}}};
  header[2] = { grpc_slice_from_static_string("piece-count"),
                grpc_slice_from_static_string(pieces_str.c_str()),
                0,
               {{NULL, NULL, NULL, NULL}}};
  header[3] = { grpc_slice_from_static_string("encoded"),
                grpc_slice_from_static_string(encoded_str.c_str()),
                0,
                {{NULL, NULL, NULL, NULL}}};
  header[4] = { grpc_slice_from_static_string("encoding"),
                grpc_slice_from_static_string(call->encoding.c_str()),
                0,
                {{NULL, NULL, NULL, NULL}}};

  call->send_initial_metadata.metadata = header;

  op->op = GRPC_OP_SEND_INITIAL_METADATA;
  op->data.send_initial_metadata.count = 5;
  op->data.send_initial_metadata.metadata = call->send_initial_metadata.metadata;
  op++;
  
  op->op = GRPC_OP_RECV_MESSAGE;
  op->data.recv_message.recv_message = &call->send_message;
  op++;
 
  op->op = GRPC_OP_SEND_MESSAGE;
  op->data.send_message.send_message = grpc_raw_byte_buffer_create(&output_slice, 1);
  op++;

  op->op = GRPC_OP_SEND_STATUS_FROM_SERVER;
  op->data.send_status_from_server.status = GRPC_STATUS_OK;
  op->data.send_status_from_server.trailing_metadata_count = 0;
  op->data.send_status_from_server.status_details = nullptr;
  op++;
  
  op->op = GRPC_OP_RECV_CLOSE_ON_SERVER;
  op->data.recv_close_on_server.cancelled = &call->cancelled;
  op++;

  error = grpc_call_start_batch(call->call, call->unary_ops, (size_t)(op - call->unary_ops),
                                tag(kCALL_END), nullptr);

  if (error != GRPC_CALL_OK) {
    DLOG(ERROR) << "error grpc_call_start_batch: " << grpc_call_error_to_string(error);
  }

  grpc_slice_unref(output_slice);

  return error == GRPC_CALL_OK;
}

bool RpcSocket::Send(base::WeakPtr<RpcCallState> call, RpcState type, std::vector<char> data) {
  call->last_method = "Send";
  base::AutoLock lock(pending_writes_lock_);
  
  bool send_all_in_one_batch = data.size() < 16376 && pending_writes_.size() == 0;
  bool last_buffer = data.size() < 16376 && pending_writes_.size() > 0;
  //if (send_all_in_one_batch) {
  if (grpc_call_is_sending_message(call->call) || pending_writes_.size() > 0) {
    DLOG(INFO) << "RpcSocket::Send: call = " << call->id << " => queueing message size: " << data.size() << " on pending writes";
    pending_writes_.insert(pending_writes_.begin(), std::move(data));
  } else {
    SendNow(std::move(call), type, std::move(data), last_buffer || send_all_in_one_batch);
  }
  // } else if (last_buffer) {
  //   //gpr_slice_buffer_add(&call->output_buffer, grpc_slice_from_static_buffer(&data.begin()[0], data.size()));
  //   call->slices[call->slice_count] = grpc_slice_from_static_buffer(&data.begin()[0], data.size());
  //   call->slice_count++;
  //   pending_writes_.insert(pending_writes_.begin(), std::move(data));
  //   SendBuffered(call, type);
  // } else {
  //   call->slices[call->slice_count] = grpc_slice_from_static_buffer(&data.begin()[0], data.size());
  //   call->slice_count++;
  //   pending_writes_.insert(pending_writes_.begin(), std::move(data));
  // }
  return true;
}

bool RpcSocket::SendNow(base::WeakPtr<RpcCallState> call, RpcState type, std::vector<char> data, bool close_stream) {
  call->last_method = "SendNow";
  grpc_call_error rc;
  grpc_exec_ctx exec_ctx = GRPC_EXEC_CTX_INIT;

  call->close_stream = close_stream;

  grpc_slice slice = grpc_slice_from_static_buffer(&data.begin()[0], data.size());

  //grpc_op op;
  //op.op = GRPC_OP_SEND_MESSAGE;
  //op.data.send_message.send_message = grpc_raw_byte_buffer_create(&slice, 1);
  //op.flags = 0;
  //op.reserved = NULL; 

  //GRPC_CLOSURE_INIT(&call->server_on_send_message,
  //                  RpcServerOnSendMessage, 
  //                  call,
  //                  grpc_schedule_on_exec_ctx);
  
  //rc = grpc_call_start_batch_and_execute(
  //    &exec_ctx, call->call, &op, 1,
  //    &call->server_on_send_message);
  memset(call->unary_ops, 0, sizeof(grpc_op) * 6);
  int num_ops = 0;

  if (call->is_new) {
    num_ops = 2;
    
    std::string content_size_str = base::IntToString(call->content_size);
    std::string buffer_size_str = base::IntToString(call->buffer_size);
    std::string encoded_str = base::IntToString(call->encoded);
    std::string pieces_str = base::IntToString(call->piece_count);
    
    grpc_metadata* header = reinterpret_cast<grpc_metadata*>(gpr_malloc(sizeof(grpc_metadata) * 5));

    header[0] = { grpc_slice_from_static_string("content-lenght"),
                  grpc_slice_from_static_string(content_size_str.c_str()),
                  0,
                  {{NULL, NULL, NULL, NULL}}};
    header[1] = { grpc_slice_from_static_string("buffer-size"),
                  grpc_slice_from_static_string(buffer_size_str.c_str()),
                  0,
                  {{NULL, NULL, NULL, NULL}}};
    header[2] = { grpc_slice_from_static_string("buffer-count"),
                  grpc_slice_from_static_string(pieces_str.c_str()),
                  0,
                {{NULL, NULL, NULL, NULL}}};
    header[3] = { grpc_slice_from_static_string("encoded"),
                  grpc_slice_from_static_string(encoded_str.c_str()),
                  0,
                {{NULL, NULL, NULL, NULL}}};
    header[4] = { grpc_slice_from_static_string("encoding"),
                  grpc_slice_from_static_string(call->encoding.c_str()),
                  0,
                {{NULL, NULL, NULL, NULL}}};

    call->send_initial_metadata.metadata = header;

    // send the content length
    call->unary_ops[0].op = GRPC_OP_SEND_INITIAL_METADATA;
    call->unary_ops[0].data.send_initial_metadata.count = 5;
    call->unary_ops[0].data.send_initial_metadata.metadata = call->send_initial_metadata.metadata;

    //call->unary_ops[1].op = GRPC_OP_RECV_MESSAGE;
    //call->unary_ops[1].data.recv_message.recv_message = &call->recv_message;
    
    call->unary_ops[1].op = GRPC_OP_SEND_MESSAGE;
    call->unary_ops[1].data.send_message.send_message = grpc_raw_byte_buffer_create(&slice, 1);

    if (close_stream) {
      num_ops = 3;
      //call->unary_ops[2].op = GRPC_OP_SEND_STATUS_FROM_SERVER;
      //call->unary_ops[2].data.send_status_from_server.status = GRPC_STATUS_OK;
      //call->unary_ops[2].data.send_status_from_server.trailing_metadata_count = 0;
      //call->unary_ops[2].data.send_status_from_server.status_details = nullptr;
      call->unary_ops[2].op = GRPC_OP_SEND_STATUS_FROM_SERVER;
      call->unary_ops[2].data.send_status_from_server.trailing_metadata_count = 0;//trailing_metadata_count_;
      call->unary_ops[2].data.send_status_from_server.trailing_metadata = call->trailing_metadata.metadata;
      call->unary_ops[2].data.send_status_from_server.status = GRPC_STATUS_OK;
      //error_message_slice_ = SliceReferencingString(send_error_message_);
      call->unary_ops[2].data.send_status_from_server.status_details = nullptr;//send_error_message_.empty() ? nullptr : &error_message_slice_;
      call->unary_ops[2].flags = 0;
      call->unary_ops[2].reserved = NULL;
    }
    call->is_new = false;
  } else {
    num_ops = 1;
    //call->unary_ops[0].op = GRPC_OP_RECV_MESSAGE;
    //call->unary_ops[0].data.recv_message.recv_message = &call->recv_message;

  //  call->unary_ops[1].op = GRPC_OP_SEND_INITIAL_METADATA;
  //  call->unary_ops[1].data.send_initial_metadata.count = 0;

    call->unary_ops[0].op = GRPC_OP_SEND_MESSAGE;
    call->unary_ops[0].data.send_message.send_message = grpc_raw_byte_buffer_create(&slice, 1);
    if (close_stream) {
      num_ops = 2;
      call->unary_ops[1].op = GRPC_OP_SEND_STATUS_FROM_SERVER;
      call->unary_ops[1].data.send_status_from_server.trailing_metadata_count = 0;//trailing_metadata_count_;
      call->unary_ops[1].data.send_status_from_server.trailing_metadata = call->trailing_metadata.metadata;
      call->unary_ops[1].data.send_status_from_server.status = GRPC_STATUS_OK;
      //error_message_slice_ = SliceReferencingString(send_error_message_);
      call->unary_ops[1].data.send_status_from_server.status_details = nullptr;//send_error_message_.empty() ? nullptr : &error_message_slice_;
      call->unary_ops[1].flags = 0;
      call->unary_ops[1].reserved = NULL;
    }
  }
  
  call->last_type = type;

  /* if (close_stream) {
    rc = grpc_call_start_batch(call->call, call->unary_ops, num_ops, tag(kCALL_STREAM_READ), nullptr);
    //rc = grpc_call_start_batch(call->call, call->unary_ops, num_ops, tag(kCALL_STREAM_WRITE), nullptr);
  } else { */

  GRPC_CLOSURE_INIT(&call->server_on_send_message,
                    RpcServerOnSendMessage, 
                    call.get(),
                    grpc_schedule_on_exec_ctx);
  
  rc = grpc_call_start_batch_and_execute(
    &exec_ctx, call->call, call->unary_ops, num_ops,
      &call->server_on_send_message);

  //rc = grpc_call_start_batch(call->call, call->unary_ops, 4, tag(kCALL_STREAM_WRITE), nullptr);
  
  //rc = grpc_call_start_batch_and_execute(&exec_ctx, call->call, &call->write_op, 1, &call->server_on_send_message);
  if (rc != GRPC_CALL_OK) {
    DLOG(ERROR) << "error grpc_call_start_batch (GRPC_OP_SEND_MESSAGE): " << grpc_call_error_to_string(rc) << " ops: " << num_ops;
    ReplySendError(std::move(call), rc);
  }
  
  grpc_exec_ctx_finish(&exec_ctx);

  //}

  return rc == GRPC_CALL_OK;
}

void RpcSocket::ProcessReadData(base::WeakPtr<RpcCallState> call, RpcState type) {
  call->last_method = "ProcessReadData";
  if (!call->done) {
    ReadData(std::move(call), RpcState::kCALL_STREAM_WRITE);
  }
}

void RpcSocket::ProcessBuffered(base::WeakPtr<RpcCallState> call, RpcState type) {
  call->last_method = "ProcessBuffered";
  //SendEnqueued(call, type);
  //if (!call->done) {
    if (have_pending_writes()) { 
      SendBuffered(std::move(call), type);
    }
  //}
}
  
bool RpcSocket::SendBuffered(base::WeakPtr<RpcCallState> call, RpcState type) {
  call->last_method = "SendBuffered";
  base::AutoLock lock(pending_writes_lock_);
  grpc_call_error rc;
  grpc_exec_ctx exec_ctx = GRPC_EXEC_CTX_INIT;
  int num_ops = 0;
  
  // if (grpc_call_is_sending_message(call->call)) {
  //   DLOG(INFO) << "SendEnqueued: grpc_call_is_sending_message = true. still busy. cancelling";
  //   return false;
  // }

  if (pending_writes_.size() > 0) {
    //bool close_stream = pending_writes_.size() == 1;
    const std::vector<char>& buffer = pending_writes_.back();
    grpc_slice slice = grpc_slice_from_static_buffer(&buffer[0], buffer.size());//grpc_raw_byte_buffer_create(&call->slices[0], 1);//call->slice_count);
    memset(call->unary_ops, 0, sizeof(grpc_op) * 1);

    call->unary_ops[0].op = GRPC_OP_SEND_MESSAGE;
    call->unary_ops[0].data.send_message.send_message =  grpc_raw_byte_buffer_create(&slice, 1);
    num_ops++;
    // if (close_stream) {
    //   call->unary_ops[1].op = GRPC_OP_SEND_STATUS_FROM_SERVER;
    //   call->unary_ops[1].data.send_status_from_server.status = GRPC_STATUS_OK;
    //   call->unary_ops[1].data.send_status_from_server.trailing_metadata_count = 0;
    //   call->unary_ops[1].data.send_status_from_server.status_details = nullptr;
    //   num_ops++;
    // }
    call->last_type = type;

    GRPC_CLOSURE_INIT(&call->server_on_send_message,
                      RpcServerOnSendBufferedMessage, 
                      call.get(),
                      grpc_schedule_on_exec_ctx);
    
    rc = grpc_call_start_batch_and_execute(
      &exec_ctx, call->call, call->unary_ops, num_ops,
        &call->server_on_send_message);

    //rc = grpc_call_start_batch(call->call, call->unary_ops, 4, tag(kCALL_STREAM_WRITE), nullptr);
    
    //rc = grpc_call_start_batch_and_execute(&exec_ctx, call->call, &call->write_op, 1, &call->server_on_send_message);
    if (rc != GRPC_CALL_OK) {
      DLOG(ERROR) << "error grpc_call_start_batch (GRPC_OP_SEND_MESSAGE): " << grpc_call_error_to_string(rc);
      ReplySendError(std::move(call), rc);
    }

    grpc_exec_ctx_finish(&exec_ctx);

    return rc == GRPC_CALL_OK;
  }

  return true;
}

bool RpcSocket::SendStatus(base::WeakPtr<RpcCallState> call, int status_code) {
  call->last_method = "SendStatus";
  if (call->status_was_sent) {
    return true;
  }
  // call->status_op[0].op = GRPC_OP_SEND_STATUS_FROM_SERVER;
  // call->status_op[0].data.send_status_from_server.status = static_cast<grpc_status_code>(status_code);
  // call->status_op[0].data.send_status_from_server.trailing_metadata_count = 0;
  // call->status_op[0].data.send_status_from_server.status_details = nullptr;

  // call->status_op[0].op = GRPC_OP_SEND_STATUS_FROM_SERVER;
  // call->status_op[0].data.send_status_from_server.trailing_metadata_count = 0;//trailing_metadata_count_;
  // call->status_op[0].data.send_status_from_server.trailing_metadata = call->trailing_metadata.metadata;
  // call->status_op[0].data.send_status_from_server.status = GRPC_STATUS_OK;
  // call->status_op[0].data.send_status_from_server.status_details = nullptr;//send_error_message_.empty() ? nullptr : &error_message_slice_;
  // call->status_op[0].flags = 0;
  // call->status_op[0].reserved = NULL;

  call->status_op[0].op = GRPC_OP_RECV_CLOSE_ON_SERVER;
  call->status_op[0].data.recv_close_on_server.cancelled = &call->cancelled;

  grpc_call_error rc = grpc_call_start_batch(call->call, call->status_op, 1, tag(kCALL_END), nullptr);

  if (rc != GRPC_CALL_OK) {
    DLOG(ERROR) << "error grpc_call_start_batch (GRPC_OP_SEND_STATUS_FROM_SERVER+GRPC_OP_RECV_CLOSE_ON_SERVER): " << grpc_call_error_to_string(rc);
  }
  call->status_was_sent = rc == GRPC_CALL_OK;
  return rc == GRPC_CALL_OK;
}

bool RpcSocket::ReceiveInitialMetadata(base::WeakPtr<RpcCallState> call) {
  grpc_call_error rc;
  grpc_exec_ctx exec_ctx = GRPC_EXEC_CTX_INIT;
  call->metadata_recv_op.op = GRPC_OP_RECV_INITIAL_METADATA;
  call->metadata_recv_op.flags = 0;
  call->metadata_recv_op.reserved = nullptr;
  call->metadata_recv_op.data.recv_initial_metadata.recv_initial_metadata = &call->recv_initial_metadata;
  GRPC_CLOSURE_INIT(&call->server_on_recv_initial_metadata,
                    RecvInitialMetadataBatchComplete, 
                    call.get(),
                    grpc_schedule_on_exec_ctx);
  rc = grpc_call_start_batch_and_execute(&exec_ctx,
                                         call->call, 
                                         &call->metadata_recv_op, 
                                         1,
                                         &call->server_on_recv_initial_metadata);
  grpc_exec_ctx_finish(&exec_ctx);
  //DLOG(INFO) << "RpcSocket::ReceiveInitialMetadata: rc = " << rc;
  return rc == GRPC_CALL_OK; 
}

bool RpcSocket::ReadHeader(const base::WeakPtr<RpcCallState>& call, const std::vector<char>& header_data) {
  call->last_method = "ReadHeader";
  uint32_t magic_number = 0;
  uint32_t version = 0;
  uint32_t content_size = 0;
  uint32_t buffer_size = 0;
  uint32_t encoded = 0;
  uint32_t encoding_size = 0;
  
  google::protobuf::io::CodedInputStream coded_input(reinterpret_cast<uint8_t const*>(header_data.data()), header_data.size());

  coded_input.ReadLittleEndian32(&magic_number);
  
  //LOG(ERROR) << "RpcSocket::ReadHeader: recovered magic number: " << magic_number;
  if (magic_number != kMagic) {
    call->header_readed = true;
    return false;
  }

  coded_input.ReadLittleEndian32(&version);

  if (version != kVersion) {
    call->header_readed = true;
    return false;
  }

  coded_input.ReadVarint32(&content_size);
  coded_input.ReadVarint32(&buffer_size);
  coded_input.ReadVarint32(&encoded); 
  coded_input.ReadVarint32(&encoding_size);

  char encoding[encoding_size + 1];

  coded_input.ReadRaw(encoding, encoding_size);

  encoding[encoding_size] = '\0';
  
  //LOG(ERROR) << "RpcSocket::ReadHeader: header size = " << header_data.size() << " decoded content_size = " << content_size << " buffer size = " << buffer_size << " encoded ? " << encoded << " encoding: " << encoding;
  
  call->content_size = content_size;
  call->buffer_size = buffer_size;
  call->encoded = encoded;
  call->encoding = std::string(encoding, static_cast<size_t>(encoding_size));
  call->piece_count = (content_size + buffer_size - 1) / buffer_size;
  call->header_readed = true;

  return true;
}

// bool RpcSocket::ReadHeader(const base::WeakPtr<RpcCallState>& call, const std::vector<char>& header_data) {
//   uint64_t magic_number = 0;
//   uint64_t content_size = 0;
//   uint64_t buffer_size = 0;

//   uint8_t const* d = reinterpret_cast<uint8_t const*>(header_data.data());

//   d += csqliteGetVarint(d, (u64*)&magic_number);
  
//   LOG(ERROR) << "RpcSocket::ReadHeader: recovered magic number: " << magic_number;
//   if (magic_number != 1249) {
//     LOG(ERROR) << "RpcSocket::ReadHeader: not a valid header";
//     call->header_readed = true;
//     return false;
//   }

//   d += csqliteGetVarint(d, (u64*)&content_size);
//   d += csqliteGetVarint(d, (u64*)&buffer_size);
  
//   LOG(ERROR) << "RpcSocket::ReadHeader: decoded content_size = " << content_size << " buffer size = " << buffer_size;
//   call->content_size = content_size;
//   call->buffer_size = buffer_size;
//   return true;
// }

void RpcSocket::ReplySendError(base::WeakPtr<RpcCallState> call, int rc) {
  call->last_method = "ReplySendError";
  service_->OnRpcSendError(call.get(), rc);
}

void RpcSocket::OnSendMessageComplete(int call_id, RpcState type) {
  // reset buffers
  base::WeakPtr<RpcCallState> call = service_->GetCallStateForCall(call_id);
  if (!call){
    //DLOG(INFO) << "RpcSocket::OnSendMessageComplete: call with id " << call_id << " not found";
    return;
  }
  call->last_method = "OnSendMessageComplete";
  if (call->recv_message != nullptr) {
    grpc_byte_buffer_destroy(call->recv_message);
    call->recv_message = nullptr;
  }
  // TODO: If is bidirectional, we should be asking for more here
 
  // FIXME: this is commented by now, but its supposed to be temporary
  // til we know that it wont affect the writing op

  //if (call->unary_ops[0].data.send_message.send_message != nullptr) {
  //  grpc_byte_buffer_destroy(call->unary_ops[0].data.send_message.send_message);
  //  call->unary_ops[0].data.send_message.send_message = nullptr;
  //}
  ReplySendError(call, GRPC_STATUS_OK);

  //DLOG(INFO) << "RpcSocket::OnSendMessageComplete: call = " << call_id << " close_stream ? " << call->close_stream << " have_pending_writes ? " << have_pending_writes() << " status_was_sent ? " << call->status_was_sent;
  if (call->close_stream && !have_pending_writes() && !call->status_was_sent) {
    //DLOG(INFO) << "RpcSocket::OnSendMessageComplete: close_stream = true => sending status";
    SendStatus(call, OK);
    return;
  }

  ProcessBuffered(call, type);

  //pending_writes_.clear();

  // FIXME: this is a trial, it might be completely wrong to do it like this (probably is)

  //service_->RequestCall(call, this);

  // TODO: better to keep this once a event on client trigger
  //       the server completion, instead of binding directly
  //       here for each message sent

  //       reminder: this will trigger to call the 'write completion'
  //       on the app host process, which say its ok to keep sending data

  //ReadData(call, RpcState::kCALL_STREAM_WRITE);

  // base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
  //    FROM_HERE,
  //    base::BindOnce(&RpcSocket::ProcessReadData, 
  //     base::Unretained(this),
  //      base::Unretained(call), 
  //      type),
  //      base::TimeDelta::FromMilliseconds(400));
  //ProcessEnqueued(call, type);

  //(call, type);

  // if (pending_writes_.size() > 0) {
  //   DLOG(INFO) << "RpcSocket::OnSendMessageComplete: sending enqueued message";
  //   SendEnqueued(call, type);
  // }
}

void RpcSocket::OnSendBufferedMessageComplete(int call_id, RpcState type) {
  base::WeakPtr<RpcCallState> call = service_->GetCallStateForCall(call_id);
  if (!call){
    //DLOG(INFO) << "RpcSocket::OnSendBufferedMessageComplete: call with id " << call_id << " not found";
    return;
  }
  call->last_method = "OnSendBufferedMessageComplete";
  if (call->unary_ops[0].data.send_message.send_message != nullptr) {
    grpc_byte_buffer_destroy(call->unary_ops[0].data.send_message.send_message);
    call->unary_ops[0].data.send_message.send_message = nullptr;
  }

  pending_writes_.pop_back();

  if (call->close_stream && !have_pending_writes() && !call->status_was_sent) {
    SendStatus(call, OK);
    return;
  }

  ProcessBuffered(call, type);
}

// bool RpcSocket::SendRecvCloseOnServer(int call_id) {
//   //DLOG(INFO) << "RpcSocket::SendRecvCloseOnServer";
//   grpc_call_error rc;
//   call->status_op[0].op = GRPC_OP_RECV_CLOSE_ON_SERVER;
//   call->status_op[0].data.recv_close_on_server.cancelled = &call->cancelled;
//   rc = grpc_call_start_batch(call->call, call->status_op, 1, tag(-1), nullptr);

//   return rc == GRPC_CALL_OK; 
// }

void RpcSocket::OnReceiveInitialMetadataComplete(int call_id) {
  base::WeakPtr<RpcCallState> call = service_->GetCallStateForCall(call_id);
  if (call) {
    call->last_method = "OnReceiveInitialMetadataComplete";
    RpcState type = call->last_type;
    if (!ReadData(call, type)) {
      LOG(ERROR) << "failed to read data for socket " << socket_id_;
      return;
    }
  } else {
    DLOG(INFO) << "RpcSocket::OnReceiveInitialMetadataComplete: call with id " << call_id << " not found";
  }
}

void RpcSocket::OnRecvMessageComplete(int call_id) {
  //if (!SendCloseOnServer(call)) {
  //  LOG(ERROR) << "failed to send close on server for socket " << socket_id_;
  //}
}

void RpcSocket::CallWillDestroy(RpcCallState* call) {
  //DLOG(INFO) << "RpcSocket::CallWillDestroy: id = " << call->id << " call = " << call;
}

void RpcSocket::CallDestroyed(int call_id) {
 // DLOG(INFO) << "RpcSocket::CallDestroyed: id = " << call_id;
  delegate_->OnRpcCallDestroyed(this, call_id);
}

base::WeakPtr<RpcSocket> RpcSocket::GetWeakPtr() {
  return weak_factory_.GetWeakPtr();
}

}
