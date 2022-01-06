// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/server/ipc_rpc_handler.h"

#include "base/logging.h"
#include "base/task_scheduler/task_traits.h"
#include "base/task_scheduler/post_task.h"
#include "rpc/support/alloc.h"
#include "rpc/support/host_port.h"
#include "ipc/ipc_sender.h"
#include "rpc/grpc.h"
#include "core/host/host_thread.h"
#include "net/rpc/server/rpc_state.h"
#include "net/rpc/server/rpc_call_state.h"
#include "core/shared/common/p2p_messages.h"
#include <rpc/support/alloc.h>
#include <rpc/support/log.h>
#include <rpc/support/string_util.h>
#include <rpc/support/sync.h>
#include <rpc/support/useful.h>

#include "rpc/ext/filters/http/server/http_server_filter.h"
#include "rpc/ext/transport/chttp2/transport/chttp2_transport.h"
#include "rpc/ext/transport/chttp2/transport/internal.h"
#include "rpc/channel/channel_args.h"
#include "rpc/channel/handshaker.h"
#include "rpc/channel/handshaker_registry.h"
#include "rpc/iomgr/endpoint.h"
#include "rpc/iomgr/resolve_address.h"
#include "rpc/iomgr/tcp_server.h"
#include "rpc/slice/slice_internal.h"
#include "rpc/surface/api_trace.h"
#include "rpc/surface/server.h"
#include <rpc/support/alloc.h>
#include <rpc/support/log.h>
#include <rpc/support/string_util.h>
#include <rpc/support/sync.h>
#include <rpc/support/time.h>
#include <rpc/support/useful.h>

#include "rpc/channel/channel_args.h"
#include "rpc/iomgr/resolve_address.h"
#include "rpc/iomgr/sockaddr.h"
#include "rpc/iomgr/sockaddr_utils.h"
#include "rpc/support/string.h"
#include "rpc/impl/codegen/byte_buffer.h"
#include "rpc/byte_buffer_reader.h"

#if defined(OS_POSIX)
#include "rpc/iomgr/socket_utils_posix.h"
#include "rpc/iomgr/tcp_posix.h"
#include "rpc/iomgr/tcp_server_utils_posix.h"
#include "rpc/iomgr/unix_sockets_posix.h"
#endif

#if defined(OS_WIN)
#include "net/socket/tcp_socket_win.h"
#include "rpc/iomgr/tcp_windows.h"
#include "rpc/iomgr/iocp_windows.h"
#include "rpc/iomgr/socket_windows.h"
#include "rpc/iomgr/tcp_server_windows.h"
#endif

namespace host {

class IPCRPCHandler::Context : public base::RefCountedThreadSafe<Context> {
public:
  Context(const base::WeakPtr<IPC::Sender>& message_sender, scoped_refptr<base::SingleThreadTaskRunner> io_task_runner): 
    message_sender_(message_sender),
    io_task_runner_(io_task_runner) {}

  IPC::Message* NewRPCBegin(
    int socket_id, 
    int call_id, 
    const std::string& method_name,
    const std::string& host_address,
    const std::string& host_name) {
    return new P2PMsg_OnRPCBegin(
      socket_id,
      call_id, 
      method_name, 
      host_address, 
      host_name);
  } 

  IPC::Message* NewRPCStreamRead(int socket_id, int call_id, const std::vector<char>& data) {
    return new P2PMsg_OnRPCStreamRead(socket_id, call_id, data);
  }

  IPC::Message* NewRPCStreamReadEOF(int socket_id, int call_id) {
    return new P2PMsg_OnRPCStreamReadEOF(socket_id, call_id);
  }

  IPC::Message* NewRPCUnaryRead(int socket_id, int call_id, const std::vector<char>& data) {
    return new P2PMsg_OnRPCUnaryRead(socket_id, call_id, data);
  }

  IPC::Message* NewRPCSendMessageAck(int socket_id, int call_id, int rpc_status) {
    return new P2PMsg_RPCSendMessageAck(socket_id, call_id, rpc_status);
  }

  IPC::Message* NewRPCEnd(int socket_id, int call_id) {
    return new P2PMsg_OnRPCEnd(socket_id, call_id);
  }

  void SendIPCMessage(IPC::Message* message) {
    // HostThread::PostTask(
    //               HostThread::IO, 
    //               FROM_HERE,
    //               base::BindOnce(&Context::SendIPCMessageOnIOThread, 
    //               this,
    //               base::Unretained(message)));
    io_task_runner_->PostTask(FROM_HERE,
                              base::BindOnce(&Context::SendIPCMessageOnIOThread, 
                              this,
                              base::Unretained(message)));
  }

private:  
  friend class base::RefCountedThreadSafe<Context>;
  
  ~Context() {}

  void SendIPCMessageOnIOThread(IPC::Message* message) {
    if (message_sender_) {
      message_sender_->Send(message);
    }
  }

  base::WeakPtr<IPC::Sender> message_sender_;
  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner_;

  DISALLOW_COPY_AND_ASSIGN(Context);
};

IPCRPCHandler::IPCRPCHandler(const base::WeakPtr<IPC::Sender>& message_sender, scoped_refptr<base::SingleThreadTaskRunner> io_task_runner):
 context_(new Context(message_sender, std::move(io_task_runner))) {

}

IPCRPCHandler::~IPCRPCHandler() {

}

void IPCRPCHandler::HandleCallBegin(net::RpcCallState* call, const std::string& method_name, const std::string& host_name) {
  auto msg = context_->NewRPCBegin(
    call->socket_id, 
    call->id, 
    method_name, 
    std::string("bettelgeuse.idontknow.com:1234"), 
    host_name);
  
  context_->SendIPCMessage(msg);
}

void IPCRPCHandler::HandleCallStreamRead(net::RpcCallState* call) {
  IPC::Message* msg = nullptr;
  std::vector<char> data;

  if (call->recv_message != nullptr) {
    grpc_byte_buffer_reader reader;
    if (grpc_byte_buffer_reader_init(&reader, call->recv_message)) {
      grpc_slice s;
      while (grpc_byte_buffer_reader_next(&reader, &s)) {
        data.insert(data.end(), GRPC_SLICE_START_PTR(s), GRPC_SLICE_START_PTR(s) + GRPC_SLICE_LENGTH(s));
      }
      grpc_byte_buffer_reader_destroy(&reader);
      msg = context_->NewRPCStreamRead(call->socket_id, call->id, data);
    } else {
      LOG(ERROR) << "error on init buffer reader for call->recv_message";
    }
  } else {
    LOG(INFO) << "call recv_message is NULL for id: " << call->id << ". letting the shell aware of it";
    msg = context_->NewRPCStreamReadEOF(call->socket_id, call->id);
  }

  if (msg) {
    context_->SendIPCMessage(msg);
  }
}

void IPCRPCHandler::HandleCallStreamSendInitMetadata(net::RpcCallState* call) {
  //LOG(INFO) << "IPCRPCHandler::HandleCallStreamSendInitMetadata";
  // do nothing
}

void IPCRPCHandler::HandleCallStreamWrite(net::RpcCallState* call) {
  if (call->recv_message != nullptr) {
    grpc_byte_buffer_destroy(call->recv_message);
    call->recv_message = nullptr;
  }
  if (call->write_op.data.send_message.send_message != nullptr) {
    grpc_byte_buffer_destroy(call->write_op.data.send_message.send_message);
    call->write_op.data.send_message.send_message = nullptr;
  }
  //LOG(INFO) << "IPCRPCHandler::HandleCallStreamWrite: sending RPCSendMessageAck";
  auto msg = context_->NewRPCSendMessageAck(call->socket_id, call->id, GRPC_STATUS_OK);
  context_->SendIPCMessage(msg);
}

void IPCRPCHandler::HandleCallUnaryRead(net::RpcCallState* call) {
  std::vector<char> data;
  if (call->recv_message != nullptr) {
    //LOG(INFO) << " recv_message != nullptr";
    grpc_byte_buffer_reader reader;
    if (grpc_byte_buffer_reader_init(&reader, call->recv_message)) {
      grpc_slice s;
      while (grpc_byte_buffer_reader_next(&reader, &s)) {
        //LOG(INFO) << " unary read: " << call->id << " processing data buffer size: " << GRPC_SLICE_LENGTH(s);
        data.insert(data.end(), GRPC_SLICE_START_PTR(s), GRPC_SLICE_START_PTR(s) + GRPC_SLICE_LENGTH(s));
      }
      grpc_byte_buffer_reader_destroy(&reader);
      //LOG(INFO) << " unary read: (call id: " << call->id << ") final data buffer size: " << data.size() << " content:\n'" << std::string(data.begin(), data.end()) << "'";
    } else {
      LOG(ERROR) << " error on init buffer reader for call->recv_message";
    }
  } else {
    LOG(ERROR) << " HEY call->recv_message (call id: " << call->id << ") is NULL";
  }
  
  //LOG(INFO) << " sending 'RPCUnaryRead' message over IPC...";
  IPC::Message* msg = context_->NewRPCUnaryRead(call->socket_id, call->id, data);
  context_->SendIPCMessage(msg);
}

void IPCRPCHandler::HandleCallEnd(net::RpcCallState* call) {
  IPC::Message* msg = context_->NewRPCEnd(call->socket_id, call->id);
  context_->SendIPCMessage(msg);
  // HostThread::PostTask(
  //   HostThread::IO, 
  //   FROM_HERE, 
  //   base::BindOnce(&IPCRPCHandler::DisconnectSocketOnIOThread, 
  //     base::Unretained(this), 
  //     base::Unretained(call->socket)));
}

void IPCRPCHandler::HandleRpcSendError(net::RpcCallState* call, int rc) {
  auto msg = context_->NewRPCSendMessageAck(call->socket_id, call->id, rc);
  context_->SendIPCMessage(msg);
}

void IPCRPCHandler::DisconnectSocketOnIOThread(net::RpcSocket* socket) {
  socket->Disconnect();
}

}