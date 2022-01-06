// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_SERVER_LOCAL_HANDLER_H_
#define NET_RPC_SERVER_LOCAL_HANDLER_H_

#include <string>

#include "base/macros.h"
#include "net/rpc/server/rpc_handler.h"
#include "base/logging.h"
#include "rpc/support/alloc.h"
#include "rpc/support/host_port.h"
#include "rpc/grpc.h"
#include "net/rpc/server/rpc_state.h"
#include "net/rpc/server/rpc_call_state.h"

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

namespace net {

template <class T>
class NET_EXPORT ProxyRpcHandler : public RpcHandler {
public:
  ProxyRpcHandler(T* handler): handler_(handler) {}
  ~ProxyRpcHandler() override {}

  void HandleCallBegin(RpcCallState* call, const std::string& method_name, const std::string& host_name) override {
    handler_->OnCallArrived(call->id, method_name);
  }

  void HandleCallStreamRead(RpcCallState* call) override {
    std::vector<char> data;
    if (call->recv_message != nullptr) {
      grpc_byte_buffer_reader reader;
      if (grpc_byte_buffer_reader_init(&reader, call->recv_message)) {
        grpc_slice s;
        while (grpc_byte_buffer_reader_next(&reader, &s)) {
          data.insert(data.end(), GRPC_SLICE_START_PTR(s), GRPC_SLICE_START_PTR(s) + GRPC_SLICE_LENGTH(s));
        }
        grpc_byte_buffer_reader_destroy(&reader);
        LOG(INFO) << "HandleCallStreamRead: call " << call->id << ": stream read final data buffer size: " << data.size() << " content:\n'" << std::string(data.begin(), data.end()) << "'";
        handler_->OnCallDataAvailable(call->id, data);
      } else {
        LOG(ERROR) << "HandleCallStreamRead: error on init buffer reader for call->recv_message";
      }
    } else {
      LOG(ERROR) << "HandleCallStreamRead: call->recv_message is NULL";
    }
  }

  void HandleCallStreamSendInitMetadata(RpcCallState* call) override {
    
  }

  void HandleCallStreamWrite(RpcCallState* call) override {
    
  }

  void HandleCallUnaryRead(RpcCallState* call) override {
    std::vector<char> data;
    if (call->recv_message != nullptr) {
      grpc_byte_buffer_reader reader;
      if (grpc_byte_buffer_reader_init(&reader, call->recv_message)) {
        grpc_slice s;
        while (grpc_byte_buffer_reader_next(&reader, &s)) {
          data.insert(data.end(), GRPC_SLICE_START_PTR(s), GRPC_SLICE_START_PTR(s) + GRPC_SLICE_LENGTH(s));
        }
        grpc_byte_buffer_reader_destroy(&reader);
        //LOG(INFO) << "unary read: (call id: " << call->id << ") final data buffer size: " << data.size() << " content:\n'" << std::string(data.begin(), data.end()) << "'";
      } else {
        LOG(ERROR) << "error on init buffer reader for call->recv_message";
      }
    }
    handler_->OnCallDataAvailable(call->id, std::move(data));
  }

  void HandleCallEnd(RpcCallState* call) override {
    handler_->OnCallEnded(call->id);  
  }

  void HandleRpcSendError(RpcCallState* call, int rc) override {
  }

private:
  T* handler_;

  DISALLOW_COPY_AND_ASSIGN(ProxyRpcHandler);
};

}

#endif