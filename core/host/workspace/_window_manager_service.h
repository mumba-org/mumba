// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_WORKSPACE_WINDOW_MANAGER_SERVICE_H_
#define MUMBA_HOST_WORKSPACE_WINDOW_MANAGER_SERVICE_H_

#include <memory>
#include <unordered_map>
#include <string>
#include <vector>

#include "base/macros.h"
#include "base/callback.h"
#include "base/atomic_sequence_num.h"
#include "rpc/grpc.h"
#include "rpc/iomgr/tcp_server.h"
#include "net/base/completion_callback.h"
#include "net/base/ip_endpoint.h"
#include "net/socket/socket_descriptor.h"
#include "net/socket/tcp_server_socket.h"
#include "net/socket/tcp_socket.h"
#include "net/traffic_annotation/network_traffic_annotation.h"

struct server_state;
struct grpc_tcp_listener;

namespace net {
class DrainableIOBuffer;
class GrowableIOBuffer;
class StreamSocket;
class URLRequestContextGetter;
}  // namespace net

namespace host {
class Workspace;
class RpcSocketClient;
class net::RpcService;

class WindowManagerServiceUnaryCallHandler {
public:
  virtual ~WindowManagerServiceUnaryCallHandler() {}
  // TODO: Params
  int method_type() const { return 0; }
  virtual const std::string& fullname() const = 0;
  virtual base::StringPiece ns() const = 0;
  virtual base::StringPiece service_name() const = 0;
  virtual base::StringPiece method_name() const = 0;
  
  virtual void HandleCall(const std::string& url) = 0;
};

class WindowManagerServiceHandler {
public:
  class Delegate {
  public:
    virtual ~Delegate() {}
    virtual void OnCallArrived(int call_id, int method_type, bool result) = 0;
    virtual void OnCallDataAvailable(int call_id, int method_type, bool result) = 0;
    virtual void OnCallEnded(int call_id, int method_type, bool result) = 0;
  };
  WindowManagerServiceHandler(Delegate* delegate);
  ~WindowManagerServiceHandler();

  void OnCallArrived(int call_id, const std::string& method_fullname);
  void OnCallDataAvailable(int call_id, const std::vector<char>& data);
  void OnCallEnded(int call_id);

private:
  Delegate* delegate_;
  std::unordered_map<int, WindowManagerServiceUnaryCallHandler*> calls_;

  DISALLOW_COPY_AND_ASSIGN(WindowManagerServiceHandler);
};

class WindowManagerService : public WindowManagerServiceHandler::Delegate {
public:
  WindowManagerService();
  ~WindowManagerService() override;

  net::RpcService* rpc_service() const {
    return rpc_service_;
  }

  WindowManagerServiceHandler* handler() const {
    return host_host_service_handler_.get();
  }

  bool Init(
    Workspace* workspace,
    const std::string& host, 
    int port,
    void* state,
    void (*on_read_cb)(grpc_exec_ctx* exec_ctx, void* arg, grpc_error* err),
    base::Callback<void(int, net::SocketDescriptor)> on_service_started);

 bool Accept(const net::IPEndPoint& remote_address,
             std::unique_ptr<net::StreamSocket> socket,
             grpc_exec_ctx* exec_ctx, 
             server_state* state,
             grpc_endpoint* tcp,
             grpc_pollset* accepting_pollset,
             grpc_tcp_server_acceptor* acceptor);

private:
  // WindowManagerServiceHandler::Delegate
  void OnCallArrived(int call_id, int method_type, bool result) override;
  void OnCallDataAvailable(int call_id, int method_type, bool result) override;
  void OnCallEnded(int call_id, int method_type, bool result) override;
  
  net::RpcService* rpc_service_;

  std::vector<std::unique_ptr<RpcSocketClient>> clients_;

  std::unique_ptr<WindowManagerServiceHandler> host_host_service_handler_;

  std::unordered_map<int, RpcSocketClient*> call_to_client_map_;

  base::AtomicSequenceNumber id_gen_;

  RpcSocketClient* accepted_client_;

  DISALLOW_COPY_AND_ASSIGN(WindowManagerService);
};

}

#endif