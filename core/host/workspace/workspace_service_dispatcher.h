// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_WORKSPACE_WORKSPACE_SERVICE_DISPATCHER_H_
#define MUMBA_HOST_WORKSPACE_WORKSPACE_SERVICE_DISPATCHER_H_

#include <memory>
#include <unordered_map>

#include "base/macros.h"
#include "base/compiler_specific.h"
#include "base/atomic_sequence_num.h"
#include "base/message_loop/message_loop.h"
#include "base/synchronization/waitable_event.h"
#include "net/base/completion_callback.h"
#include "net/socket/socket_descriptor.h"
#include "net/socket/tcp_server_socket.h"
#include "net/socket/tcp_socket.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "rpc/grpc.h"
#include "rpc/iomgr/tcp_server.h"

struct server_state;
struct grpc_tcp_listener;

namespace net {
class StreamSocket;
}  // namespace net

namespace host {
class Workspace;
class MumbaServices;
class MumbaServicesUnaryCallHandler;

class WorkspaceServiceDispatcher {
public:
  WorkspaceServiceDispatcher(scoped_refptr<Workspace> workspace, const std::string& service_host, int service_port);
  ~WorkspaceServiceDispatcher();

  MumbaServices* mumba_services() const {
    return mumba_services_.get();
  }

  bool Init();
  void Shutdown();
  
  //void OnRead(grpc_exec_ctx* exec_ctx, grpc_tcp_listener* sp, grpc_error* err);
  void OnAccept(grpc_exec_ctx* exec_ctx, grpc_tcp_listener* sp, grpc_error* err, int fd, grpc_resolved_address addr);

  bool InstallSchemaFromBundle();

  void AddServiceHandler(std::unique_ptr<MumbaServicesUnaryCallHandler> handler);
  
private:
  
  //void DoAccept();
  void HandleAcceptResult(int result);

  void OnRpcServiceStarted(
    int result, 
    net::SocketDescriptor server_fd);

  void AddServiceHandlers();

  bool InstallPackagedApp();
  
  scoped_refptr<Workspace> workspace_;

  std::unique_ptr<MumbaServices> mumba_services_;

  net::IPEndPoint local_address_;

  std::unique_ptr<net::ServerSocket> socket_;
  std::unique_ptr<net::StreamSocket> accept_socket_;

  grpc_exec_ctx* exec_ctx_;
  grpc_tcp_listener* listener_;
  bool proto_installed_;
  bool initialized_;
  std::string service_host_;
  int service_port_;

  base::WeakPtrFactory<WorkspaceServiceDispatcher> weak_factory_;
  
  DISALLOW_COPY_AND_ASSIGN(WorkspaceServiceDispatcher);
};

}

#endif
