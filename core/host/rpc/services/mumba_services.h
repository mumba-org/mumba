// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MUMBA_HOST_WORKSPACE_MUMBA_SERVICES_H_
#define MUMBA_HOST_WORKSPACE_MUMBA_SERVICES_H_

#include <memory>
#include <unordered_map>
#include <string>
#include <vector>

#include "base/macros.h"
#include "base/callback.h"
#include "base/atomic_sequence_num.h"
#include "base/sequenced_task_runner.h"
#include "core/host/host_thread.h"
#include "rpc/grpc.h"
#include "rpc/iomgr/tcp_server.h"
#include "net/base/completion_callback.h"
#include "net/base/ip_endpoint.h"
#include "net/socket/socket_descriptor.h"
#include "net/socket/tcp_server_socket.h"
#include "net/socket/tcp_socket.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "third_party/protobuf/src/google/protobuf/compiler/parser.h"
#include "third_party/protobuf/src/google/protobuf/io/tokenizer.h"
#include "third_party/protobuf/src/google/protobuf/io/zero_copy_stream_impl.h"
#include "third_party/protobuf/src/google/protobuf/stubs/strutil.h"
#include "third_party/protobuf/src/google/protobuf/io/zero_copy_stream_impl_lite.h"
#include "third_party/protobuf/src/google/protobuf/arena.h"
#include "third_party/protobuf/src/google/protobuf/arenastring.h"
#include "third_party/protobuf/src/google/protobuf/generated_message_table_driven.h"
#include "third_party/protobuf/src/google/protobuf/generated_message_util.h"
#include "third_party/protobuf/src/google/protobuf/inlined_string_field.h"
#include "third_party/protobuf/src/google/protobuf/metadata.h"
#include "third_party/protobuf/src/google/protobuf/message.h"
#include "third_party/protobuf/src/google/protobuf/dynamic_message.h"

struct server_state;
struct grpc_tcp_listener;

namespace net {
class DrainableIOBuffer;
class GrowableIOBuffer;
class StreamSocket;
class URLRequestContextGetter;
class RpcSocketClient;
}  // namespace net

namespace host {
class Workspace;
class HostRpcService;

class MumbaServicesUnaryCallHandler {
public:
  virtual ~MumbaServicesUnaryCallHandler() {}
  // TODO: Params
  int method_type() const { return 0; }
  virtual const std::string& fullname() const = 0;
  virtual base::StringPiece ns() const = 0;
  virtual base::StringPiece service_name() const = 0;
  virtual base::StringPiece method_name() const = 0;
  virtual const std::string& output() const = 0;
  
  virtual void HandleCall(std::vector<char> data, base::Callback<void(int)> cb) = 0;

  const google::protobuf::Descriptor* GetDescriptorFor(scoped_refptr<Workspace> workspace, const std::string& type_name) const;
  const google::protobuf::Message* GetProtoMessageFor(scoped_refptr<Workspace> workspace, const std::string& type_name) const;
  std::string GetStringField(scoped_refptr<Workspace> workspace, google::protobuf::Message* message, const std::string& type_name, const std::string& field_name);
};

class MumbaServicesHandler {
public:
  class Delegate {
  public:
    virtual ~Delegate() {}
    virtual void OnCallArrived(int call_id, int method_type, bool result) = 0;
    virtual void OnCallDataAvailable(int call_id, MumbaServicesUnaryCallHandler* handler, int method_type, bool result) = 0;
    virtual void OnCallEnded(int call_id, int method_type, bool result) = 0;
  };
  MumbaServicesHandler(base::WeakPtr<Delegate> delegate);//, const scoped_refptr<base::SequencedTaskRunner>& service_worker);
  ~MumbaServicesHandler();

  void OnCallArrived(int call_id, const std::string& method_fullname);
  void OnCallDataAvailable(int call_id, std::vector<char> data);
  void OnCallEnded(int call_id);

  void AddServiceHandler(std::unique_ptr<MumbaServicesUnaryCallHandler> handler);

private:

  void OnCallHandled(int call_id, MumbaServicesUnaryCallHandler* handler, int method_type, int r);
  void OnCallArrivedOnIOThread(int call_id, const std::string& method_fullname);
  void OnCallDataAvailableOnIOThread(int call_id, std::vector<char> data, MumbaServicesUnaryCallHandler* handler, base::Callback<void(int)> cb);
  void OnCallEndedOnIOThread(int call_id);

  base::WeakPtr<Delegate> delegate_;
  std::vector<std::unique_ptr<MumbaServicesUnaryCallHandler>> handlers_;
  std::unordered_map<int, MumbaServicesUnaryCallHandler*> calls_;
  scoped_refptr<base::SequencedTaskRunner> service_worker_;
  //base::WeakPtrFactory<MumbaServicesHandler> weak_factory_;
  std::unique_ptr<base::WeakPtrFactory<MumbaServicesHandler>, HostThread::DeleteOnIOThread> io_weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(MumbaServicesHandler);
};

class MumbaServices : public MumbaServicesHandler::Delegate {
public:
  MumbaServices();
  ~MumbaServices() override;

  HostRpcService* rpc_service() const {
    return rpc_service_;
  }

  MumbaServicesHandler* handler() const {
    return host_host_service_handler_.get();
  }

  void Shutdown();

  // const scoped_refptr<base::SequencedTaskRunner>& service_worker() const {
  //   return service_worker_;
  // }

  bool Init(
    scoped_refptr<Workspace> workspace,
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


  void AddServiceHandler(std::unique_ptr<MumbaServicesUnaryCallHandler> handler);

  void AddDefaultServices();

private:

  void AcceptOnIOThread(const net::IPEndPoint& remote_address,
    std::unique_ptr<net::StreamSocket> socket,
    grpc_exec_ctx* exec_ctx, 
    server_state* state,
    grpc_endpoint* tcp,
    grpc_pollset* accepting_pollset,
    grpc_tcp_server_acceptor* acceptor);

  void EndCallOnIOThread(int call_id);
  
  void OnCallHandled(int call_id, MumbaServicesUnaryCallHandler* handler, int method_type, int r);

  // MumbaServicesHandler::Delegate
  void OnCallArrived(int call_id, int method_type, bool result) override;
  void OnCallDataAvailable(int call_id, MumbaServicesUnaryCallHandler* handler, int method_type, bool result) override;
  void OnCallEnded(int call_id, int method_type, bool result) override;
  void ShutdownOnIO();
  
  HostRpcService* rpc_service_;

  std::vector<std::unique_ptr<net::RpcSocketClient, HostThread::DeleteOnIOThread>> clients_;

  std::unique_ptr<MumbaServicesHandler> host_host_service_handler_;

  std::unordered_map<int, net::RpcSocketClient*> call_to_client_map_;
  base::Lock client_lock_;

 // scoped_refptr<base::SequencedTaskRunner> service_worker_;

  base::AtomicSequenceNumber id_gen_;

  net::RpcSocketClient* accepted_client_;
  
  base::WaitableEvent shutdown_event_;
  base::WeakPtrFactory<MumbaServices> weak_factory_;
  base::WeakPtrFactory<MumbaServices> io_weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(MumbaServices);
};

}

#endif