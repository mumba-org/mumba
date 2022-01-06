// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_RPC_RPC_SERVICE_H_
#define NET_RPC_RPC_SERVICE_H_

#include <unordered_map>
#include <memory>

#include "base/macros.h"
#include "base/callback.h"
#include "base/memory/weak_ptr.h"
#include "base/threading/thread.h"
#include "base/synchronization/lock.h"
#include "base/strings/string_number_conversions.h"
#include "base/atomic_sequence_num.h"
#include "base/memory/ref_counted.h"
#include "base/synchronization/waitable_event.h"
#include "net/rpc/rpc.h"
#include "net/base/net_export.h"
#include "net/rpc/server/rpc_handler.h"
#include "base/uuid.h"
#include "net/socket/socket_descriptor.h"
#include "net/socket/server_socket.h"
#include "rpc/grpc.h"
#include "third_party/protobuf/src/google/protobuf/descriptor.h"

// namespace IPC {
// class Sender;
// class Message;
// }

namespace net {
class RpcServiceManager;
class RpcSocket;
struct RpcCallState;
class RpcServiceHandler;

enum class RpcServiceState {
 kINIT,
 kSTARTED,
 kSTOPPED,
 kERROR,
};

struct RpcServiceOptions {
  std::string host;
  int port;
  void* state;
  void (*read_callback)(grpc_exec_ctx*, void* arg, grpc_error*);
  //void (*accept_callback)(grpc_exec_ctx*, void*, grpc_endpoint*, grpc_pollset*, grpc_tcp_server_acceptor*);

  RpcServiceOptions(): host("localhost"), port(0) {}
};

// struct RpcMethod {
//   RpcTransportType transport_type;
//   common::RpcMethodType method_type;
//   std::string host;
//   int port;
//   base::StringPiece service;
//   base::StringPiece container;
//   base::StringPiece method;
//   std::string full_method;
//   const google::protobuf::MethodDescriptor* descriptor;
//   //void* tag;
  
//   RpcMethod(
//     const google::protobuf::MethodDescriptor* descriptor,
//     RpcTransportType transport_type, 
//     common::RpcMethodType method_type, 
//     const std::string& host,
//     int port);
  
//   ~RpcMethod();

//   const std::string& full_name() const;

//   // URL url() const {
//   //   return GURL((transport_type == RpcTransportType::kHTTP ? "http://" : "unix://")+host+":"+base::IntToString(port)+name);
//   // }

//   grpc_server_register_method_payload_handling payload_handling() const {
//     switch (method_type) {
//       case common::RpcMethodType::kNORMAL:
//       case common::RpcMethodType::kSERVER_STREAM:
//         return GRPC_SRM_PAYLOAD_READ_INITIAL_BYTE_BUFFER;
//       case common::RpcMethodType::kCLIENT_STREAM:
//       case common::RpcMethodType::kBIDI_STREAM:
//         return GRPC_SRM_PAYLOAD_NONE;
//     }
//     return GRPC_SRM_PAYLOAD_NONE;
//   }

//   bool has_payload() const {
//     return method_type == common::RpcMethodType::kNORMAL || 
//       method_type == common::RpcMethodType::kSERVER_STREAM;
//   }

//   void Init();

// };

// Basically a thread to handle the completion queue
class RpcServiceContext : public base::RefCountedThreadSafe<RpcServiceContext> {
public:
  //typedef std::vector<RpcMethod*> Methods;
  //typedef Methods::const_iterator ConstIterator;
  //typedef Methods::iterator Iterator;
  class Delegate {
  public:
    virtual ~Delegate() {}
    virtual void OnStart(bool result, net::SocketDescriptor fd) = 0;
    virtual void OnStop(bool result) = 0;
  };

  RpcServiceContext(
    Delegate* delegate, 
    const std::string& host,
    int port, 
    RpcTransportType type,
    std::unique_ptr<RpcHandler> rpc_handler);

  void Init(const RpcServiceOptions& options, scoped_refptr<base::SingleThreadTaskRunner> delegate_thread, scoped_refptr<base::SingleThreadTaskRunner> io_thread);
  void Shutdown(scoped_refptr<base::SingleThreadTaskRunner> delegate_thread,
    base::WaitableEvent* shutdown_event);
  //void Wait(scoped_refptr<base::SequencedWorkerPool> worker_pool);
  void Wait();

  const base::UUID& uuid() const { return uuid_; }

  // '127.0.0.1'
  const std::string& host() const { return host_; }

  const scoped_refptr<base::SingleThreadTaskRunner>& io_thread() const {
    return io_thread_;
  }

  int port() const { return port_; }

  RpcTransportType transport_type() const { return transport_type_; }

  //RpcServiceContext::Iterator methods_begin() { return methods_.begin(); }
  //RpcServiceContext::ConstIterator methods_begin() const { return methods_.begin(); }

  //RpcServiceContext::Iterator methods_end() { return methods_.end(); }
  //RpcServiceContext::ConstIterator methods_end() const { return methods_.end(); }

  //size_t method_count() { return methods_.size(); }

  //RpcMethod* AddMethod(const google::protobuf::MethodDescriptor* descriptor, common::RpcMethodType type);
  //RpcMethod* GetMethod(const std::string& method_name) const;
 
  RpcServiceHandler* handler() const {
    return handler_;
  }

  void BindHandler(RpcServiceHandler* handler);

  void OnRpcSendError(RpcCallState* call, int rc);

private:
  friend class base::RefCountedThreadSafe<RpcServiceContext>;
  friend class RpcService;

  ~RpcServiceContext();

  void RegisterSocket(RpcSocket* socket);
  
  void ProcessCall(RpcCallState* call);
  void RequestCall(RpcCallState* call, RpcSocket* socket);
  void RequestSameCall(RpcCallState* call, RpcSocket* socket);
  void DestroyCall(RpcCallState* call);
  grpc_event NextEvent(RpcCallState* call);
  base::WeakPtr<RpcCallState> GetCallStateForCall(int call_id);

  //void SendIPCMessageOnIOThread(IPC::Message* message);

  base::Lock call_vector_mutex_;

  Delegate* delegate_;

  grpc_completion_queue* server_completion_queue_;

  grpc_server* server_;

  //IPC::Sender* message_sender_;

  std::vector<std::unique_ptr<RpcCallState>> processing_calls_;

  base::UUID uuid_;

  std::string host_;

  int port_;
  
  RpcTransportType transport_type_;

  //Methods methods_;

  RpcServiceHandler* handler_;

  std::unique_ptr<RpcHandler> rpc_handler_;

  scoped_refptr<base::SingleThreadTaskRunner> io_thread_;

  mutable bool is_shutting_down_;

  base::WaitableEvent wait_event_;

  base::AtomicSequenceNumber call_id_gen_;

  DISALLOW_COPY_AND_ASSIGN(RpcServiceContext);
};

class NET_EXPORT RpcService : public RpcServiceContext::Delegate {
public:
  class Observer {
  public:
    virtual ~Observer() {}
    virtual void OnStart(RpcService* service) = 0;
    virtual void OnStop(RpcService* service) = 0;
  };

  RpcService(
    //AppHost* shell,
    const std::string& container,
    const std::string& name,
    const std::string& host,
    int port,
    RpcTransportType type,
    const scoped_refptr<base::SingleThreadTaskRunner>& context_thread,
    const scoped_refptr<base::SingleThreadTaskRunner>& delegate_thread,
    const scoped_refptr<base::SingleThreadTaskRunner>& io_thread,
    //Protocol* proto,
    std::unique_ptr<RpcHandler> rpc_handler);

  ~RpcService() override;

  //AppHost* shell() const { return apphost_; }
  const base::UUID& uuid() const { return context_->uuid_; }
  const std::string& container() const { return container_; }
  const std::string& name() const { return name_; }
  RpcTransportType transport_type() const { return context_->transport_type_; }
  RpcServiceState state() const { return state_; }

  const std::string& host() const { return options_.host; }
  void set_host(const std::string& host) { options_.host = host;}

  int port() const { return options_.port; }
  void set_port(int port) { options_.port = port; }

  const scoped_refptr<base::SingleThreadTaskRunner>& context_thread() const {
    return context_thread_;
  }

  const scoped_refptr<base::SingleThreadTaskRunner>& io_thread() const {
    return io_thread_;
  }

  // return proto associated with this service
  //Protocol* proto() const {
  //  return proto_;
  //}

  const google::protobuf::ServiceDescriptor* service_descriptor();

  void set_service_descriptor(const google::protobuf::ServiceDescriptor* service_descriptor) {
    service_descriptor_ = service_descriptor;
  }

  RpcServiceOptions& options() {
    return options_;
  }

  const RpcServiceOptions& options() const {
    return options_;
  }

  RpcServiceHandler* handler() const {
    return context_->handler();
  }

  void BindHandler(RpcServiceHandler* handler);

  //RpcServiceContext::Iterator methods_begin() { return context_->methods_.begin(); }
  //RpcServiceContext::ConstIterator methods_begin() const { return context_->methods_.begin(); }

  //RpcServiceContext::Iterator methods_end() { return context_->methods_.end(); }
  //RpcServiceContext::ConstIterator methods_end() const { return context_->methods_.end(); }

  //size_t method_count() { return context_->methods_.size(); }

  //RpcMethod* AddMethod(const google::protobuf::MethodDescriptor* descriptor, common::RpcMethodType type);
  //RpcMethod* GetMethod(const std::string& method_name) const;
  
  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

  int Start(base::Callback<void(int, net::SocketDescriptor)> reply_to);
  void Stop(base::WaitableEvent* shutdown_event);

  void RegisterSocket(RpcSocket* socket);
  void RequestCall(RpcCallState* call, RpcSocket* socket);
  //RpcCallState* GetCallStateForSocket(int socket_id);
  base::WeakPtr<RpcCallState> GetCallStateForCall(int call_id);

  void OnRpcSendError(RpcCallState* call, int rc);

  std::vector<RpcDescriptor> GetMethodDescriptors();

private:
  friend class RpcServiceManager;

  void OnStart(bool result, net::SocketDescriptor fd) override;
  void OnStop(bool result) override;

  void NotifyStart();
  void NotifyStop();

  //base::Thread context_thread_;
  scoped_refptr<base::SingleThreadTaskRunner> context_thread_;

  scoped_refptr<RpcServiceContext> context_;

  std::vector<Observer *> observers_;

  //AppHost* apphost_;

  //Protocol* proto_;

  const google::protobuf::ServiceDescriptor* service_descriptor_;

  std::string container_;

  std::string name_; 
  
  RpcServiceOptions options_;

  RpcServiceState state_;

  scoped_refptr<base::SingleThreadTaskRunner> delegate_thread_;

  scoped_refptr<base::SingleThreadTaskRunner> io_thread_;

  base::Callback<void(int, net::SocketDescriptor)> reply_to_;

  base::WeakPtrFactory<RpcService> weak_factory_;

  DISALLOW_COPY_AND_ASSIGN(RpcService);
};

}

#endif