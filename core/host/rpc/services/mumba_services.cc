// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/services/mumba_services.h"

#include <vector>

#include "base/strings/string_split.h"
#include "base/strings/utf_string_conversions.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/workspace/workspace.h"
#include "core/host/host_controller.h"
#include "core/host/host_main_loop.h"
#include "net/rpc/server/rpc_socket_client.h"
#include "net/rpc/server/proxy_rpc_handler.h"
#include "core/host/rpc/server/host_rpc_service.h"
#include "core/host/rpc/services/service_start_handler.h"
#include "core/host/rpc/services/service_list_handler.h"
#include "core/host/rpc/services/service_stop_handler.h"
#include "core/host/rpc/services/bundle_handler.h"
#include "core/host/rpc/services/application_handler.h"
#include "core/host/rpc/services/system_handler.h"
#include "core/host/rpc/services/ml_handler.h"

namespace host {


const google::protobuf::Descriptor* MumbaServicesUnaryCallHandler::GetDescriptorFor(scoped_refptr<Workspace> workspace, const std::string& type_name) const {
  SchemaRegistry* schema_registry = workspace->schema_registry();
  Schema* mumba_schema = schema_registry->GetSchemaByName("mumba");
  if (!mumba_schema) {
    DLOG(INFO) << "main 'mumba.proto' schema not found";
    return nullptr;
  }
  return mumba_schema->GetMessageDescriptorNamed(type_name);
}

const google::protobuf::Message* MumbaServicesUnaryCallHandler::GetProtoMessageFor(scoped_refptr<Workspace> workspace, const std::string& type_name) const {
  const google::protobuf::Descriptor* message_descriptor = GetDescriptorFor(workspace, type_name);
  if (!message_descriptor) {
    DLOG(INFO) << "output message for ServiceStart() '" << type_name << "' not found";
    return nullptr;
  }
  SchemaRegistry* schema_registry = workspace->schema_registry();
  google::protobuf::DescriptorPool* descriptor_pool = schema_registry->descriptor_pool();
  google::protobuf::DynamicMessageFactory factory(descriptor_pool);
  const google::protobuf::Message* message = factory.GetPrototype(message_descriptor);
  return message;
}

std::string MumbaServicesUnaryCallHandler::GetStringField(scoped_refptr<Workspace> workspace, google::protobuf::Message* message, const std::string& type_name, const std::string& field_name) {
  SchemaRegistry* schema_registry = workspace->schema_registry();
  Schema* mumba_schema = schema_registry->GetSchemaByName("mumba");
  if (!mumba_schema) {
    LOG(ERROR) << "main 'mumba.proto' schema not found";
    return std::string();
  }
  const google::protobuf::Descriptor* descriptor = mumba_schema->GetMessageDescriptorNamed(type_name);
  const google::protobuf::FieldDescriptor* field = descriptor->FindFieldByName(field_name);
  if (!field) {
    LOG(ERROR) << "field named '" << field_name << "' not found";
    return std::string();
  }
  return message->GetReflection()->GetString(*message, field);
}

MumbaServicesHandler::MumbaServicesHandler(base::WeakPtr<Delegate> delegate)://,
 //const scoped_refptr<base::SequencedTaskRunner>& service_worker):
 delegate_(std::move(delegate)),
 //weak_factory_(this),
 io_weak_factory_(new base::WeakPtrFactory<MumbaServicesHandler>(this)) {//,
 //service_worker_(service_worker) {

}

MumbaServicesHandler::~MumbaServicesHandler() {
  //for (auto it = calls_.begin(); it != calls_.end(); ++it) {
  //  delete it->second;
  //}
  calls_.clear();
  handlers_.clear();
}

void MumbaServicesHandler::AddServiceHandler(std::unique_ptr<MumbaServicesUnaryCallHandler> handler) {
  handlers_.push_back(std::move(handler));
}

void MumbaServicesHandler::OnCallArrived(int call_id, const std::string& method_fullname) {
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE, 
    base::BindOnce(&MumbaServicesHandler::OnCallArrivedOnIOThread, 
      //base::Unretained(this), 
      //weak_factory_.GetWeakPtr(),
      io_weak_factory_->GetWeakPtr(),
      call_id, 
      method_fullname));
}

void MumbaServicesHandler::OnCallArrivedOnIOThread(int call_id, const std::string& method_fullname) {
  DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  for (auto it = handlers_.begin(); it != handlers_.end(); ++it) {
    MumbaServicesUnaryCallHandler* handler = it->get();
    if (handler->fullname() == method_fullname) {
      calls_.emplace(std::make_pair(call_id, handler));
      if (delegate_) {
        delegate_->OnCallArrived(call_id, handler->method_type(), true);
      }
      return;
    }
  }
  if (delegate_) {
    delegate_->OnCallArrived(call_id, -1, false);
  }
}

void MumbaServicesHandler::OnCallDataAvailable(int call_id, std::vector<char> data) {
  //DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  auto it = calls_.find(call_id);
  if (it != calls_.end()) {
    MumbaServicesUnaryCallHandler* handler = it->second;
    auto cb = base::Bind(&MumbaServicesHandler::OnCallHandled,
          //weak_factory_.GetWeakPtr(),
          //io_weak_factory_->GetWeakPtr(),
          base::Unretained(this), 
          call_id, 
          base::Unretained(handler), 
          handler->method_type());

    HostThread::PostTask(
      HostThread::UI,
      FROM_HERE, 
      base::BindOnce(&MumbaServicesHandler::OnCallDataAvailableOnIOThread, 
        base::Unretained(this), 
        //weak_factory_.GetWeakPtr(),
        //io_weak_factory_->GetWeakPtr(),
        call_id, 
        base::Passed(std::move(data)),
        base::Unretained(handler),
        base::Passed(std::move(cb))));
    //OnCallDataAvailableOnIOThread(call_id, std::move(data), handler, std::move(cb));
  }
}

void MumbaServicesHandler::OnCallDataAvailableOnIOThread(int call_id, std::vector<char> data, MumbaServicesUnaryCallHandler* handler, base::Callback<void(int)> cb) {
  //DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  //DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  handler->HandleCall(std::move(data), std::move(cb));
  //delegate_->OnCallDataAvailable(call_id, handler, handler->method_type(), true);
  //if (delegate_) {
  //  delegate_->OnCallEnded(call_id, handler->method_type(), true);
  //}
  //delegate_->OnCallDataAvailable(call_id, nullptr, -1, false);
  OnCallEnded(call_id);
}

void MumbaServicesHandler::OnCallEnded(int call_id) {
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE, 
    base::BindOnce(&MumbaServicesHandler::OnCallEndedOnIOThread, 
      //base::Unretained(this), 
      //weak_factory_.GetWeakPtr(),
      io_weak_factory_->GetWeakPtr(),
      call_id));
  //OnCallEndedOnIOThread(call_id);
}

void MumbaServicesHandler::OnCallEndedOnIOThread(int call_id) {
  DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  auto it = calls_.find(call_id);
  if (it != calls_.end()) {
    if (delegate_) {
      delegate_->OnCallEnded(call_id, it->second->method_type(), true);
    }
    //delete it->second;
    calls_.erase(it);
    return;
  }
  if (delegate_) {
    delegate_->OnCallEnded(call_id, -1, false);
  }
}

void MumbaServicesHandler::OnCallHandled(int call_id, MumbaServicesUnaryCallHandler* handler, int method_type, int r) {
  //DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  if (delegate_) {
    delegate_->OnCallDataAvailable(call_id, handler, method_type, r == 0);
  }
}

MumbaServices::MumbaServices(): 
  rpc_service_(nullptr),
  //service_worker_(base::CreateSequencedTaskRunnerWithTraits({base::MayBlock(), base::WithBaseSyncPrimitives(), base::TaskPriority::BACKGROUND})),
  accepted_client_(nullptr),
  shutdown_event_(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED),
  weak_factory_(this),
  io_weak_factory_(this) {

  host_host_service_handler_.reset(new MumbaServicesHandler(weak_factory_.GetWeakPtr()));//, service_worker_));
}

MumbaServices::~MumbaServices() {
  rpc_service_ = nullptr;
}

bool MumbaServices::Init(
  scoped_refptr<Workspace> workspace,
  const std::string& host, 
  int port, 
  void* state,
  void (*on_read_cb)(grpc_exec_ctx* exec_ctx, void* arg, grpc_error* err),
  base::Callback<void(int, net::SocketDescriptor)> on_service_started) {
  
  rpc_service_ = workspace->CreateService(
    "mumba",
    "Mumba",
    host,
    port, 
    net::RpcTransportType::kHTTP,
    //base::ThreadTaskRunnerHandle::Get(),
    HostThread::GetTaskRunnerForThread(HostThread::UI),
    std::make_unique<net::ProxyRpcHandler<MumbaServicesHandler>>(host_host_service_handler_.get()));

  if (!rpc_service_) {
    LOG(ERROR) << "Rpc server: Unable to create service 'mumba.Mumba'";
    return false;
  }

  net::RpcServiceOptions& service_options = rpc_service_->options();
  service_options.state = state;
  service_options.read_callback = on_read_cb;

  int result = rpc_service_->Start(std::move(on_service_started));

  return result == 0;
}

void MumbaServices::AddServiceHandler(std::unique_ptr<MumbaServicesUnaryCallHandler> handler) {
  host_host_service_handler_->AddServiceHandler(std::move(handler));
}

void MumbaServices::AddDefaultServices() {
  AddServiceHandler(std::make_unique<SystemShutdownHandler>());
  AddServiceHandler(std::make_unique<ApplicationInstanceLaunchHandler>());
  AddServiceHandler(std::make_unique<ApplicationInstanceCloseHandler>());
  AddServiceHandler(std::make_unique<BundleInstallHandler>());
  AddServiceHandler(std::make_unique<ServiceStartHandler>());
  AddServiceHandler(std::make_unique<ServiceStopHandler>());
  AddServiceHandler(std::make_unique<ServiceListHandler>());
  // ml
  AddServiceHandler(std::make_unique<MLPredictorInstallHandler>());
}

bool MumbaServices::Accept(
    const net::IPEndPoint& remote_address,
    std::unique_ptr<net::StreamSocket> socket,
    grpc_exec_ctx* exec_ctx, 
    server_state* state,
    grpc_endpoint* tcp,
    grpc_pollset* accepting_pollset,
    grpc_tcp_server_acceptor* acceptor) {
  // std::unique_ptr<net::RpcSocketClient, HostThread::DeleteOnIOThread> client(new net::RpcSocketClient(id_gen_.GetNext() + 1));

  // // not very good as more than one connection might arrive before
  // // we can clean it up.. passing as state to get it later is the only option
  // // better if we use a int identifier
  // accepted_client_ = client.get();
  
  // if (!client->InitAccepted(
  //     rpc_service_,
  //     remote_address, 
  //     std::move(socket),
  //     exec_ctx,
  //     state,
  //     tcp,
  //     accepting_pollset,
  //     acceptor)) {
    
  //   return false;
  // }
    
  // rpc_service_->RegisterSocket(client->socket());

  // clients_.push_back(std::move(client));
  //if (HostThread::CurrentlyOn(HostThread::IO)) {
    AcceptOnIOThread(
      remote_address,
      std::move(socket),
      exec_ctx, 
      state,
      tcp,
      accepting_pollset,
      acceptor);
  // } else {
  //   HostThread::PostTask(HostThread::IO, 
  //     FROM_HERE, 
  //     base::BindOnce(
  //       &MumbaServices::AcceptOnIOThread, 
  //       weak_factory_.GetWeakPtr(), 
  //       remote_address,
  //       base::Passed(std::move(socket)),
  //       base::Unretained(exec_ctx), 
  //       base::Unretained(state),
  //       base::Unretained(tcp),
  //       base::Unretained(accepting_pollset),
  //       base::Unretained(acceptor)));
  // }
  return true;
}

void MumbaServices::AcceptOnIOThread(
  const net::IPEndPoint& remote_address,
  std::unique_ptr<net::StreamSocket> socket,
  grpc_exec_ctx* exec_ctx, 
  server_state* state,
  grpc_endpoint* tcp,
  grpc_pollset* accepting_pollset,
  grpc_tcp_server_acceptor* acceptor) {
  std::unique_ptr<net::RpcSocketClient, HostThread::DeleteOnIOThread> client(new net::RpcSocketClient(id_gen_.GetNext() + 1));

  // not very good as more than one connection might arrive before
  // we can clean it up.. passing as state to get it later is the only option
  // better if we use a int identifier
  accepted_client_ = client.get();
  
  if (!client->InitAccepted(
      rpc_service_,
      remote_address, 
      std::move(socket),
      exec_ctx,
      state,
      tcp,
      accepting_pollset,
      acceptor)) {
    return;
  }

  rpc_service_->RegisterSocket(client->socket());

  base::AutoLock lock(client_lock_);
  clients_.push_back(std::move(client));
}

void MumbaServices::OnCallHandled(int call_id, MumbaServicesUnaryCallHandler* handler, int method_type, int r) {
  DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  OnCallDataAvailable(call_id, handler, method_type, r == 0);
}

void MumbaServices::Shutdown() {
  // We need to dispatch to IO and yet we need to block
  // but its ok because we are in clean shutdown  
  HostThread::PostTask(HostThread::IO, 
    FROM_HERE, 
    base::BindOnce(
      &MumbaServices::ShutdownOnIO, 
      base::Unretained(this)));
  shutdown_event_.Wait();
  host_host_service_handler_.reset();
}

void MumbaServices::ShutdownOnIO() {
  weak_factory_.InvalidateWeakPtrs();
  shutdown_event_.Signal();
}

void MumbaServices::OnCallArrived(int call_id, int method_type, bool result) {
  DCHECK(accepted_client_);
  if (result) {
    call_to_client_map_.emplace(std::make_pair(call_id, accepted_client_));
    accepted_client_->socket()->DispatchReceiveMessage(call_id, method_type);
  }
  accepted_client_ = nullptr;
}

void MumbaServices::OnCallDataAvailable(int call_id, MumbaServicesUnaryCallHandler* handler, int method_type, bool result) {
  //DLOG(INFO) << "MumbaServices::OnCallDataAvailable:  WARNING: sending rpc output back is disabled until process launch bug is solved";
  base::AutoLock lock(client_lock_);
  auto it = call_to_client_map_.find(call_id);
  if (result && it != call_to_client_map_.end()) {
    std::vector<char> data(handler->output().begin(), handler->output().end());
    net::RpcSocketClient* client = it->second;
    client->socket()->DispatchSendMessage(call_id, data, method_type);
  }
}

void MumbaServices::OnCallEnded(int call_id, int method_type, bool result) {
  //HostThread::PostTask(
  //     HostThread::IO, 
  rpc_service_->context_thread()->PostTask(
     FROM_HERE, 
     base::BindOnce(
       &MumbaServices::EndCallOnIOThread, 
       io_weak_factory_.GetWeakPtr(), 
       call_id));
  //DLOG(INFO) << "MumbaServices::OnCallEnded";
  //EndCallOnIOThread(call_id);
}

void MumbaServices::EndCallOnIOThread(int call_id) {
  //DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  base::AutoLock lock(client_lock_);

  auto it = call_to_client_map_.find(call_id);
  if (it != call_to_client_map_.end()) {
    net::RpcSocketClient* client = it->second;
    client->socket()->Disconnect();
    call_to_client_map_.erase(it);
    for (auto cli_it = clients_.begin(); cli_it != clients_.end(); ++ cli_it) {
      if (cli_it->get() == client) {
        clients_.erase(cli_it);       
        return;
      }
    }
  }
}

}
