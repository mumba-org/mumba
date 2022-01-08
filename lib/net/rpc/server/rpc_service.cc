// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/rpc/server/rpc_service.h"

#include "base/bind.h"
#include "base/stl_util.h"
#include "base/task_scheduler/task_traits.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread_task_runner_handle.h"
#include "rpc/support/alloc.h"
#include "rpc/support/host_port.h"
#include "net/socket/tcp_server_socket.h"
#include "net/rpc/server/rpc_state.h"
#include "net/rpc/server/rpc_call_state.h"
#include "net/rpc/server/rpc_socket.h"
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

// layering violation => should be temporary
#include "core/host/host_thread.h"

namespace net {

namespace {

gpr_timespec grpc_timeout_seconds_to_deadline(int64_t time_s) {
  return gpr_time_add(
      gpr_now(GPR_CLOCK_MONOTONIC),
      gpr_time_from_millis((int64_t)1e3 * time_s,
                           GPR_TIMESPAN));
                           
}

static void* tag(intptr_t i) { return (void*)i; }

}

RpcMethodType GetMethodType(const google::protobuf::MethodDescriptor* method) {
  if (method->client_streaming() && method->server_streaming()) {
    return RpcMethodType::kBIDI_STREAM;
  }
  if (method->client_streaming()) {
    return RpcMethodType::kCLIENT_STREAM;
  }
  if (method->server_streaming()) {
    return RpcMethodType::kSERVER_STREAM; 
  }
  return RpcMethodType::kNORMAL;
}

RpcServiceContext::RpcServiceContext(
    Delegate* delegate,
    const std::string& host,
    int port, 
    RpcTransportType type,
    std::unique_ptr<RpcHandler> rpc_handler):
  delegate_(delegate),
  uuid_(base::UUID::generate()),
  host_(host),
  port_(port),
  transport_type_(type), 
  handler_(nullptr),
  rpc_handler_(std::move(rpc_handler)),
  is_shutting_down_(false),
  wait_event_(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED) {
  
  server_ = grpc_server_create(nullptr, nullptr);  
  server_completion_queue_ = grpc_completion_queue_create_for_next(nullptr);
  grpc_server_register_completion_queue(server_, server_completion_queue_, nullptr);
}

RpcServiceContext::~RpcServiceContext() {
  
}

void RpcServiceContext::Init(
  const RpcServiceOptions& options,
  scoped_refptr<base::SingleThreadTaskRunner> delegate_thread,
  scoped_refptr<base::SingleThreadTaskRunner> io_thread) {
  
  char* server_hostport;
  //void* tag = nullptr;
  net::SocketDescriptor descr = net::kInvalidSocket;

  io_thread_ = io_thread;

  gpr_join_host_port(&server_hostport, options.host.c_str(), options.port);
  grpc_server_add_insecure_http2_port(server_, server_hostport, options.state, options.read_callback);
 
  //DLOG(INFO) << "method count: " << node->method_count();

  //grpc_call_details_init(&call_details_);

  // TODO: we need a lock here to access node
//  for (auto it = methods_begin(); it != methods_end(); it++) {
 //   tag = grpc_server_register_method(
  //      server_, (*it)->name.c_str(), options.host.c_str(), (*it)->payload_handling(), 0);
 
    //DLOG(INFO) << "TAG: " << tag;
  //  if (tag == nullptr) {
  //    DLOG(ERROR) << "error registering method: " << (*it)->name;
  //  } else {
  //    DLOG(INFO) << "registered method: " << (*it)->name;
  //    (*it)->tag = tag;
//    }

//    tag = nullptr;
//  }

  grpc_server_start(server_);
  //RequestCall(nullptr, socket_id);
  // for (auto it = node->methods_begin(); it != node->methods_end(); it++) {
  //   RpcCallState* call = new RpcCallState(this, *it);
  //   calls_.push_back(call);
  // }

  //completion_queue_verifier_ = cq_verifier_create(server_completion_queue_);
  gpr_free(server_hostport);
  //Call();
  grpc_tcp_listener* tcp_listener = nullptr;
  for (listener* l = server_->listeners; l; l = l->next) {
    // FIX: i dont know if arg has the tcp_listener.. im just guessing here..
    server_state* state = (server_state *)l->arg;
    tcp_listener = state->tcp_server->head;
    DCHECK(tcp_listener);
#if defined(OS_POSIX)
    descr = tcp_listener->fd;
#elif defined(OS_WIN)
    descr = tcp_listener->socket->socket;
#endif
  }

  delegate_thread->PostTask(FROM_HERE, 
    base::Bind(&RpcServiceContext::Delegate::OnStart, 
      base::Unretained(delegate_), 
      true,
      descr));
}

void RpcServiceContext::Shutdown(scoped_refptr<base::SingleThreadTaskRunner> delegate_thread, base::WaitableEvent* shutdown_event) {
  //DestroyCall();
  //grpc_call_details_destroy(&call_details_);
  is_shutting_down_ = true;
  
  call_vector_mutex_.Acquire();
  for (auto it = processing_calls_.begin(); it != processing_calls_.end(); it++) {
    RpcCallState* state = it->release();
    state->Dispose();
    io_thread()->DeleteSoon(FROM_HERE, state);
  }
  processing_calls_.clear();
  call_vector_mutex_.Release();

  grpc_completion_queue* shutdown_cq = grpc_completion_queue_create_for_pluck(nullptr);
  grpc_server_shutdown_and_notify(server_, shutdown_cq, tag(1000));
  DCHECK(grpc_completion_queue_pluck(shutdown_cq, tag(1000),
                                    grpc_timeout_seconds_to_deadline(5),
                                    nullptr)
                 .type == GRPC_OP_COMPLETE);
  grpc_server_destroy(server_);
  grpc_completion_queue_destroy(shutdown_cq);

  //mutex_.Acquire();
  grpc_completion_queue_shutdown(server_completion_queue_);
  drain_cq(server_completion_queue_);
  
  wait_event_.Wait();

//  if (call_details_)
//    delete call_details_;
  //cq_verifier_destroy(completion_queue_verifier_);
  grpc_completion_queue_destroy(server_completion_queue_);
  //mutex_.Release();

  delegate_thread->PostTask(FROM_HERE, 
    base::Bind(&RpcServiceContext::Delegate::OnStop, 
      base::Unretained(delegate_), 
      true));

  if (shutdown_event) {
    shutdown_event->Signal();
  }
}

void RpcServiceContext::Wait(){//scoped_refptr<base::SequencedWorkerPool> worker_pool) {  
  for (;;) {
    auto ev = grpc_completion_queue_next(server_completion_queue_, gpr_inf_future(GPR_CLOCK_REALTIME), nullptr); //ms_from_now(5000), nullptr);
    switch (ev.type) {
      case GRPC_QUEUE_TIMEOUT: {
        //DLOG(INFO) << "RpcServiceContext::Wait: GRPC_QUEUE_TIMEOUT";
        continue;
      }
      case GRPC_QUEUE_SHUTDOWN: {
        //DLOG(INFO) << "RpcServiceContext::Wait: GRPC_QUEUE_SHUTDOWN";
        call_vector_mutex_.Acquire();
        for (auto it = processing_calls_.begin(); it != processing_calls_.end(); it++) {
          RpcCallState* state = it->release();
          state->Dispose();
          io_thread()->DeleteSoon(FROM_HERE, state);
        }
        processing_calls_.clear();
        call_vector_mutex_.Release();
        wait_event_.Signal();
        return;
      }
      case GRPC_OP_COMPLETE: {
        //DLOG(INFO) << "RpcServiceContext::Wait: GRPC_OP_COMPLETE";
        if (is_shutting_down_) {
          return;
        }
        RpcCallState* state = reinterpret_cast<RpcCallState *>(ev.tag);
        RpcSocket* socket = state->socket;
        if (ev.success != 0) {     
          base::PostTaskWithTraits(
            FROM_HERE,
            { base::MayBlock() },
            base::BindOnce(&RpcServiceContext::ProcessCall,
              this,
              base::Unretained(state)));
        }
        RequestCall(nullptr, socket);
        break;
      }
    }
  }
}

// RpcMethod* RpcServiceContext::GetMethod(const std::string& method_name) const {
//   //URL full_address = FormatAddress(transport_type_, addr);

//   for (auto it = methods_.begin(); it != methods_.end(); it++) {
//     if ((*it)->full_method == method_name) {
//       return *it;
//     }
//   }
//   return nullptr;
// }

// RpcMethod* RpcServiceContext::AddMethod(const google::protobuf::MethodDescriptor* descriptor, RpcMethodType method_type) {
//   RpcMethod* m = new RpcMethod(descriptor, transport_type_, method_type, host_, port_);
//   methods_.push_back(m);
//   return m;
// }

void RpcServiceContext::DestroyCall(RpcCallState* call) {
  //DLOG(INFO) << "RpcServiceContext::DestroyCall: call: " << call->id;
  call_vector_mutex_.Acquire();
  int call_id = 0;
  RpcSocket* call_socket = nullptr;
  bool call_found = false;
  for (auto it = processing_calls_.begin(); it != processing_calls_.end(); it++) {
    if (it->get() == call) {
      RpcCallState* state = it->release();
      call_id = state->id;
      call_socket = state->socket;
      call_socket->CallWillDestroy(state);
      state->Dispose();
      io_thread()->DeleteSoon(FROM_HERE, state);
      processing_calls_.erase(it);
      call_socket->CallDestroyed(call_id);
      break;
    }
  }
  call_vector_mutex_.Release();
  if (call_found && call_socket) {
    call_socket->CallDestroyed(call_id);
  }
}

grpc_event RpcServiceContext::NextEvent(RpcCallState* call) {
  //return (call->state == kCALL_BEGIN) ? grpc_event{ GRPC_OP_COMPLETE, 1, tag(kCALL_BEGIN) } : grpc_completion_queue_next(call->completion_queue, gpr_inf_future(GPR_CLOCK_REALTIME), nullptr);
  return (call->state == kCALL_BEGIN) ? grpc_event{ GRPC_OP_COMPLETE, 1, tag(kCALL_BEGIN) } : grpc_completion_queue_next(call->completion_queue, grpc_timeout_seconds_to_deadline(6), nullptr);
}

void RpcServiceContext::BindHandler(RpcServiceHandler* handler) {
  handler_ = handler;
}

void RpcServiceContext::ProcessCall(RpcCallState* call) {
  bool shutdown = false;
  char* method_name = grpc_slice_to_c_string(call->call_details->method);
  char* host_name = grpc_slice_to_c_string(call->call_details->host);
 
  RpcServiceMethod* method = handler()->GetMethod(method_name);
  
  if (!method) {
    rpc_handler_->HandleRpcSendError(call, 5);
    //RequestCall(call, call->socket);
    DestroyCall(call);
    gpr_free(method_name);
    gpr_free(host_name);
    return;
  }

  call->method = method;
  
  while(!shutdown) {
    grpc_event ev = NextEvent(call);
    CallStatus* s = static_cast<CallStatus*>(ev.tag);
    switch (ev.type) {
      case GRPC_QUEUE_TIMEOUT: {
        //call->timeout_count++;
        //if (call->timeout_count == 3) {
        //printf("\n\ntimeout: %s:%d call id: %d last op: %d last method: %s\n", host_.c_str(), port_, call->id, call->timeout_count, call->last_method.c_str());
        shutdown = true;
        //  break;  
        //}
        continue;
      }
      case GRPC_QUEUE_SHUTDOWN: {
        shutdown = true;
        break;
      }
      case GRPC_OP_COMPLETE: {
        if (ev.success != 0) {
          switch((intptr_t)s) {
            case kCALL_BEGIN:
              //DLOG(INFO) << "RpcServer call: BEGIN call->id = " << call->id;
              rpc_handler_->HandleCallBegin(call, std::string(method_name), std::string(host_name));
              call->state = kCALL_NOOP;
              call->timeout_count = kCALL_BEGIN;
              break;
            case kCALL_STREAM_READ:
              //DLOG(INFO) << "RpcServer call: STREAM_READ call->id = " << call->id;
              rpc_handler_->HandleCallStreamRead(call);
              call->timeout_count = kCALL_STREAM_READ;
              break;
            case kCALL_STREAM_SEND_INIT_METADATA:
              //DLOG(INFO) << "RpcServer call: STREAM_SEND_INIT_METADATA";
              rpc_handler_->HandleCallStreamSendInitMetadata(call);
              call->timeout_count = kCALL_STREAM_SEND_INIT_METADATA;
              break;  
            case kCALL_STREAM_WRITE:
              //DLOG(INFO) << "RpcServer call: STREAM_WRITE";
              rpc_handler_->HandleCallStreamWrite(call);
              call->timeout_count = kCALL_STREAM_WRITE;
              break;
            case kCALL_UNARY_READ:
              //DLOG(INFO) << "RpcServer call: UNARY_READ";
              rpc_handler_->HandleCallUnaryRead(call);
              call->timeout_count = kCALL_UNARY_READ;
              break;
            case kCALL_END: {
              //DLOG(INFO) << "** RpcServer call: END **";
              rpc_handler_->HandleCallEnd(call);
              call->timeout_count = kCALL_END;
              //RequestCall(call, call->socket);
              gpr_free(method_name);
              gpr_free(host_name);
              DestroyCall(call);
              shutdown = true;
              return;
            }
          }
        } else {
          int x = (intptr_t)s;
          DLOG(INFO) <<"RpcServer call: bad.. ev.success = 0 => event type = " << x;
        }
        break;
      }
    }
  }

  // TODO: figure out a clever way to manage this memory destruction
  gpr_free(method_name);
  gpr_free(host_name);
}

void RpcServiceContext::RegisterSocket(RpcSocket* socket) {
  RequestCall(nullptr, socket);
}

void RpcServiceContext::RequestCall(RpcCallState* call, RpcSocket* socket) {//(RpcRequest* req) {
  
  if (call) {
    DestroyCall(call);
  }
 
  //call_completion_queue_ = grpc_completion_queue_create_for_next(nullptr);
  //grpc_metadata_array_init(&recv_initial_metadata_);

  // if (call) {
  //   for (auto it = node_->methods_begin(); it != node_->methods_end(); it++) {
  //     grpc_call_error rc = grpc_server_request_registered_call(//grpc_server_request_call(
  //       server_,
  //       (*it)->tag,
  //       &call_,
  //       &deadline_,
  //       &recv_initial_metadata_,
  //       &recv_message_,
  //       call_completion_queue_,
  //       server_completion_queue_, 
  //       tag(RpcState::kCALL_NEW));

  //     if (rc != GRPC_CALL_OK) {
  //       LOG(ERROR) << "error registering Rpc call: grpc_server_request_call = " << rc;
  //     }
  //   } 
  // } else {
   
    std::unique_ptr<RpcCallState> state = std::make_unique<RpcCallState>();
    RpcCallState* state_ptr = state.get();
    state_ptr->id = call_id_gen_.GetNext() + 1;
    state_ptr->server = server_;
    if (socket) {
      state_ptr->socket = socket;
      state_ptr->socket_id = socket->socket_id();
    }
    call_vector_mutex_.Acquire();
    processing_calls_.push_back(std::move(state));
    call_vector_mutex_.Release();
        

    //DLOG(INFO) << "RpcServiceContext::Reboot: grpc_server_request_call";
    grpc_call_error rc = grpc_server_request_call(
        server_,
        &state_ptr->call,
        state_ptr->call_details,
        &state_ptr->recv_initial_metadata,
        state_ptr->completion_queue,
        server_completion_queue_, 
        state_ptr);

    if (rc != GRPC_CALL_OK) {
      LOG(ERROR) << "error registering Rpc call: grpc_server_request_call = " << rc;
      call_vector_mutex_.Acquire();
      for (auto it = processing_calls_.begin(); it != processing_calls_.end(); it++) {
        if (it->get() == state_ptr)
          processing_calls_.erase(it);
      }
      call_vector_mutex_.Release();
      //delete state;
    }

    //DLOG(INFO) << "RpcServiceContext::Reboot end";
  //}
}

void RpcServiceContext::RequestSameCall(RpcCallState* call, RpcSocket* socket) {
  grpc_call_error rc = grpc_server_request_call(
        server_,
        &call->call,
        call->call_details,
        &call->recv_initial_metadata,
        call->completion_queue,
        server_completion_queue_, 
        call);
    if (rc != GRPC_CALL_OK) {
      LOG(ERROR) << "error registering Rpc call: grpc_server_request_call = " << grpc_call_error_to_string(rc);
    }
}

void RpcServiceContext::OnRpcSendError(RpcCallState* call, int rc) {
  rpc_handler_->HandleRpcSendError(call, rc);
}

base::WeakPtr<RpcCallState> RpcServiceContext::GetCallStateForCall(int call_id) {
  base::AutoLock lock(call_vector_mutex_);
  for (auto it = processing_calls_.begin(); it != processing_calls_.end(); it++) {
    RpcCallState* state = it->get();
    if (state->id == call_id) {
      return state->GetWeakPtr();
    }
  }
  return base::WeakPtr<RpcCallState>();
}

// void RpcServiceContext::SendIPCMessageOnIOThread(IPC::Message* message) {
//   DCHECK(HostThread::CurrentlyOn(HostThread::IO));
//   message_sender_->Send(message);
// }

RpcService::RpcService(
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
  std::unique_ptr<RpcHandler> rpc_handler):
    context_thread_(context_thread),
    context_(new RpcServiceContext(this, host, port, type, std::move(rpc_handler))),
    //apphost_(shell),
    //proto_(proto),
    service_descriptor_(nullptr),
    container_(base::ToLowerASCII(container)),
    //name_(base::ToLowerASCII(name)),
    name_(name),
    state_(RpcServiceState::kINIT),
    delegate_thread_(delegate_thread),
    io_thread_(io_thread),
    //worker_pool_(worker_pool),
    weak_factory_(this) {
  //CHECK(context_thread_.StartWithOptions(
  //  base::Thread::Options(base::MessageLoop::TYPE_IO, 0)));
}

RpcService::~RpcService() {
  //context_thread_.Stop();
  context_ = nullptr;
  delegate_thread_ = nullptr;
  //worker_pool_ = nullptr;
}

const google::protobuf::ServiceDescriptor* RpcService::service_descriptor() {
  return service_descriptor_;
}

std::vector<RpcDescriptor> RpcService::GetMethodDescriptors() {
  std::vector<RpcDescriptor> result;
  const google::protobuf::ServiceDescriptor* service = service_descriptor();
  for (int i = 0; i < service->method_count(); ++i) {
    const google::protobuf::MethodDescriptor* method = service->method(i);
    RpcDescriptor descr;
    descr.full_name = method->full_name();
    descr.name = method->name();
    descr.uuid = base::UUID::generate();
    descr.transport_type = transport_type();
    descr.method_type = GetMethodType(method);
    //DLOG(INFO) << "adding method: full_name: " << descr.full_name << " name: " << descr.name << " method_type: " << (int)descr.method_type;
    result.push_back(std::move(descr));
  }
  return result;
}

void RpcService::BindHandler(RpcServiceHandler* handler) {
  context_->BindHandler(handler);
}

// RpcMethod* RpcService::AddMethod(const google::protobuf::MethodDescriptor* descriptor, RpcMethodType type) {
//   return context_->AddMethod(descriptor, type);
// }

// RpcMethod* RpcService::GetMethod(const std::string& method_name) const {
//   return context_->GetMethod(method_name);
// }

void RpcService::AddObserver(Observer* observer) {
  observers_.push_back(observer);
}

void RpcService::RemoveObserver(Observer* observer) {
  for (auto it = observers_.begin(); it != observers_.end(); it++) {
    if (*it == observer) {
      observers_.erase(it);
      return;
    }
  }
}

// RpcCallState* RpcService::GetCallStateForSocket(int socket_id) {
//   for (auto it = context_->processing_calls_.begin(); it != context_->processing_calls_.end(); it++) {
//     if ((*it)->socket_id == socket_id) {
//       return *it;
//     }
//   }
//   return nullptr;
// }

base::WeakPtr<RpcCallState> RpcService::GetCallStateForCall(int call_id) {
  return context_->GetCallStateForCall(call_id);
}

int RpcService::Start(base::Callback<void(int, net::SocketDescriptor)> reply_to) {
  //DLOG(INFO) << "RpcService::Start";

  reply_to_ = std::move(reply_to);
  //if (options_.port == 0)
  options_.host = context_->host();
  options_.port = context_->port();//grpc_pick_port_using_server();

  //DLOG(INFO) << "method count: " << rpc_node()->method_count();

  //DLOG(INFO) << "rpc service '" << name_ << "' - host: '" << options_.host << "' port: " << options_.port;

  context_thread_->PostTask(
    FROM_HERE,
    base::Bind(&RpcServiceContext::Init, 
      context_,
      options_,
      delegate_thread_,
      io_thread_));

  return 0;  
}

void RpcService::Stop(
  base::WaitableEvent* shutdown_event) {
  if (state_ == RpcServiceState::kSTARTED) {
    //context_thread_.task_runner()->PostTask(
    // base::PostTaskWithTraits(
    //   FROM_HERE,
    //   { base::MayBlock(), base::WithBaseSyncPrimitives() },
    //   base::BindOnce(&RpcServiceContext::Shutdown, 
    //     context_,
    //     delegate_thread_,
    //     base::Unretained(shutdown_event)));
    context_->Shutdown(delegate_thread_, shutdown_event);
  }
}

void RpcService::RegisterSocket(RpcSocket* socket) {
  base::PostTask(
    FROM_HERE,
    base::BindOnce(
      &RpcServiceContext::RegisterSocket,
      context_,
      base::Unretained(socket)));
}

void RpcService::RequestCall(RpcCallState* call, RpcSocket* socket) {
  context_->RequestSameCall(call, socket);
}

void RpcService::OnStart(bool result, net::SocketDescriptor fd) {
  if (result) {
    state_ = RpcServiceState::kSTARTED;
    context_thread_->PostTask(
      FROM_HERE,
      base::Bind(&RpcServiceContext::Wait, 
        context_));

    NotifyStart();
  } 
  
  reply_to_.Run(result ? 0 : -1, fd);
}

void RpcService::OnRpcSendError(RpcCallState* call, int rc) {
  context_thread_->PostTask(
      FROM_HERE,
      base::BindOnce(&RpcServiceContext::OnRpcSendError,
        context_,
        base::Unretained(call),
        rc));  
}

void RpcService::OnStop(bool result) {
  if (result) {
    state_ = RpcServiceState::kSTOPPED;
    NotifyStop();
  }
}

void RpcService::NotifyStart() {
  for (auto it = observers_.begin(); it != observers_.end(); it++) {
    (*it)->OnStart(this);
  }
}

void RpcService::NotifyStop() {
  for (auto it = observers_.begin(); it != observers_.end(); it++) {
    (*it)->OnStop(this);
  }
}

}