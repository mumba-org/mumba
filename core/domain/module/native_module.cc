// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/module/native_module.h"

#include "base/allocator/allocator_shim.h"
#include "base/allocator/allocator_check.h"
#include "base/task_scheduler/post_task.h"
#include "core/shared/common/p2p_messages.h"
#include "net/base/ip_endpoint.h"
#include "core/domain/domain_main_thread.h"
#include "core/domain/application/application_manager.h"
#include "core/domain/domain_context.h"
#include "core/shared/domain/module/module_client.h"
#include "runtime/MumbaShims/EngineShims.h"
#include "third_party/skia/include/core/SkGraphics.h"

namespace domain {

namespace {

storage_proto::ExecutableArchitecture GetCurrentArchitecture() {
#if defined(OS_LINUX) && defined(ARCH_CPU_X86_64)
  return storage_proto::LINUX_X86_64;
#elif defined(OS_WIN) && defined(ARCH_CPU_X86_64)
  return storage_proto::WINDOWS_X86_64;
#endif
}

}

NativeModule::NativeModule(
  scoped_refptr<DomainContext> context,
  const base::UUID& id,
  const std::string& name, 
  P2PSocketDispatcher* dispatcher,
  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner,
  scoped_refptr<base::SingleThreadTaskRunner> module_task_runner):
 context_(context),
 main_task_runner_(main_task_runner),
 module_task_runner_(module_task_runner),
 io_task_runner_(io_task_runner),
 id_(id),
 name_(name),
 engine_state_(this),
 client_(nullptr),
 dispatcher_(dispatcher) {

}

NativeModule::~NativeModule() {
  main_task_runner_ = nullptr;
}

const base::UUID& NativeModule::id() const {
  return id_;
}

const std::string& NativeModule::name() const {
  return name_;
}

common::mojom::ModuleHandlePtr NativeModule::module_handle() const {
  return common::mojom::ModuleHandlePtr{};
}

bool NativeModule::Load(Executable::InitParams executable_params) {
  base::AutoLock lock(client_mutex_);
  executable_ = std::make_unique<NativeExecutable>(id_, name_);
  if (!executable_->Init(std::move(executable_params))) {
    LOG(ERROR) << "Loading module '" << name() << "' error. executable image initialization failed";
    return false;
  }
  if (executable_->executable_format() != storage_proto::LIBRARY) {
    LOG(ERROR) << "Loading module '" << name() << "' error. executable image format is not library";
    return false;
  }
  storage_proto::ExecutableArchitecture arch = GetCurrentArchitecture();
  if (!executable_->SupportsArch(arch)) {
    LOG(ERROR) << "Loading module '" << name() << "' error. Your architecture is not supported by the application disk";
    // TODO: list the supported archs
    return false; 
  }

  // If we are on a platform where the default allocator is overridden (shim
  // layer on windows, tcmalloc on Linux Desktop) smoke-tests that the
  // overriding logic is working correctly. If not causes a hard crash, as its
  // unexpected absence has security implications.
  CHECK(base::allocator::IsAllocatorInitialized());

  // TODO: DEPRECATE HERE.. we should execute this using the 'ExecutionContext' object
  // the ExecutionContext abstracts away v8 and native execution and also deals
  // with threading, scheduling, thread affinity, loading supporting libraries, etc..

  auto init_entry = executable_->GetStaticEntry(storage_proto::APP_INIT);
  auto get_client_entry = executable_->GetStaticEntry(storage_proto::APP_GET_CLIENT);

  auto init_callback = BindClosure(init_entry);
  if (init_callback) {
    std::move(init_callback).Call();
    auto get_callback = Bind<ModuleClient*()>(get_client_entry);
    if (get_callback) {
      client_ = std::move(get_callback).Call();
    }
  } else {
    //DLOG(ERROR) << "init entry in \"" << name_ << "\" not found";
    return false;
  }
  if (client_) {
    SkGraphics::Init();
    client_->OnInit(&engine_state_);
    //EventQueue* queue = client_->event_queue();
    //DCHECK(queue);
    //queue->task_runner()->PostTask(
    //  FROM_HERE, 
    //  base::BindOnce(&EngineClient::OnRun, base::Unretained(client_)));
  }
  return true;
}

void NativeModule::Unload() {
  base::AutoLock lock(client_mutex_);

  // TODO: DEPRECATE HERE.. we should execute this using the 'ExecutionContext' object
  // the ExecutionContext abstracts away v8 and native execution and also deals
  // with threading, scheduling, thread affinity, loading supporting libraries, etc..

  if (client_) {
    // send the exit loop mesage first
  //  EventQueue* queue = client_->event_queue();
   //  Event* message = new Event(EventType::kCONTROL_QUEUE_SHUTDOWN);
   //  queue->Push(message);
    // TODO: this ref is not thread safe and the client module
    //       also has a reference to it, so we might get in trouble here ...
    //       how to lock?
    //EventLoop* loop = client_->event_loop();
    //loop->Shutdown();
    client_->OnShutdown();
    client_ = nullptr;
  }

  auto destroy_entry = executable_->GetStaticEntry(storage_proto::APP_DESTROY);
  auto unload_callback = BindClosure(destroy_entry);
  if (unload_callback) {
    std::move(unload_callback).Call();
  } else {
    //DLOG(ERROR) << "destroy entry in \"" << name_ << "\" not found";
  }
  executable_.reset();
}

//void NativeModule::SendEventForTest() {
  // base::AutoLock lock(client_mutex_);
  // if (client_) {
  //   printf("NativeModule::SendEventForTest: sending some event..\n");
  //   EventQueue* queue = client_->event_queue();
  //   Event* message = nullptr;
  //   if (event_count_ == 0) {
  //     message = new Event(EventType::kCALL_BEGIN);
  //   } else if (event_count_ == 1) {
  //     message = new Event(EventType::kCALL_END);
  //   } else {
  //     message = new Event(EventType::kCONTROL_QUEUE_SHUTDOWN);
  //   }
  //   queue->Push(message);
  //   event_count_++;
  // }
//}

scoped_refptr<base::SingleThreadTaskRunner> NativeModule::GetMainTaskRunner() const {
  return main_task_runner_;
}

scoped_refptr<base::SingleThreadTaskRunner> NativeModule::GetModuleTaskRunner() const {
  return module_task_runner_;
}

scoped_refptr<base::SingleThreadTaskRunner> NativeModule::GetIOTaskRunner() const {
  return io_task_runner_;
}

common::ServiceManagerConnection* NativeModule::GetServiceManagerConnection() {
  return context_->GetServiceManagerConnection();
}

P2PSocketDispatcher* NativeModule::socket_dispatcher() const {
  return dispatcher_;
}

StorageManager* NativeModule::storage_manager() const {
  return context_->storage_manager();
}

RouteDispatcher* NativeModule::route_dispatcher() const {
  return context_->route_dispatcher();
}

common::mojom::RouteRegistry* NativeModule::route_registry() const {
  return context_->GetRouteRegistry();
}

common::mojom::ServiceRegistry* NativeModule::service_registry() const {
  return context_->GetServiceRegistry();
}

common::mojom::ChannelRegistry* NativeModule::channel_registry() const {
  return context_->GetChannelRegistry();
}

ModuleClient* NativeModule::module_client() const {
  return client_;
}

void NativeModule::CreateP2PSocket(
      int type, 
      int id, 
      const uint8_t* local_addr, 
      int local_port,
      uint16_t port_range_min, 
      uint16_t port_range_max,
      const uint8_t* remote_addr, 
      int remote_port,
      base::Callback<void(int, int)> onCreate) {
  // now, dispatch the IPC message on IO Thread

  // TODO: DEPRECATE HERE.. we should execute this using the 'ExecutionContext' object
  //       using a "pseudo-syscall" layer

  net::IPAddress local_ipaddr(local_addr[0], local_addr[1], local_addr[2], local_addr[3]);
  net::IPAddress remote_ipaddr(remote_addr[0], remote_addr[1], remote_addr[2], remote_addr[3]);
  
  main_task_runner_->PostTask(
    FROM_HERE, 
    base::Bind(
      &NativeModule::SendCreateP2PSocketOnMainThread, 
      base::Unretained(this), 
      type,
      id,
      base::Passed(std::move(local_ipaddr)), 
      local_port,
      port_range_min, 
      port_range_max, 
      base::Passed(std::move(remote_ipaddr)),
      remote_port,
      base::Passed(std::move(onCreate))));
}

void NativeModule::CloseP2PSocket(int id) {
  main_task_runner_->PostTask(
    FROM_HERE, 
    base::Bind(&NativeModule::SendCloseP2PSocketOnMainThread, 
      base::Unretained(this), 
      id));
}

void NativeModule::SendCreateP2PSocketOnMainThread(
      int type, 
      int id, 
      net::IPAddress local_ipaddr, 
      int local_port, 
      uint16_t port_range_min, 
      uint16_t port_range_max, 
      net::IPAddress remote_ipaddr, 
      int remote_port,
      base::Callback<void(int, int)> onCreate) {
  
 // TODO: DEPRECATE HERE.. we should execute this using the 'ExecutionContext' object
 //       using a "pseudo-syscall" layer

  DomainMainThread* main_thread = DomainMainThread::current();
  // main thread is on UI thread thread-local-storage
  DCHECK(main_thread);
  common::P2PSocketOptions options(net::IPEndPoint(local_ipaddr, local_port),
                     common::P2PPortRange(),
                     common::P2PHostAndIPEndPoint(
                     "localhost.localaddr.local", // invented name
                     net::IPEndPoint(remote_ipaddr, remote_port)));

  main_thread->Send(new P2PHostMsg_CreateSocket(
                     static_cast<common::P2PSocketType>(type),
                     id,
                     options));
  // this is fake fix it
  module_task_runner_->PostTask(FROM_HERE, base::Bind(onCreate, id, 0));
}

void NativeModule::SendCloseP2PSocketOnMainThread(int id) {
  DomainMainThread* main_thread = DomainMainThread::current();
  // main thread is on UI thread thread-local-storage
  DCHECK(main_thread);
  
  main_thread->Send(new P2PHostMsg_DestroySocket(id));
}


void NativeModule::ForeachApplication(void* state, void(*foreach)(void* state, void* app_state, const char* name, const char* uuid, const char* url)) {
  ApplicationManager* app_manager = context_->application_manager();
  const std::unordered_map<std::string, std::unique_ptr<Application>>& apps = app_manager->applications();
  for (auto it = apps.begin(); it != apps.end(); ++it) {
    Application* app = it->second.get();
    foreach(state, app, app->name().c_str(), app->uuid().to_string().c_str(), app->url().spec().c_str());
  }
}

}