// Copyright 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/domain/domain_context.h"

#include "base/path_service.h"
#include "base/base_paths.h"
#include "base/deferred_sequenced_task_runner.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/synchronization/waitable_event.h"
#include "base/system_monitor/system_monitor.h"
#include "base/task_scheduler/initialization_util.h"
#include "base/task_scheduler/task_scheduler.h"
#include "base/task_scheduler/post_task.h"
#include "base/threading/thread.h"
#include "base/threading/thread_restrictions.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "base/timer/hi_res_timer_manager.h"
#include "base/trace_event/memory_dump_manager.h"
#include "base/trace_event/trace_event.h"
#include "build/build_config.h"
#include "core/shared/common/paths.h"
#include "core/domain/domain_main_thread.h"
#include "core/domain/device/device_manager.h"
#include "core/domain/identity/identity_manager_client.h"
#include "core/domain/launcher/launcher_client.h"
#include "core/domain/module/module_loader.h"
#include "core/domain/module/module_dispatcher.h"
#include "core/shared/domain/service/service_dispatcher.h"
#include "core/shared/domain/storage/storage_dispatcher.h"
#include "core/shared/domain/storage/storage_context.h"
#include "core/shared/domain/storage/storage_index.h"
#include "core/shared/domain/route/route_dispatcher.h"
#include "core/domain/application/application_manager.h"
#include "core/domain/application/window_manager_client.h"
#include "core/domain/application/application_manager_client.h"
#include "core/domain/device/device_dispatcher.h"

namespace domain {

DomainContext::DomainContext(
  DomainMainThread* main_thread,
  const base::FilePath& domain_root,
  const base::UUID& domain_id,
  const std::string& domain_name):
    main_thread_(main_thread),
    domain_root_(domain_root),
    name_(domain_name),
    id_(domain_id),
    storage_dispatcher_(new StorageDispatcher()),
    module_dispatcher_(new ModuleDispatcher()),
    device_dispatcher_(new DeviceDispatcher()),
    window_manager_client_(new WindowManagerClient()),
    application_manager_client_(new ApplicationManagerClient()),
    identity_manager_client_(new IdentityManagerClient()),
    service_dispatcher_(new ServiceDispatcher()),
    route_dispatcher_(new RouteDispatcher()),
    launcher_client_(new LauncherClient()),
    storage_manager_(new StorageManager(this, domain_root)),
    device_manager_(new DeviceManager()),
    module_loader_(new ModuleLoader(domain_root_)) {
}

DomainContext::~DomainContext() {

}

bool DomainContext::Init(P2PSocketDispatcher* p2p_socket_dispatcher, 
  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner,
  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner,
  IPC::SyncChannel* ipc_channel,
  blink::AssociatedInterfaceRegistry* associated_interface_registry) {

  module_loader_->Init(this, p2p_socket_dispatcher, main_task_runner, io_task_runner);
  application_manager_.reset(new ApplicationManager(this, main_task_runner, ipc_channel, associated_interface_registry));
  storage_manager_->Initialize(storage_dispatcher_.get(), main_task_runner, io_task_runner);
  route_dispatcher_->Initialize(main_task_runner);

  return true;
}

void DomainContext::Shutdown() {
  storage_manager_->Shutdown();
  application_manager_.reset();
  module_loader_->Shutdown();
  storage_dispatcher_.reset();
  module_dispatcher_.reset();
  device_dispatcher_.reset();
  window_manager_client_.reset();
  application_manager_client_.reset();
  identity_manager_client_.reset();
  launcher_client_.reset();
}


common::mojom::ApplicationManagerHost* DomainContext::GetApplicationManagerHost() {
  return application_manager_client_->GetApplicationManagerHost();
}

common::mojom::RouteRegistry* DomainContext::GetRouteRegistry() {
  return domain_registry_interface_.get();
}

common::mojom::ServiceRegistry* DomainContext::GetServiceRegistry() {
  return service_registry_interface_.get();
}

common::mojom::ChannelRegistry* DomainContext::GetChannelRegistry() {
  return channel_registry_interface_.get();
}

common::ServiceManagerConnection* DomainContext::GetServiceManagerConnection() {
  return main_thread_->GetServiceManagerConnection();
}

void DomainContext::OnStorageManagerInit(bool result) {
  if (result) {
    //scoped_refptr<StorageContext> context = storage_manager_->CreateContext(
    //  base::Bind(&DomainContext::OnContextCreated, 
    //           base::Unretained(this)));
    LoadModules();
  } else {
    LOG(ERROR) << "StorageManager initialization failed. as a consequence the main engine was not loaded.";
  }
}

// void DomainContext::OnContextCreated(scoped_refptr<StorageContext> context) {
//   OnModuleAvailable(context);
// }

void DomainContext::LoadModules() {
  module_loader_->LoadModules();
}

}