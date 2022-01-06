// Copyright (c) 2017 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/server/rpc_manager.h"

#include "base/stl_util.h"
#include "base/sequenced_task_runner.h"
#include "base/task_scheduler/task_traits.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/schema/schema.h"
#include "core/host/host_thread.h"
#include "core/host/workspace/workspace.h"

namespace host {

//namespace {

//const size_t kNumWorkerThreads = 4;

//}  

RpcManager::RpcManager(scoped_refptr<Workspace> workspace):
  //worker_pool_(new base::SequencedWorkerPool(kNumWorkerThreads, "RpcServiceWorker")),
 // main_runner_(main_runner),
  // service_task_runner_(
  //   base::CreateSingleThreadTaskRunnerWithTraits(
  //     { base::MayBlock(), base::WithBaseSyncPrimitives() }, 
  //     base::SingleThreadTaskRunnerThreadMode::DEDICATED)),
  workspace_(workspace),
  shutdown_event_(base::WaitableEvent::ResetPolicy::MANUAL, base::WaitableEvent::InitialState::NOT_SIGNALED) {
  
}

RpcManager::~RpcManager() {
  //STLDeleteDomainPairSecondPointers(services_.begin(), services_.end());
  //worker_pool_->Shutdown();
  for (auto it = services_.begin(); it != services_.end(); it++) {
    delete it->second;
  }
  services_.clear();
  
  //main_runner_ = nullptr;
}

void RpcManager::Init() {
  OnLoad(net::OK, 0);
}

void RpcManager::Shutdown() {
  for (auto it = services_.begin(); it != services_.end(); it++) {
    it->second->Stop(nullptr);
  }
  service_task_runners_.clear();
}


HostRpcService* RpcManager::CreateService(
    //Domain* shell,
    const std::string& container,
    const std::string& name,
    const std::string& host,
    int port,
    net::RpcTransportType type,
    const scoped_refptr<base::SingleThreadTaskRunner>& main_runner,
    const scoped_refptr<base::SingleThreadTaskRunner>& io_runner,
    Schema* schema,
    std::unique_ptr<net::RpcHandler> rpc_handler) {
  
  // service_task_runners_.emplace(
  //     std::make_pair(
  //       name,
  //       base::CreateSingleThreadTaskRunnerWithTraits(
  //       { base::MayBlock(), base::WithBaseSyncPrimitives() }, 
  //       base::SingleThreadTaskRunnerThreadMode::DEDICATED)));

  HostRpcService* service = new HostRpcService(//shell, 
    container, 
    name, 
    host, 
    port, 
    type, 
    //service_task_runners_[name],
    //service_task_runner_,
    base::CreateSingleThreadTaskRunnerWithTraits(
        { base::MayBlock(), base::WithBaseSyncPrimitives() }, 
        base::SingleThreadTaskRunnerThreadMode::DEDICATED),
    main_runner,
    io_runner,
    schema, 
    std::move(rpc_handler));
  AddService(service);
  return service;
}

HostRpcService* RpcManager::GetService(const base::UUID& uuid) const {
  auto it = services_.find(uuid);
  if (it != services_.end()) {
    return it->second;
  }
  return nullptr;
}

HostRpcService* RpcManager::GetService(const std::string& name) const {
  base::UUID service_id;
  auto it = services_names_.find(base::ToLowerASCII(name));
  if (it != services_names_.end()) {
    service_id = it->second;
  }
  auto service_it = services_.find(service_id);
  if (service_it != services_.end()) {
    return service_it->second;
  }  
  return nullptr; 
}

bool RpcManager::HaveService(const base::UUID& uuid) const {
  auto it = services_.find(uuid);
  if (it != services_.end()) {
    return true;
  }
  return false;
}

bool RpcManager::HaveService(const std::string& name) const {
  auto it = services_names_.find(base::ToLowerASCII(name));
  if (it != services_names_.end()) {
    return true;
  }
  return false;
}

void RpcManager::AddService(HostRpcService* service) {
  //DLOG(INFO) << "RpcManager::AddService: " << service->container();
  service->AddObserver(this);
  services_.emplace(std::make_pair(service->uuid(), service));
  services_names_.emplace(std::make_pair(base::ToLowerASCII(service->name()), service->uuid()));
  HostThread::PostTask(HostThread::UI, FROM_HERE, base::Bind(&RpcManager::NotifyServiceAdded, base::Unretained(this), base::Unretained(service)));
  //NotifyServiceAdded(service);
  //rpc_tree_.Add(service->rpc_node());
}

void RpcManager::RemoveService(const base::UUID& uuid) {
  auto it = services_.find(uuid);
  if (it != services_.end()) {
    HostRpcService* s = it->second;
    HostThread::PostTask(HostThread::UI, FROM_HERE, base::Bind(&RpcManager::NotifyServiceRemoved, base::Unretained(this), base::Unretained(s)));
    //NotifyServiceRemoved(s);
    s->RemoveObserver(this);
    //rpc_tree_.Remove(s->rpc_node());
    services_.erase(it);
    delete s;
  }
  for (auto service_it = services_names_.begin(); service_it != services_names_.end(); ++service_it) {
    if (service_it->second == uuid) {
      services_names_.erase(service_it);
      return;
    }
  }
}

void RpcManager::AddObserver(Observer* observer) {
  observers_.push_back(observer);
}

void RpcManager::RemoveObserver(Observer* observer) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == *it) {
      observers_.erase(it);
      return;
    }
  }
}

void RpcManager::OnLoad(int r, int count) {
  NotifyServicesLoad(r, count);
}

void RpcManager::OnStart(net::RpcService* service) {
  workspace_->OnRpcServiceStarted(static_cast<HostRpcService *>(service));
}

void RpcManager::OnStop(net::RpcService* service) {
  workspace_->OnRpcServiceStopped(static_cast<HostRpcService *>(service)); 
}

void RpcManager::NotifyServiceAdded(HostRpcService* service) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnServiceAdded(service);
  }
}

void RpcManager::NotifyServiceRemoved(HostRpcService* service) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnServiceRemoved(service);
  }
}

void RpcManager::NotifyServicesLoad(int r, int count) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnServicesLoad(r, count);
  }
}

}