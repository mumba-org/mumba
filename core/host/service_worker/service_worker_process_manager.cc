// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/service_worker/service_worker_process_manager.h"

#include <stddef.h>

#include <algorithm>
#include <utility>

#include "core/host/application/application.h"
#include "core/host/application/application_process_host.h"
#include "core/host/application/domain_process_host.h"
#include "core/host/service_worker/service_worker_context_wrapper.h"
//#include "core/host/site_instance_impl.h"
//#include "core/host/storage_partition_impl.h"
#include "core/host/host_thread.h"
//#include "core/host/site_instance.h"
//#include "core/shared/common/browser_side_navigation_policy.h"
#include "core/shared/common/child_process_host.h"
#include "url/gurl.h"

namespace host {

ServiceWorkerProcessManager::ServiceWorkerProcessManager(
    Domain* domain)
    : domain_(domain),
      //storage_partition_(nullptr),
      process_id_for_test_(common::ChildProcessHost::kInvalidUniqueID),
      new_process_id_for_test_(common::ChildProcessHost::kInvalidUniqueID),
      weak_this_factory_(this) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  weak_this_ = weak_this_factory_.GetWeakPtr();
}

ServiceWorkerProcessManager::~ServiceWorkerProcessManager() {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  DCHECK(IsShutdown())
      << "Call Shutdown() before destroying |this|, so that racing method "
      << "invocations don't use a destroyed BrowserContext.";
  // TODO(horo): Remove after collecting crash data.
  // Temporary checks to verify that ServiceWorkerProcessManager doesn't prevent
  // render process hosts from shutting down: crbug.com/639193
  CHECK(worker_process_map_.empty());
}

// BrowserContext* ServiceWorkerProcessManager::browser_context() {
//   DCHECK_CURRENTLY_ON(HostThread::UI);
//   // This is safe because reading |browser_context_| on the UI thread doesn't
//   // need locking (while modifying does).
//   return browser_context_;
// }
Domain* ServiceWorkerProcessManager::domain() {
  return domain_;
}

void ServiceWorkerProcessManager::Shutdown() {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  {
    base::AutoLock lock(browser_context_lock_);
    domain_ = nullptr;
  }

  // In single-process mode, Shutdown() is called when deleting the default
  // browser context, which is itself destroyed after the RenderProcessHost.
  // The refcount decrement can be skipped anyway since there's only one
  // process.
  // if (!ApplicationProcessHost::run_application_in_process()) {
  //   for (const auto& it : worker_process_map_) {
  //     if (it.second->HasProcess()) {
  //       ApplicationProcessHost* process = it.second->GetProcess();
  //       if (!process->IsKeepAliveRefCountDisabled())
  //         process->DecrementKeepAliveRefCount(
  //             ApplicationProcessHost::KeepAliveClientType::kServiceWorker);
  //     }
  //   }
  // }
  worker_process_map_.clear();
}

bool ServiceWorkerProcessManager::IsShutdown() {
  base::AutoLock lock(browser_context_lock_);
  return !domain_;
}


common::ServiceWorkerStatusCode ServiceWorkerProcessManager::AllocateWorkerProcess(
    ServiceWorkerProcessType type,
    int embedded_worker_id,
    int process_id,
    const GURL& pattern,
    const GURL& script_url,
    bool can_use_existing_process,
    AllocatedProcessInfo* out_info) {
  DomainProcessHost* sph = nullptr;
  ApplicationProcessHost* aph = nullptr;
  if (type == kPROCESS_TYPE_APPLICATION) {
    aph = ApplicationProcessHost::FromID(process_id);
  } else {
    sph = DomainProcessHost::FromID(process_id);    
  }  
  return AllocateWorkerProcess(
    type,
    embedded_worker_id,
    sph,
    aph,
    pattern,
    script_url,
    can_use_existing_process,
    out_info);
}

common::ServiceWorkerStatusCode ServiceWorkerProcessManager::AllocateWorkerProcess(
    ServiceWorkerProcessType type,
    int embedded_worker_id,
    DomainProcessHost* sph,
    ApplicationProcessHost* aph,
    const GURL& pattern,
    const GURL& script_url,
    bool can_use_existing_process,
    AllocatedProcessInfo* out_info) {
  DCHECK_CURRENTLY_ON(HostThread::UI);

  // DLOG(INFO) << "ServiceWorkerProcessManager::AllocateWorkerProcess: process_type: " << type;

  out_info->process_id = common::ChildProcessHost::kInvalidUniqueID;
  out_info->start_situation = ServiceWorkerMetrics::StartSituation::UNKNOWN;

  // if (process_id_for_test_ != common::ChildProcessHost::kInvalidUniqueID) {
  //   // Let tests specify the returned process ID.
  //   int result = can_use_existing_process ? process_id_for_test_
  //                                         : new_process_id_for_test_;
  //   out_info->process_id = result;
  //   out_info->start_situation =
  //       ServiceWorkerMetrics::StartSituation::EXISTING_READY_PROCESS;
  //   return common::SERVICE_WORKER_OK;
  // }

  if (IsShutdown()) {
    return common::SERVICE_WORKER_ERROR_ABORT;
  }

  DCHECK(!base::ContainsKey(worker_process_map_, embedded_worker_id))
      << embedded_worker_id << " already has a process allocated";

  // Create a SiteInstance to get the renderer process from. Use the site URL
  // from the StoragePartition in case this StoragePartition is for guests
  // (e.g., <webview>).
  // bool use_url_from_storage_partition =
  //     storage_partition_ &&
  //     !storage_partition_->site_for_service_worker().is_empty();
  // scoped_refptr<SiteInstanceImpl> site_instance =
  //     SiteInstanceImpl::CreateForURL(
  //         browser_context_, script_url);//use_url_from_storage_partition
  //                           //    ? storage_partition_->site_for_service_worker()
  //                           //    : script_url);
  // site_instance->set_is_for_service_worker();

  // // Attempt to reuse a renderer process if possible. Note that in the
  // // <webview> case, process reuse isn't currently supported and a new
  // // process will always be created (https://crbug.com/752667).
  // DCHECK(site_instance->process_reuse_policy() ==
  //            SiteInstanceImpl::ProcessReusePolicy::DEFAULT ||
  //        site_instance->process_reuse_policy() ==
  //            SiteInstanceImpl::ProcessReusePolicy::PROCESS_PER_SITE);
  // if (can_use_existing_process) {
  //   site_instance->set_process_reuse_policy(
  //       SiteInstanceImpl::ProcessReusePolicy::REUSE_PENDING_OR_COMMITTED_SITE);
  // }
 
  // // Get the process from the SiteInstance.
  int allocated_process_id = -1;
  ServiceWorkerProcessHandle handle;
  handle.type = type;

  if (type == kPROCESS_TYPE_APPLICATION) {
    DCHECK(aph);
    allocated_process_id = aph->GetID();
    handle.application = aph;
  } else {
    DCHECK(sph);
    allocated_process_id = sph->GetID();
    handle.service = sph;
    // DLOG(INFO) << "ServiceWorkerProcessManager::AllocateWorkerProcess: sph = " << sph << " process_id: " << allocated_process_id;
  }

  // DCHECK(!storage_partition_ ||
  //        rph->InSameStoragePartition(storage_partition_));

  ServiceWorkerMetrics::StartSituation start_situation;
  // if (!rph->HasConnection()) {
  //   // HasConnection() is false means that Init() has not been called or the
  //   // process has been killed.
  //   start_situation = ServiceWorkerMetrics::StartSituation::NEW_PROCESS;
  // } else if (!rph->IsReady()) {
  //   start_situation =
  //       ServiceWorkerMetrics::StartSituation::EXISTING_UNREADY_PROCESS;
  // } else {
    start_situation =
        ServiceWorkerMetrics::StartSituation::EXISTING_READY_PROCESS;
  //}

  // if (!rph->Init()) {
  //   LOG(ERROR) << "Couldn't start a new process!";
  //   return common::SERVICE_WORKER_ERROR_PROCESS_NOT_FOUND;
  // }

  worker_process_map_.emplace(embedded_worker_id, std::move(handle));
  
  
  // if (!rph->IsKeepAliveRefCountDisabled())
  //   rph->IncrementKeepAliveRefCount(
  //       ApplicationProcessHost::KeepAliveClientType::kServiceWorker);
  out_info->process_id = allocated_process_id;
  out_info->start_situation = start_situation;
  return common::SERVICE_WORKER_OK;
}

void ServiceWorkerProcessManager::ReleaseWorkerProcess(int embedded_worker_id) {
  DCHECK_CURRENTLY_ON(HostThread::UI);
  
  if (process_id_for_test_ != common::ChildProcessHost::kInvalidUniqueID) {
    // Unittests don't increment or decrement the worker refcount of a
    // RenderProcessHost.
    return;
  }

  if (IsShutdown()) {
    // Shutdown already released all instances.
    DCHECK(worker_process_map_.empty());
    return;
  }

  auto it = worker_process_map_.find(embedded_worker_id);
  // ReleaseWorkerProcess could be called for a nonexistent worker id, for
  // example, when request to start a worker is aborted on the IO thread during
  // process allocation that is failed on the UI thread.
  if (it == worker_process_map_.end())
    return;

  // if (it->second->HasProcess()) {
  //   ApplicationProcessHost* process = it->second->GetProcess();
  //   if (!process->IsKeepAliveRefCountDisabled())
  //     process->DecrementKeepAliveRefCount(
  //         ApplicationProcessHost::KeepAliveClientType::kServiceWorker);
  // }
  worker_process_map_.erase(it);
}

}  // namespace host

namespace std {
// Destroying ServiceWorkerProcessManagers only on the UI thread allows the
// member WeakPtr to safely guard the object's lifetime when used on that
// thread.
void default_delete<host::ServiceWorkerProcessManager>::operator()(
    host::ServiceWorkerProcessManager* ptr) const {
  host::HostThread::DeleteSoon(
      host::HostThread::UI, FROM_HERE, ptr);
}
}  // namespace std
