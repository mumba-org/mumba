// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/application/domain_manager.h"

#include "base/path_service.h"
#include "base/base_paths.h"
#include "base/files/file_util.h"
#include "base/task_scheduler/post_task.h"
#include "core/shared/common/paths.h"
#include "core/host/application/domain_process_host.h"
#include "core/host/share/share_database.h"
#include "core/host/host.h"
#include "core/host/host_thread.h"
#include "core/host/io_thread.h"
#include "core/host/workspace/workspace.h"
#include "storage/db/db.h"
#include "storage/torrent.h"

namespace host {

DomainManager::DomainManager(scoped_refptr<Workspace> workspace, scoped_refptr<HostController> controller):
  workspace_(workspace),
  controller_(controller),
  io_thread_(nullptr),
  clean_shutdown_(false) {

}

DomainManager::~DomainManager() {
  hosts_.reset();
}

void DomainManager::Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy, const base::FilePath& root_path, IOThread* io_thread) {
  io_thread_ = io_thread;
  hosts_.reset(new DomainModel(workspace_, db, policy));
  InitImpl(root_path);
}

void DomainManager::Shutdown() {
  ShutdownImpl();
}

bool DomainManager::HasDomain(const std::string& name) const {
  return hosts_->HasDomain(name); 
}

bool DomainManager::HasDomainUUID(const std::string& uuid) const {
  return hosts_->HasDomainUUID(uuid);
}

bool DomainManager::HasDomain(const base::UUID& uuid) const {
  return hosts_->HasDomain(uuid);
}

bool DomainManager::HasDomain(const common::DomainInfo& info) const {
  return hosts_->HasDomain(info);
}

bool DomainManager::HasDomain(const GURL& urn) const {
  return hosts_->HasDomain(urn);
}

Domain* DomainManager::GetDomain(const std::string& name) const {
  return hosts_->GetDomain(name);
}

Domain* DomainManager::GetDomain(const base::UUID& uuid) const {
  return hosts_->GetDomain(uuid);
}

Domain* DomainManager::GetDomain(const GURL& url) const {
  return hosts_->GetDomain(url);
}

Domain* DomainManager::GetDomain(const common::DomainInfo& info) const {
  return hosts_->GetDomain(info);
}

const DomainModel::Domains& DomainManager::GetDomains() const {
  return hosts_->GetDomains();
}

DomainModel::Domains& DomainManager::GetDomains() {
  return hosts_->GetDomains();
}

void DomainManager::CreateDomain(std::unique_ptr<Domain> host, base::Callback<void(int)> callback, bool sync) {
  if (sync) {
    CreateDomainImpl(std::move(host), std::move(callback));
  } else {
    base::PostTaskWithTraits(
      FROM_HERE,
      { base::MayBlock(), 
        base::WithBaseSyncPrimitives(), 
        base::TaskPriority::USER_BLOCKING },
      base::Bind(
        &DomainManager::CreateDomainImpl,
          base::Unretained(this),
          base::Passed(std::move(host)),
          base::Passed(std::move(callback))));
  }
}

void DomainManager::DestroyDomain(const std::string& name) {
  Domain* host = hosts_->GetDomain(name);
  
  if (!host) {
    LOG(ERROR) << "host with name " << name << " not found";
    return;
  }

  base::PostTaskWithTraits(
    FROM_HERE,
    { base::MayBlock(), 
      base::WithBaseSyncPrimitives(), 
      base::TaskPriority::USER_BLOCKING },
    base::Bind(
      &DomainManager::DestroyDomainImpl,
        base::Unretained(this),
        base::Unretained(host)));
}

void DomainManager::DestroyDomain(const base::UUID& uuid) {
  Domain* host = hosts_->GetDomain(uuid);
  
  if (!host) {
    LOG(ERROR) << "host with name " << uuid.to_string() << " not found";
    return;
  }

  base::PostTaskWithTraits(
    FROM_HERE,
    { base::MayBlock(), 
      base::WithBaseSyncPrimitives(), 
      base::TaskPriority::USER_BLOCKING
    },
    base::Bind(
      &DomainManager::DestroyDomainImpl,
        base::Unretained(this),
        base::Unretained(host)));
}

void DomainManager::LaunchDomain(const base::UUID& uuid, StorageManager* storage_manager, const scoped_refptr<base::SingleThreadTaskRunner>& acceptor_task_runner, base::Callback<void(int)> callback) {
  DCHECK(io_thread_);
  
  Domain* host = GetDomain(uuid);
  if (!host) {
    LOG(ERROR) << "Launch failed: host with uuid " << uuid.to_string() << " not found";
    return;
  }

  LaunchDomain(host, storage_manager, acceptor_task_runner, std::move(callback));
}

void DomainManager::LaunchDomain(const std::string& name, StorageManager* storage_manager, const scoped_refptr<base::SingleThreadTaskRunner>& acceptor_task_runner, base::Callback<void(int)> callback) {
  DCHECK(io_thread_);
  
  Domain* host = GetDomain(name);
  if (!host) {
    LOG(ERROR) << "Launch failed: host with name " << name << " not found";
    return;
  }

  LaunchDomain(host, storage_manager, acceptor_task_runner, std::move(callback));
}

void DomainManager::LaunchDomain(Domain* host, StorageManager* storage_manager, const scoped_refptr<base::SingleThreadTaskRunner>& acceptor_task_runner, base::Callback<void(int)> callback) {
  HostThread::PostTask(
    HostThread::IO,
    FROM_HERE,
    base::BindOnce(&DomainManager::LaunchDomainImpl,
      base::Unretained(this),
      base::Unretained(host),
      base::Unretained(storage_manager),
      acceptor_task_runner,
      base::Passed(std::move(callback))));
}

void DomainManager::ShutdownDomain(const std::string& name, base::Callback<void(int)> callback) {
  Domain* host = GetDomain(name);
  if (!host) {
    LOG(ERROR) << "Shutdown failed: host '" << name << "' not found";
    if (!callback.is_null())
      std::move(callback).Run(net::ERR_FAILED);
    return;
  }
  if (!host->IsRunning()) {
    LOG(ERROR) << "Shutdown failed: host '" << name << "' is not running";
    if (!callback.is_null())
      std::move(callback).Run(net::ERR_FAILED);
    return;
  }
  host->Shutdown(std::move(callback));
  NotifyDomainShutdown(host);
}

void DomainManager::InitImpl(const base::FilePath& root_path) {
  root_path_ = root_path;
  hosts_->LoadDomains(base::Bind(&DomainManager::OnLoad, base::Unretained(this)));
}

void DomainManager::ShutdownImpl() {
  auto& domains = hosts_->GetDomains();
  for (auto it = domains.begin(); it != domains.end(); it++) {
    it->second->Shutdown(base::Callback<void(int)>(), /*global shutdown*/ true);
  }
  //hosts_.reset();
  clean_shutdown_ = true;
}

void DomainManager::CreateDomainImpl(std::unique_ptr<Domain> domain, base::Callback<void(int)> callback) {
  // create the symlink between the host root and the container checkout
//#if defined (OS_POSIX) // TODO: support windows.. apparently it already support this
//  base::FilePath from = root_path_.AppendASCII("apps")
//    .AppendASCII(domain->container_id().to_string());
//  base::FilePath to = root_path_.AppendASCII("hosts")
//    .AppendASCII(domain->id().to_string());

//  if (base::CreateSymbolicLink(from, to)) {
//#endif
    Domain* handle = domain.get();
    // add it to the index
    hosts_->AddDomainIntoDB(handle);
    // add it to the model
    hosts_->AddDomain(std::move(domain));

    controller_->OnDomainAdded(handle);
    NotifyDomainAdded(handle);
//#if defined (OS_POSIX)
//  } else {
//    LOG(ERROR) << "unable to create the symlink from " << from << " to " << to;
//  }
//#endif  
  if (!callback.is_null()) {
    std::move(callback).Run(net::OK);
  }
}

void DomainManager::DestroyDomainImpl(Domain* host) {
  controller_->OnDomainRemoved(host);
  NotifyDomainRemoved(host);
  // remove it from the index
  hosts_->RemoveDomainFromDB(host);
  // remove it from the model
  hosts_->RemoveDomain(host->id());
}

void DomainManager::LaunchDomainImpl(Domain* host, StorageManager* storage_manager, const scoped_refptr<base::SingleThreadTaskRunner>& acceptor_task_runner, base::Callback<void(int)> callback) {
  DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  DomainProcessHost* process = io_thread_->LaunchDomainProcessOnIOThread(host, storage_manager, host->name(), host->id(), acceptor_task_runner);
  if (!process) {
    LOG(ERROR) << "Launch failed: IO thread failed to launch host process";
    std::move(callback).Run(net::ERR_FAILED);
    return;
  }
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE,
    base::BindOnce(&DomainManager::OnDomainLaunched,
      base::Unretained(this),
      base::Unretained(host),
      base::Unretained(process),
      base::Passed(std::move(callback))));  
}

void DomainManager::OnDomainLaunched(Domain* host, DomainProcessHost* process, base::Callback<void(int)> callback) {
  //DLOG(INFO) << "DomainManager::OnDomainLaunched";
  DCHECK(HostThread::CurrentlyOn(HostThread::UI));
  host->OnDomainProcessLaunched(process);
  if (!callback.is_null())
    std::move(callback).Run(net::OK);
  NotifyDomainLaunched(host);
}

void DomainManager::OnLoad(int r, int count) {
  NotifyApplicationsLoad(r, count);
}

void DomainManager::AddObserver(Observer* observer) {
  observers_.push_back(observer);
}

void DomainManager::RemoveObserver(Observer* observer) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == *it) {
      observers_.erase(it);
      return;
    }
  }
}

void DomainManager::NotifyDomainAdded(Domain* app) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnDomainAdded(app);
  }
}

void DomainManager::NotifyDomainRemoved(Domain* app) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnDomainRemoved(app);
  }
}

void DomainManager::NotifyDomainLaunched(Domain* app) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnDomainLaunched(app);
  }
}

void DomainManager::NotifyDomainShutdown(Domain* app) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnDomainShutdown(app);
  }
}

void DomainManager::NotifyApplicationsLoad(int r, int count) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnApplicationsLoad(r, count);
  }
}

const google::protobuf::Descriptor* DomainManager::resource_descriptor() {
  Schema* schema = workspace_->schema_registry()->GetSchemaByName("objects.proto");
  DCHECK(schema);
  return schema->GetMessageDescriptorNamed("Domain");
}

std::string DomainManager::resource_classname() const {
  return Domain::kClassName;
}


}

