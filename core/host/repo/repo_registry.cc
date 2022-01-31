// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/repo/repo_registry.h"

#include "core/host/host_thread.h"
#include "core/host/repo/repo.h"
#include "core/host/workspace/workspace.h"

namespace host {

RepoRegistry::RepoRegistry(scoped_refptr<Workspace> workspace, RepoManager* repo_manager): 
  share_controller_(workspace->share_manager()),
  controller_(repo_manager, &share_controller_),
  workspace_(workspace),
  repo_manager_(repo_manager),
  next_watcher_id_(1) {

}

RepoRegistry::~RepoRegistry() {
  workspace_ = nullptr;
}

void RepoRegistry::Init() {

}

void RepoRegistry::Shutdown() {

}

void RepoRegistry::AddBinding(common::mojom::RepoRegistryAssociatedRequest request) {
  repo_registry_binding_.AddBinding(this, std::move(request));
}

void RepoRegistry::AddRepo(common::mojom::RepoEntryPtr entry, AddRepoCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&RepoRegistry::AddRepoImpl, 
      base::Unretained(this),
      base::Passed(std::move(entry)),
      base::Passed(std::move(callback))));
}

void RepoRegistry::AddRepoByAddress(common::mojom::RepoDescriptorPtr descriptor, AddRepoByAddressCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&RepoRegistry::AddRepoByAddressImpl, 
      base::Unretained(this),
      base::Passed(std::move(descriptor)),
      base::Passed(std::move(callback))));
}

void RepoRegistry::RemoveRepo(const std::string& address, RemoveRepoCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&RepoRegistry::RemoveRepoImpl, 
      base::Unretained(this),
      address,
      base::Passed(std::move(callback))));
}

void RepoRegistry::RemoveRepoByUUID(const std::string& uuid, RemoveRepoByUUIDCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&RepoRegistry::RemoveRepoByUUIDImpl, 
      base::Unretained(this),
      uuid,
      base::Passed(std::move(callback))));
}

void RepoRegistry::LookupRepo(const std::string& address, LookupRepoCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&RepoRegistry::LookupRepoImpl, 
      base::Unretained(this),
      address,
      base::Passed(std::move(callback))));
}

void RepoRegistry::LookupRepoByName(const std::string& name, LookupRepoCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&RepoRegistry::LookupRepoByNameImpl, 
      base::Unretained(this),
      name,
      base::Passed(std::move(callback))));
}

void RepoRegistry::LookupRepoByUUID(const std::string& uuid, LookupRepoByUUIDCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&RepoRegistry::LookupRepoByUUIDImpl, 
      base::Unretained(this),
      uuid,
      base::Passed(std::move(callback))));
}

void RepoRegistry::HaveRepo(const std::string& address, HaveRepoCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&RepoRegistry::HaveRepoImpl, 
      base::Unretained(this),
      address,
      base::Passed(std::move(callback))));
}

void RepoRegistry::HaveRepoByName(const std::string& name, HaveRepoCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&RepoRegistry::HaveRepoByNameImpl, 
      base::Unretained(this),
      name,
      base::Passed(std::move(callback))));
}

void RepoRegistry::HaveRepoByUUID(const std::string& uuid, HaveRepoByUUIDCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&RepoRegistry::HaveRepoByUUIDImpl, 
      base::Unretained(this),
      uuid,
      base::Passed(std::move(callback))));
}

void RepoRegistry::ListRepos(ListReposCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&RepoRegistry::ListReposImpl, 
      base::Unretained(this),
      base::Passed(std::move(callback))));
}

void RepoRegistry::GetRepoCount(GetRepoCountCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&RepoRegistry::GetRepoCountImpl, 
      base::Unretained(this),
      base::Passed(std::move(callback))));
}

void RepoRegistry::AddWatcher(common::mojom::RepoWatcherPtr watcher, AddWatcherCallback callback) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&RepoRegistry::AddWatcherImpl, 
      base::Unretained(this),
      base::Passed(std::move(watcher)),
      base::Passed(std::move(callback))));
}

void RepoRegistry::RemoveWatcher(int watcher) {
  HostThread::PostTask(
    HostThread::UI,
    FROM_HERE, 
    base::BindOnce(&RepoRegistry::RemoveWatcherImpl, 
      base::Unretained(this),
      watcher));
}

void RepoRegistry::AddRepoImpl(common::mojom::RepoEntryPtr entry, AddRepoCallback callback) {
  DLOG(INFO) << "RepoRegistry::AddRepoImpl";
  const std::string& address = entry->address;
  controller_.AddRepo(address,
   base::Bind(&RepoRegistry::OnStorageCloned, 
                  base::Unretained(this),
                  base::Passed(std::move(callback))));
}

void RepoRegistry::AddRepoByAddressImpl(common::mojom::RepoDescriptorPtr descriptor, AddRepoByAddressCallback callback) {
  DLOG(INFO) << "RepoRegistry::AddRepoByAddressImpl";
  const std::string& address = descriptor->address;
  controller_.AddRepo(address,
    base::Bind(&RepoRegistry::OnStorageCloned, 
                  base::Unretained(this),
                  base::Passed(std::move(callback))));
}

void RepoRegistry::RemoveRepoImpl(const std::string& address, RemoveRepoCallback callback) {
  bool removed = controller_.RemoveRepo(address);
  HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
        removed ? 
        common::mojom::RepoStatusCode::kREPO_STATUS_OK :
        common::mojom::RepoStatusCode::kREPO_STATUS_ERR_FAILED));
}

void RepoRegistry::RemoveRepoByUUIDImpl(const std::string& uuid, RemoveRepoByUUIDCallback callback) {
  bool removed = controller_.RemoveRepo(uuid);
  HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
        removed ? 
        common::mojom::RepoStatusCode::kREPO_STATUS_OK :
        common::mojom::RepoStatusCode::kREPO_STATUS_ERR_FAILED));
}

void RepoRegistry::LookupRepoImpl(const std::string& address, LookupRepoCallback callback) {
  controller_.LookupRepoByAddress(address);
}

void RepoRegistry::LookupRepoByNameImpl(const std::string& name, LookupRepoCallback callback) {
  controller_.LookupRepoByName(name);
}

void RepoRegistry::LookupRepoByUUIDImpl(const std::string& uuid, LookupRepoByUUIDCallback callback) {
  base::UUID id(reinterpret_cast<const uint8_t *>(uuid.data()));
  controller_.LookupRepoByUUID(id);
}

void RepoRegistry::HaveRepoImpl(const std::string& address, HaveRepoCallback callback) {
  bool have = controller_.HaveRepoByAddress(address);
  std::move(callback).Run(have);
}

void RepoRegistry::HaveRepoByNameImpl(const std::string& name, HaveRepoCallback callback) {
  bool have = controller_.HaveRepoByName(name);
  std::move(callback).Run(have);
}

void RepoRegistry::HaveRepoByUUIDImpl(const std::string& uuid, HaveRepoByUUIDCallback callback) {
  base::UUID id(reinterpret_cast<const uint8_t *>(uuid.data()));
  bool have = controller_.HaveRepoByUUID(id);
  std::move(callback).Run(have);
}

void RepoRegistry::ListReposImpl(ListReposCallback callback) {
  std::vector<common::mojom::RepoEntryPtr> entries;
  const std::vector<std::unique_ptr<Repo>>& repos = controller_.ListRepos();
  for (size_t i = 0; i < repos.size(); ++i) {
    entries.push_back(repos[i]->ToRepoEntry());
  }
  std::move(callback).Run(std::move(entries));
}

void RepoRegistry::GetRepoCountImpl(GetRepoCountCallback callback) {
  uint32_t count = controller_.CountRepos();
  std::move(callback).Run(count);
}

void RepoRegistry::AddWatcherImpl(common::mojom::RepoWatcherPtr watcher, AddWatcherCallback callback) {
  int id = next_watcher_id_++;
  watchers_.emplace(std::make_pair(id, std::move(watcher)));
  HostThread::PostTask(
    HostThread::IO, 
    FROM_HERE,
    base::BindOnce(
      std::move(callback), 
      id));
}

void RepoRegistry::RemoveWatcherImpl(int watcher) {
  auto found = watchers_.find(watcher);
  if (found != watchers_.end()) {
    watchers_.erase(found);
  }
}

void RepoRegistry::OnStorageCloned(AddRepoCallback callback, int result) {
  common::mojom::RepoStatusCode r = (result == 0 ? common::mojom::RepoStatusCode::kREPO_STATUS_OK : common::mojom::RepoStatusCode::kREPO_STATUS_ERR_FAILED);
  HostThread::PostTask(
      HostThread::IO, 
      FROM_HERE,
      base::BindOnce(
        std::move(callback), 
        r));
}

}
