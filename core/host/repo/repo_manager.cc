// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/repo/repo_manager.h"

#include "base/path_service.h"
#include "base/base_paths.h"
#include "base/files/file_util.h"
#include "base/task_scheduler/post_task.h"
#include "core/shared/common/paths.h"
#include "core/host/host_thread.h"
#include "core/host/repo/repo.h"
#include "core/host/repo/repo_model.h"
#include "core/host/repo/repo_manager_observer.h"
#include "core/host/workspace/workspace.h"
#include "core/host/share/share_database.h"
#include "storage/torrent.h"

namespace host {

RepoManager::RepoManager(scoped_refptr<Workspace> workspace): 
  workspace_(workspace),
  weak_factory_(this) {
  
}

RepoManager::~RepoManager() {

}

void RepoManager::Init(scoped_refptr<ShareDatabase> db, DatabasePolicy policy) {
  repos_ = std::make_unique<RepoModel>(db, policy);
  InitImpl();
}

void RepoManager::Shutdown() {
  ShutdownImpl();
}

void RepoManager::InitImpl() {
  repos_->Load(base::Bind(&RepoManager::OnLoad, base::Unretained(this)));
}

void RepoManager::ShutdownImpl() {
  repos_.reset();
}

bool RepoManager::RepoExists(Repo* repo) const {
  return repos_->RepoExists(repo);
}

bool RepoManager::RepoExistsById(const base::UUID& id) const {
  return repos_->RepoExistsById(id);
}

bool RepoManager::RepoExistsByName(const std::string& name) const {
  return repos_->RepoExistsByName(name);
}

bool RepoManager::RepoExistsByAddress(const std::string& address) const {
  return repos_->RepoExistsByAddress(address);
}

Repo* RepoManager::GetRepoById(const base::UUID& id) {
  return repos_->GetRepoById(id);
}

Repo* RepoManager::GetRepoByName(const std::string& name) {
  return repos_->GetRepoByName(name);
}

Repo* RepoManager::GetRepoByAddress(const std::string& address) {
  return repos_->GetRepoByAddress(address);
}

std::vector<Repo*> RepoManager::GetRepoList() const {
  return repos_->GetRepoList();
}

size_t RepoManager::GetRepoCount() const {
  return repos_->GetRepoCount();
}

void RepoManager::InsertRepo(std::unique_ptr<Repo> repo, bool persist) {
  Repo* reference = repo.get();
  repos_->InsertRepo(repo->id(), std::move(repo), persist);
  NotifyRepoAdded(reference);
}

bool RepoManager::RemoveRepo(Repo* repo) {
  NotifyRepoRemoved(repo);
  return repos_->RemoveRepo(repo->id());
}

bool RepoManager::RemoveRepo(const base::UUID& uuid) {
  Repo* repo = repos_->GetRepoById(uuid);
  if (repo) {
    NotifyRepoRemoved(repo);
    return repos_->RemoveRepo(uuid);
  }
  return false;
}

bool RepoManager::RemoveRepoByAddress(const std::string& address) {
  Repo* repo = repos_->GetRepoByAddress(address);
  if (repo) {
    NotifyRepoRemoved(repo);
    return repos_->RemoveRepo(repo->id());
  }
  return false;
}

void RepoManager::AddObserver(RepoManagerObserver* observer) {
  observers_.push_back(observer);
}

void RepoManager::RemoveObserver(RepoManagerObserver* observer) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == *it) {
      observers_.erase(it);
      return;
    }
  }
}

void RepoManager::OnLoad(int result_code, int count) {
  NotifyReposLoad(result_code, count);
}

void RepoManager::NotifyReposLoad(int result_code, int count) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    RepoManagerObserver* observer = *it;
    observer->OnReposLoad(result_code, count);
  }
}

void RepoManager::NotifyRepoAdded(Repo* repo) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    RepoManagerObserver* observer = *it;
    observer->OnRepoAdded(repo);
  }
}

void RepoManager::NotifyRepoRemoved(Repo* repo) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    RepoManagerObserver* observer = *it;
    observer->OnRepoRemoved(repo);
  }
}

const google::protobuf::Descriptor* RepoManager::resource_descriptor() {
  Schema* schema = workspace_->schema_registry()->GetSchemaByName("objects.proto");
  DCHECK(schema);
  return schema->GetMessageDescriptorNamed("Repo");
}

std::string RepoManager::resource_classname() const {
  return Repo::kClassName;
}

}
