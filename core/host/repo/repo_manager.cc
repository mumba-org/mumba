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
#include "core/host/workspace/workspace.h"
#include "core/host/share/share_database.h"
#include "storage/torrent.h"

namespace host {

RepoManager::RepoManager(): weak_factory_(this) {
  
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

void RepoManager::InsertRepo(std::unique_ptr<Repo> repo, bool persist) {
  Repo* reference = repo.get();
  repos_->InsertRepo(repo->id(), std::move(repo), persist);
  NotifyRepoAdded(reference);
}

void RepoManager::RemoveRepo(Repo* repo) {
  NotifyRepoRemoved(repo);
  repos_->RemoveRepo(repo->id());
}

void RepoManager::RemoveRepo(const base::UUID& uuid) {
  Repo* repo = repos_->GetRepoById(uuid);
  if (repo) {
    NotifyRepoRemoved(repo);
    repos_->RemoveRepo(uuid);
  }
}

void RepoManager::AddObserver(Observer* observer) {
  observers_.push_back(observer);
}

void RepoManager::RemoveObserver(Observer* observer) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    if (observer == *it) {
      observers_.erase(it);
      return;
    }
  }
}

void RepoManager::OnLoad(int r, int count) {
  NotifyReposLoad(r, count);
}

void RepoManager::NotifyReposLoad(int r, int count) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnReposLoad(r, count);
  }
}

void RepoManager::NotifyRepoAdded(Repo* repo) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnRepoAdded(repo);
  }
}

void RepoManager::NotifyRepoRemoved(Repo* repo) {
  for (auto it = observers_.begin(); it != observers_.end(); ++it) {
    Observer* observer = *it;
    observer->OnRepoRemoved(repo);
  }
}

}